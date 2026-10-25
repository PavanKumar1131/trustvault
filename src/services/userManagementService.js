"use strict";

/**
 * Guarded account role and status changes.
 *
 * Every mutation of `users.role` or `users.is_disabled` goes through this
 * service so that the same invariants apply to the direct Admin screens and
 * to the request-review workflow:
 *
 *   - only Viewer <-> Document Owner transitions are possible;
 *   - Admin accounts are never assigned, demoted, disabled or re-enabled;
 *   - an administrator can never change their own role or status;
 *   - every change carries a 10-500 character reason;
 *   - a Document Owner demotion leaves a Read grant behind for every document
 *     the account owns, so ownership never remains an implicit privilege;
 *   - the database change, session invalidation, audit rows and pending
 *     request resolution commit or roll back together.
 *
 * `role` and `is_disabled` are deliberately centralised here: scattering the
 * checks across routes is how the two workflows drifted apart before.
 */

const pool = require("../db");
const { writeAuditLog, lockAuditChain } = require("./auditService");
const { resolvePendingUpgradeRequest } = require("./requestService");
const {
    OWNER_ROLE,
    getRequestPolicy,
    canReviewRequest,
    canReviewerActOnRequest,
    canTransitionRequest
} = require("./requestPolicyRegistry");

/** Advisory lock guarding the "at least one active administrator" invariant. */
const ADMIN_INVARIANT_LOCK_KEY = 918273645;

const ADMIN_ROLE = "admin";
const VIEWER_ROLE = "viewer";

const MIN_REASON_LENGTH = 10;
const MAX_REASON_LENGTH = 500;

/** C0, DEL, C1 and the Unicode line separators are never valid in a reason. */
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;

/** Roles that may be assigned through the administration API. */
const ASSIGNABLE_ROLES = Object.freeze([VIEWER_ROLE, OWNER_ROLE]);

class UserManagementError extends Error {
    constructor(status, message, code = null) {
        super(message);
        this.name = "UserManagementError";
        this.status = status;
        this.code = code;
    }
}

/**
 * Validates and normalises a human-entered reason.
 *
 * Returning a value rather than throwing keeps simple route validation
 * readable, while `changeUserRole()` / `setUserStatus()` re-check the value as
 * a defence-in-depth measure.
 */
function parseReason(value, { field = "Reason", required = true } = {}) {
    if (value === undefined || value === null) {
        return required
            ? { error: field + " is required" }
            : { value: null };
    }

    if (typeof value !== "string") {
        return { error: field + " must be text" };
    }

    const normalized = value.trim();

    if (!normalized) {
        return required
            ? { error: field + " is required" }
            : { value: null };
    }

    if (CONTROL_CHARACTERS.test(normalized)) {
        return { error: field + " must not contain control characters" };
    }

    const length = Array.from(normalized).length;
    if (length < MIN_REASON_LENGTH || length > MAX_REASON_LENGTH) {
        return {
            error:
                field + " must be between " + MIN_REASON_LENGTH +
                " and " + MAX_REASON_LENGTH + " characters"
        };
    }

    return { value: normalized };
}

async function countActiveAdmins(client = pool) {
    const result = await client.query(
        "SELECT COUNT(*)::int AS cnt FROM users WHERE role = 'admin' AND is_disabled = false"
    );
    return result.rows[0].cnt;
}

async function invalidateUserSessions(client, userId) {
    const result = await client.query(
        "DELETE FROM user_sessions WHERE sess->>'userId' = $1",
        [userId]
    );
    return result.rowCount || 0;
}

/**
 * Re-reads the operator inside the change transaction. The route has already
 * authenticated the session, but a concurrent disable or role change must not
 * be able to make this transaction act on a stale privilege.
 */
async function requireActiveAdminActor(client, actorId) {
    const result = await client.query(
        "SELECT id, role, is_disabled FROM users WHERE id = $1 FOR SHARE",
        [actorId]
    );
    const actor = result.rows[0];
    if (!actor || actor.role !== ADMIN_ROLE || actor.is_disabled) {
        throw new UserManagementError(
            403,
            "An active Admin reviewer is required"
        );
    }
    return actor;
}

/**
 * Writes a denial audit from outside the (already rolled back) transaction.
 * Failing to record a denial must not turn a correct 4xx answer into a 500,
 * so the failure is logged and the caller keeps its status code.
 */
async function writeDenial(req, action, targetId, details) {
    try {
        await writeAuditLog(
            req,
            action,
            "denied",
            null,
            Object.assign({ targetUserId: targetId }, details),
            targetId
        );
    } catch (error) {
        console.error("Account-change denial audit failed:", error.message);
    }
}

/**
 * Creates or downgrades a Read grant for every document owned by a demoted
 * Document Owner. The grants are written and audited inside the caller's
 * transaction, so a failed audit cannot leave a role change without its
 * legacy grants. A grant that is already Read is left untouched and is not
 * audited as a change.
 */
async function ensureLegacyReadGrants(client, { ownerId, actorId, reason, req }) {
    const owned = await client.query(
        `SELECT d.id AS document_id,
                dp.permission AS previous_permission
         FROM documents d
         LEFT JOIN document_permissions dp
                ON dp.document_id = d.id
               AND dp.user_id = $1
         WHERE d.owner_id = $1
         ORDER BY d.id
         FOR UPDATE OF d`,
        [ownerId]
    );

    let changed = 0;

    for (const document of owned.rows) {
        if (document.previous_permission === "read") {
            continue;
        }

        const granted = await client.query(
            `INSERT INTO document_permissions
                (document_id, user_id, permission, granted_by)
             VALUES ($1, $2, 'read', $3)
             ON CONFLICT (document_id, user_id)
             DO UPDATE
             SET permission = 'read',
                 granted_by = EXCLUDED.granted_by
             WHERE document_permissions.permission <> 'read'
             RETURNING permission`,
            [document.document_id, ownerId, actorId]
        );

        if (!granted.rows[0]) {
            continue;
        }

        await writeAuditLog(
            req,
            "document_permission_grant",
            "success",
            document.document_id,
            {
                source: "owner_demotion",
                permission: "read",
                previousPermission: document.previous_permission || null,
                reason
            },
            ownerId,
            client
        );
        changed += 1;
    }

    return changed;
}

/**
 * Applies a non-Admin role transition on an already-locked target inside an
 * existing transaction. The caller holds the audit lock and the administrator
 * invariant lock, and has already checked the target's current role.
 */
async function applyRoleChange(
    client,
    { req, actorId, target, newRole, reason, requestReference = null, resolvePending = true }
) {
    const previousRole = target.role;

    const updated = await client.query(
        `UPDATE users
         SET role = $1, updated_at = NOW()
         WHERE id = $2
         RETURNING id, name, email, role, is_disabled`,
        [newRole, target.id]
    );

    // A direct role change settles any pending upgrade request so the account
    // can never keep a request whose outcome contradicts the stored role. The
    // request decision reuses the same operator reason but preserves the
    // requester's original justification.
    const requestDecision = newRole === OWNER_ROLE ? "approved" : "rejected";
    const resolvedRequest = resolvePending
        ? await resolvePendingUpgradeRequest(client, {
              userId: target.id,
              status: requestDecision,
              decidedBy: actorId,
              decisionNote: reason
          })
        : null;

    const auditDetails = {
        targetUserId: target.id,
        targetEmail: updated.rows[0].email,
        previousRole,
        newRole,
        reason
    };

    if (requestReference) {
        auditDetails.requestReference = requestReference;
    }
    if (resolvedRequest) {
        auditDetails.pendingRequestId = resolvedRequest.id;
        auditDetails.pendingRequestOutcome = requestDecision;
    }

    await writeAuditLog(
        req,
        "admin_user_role_change",
        "success",
        null,
        auditDetails,
        target.id,
        client
    );

    if (resolvedRequest) {
        await writeAuditLog(
            req,
            requestDecision === "approved"
                ? "role_upgrade_request_approved"
                : "role_upgrade_request_rejected",
            "success",
            null,
            {
                requestId: resolvedRequest.id,
                requestedRole: resolvedRequest.requested_role,
                previousRole,
                newRole,
                reason,
                requesterReason: resolvedRequest.reason || null,
                viaDirectRoleChange: true
            },
            target.id,
            client
        );
    }

    return {
        user: updated.rows[0],
        request: resolvedRequest
            ? {
                  id: resolvedRequest.id,
                  status: requestDecision,
                  decidedAt: resolvedRequest.decided_at
              }
            : null,
        previousRole
    };
}

/**
 * Changes a non-Admin account between Viewer and Document Owner.
 *
 * The caller has already authenticated as an Admin. Validation of the
 * request shape is repeated here so this service cannot be misused by a new
 * route that forgets one of the checks.
 */
async function changeUserRole({ req, targetId, newRole, reason }) {
    const normalizedRole = typeof newRole === "string" ? newRole.trim().toLowerCase() : "";

    const reject = async (status, message, details) => {
        await writeDenial(req, "admin_user_role_change", targetId, details);
        throw new UserManagementError(status, message);
    };

    if (normalizedRole === ADMIN_ROLE) {
        await reject(
            400,
            "The Admin role cannot be assigned through this interface",
            { reason: "direct_admin_promotion", requestedRole: normalizedRole }
        );
    }

    if (!ASSIGNABLE_ROLES.includes(normalizedRole)) {
        await reject(
            400,
            "Role must be one of: document_owner, viewer",
            {
                reason: "invalid_role",
                requestedRole: typeof newRole === "string" ? newRole.slice(0, 40) : null
            }
        );
    }

    if (targetId === req.user.id) {
        await reject(
            400,
            "Administrators cannot change their own role",
            { reason: "self_modification", requestedRole: normalizedRole }
        );
    }

    const parsedReason = parseReason(reason);
    if (parsedReason.error) {
        await reject(400, parsedReason.error, {
            reason: "invalid_reason",
            requestedRole: normalizedRole
        });
    }
    const normalizedReason = parsedReason.value;

    const client = await pool.connect();
    let inTransaction = false;

    try {
        await client.query("BEGIN");
        inTransaction = true;

        // Lock order is the same across every workflow: audit chain ->
        // administrator invariant -> account rows -> request rows.
        await lockAuditChain(client);
        await client.query("SELECT pg_advisory_xact_lock($1)", [
            ADMIN_INVARIANT_LOCK_KEY
        ]);
        await requireActiveAdminActor(client, req.user.id);

        const targetResult = await client.query(
            "SELECT id, name, email, role, is_disabled FROM users WHERE id = $1 FOR UPDATE",
            [targetId]
        );

        if (targetResult.rows.length === 0) {
            await client.query("ROLLBACK");
            inTransaction = false;
            await writeDenial(req, "admin_user_role_change", targetId, {
                reason: "user_not_found",
                requestedRole: normalizedRole
            });
            throw new UserManagementError(404, "User not found");
        }

        const target = targetResult.rows[0];
        const previousRole = target.role;

        if (previousRole === ADMIN_ROLE) {
            // Admin targets are refused even when more than one active Admin
            // exists. The last-active check is retained as defence in depth
            // for any future caller that manages Admin accounts explicitly.
            const activeAdmins = await countActiveAdmins(client);
            const isLastActiveAdmin =
                target.is_disabled === false && activeAdmins <= 1;

            await client.query("ROLLBACK");
            inTransaction = false;

            await writeDenial(req, "admin_user_role_change", targetId, {
                reason: isLastActiveAdmin ? "last_active_admin" : "admin_target",
                previousRole,
                requestedRole: normalizedRole
            });

            throw new UserManagementError(
                409,
                isLastActiveAdmin
                    ? "Cannot demote the last active administrator"
                    : "Administrator accounts cannot be changed through this interface"
            );
        }

        if (previousRole === normalizedRole) {
            await client.query("ROLLBACK");
            inTransaction = false;
            await writeDenial(req, "admin_user_role_change", targetId, {
                reason: "same_role",
                previousRole,
                requestedRole: normalizedRole
            });
            throw new UserManagementError(
                409,
                "The account already has this role"
            );
        }

        let legacyReadGrants = 0;
        if (previousRole === OWNER_ROLE && normalizedRole === VIEWER_ROLE) {
            legacyReadGrants = await ensureLegacyReadGrants(client, {
                ownerId: targetId,
                actorId: req.user.id,
                reason: normalizedReason,
                req
            });
        }

        const result = await applyRoleChange(client, {
            req,
            actorId: req.user.id,
            target,
            newRole: normalizedRole,
            reason: normalizedReason,
            resolvePending: true
        });

        await client.query("COMMIT");
        inTransaction = false;

        return {
            user: result.user,
            request: result.request,
            legacyReadGrants
        };
    } catch (error) {
        if (inTransaction) {
            await client.query("ROLLBACK").catch(() => {});
        }
        throw error;
    } finally {
        client.release();
    }
}

/**
 * Disables or re-enables a non-Admin account. Sessions are deleted in the
 * same transaction as a disable, so a commit can never leave a live cookie
 * behind and a rollback can never restore a half-applied status change.
 * Re-enabling never restores sessions, and it never changes the stored role.
 */
async function setUserStatus({ req, targetId, disabled, reason }) {
    if (typeof disabled !== "boolean") {
        throw new UserManagementError(400, "Provide disabled: true or false");
    }

    const action = disabled ? "admin_user_disabled" : "admin_user_enabled";

    const reject = async (status, message, details) => {
        await writeDenial(req, action, targetId, details);
        throw new UserManagementError(status, message);
    };

    if (targetId === req.user.id) {
        await reject(
            400,
            "Administrators cannot disable their own account",
            { reason: "self_modification", disabled }
        );
    }

    const parsedReason = parseReason(reason);
    if (parsedReason.error) {
        await reject(400, parsedReason.error, {
            reason: "invalid_reason",
            disabled
        });
    }
    const normalizedReason = parsedReason.value;

    const client = await pool.connect();
    let inTransaction = false;

    try {
        await client.query("BEGIN");
        inTransaction = true;
        await lockAuditChain(client);
        await client.query("SELECT pg_advisory_xact_lock($1)", [
            ADMIN_INVARIANT_LOCK_KEY
        ]);
        await requireActiveAdminActor(client, req.user.id);

        const targetResult = await client.query(
            "SELECT id, name, email, role, is_disabled FROM users WHERE id = $1 FOR UPDATE",
            [targetId]
        );

        if (targetResult.rows.length === 0) {
            await client.query("ROLLBACK");
            inTransaction = false;
            await writeDenial(req, action, targetId, {
                reason: "user_not_found",
                disabled
            });
            throw new UserManagementError(404, "User not found");
        }

        const target = targetResult.rows[0];

        if (target.role === ADMIN_ROLE) {
            const activeAdmins = disabled
                ? await countActiveAdmins(client)
                : null;
            const isLastActiveAdmin =
                disabled && target.is_disabled === false && activeAdmins <= 1;

            await client.query("ROLLBACK");
            inTransaction = false;

            await writeDenial(req, action, targetId, {
                reason: isLastActiveAdmin ? "last_active_admin" : "admin_target",
                disabled
            });

            throw new UserManagementError(
                409,
                isLastActiveAdmin
                    ? "Cannot disable the last active administrator"
                    : "Administrator accounts cannot have their status changed through this interface"
            );
        }

        if (target.is_disabled === disabled) {
            await client.query("ROLLBACK");
            inTransaction = false;
            await writeDenial(req, action, targetId, {
                reason: "same_status",
                disabled
            });
            throw new UserManagementError(
                409,
                disabled
                    ? "The account is already disabled"
                    : "The account is already enabled"
            );
        }

        const updated = await client.query(
            `UPDATE users
             SET is_disabled = $1, updated_at = NOW()
             WHERE id = $2
             RETURNING id, name, email, role, is_disabled`,
            [disabled, targetId]
        );

        // Disabling deletes every live session in the same transaction.
        // Re-enabling does not resurrect them: the user signs in again.
        const revokedSessions = disabled
            ? await invalidateUserSessions(client, targetId)
            : 0;

        await writeAuditLog(
            req,
            action,
            "success",
            null,
            {
                targetUserId: targetId,
                targetEmail: updated.rows[0].email,
                previousDisabled: target.is_disabled,
                disabled: updated.rows[0].is_disabled,
                revokedSessions,
                reason: normalizedReason
            },
            targetId,
            client
        );

        await client.query("COMMIT");
        inTransaction = false;

        return {
            user: updated.rows[0],
            revokedSessions
        };
    } catch (error) {
        if (inTransaction) {
            await client.query("ROLLBACK").catch(() => {});
        }
        throw error;
    } finally {
        client.release();
    }
}

/**
 * Approves a Document Owner upgrade request through the same guarded role
 * transition used by the manual editor. The reason is required, stored in
 * `requests.decision_note`, and written to both audit entries. The request
 * row, role change and audits commit together.
 */
async function approveUpgrade({ req, requestId, approvalReason }) {
    const parsedReason = parseReason(approvalReason, { field: "Approval reason" });
    if (parsedReason.error) {
        await writeDenial(req, "role_upgrade_request_decision", null, {
            requestId,
            decision: "approved",
            reason: "invalid_reason"
        });
        throw new UserManagementError(400, parsedReason.error);
    }
    const normalizedReason = parsedReason.value;

    const deny = async (status, message, targetId, details, code = null) => {
        await writeDenial(req, "role_upgrade_request_decision", targetId, Object.assign({
            requestId,
            decision: "approved"
        }, details));
        throw new UserManagementError(status, message, code);
    };

    const client = await pool.connect();
    let inTransaction = false;

    try {
        await client.query("BEGIN");
        inTransaction = true;
        await lockAuditChain(client);
        await client.query("SELECT pg_advisory_xact_lock($1)", [
            ADMIN_INVARIANT_LOCK_KEY
        ]);

        const reviewer = await requireActiveAdminActor(client, req.user.id);

        const found = await client.query(
            `SELECT id, requester_id, request_type, requested_role, reason,
                    reviewer_role, reviewer_user_id, status
             FROM requests
             WHERE id = $1
             FOR UPDATE`,
            [requestId]
        );
        const request = found.rows[0];

        if (!request) {
            await client.query("ROLLBACK");
            inTransaction = false;
            await deny(404, "Request not found", null, {
                reason: "request_not_found"
            });
        }

        if (request.requester_id === reviewer.id) {
            await client.query("ROLLBACK");
            inTransaction = false;
            await deny(
                403,
                "You cannot review your own request",
                request.requester_id,
                { reason: "self_decision", requestType: request.request_type },
                "SELF_DECISION"
            );
        }

        const policy = getRequestPolicy(request.request_type);
        if (!policy || !canReviewRequest(request.request_type, reviewer.role)) {
            await client.query("ROLLBACK");
            inTransaction = false;
            await deny(
                403,
                "This request type has no enabled reviewer",
                request.requester_id,
                { reason: "no_enabled_reviewer", requestType: request.request_type }
            );
        }

        if (request.reviewer_user_id && request.reviewer_user_id !== reviewer.id) {
            await client.query("ROLLBACK");
            inTransaction = false;
            await deny(
                403,
                "This request is assigned to another reviewer",
                request.requester_id,
                { reason: "not_assigned_reviewer", requestType: request.request_type }
            );
        }

        if (
            !canReviewerActOnRequest(
                request.request_type,
                reviewer.role,
                reviewer.id,
                request.requester_id,
                request.reviewer_user_id
            )
        ) {
            await client.query("ROLLBACK");
            inTransaction = false;
            await deny(
                403,
                "This reviewer cannot act on this request",
                request.requester_id,
                { reason: "reviewer_not_allowed", requestType: request.request_type }
            );
        }

        if (!canTransitionRequest(request.request_type, request.status, "approved")) {
            await client.query("ROLLBACK");
            inTransaction = false;
            await deny(
                409,
                "This request is no longer pending",
                request.requester_id,
                {
                    reason: "request_not_pending",
                    requestType: request.request_type,
                    currentStatus: request.status
                },
                "REQUEST_NOT_PENDING"
            );
        }

        if (
            policy.handler !== "documentOwnerUpgrade" ||
            request.requested_role !== OWNER_ROLE
        ) {
            await client.query("ROLLBACK");
            inTransaction = false;
            await deny(
                403,
                "No processing handler is enabled for this request",
                request.requester_id,
                { reason: "no_handler", requestType: request.request_type }
            );
        }

        const requesterResult = await client.query(
            `SELECT id, name, email, role, is_disabled
             FROM users
             WHERE id = $1
             FOR UPDATE`,
            [request.requester_id]
        );
        const requester = requesterResult.rows[0];

        if (!requester || requester.is_disabled) {
            await client.query("ROLLBACK");
            inTransaction = false;
            await deny(
                409,
                "The requester is no longer eligible for this decision",
                request.requester_id,
                { reason: "requester_not_eligible" }
            );
        }

        if (requester.role === ADMIN_ROLE) {
            await client.query("ROLLBACK");
            inTransaction = false;
            await deny(
                409,
                "Administrator accounts cannot be changed through this interface",
                requester.id,
                { reason: "admin_target", currentRole: requester.role }
            );
        }

        if (requester.role !== VIEWER_ROLE) {
            await client.query("ROLLBACK");
            inTransaction = false;
            await deny(
                409,
                "The requester is no longer eligible for this decision",
                requester.id,
                { reason: "requester_not_viewer", currentRole: requester.role }
            );
        }

        const roleResult = await applyRoleChange(client, {
            req,
            actorId: reviewer.id,
            target: requester,
            newRole: OWNER_ROLE,
            reason: normalizedReason,
            requestReference: requestId,
            resolvePending: false
        });

        const updated = await client.query(
            `UPDATE requests
             SET status = 'approved', decision_note = $1, decided_by = $2,
                 decided_at = NOW()
             WHERE id = $3 AND status = 'pending'
             RETURNING id, requester_id, request_type, requested_role,
                       target_resource_id, requested_permission, reason,
                       decision_note, status, reviewer_role, reviewer_user_id,
                       decided_by, submitted_at, decided_at,
                       NULL::timestamptz AS next_eligible_at`,
            [normalizedReason, reviewer.id, requestId]
        );

        if (!updated.rows[0]) {
            throw new Error("Pending request changed while deciding");
        }

        await writeAuditLog(
            req,
            "role_upgrade_request_approved",
            "success",
            null,
            {
                requestId,
                requestType: request.request_type,
                requestedRole: request.requested_role,
                requesterReason: updated.rows[0].reason || null,
                reason: normalizedReason,
                decision: "approved",
                decidedBy: reviewer.id,
                previousRole: requester.role,
                newRole: roleResult.user.role,
                requestReference: requestId
            },
            requester.id,
            client
        );

        await client.query("COMMIT");
        inTransaction = false;

        return {
            request: updated.rows[0],
            user: roleResult.user
        };
    } catch (error) {
        if (inTransaction) {
            await client.query("ROLLBACK").catch(() => {});
        }
        throw error;
    } finally {
        client.release();
    }
}

module.exports = {
    ADMIN_INVARIANT_LOCK_KEY,
    ADMIN_ROLE,
    ASSIGNABLE_ROLES,
    MIN_REASON_LENGTH,
    MAX_REASON_LENGTH,
    UserManagementError,
    parseReason,
    countActiveAdmins,
    invalidateUserSessions,
    changeUserRole,
    setUserStatus,
    approveUpgrade
};
