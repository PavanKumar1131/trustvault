"use strict";

const express = require("express");
const rateLimit = require("express-rate-limit");
const pool = require("../db");
const config = require("../config");
const { requireAuth } = require("../middleware/auth");
const { writeAuditLog, lockAuditChain } = require("../services/auditService");
const {
    UserManagementError,
    approveUpgrade
} = require("../services/userManagementService");
const {
    REQUEST_TYPES,
    OWNER_ROLE,
    getRequestPolicy,
    canSubmitRequest,
    canReviewRequest,
    canReviewerActOnRequest,
    canTransitionRequest,
    resolveRequestReviewer
} = require("../services/requestPolicyRegistry");

const requestsRouter = express.Router();
const adminRequestsRouter = express.Router();
const legacyAuthRouter = express.Router();

const REJECTION_COOLDOWN_DAYS = 7;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_PAGE_SIZE = 100;

const submitLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: config.IS_TEST ? 100000 : 20,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { message: "Too many request submissions. Please try again later." }
});

function parseText(value, field, maxLength = 500) {
    if (value === undefined || value === null) return { value: null };
    if (typeof value !== "string") return { error: field + " must be text" };
    const normalized = value.trim();
    if (normalized.length > maxLength) {
        return { error: field + " must be at most " + maxLength + " characters" };
    }
    return { value: normalized || null };
}

function parseLimit(value, fallback = 50) {
    if (value === undefined) return fallback;
    if (typeof value !== "string" || !/^\d+$/.test(value)) return null;
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) && parsed >= 1 && parsed <= MAX_PAGE_SIZE
        ? parsed
        : null;
}

function parseOffset(value) {
    if (value === undefined) return 0;
    if (typeof value !== "string" || !/^\d+$/.test(value)) return null;
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) && parsed <= 1000000 ? parsed : null;
}

function serializeRequest(row, { includeDecisionActor = false } = {}) {
    if (!row) return null;
    return {
        id: row.id,
        requester: row.requester_id
            ? {
                  id: row.requester_id,
                  name: row.requester_name || null,
                  email: row.requester_email || null,
                  role: row.requester_role || null,
                  isDisabled: Boolean(row.requester_is_disabled)
              }
            : undefined,
        requesterId: row.requester_id,
        requestType: row.request_type,
        requestedRole: row.requested_role,
        targetResourceId: row.target_resource_id,
        requestedPermission: row.requested_permission,
        reason: row.reason || null,
        // Compatibility with the pre-existing Profile/Admin UI. Both names
        // represent the same stored reason; there is still only one table.
        justification: row.reason || null,
        decisionNote: row.decision_note || null,
        rejectionNote: row.decision_note || null,
        status: row.status,
        reviewerRole: row.reviewer_role,
        reviewerUserId: row.reviewer_user_id || null,
        decidedAt: row.decided_at || null,
        ...(includeDecisionActor
            ? {
                  decidedBy: row.decided_by
                      ? {
                            id: row.decided_by,
                            name: row.decider_name || null,
                            email: row.decider_email || null
                        }
                      : null
              }
            : {}),
        submittedAt: row.submitted_at,
        nextEligibleAt: row.next_eligible_at || null
    };
}

const OWN_REQUEST_SELECT = `
    SELECT id, requester_id, request_type, requested_role, target_resource_id,
           requested_permission, reason, decision_note, status, reviewer_role,
           reviewer_user_id, decided_by, submitted_at, decided_at,
           CASE
               WHEN request_type = '${REQUEST_TYPES.DOCUMENT_OWNER_UPGRADE}'
                AND status = 'rejected'
                AND decided_at > NOW() - INTERVAL '${REJECTION_COOLDOWN_DAYS} days'
               THEN decided_at + INTERVAL '${REJECTION_COOLDOWN_DAYS} days'
               ELSE NULL
           END AS next_eligible_at
    FROM requests`;

async function getMine(req, res) {
    try {
        const result = await pool.query(
            OWN_REQUEST_SELECT + " WHERE requester_id = $1 ORDER BY submitted_at DESC, id DESC",
            [req.user.id]
        );
        res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
        return res.json({ requests: result.rows.map(serializeRequest) });
    } catch (error) {
        console.error("Request history lookup failed:", error.message);
        return res.status(500).json({ message: "Unable to load your requests" });
    }
}

async function submit(req, res, { legacy = false } = {}) {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const type = legacy ? REQUEST_TYPES.DOCUMENT_OWNER_UPGRADE : body.requestType;
    const policy = getRequestPolicy(type);
    if (!policy) {
        return res.status(400).json({ message: "Unsupported request type" });
    }

    if (legacy && body.role !== undefined &&
        (typeof body.role !== "string" || body.role.trim().toLowerCase() !== OWNER_ROLE)) {
        return res.status(400).json({
            message: "Only the document_owner role can be requested",
            ...(legacy ? { code: "INVALID_REQUESTED_ROLE" } : {})
        });
    }

    if (type !== REQUEST_TYPES.DOCUMENT_OWNER_UPGRADE || body.targetResourceId || body.requestedPermission) {
        return res.status(400).json({ message: "This request type is not available" });
    }

    const reasonInput = legacy && body.reason === undefined ? body.justification : body.reason;
    const reason = parseText(reasonInput, "Reason");
    if (reason.error) {
        return res.status(400).json({
            message: reason.error,
            ...(legacy ? { code: "INVALID_JUSTIFICATION" } : {})
        });
    }

    const client = await pool.connect();
    let denialAuditWritten = false;
    try {
        await client.query("BEGIN");
        await lockAuditChain(client);

        const requesterResult = await client.query(
            `SELECT id, role, is_disabled
             FROM users WHERE id = $1 FOR UPDATE`,
            [req.user.id]
        );
        const requester = requesterResult.rows[0];
        if (!requester || requester.is_disabled) {
            await client.query("ROLLBACK");
            return res.status(401).json({ message: "Authentication required" });
        }

        if (!canSubmitRequest(type, requester.role)) {
            await writeAuditLog(req, policy.auditEvents.submit, "denied", null, {
                requestType: type,
                reason: "role_not_eligible"
            }, requester.id, client);
            denialAuditWritten = true;
            await client.query("COMMIT");
            return res.status(409).json({
                message: "Your account cannot submit this request",
                ...(legacy ? { code: "ROLE_NOT_ELIGIBLE", currentRole: requester.role } : {})
            });
        }

        const pending = await client.query(
            `SELECT id FROM requests
             WHERE requester_id = $1 AND request_type = $2
               AND target_resource_id IS NULL AND status = 'pending'
             LIMIT 1`,
            [requester.id, type]
        );
        if (pending.rows.length > 0) {
            await writeAuditLog(req, policy.auditEvents.submit, "denied", null, {
                requestId: pending.rows[0].id,
                pendingRequestId: pending.rows[0].id,
                requestType: type,
                reason: "request_already_pending"
            }, requester.id, client);
            denialAuditWritten = true;
            await client.query("COMMIT");
            return res.status(409).json({
                message: "You already have a pending request",
                code: "REQUEST_PENDING"
            });
        }

        const cooldown = await client.query(
            `SELECT id, decided_at + INTERVAL '${REJECTION_COOLDOWN_DAYS} days' AS next_eligible_at
             FROM requests
             WHERE requester_id = $1
               AND request_type = $2
               AND status = 'rejected'
               AND decided_at > NOW() - INTERVAL '${REJECTION_COOLDOWN_DAYS} days'
             ORDER BY decided_at DESC, id DESC
             LIMIT 1`,
            [requester.id, type]
        );
        if (cooldown.rows.length > 0) {
            const { id, next_eligible_at: nextEligibleAt } = cooldown.rows[0];
            await writeAuditLog(req, policy.auditEvents.submit, "denied", null, {
                requestId: id,
                requestType: type,
                reason: "rejection_cooldown_active",
                nextEligibleAt
            }, requester.id, client);
            denialAuditWritten = true;
            await client.query("COMMIT");
            const retryAfterSeconds = Math.max(
                1,
                Math.ceil((new Date(nextEligibleAt).getTime() - Date.now()) / 1000)
            );
            res.setHeader("Retry-After", String(retryAfterSeconds));
            return res.status(429).json({
                message: "Your previous request was rejected. You can submit again after seven days.",
                code: legacy ? "ROLE_UPGRADE_COOLDOWN" : "REQUEST_COOLDOWN",
                nextEligibleAt
            });
        }

        const reviewer = await resolveRequestReviewer(client, type, null);
        if (!reviewer) throw new Error("No eligible reviewer policy is configured");

        const inserted = await client.query(
            `INSERT INTO requests
                (requester_id, request_type, requested_role, reason, reviewer_role)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, requester_id, request_type, requested_role,
                       target_resource_id, requested_permission, reason,
                       decision_note, status, reviewer_role, reviewer_user_id,
                       decided_by, submitted_at, decided_at`,
            [requester.id, type, OWNER_ROLE, reason.value, reviewer.reviewerRole]
        );
        const request = inserted.rows[0];

        await writeAuditLog(req, policy.auditEvents.submit, "success", null, {
            requestId: request.id,
            requestType: type,
            requestedRole: OWNER_ROLE,
            reasonProvided: Boolean(reason.value),
            justificationProvided: Boolean(reason.value)
        }, requester.id, client);
        await client.query("COMMIT");
        return res.status(201).json({
            message: "Request submitted",
            request: serializeRequest(request),
            currentRole: requester.role,
            canSubmit: false
        });
    } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        if (error.code === "23505") {
            if (!denialAuditWritten) {
                try {
                    await writeAuditLog(req, policy.auditEvents.submit, "denied", null, {
                        requestType: type,
                        reason: "request_already_pending"
                    }, req.user.id);
                } catch (auditError) {
                    console.error("Duplicate request denial audit failed:", auditError.message);
                    return res.status(500).json({ message: "The request could not be audited" });
                }
            }
            return res.status(409).json({
                message: "You already have a pending request",
                code: "REQUEST_PENDING"
            });
        }
        console.error("Request submission failed:", error.message);
        return res.status(500).json({ message: "The request was not submitted" });
    } finally {
        client.release();
    }
}

async function cancel(req, res) {
    const requestId = req.params.id;
    if (!UUID_PATTERN.test(requestId)) return res.status(404).json({ message: "Request not found" });

    const client = await pool.connect();
    try {
        await client.query("BEGIN");
        await lockAuditChain(client);
        const found = await client.query(
            `SELECT id, requester_id, request_type, status
             FROM requests WHERE id = $1 FOR UPDATE`,
            [requestId]
        );
        const request = found.rows[0];
        if (!request || request.requester_id !== req.user.id) {
            await client.query("ROLLBACK");
            return res.status(404).json({ message: "Request not found" });
        }
        if (!canTransitionRequest(request.request_type, request.status, "cancelled")) {
            await client.query("ROLLBACK");
            return res.status(409).json({ message: "Only a pending request can be cancelled" });
        }

        const updated = await client.query(
            `UPDATE requests
             SET status = 'cancelled', decided_by = $2, decided_at = NOW()
             WHERE id = $1 AND status = 'pending'
             RETURNING id, requester_id, request_type, requested_role,
                       target_resource_id, requested_permission, reason,
                       decision_note, status, reviewer_role, reviewer_user_id,
                       decided_by, submitted_at, decided_at`,
            [requestId, req.user.id]
        );
        if (!updated.rows[0]) throw new Error("Pending request changed while cancelling");

        const policy = getRequestPolicy(request.request_type, { requireEnabled: false });
        await writeAuditLog(req, policy.auditEvents.cancel, "success", null, {
            requestId,
            requestType: request.request_type,
            decidedBy: req.user.id
        }, req.user.id, client);
        await client.query("COMMIT");
        return res.json({ message: "Request cancelled", request: serializeRequest(updated.rows[0]) });
    } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        console.error("Request cancellation failed:", error.message);
        return res.status(500).json({ message: "The request could not be cancelled" });
    } finally {
        client.release();
    }
}

async function requireActiveAdmin(req, res, next) {
    if (!req.user || req.user.role !== "admin") {
        await writeAuditLog(req, "admin_console_access", "denied", null, {
            path: req.originalUrl,
            role: req.user ? req.user.role : "unauthenticated"
        }).catch((error) => {
            console.error("Admin request denial audit failed:", error.message);
        });
        return res.status(403).json({
            message: "Access denied: Administrator privileges required"
        });
    }
    return next();
}

adminRequestsRouter.use(requireAuth, requireActiveAdmin);

async function listAdmin(req, res, { legacy = false } = {}) {
    const query = req.query || {};
    const status = typeof query.status === "string" ? query.status.toLowerCase() : "pending";
    const allowedStatuses = new Set(["pending", "approved", "rejected", "cancelled", "resolved", "all"]);
    const type = typeof query.type === "string" ? query.type : "";
    const policy = type ? getRequestPolicy(type, { requireEnabled: false }) : null;
    const limit = parseLimit(query.limit);
    const offset = parseOffset(query.offset);
    const search = typeof query.search === "string" ? query.search.trim() : "";

    if (!allowedStatuses.has(status) || (type && !policy) || limit === null || offset === null || search.length > 100) {
        return res.status(400).json({ message: "Invalid request-list filters" });
    }

    const params = [];
    const where = [];
    if (status === "resolved") {
        where.push("r.status IN ('approved', 'rejected', 'cancelled')");
    } else if (status !== "all") {
        params.push(status);
        where.push("r.status = $" + params.length);
    }
    if (type) {
        params.push(type);
        where.push("r.request_type = $" + params.length);
    }
    if (search) {
        params.push(search.toLocaleLowerCase());
        const idx = "$" + params.length;
        where.push("(position(" + idx + " in lower(u.name)) > 0 OR position(" + idx + " in lower(u.email)) > 0)");
    }
    const whereSql = where.length ? " WHERE " + where.join(" AND ") : "";
    const countParams = params.slice();
    const listParams = params.concat([limit, offset]);

    try {
        const [items, count] = await Promise.all([
            pool.query(
                `SELECT r.id, r.requester_id, r.request_type, r.requested_role,
                        r.target_resource_id, r.requested_permission, r.reason,
                        r.decision_note, r.status, r.reviewer_role,
                        r.reviewer_user_id, r.decided_by, r.submitted_at, r.decided_at,
                        u.name AS requester_name, u.email AS requester_email,
                        u.role AS requester_role, u.is_disabled AS requester_is_disabled,
                        decider.name AS decider_name, decider.email AS decider_email,
                        CASE WHEN r.request_type = '${REQUEST_TYPES.DOCUMENT_OWNER_UPGRADE}'
                                  AND r.status = 'rejected'
                                  AND r.decided_at > NOW() - INTERVAL '${REJECTION_COOLDOWN_DAYS} days'
                             THEN r.decided_at + INTERVAL '${REJECTION_COOLDOWN_DAYS} days'
                             ELSE NULL END AS next_eligible_at
                 FROM requests r
                 JOIN users u ON u.id = r.requester_id
                 LEFT JOIN users decider ON decider.id = r.decided_by
                 ${whereSql}
                 ORDER BY CASE WHEN r.status = 'pending' THEN r.submitted_at END ASC,
                          COALESCE(r.decided_at, r.submitted_at) DESC, r.id DESC
                 LIMIT $${listParams.length - 1} OFFSET $${listParams.length}`,
                listParams
            ),
            pool.query("SELECT COUNT(*)::int AS total FROM requests r JOIN users u ON u.id = r.requester_id" + whereSql, countParams)
        ]);
        return res.json({
            requests: items.rows.map((row) => serializeRequest(row, { includeDecisionActor: true })),
            total: count.rows[0].total,
            status,
            type: type || null,
            limit,
            offset,
            ...(legacy ? { legacy: true } : {})
        });
    } catch (error) {
        console.error("Admin request list failed:", error.message);
        return res.status(500).json({ message: "Unable to retrieve requests" });
    }
}

/**
 * Approval is a privileged role transition, so it runs through the same
 * guarded account service as the Admin user editor. The administrator's
 * reason is mandatory and is stored separately from the requester's original
 * justification.
 */
async function approveRequest(req, res) {
    const requestId = req.params.id;
    if (!UUID_PATTERN.test(requestId)) {
        return res.status(404).json({ message: "Request not found" });
    }

    try {
        const result = await approveUpgrade({
            req,
            requestId,
            approvalReason: (req.body || {}).decisionNote
        });
        const requester = result.user;
        const reviewer = req.user;

        return res.json({
            message: "Request approved",
            request: serializeRequest(
                Object.assign({}, result.request, {
                    requester_name: requester.name,
                    requester_email: requester.email,
                    requester_role: requester.role,
                    requester_is_disabled: requester.is_disabled,
                    decider_name: reviewer.name,
                    decider_email: reviewer.email
                }),
                { includeDecisionActor: true }
            ),
            user: requester
        });
    } catch (error) {
        if (error instanceof UserManagementError) {
            return res.status(error.status).json({
                message: error.message,
                ...(error.code ? { code: error.code } : {})
            });
        }
        console.error("Request approval failed:", error.message);
        return res.status(500).json({
            message: "The request decision could not be completed"
        });
    }
}

async function decide(req, res, decision) {
    if (decision === "approved") {
        return approveRequest(req, res);
    }

    const requestId = req.params.id;
    if (!UUID_PATTERN.test(requestId)) return res.status(404).json({ message: "Request not found" });

    const rawNote = (req.body || {}).decisionNote;
    const note = parseText(rawNote, "Decision note");
    if (note.error) return res.status(400).json({ message: note.error });

    const client = await pool.connect();
    try {
        await client.query("BEGIN");
        await lockAuditChain(client);

        const reviewerResult = await client.query(
            `SELECT id, name, email, role, is_disabled FROM users WHERE id = $1 FOR SHARE`,
            [req.user.id]
        );
        const reviewer = reviewerResult.rows[0];
        if (!reviewer || reviewer.role !== "admin" || reviewer.is_disabled) {
            await client.query("ROLLBACK");
            return res.status(403).json({ message: "An active Admin reviewer is required" });
        }

        const found = await client.query(
            `SELECT id, requester_id, request_type, requested_role, reason,
                    reviewer_role, reviewer_user_id, status
             FROM requests WHERE id = $1 FOR UPDATE`,
            [requestId]
        );
        const request = found.rows[0];
        if (!request) {
            await client.query("ROLLBACK");
            return res.status(404).json({ message: "Request not found" });
        }

        const policy = getRequestPolicy(request.request_type);
        if (!policy || !canReviewRequest(request.request_type, reviewer.role)) {
            await client.query("ROLLBACK");
            return res.status(403).json({ message: "This request type has no enabled reviewer" });
        }
        if (request.requester_id === reviewer.id) {
            await client.query("ROLLBACK");
            await writeAuditLog(req, "role_upgrade_request_decision", "denied", null, {
                requestId,
                requestType: request.request_type,
                decision,
                reason: "self_decision"
            }, request.requester_id).catch((error) => {
                console.error("Self-review denial audit failed:", error.message);
            });
            return res.status(403).json({
                message: "You cannot review your own request",
                code: "SELF_DECISION"
            });
        }
        if (request.reviewer_user_id && request.reviewer_user_id !== reviewer.id) {
            await client.query("ROLLBACK");
            return res.status(403).json({ message: "This request is assigned to another reviewer" });
        }
        if (!canReviewerActOnRequest(
            request.request_type,
            reviewer.role,
            reviewer.id,
            request.requester_id,
            request.reviewer_user_id
        )) {
            await client.query("ROLLBACK");
            return res.status(403).json({ message: "This reviewer cannot act on this request" });
        }
        if (!canTransitionRequest(request.request_type, request.status, decision)) {
            await client.query("ROLLBACK");
            await writeAuditLog(req, "role_upgrade_request_decision", "denied", null, {
                requestId,
                requestType: request.request_type,
                decision,
                reason: "request_not_pending",
                currentStatus: request.status
            }, request.requester_id).catch((error) => {
                console.error("Repeated decision denial audit failed:", error.message);
            });
            return res.status(409).json({
                message: "This request is no longer pending",
                code: "REQUEST_NOT_PENDING"
            });
        }

        const requesterResult = await client.query(
            `SELECT id, name, email, role, is_disabled
             FROM users WHERE id = $1 FOR UPDATE`,
            [request.requester_id]
        );
        const requester = requesterResult.rows[0];
        if (!requester || requester.is_disabled || (decision === "approved" && requester.role !== "viewer")) {
            await client.query("ROLLBACK");
            return res.status(409).json({ message: "The requester is no longer eligible for this decision" });
        }

        if (policy.handler !== "documentOwnerUpgrade" || request.requested_role !== OWNER_ROLE) {
            await client.query("ROLLBACK");
            return res.status(403).json({ message: "No processing handler is enabled for this request" });
        }

        let updatedUser = requester;
        if (decision === "approved") {
            const promoted = await client.query(
                `UPDATE users SET role = $1, updated_at = NOW()
                 WHERE id = $2
                 RETURNING id, name, email, role, is_disabled`,
                [OWNER_ROLE, requester.id]
            );
            updatedUser = promoted.rows[0];
        }

        const action = policy.auditEvents[decision === "approved" ? "approve" : "reject"];
        const updated = await client.query(
            `UPDATE requests
             SET status = $1, decision_note = $2, decided_by = $3,
                 decided_at = NOW()
             WHERE id = $4 AND status = 'pending'
             RETURNING id, requester_id, request_type, requested_role,
                       target_resource_id, requested_permission, reason,
                       decision_note, status, reviewer_role, reviewer_user_id,
                       decided_by, submitted_at, decided_at,
                       CASE WHEN $1 = 'rejected'
                            THEN decided_at + INTERVAL '${REJECTION_COOLDOWN_DAYS} days'
                            ELSE NULL END AS next_eligible_at`,
            [decision, note.value, reviewer.id, requestId]
        );
        if (!updated.rows[0]) throw new Error("Pending request changed while deciding");

        await writeAuditLog(req, action, "success", null, {
            requestId,
            requestType: request.request_type,
            requestedRole: request.requested_role,
            decidedBy: reviewer.id,
            decision,
            ...(decision === "approved"
                ? {
                      previousRole: requester.role,
                      newRole: updatedUser.role,
                      reason: note.value,
                      requesterReason: request.reason || null
                  }
                : {
                      roleUnchanged: true,
                      ...(note.value ? { reason: note.value } : {})
                  })
        }, requester.id, client);

        await client.query("COMMIT");
        return res.json({
            message: decision === "approved" ? "Request approved" : "Request rejected",
            request: serializeRequest(Object.assign({}, updated.rows[0], {
                requester_name: updatedUser.name,
                requester_email: updatedUser.email,
                requester_role: updatedUser.role,
                requester_is_disabled: updatedUser.is_disabled,
                decider_name: reviewer.name,
                decider_email: reviewer.email
            }), { includeDecisionActor: true }),
            user: updatedUser
        });
    } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        console.error("Request decision failed:", error.message);
        return res.status(500).json({ message: "The request decision could not be completed" });
    } finally {
        client.release();
    }
}

requestsRouter.use(requireAuth);
requestsRouter.get("/mine", getMine);
requestsRouter.post("/", submitLimiter, (req, res) => submit(req, res));
requestsRouter.post("/:id/cancel", cancel);

adminRequestsRouter.get("/requests", (req, res) => listAdmin(req, res));
adminRequestsRouter.post("/requests/:id/approve", (req, res) => decide(req, res, "approved"));
adminRequestsRouter.post("/requests/:id/reject", (req, res) => decide(req, res, "rejected"));

// Compatibility endpoints for the already-present, uncommitted frontend. They
// delegate to the shared table and shared handlers; no legacy storage remains.
legacyAuthRouter.get("/role-upgrade-request", requireAuth, async (req, res) => {
    try {
        const [items, clock] = await Promise.all([
            pool.query(
                OWN_REQUEST_SELECT + ` WHERE requester_id = $1
                  AND request_type = '${REQUEST_TYPES.DOCUMENT_OWNER_UPGRADE}'
                  ORDER BY submitted_at DESC, id DESC LIMIT 1`,
                [req.user.id]
            ),
            pool.query("SELECT NOW() AS server_time")
        ]);
        const row = items.rows[0] || null;
        const currentRole = req.user.role;
        const cooldownEndsAt = row && row.next_eligible_at;
        const canSubmit = currentRole === "viewer" &&
            !(row && row.status === "pending") && !cooldownEndsAt;
        res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
        return res.json({
            currentRole,
            request: serializeRequest(row),
            canSubmit,
            cooldownEndsAt: cooldownEndsAt || null,
            serverTime: clock.rows[0].server_time
        });
    } catch (error) {
        console.error("Role-upgrade status lookup failed:", error.message);
        return res.status(500).json({ message: "Unable to load your role upgrade request" });
    }
});
legacyAuthRouter.post("/role-upgrade-request", requireAuth, submitLimiter,
    (req, res) => submit(req, res, { legacy: true }));

adminRequestsRouter.get("/role-upgrade-requests", (req, res) => {
    const query = Object.assign({}, req.query, { type: REQUEST_TYPES.DOCUMENT_OWNER_UPGRADE });
    if (query.status === "resolved") query.status = "resolved";
    return listAdmin(Object.assign({}, req, { query }), res, { legacy: true });
});
adminRequestsRouter.post("/role-upgrade-requests/:id/approve", (req, res) => decide(req, res, "approved"));
adminRequestsRouter.post("/role-upgrade-requests/:id/reject", (req, res) => decide(req, res, "rejected"));

module.exports = { requestsRouter, adminRequestsRouter, legacyAuthRouter };
