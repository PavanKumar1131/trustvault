"use strict";

const pool = require("../db");

const REQUEST_TYPES = Object.freeze({
    DOCUMENT_OWNER_UPGRADE: "document_owner_upgrade",
    DOCUMENT_ACCESS: "document_access"
});

const OWNER_ROLE = "document_owner";

/**
 * Server-owned request policies. A null handler means the type is design-only
 * and cannot be submitted or approved by the current API.
 */
const REQUEST_POLICIES = Object.freeze({
    [REQUEST_TYPES.DOCUMENT_OWNER_UPGRADE]: Object.freeze({
        type: REQUEST_TYPES.DOCUMENT_OWNER_UPGRADE,
        enabled: true,
        submitterRoles: Object.freeze(["viewer"]),
        reviewerRoles: Object.freeze(["admin"]),
        reviewerResolver: "any_active_reviewer",
        handler: "documentOwnerUpgrade",
        allowedTransitions: Object.freeze(["approved", "rejected", "cancelled"]),
        permissionChanges: Object.freeze(["users.role:viewer->document_owner"]),
        auditEvents: Object.freeze({
            submit: "role_upgrade_request_submit",
            approve: "role_upgrade_request_approved",
            reject: "role_upgrade_request_rejected",
            cancel: "role_upgrade_request_cancelled"
        })
    }),
    [REQUEST_TYPES.DOCUMENT_ACCESS]: Object.freeze({
        type: REQUEST_TYPES.DOCUMENT_ACCESS,
        enabled: false,
        submitterRoles: Object.freeze(["viewer", OWNER_ROLE, "admin"]),
        reviewerRoles: Object.freeze([OWNER_ROLE]),
        reviewerResolver: "target_resource_owner",
        handler: null,
        allowedTransitions: Object.freeze(["approved", "rejected", "cancelled"]),
        permissionChanges: Object.freeze(["document_permissions:read", "document_permissions:edit"]),
        auditEvents: Object.freeze({
            submit: "document_access_request_submit",
            approve: "document_access_request_approved",
            reject: "document_access_request_rejected",
            cancel: "document_access_request_cancelled"
        })
    })
});

function getRequestPolicy(type, { requireEnabled = true } = {}) {
    const policy = REQUEST_POLICIES[type];
    if (!policy || (requireEnabled && !policy.enabled)) return null;
    return policy;
}

function canSubmitRequest(type, role) {
    const policy = getRequestPolicy(type);
    return Boolean(policy && policy.submitterRoles.includes(role));
}

function canReviewRequest(type, role) {
    const policy = getRequestPolicy(type);
    return Boolean(policy && policy.reviewerRoles.includes(role));
}

function canReviewerActOnRequest(type, role, actorId, requesterId, assignedReviewerId = null) {
    return canReviewRequest(type, role) &&
        actorId !== requesterId &&
        (!assignedReviewerId || assignedReviewerId === actorId);
}

function canTransitionRequest(type, fromStatus, toStatus) {
    const policy = getRequestPolicy(type);
    return Boolean(
        policy && fromStatus === "pending" && policy.allowedTransitions.includes(toStatus)
    );
}

/**
 * Resolve the actual reviewer for a resource request. This is policy support
 * only; document_access is disabled and no route executes a permission grant.
 */
async function resolveRequestReviewer(db, type, targetResourceId) {
    const policy = getRequestPolicy(type, { requireEnabled: false });
    if (!policy) return null;
    if (policy.reviewerResolver === "any_active_reviewer") {
        return { reviewerRole: policy.reviewerRoles[0], reviewerUserId: null };
    }
    if (policy.reviewerResolver !== "target_resource_owner" || !targetResourceId) {
        return null;
    }

    const result = await (db || pool).query(
        `SELECT u.id, u.role
         FROM documents d
         JOIN users u ON u.id = d.owner_id
         WHERE d.id = $1
           AND u.role = $2
           AND u.is_disabled = false`,
        [targetResourceId, OWNER_ROLE]
    );
    if (result.rows.length === 0) return null;
    return {
        reviewerRole: result.rows[0].role,
        reviewerUserId: result.rows[0].id
    };
}

module.exports = {
    REQUEST_TYPES,
    OWNER_ROLE,
    REQUEST_POLICIES,
    getRequestPolicy,
    canSubmitRequest,
    canReviewRequest,
    canReviewerActOnRequest,
    canTransitionRequest,
    resolveRequestReviewer
};
