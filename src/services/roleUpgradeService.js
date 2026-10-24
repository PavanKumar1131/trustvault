"use strict";

// Compatibility exports for the pre-existing role-upgrade service name.
// Storage and route handling now live in the general requests system.
const REQUESTED_ROLE = "document_owner";
const REJECTION_COOLDOWN_DAYS = 7;
const MAX_JUSTIFICATION_LENGTH = 500;
const REQUEST_STATUSES = new Set(["pending", "approved", "rejected", "cancelled"]);

function parseJustification(value) {
    if (value === undefined || value === null) return { value: null };
    if (typeof value !== "string") return { error: "Justification must be text" };
    const trimmed = value.trim();
    if (trimmed.length > MAX_JUSTIFICATION_LENGTH) {
        return { error: "Justification must be at most 500 characters" };
    }
    return { value: trimmed || null };
}

function serializeRequest(row) {
    if (!row) return null;
    const requesterId = row.requester_id || row.user_id;
    return {
        id: row.id,
        requester: {
            id: requesterId,
            name: row.requester_name || null,
            email: row.requester_email || null,
            role: row.requester_role || null,
            isDisabled: Boolean(row.requester_is_disabled)
        },
        requestedRole: row.requested_role,
        status: row.status,
        justification: row.reason || row.justification || null,
        submittedAt: row.submitted_at,
        decidedAt: row.decided_at || null,
        decidedBy: row.decided_by
            ? { id: row.decided_by, name: row.decider_name || null, email: row.decider_email || null }
            : null,
        nextEligibleAt: row.next_eligible_at || null
    };
}

function serializeOwnRequest(row) {
    if (!row) return null;
    return {
        id: row.id,
        status: row.status,
        requestedRole: row.requested_role,
        justification: row.reason || row.justification || null,
        submittedAt: row.submitted_at,
        decidedAt: row.decided_at || null,
        nextEligibleAt: row.next_eligible_at || null
    };
}

async function resolvePendingRequest(client, { userId, status, decidedBy }) {
    if (status !== "approved" && status !== "rejected") {
        throw new Error("resolvePendingRequest: invalid decision status");
    }
    const result = await client.query(
        `UPDATE requests
         SET status = $1, decided_by = $2, decided_at = NOW()
         WHERE requester_id = $3
           AND request_type = 'document_owner_upgrade'
           AND status = 'pending'
         RETURNING id, requester_id, request_type, requested_role, status,
                   reason, decided_by, submitted_at, decided_at`,
        [status, decidedBy, userId]
    );
    return result.rows[0] || null;
}

module.exports = {
    REQUESTED_ROLE,
    REJECTION_COOLDOWN_DAYS,
    MAX_JUSTIFICATION_LENGTH,
    REQUEST_STATUSES,
    parseJustification,
    serializeRequest,
    serializeOwnRequest,
    resolvePendingRequest
};
