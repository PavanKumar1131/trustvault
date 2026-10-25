"use strict";

const { REQUEST_TYPES } = require("./requestPolicyRegistry");

/**
 * Keeps the existing Admin Users role editor consistent with the unified
 * request history. The caller holds the audit lock and the target user's row
 * lock in the same transaction.
 */
async function resolvePendingUpgradeRequest(
    client,
    { userId, status, decidedBy, decisionNote = null }
) {
    if (status !== "approved" && status !== "rejected") {
        throw new Error("resolvePendingUpgradeRequest: invalid status");
    }
    const result = await client.query(
        `UPDATE requests
         SET status = $1,
             decision_note = COALESCE($5, decision_note),
             decided_by = $2,
             decided_at = NOW()
         WHERE requester_id = $3
           AND request_type = $4
           AND status = 'pending'
         RETURNING id, requester_id, request_type, requested_role, reason,
                   decision_note, status, decided_by, submitted_at, decided_at`,
        [status, decidedBy, userId, REQUEST_TYPES.DOCUMENT_OWNER_UPGRADE, decisionNote]
    );
    return result.rows[0] || null;
}

module.exports = { resolvePendingUpgradeRequest };
