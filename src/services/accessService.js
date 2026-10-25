/**
 * Centralised document authorization.
 *
 * Every document route derives its decision from `resolveDocumentAccess()` so
 * that no route can implement its own, contradictory, version of the access
 * rules. The decision is always made against the *current* database state,
 * which means a revoked permission takes effect on the very next request.
 *
 * Policy (see docs/PERMISSIONS.md)
 * --------------------------------
 *   owner : full control — read, download, edit, delete, share
 *   edit  : read + download + edit (no delete, no sharing)
 *   read  : read + download only
 *   none  : no access at all (the document is reported as "not found")
 *
 * Administrators receive no implicit access to document content.
 */

const pool = require("../db");

const ACCESS_LEVEL = {
    NONE: "none",
    READ: "read",
    EDIT: "edit",
    OWNER: "owner"
};

/** Actions understood by `canAccess`. */
const SUPPORTED_ACTIONS = ["read", "view", "download", "edit", "delete", "manage", "share"];

const NO_ACCESS = Object.freeze({
    exists: false,
    isOwner: false,
    level: ACCESS_LEVEL.NONE,
    canRead: false,
    canDownload: false,
    canEdit: false,
    canDelete: false,
    canManage: false
});

/**
 * Builds the access decision from a row that already contains the document
 * owner, the current account role/status and the caller's grants.
 */
function accessDecisionFromRow(document, userId) {
    // A disabled account has no effective document access, even if a session
    // somehow reaches this service. `requireAuth` is the primary guard; this
    // keeps the access service safe when called directly.
    if (document.account_disabled) {
        return NO_ACCESS;
    }

    // Ownership is only an *effective* Owner right while the account still
    // holds the Document Owner role. After a demotion the legacy Read grant
    // created by the role service is the only remaining access path.
    const isOwner =
        document.owner_id === userId &&
        document.account_role === "document_owner";

    let level = ACCESS_LEVEL.NONE;
    if (isOwner) {
        level = ACCESS_LEVEL.OWNER;
    } else if (document.has_edit) {
        level = ACCESS_LEVEL.EDIT;
    } else if (document.has_read) {
        level = ACCESS_LEVEL.READ;
    }

    return {
        exists: true,
        documentId: document.id,
        documentOwnerId: document.owner_id,
        isOwner,
        level,
        canRead: level !== ACCESS_LEVEL.NONE,
        canDownload: level !== ACCESS_LEVEL.NONE,
        canEdit: level === ACCESS_LEVEL.OWNER || level === ACCESS_LEVEL.EDIT,
        canDelete: level === ACCESS_LEVEL.OWNER,
        canManage: level === ACCESS_LEVEL.OWNER
    };
}

/**
 * Re-reads the actor and locks their account row for the duration of a
 * security-sensitive write. The lock conflicts with the `FOR UPDATE` used by
 * the account-management service, so a concurrent disable or role change
 * either commits before the write or waits until it has finished.
 *
 * @param {object} client PostgreSQL client inside a transaction
 * @param {string} userId Authenticated account id
 * @param {{roles?: Set<string>|string[]}} [options]
 */
async function lockActiveActorForWrite(client, userId, { roles = null } = {}) {
    const result = await client.query(
        `SELECT id, name, email, role, is_disabled
         FROM users
         WHERE id = $1
         FOR SHARE`,
        [userId]
    );

    const actor = result.rows[0];
    if (!actor || actor.is_disabled) {
        return null;
    }

    if (roles) {
        const allowed = roles instanceof Set ? roles.has(actor.role) : roles.includes(actor.role);
        if (!allowed) {
            return null;
        }
    }

    return actor;
}

/**
 * Transactional variant used by document mutations.
 *
 * It takes the actor's account lock first and the document row lock second,
 * matching the lock order of the account-management service. Grant, revoke,
 * edit and delete routes all use it, so a permission or role change cannot
 * commit between an authorization check and the protected write.
 */
async function resolveDocumentAccessForWrite(client, user, documentId) {
    if (!user || !user.id || !documentId) {
        return NO_ACCESS;
    }

    const actor = await lockActiveActorForWrite(client, user.id);
    if (!actor) {
        return NO_ACCESS;
    }

    const documentResult = await client.query(
        `SELECT id, owner_id
         FROM documents
         WHERE id = $1
         FOR UPDATE`,
        [documentId]
    );

    if (documentResult.rows.length === 0) {
        return NO_ACCESS;
    }

    const document = documentResult.rows[0];
    const grants = await client.query(
        `SELECT
            EXISTS (
                SELECT 1 FROM document_permissions
                WHERE document_id = $1 AND user_id = $2 AND permission = 'read'
            ) AS has_read,
            EXISTS (
                SELECT 1 FROM document_permissions
                WHERE document_id = $1 AND user_id = $2 AND permission = 'edit'
            ) AS has_edit`,
        [documentId, user.id]
    );

    return accessDecisionFromRow(
        {
            id: document.id,
            owner_id: document.owner_id,
            account_role: actor.role,
            account_disabled: actor.is_disabled,
            has_read: grants.rows[0].has_read,
            has_edit: grants.rows[0].has_edit
        },
        user.id
    );
}

/**
 * Resolves the effective access level of `user` for `documentId`.
 *
 * @param {{id: string}|null} user      Authenticated principal
 * @param {string} documentId           Document identifier
 * @returns {Promise<object>}          Access decision
 */
async function resolveDocumentAccess(user, documentId) {
    if (!user || !user.id || !documentId) {
        return NO_ACCESS;
    }

    const result = await pool.query(
        `SELECT d.id,
                d.owner_id,
                account.role AS account_role,
                account.is_disabled AS account_disabled,
                EXISTS (
                    SELECT 1 FROM document_permissions dp
                    WHERE dp.document_id = d.id
                      AND dp.user_id = $2
                      AND dp.permission = 'read'
                ) AS has_read,
                EXISTS (
                    SELECT 1 FROM document_permissions dp
                    WHERE dp.document_id = d.id
                      AND dp.user_id = $2
                      AND dp.permission = 'edit'
                ) AS has_edit
         FROM documents d
         JOIN users account ON account.id = $2
         WHERE d.id = $1
         LIMIT 1`,
        [documentId, user.id]
    );

    if (result.rows.length === 0) {
        return NO_ACCESS;
    }

    return accessDecisionFromRow(result.rows[0], user.id);
}

/**
 * Boolean helper kept for call sites that only need a yes/no answer.
 * @param {{id: string}|null} user
 * @param {string} documentId
 * @param {string} action One of SUPPORTED_ACTIONS
 */
async function canAccess(user, documentId, action) {
    if (!SUPPORTED_ACTIONS.includes(action)) {
        return false;
    }

    const access = await resolveDocumentAccess(user, documentId);

    switch (action) {
        case "read":
        case "view":
        case "download":
            return access.canRead;
        case "edit":
            return access.canEdit;
        case "delete":
        case "manage":
        case "share":
            return access.canManage;
        default:
            return false;
    }
}

module.exports = {
    ACCESS_LEVEL,
    SUPPORTED_ACTIONS,
    lockActiveActorForWrite,
    resolveDocumentAccess,
    resolveDocumentAccessForWrite,
    canAccess
};
