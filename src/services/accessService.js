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
         WHERE d.id = $1
         LIMIT 1`,
        [documentId, user.id]
    );

    if (result.rows.length === 0) {
        return NO_ACCESS;
    }

    const document = result.rows[0];
    const isOwner = document.owner_id === user.id;

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
    resolveDocumentAccess,
    canAccess
};
