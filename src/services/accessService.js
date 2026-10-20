
const pool = require("../db");

async function canAccess(user, documentId, action) {
    const allowedActions = ["view", "download", "manage", "share"];

    if (!user || !user.id || !allowedActions.includes(action)) {
        return false;
    }

    const result = await pool.query(
        `SELECT
            d.id,
            d.owner_id,
            EXISTS (
                SELECT 1
                FROM document_permissions dp
                WHERE dp.document_id = d.id
                  AND dp.user_id = $2
                  AND dp.permission = 'view'
            ) AS can_view,
            EXISTS (
                SELECT 1
                FROM document_permissions dp
                WHERE dp.document_id = d.id
                  AND dp.user_id = $2
                  AND dp.permission = 'download'
            ) AS can_download
         FROM documents d
         WHERE d.id = $1
         LIMIT 1`,
        [documentId, user.id]
    );

    if (result.rows.length === 0) {
        return false;
    }

    const document = result.rows[0];
    const isOwner = document.owner_id === user.id;

    if (isOwner) {
        return true;
    }

    switch (action) {
        case "view":
            return document.can_view || document.can_download;

        case "download":
            return document.can_download;

        case "manage":
        case "share":
            return false;

        default:
            return false;
    }
}

module.exports = { canAccess };
