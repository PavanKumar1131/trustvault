
const pool = require("../db");

async function listAccessibleDocuments(userId) {
    const result = await pool.query(
        `SELECT DISTINCT
            d.id,
            d.owner_id,
            d.name,
            d.category,
            d.description,
            d.original_filename,
            d.content_type,
            d.file_size,
            d.created_at,
            CASE
                WHEN d.owner_id = $1 THEN 'owner'
                WHEN EXISTS (
                    SELECT 1
                    FROM document_permissions dp
                    WHERE dp.document_id = d.id
                      AND dp.user_id = $1
                      AND dp.permission = 'download'
                ) THEN 'download'
                ELSE 'view'
            END AS access_level
         FROM documents d
         WHERE d.owner_id = $1
            OR EXISTS (
                SELECT 1
                FROM document_permissions dp
                WHERE dp.document_id = d.id
                  AND dp.user_id = $1
                  AND dp.permission IN ('view', 'download')
            )
         ORDER BY d.created_at DESC`,
        [userId]
    );

    return result.rows;
}

async function getDocumentAccess(documentId, userId) {
    const result = await pool.query(
        `SELECT
            d.id,
            d.owner_id,
            d.name,
            d.category,
            d.description,
            d.original_filename,
            d.content_type,
            d.file_size,
            d.created_at,
            CASE
                WHEN d.owner_id = $2 THEN 'owner'
                WHEN EXISTS (
                    SELECT 1
                    FROM document_permissions dp
                    WHERE dp.document_id = d.id
                      AND dp.user_id = $2
                      AND dp.permission = 'download'
                ) THEN 'download'
                ELSE 'view'
            END AS access_level
         FROM documents d
         WHERE d.id = $1
           AND (
                d.owner_id = $2
                OR EXISTS (
                    SELECT 1
                    FROM document_permissions dp
                    WHERE dp.document_id = d.id
                      AND dp.user_id = $2
                      AND dp.permission IN ('view', 'download')
                )
           )
         LIMIT 1`,
        [documentId, userId]
    );

    return result.rows[0] || null;
}

module.exports = {
    listAccessibleDocuments,
    getDocumentAccess
};
