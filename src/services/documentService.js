const pool = require("../db");

/**
 * Escapes the LIKE wildcards `%`, `_` and the escape character itself so that
 * a user supplied search term is matched literally instead of acting as a
 * wildcard (e.g. searching for "100%" must not match every document).
 */
function escapeLikePattern(value) {
    return String(value).replace(/[\\%_]/g, (character) => `\\${character}`);
}

/** Trims a string filter and returns an empty string when it is unusable. */
function cleanFilter(value) {
    if (typeof value !== "string") return "";
    return value.trim();
}

// ── listAccessibleDocuments ───────────────────────────────────────────────────
// Returns all documents accessible to userId (owned or permission-granted),
// optionally filtered and paginated via limit/page.
//
// `filters.shared === true` narrows the result to the documents that were
// shared *with* the caller by somebody else. Owned documents are never part
// of that list — they belong to "My documents". The grant timestamp is
// returned as `shared_at` so that the UI can show when the share happened.
async function listAccessibleDocuments(userId, filters = {}) {
    const params = [userId];
    const whereClauses = [
        "account.is_disabled = false",
        "(" +
        "(account.role = 'document_owner' AND d.owner_id = $1) " +
        "OR EXISTS (" +
        "SELECT 1 FROM document_permissions dp " +
        "WHERE dp.document_id = d.id AND dp.user_id = $1 " +
        "AND dp.permission IN ('read', 'edit')" +
        "))"
    ];

    if (filters.shared === true) {
        whereClauses.push(
            "EXISTS (" +
            "SELECT 1 FROM document_permissions dp " +
            "WHERE dp.document_id = d.id AND dp.user_id = $1 " +
            "AND dp.permission IN ('read', 'edit')" +
            ")"
        );
    }

    // `filters.owned === true` narrows the result to the documents the
    // caller owns. It is the server-side counterpart of the "My documents"
    // screen, so that the screen can be paginated by the database instead of
    // by slicing the client's copy of the list.
    if (filters.owned === true) {
        whereClauses.push("account.role = 'document_owner' AND d.owner_id = $1");
    }

    const searchName = cleanFilter(filters.q) || cleanFilter(filters.name);

    if (searchName) {
        params.push("%" + escapeLikePattern(searchName) + "%");
        const idx = "$" + params.length;
        whereClauses.push(
            "(d.name ILIKE " + idx + " ESCAPE '\\' OR COALESCE(d.description, '') ILIKE " + idx + " ESCAPE '\\')"
        );
    }

    const category = cleanFilter(filters.category);
    if (category) {
        params.push(category);
        const idx = "$" + params.length;
        whereClauses.push("LOWER(d.category) = LOWER(" + idx + ")");
    }

    const owner = cleanFilter(filters.owner);
    if (owner) {
        params.push("%" + escapeLikePattern(owner) + "%");
        const idx = "$" + params.length;
        whereClauses.push("(u.name ILIKE " + idx + " ESCAPE '\\' OR u.email ILIKE " + idx + " ESCAPE '\\')");
    }

    const from = cleanFilter(filters.from);
    if (from) {
        const fromDate = new Date(from);
        if (!Number.isNaN(fromDate.getTime())) {
            params.push(fromDate.toISOString());
            const idx = "$" + params.length;
            whereClauses.push("d.created_at >= " + idx + "::timestamptz");
        }
    }

    const to = cleanFilter(filters.to);
    if (to) {
        const toDate = new Date(to);
        if (!Number.isNaN(toDate.getTime())) {
            if (/^\d{4}-\d{2}-\d{2}$/.test(to)) {
                toDate.setUTCHours(23, 59, 59, 999);
            }
            params.push(toDate.toISOString());
            const idx = "$" + params.length;
            whereClauses.push("d.created_at <= " + idx + "::timestamptz");
        }
    }

    // ── Pagination ────────────────────────────────────────────────────────────
    const limit = Math.min(
        Math.max(Number.isInteger(filters.limit) ? filters.limit : parseInt(filters.limit || "50", 10) || 50, 1),
        200
    );
    const page = Math.max(
        Number.isInteger(filters.page) ? filters.page : parseInt(filters.page || "1", 10) || 1,
        1
    );
    const offset = (page - 1) * limit;

    params.push(limit);
    const limitIdx = "$" + params.length;
    params.push(offset);
    const offsetIdx = "$" + params.length;

    const sql =
        "SELECT DISTINCT " +
        "d.id, d.owner_id, u.name AS owner_name, u.email AS owner_email, " +
        "d.name, d.category, d.description, d.original_filename, " +
        "d.content_type, d.file_size, d.created_at, d.updated_at, " +
        "(SELECT MAX(dp.created_at) FROM document_permissions dp " +
        " WHERE dp.document_id = d.id AND dp.user_id = $1) AS shared_at, " +
        "CASE " +
        "WHEN account.role = 'document_owner' AND d.owner_id = $1 THEN 'owner' " +
        "WHEN EXISTS (SELECT 1 FROM document_permissions dp WHERE dp.document_id = d.id AND dp.user_id = $1 AND dp.permission = 'edit') THEN 'edit' " +
        "ELSE 'read' END AS access_level " +
        "FROM documents d " +
        "JOIN users u ON u.id = d.owner_id " +
        "JOIN users account ON account.id = $1 " +
        "WHERE " + whereClauses.join(" AND ") + " " +
        "ORDER BY d.created_at DESC " +
        "LIMIT " + limitIdx + " OFFSET " + offsetIdx;

    const result = await pool.query(sql, params);
    return result.rows;
}

// ── getDocumentAccess ─────────────────────────────────────────────────────────
// Returns the document metadata for a user that is allowed to see it, or
// null. The access rule is identical to the one enforced by the
// accessService, so no route can accidentally widen the scope.
async function getDocumentAccess(documentId, userId) {
    const result = await pool.query(
        `SELECT
            d.id,
            d.owner_id,
            u.name AS owner_name,
            u.email AS owner_email,
            d.name,
            d.category,
            d.description,
            d.original_filename,
            d.content_type,
            d.file_size,
            d.created_at,
            d.updated_at,
            (SELECT MAX(dp.created_at)
               FROM document_permissions dp
              WHERE dp.document_id = d.id
                AND dp.user_id = $2) AS shared_at,
            CASE
                WHEN account.role = 'document_owner'
                 AND d.owner_id = $2 THEN 'owner'
                WHEN EXISTS (
                    SELECT 1
                    FROM document_permissions dp
                    WHERE dp.document_id = d.id
                      AND dp.user_id = $2
                      AND dp.permission = 'edit'
                ) THEN 'edit'
                ELSE 'read'
            END AS access_level
         FROM documents d
         JOIN users u ON u.id = d.owner_id
         JOIN users account ON account.id = $2
         WHERE d.id = $1
           AND account.is_disabled = false
           AND (
                (account.role = 'document_owner' AND d.owner_id = $2)
                OR EXISTS (
                    SELECT 1
                    FROM document_permissions dp
                    WHERE dp.document_id = d.id
                      AND dp.user_id = $2
                      AND dp.permission IN ('read', 'edit')
                )
           )
         LIMIT 1`,
        [documentId, userId]
    );

    return result.rows[0] || null;
}

module.exports = {
    listAccessibleDocuments,
    getDocumentAccess,
    escapeLikePattern
};
