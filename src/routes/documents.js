const express = require("express");
const multer = require("multer");
const path = require("node:path");
const { requireAuth } = require("../middleware/auth");
const pool = require("../db");
const {
    resolveDocumentAccess,
    resolveDocumentAccessForWrite,
    lockActiveActorForWrite
} = require("../services/accessService");
const { writeAuditLog, lockAuditChain } = require("../services/auditService");
const {
    saveTemporaryFile,
    getFileBuffer,
    deleteFile,
    removeStoredFile,
    isValidStorageKey
} = require("../services/storage");
const {
    listAccessibleDocuments,
    getDocumentAccess
} = require("../services/documentService");

const router = express.Router();

const MAX_FILE_SIZE = 5 * 1024 * 1024;
const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ALLOWED_PERMISSIONS = new Set(["read", "edit"]);

/** Only these account types may create new documents. */
const UPLOAD_ROLES = new Set(["document_owner"]);

function normalizePermission(perm) {
    if (perm === "view" || perm === "download") return "read";
    return perm;
}

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: MAX_FILE_SIZE,
        files: 1,
        fields: 10,
        fieldSize: 10 * 1024
    }
});

function validUuid(id) {
    return typeof id === "string" && UUID_PATTERN.test(id);
}

function safeOriginalFilename(filename) {
    const base = path.basename(String(filename || "document").replace(/[\\/]/g, "/"));
    const cleaned = base.replace(/[\u0000-\u001f\u007f"<>|:*?]/g, "").trim();
    return cleaned.slice(0, 255) || "download";
}

function setNoCacheHeaders(res) {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
}

/**
 * Parses a positive integer query parameter.
 * Returns `undefined` when the parameter is absent, `null` when it is
 * present but malformed (the caller answers 400 in that case).
 */
function parsePositiveInt(value) {
    if (value === undefined || value === null || value === "") {
        return undefined;
    }

    if (typeof value !== "string" && typeof value !== "number") {
        return null;
    }

    const raw = String(value).trim();

    if (!/^\d+$/.test(raw)) {
        return null;
    }

    const parsed = Number.parseInt(raw, 10);

    if (!Number.isSafeInteger(parsed) || parsed < 1) {
        return null;
    }

    return parsed;
}

/**
 * Parses an ISO-8601 date. Returns `undefined` when absent and `null` when
 * the value is not a valid date (the caller answers 400 in that case).
 */
function parseDate(value) {
    if (value === undefined || value === null || value === "") {
        return undefined;
    }

    if (typeof value !== "string") {
        return null;
    }

    const trimmed = value.trim();

    if (!/^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?$/.test(trimmed)) {
        return null;
    }

    const parsed = new Date(trimmed);

    if (Number.isNaN(parsed.getTime())) {
        return null;
    }

    return parsed;
}

async function detectAllowedFileType(buffer) {
    if (!Buffer.isBuffer(buffer) || buffer.length < 8) {
        return null;
    }

    const allowedTypes = new Set([
        "application/pdf",
        "image/jpeg",
        "image/png"
    ]);

    try {
        const { fileTypeFromBuffer } = await import("file-type");
        const detected = await fileTypeFromBuffer(buffer);
        if (detected && allowedTypes.has(detected.mime)) {
            return detected.mime;
        }
        if (detected && !allowedTypes.has(detected.mime)) {
            return null;
        }
    } catch {}

    if (
        buffer[0] === 0x25 &&
        buffer[1] === 0x50 &&
        buffer[2] === 0x44 &&
        buffer[3] === 0x46 &&
        buffer[4] === 0x2d
    ) {
        return "application/pdf";
    }

    if (
        buffer[0] === 0x89 &&
        buffer[1] === 0x50 &&
        buffer[2] === 0x4e &&
        buffer[3] === 0x47 &&
        buffer[4] === 0x0d &&
        buffer[5] === 0x0a &&
        buffer[6] === 0x1a &&
        buffer[7] === 0x0a
    ) {
        return "image/png";
    }

    if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
        return "image/jpeg";
    }

    return null;
}

/**
 * The document id that may safely be written to an audit row.
 * `audit_logs.document_id` is a foreign key, so it may only be set for
 * documents that really exist.
 */
function auditDocumentId(access, requestedId) {
    return access && access.exists ? requestedId : null;
}

function handleMulterUpload(req, res, next) {
    upload.single("file")(req, res, (error) => {
        if (!error) return next();

        if (error instanceof multer.MulterError) {
            const status = error.code === "LIMIT_FILE_SIZE" ? 413 : 400;
            return res.status(status).json({
                message: error.code === "LIMIT_FILE_SIZE"
                    ? "File exceeds the 5 MB limit"
                    : "Invalid upload request"
            });
        }

        return res.status(400).json({
            message: "Unable to process upload"
        });
    });
}

// ── POST /api/documents — Upload a document (Document Owner only) ─────────────
router.post(
    "/",
    requireAuth,
    async (req, res, next) => {
        if (!UPLOAD_ROLES.has(req.user.role)) {
            await writeAuditLog(req, "document_upload", "denied", null, {
                reason: "insufficient_role",
                role: req.user.role
            });
            return res.status(403).json({
                message: "Access denied: only document owners can upload documents"
            });
        }
        return next();
    },
    handleMulterUpload,
    async (req, res) => {
        let storedFile = null;

        try {
            if (!req.file) {
                return res.status(400).json({
                    message: "A file is required"
                });
            }

            // Reject empty uploads explicitly: the `file_size > 0` database
            // constraint would otherwise surface as an opaque 500.
            if (!req.file.buffer || req.file.buffer.length === 0) {
                await writeAuditLog(req, "document_upload", "denied", null, {
                    reason: "empty_file",
                    originalFilename: safeOriginalFilename(req.file.originalname)
                });

                return res.status(400).json({
                    message: "The uploaded file is empty"
                });
            }

            const name =
                typeof req.body.name === "string"
                    ? req.body.name.trim()
                    : "";

            const category =
                typeof req.body.category === "string" && req.body.category.trim()
                    ? req.body.category.trim()
                    : "General";

            const description =
                typeof req.body.description === "string"
                    ? req.body.description.trim()
                    : null;

            if (
                !name ||
                name.length > 255 ||
                category.length > 100 ||
                (description !== null && description.length > 2000)
            ) {
                return res.status(400).json({
                    message: "Invalid document name, category, or description"
                });
            }

            const detectedMime = await detectAllowedFileType(req.file.buffer);

            if (!detectedMime) {
                await writeAuditLog(req, "document_upload", "denied", null, {
                    reason: "unsupported_or_spoofed_file_type",
                    originalFilename: safeOriginalFilename(req.file.originalname)
                });

                return res.status(415).json({
                    message: "Only valid PDF, JPEG, and PNG files are allowed"
                });
            }

            const client = await pool.connect();
            let document;

            try {
                await client.query("BEGIN");

                // Take the audit-chain lock before any row locks so that every
                // transaction acquires the locks in the same order.
                await lockAuditChain(client);

                // The role check above ran before Multer parsed the request.
                // Re-read the actor inside the transaction so a concurrent
                // disable or demotion cannot be bypassed by a slow upload.
                const actor = await lockActiveActorForWrite(client, req.user.id, {
                    roles: UPLOAD_ROLES
                });

                if (!actor) {
                    await client.query("ROLLBACK");
                    await writeAuditLog(req, "document_upload", "denied", null, {
                        reason: "role_or_status_changed_during_upload"
                    });
                    return res.status(403).json({
                        message: "Access denied: only document owners can upload documents"
                    });
                }

                storedFile = await saveTemporaryFile(req.file.buffer, client);

                const inserted = await client.query(
                    `INSERT INTO documents
                        (owner_id, name, category, description, storage_key,
                         original_filename, content_type, file_size)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                     RETURNING id, owner_id, name, category, description,
                               original_filename, content_type, file_size,
                               created_at, updated_at`,
                    [
                        req.user.id,
                        name,
                        category,
                        description,
                        storedFile.storageKey,
                        safeOriginalFilename(req.file.originalname),
                        detectedMime,
                        storedFile.size
                    ]
                );

                document = inserted.rows[0];
                document.access_level = "owner";

                await writeAuditLog(
                    req,
                    "document_upload",
                    "success",
                    document.id,
                    {
                        name: document.name,
                        category: document.category,
                        contentType: detectedMime,
                        fileSize: storedFile.size
                    },
                    null,
                    client
                );

                await client.query("COMMIT");
            } catch (error) {
                await client.query("ROLLBACK").catch(() => {});
                throw error;
            } finally {
                client.release();
            }

            return res.status(201).json({ document });
        } catch (error) {
            if (storedFile) {
                await deleteFile(storedFile.storageKey).catch(() => {});
            }

            console.error("Document upload failed:", error.message);

            return res.status(500).json({
                message: "Unable to upload document"
            });
        }
    }
);

// ── GET /api/documents — List & search documents ─────────────────────────────
router.get("/", requireAuth, async (req, res) => {
    try {
        setNoCacheHeaders(res);

        // Pagination: default 50 per page, max 200
        const rawLimit = parsePositiveInt(req.query.limit);
        const rawPage = parsePositiveInt(req.query.page);

        if (rawLimit === null || rawPage === null) {
            return res.status(400).json({
                message: "limit and page must be positive integers"
            });
        }

        const limit = Math.min(rawLimit || 50, 200);
        const page = rawPage || 1;

        // Date filters must be valid ISO-8601 dates; a silently ignored
        // filter would return results the caller did not ask for.
        const fromDate = parseDate(req.query.from);
        const toDate = parseDate(req.query.to);

        if (fromDate === null || toDate === null) {
            return res.status(400).json({
                message: "from and to must be valid ISO-8601 dates"
            });
        }

        // A date-only `to` means the whole UTC day, not midnight at its start.
        // Expand it before the range check and before the value is passed to
        // the query builder, which otherwise receives an ISO timestamp.
        const rawTo = typeof req.query.to === "string" ? req.query.to.trim() : "";
        if (toDate && /^\d{4}-\d{2}-\d{2}$/.test(rawTo)) {
            toDate.setUTCHours(23, 59, 59, 999);
        }

        if (fromDate && toDate && fromDate.getTime() > toDate.getTime()) {
            return res.status(400).json({
                message: "from must not be later than to"
            });
        }

        // `shared=true` returns only the documents that other people shared
        // with the caller. Anything else is rejected instead of being
        // silently ignored, so the client never sees a list it did not ask
        // for.
        const rawShared = req.query.shared;
        let sharedOnly = false;

        if (rawShared !== undefined && rawShared !== null && rawShared !== "") {
            const normalized = String(rawShared).trim().toLowerCase();

            if (normalized !== "true" && normalized !== "false") {
                return res.status(400).json({
                    message: "shared must be true or false"
                });
            }

            sharedOnly = normalized === "true";
        }

        // `owned=true` returns only the documents the caller owns. It is the
        // server-side filter behind the "My documents" screen.
        const rawOwned = req.query.owned;
        let ownedOnly = false;

        if (rawOwned !== undefined && rawOwned !== null && rawOwned !== "") {
            const normalized = String(rawOwned).trim().toLowerCase();

            if (normalized !== "true" && normalized !== "false") {
                return res.status(400).json({
                    message: "owned must be true or false"
                });
            }

            ownedOnly = normalized === "true";
        }

        const filters = {
            q: typeof req.query.q === "string" ? req.query.q : (typeof req.query.name === "string" ? req.query.name : ""),
            category: typeof req.query.category === "string" ? req.query.category : "",
            owner: typeof req.query.owner === "string" ? req.query.owner : "",
            from: fromDate ? fromDate.toISOString() : "",
            to: toDate ? toDate.toISOString() : "",
            shared: sharedOnly,
            owned: ownedOnly,
            limit,
            page
        };

        const documents = await listAccessibleDocuments(req.user.id, filters);
        await writeAuditLog(req, "document_list", "success", null, {
            filterCount: Object.values(filters).filter(Boolean).length,
            resultCount: documents.length,
            page,
            limit
        });

        return res.json({ documents, page, limit, count: documents.length });
    } catch (error) {
        console.error("Document listing failed:", error.message);

        return res.status(500).json({
            message: "Unable to retrieve documents"
        });
    }
});

// ── GET /api/documents/filters — Filter options for the list screens ─────────
// The category and owner dropdowns are filled with the values that really
// occur in the documents the caller may open. Nothing is hard-coded in the
// browser and no option is offered that would return an empty list by
// construction.
router.get("/filters", requireAuth, async (req, res) => {
    try {
        setNoCacheHeaders(res);

        const result = await pool.query(
            `SELECT DISTINCT d.category, u.name AS owner_name, u.email AS owner_email
             FROM documents d
             JOIN users u ON u.id = d.owner_id
             JOIN users account ON account.id = $1
             WHERE account.is_disabled = false
               AND (
                (account.role = 'document_owner' AND d.owner_id = $1)
                OR EXISTS (
                    SELECT 1 FROM document_permissions dp
                    WHERE dp.document_id = d.id
                      AND dp.user_id = $1
                      AND dp.permission IN ('read', 'edit')
                )
             )
             ORDER BY d.category ASC, u.email ASC`,
            [req.user.id]
        );

        const categories = [];
        const owners = [];
        const seenCategories = new Set();
        const seenOwners = new Set();

        result.rows.forEach((row) => {
            if (row.category && !seenCategories.has(row.category)) {
                seenCategories.add(row.category);
                categories.push(row.category);
            }
            if (row.owner_email && !seenOwners.has(row.owner_email)) {
                seenOwners.add(row.owner_email);
                owners.push({ name: row.owner_name, email: row.owner_email });
            }
        });

        return res.json({ categories, owners });
    } catch (error) {
        console.error("Document filter options failed:", error.message);
        return res.status(500).json({ message: "Unable to retrieve filter options" });
    }
});

// ── GET /api/documents/summary — Dashboard counters for the document owner ───
// Every number on the owner's dashboard comes from this single aggregated
// query. Nothing is estimated in the browser: the counters are counts over
// the real rows in the database.
//
// The route is declared before "/:id" so that the literal path wins over the
// parameterised one.
router.get("/summary", requireAuth, async (req, res) => {
    try {
        setNoCacheHeaders(res);

        // The dashboard aggregates Owner-only management data. A Viewer whose
        // former documents now carry legacy Read grants must not see it.
        if (req.user.role !== "document_owner") {
            return res.status(403).json({
                message: "Access denied: document owner role required"
            });
        }

        const userId = req.user.id;

        const [statsResult, activityResult, categoriesResult] = await Promise.all([
            pool.query(
                `SELECT
                    (SELECT COUNT(*)::int FROM documents d WHERE d.owner_id = $1) AS owned_count,
                    (SELECT COUNT(*)::int FROM document_permissions dp
                       JOIN documents d2 ON d2.id = dp.document_id
                      WHERE d2.owner_id = $1) AS shared_with_others_count,
                    (SELECT COUNT(DISTINCT dp.document_id)::int FROM document_permissions dp
                      WHERE dp.user_id = $1 AND dp.permission IN ('read', 'edit')) AS shared_with_me_count,
                    (SELECT COUNT(*)::int FROM audit_logs al
                       JOIN documents d3 ON d3.id = al.document_id
                      WHERE d3.owner_id = $1 AND al.outcome = 'denied') AS refused_attempts_count,
                    (SELECT COUNT(*)::int FROM audit_logs al
                       JOIN documents d4 ON d4.id = al.document_id
                      WHERE d4.owner_id = $1) AS activity_count`,
                [userId]
            ),
            pool.query(
                `SELECT al.id, al.action, al.outcome, al.created_at, al.document_id,
                        d.name AS document_name,
                        actor.name AS actor_name,
                        actor.email AS actor_email,
                        actor.role AS actor_role
                 FROM audit_logs al
                 JOIN documents d ON d.id = al.document_id
                 LEFT JOIN users actor ON actor.id = al.actor_id
                 WHERE d.owner_id = $1
                 ORDER BY al.id DESC
                 LIMIT 8`,
                [userId]
            ),
            pool.query(
                `SELECT DISTINCT d.category
                 FROM documents d
                 WHERE d.owner_id = $1
                   AND d.category IS NOT NULL
                   AND d.category <> ''
                 ORDER BY d.category ASC`,
                [userId]
            )
        ]);

        const stats = statsResult.rows[0];

        return res.json({
            stats: {
                ownedDocuments: stats.owned_count,
                sharedWithOthers: stats.shared_with_others_count,
                sharedWithMe: stats.shared_with_me_count,
                refusedAttempts: stats.refused_attempts_count,
                totalActivityEvents: stats.activity_count
            },
            recentActivity: activityResult.rows,
            categories: categoriesResult.rows.map((row) => row.category)
        });
    } catch (error) {
        console.error("Document summary failed:", error.message);
        return res.status(500).json({ message: "Unable to retrieve dashboard summary" });
    }
});

// ── GET /api/documents/:id/permissions — List grants (Owner only) ────────────
router.get("/:id/permissions", requireAuth, async (req, res) => {
    const documentId = req.params.id;
    if (!validUuid(documentId)) {
        return res.status(404).json({ message: "Document not found" });
    }

    try {
        setNoCacheHeaders(res);

        const access = await resolveDocumentAccess(req.user, documentId);

        if (!access.canManage) {
            await writeAuditLog(req, "document_permissions_view", "denied", auditDocumentId(access, documentId), {
                requestedDocumentId: documentId,
                reason: access.exists ? "not_document_owner" : "document_not_found"
            });
            return res.status(404).json({ message: "Document not found" });
        }

        const result = await pool.query(
            `SELECT
                dp.id,
                dp.document_id,
                dp.user_id,
                u.name AS user_name,
                u.email AS user_email,
                u.role AS user_role,
                dp.permission,
                dp.created_at
             FROM document_permissions dp
             JOIN users u ON u.id = dp.user_id
             WHERE dp.document_id = $1
             ORDER BY dp.created_at DESC`,
            [documentId]
        );

        return res.json({ permissions: result.rows });
    } catch (error) {
        console.error("Permissions listing failed:", error.message);
        return res.status(500).json({ message: "Unable to retrieve permissions" });
    }
});

// ── POST /api/documents/:id/permissions — Grant access (Owner only) ──────────
router.post("/:id/permissions", requireAuth, async (req, res) => {
    const documentId = req.params.id;
    const email =
        typeof req.body?.email === "string"
            ? req.body.email.trim().toLowerCase()
            : "";
    const rawPermission = req.body?.permission;
    const permission = normalizePermission(rawPermission);

    if (!validUuid(documentId)) {
        return res.status(404).json({ message: "Document not found" });
    }

    if (
        !email ||
        email.length > 255 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        !ALLOWED_PERMISSIONS.has(permission)
    ) {
        return res.status(400).json({
            message: "Provide a valid email and permission: read or edit"
        });
    }

    let client;

    try {
        const access = await resolveDocumentAccess(req.user, documentId);

        if (!access.canManage) {
            await writeAuditLog(
                req,
                "document_permission_grant",
                "denied",
                auditDocumentId(access, documentId),
                {
                    requestedDocumentId: documentId,
                    reason: access.exists ? "not_document_owner" : "document_not_found",
                    permission
                }
            );

            return res.status(404).json({ message: "Document not found" });
        }

        const targetResult = await pool.query(
            `SELECT id, name, email
             FROM users
             WHERE lower(email) = $1
             LIMIT 1`,
            [email]
        );

        if (
            targetResult.rows.length === 0 ||
            targetResult.rows[0].id === req.user.id
        ) {
            await writeAuditLog(
                req,
                "document_permission_grant",
                "denied",
                documentId,
                { reason: "invalid_or_self_recipient", permission, email }
            );

            return res.status(400).json({
                message: "Recipient not found or cannot be shared with yourself"
            });
        }

        const target = targetResult.rows[0];

        if (target.id === access.documentOwnerId) {
            return res.status(400).json({
                message: "The document owner already has full access"
            });
        }

        client = await pool.connect();

        try {
            await client.query("BEGIN");
            await lockAuditChain(client);

            // Re-check the owner privilege after the account and document
            // rows are locked. A concurrent demotion, disable or deletion
            // must not be able to slip between the pre-check and this write.
            const lockedAccess = await resolveDocumentAccessForWrite(
                client,
                req.user,
                documentId
            );

            if (!lockedAccess.canManage) {
                await client.query("ROLLBACK");
                await writeAuditLog(
                    req,
                    "document_permission_grant",
                    "denied",
                    auditDocumentId(lockedAccess, documentId),
                    {
                        requestedDocumentId: documentId,
                        reason: lockedAccess.exists
                            ? "not_document_owner"
                            : "document_not_found",
                        permission
                    }
                );
                return res.status(404).json({ message: "Document not found" });
            }

            // Atomic upsert: a user can only hold one permission level per
            // document, so granting "edit" replaces an existing "read" grant
            // instead of creating a second, conflicting row.
            const granted = await client.query(
                `INSERT INTO document_permissions
                    (document_id, user_id, permission, granted_by)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (document_id, user_id)
                 DO UPDATE
                 SET permission = EXCLUDED.permission,
                     granted_by = EXCLUDED.granted_by,
                     created_at = NOW()
                 RETURNING id, document_id, user_id, permission, created_at`,
                [documentId, target.id, permission, req.user.id]
            );

            await writeAuditLog(
                req,
                "document_permission_grant",
                "success",
                documentId,
                { permission, recipientEmail: target.email },
                target.id,
                client
            );

            await client.query("COMMIT");

            return res.status(200).json({
                message: "Permission granted",
                documentId,
                user: { id: target.id, name: target.name, email: target.email },
                permission: granted.rows[0].permission
            });
        } catch (error) {
            await client.query("ROLLBACK").catch(() => {});
            throw error;
        }
    } catch (error) {
        console.error("Permission grant failed:", error.message);

        return res.status(500).json({
            message: "Unable to grant permission"
        });
    } finally {
        if (client) client.release();
    }
});

// ── DELETE /api/documents/:id/permissions/:userId[/:permission] — Revoke ─────
async function handleRevokePermission(req, res) {
    const { id: documentId, userId } = req.params;
    const rawPermission = req.params.permission;
    const permission = rawPermission ? normalizePermission(rawPermission) : null;

    if (
        !validUuid(documentId) ||
        !validUuid(userId) ||
        (permission !== null && !ALLOWED_PERMISSIONS.has(permission))
    ) {
        return res.status(404).json({
            message: "Permission not found"
        });
    }

    let client;

    try {
        const access = await resolveDocumentAccess(req.user, documentId);

        if (!access.canManage) {
            await writeAuditLog(
                req,
                "document_permission_revoke",
                "denied",
                auditDocumentId(access, documentId),
                {
                    requestedDocumentId: documentId,
                    userId,
                    permission,
                    reason: access.exists ? "not_document_owner" : "document_not_found"
                }
            );

            return res.status(404).json({
                message: "Permission not found"
            });
        }

        if (userId === access.documentOwnerId) {
            return res.status(400).json({
                message: "The document owner's access cannot be revoked"
            });
        }

        client = await pool.connect();

        try {
            await client.query("BEGIN");
            await lockAuditChain(client);

            const lockedAccess = await resolveDocumentAccessForWrite(
                client,
                req.user,
                documentId
            );

            if (!lockedAccess.canManage) {
                await client.query("ROLLBACK");
                await writeAuditLog(
                    req,
                    "document_permission_revoke",
                    "denied",
                    auditDocumentId(lockedAccess, documentId),
                    {
                        requestedDocumentId: documentId,
                        userId,
                        permission,
                        reason: lockedAccess.exists
                            ? "not_document_owner"
                            : "document_not_found"
                    }
                );
                return res.status(404).json({ message: "Permission not found" });
            }

            if (userId === lockedAccess.documentOwnerId) {
                await client.query("ROLLBACK");
                return res.status(400).json({
                    message: "The document owner's access cannot be revoked"
                });
            }

            const deleted = permission
                ? await client.query(
                      `DELETE FROM document_permissions
                       WHERE document_id = $1
                         AND user_id = $2
                         AND permission = $3
                       RETURNING user_id, permission`,
                      [documentId, userId, permission]
                  )
                : await client.query(
                      `DELETE FROM document_permissions
                       WHERE document_id = $1
                         AND user_id = $2
                       RETURNING user_id, permission`,
                      [documentId, userId]
                  );

            if (deleted.rows.length === 0) {
                await client.query("ROLLBACK");

                await writeAuditLog(
                    req,
                    "document_permission_revoke",
                    "denied",
                    documentId,
                    { reason: "permission_not_found", permission },
                    userId
                );

                return res.status(404).json({
                    message: "Permission not found"
                });
            }

            await writeAuditLog(
                req,
                "document_permission_revoke",
                "success",
                documentId,
                { revokedPermissions: deleted.rows.map((r) => r.permission) },
                userId,
                client
            );

            await client.query("COMMIT");

            return res.json({
                message: "Permission revoked",
                documentId,
                userId,
                permission: deleted.rows[0].permission
            });
        } catch (error) {
            await client.query("ROLLBACK").catch(() => {});
            throw error;
        }
    } catch (error) {
        console.error("Permission revocation failed:", error.message);

        return res.status(500).json({
            message: "Unable to revoke permission"
        });
    } finally {
        if (client) client.release();
    }
}

router.delete("/:id/permissions/:userId/:permission", requireAuth, handleRevokePermission);
router.delete("/:id/permissions/:userId", requireAuth, handleRevokePermission);

// ── GET /api/documents/:id/download — Download (live permission check) ───────
router.get("/:id/download", requireAuth, async (req, res) => {
    const documentId = req.params.id;

    if (!validUuid(documentId)) {
        return res.status(404).json({ message: "Document not found" });
    }

    try {
        setNoCacheHeaders(res);

        const access = await resolveDocumentAccess(req.user, documentId);

        if (!access.canDownload) {
            await writeAuditLog(req, "document_download", "denied", auditDocumentId(access, documentId), {
                requestedDocumentId: documentId,
                reason: access.exists ? "insufficient_permission" : "document_not_found"
            });

            return res.status(404).json({ message: "Document not found" });
        }

        const document = await getDocumentAccess(documentId, req.user.id);

        if (!document) {
            return res.status(404).json({ message: "Document not found" });
        }

        const storageResult = await pool.query(
            "SELECT storage_key, content_type, original_filename FROM documents WHERE id = $1",
            [documentId]
        );

        if (!storageResult.rows[0]) {
            return res.status(404).json({ message: "Document not found" });
        }

        const { storage_key, content_type, original_filename } = storageResult.rows[0];

        // The storage key is generated by the application and is always a
        // UUID. A key that does not match the pattern was tampered with in
        // the database; the file system is not touched in that case, which
        // makes a path traversal impossible.
        if (!isValidStorageKey(storage_key)) {
            console.error("Refusing to serve a document with an invalid storage key");
            return res.status(404).json({ message: "Document not found" });
        }

        const fileBuffer = await getFileBuffer(storage_key);

        await writeAuditLog(req, "document_download", "success", documentId, {
            accessLevel: document.access_level
        });

        const safeName = safeOriginalFilename(original_filename);
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("Content-Type", content_type || "application/octet-stream");
        res.setHeader(
            "Content-Disposition",
            `attachment; filename="${safeName.replace(/"/g, "")}"`
        );
        res.setHeader("Content-Length", String(fileBuffer.length));

        return res.send(fileBuffer);
    } catch (error) {
        console.error("Document download failed:", error.message);

        if (!res.headersSent) {
            return res.status(500).json({
                message: "Unable to download document"
            });
        }
    }
});

// ── GET /api/documents/:id — Read document metadata ──────────────────────────
router.get("/:id", requireAuth, async (req, res) => {
    const documentId = req.params.id;

    if (!validUuid(documentId)) {
        return res.status(404).json({ message: "Document not found" });
    }

    try {
        setNoCacheHeaders(res);

        const access = await resolveDocumentAccess(req.user, documentId);

        if (!access.canRead) {
            await writeAuditLog(req, "document_read", "denied", auditDocumentId(access, documentId), {
                requestedDocumentId: documentId,
                reason: access.exists ? "insufficient_permission" : "document_not_found"
            });

            return res.status(404).json({ message: "Document not found" });
        }

        const document = await getDocumentAccess(documentId, req.user.id);

        if (!document) {
            return res.status(404).json({ message: "Document not found" });
        }

        await writeAuditLog(req, "document_read", "success", documentId, {
            accessLevel: document.access_level
        });

        return res.json({ document });
    } catch (error) {
        console.error("Document retrieval failed:", error.message);

        return res.status(500).json({
            message: "Unable to retrieve document"
        });
    }
});

// ── PUT /api/documents/:id — Edit metadata or replace file (Owner or editor) ─
router.put("/:id", requireAuth, handleMulterUpload, async (req, res) => {
    const documentId = req.params.id;

    if (!validUuid(documentId)) {
        return res.status(404).json({ message: "Document not found" });
    }

    let newStoredFile = null;
    let newStorageKey = null;

    try {
        const access = await resolveDocumentAccess(req.user, documentId);

        if (!access.canEdit) {
            await writeAuditLog(
                req,
                "document_edit",
                "denied",
                auditDocumentId(access, documentId),
                {
                    requestedDocumentId: documentId,
                    reason: access.canRead ? "read_only_user_attempted_edit" : "unauthorized_user"
                }
            );

            return res.status(access.canRead ? 403 : 404).json({
                message: access.canRead
                    ? "Access denied: edit permission is required to modify this document"
                    : "Document not found"
            });
        }

        let detectedMime = null;

        if (req.file) {
            if (!req.file.buffer || req.file.buffer.length === 0) {
                return res.status(400).json({
                    message: "The uploaded file is empty"
                });
            }

            detectedMime = await detectAllowedFileType(req.file.buffer);
            if (!detectedMime) {
                await writeAuditLog(req, "document_edit", "denied", documentId, {
                    reason: "unsupported_or_spoofed_file_type"
                });
                return res.status(415).json({
                    message: "Only valid PDF, JPEG, and PNG files are allowed"
                });
            }
        }

        let oldStorageKey = null;
        const client = await pool.connect();
        try {
            await client.query("BEGIN");
            await lockAuditChain(client);

            // Re-check edit access after locking the actor and the document.
            // A revoked grant, demotion, disable or concurrent deletion must
            // not be bypassed by the earlier read-only pre-check.
            const lockedAccess = await resolveDocumentAccessForWrite(
                client,
                req.user,
                documentId
            );

            if (!lockedAccess.canEdit) {
                await client.query("ROLLBACK");
                await writeAuditLog(
                    req,
                    "document_edit",
                    "denied",
                    auditDocumentId(lockedAccess, documentId),
                    {
                        requestedDocumentId: documentId,
                        reason: lockedAccess.canRead
                            ? "read_only_user_attempted_edit"
                            : "unauthorized_user"
                    }
                );
                return res.status(lockedAccess.canRead ? 403 : 404).json({
                    message: lockedAccess.canRead
                        ? "Access denied: edit permission is required to modify this document"
                        : "Document not found"
                });
            }

            const existingResult = await client.query(
                "SELECT * FROM documents WHERE id = $1 LIMIT 1",
                [documentId]
            );
            if (existingResult.rows.length === 0) {
                await client.query("ROLLBACK");
                return res.status(404).json({ message: "Document not found" });
            }
            const existing = existingResult.rows[0];
            oldStorageKey = existing.storage_key;

            const updatedName =
                typeof req.body?.name === "string" && req.body.name.trim()
                    ? req.body.name.trim()
                    : existing.name;
            const updatedCategory =
                typeof req.body?.category === "string" && req.body.category.trim()
                    ? req.body.category.trim()
                    : existing.category;
            const updatedDescription =
                typeof req.body?.description === "string"
                    ? req.body.description.trim()
                    : existing.description;

            if (
                !updatedName ||
                updatedName.length > 255 ||
                updatedCategory.length > 100 ||
                (updatedDescription !== null && updatedDescription.length > 2000)
            ) {
                await client.query("ROLLBACK");
                return res.status(400).json({
                    message: "Invalid document name, category, or description"
                });
            }

            let newMime = existing.content_type;
            let newOriginalFilename = existing.original_filename;
            let newFileSize = existing.file_size;
            newStorageKey = existing.storage_key;

            if (req.file) {
                newStoredFile = await saveTemporaryFile(req.file.buffer, client);
                newStorageKey = newStoredFile.storageKey;
                newFileSize = newStoredFile.size;
                newMime = detectedMime;
                newOriginalFilename = safeOriginalFilename(req.file.originalname);
            }

            await client.query(
                `UPDATE documents
                 SET name = $1,
                     category = $2,
                     description = $3,
                     storage_key = $4,
                     original_filename = $5,
                     content_type = $6,
                     file_size = $7,
                     updated_at = NOW()
                 WHERE id = $8`,
                [
                    updatedName,
                    updatedCategory,
                    updatedDescription,
                    newStorageKey,
                    newOriginalFilename,
                    newMime,
                    newFileSize,
                    documentId
                ]
            );

            await writeAuditLog(
                req,
                "document_edit",
                "success",
                documentId,
                {
                    name: updatedName,
                    category: updatedCategory,
                    fileReplaced: Boolean(req.file)
                },
                null,
                client
            );

            await client.query("COMMIT");
        } catch (error) {
            await client.query("ROLLBACK").catch(() => {});
            throw error;
        } finally {
            client.release();
        }

        if (req.file && oldStorageKey && oldStorageKey !== newStorageKey) {
            await deleteFile(oldStorageKey).catch(() => {});
        }

        const updatedDoc = await getDocumentAccess(documentId, req.user.id);
        return res.json({
            message: "Document updated",
            document: updatedDoc
        });
    } catch (error) {
        if (newStoredFile) {
            await deleteFile(newStoredFile.storageKey).catch(() => {});
        }
        console.error("Document update failed:", error.message);
        return res.status(500).json({ message: "Unable to update document" });
    }
});

// ── DELETE /api/documents/:id — Delete (Owner only) ──────────────────────────
router.delete("/:id", requireAuth, async (req, res) => {
    const documentId = req.params.id;

    if (!validUuid(documentId)) {
        return res.status(404).json({ message: "Document not found" });
    }

    try {
        const access = await resolveDocumentAccess(req.user, documentId);

        if (!access.canDelete) {
            await writeAuditLog(
                req,
                "document_delete",
                "denied",
                auditDocumentId(access, documentId),
                {
                    requestedDocumentId: documentId,
                    reason: access.exists ? "non_owner_attempted_delete" : "unauthorized_user"
                }
            );

            return res.status(access.canRead ? 403 : 404).json({
                message: access.canRead
                    ? "Access denied: only the document owner can delete this document"
                    : "Document not found"
            });
        }

        let existing = null;
        const client = await pool.connect();
        try {
            await client.query("BEGIN");
            await lockAuditChain(client);

            // The earlier access check is only a fast path. Re-check after
            // locking the actor and the document so a demotion, disable,
            // grant change or concurrent deletion cannot race this write.
            const lockedAccess = await resolveDocumentAccessForWrite(
                client,
                req.user,
                documentId
            );

            if (!lockedAccess.canDelete) {
                await client.query("ROLLBACK");
                await writeAuditLog(
                    req,
                    "document_delete",
                    "denied",
                    auditDocumentId(lockedAccess, documentId),
                    {
                        requestedDocumentId: documentId,
                        reason: lockedAccess.exists
                            ? "non_owner_attempted_delete"
                            : "unauthorized_user"
                    }
                );
                return res.status(lockedAccess.canRead ? 403 : 404).json({
                    message: lockedAccess.canRead
                        ? "Access denied: only the document owner can delete this document"
                        : "Document not found"
                });
            }

            const existingResult = await client.query(
                "SELECT id, name, storage_key FROM documents WHERE id = $1 LIMIT 1",
                [documentId]
            );
            if (existingResult.rows.length === 0) {
                await client.query("ROLLBACK");
                return res.status(404).json({ message: "Document not found" });
            }
            existing = existingResult.rows[0];

            await writeAuditLog(
                req,
                "document_delete",
                "success",
                documentId,
                { deletedDocumentName: existing.name },
                null,
                client
            );

            // Remove the metadata (which cascades the grants) and the blob
            // row in the same transaction. The blob row is deleted after the
            // document so the documents.storage_key foreign key cannot cascade
            // the document itself.
            await client.query("DELETE FROM documents WHERE id = $1", [documentId]);
            await client.query(
                "DELETE FROM document_blobs WHERE storage_key = $1",
                [existing.storage_key]
            );

            await client.query("COMMIT");
        } catch (error) {
            await client.query("ROLLBACK").catch(() => {});
            throw error;
        } finally {
            client.release();
        }

        // The database no longer references the file. The filesystem unlink is
        // a post-commit step: if it fails, the document is still permanently
        // deleted but an orphaned file may remain, so the response must not
        // claim that cleanup completed.
        const cleanup = await removeStoredFile(existing.storage_key);
        if (!cleanup.removed) {
            console.error("Document file cleanup pending:", cleanup.reason);
        }

        return res.json({
            message: cleanup.removed
                ? "Document deleted"
                : "Document deleted; the stored file could not be removed and requires cleanup",
            documentId,
            storageCleanup: cleanup.removed ? "complete" : "pending"
        });
    } catch (error) {
        console.error("Document deletion failed:", error.message);
        return res.status(500).json({ message: "Unable to delete document" });
    }
});

// ── GET /api/documents/:id/audit — Owner-scoped audit log ────────────────────
router.get("/:id/audit", requireAuth, async (req, res) => {
    const documentId = req.params.id;

    if (!validUuid(documentId)) {
        return res.status(404).json({ message: "Document not found" });
    }

    try {
        setNoCacheHeaders(res);

        const access = await resolveDocumentAccess(req.user, documentId);

        // Only the document's owner may call this endpoint. Non-owners get a
        // 404 so that the existence of the document is not confirmed.
        if (!access.isOwner) {
            await writeAuditLog(req, "document_audit_view", "denied", auditDocumentId(access, documentId), {
                requestedDocumentId: documentId,
                reason: access.exists ? "not_document_owner" : "document_not_found"
            });
            return res.status(404).json({ message: "Document not found" });
        }

        const params = [documentId];
        const where = ["al.document_id = $1"];

        if (typeof req.query.before === "string" && /^\d+$/.test(req.query.before.trim())) {
            params.push(parseInt(req.query.before.trim(), 10));
            where.push("al.id < $" + params.length);
        }

        const limit = Math.min(
            Math.max(parseInt(req.query.limit || "50", 10) || 50, 1),
            200
        );
        params.push(limit);
        const limitIdx = "$" + params.length;

        const sql =
            "SELECT al.id, al.document_id, al.action, al.outcome, al.created_at, " +
            "actor.name AS actor_name, actor.email AS actor_email, actor.role AS actor_role, " +
            "al.ip_address, al.details " +
            "FROM audit_logs al " +
            "LEFT JOIN users actor ON actor.id = al.actor_id " +
            "WHERE " + where.join(" AND ") + " " +
            "ORDER BY al.id DESC LIMIT " + limitIdx;

        const result = await pool.query(sql, params);
        const logs = result.rows;

        return res.json({
            logs,
            documentId,
            nextCursor: logs.length === limit ? String(logs[logs.length - 1].id) : null
        });
    } catch (error) {
        console.error("Document audit log failed:", error.message);
        return res.status(500).json({ message: "Unable to retrieve audit log" });
    }
});

module.exports = router;
