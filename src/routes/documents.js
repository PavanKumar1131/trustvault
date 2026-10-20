
const express = require("express");
const multer = require("multer");
const path = require("node:path");
const { requireAuth, requireRole } = require("../middleware/auth");
const pool = require("../db");
const { canAccess } = require("../services/accessService");
const {
    saveTemporaryFile,
    getFilePath,
    deleteFile
} = require("../services/storage");
const {
    listAccessibleDocuments,
    getDocumentAccess
} = require("../services/documentService");

const router = express.Router();

const MAX_FILE_SIZE = 5 * 1024 * 1024;
const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ALLOWED_PERMISSIONS = new Set(["view", "download"]);

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: MAX_FILE_SIZE,
        files: 1,
        fields: 10,
        fieldSize: 10 * 1024
    }
});

async function writeAuditLog(
    req,
    action,
    outcome,
    documentId = null,
    details = {},
    targetUserId = null,
    db = pool
) {
    await db.query(
        `INSERT INTO audit_logs
            (actor_id, document_id, target_user_id, action, outcome,
             ip_address, user_agent, details)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [
            req.user.id,
            documentId,
            targetUserId,
            action,
            outcome,
            req.ip || null,
            req.get("user-agent") || null,
            JSON.stringify(details)
        ]
    );
}

function validDocumentId(id) {
    return typeof id === "string" && UUID_PATTERN.test(id);
}

function safeOriginalFilename(filename) {
    const base = path.basename(filename.replace(/\\/g, "/"));
    const cleaned = base.replace(/[\u0000-\u001f\u007f]/g, "").trim();

    return cleaned.slice(0, 255) || "download";
}

async function ownerCanManageSharing(req, documentId) {
    const result = await pool.query(
        "SELECT owner_id FROM documents WHERE id = $1",
        [documentId]
    );

    if (result.rows.length === 0) {
        return false;
    }

    return (
        result.rows[0].owner_id === req.user.id &&
        await canAccess(req.user, documentId, "share")
    );
}

// Upload: only administrators and document owners may upload.
router.post(
    "/",
    requireAuth,
    requireRole("admin", "document_owner"),
    (req, res, next) => {
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
    },
    async (req, res) => {
        let storedFile = null;

        try {
            if (!req.file) {
                return res.status(400).json({
                    message: "A file is required"
                });
            }

            const name =
                typeof req.body.name === "string"
                    ? req.body.name.trim()
                    : "";

            const category =
                typeof req.body.category === "string" &&
                    req.body.category.trim()
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

            const { fileTypeFromBuffer } = await import("file-type");
            const detectedType = await fileTypeFromBuffer(req.file.buffer);

            const allowedTypes = new Set([
                "application/pdf",
                "image/jpeg",
                "image/png"
            ]);

            if (!detectedType || !allowedTypes.has(detectedType.mime)) {
                await writeAuditLog(req, "document_upload", "denied", null, {
                    reason: "unsupported_file_type"
                });

                return res.status(415).json({
                    message: "Only PDF, JPEG, and PNG files are allowed"
                });
            }

            storedFile = await saveTemporaryFile(req.file.buffer);

            const client = await pool.connect();
            let document;

            try {
                await client.query("BEGIN");

                const inserted = await client.query(
                    `INSERT INTO documents
                        (owner_id, name, category, description, storage_key,
                         original_filename, content_type, file_size)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                     RETURNING id, owner_id, name, category, description,
                               original_filename, content_type, file_size,
                               created_at`,
                    [
                        req.user.id,
                        name,
                        category,
                        description,
                        storedFile.storageKey,
                        safeOriginalFilename(req.file.originalname),
                        detectedType.mime,
                        storedFile.size
                    ]
                );

                document = inserted.rows[0];

                await writeAuditLog(
                    req,
                    "document_upload",
                    "success",
                    document.id,
                    {
                        contentType: detectedType.mime,
                        fileSize: storedFile.size
                    },
                    null,
                    client
                );

                await client.query("COMMIT");
            } catch (error) {
                await client.query("ROLLBACK").catch(() => { });
                throw error;
            } finally {
                client.release();
            }

            return res.status(201).json({ document });
        } catch (error) {
            if (storedFile) {
                await deleteFile(storedFile.storageKey).catch((cleanupError) => {
                    console.error(
                        "Upload cleanup failed:",
                        cleanupError.message
                    );
                });
            }

            console.error("Document upload failed:", error.message);

            return res.status(500).json({
                message: "Unable to upload document"
            });
        }
    }
);

// List documents owned by the user or shared with them.
router.get("/", requireAuth, async (req, res) => {
    try {
        const documents = await listAccessibleDocuments(req.user.id);
        await writeAuditLog(req, "document_list", "success");

        return res.json({ documents });
    } catch (error) {
        console.error("Document listing failed:", error.message);

        return res.status(500).json({
            message: "Unable to retrieve documents"
        });
    }
});

// Grant a view or download permission to a registered user by email.
router.post("/:id/permissions", requireAuth, async (req, res) => {
    const documentId = req.params.id;
    const email =
        typeof req.body?.email === "string"
            ? req.body.email.trim().toLowerCase()
            : "";
    const permission = req.body?.permission;

    if (!validDocumentId(documentId)) {
        return res.status(404).json({ message: "Document not found" });
    }

    if (
        !email ||
        email.length > 255 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        !ALLOWED_PERMISSIONS.has(permission)
    ) {
        return res.status(400).json({
            message: "Provide a valid email and permission: view or download"
        });
    }

    let client;

    try {
        if (!(await ownerCanManageSharing(req, documentId))) {
            await writeAuditLog(
                req,
                "document_permission_grant",
                "denied",
                null,
                { requestedDocumentId: documentId, permission }
            );

            return res.status(404).json({ message: "Document not found" });
        }

        const targetResult = await pool.query(
            `SELECT id, email
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
                { reason: "invalid_or_self_recipient", permission }
            );

            return res.status(400).json({
                message: "Recipient not found or cannot be shared with yourself"
            });
        }

        const target = targetResult.rows[0];

        const documentResult = await pool.query(
            "SELECT owner_id FROM documents WHERE id = $1",
            [documentId]
        );

        if (target.id === documentResult.rows[0].owner_id) {
            return res.status(400).json({
                message: "The document owner already has access"
            });
        }

        client = await pool.connect();

        try {
            await client.query("BEGIN");

            await client.query(
                `INSERT INTO document_permissions
                    (document_id, user_id, permission, granted_by)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (document_id, user_id, permission) DO NOTHING`,
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
        } catch (error) {
            await client.query("ROLLBACK").catch(() => { });
            throw error;
        }

        return res.status(200).json({
            message: "Permission granted",
            documentId,
            user: { id: target.id, email: target.email },
            permission
        });
    } catch (error) {
        console.error("Permission grant failed:", error.message);

        return res.status(500).json({
            message: "Unable to grant permission"
        });
    } finally {
        if (client) client.release();
    }
});

// Revoke one specific permission from a user.
router.delete(
    "/:id/permissions/:userId/:permission",
    requireAuth,
    async (req, res) => {
        const { id: documentId, userId, permission } = req.params;

        if (
            !validDocumentId(documentId) ||
            !validDocumentId(userId) ||
            !ALLOWED_PERMISSIONS.has(permission)
        ) {
            return res.status(404).json({
                message: "Permission not found"
            });
        }

        let client;

        try {
            if (!(await ownerCanManageSharing(req, documentId))) {
                await writeAuditLog(
                    req,
                    "document_permission_revoke",
                    "denied",
                    null,
                    { requestedDocumentId: documentId, userId, permission }
                );

                return res.status(404).json({
                    message: "Permission not found"
                });
            }

            const documentResult = await pool.query(
                "SELECT owner_id FROM documents WHERE id = $1",
                [documentId]
            );

            if (documentResult.rows[0].owner_id === userId) {
                return res.status(400).json({
                    message: "The document owner's access cannot be revoked"
                });
            }

            client = await pool.connect();

            try {
                await client.query("BEGIN");

                const deleted = await client.query(
                    `DELETE FROM document_permissions
                     WHERE document_id = $1
                       AND user_id = $2
                       AND permission = $3
                     RETURNING user_id`,
                    [documentId, userId, permission]
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
                    { permission },
                    userId,
                    client
                );

                await client.query("COMMIT");

                return res.json({
                    message: "Permission revoked",
                    documentId,
                    userId,
                    permission
                });
            } catch (error) {
                await client.query("ROLLBACK").catch(() => { });
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
);

// Download only after checking the user's current permission.
router.get("/:id/download", requireAuth, async (req, res) => {
    const documentId = req.params.id;

    if (!validDocumentId(documentId)) {
        return res.status(404).json({ message: "Document not found" });
    }

    try {
        const document = await getDocumentAccess(documentId, req.user.id);

        if (!document || !(await canAccess(req.user, documentId, "download"))) {
            await writeAuditLog(req, "document_download", "denied", null, {
                requestedDocumentId: documentId
            });

            return res.status(404).json({ message: "Document not found" });
        }

        const storageResult = await pool.query(
            "SELECT storage_key FROM documents WHERE id = $1",
            [documentId]
        );

        if (!storageResult.rows[0]) {
            return res.status(404).json({ message: "Document not found" });
        }

        const filePath = await getFilePath(storageResult.rows[0].storage_key);

        await writeAuditLog(req, "document_download", "success", documentId);

        res.setHeader("X-Content-Type-Options", "nosniff");

        return res.download(
            filePath,
            safeOriginalFilename(document.original_filename),
            (error) => {
                if (error && !res.headersSent) {
                    console.error("File download failed:", error.message);
                    res.status(500).json({
                        message: "Unable to download document"
                    });
                }
            }
        );
    } catch (error) {
        console.error("Document download failed:", error.message);

        if (!res.headersSent) {
            return res.status(500).json({
                message: "Unable to download document"
            });
        }
    }
});

// Retrieve metadata only after verifying document-level access.
router.get("/:id", requireAuth, async (req, res) => {
    const documentId = req.params.id;

    if (!validDocumentId(documentId)) {
        return res.status(404).json({ message: "Document not found" });
    }

    try {
        const document = await getDocumentAccess(documentId, req.user.id);

        if (!document || !(await canAccess(req.user, documentId, "view"))) {
            await writeAuditLog(req, "document_read", "denied", null, {
                requestedDocumentId: documentId
            });

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

module.exports = router;
