/**
 * Permanent-deletion retention and cleanup tests.
 *
 * A document deletion removes metadata, grants and the database blob in one
 * transaction. The audit row written for the deletion must survive, older
 * audit hashes must not be rewritten, and a failed file-system unlink must be
 * reported honestly instead of being hidden as a complete cleanup.
 */

const fs = require("node:fs/promises");
const path = require("node:path");
const app = require("../src/app");
const config = require("../src/config");
const pool = require("../src/db");
const { verifyAuditChain } = require("../src/services/auditService");
const {
    resetDatabase,
    registerAndLogin,
    uploadDocument,
    fetchRow,
    countRows,
    fetchAuditLogs
} = require("./helpers");

describe("TrustVault deletion retention and cleanup", () => {
    const testRunId = Date.now().toString(36);
    const emails = {
        owner: `deletion.owner.${testRunId}@trustvault.test`,
        viewer: `deletion.viewer.${testRunId}@trustvault.test`
    };

    const agents = {};

    beforeAll(async () => {
        await resetDatabase();

        const owner = await registerAndLogin(app, {
            name: "Deletion Owner",
            email: emails.owner,
            role: "document_owner"
        });
        agents.owner = owner.agent;

        const viewer = await registerAndLogin(app, {
            name: "Deletion Viewer",
            email: emails.viewer,
            role: "viewer"
        });
        agents.viewer = viewer.agent;
    });

    async function auditSnapshot() {
        const result = await pool.query(
            "SELECT id, prev_hash, entry_hash FROM audit_logs ORDER BY id ASC"
        );
        return result.rows;
    }

    function expectOlderHashesUnchanged(before, after) {
        const afterById = new Map(after.map((row) => [String(row.id), row]));

        before.forEach((row) => {
            const current = afterById.get(String(row.id));
            expect(current).toBeDefined();
            expect(current.prev_hash).toBe(row.prev_hash);
            expect(current.entry_hash).toBe(row.entry_hash);
        });
    }

    test("1. A successful delete removes metadata, grants and blob while retaining the audit trail", async () => {
        const document = await uploadDocument(agents.owner, {
            name: `Retention_${testRunId}`,
            category: "Retention"
        });

        const grant = await agents.owner
            .post(`/api/documents/${document.id}/permissions`)
            .send({ email: emails.viewer, permission: "read" });
        expect(grant.status).toBe(200);

        const stored = await fetchRow("documents", "id = $1", [document.id]);
        const storageKey = stored.storage_key;
        await expect(
            fs.access(path.join(config.UPLOAD_DIR, storageKey))
        ).resolves.toBeUndefined();

        const beforeLogs = await auditSnapshot();

        const response = await agents.owner.delete(`/api/documents/${document.id}`);
        expect(response.status).toBe(200);
        expect(response.body.message).toMatch(/deleted/i);
        expect(response.body.storageCleanup).toBe("complete");

        // Metadata, grants, blob and the local file are gone.
        expect(await fetchRow("documents", "id = $1", [document.id])).toBeNull();
        expect(
            await fetchRow("document_blobs", "storage_key = $1", [storageKey])
        ).toBeNull();
        expect(
            await countRows("document_permissions", "document_id = $1", [document.id])
        ).toBe(0);
        await expect(
            fs.access(path.join(config.UPLOAD_DIR, storageKey))
        ).rejects.toBeDefined();

        // The deletion event itself is retained and still points at the
        // deleted document id, which is not a foreign key on audit_logs.
        const deletionLogs = await fetchAuditLogs({
            action: "document_delete",
            outcome: "success",
            documentId: document.id
        });
        expect(deletionLogs).toHaveLength(1);
        expect(deletionLogs[0].document_id).toBe(document.id);

        const afterLogs = await auditSnapshot();
        expectOlderHashesUnchanged(beforeLogs, afterLogs);

        const verification = await verifyAuditChain();
        expect(verification.valid).toBe(true);
        expect(verification.totalEntries).toBeGreaterThan(beforeLogs.length);
    });

    test("2. A failed file-system unlink is reported as pending, not as complete cleanup", async () => {
        const document = await uploadDocument(agents.owner, {
            name: `CleanupFailure_${testRunId}`,
            category: "Retention"
        });

        const stored = await fetchRow("documents", "id = $1", [document.id]);
        const storageKey = stored.storage_key;
        const storedPath = path.join(config.UPLOAD_DIR, storageKey);

        // Replace the regular file with a directory. `unlink` cannot remove a
        // directory on any supported platform, so this simulates a real local
        // cleanup failure without touching permissions or the database.
        await fs.rm(storedPath, { force: true });
        await fs.mkdir(storedPath);

        try {
            const beforeLogs = await auditSnapshot();

            const response = await agents.owner.delete(`/api/documents/${document.id}`);
            expect(response.status).toBe(200);
            expect(response.body.message).toMatch(/could not be removed/i);
            expect(response.body.storageCleanup).toBe("pending");

            // The database deletion is still complete and atomic.
            expect(await fetchRow("documents", "id = $1", [document.id])).toBeNull();
            expect(
                await fetchRow("document_blobs", "storage_key = $1", [storageKey])
            ).toBeNull();
            expect(
                await countRows("document_permissions", "document_id = $1", [document.id])
            ).toBe(0);

            // The orphan remains on disk, so the response must not claim that
            // cleanup succeeded.
            const orphan = await fs.stat(storedPath);
            expect(orphan.isDirectory()).toBe(true);

            const deletionLogs = await fetchAuditLogs({
                action: "document_delete",
                outcome: "success",
                documentId: document.id
            });
            expect(deletionLogs).toHaveLength(1);

            const afterLogs = await auditSnapshot();
            expectOlderHashesUnchanged(beforeLogs, afterLogs);

            const verification = await verifyAuditChain();
            expect(verification.valid).toBe(true);
        } finally {
            await fs.rm(storedPath, { recursive: true, force: true });
        }
    });
});
