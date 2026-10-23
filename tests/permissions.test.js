/**
 * Access-control-list suite.
 *
 * Verifies the grant / revoke semantics, the one-permission-per-user rule
 * and the invariants that protect the owner.
 */

const request = require("supertest");
const app = require("../src/app");
const pool = require("../src/db");
const {
    TEST_PASSWORD,
    resetDatabase,
    registerAndLogin,
    uploadDocument,
    fetchRow,
    countRows,
    fetchAuditLogs
} = require("./helpers");

describe("TrustVault document permissions", () => {
    const testRunId = Date.now().toString(36);
    const password = TEST_PASSWORD;

    const emails = {
        owner: `perm.owner.${testRunId}@trustvault.test`,
        reader: `perm.reader.${testRunId}@trustvault.test`,
        editor: `perm.editor.${testRunId}@trustvault.test`,
        other: `perm.other.${testRunId}@trustvault.test`
    };

    const agents = {};
    const users = {};
    let documentId = null;

    beforeAll(async () => {
        await resetDatabase();

        const owner = await registerAndLogin(app, {
            name: "Perm Owner", email: emails.owner, role: "document_owner"
        });
        agents.owner = owner.agent;
        users.owner = owner.user;

        const reader = await registerAndLogin(app, {
            name: "Perm Reader", email: emails.reader, role: "viewer"
        });
        agents.reader = reader.agent;
        users.reader = reader.user;

        const editor = await registerAndLogin(app, {
            name: "Perm Editor", email: emails.editor, role: "viewer"
        });
        agents.editor = editor.agent;
        users.editor = editor.user;

        const other = await registerAndLogin(app, {
            name: "Perm Other", email: emails.other, role: "document_owner"
        });
        agents.other = other.agent;
        users.other = other.user;

        documentId = (
            await uploadDocument(agents.owner, { name: `Perm_${testRunId}`, category: "Legal" })
        ).id;
    });

    // ══════════════════════════════════════════════════════════════════════
    test("1. The owner grants 'read' access", async () => {
        const response = await agents.owner
            .post(`/api/documents/${documentId}/permissions`)
            .send({ email: emails.reader, permission: "read" });

        expect(response.status).toBe(200);
        expect(response.body.permission).toBe("read");
        expect(response.body.documentId).toBe(documentId);
        expect(response.body.user.email).toBe(emails.reader);

        // Database state: exactly one grant row.
        const rows = await pool.query(
            "SELECT * FROM document_permissions WHERE document_id = $1 AND user_id = $2",
            [documentId, users.reader.id]
        );
        expect(rows.rows).toHaveLength(1);
        expect(rows.rows[0].permission).toBe("read");
        expect(rows.rows[0].granted_by).toBe(users.owner.id);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("2. Upgrading 'read' to 'edit' updates the same row", async () => {
        const response = await agents.owner
            .post(`/api/documents/${documentId}/permissions`)
            .send({ email: emails.reader, permission: "edit" });

        expect(response.status).toBe(200);
        expect(response.body.permission).toBe("edit");

        // Database state: still exactly one row, now with the stronger level.
        const rows = await pool.query(
            "SELECT * FROM document_permissions WHERE document_id = $1 AND user_id = $2",
            [documentId, users.reader.id]
        );
        expect(rows.rows).toHaveLength(1);
        expect(rows.rows[0].permission).toBe("edit");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("3. The database refuses a second grant for the same user", async () => {
        await expect(
            pool.query(
                `INSERT INTO document_permissions (document_id, user_id, permission, granted_by)
                 VALUES ($1, $2, 'read', $3)`,
                [documentId, users.reader.id, users.owner.id]
            )
        ).rejects.toThrow();

        // Database state: still one row.
        expect(
            await countRows(
                "document_permissions",
                "document_id = $1 AND user_id = $2",
                [documentId, users.reader.id]
            )
        ).toBe(1);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("4. Invalid permission values are rejected", async () => {
        for (const permission of ["owner", "delete", "admin", "", "superuser"]) {
            const response = await agents.owner
                .post(`/api/documents/${documentId}/permissions`)
                .send({ email: emails.other, permission });

            expect(response.status).toBe(400);
            expect(response.body.message).toMatch(/valid email and permission/i);
        }

        // Database state: no grant was created.
        expect(
            await countRows(
                "document_permissions",
                "document_id = $1 AND user_id = $2",
                [documentId, users.other.id]
            )
        ).toBe(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("5. The legacy permission names 'view' and 'download' map to 'read'", async () => {
        const response = await agents.owner
            .post(`/api/documents/${documentId}/permissions`)
            .send({ email: emails.other, permission: "view" });

        expect(response.status).toBe(200);
        expect(response.body.permission).toBe("read");

        const row = await fetchRow(
            "document_permissions",
            "document_id = $1 AND user_id = $2",
            [documentId, users.other.id]
        );
        expect(row.permission).toBe("read");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("6. Grants to unknown recipients, oneself and the owner are rejected", async () => {
        const unknown = await agents.owner
            .post(`/api/documents/${documentId}/permissions`)
            .send({ email: `nobody.${testRunId}@trustvault.test`, permission: "read" });
        expect(unknown.status).toBe(400);

        const self = await agents.owner
            .post(`/api/documents/${documentId}/permissions`)
            .send({ email: emails.owner, permission: "read" });
        expect(self.status).toBe(400);

        const malformed = await agents.owner
            .post(`/api/documents/${documentId}/permissions`)
            .send({ email: "not-an-email", permission: "read" });
        expect(malformed.status).toBe(400);

        // Database state: no grant was created for the owner.
        expect(
            await countRows(
                "document_permissions",
                "document_id = $1 AND user_id = $2",
                [documentId, users.owner.id]
            )
        ).toBe(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("7. Only the owner can manage the access list", async () => {
        const list = await agents.owner.get(`/api/documents/${documentId}/permissions`);
        expect(list.status).toBe(200);
        expect(list.body.permissions.length).toBeGreaterThan(0);
        expect(
            list.body.permissions.every((p) => p.document_id === documentId)
        ).toBe(true);

        const readerList = await agents.reader.get(`/api/documents/${documentId}/permissions`);
        expect(readerList.status).toBe(404);

        const otherList = await agents.other.get(`/api/documents/${documentId}/permissions`);
        expect(otherList.status).toBe(404);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("8. A specific permission level can be revoked", async () => {
        // The reader currently holds 'edit'; revoking 'read' must not match.
        const wrongLevel = await agents.owner.delete(
            `/api/documents/${documentId}/permissions/${users.reader.id}/read`
        );
        expect(wrongLevel.status).toBe(404);

        const row = await fetchRow(
            "document_permissions",
            "document_id = $1 AND user_id = $2",
            [documentId, users.reader.id]
        );
        expect(row.permission).toBe("edit");

        const response = await agents.owner.delete(
            `/api/documents/${documentId}/permissions/${users.reader.id}/edit`
        );
        expect(response.status).toBe(200);
        expect(response.body.permission).toBe("edit");

        // Database state: the grant is gone.
        expect(
            await countRows(
                "document_permissions",
                "document_id = $1 AND user_id = $2",
                [documentId, users.reader.id]
            )
        ).toBe(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("9. Revoking without a permission level removes every grant", async () => {
        await agents.owner
            .post(`/api/documents/${documentId}/permissions`)
            .send({ email: emails.editor, permission: "edit" });

        expect(
            await countRows(
                "document_permissions",
                "document_id = $1 AND user_id = $2",
                [documentId, users.editor.id]
            )
        ).toBe(1);

        const response = await agents.owner.delete(
            `/api/documents/${documentId}/permissions/${users.editor.id}`
        );
        expect(response.status).toBe(200);

        // Database state: the grant is gone.
        expect(
            await countRows(
                "document_permissions",
                "document_id = $1 AND user_id = $2",
                [documentId, users.editor.id]
            )
        ).toBe(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("10. The owner's own access cannot be revoked", async () => {
        const response = await agents.owner.delete(
            `/api/documents/${documentId}/permissions/${users.owner.id}`
        );
        expect(response.status).toBe(400);
        expect(response.body.message).toMatch(/owner/i);

        // Database state: no owner row was created in the first place.
        expect(
            await countRows(
                "document_permissions",
                "document_id = $1 AND user_id = $2",
                [documentId, users.owner.id]
            )
        ).toBe(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("11. Every grant and revocation is audited", async () => {
        const grants = await fetchAuditLogs({ action: "document_permission_grant" });
        const revocations = await fetchAuditLogs({ action: "document_permission_revoke" });

        expect(grants.length).toBeGreaterThan(0);
        expect(revocations.length).toBeGreaterThan(0);

        const successGrant = grants.find((row) => row.outcome === "success");
        expect(successGrant).toBeDefined();
        expect(successGrant.document_id).toBe(documentId);
        expect(successGrant.details.permission).toBeDefined();

        const denial = grants.find((row) => row.outcome === "denied");
        expect(denial).toBeDefined();
        expect(denial.details.reason).toBeDefined();
    });

    // ══════════════════════════════════════════════════════════════════════
    test("12. A grant to a disabled account is still possible but grants nothing extra", async () => {
        // The owner grants access to an account; the grant is a row in the ACL.
        const response = await agents.owner
            .post(`/api/documents/${documentId}/permissions`)
            .send({ email: emails.other, permission: "read" });
        expect(response.status).toBe(200);

        const row = await fetchRow(
            "document_permissions",
            "document_id = $1 AND user_id = $2",
            [documentId, users.other.id]
        );
        expect(row).not.toBeNull();
        expect(row.permission).toBe("read");
    });
});
