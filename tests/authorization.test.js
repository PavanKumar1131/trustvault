/**
 * Authorization suite.
 *
 * Verifies the complete role / permission matrix:
 *
 *   role            | upload | read own | read shared | edit | delete | share
 *   ----------------+--------+----------+-------------+------+--------+-------
 *   viewer          |   no   |    no    |  only with an explicit grant
 *   document_owner  |  yes   |   yes    |  only with an explicit grant
 *   admin           |   no   |    no    |  no  (no implicit document access)
 *
 * Every test asserts the HTTP status, the response body and the database
 * state.
 */

const request = require("supertest");
const signature = require("cookie-signature");
const app = require("../src/app");
const pool = require("../src/db");
const config = require("../src/config");
const {
    TEST_PASSWORD,
    VALID_PDF_BUFFER,
    resetDatabase,
    createUser,
    registerAndLogin,
    uploadDocument,
    fetchRow,
    countRows
} = require("./helpers");

describe("TrustVault authorization matrix", () => {
    const testRunId = Date.now().toString(36);
    const password = TEST_PASSWORD;

    const emails = {
        owner: `matrix.owner.${testRunId}@trustvault.test`,
        viewer: `matrix.viewer.${testRunId}@trustvault.test`,
        editor: `matrix.editor.${testRunId}@trustvault.test`,
        admin: `matrix.admin.${testRunId}@trustvault.test`,
        stranger: `matrix.stranger.${testRunId}@trustvault.test`,
        survivor: `matrix.survivor.${testRunId}@trustvault.test`
    };

    const agents = {};
    const users = {};
    let documentId = null;

    beforeAll(async () => {
        await resetDatabase();

        const owner = await registerAndLogin(app, {
            name: "Matrix Owner", email: emails.owner, role: "document_owner"
        });
        agents.owner = owner.agent;
        users.owner = owner.user;

        const viewer = await registerAndLogin(app, {
            name: "Matrix Viewer", email: emails.viewer, role: "viewer"
        });
        agents.viewer = viewer.agent;
        users.viewer = viewer.user;

        const editor = await registerAndLogin(app, {
            name: "Matrix Editor", email: emails.editor, role: "viewer"
        });
        agents.editor = editor.agent;
        users.editor = editor.user;

        const stranger = await registerAndLogin(app, {
            name: "Matrix Stranger", email: emails.stranger, role: "document_owner"
        });
        agents.stranger = stranger.agent;
        users.stranger = stranger.user;

        users.admin = await createUser({
            name: "Matrix Admin", email: emails.admin, role: "admin"
        });
        agents.admin = request.agent(app);
        await agents.admin.post("/api/auth/login").send({ email: emails.admin, password });

        // Dedicated account for the "session survived the account lock" case.
        users.survivor = await createUser({
            name: "Matrix Survivor", email: emails.survivor, role: "viewer"
        });

        documentId = (
            await uploadDocument(agents.owner, { name: `Matrix_${testRunId}`, category: "Testing" })
        ).id;
    });

    // ══════════════════════════════════════════════════════════════════════
    test("1. Only document owners may upload", async () => {
        const before = await countRows("documents");

        const viewer = await agents.viewer
            .post("/api/documents")
            .field("name", "Viewer Document")
            .attach("file", VALID_PDF_BUFFER, "viewer.pdf");
        expect(viewer.status).toBe(403);

        const admin = await agents.admin
            .post("/api/documents")
            .field("name", "Admin Document")
            .attach("file", VALID_PDF_BUFFER, "admin.pdf");
        expect(admin.status).toBe(403);

        const owner = await agents.owner
            .post("/api/documents")
            .field("name", "Owner Document")
            .attach("file", VALID_PDF_BUFFER, "owner.pdf");
        expect(owner.status).toBe(201);

        // Database state: only the owner's upload created a document.
        expect(await countRows("documents")).toBe(before + 1);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("2. The owner has full control over their own document", async () => {
        const read = await agents.owner.get(`/api/documents/${documentId}`);
        expect(read.status).toBe(200);
        expect(read.body.document.access_level).toBe("owner");

        const download = await agents.owner.get(`/api/documents/${documentId}/download`);
        expect(download.status).toBe(200);

        const edit = await agents.owner
            .put(`/api/documents/${documentId}`)
            .field("name", `Matrix_Owner_Edited_${testRunId}`);
        expect(edit.status).toBe(200);

        const permissions = await agents.owner.get(`/api/documents/${documentId}/permissions`);
        expect(permissions.status).toBe(200);

        const audit = await agents.owner.get(`/api/documents/${documentId}/audit`);
        expect(audit.status).toBe(200);

        // Database state: the edit was persisted.
        const document = await fetchRow("documents", "id = $1", [documentId]);
        expect(document.name).toBe(`Matrix_Owner_Edited_${testRunId}`);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("3. A user without a grant sees nothing", async () => {
        expect((await agents.viewer.get(`/api/documents/${documentId}`)).status).toBe(404);
        expect((await agents.viewer.get(`/api/documents/${documentId}/download`)).status).toBe(404);
        expect((await agents.viewer.get(`/api/documents/${documentId}/audit`)).status).toBe(404);
        expect((await agents.stranger.get(`/api/documents/${documentId}`)).status).toBe(404);

        // Database state: no grant exists for them.
        for (const target of [users.viewer, users.editor, users.stranger, users.admin]) {
            expect(
                await countRows(
                    "document_permissions",
                    "document_id = $1 AND user_id = $2",
                    [documentId, target.id]
                )
            ).toBe(0);
        }
    });

    // ══════════════════════════════════════════════════════════════════════
    test("4. Administrators have no implicit document access", async () => {
        expect((await agents.admin.get(`/api/documents/${documentId}`)).status).toBe(404);
        expect((await agents.admin.get(`/api/documents/${documentId}/download`)).status).toBe(404);
        expect((await agents.admin.get(`/api/documents/${documentId}/permissions`)).status).toBe(404);
        expect((await agents.admin.get(`/api/documents/${documentId}/audit`)).status).toBe(404);

        const edit = await agents.admin
            .put(`/api/documents/${documentId}`)
            .field("name", "Admin Edit");
        expect(edit.status).toBe(404);

        const remove = await agents.admin.delete(`/api/documents/${documentId}`);
        expect(remove.status).toBe(404);

        const share = await agents.admin
            .post(`/api/documents/${documentId}/permissions`)
            .send({ email: emails.stranger, permission: "read" });
        expect(share.status).toBe(404);

        const listing = await agents.admin.get("/api/documents");
        expect(listing.status).toBe(200);
        expect(listing.body.documents.some((d) => d.id === documentId)).toBe(false);

        // Database state: nothing changed.
        const document = await fetchRow("documents", "id = $1", [documentId]);
        expect(document.owner_id).toBe(users.owner.id);
        expect(
            await countRows(
                "document_permissions",
                "document_id = $1 AND user_id = $2",
                [documentId, users.stranger.id]
            )
        ).toBe(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("5. A 'read' grant allows reading but blocks every write", async () => {
        const grant = await agents.owner
            .post(`/api/documents/${documentId}/permissions`)
            .send({ email: emails.viewer, permission: "read" });
        expect(grant.status).toBe(200);

        const read = await agents.viewer.get(`/api/documents/${documentId}`);
        expect(read.status).toBe(200);
        expect(read.body.document.access_level).toBe("read");

        const download = await agents.viewer.get(`/api/documents/${documentId}/download`);
        expect(download.status).toBe(200);

        const edit = await agents.viewer
            .put(`/api/documents/${documentId}`)
            .field("name", "Viewer Edit");
        expect(edit.status).toBe(403);

        const remove = await agents.viewer.delete(`/api/documents/${documentId}`);
        expect(remove.status).toBe(403);

        const share = await agents.viewer
            .post(`/api/documents/${documentId}/permissions`)
            .send({ email: emails.stranger, permission: "read" });
        expect(share.status).toBe(404);

        const permissionList = await agents.viewer.get(`/api/documents/${documentId}/permissions`);
        expect(permissionList.status).toBe(404);

        // Database state: the grant is still exactly one 'read' row.
        const rows = await pool.query(
            "SELECT permission FROM document_permissions WHERE document_id = $1 AND user_id = $2",
            [documentId, users.viewer.id]
        );
        expect(rows.rows).toHaveLength(1);
        expect(rows.rows[0].permission).toBe("read");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("6. An 'edit' grant allows editing but never deleting or sharing", async () => {
        const grant = await agents.owner
            .post(`/api/documents/${documentId}/permissions`)
            .send({ email: emails.editor, permission: "edit" });
        expect(grant.status).toBe(200);

        const edit = await agents.editor
            .put(`/api/documents/${documentId}`)
            .field("name", `Matrix_Editor_Edited_${testRunId}`)
            .field("description", "Edited by the editor");
        expect(edit.status).toBe(200);
        expect(edit.body.document.access_level).toBe("edit");

        const remove = await agents.editor.delete(`/api/documents/${documentId}`);
        expect(remove.status).toBe(403);

        const share = await agents.editor
            .post(`/api/documents/${documentId}/permissions`)
            .send({ email: emails.stranger, permission: "read" });
        expect(share.status).toBe(404);

        const revoke = await agents.editor.delete(
            `/api/documents/${documentId}/permissions/${users.viewer.id}`
        );
        expect(revoke.status).toBe(404);

        // Database state: the editor's changes are stored, the document lives.
        const document = await fetchRow("documents", "id = $1", [documentId]);
        expect(document.name).toBe(`Matrix_Editor_Edited_${testRunId}`);
        expect(document.description).toBe("Edited by the editor");
        expect(document.owner_id).toBe(users.owner.id);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("7. A revoked grant loses access immediately", async () => {
        const revoke = await agents.owner.delete(
            `/api/documents/${documentId}/permissions/${users.editor.id}`
        );
        expect(revoke.status).toBe(200);

        const read = await agents.editor.get(`/api/documents/${documentId}`);
        expect(read.status).toBe(404);

        const edit = await agents.editor
            .put(`/api/documents/${documentId}`)
            .field("name", "Should Not Work");
        expect(edit.status).toBe(404);

        // Database state: the grant row is gone.
        expect(
            await countRows(
                "document_permissions",
                "document_id = $1 AND user_id = $2",
                [documentId, users.editor.id]
            )
        ).toBe(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("8. Role changes take effect without a new login", async () => {
        // Promote the stranger to administrator and demote them again.
        const promote = await agents.admin
            .patch(`/api/admin/users/${users.stranger.id}/role`)
            .send({ role: "admin" });
        expect(promote.status).toBe(200);

        // The session that was created as document_owner now has admin rights.
        const adminUsers = await agents.stranger.get("/api/admin/users");
        expect(adminUsers.status).toBe(200);

        const demote = await agents.admin
            .patch(`/api/admin/users/${users.stranger.id}/role`)
            .send({ role: "document_owner" });
        expect(demote.status).toBe(200);

        // The very same session loses the administrator rights immediately.
        const afterDemotion = await agents.stranger.get("/api/admin/users");
        expect(afterDemotion.status).toBe(403);

        // Database state: the role was persisted.
        const account = await fetchRow("users", "id = $1", [users.stranger.id]);
        expect(account.role).toBe("document_owner");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("9. A disabled account with a surviving session is rejected with 403", async () => {
        // Simulate a session that was re-created after the account was
        // disabled (race condition). The middleware must still refuse it.
        const sessionId = `surviving-${Date.now()}`;
        const sessionPayload = {
            cookie: {
                originalMaxAge: 28800000,
                expires: new Date(Date.now() + 3600000).toISOString(),
                secure: false,
                httpOnly: true,
                path: "/",
                sameSite: "lax"
            },
            userId: users.survivor.id
        };

        await pool.query(
            `INSERT INTO user_sessions (sid, sess, expire)
             VALUES ($1, $2::json, now() + interval '1 hour')`,
            [sessionId, JSON.stringify(sessionPayload)]
        );

        await pool.query("UPDATE users SET is_disabled = true WHERE id = $1", [users.survivor.id]);

        const signedCookie = `s:${signature.sign(sessionId, config.SESSION_SECRET)}`;

        const response = await request(app)
            .get("/api/documents")
            .set("Cookie", `trustvault.sid=${encodeURIComponent(signedCookie)}`);

        expect(response.status).toBe(403);
        expect(response.body.message).toMatch(/disabled/i);

        // Database state: the account is flagged as disabled.
        const account = await fetchRow("users", "id = $1", [users.survivor.id]);
        expect(account.is_disabled).toBe(true);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("10. Non-administrators cannot reach any administration endpoint", async () => {
        const endpoints = [
            ["get", "/api/admin/overview"],
            ["get", "/api/admin/users"],
            ["get", "/api/admin/audit-logs"],
            ["get", "/api/admin/verify-chain"]
        ];

        for (const [method, path] of endpoints) {
            const response = await agents.viewer[method](path);
            expect(response.status).toBe(403);
            expect(response.body.message).toMatch(/administrator privileges required/i);
        }

        const roleChange = await agents.viewer
            .patch(`/api/admin/users/${users.owner.id}/role`)
            .send({ role: "admin" });
        expect(roleChange.status).toBe(403);

        // Database state: the role was not changed.
        const account = await fetchRow("users", "id = $1", [users.owner.id]);
        expect(account.role).toBe("document_owner");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("11. The document listing only contains accessible documents", async () => {
        const ownerListing = await agents.owner.get("/api/documents");
        expect(ownerListing.status).toBe(200);
        expect(ownerListing.body.documents.some((d) => d.id === documentId)).toBe(true);

        const viewerListing = await agents.viewer.get("/api/documents");
        expect(viewerListing.status).toBe(200);
        expect(viewerListing.body.documents.some((d) => d.id === documentId)).toBe(true); // still granted 'read'

        const strangerListing = await agents.stranger.get("/api/documents");
        expect(strangerListing.status).toBe(200);
        expect(strangerListing.body.documents.some((d) => d.id === documentId)).toBe(false);
    });
});
