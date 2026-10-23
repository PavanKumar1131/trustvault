/**
 * Core security suite: authentication, authorization, isolation and the
 * audit trail.
 *
 * Every test asserts the HTTP status, the response body/behaviour *and* the
 * resulting database state.
 */

const request = require("supertest");
const fs = require("node:fs/promises");
const path = require("node:path");
const app = require("../src/app");
const pool = require("../src/db");
const config = require("../src/config");
const { verifyAuditChain } = require("../src/services/auditService");
const {
    getFileBuffer,
    deleteFile,
    isValidStorageKey
} = require("../src/services/storage");
const {
    TEST_PASSWORD,
    VALID_PDF_BUFFER,
    SPOOFED_MALICIOUS_BUFFER,
    resetDatabase,
    createUser,
    registerAndLogin,
    uploadDocument,
    fetchRow,
    countRows,
    fetchAuditLogs
} = require("./helpers");

describe("TrustVault security suite", () => {
    const testRunId = Date.now().toString(36);
    const password = TEST_PASSWORD;

    const emails = {
        ownerA: `ownera.${testRunId}@trustvault.test`,
        ownerB: `ownerb.${testRunId}@trustvault.test`,
        viewerC: `viewerc.${testRunId}@trustvault.test`,
        editorD: `editord.${testRunId}@trustvault.test`,
        adminE: `admine.${testRunId}@trustvault.test`,
        adminF: `adminf.${testRunId}@trustvault.test`,
        adminG: `adming.${testRunId}@trustvault.test`,
        disableTarget: `disable.${testRunId}@trustvault.test`
    };

    const agents = {};
    const users = {};
    let confidentialDocId = null;

    beforeAll(async () => {
        await resetDatabase();

        // ── Owners, viewers and editors (public registration) ─────────────────
        const a = await registerAndLogin(app, {
            name: "Alice Owner", email: emails.ownerA, role: "document_owner"
        });
        agents.ownerA = a.agent;
        users.ownerA = a.user;

        const b = await registerAndLogin(app, {
            name: "Bob Unrelated", email: emails.ownerB, role: "document_owner"
        });
        agents.ownerB = b.agent;
        users.ownerB = b.user;

        const c = await registerAndLogin(app, {
            name: "Charlie Viewer", email: emails.viewerC, role: "viewer"
        });
        agents.viewerC = c.agent;
        users.viewerC = c.user;

        const d = await registerAndLogin(app, {
            name: "Dana Editor", email: emails.editorD, role: "viewer"
        });
        agents.editorD = d.agent;
        users.editorD = d.user;

        // ── Administrators (created directly, never self-assignable) ─────────
        users.adminE = await createUser({
            name: "Eve Admin", email: emails.adminE, role: "admin"
        });
        users.adminF = await createUser({
            name: "Frank Admin", email: emails.adminF, role: "admin"
        });
        users.adminG = await createUser({
            name: "Grace Admin", email: emails.adminG, role: "admin"
        });

        agents.adminE = request.agent(app);
        await agents.adminE.post("/api/auth/login").send({ email: emails.adminE, password });
        agents.adminF = request.agent(app);
        await agents.adminF.post("/api/auth/login").send({ email: emails.adminF, password });
        agents.adminG = request.agent(app);
        await agents.adminG.post("/api/auth/login").send({ email: emails.adminG, password });

        // ── Account that will be disabled later ──────────────────────────────
        const target = await registerAndLogin(app, {
            name: "Disable Target", email: emails.disableTarget, role: "document_owner"
        });
        agents.disableTarget = target.agent;
        users.disableTarget = target.user;
    });

    // ══════════════════════════════════════════════════════════════════════
    test("1. Registration never lets a client choose its own role", async () => {
        const before = await countRows("users");

        // The client asks for the admin role. The server ignores it.
        const adminRes = await request(app).post("/api/auth/register").send({
            name: "Admin Attempt",
            email: `admin.attempt.${testRunId}@trustvault.test`,
            password,
            role: "admin"
        });
        expect(adminRes.status).toBe(201);
        expect(adminRes.body.user.role).toBe("viewer");

        // The client asks for the document_owner role. The server ignores it.
        const ownerRes = await request(app).post("/api/auth/register").send({
            name: "Owner Attempt",
            email: `owner.attempt.${testRunId}@trustvault.test`,
            password,
            role: "document_owner"
        });
        expect(ownerRes.status).toBe(201);
        expect(ownerRes.body.user.role).toBe("viewer");

        // An unknown role is ignored in exactly the same way.
        const invalidRes = await request(app).post("/api/auth/register").send({
            name: "Invalid Role",
            email: `invalid.${testRunId}@trustvault.test`,
            password,
            role: "superadmin"
        });
        expect(invalidRes.status).toBe(201);
        expect(invalidRes.body.user.role).toBe("viewer");

        // Database state: three viewers were created, none of them privileged.
        const after = await countRows("users");
        expect(after).toBe(before + 3);

        const privileged = await countRows(
            "users",
            "email = ANY($1::text[]) AND role <> 'viewer'",
            [[
                `admin.attempt.${testRunId}@trustvault.test`,
                `owner.attempt.${testRunId}@trustvault.test`,
                `invalid.${testRunId}@trustvault.test`
            ]]
        );
        expect(privileged).toBe(0);

        // The database agrees with the response for every one of them.
        const created = await fetchRow("users", "email = $1", [
            `admin.attempt.${testRunId}@trustvault.test`
        ]);
        expect(created.role).toBe("viewer");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("2. Unauthenticated requests are rejected with 401", async () => {
        const anonymous = request(app);
        const sessionsBefore = await countRows("user_sessions");

        expect((await anonymous.get("/api/documents")).status).toBe(401);
        expect((await anonymous.get("/api/admin/audit-logs")).status).toBe(401);
        expect((await anonymous.get("/api/admin/users")).status).toBe(401);
        expect((await anonymous.get("/api/auth/me")).status).toBe(401);
        expect((await anonymous.get("/api/auth/users")).status).toBe(401);

        // Database state: an anonymous request never creates a session.
        expect(await countRows("user_sessions")).toBe(sessionsBefore);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("3. Disabled accounts cannot log in", async () => {
        const freshEmail = `disabled.login.${testRunId}@trustvault.test`;

        const registration = await request(app).post("/api/auth/register").send({
            name: "Disabled Login Test", email: freshEmail, password, role: "viewer"
        });
        expect(registration.status).toBe(201);

        await pool.query("UPDATE users SET is_disabled = true WHERE id = $1", [
            registration.body.user.id
        ]);

        const login = await request(app).post("/api/auth/login").send({
            email: freshEmail, password
        });
        expect(login.status).toBe(403);
        expect(login.body.message).toMatch(/disabled/i);

        // Database state: the account is flagged and no session was created.
        const account = await fetchRow("users", "id = $1", [registration.body.user.id]);
        expect(account.is_disabled).toBe(true);

        const sessions = await countRows("user_sessions", "sess->>'userId' = $1", [
            registration.body.user.id
        ]);
        expect(sessions).toBe(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("4. Active session stops working after the account is disabled", async () => {
        const before = await agents.disableTarget.get("/api/documents");
        expect(before.status).toBe(200);

        const sessionsBefore = await countRows("user_sessions", "sess->>'userId' = $1", [
            users.disableTarget.id
        ]);
        expect(sessionsBefore).toBe(1);

        const disableRes = await agents.adminE
            .patch(`/api/admin/users/${users.disableTarget.id}/disable`)
            .send({ disabled: true });
        expect(disableRes.status).toBe(200);
        expect(disableRes.body.revokedSessions).toBeGreaterThan(0);

        // The old cookie is worthless now: the server-side session was
        // destroyed together with the account, so the request is
        // unauthenticated (401) instead of authorised.
        const afterDisable = await agents.disableTarget.get("/api/documents");
        expect(afterDisable.status).toBe(401);

        const meCheck = await agents.disableTarget.get("/api/auth/me");
        expect(meCheck.status).toBe(401);

        // A login attempt is refused with an explicit message.
        const reLogin = await request(app).post("/api/auth/login").send({
            email: emails.disableTarget, password
        });
        expect(reLogin.status).toBe(403);
        expect(reLogin.body.message).toMatch(/disabled/i);

        // Database state: the server-side session rows were deleted.
        const sessionsAfter = await countRows("user_sessions", "sess->>'userId' = $1", [
            users.disableTarget.id
        ]);
        expect(sessionsAfter).toBe(0);

        const account = await fetchRow("users", "id = $1", [users.disableTarget.id]);
        expect(account.is_disabled).toBe(true);

        // Re-enable for the remaining tests.
        const enableRes = await agents.adminE
            .patch(`/api/admin/users/${users.disableTarget.id}/disable`)
            .send({ disabled: false });
        expect(enableRes.status).toBe(200);

        // Re-enabling must NOT resurrect the old session.
        const stillRejected = await agents.disableTarget.get("/api/documents");
        expect(stillRejected.status).toBe(401);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("5. Viewers and administrators cannot upload documents", async () => {
        const before = await countRows("documents");

        const viewerUpload = await agents.viewerC
            .post("/api/documents")
            .field("name", "Viewer Upload")
            .attach("file", VALID_PDF_BUFFER, "viewer.pdf");
        expect(viewerUpload.status).toBe(403);
        expect(viewerUpload.body.message).toMatch(/access denied/i);

        const adminUpload = await agents.adminE
            .post("/api/documents")
            .field("name", "Admin Upload")
            .attach("file", VALID_PDF_BUFFER, "admin.pdf");
        expect(adminUpload.status).toBe(403);

        // Database state: no document was created.
        expect(await countRows("documents")).toBe(before);

        const denial = await fetchAuditLogs({ action: "document_upload", outcome: "denied" });
        expect(denial.length).toBeGreaterThanOrEqual(2);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("6. Spoofed file uploads are rejected with 415", async () => {
        const before = await countRows("documents");

        const res = await agents.ownerA
            .post("/api/documents")
            .field("name", "Disguised Malware")
            .field("category", "HR")
            .attach("file", SPOOFED_MALICIOUS_BUFFER, "salary.pdf");
        expect(res.status).toBe(415);
        expect(res.body.message).toMatch(/PDF, JPEG, and PNG/i);

        // Database state: neither the document nor a blob row was created.
        expect(await countRows("documents")).toBe(before);
        expect(await countRows("document_blobs")).toBe(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("7. A document owner uploads and accesses their own document", async () => {
        const res = await agents.ownerA
            .post("/api/documents")
            .field("name", `Salary_Letter_${testRunId}`)
            .field("category", "Compensation")
            .field("description", "Confidential compensation breakdown")
            .attach("file", VALID_PDF_BUFFER, "Salary_Letter.pdf");
        expect(res.status).toBe(201);
        expect(res.body.document.owner_id).toBe(users.ownerA.id);
        expect(res.body.document.access_level).toBe("owner");
        confidentialDocId = res.body.document.id;

        // Database state: the document and its blob exist and are linked.
        const document = await fetchRow("documents", "id = $1", [confidentialDocId]);
        expect(document).not.toBeNull();
        expect(document.owner_id).toBe(users.ownerA.id);
        expect(document.file_size).toBe(String(VALID_PDF_BUFFER.length));
        expect(Number(document.file_size)).toBe(VALID_PDF_BUFFER.length);

        const blob = await fetchRow("document_blobs", "storage_key = $1", [document.storage_key]);
        expect(blob).not.toBeNull();
        expect(Buffer.from(blob.file_data).equals(VALID_PDF_BUFFER)).toBe(true);

        // Metadata and download work for the owner.
        const meta = await agents.ownerA.get(`/api/documents/${confidentialDocId}`);
        expect(meta.status).toBe(200);
        expect(meta.body.document.access_level).toBe("owner");

        const download = await agents.ownerA.get(`/api/documents/${confidentialDocId}/download`);
        expect(download.status).toBe(200);
        expect(Buffer.from(download.body).equals(VALID_PDF_BUFFER)).toBe(true);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("8. Unrelated users cannot read or download private documents", async () => {
        const meta = await agents.ownerB.get(`/api/documents/${confidentialDocId}`);
        expect(meta.status).toBe(404);

        const download = await agents.ownerB.get(`/api/documents/${confidentialDocId}/download`);
        expect(download.status).toBe(404);

        // Database state: no successful read/download was logged for ownerB.
        const successfulReads = await fetchAuditLogs({
            action: "document_read", outcome: "success"
        });
        expect(successfulReads.every((row) => row.actor_id !== users.ownerB.id)).toBe(true);

        const denials = await fetchAuditLogs({
            action: "document_read", outcome: "denied"
        });
        expect(denials.some((row) => row.actor_id === users.ownerB.id)).toBe(true);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("9. IDOR is blocked on every document endpoint", async () => {
        const metaRes = await agents.ownerB.get(`/api/documents/${confidentialDocId}`);
        expect(metaRes.status).toBe(404);

        const downloadRes = await agents.ownerB.get(`/api/documents/${confidentialDocId}/download`);
        expect(downloadRes.status).toBe(404);

        const editRes = await agents.ownerB
            .put(`/api/documents/${confidentialDocId}`)
            .field("name", "Hacked Title");
        expect(editRes.status).toBe(404);

        const shareRes = await agents.ownerB
            .post(`/api/documents/${confidentialDocId}/permissions`)
            .send({ email: emails.ownerB, permission: "read" });
        expect(shareRes.status).toBe(404);

        const permissionList = await agents.ownerB.get(`/api/documents/${confidentialDocId}/permissions`);
        expect(permissionList.status).toBe(404);

        const deleteRes = await agents.ownerB.delete(`/api/documents/${confidentialDocId}`);
        expect(deleteRes.status).toBe(404);

        const auditRes = await agents.ownerB.get(`/api/documents/${confidentialDocId}/audit`);
        expect(auditRes.status).toBe(404);

        // Administrators have no implicit document access either.
        const adminMeta = await agents.adminE.get(`/api/documents/${confidentialDocId}`);
        expect(adminMeta.status).toBe(404);

        const adminDownload = await agents.adminE.get(`/api/documents/${confidentialDocId}/download`);
        expect(adminDownload.status).toBe(404);

        // Database state: the document is untouched and no grant was created.
        const document = await fetchRow("documents", "id = $1", [confidentialDocId]);
        expect(document.name).toBe(`Salary_Letter_${testRunId}`);
        expect(document.owner_id).toBe(users.ownerA.id);

        expect(
            await countRows(
                "document_permissions",
                "document_id = $1 AND user_id = $2",
                [confidentialDocId, users.ownerB.id]
            )
        ).toBe(0);

        expect(
            await countRows(
                "document_permissions",
                "document_id = $1 AND user_id = $2",
                [confidentialDocId, users.adminE.id]
            )
        ).toBe(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("10. 'read' allows view/download but blocks edit/delete/share", async () => {
        const grantRes = await agents.ownerA
            .post(`/api/documents/${confidentialDocId}/permissions`)
            .send({ email: emails.viewerC, permission: "read" });
        expect(grantRes.status).toBe(200);
        expect(grantRes.body.permission).toBe("read");

        // Database state: exactly one grant row.
        const grants = await pool.query(
            "SELECT permission FROM document_permissions WHERE document_id = $1 AND user_id = $2",
            [confidentialDocId, users.viewerC.id]
        );
        expect(grants.rows).toHaveLength(1);
        expect(grants.rows[0].permission).toBe("read");

        const meta = await agents.viewerC.get(`/api/documents/${confidentialDocId}`);
        expect(meta.status).toBe(200);
        expect(meta.body.document.access_level).toBe("read");

        const download = await agents.viewerC.get(`/api/documents/${confidentialDocId}/download`);
        expect(download.status).toBe(200);
        expect(download.headers["cache-control"]).toMatch(/no-store/i);
        expect(download.headers["x-content-type-options"]).toBe("nosniff");
        expect(download.headers["content-disposition"]).toMatch(/attachment/);

        const edit = await agents.viewerC
            .put(`/api/documents/${confidentialDocId}`)
            .field("name", "Hacked");
        expect(edit.status).toBe(403);

        const remove = await agents.viewerC.delete(`/api/documents/${confidentialDocId}`);
        expect(remove.status).toBe(403);

        const share = await agents.viewerC
            .post(`/api/documents/${confidentialDocId}/permissions`)
            .send({ email: emails.ownerB, permission: "read" });
        expect(share.status).toBe(404);

        // Database state: the document was not modified.
        const document = await fetchRow("documents", "id = $1", [confidentialDocId]);
        expect(document.name).toBe(`Salary_Letter_${testRunId}`);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("11. 'edit' allows editing but blocks delete and sharing", async () => {
        const grantRes = await agents.ownerA
            .post(`/api/documents/${confidentialDocId}/permissions`)
            .send({ email: emails.editorD, permission: "edit" });
        expect(grantRes.status).toBe(200);

        const edit = await agents.editorD
            .put(`/api/documents/${confidentialDocId}`)
            .field("name", `Updated_Salary_${testRunId}`)
            .field("category", "Compensation")
            .field("description", "Updated by editor");
        expect(edit.status).toBe(200);
        expect(edit.body.document.name).toBe(`Updated_Salary_${testRunId}`);

        const remove = await agents.editorD.delete(`/api/documents/${confidentialDocId}`);
        expect(remove.status).toBe(403);

        const share = await agents.editorD
            .post(`/api/documents/${confidentialDocId}/permissions`)
            .send({ email: emails.ownerB, permission: "read" });
        expect(share.status).toBe(404);

        // Database state: the edit was persisted, the document still exists.
        const document = await fetchRow("documents", "id = $1", [confidentialDocId]);
        expect(document.name).toBe(`Updated_Salary_${testRunId}`);
        expect(document.updated_at).not.toBeNull();
    });

    // ══════════════════════════════════════════════════════════════════════
    test("12. Revoked permissions take effect immediately", async () => {
        const revokeRes = await agents.ownerA.delete(
            `/api/documents/${confidentialDocId}/permissions/${users.viewerC.id}/read`
        );
        expect(revokeRes.status).toBe(200);

        const download = await agents.viewerC.get(`/api/documents/${confidentialDocId}/download`);
        expect(download.status).toBe(404);

        const meta = await agents.viewerC.get(`/api/documents/${confidentialDocId}`);
        expect(meta.status).toBe(404);

        // Database state: the grant row is gone.
        expect(
            await countRows(
                "document_permissions",
                "document_id = $1 AND user_id = $2",
                [confidentialDocId, users.viewerC.id]
            )
        ).toBe(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("13. Search only returns documents the caller may access", async () => {
        const ownerSearch = await agents.ownerA
            .get("/api/documents")
            .query({ q: testRunId, category: "Compensation" });
        expect(ownerSearch.status).toBe(200);
        expect(ownerSearch.body.documents.some((d) => d.id === confidentialDocId)).toBe(true);

        const attackerSearch = await agents.ownerB
            .get("/api/documents")
            .query({ q: testRunId, category: "Compensation" });
        expect(attackerSearch.status).toBe(200);
        expect(attackerSearch.body.documents.some((d) => d.id === confidentialDocId)).toBe(false);
        expect(attackerSearch.body.documents).toHaveLength(0);

        // Database state: the query never widened the access rules.
        expect(
            await countRows(
                "document_permissions",
                "document_id = $1 AND user_id = $2",
                [confidentialDocId, users.ownerB.id]
            )
        ).toBe(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("14. Non-admins are blocked from the global audit log and user management", async () => {
        expect((await agents.viewerC.get("/api/admin/audit-logs")).status).toBe(403);
        expect((await agents.ownerA.get("/api/admin/audit-logs")).status).toBe(403);
        expect((await agents.ownerA.get("/api/admin/users")).status).toBe(403);

        const ownerRole = await agents.ownerA
            .patch(`/api/admin/users/${users.viewerC.id}/role`)
            .send({ role: "admin" });
        expect(ownerRole.status).toBe(403);

        // Database state: the role was not changed.
        const account = await fetchRow("users", "id = $1", [users.viewerC.id]);
        expect(account.role).toBe("viewer");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("15. Only the document owner sees the owner-scoped audit trail", async () => {
        const ownerAudit = await agents.ownerA.get(`/api/documents/${confidentialDocId}/audit`);
        expect(ownerAudit.status).toBe(200);
        expect(ownerAudit.body.logs.length).toBeGreaterThan(0);
        expect(
            ownerAudit.body.logs.every((log) => log.document_id === confidentialDocId)
        ).toBe(true);

        const bobAudit = await agents.ownerB.get(`/api/documents/${confidentialDocId}/audit`);
        expect(bobAudit.status).toBe(404);

        const adminAudit = await agents.adminE.get(`/api/documents/${confidentialDocId}/audit`);
        expect(adminAudit.status).toBe(404);

        // Database state: the denied attempt was recorded.
        const denials = await fetchAuditLogs({
            action: "document_audit_view", outcome: "denied"
        });
        expect(denials.length).toBeGreaterThanOrEqual(2);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("16. Only administrators can change roles or account status", async () => {
        const ownerAttempt = await agents.ownerA
            .patch(`/api/admin/users/${users.viewerC.id}/role`)
            .send({ role: "document_owner" });
        expect(ownerAttempt.status).toBe(403);

        const viewerAttempt = await agents.viewerC
            .patch(`/api/admin/users/${users.viewerC.id}/disable`)
            .send({ disabled: true });
        expect(viewerAttempt.status).toBe(403);

        const adminChange = await agents.adminE
            .patch(`/api/admin/users/${users.viewerC.id}/role`)
            .send({ role: "viewer" });
        expect(adminChange.status).toBe(200);

        // Database state: the role was persisted and the change was audited.
        const account = await fetchRow("users", "id = $1", [users.viewerC.id]);
        expect(account.role).toBe("viewer");

        const audit = await fetchAuditLogs({ action: "admin_user_role_change", outcome: "success" });
        expect(audit.length).toBeGreaterThan(0);
        expect(audit[0].details.previousRole).toBeDefined();
        expect(audit[0].details.newRole).toBe("viewer");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("17. The last active administrator cannot be demoted or disabled", async () => {
        // Reduce the number of active administrators to one (adminE).
        const disableG = await agents.adminE
            .patch(`/api/admin/users/${users.adminG.id}/disable`)
            .send({ disabled: true });
        expect(disableG.status).toBe(200);

        const disableF = await agents.adminE
            .patch(`/api/admin/users/${users.adminF.id}/disable`)
            .send({ disabled: true });
        expect(disableF.status).toBe(200);

        const activeAdmins = await countRows(
            "users", "role = 'admin' AND is_disabled = false"
        );
        expect(activeAdmins).toBe(1);

        // Demoting the only remaining active administrator must be refused.
        const demote = await agents.adminE
            .patch(`/api/admin/users/${users.adminG.id}/role`)
            .send({ role: "viewer" });
        expect(demote.status).toBe(409);
        expect(demote.body.message).toMatch(/last active administrator/i);

        const disable = await agents.adminE
            .patch(`/api/admin/users/${users.adminF.id}/disable`)
            .send({ disabled: true });
        expect(disable.status).toBe(409);

        // Self-modification is refused as well.
        const selfDemote = await agents.adminE
            .patch(`/api/admin/users/${users.adminE.id}/role`)
            .send({ role: "viewer" });
        expect(selfDemote.status).toBe(400);

        const selfDisable = await agents.adminE
            .patch(`/api/admin/users/${users.adminE.id}/disable`)
            .send({ disabled: true });
        expect(selfDisable.status).toBe(400);

        // Database state: nobody was demoted or disabled.
        for (const adminId of [users.adminE.id, users.adminF.id, users.adminG.id]) {
            const account = await fetchRow("users", "id = $1", [adminId]);
            expect(account.role).toBe("admin");
        }

        const adminF = await fetchRow("users", "id = $1", [users.adminF.id]);
        expect(adminF.is_disabled).toBe(true);

        // Restore a second active administrator for the remaining tests.
        const enableF = await agents.adminE
            .patch(`/api/admin/users/${users.adminF.id}/disable`)
            .send({ disabled: false });
        expect(enableF.status).toBe(200);

        expect(
            await countRows("users", "role = 'admin' AND is_disabled = false")
        ).toBe(2);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("18. Audit events distinguish success and denial", async () => {
        const logs = await agents.adminE
            .get("/api/admin/audit-logs")
            .query({ limit: 200 });
        expect(logs.status).toBe(200);

        const successEvents = logs.body.logs.filter((l) => l.outcome === "success");
        const deniedEvents = logs.body.logs.filter((l) => l.outcome === "denied");
        expect(successEvents.length).toBeGreaterThan(0);
        expect(deniedEvents.length).toBeGreaterThan(0);
        expect(logs.body.logs.length).toBeGreaterThan(10);

        // Database state: both outcomes exist.
        expect(await countRows("audit_logs", "outcome = 'success'")).toBeGreaterThan(0);
        expect(await countRows("audit_logs", "outcome = 'denied'")).toBeGreaterThan(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("19. The audit log is append-only and the hash chain verifies", async () => {
        const before = await countRows("audit_logs");

        await expect(
            pool.query("DELETE FROM audit_logs WHERE outcome = 'denied'")
        ).rejects.toThrow(/append-only/i);

        await expect(
            pool.query("UPDATE audit_logs SET outcome = 'success' WHERE outcome = 'denied'")
        ).rejects.toThrow(/append-only/i);

        // Database state: nothing was deleted or modified.
        expect(await countRows("audit_logs")).toBe(before);

        const chain = await verifyAuditChain();
        expect(chain.valid).toBe(true);
        expect(chain.totalEntries).toBe(before);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("20. Logging out invalidates the session", async () => {
        const email = `logout.${testRunId}@trustvault.test`;
        const tempAgent = request.agent(app);

        await tempAgent.post("/api/auth/register").send({
            name: "Logout Test", email, password, role: "viewer"
        });
        await tempAgent.post("/api/auth/login").send({ email, password });

        const before = await tempAgent.get("/api/auth/me");
        expect(before.status).toBe(200);

        const sessionsBefore = await countRows("user_sessions");
        expect(sessionsBefore).toBeGreaterThan(0);

        const logout = await tempAgent.post("/api/auth/logout");
        expect(logout.status).toBe(200);

        const after = await tempAgent.get("/api/auth/me");
        expect(after.status).toBe(401);

        // Database state: the session row was removed.
        expect(await countRows("user_sessions")).toBe(sessionsBefore - 1);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("21. The database rejects invalid permission values", async () => {
        await expect(
            pool.query(
                `INSERT INTO document_permissions (document_id, user_id, permission, granted_by)
                 VALUES ($1, $2, 'superuser', $3)`,
                [confidentialDocId, users.ownerB.id, users.ownerA.id]
            )
        ).rejects.toThrow();

        // Database state: no invalid row was written.
        expect(
            await countRows(
                "document_permissions",
                "document_id = $1 AND user_id = $2",
                [confidentialDocId, users.ownerB.id]
            )
        ).toBe(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("22. Error responses do not expose internals", async () => {
        const badId = "00000000-0000-0000-0000-000000000000";
        const meta = await agents.ownerA.get(`/api/documents/${badId}`);
        expect(meta.status).toBe(404);

        const body = JSON.stringify(meta.body);
        expect(body).not.toMatch(/SELECT|FROM|WHERE|postgres|pg_/i);
        expect(body).not.toMatch(/Error:|at\s+\w+\s*\(/);
        expect(body).not.toMatch(/stack/i);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("23. The admin console is protected and functional", async () => {
        const nonAdminRes = await agents.ownerA.get("/api/admin/audit-logs");
        expect(nonAdminRes.status).toBe(403);

        const adminLogs = await agents.adminE
            .get("/api/admin/audit-logs")
            .query({ outcome: "denied", limit: 50 });
        expect(adminLogs.status).toBe(200);
        expect(adminLogs.body.logs.length).toBeGreaterThan(0);
        expect(
            adminLogs.body.logs.every((log) => log.outcome === "denied")
        ).toBe(true);

        const chain = await agents.adminE.get("/api/admin/verify-chain");
        expect(chain.status).toBe(200);
        expect(chain.body.valid).toBe(true);

        const overview = await agents.adminE.get("/api/admin/overview");
        expect(overview.status).toBe(200);
        expect(overview.body.stats).toBeDefined();
        expect(overview.body.stats.total_users).toBeGreaterThan(0);
        expect(overview.body.chainIntegrity.valid).toBe(true);

        // Database state: the denied console access was recorded.
        const denials = await fetchAuditLogs({
            action: "admin_console_access", outcome: "denied"
        });
        expect(denials.length).toBeGreaterThan(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("24. Permissions cannot be granted to oneself or to the owner", async () => {
        const selfGrant = await agents.ownerA
            .post(`/api/documents/${confidentialDocId}/permissions`)
            .send({ email: emails.ownerA, permission: "read" });
        expect(selfGrant.status).toBe(400);

        // Database state: no grant was created.
        expect(
            await countRows(
                "document_permissions",
                "document_id = $1 AND user_id = $2",
                [confidentialDocId, users.ownerA.id]
            )
        ).toBe(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("25. Administrators never receive implicit document access", async () => {
        expect(
            await countRows(
                "document_permissions",
                "document_id = $1 AND user_id = ANY($2::uuid[])",
                [confidentialDocId, [users.adminE.id, users.adminF.id, users.adminG.id]]
            )
        ).toBe(0);

        const adminListing = await agents.adminE.get("/api/documents");
        expect(adminListing.status).toBe(200);
        expect(
            adminListing.body.documents.some((d) => d.id === confidentialDocId)
        ).toBe(false);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("26. The user directory is restricted to owners and administrators", async () => {
        const viewerDirectory = await agents.viewerC.get("/api/auth/users");
        expect(viewerDirectory.status).toBe(403);

        const ownerDirectory = await agents.ownerA.get("/api/auth/users");
        expect(ownerDirectory.status).toBe(200);
        expect(Array.isArray(ownerDirectory.body.users)).toBe(true);

        const adminDirectory = await agents.adminE.get("/api/auth/users");
        expect(adminDirectory.status).toBe(200);

        // Database state: the denied attempt was recorded.
        const denials = await fetchAuditLogs({
            action: "auth_user_directory", outcome: "denied"
        });
        expect(denials.length).toBeGreaterThan(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("27. Uploads with an empty file are rejected with 400", async () => {
        const before = await countRows("documents");

        const res = await agents.ownerA
            .post("/api/documents")
            .field("name", "Empty Upload")
            .attach("file", Buffer.alloc(0), "empty.pdf");
        expect(res.status).toBe(400);
        expect(res.body.message).toMatch(/empty/i);

        // Database state: nothing was stored.
        expect(await countRows("documents")).toBe(before);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("28. Malformed pagination and date filters are rejected with 400", async () => {
        expect((await agents.ownerA.get("/api/documents").query({ limit: "abc" })).status).toBe(400);
        expect((await agents.ownerA.get("/api/documents").query({ page: "-1" })).status).toBe(400);
        expect((await agents.ownerA.get("/api/documents").query({ from: "not-a-date" })).status).toBe(400);
        expect(
            (await agents.ownerA.get("/api/documents").query({ from: "2030-01-02", to: "2030-01-01" })).status
        ).toBe(400);

        // A valid filter still works.
        const valid = await agents.ownerA
            .get("/api/documents")
            .query({ from: "2020-01-01", to: "2030-01-01", page: 1, limit: 10 });
        expect(valid.status).toBe(200);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("29. The session cookie is httpOnly and SameSite=Lax", async () => {
        const response = await request(app)
            .post("/api/auth/login")
            .send({ email: emails.ownerA, password });

        expect(response.status).toBe(200);

        const cookies = response.headers["set-cookie"] || [];
        const sessionCookie = cookies.find((cookie) => cookie.startsWith("trustvault.sid="));

        expect(sessionCookie).toBeDefined();
        expect(sessionCookie).toMatch(/HttpOnly/i);
        expect(sessionCookie).toMatch(/SameSite=Lax/i);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("30. Passwords longer than 72 bytes are rejected", async () => {
        const email = `longpassword.${testRunId}@trustvault.test`;
        const tooLong = "a".repeat(73);

        const response = await request(app).post("/api/auth/register").send({
            name: "Long Password", email, password: tooLong, role: "viewer"
        });
        expect(response.status).toBe(400);
        expect(response.body.message).toMatch(/72 bytes/i);

        // Database state: the account was not created.
        expect(await fetchRow("users", "email = $1", [email])).toBeNull();
    });

    // ══════════════════════════════════════════════════════════════════════
    test("31. The document owner can delete their document and the blob is removed", async () => {
        const document = await uploadDocument(agents.ownerA, {
            name: `Disposable_${testRunId}`,
            category: "Temporary"
        });

        const storageKey = (await fetchRow("documents", "id = $1", [document.id])).storage_key;

        const response = await agents.ownerA.delete(`/api/documents/${document.id}`);
        expect(response.status).toBe(200);
        expect(response.body.message).toMatch(/deleted/i);

        // Database state: the document and its blob are gone.
        expect(await fetchRow("documents", "id = $1", [document.id])).toBeNull();
        expect(await fetchRow("document_blobs", "storage_key = $1", [storageKey])).toBeNull();
        expect(
            await countRows(
                "document_permissions",
                "document_id = $1",
                [document.id]
            )
        ).toBe(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("32. The complete audit chain is valid at the end of the run", async () => {
        const chain = await verifyAuditChain();
        expect(chain.valid).toBe(true);
        expect(chain.reason).toBe("ok");
        expect(chain.totalEntries).toBeGreaterThan(30);

        const anchor = await pool.query(
            "SELECT last_entry_id, last_hash FROM audit_chain_state WHERE id = 1"
        );
        const head = await pool.query(
            "SELECT COALESCE(MAX(id), 0)::bigint AS id FROM audit_logs"
        );

        expect(anchor.rows).toHaveLength(1);
        // The anchor stores the *id* of the newest entry — not the number of
        // entries (the ids are not contiguous when rows were removed).
        expect(Number(anchor.rows[0].last_entry_id)).toBe(Number(head.rows[0].id));
        expect(anchor.rows[0].last_hash).toBe(chain.headHash);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("33. A tampered storage key cannot escape the upload directory", async () => {
        const canaryName = `canary-${testRunId}.txt`;
        const canaryPath = path.join(path.dirname(config.UPLOAD_DIR), canaryName);
        const canaryContent = "CANARY-CONTENT-MUST-NOT-LEAK";

        await fs.writeFile(canaryPath, canaryContent, "utf8");

        try {
            // ── The unit boundary ─────────────────────────────────────────
            // A storage key is always a UUID. Everything else is rejected
            // before it is ever used to build a path.
            expect(isValidStorageKey(`../${canaryName}`)).toBe(false);
            expect(isValidStorageKey("../../../../../../etc/passwd")).toBe(false);
            expect(isValidStorageKey("C:\\Windows\\win.ini")).toBe(false);
            expect(isValidStorageKey("")).toBe(false);
            expect(isValidStorageKey(null)).toBe(false);

            // Reading through a traversing key must fail ...
            await expect(getFileBuffer(`../${canaryName}`)).rejects.toBeDefined();
            // ... and it must not have touched the file.
            await expect(fs.readFile(canaryPath, "utf8")).resolves.toBe(canaryContent);

            // Deleting through a traversing key must delete nothing.
            await deleteFile(`../${canaryName}`);
            await expect(fs.readFile(canaryPath, "utf8")).resolves.toBe(canaryContent);

            // ── The HTTP boundary ─────────────────────────────────────────
            const document = await uploadDocument(agents.ownerA, {
                name: `Traversal_${testRunId}`,
                category: "Security"
            });

            const maliciousKey = `../${canaryName}`;

            // The blob row is created as well, so that the validated foreign
            // key of `documents.storage_key` is satisfied and the tampered
            // key really reaches the application.
            await pool.query(
                "INSERT INTO document_blobs (storage_key, file_data) VALUES ($1, $2)",
                [maliciousKey, Buffer.from(canaryContent, "utf8")]
            );
            await pool.query(
                "UPDATE documents SET storage_key = $1 WHERE id = $2",
                [maliciousKey, document.id]
            );

            const stored = await fetchRow("documents", "id = $1", [document.id]);
            expect(stored.storage_key).toBe(maliciousKey);

            // The download must refuse the tampered key instead of serving the
            // file that lies outside the upload directory.
            const download = await agents.ownerA.get(
                `/api/documents/${document.id}/download`
            );
            expect(download.status).toBe(404);
            expect(JSON.stringify(download.body)).not.toContain("CANARY");

            // Deleting the document must not remove the file outside the
            // upload directory either.
            const removal = await agents.ownerA.delete(`/api/documents/${document.id}`);
            expect(removal.status).toBe(200);

            // The canary is still there.
            await expect(fs.readFile(canaryPath, "utf8")).resolves.toBe(canaryContent);

            // Database state: the document and its blob row are gone, the file
            // outside the upload directory is untouched.
            expect(await fetchRow("documents", "id = $1", [document.id])).toBeNull();
            expect(
                await fetchRow("document_blobs", "storage_key = $1", [maliciousKey])
            ).toBeNull();
        } finally {
            await fs.rm(canaryPath, { force: true });
        }
    });

    // ══════════════════════════════════════════════════════════════════════
    test("34. An oversized request body is rejected", async () => {
        const oversized = JSON.stringify({ name: "x".repeat(2 * 1024 * 1024) });

        const response = await request(app)
            .put("/api/auth/me")
            .type("json")
            .send(oversized);

        expect(response.status).toBe(413);
        expect(response.body.message).toMatch(/too large/i);

        // Database state: nothing was written.
        const profile = await fetchRow("users", "id = $1", [users.ownerA.id]);
        expect(profile.name).toBe("Alice Owner");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("35. No secret material is exposed in a response", async () => {
        const responses = [
            await agents.ownerA.get("/api/auth/me"),
            await agents.ownerA.get("/api/documents"),
            await agents.adminE.get("/api/admin/overview"),
            await agents.adminE.get("/api/admin/users"),
            await agents.adminE.get("/api/admin/audit-logs"),
            await agents.adminE.get("/api/admin/verify-chain"),
            await request(app).get("/api/auth/csrf-token"),
            await request(app).get("/api/health"),
            await request(app).get("/api/health/db"),
            await request(app)
                .post("/api/auth/login")
                .send({ email: `nobody.${testRunId}@trustvault.test`, password: "wrong" }),
            await request(app).get("/api/documents/00000000-0000-0000-0000-000000000000")
        ];

        const secret = config.SESSION_SECRET;

        for (const response of responses) {
            const body = JSON.stringify(response.body || {});

            if (typeof secret === "string" && secret.length > 0) {
                expect(body).not.toContain(secret);
            }

            expect(body).not.toMatch(/postgresql:\/\//i);
            expect(body).not.toMatch(/password_hash/i);
            expect(body).not.toMatch(/SESSION_SECRET/i);
            expect(body).not.toMatch(/DATABASE_URL/i);
        }
    });

    // ══════════════════════════════════════════════════════════════════════
    test("36. Concurrent demotions never leave the system without an administrator", async () => {
        // A third administrator, so that the demotions can race each other.
        const adminH = await createUser({
            name: "Heidi Admin",
            email: `adminh.${testRunId}@trustvault.test`,
            role: "admin"
        });

        const loginAs = async (email) => {
            const agent = request.agent(app);
            const response = await agent
                .post("/api/auth/login")
                .send({ email, password });

            expect(response.status).toBe(200);
            return agent;
        };

        // Fresh sessions: the accounts were disabled and re-enabled in an
        // earlier test, and a disable invalidates every session.
        const actorE = await loginAs(emails.adminE);
        const actorF = await loginAs(emails.adminF);
        const actorH = await loginAs(`adminh.${testRunId}@trustvault.test`);

        const before = await countRows("users", "role = 'admin' AND is_disabled = false");
        expect(before).toBe(3);

        // Three administrators demote each other at the same time.
        const responses = await Promise.all([
            actorE.patch(`/api/admin/users/${users.adminF.id}/role`).send({ role: "viewer" }),
            actorF.patch(`/api/admin/users/${adminH.id}/role`).send({ role: "viewer" }),
            actorH.patch(`/api/admin/users/${users.adminE.id}/role`).send({ role: "viewer" })
        ]);

        // No request may fail with a server error, and the refusals must be
        // the documented ones (the actor lost the role in the meantime, or
        // the target was the last active administrator).
        for (const response of responses) {
            expect([200, 403, 409]).toContain(response.status);
        }

        const successful = responses.filter((response) => response.status === 200).length;

        // Database state: every successful request really changed a role, and
        // at least one administrator is left.
        const contenderIds = [users.adminE.id, users.adminF.id, adminH.id];
        const placeholders = contenderIds.map((_, index) => `$${index + 1}`).join(", ");

        const demoted = await countRows(
            "users",
            `id IN (${placeholders}) AND role <> 'admin'`,
            contenderIds
        );

        expect(demoted).toBeGreaterThanOrEqual(1);
        expect(demoted).toBeLessThanOrEqual(successful);
        expect(demoted).toBeLessThan(3);

        const after = await countRows("users", "role = 'admin' AND is_disabled = false");
        expect(after).toBe(3 - demoted);
        expect(after).toBeGreaterThanOrEqual(1);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("37. Injection payloads are treated as data and not as SQL", async () => {
        const payloads = [
            "' OR '1'='1",
            "'; DROP TABLE documents; --",
            "' UNION SELECT NULL, NULL, NULL --",
            "\\'; DELETE FROM users; --",
            "1; DELETE FROM audit_logs; --"
        ];

        const documentsBefore = await countRows("documents");
        const usersBefore = await countRows("users");
        const logsBefore = await countRows("audit_logs");

        // In the search query.
        for (const payload of payloads) {
            const response = await agents.ownerA
                .get("/api/documents")
                .query({ q: payload });

            expect([200, 400]).toContain(response.status);
            expect(JSON.stringify(response.body)).not.toMatch(
                /SELECT\s|FROM\s+(users|documents|audit_logs)|pg_|postgres/i
            );
        }

        // In the path.
        for (const payload of payloads) {
            const response = await agents.ownerA.get(
                `/api/documents/${encodeURIComponent(payload)}`
            );
            expect(response.status).toBe(404);
        }

        // In the body of an upload.
        const upload = await agents.ownerA
            .post("/api/documents")
            .field("name", "'; DROP TABLE documents; --")
            .field("category", "' OR '1'='1")
            .field("description", "'; DELETE FROM users; --")
            .attach("file", VALID_PDF_BUFFER, "document.pdf");

        expect(upload.status).toBe(201);

        // In the administration search — a fresh administrator, because the
        // previous test may have demoted the existing ones.
        const adminEmail = `admini.${testRunId}@trustvault.test`;
        await createUser({ name: "Ivan Admin", email: adminEmail, role: "admin" });

        const adminAgent = request.agent(app);
        const adminLogin = await adminAgent
            .post("/api/auth/login")
            .send({ email: adminEmail, password });
        expect(adminLogin.status).toBe(200);

        const adminSearch = await adminAgent
            .get("/api/admin/audit-logs")
            .query({ q: "' OR '1'='1" });
        expect(adminSearch.status).toBe(200);
        expect(Array.isArray(adminSearch.body.logs)).toBe(true);

        // Database state: every table is intact and the payload was stored as
        // a plain string.
        expect(await countRows("documents")).toBe(documentsBefore + 1);
        expect(await countRows("users")).toBe(usersBefore + 1);
        expect(await countRows("audit_logs")).toBeGreaterThanOrEqual(logsBefore);

        const stored = await fetchRow("documents", "id = $1", [upload.body.document.id]);
        expect(stored.name).toBe("'; DROP TABLE documents; --");
        expect(stored.category).toBe("' OR '1'='1");
        expect(stored.description).toBe("'; DELETE FROM users; --");

        // The audit trail of the upload exists — the payload did not disable
        // the logging.
        const uploadLogs = await fetchAuditLogs({ action: "document_upload", limit: 20 });
        expect(uploadLogs.length).toBeGreaterThan(0);

        // Clean up.
        const removal = await agents.ownerA.delete(
            `/api/documents/${upload.body.document.id}`
        );
        expect(removal.status).toBe(200);
        expect(await countRows("documents")).toBe(documentsBefore);
    });
});
