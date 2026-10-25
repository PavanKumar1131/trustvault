/**
 * Session suite.
 *
 * Covers the session lifecycle, the invalidation of sessions when an account
 * is disabled, the revocation of other sessions after a password change and
 * the cookie hardening.
 */

const request = require("supertest");
const app = require("../src/app");
const pool = require("../src/db");
const {
    TEST_PASSWORD,
    VALID_PDF_BUFFER,
    resetDatabase,
    createUser,
    registerAndLogin,
    fetchRow,
    countRows,
    fetchAuditLogs
} = require("./helpers");

const REASON = "Operational access change approved by an administrator.";

describe("TrustVault sessions", () => {
    const testRunId = Date.now().toString(36);
    const password = TEST_PASSWORD;

    /**
     * Extracts the raw session id from a `set-cookie` header.
     *
     * express-session signs the cookie value ("s:<sid>.<signature>"); the
     * interesting part is the session id in front of the signature.
     */
    function extractSessionCookie(setCookieHeader) {
        const cookies = setCookieHeader || [];
        const raw = cookies.find((cookie) => cookie.startsWith("trustvault.sid="));

        if (!raw) {
            return null;
        }

        const value = decodeURIComponent(
            raw.split(";")[0].slice("trustvault.sid=".length)
        );

        return value.startsWith("s:")
            ? value.slice(2).split(".")[0]
            : value;
    }

    const emails = {
        user: `session.user.${testRunId}@trustvault.test`,
        second: `session.second.${testRunId}@trustvault.test`,
        admin: `session.admin.${testRunId}@trustvault.test`
    };

    const agents = {};
    const users = {};

    beforeAll(async () => {
        await resetDatabase();

        const user = await registerAndLogin(app, {
            name: "Session User", email: emails.user, role: "document_owner"
        });
        agents.user = user.agent;
        users.user = user.user;

        const second = await registerAndLogin(app, {
            name: "Session Second", email: emails.second, role: "viewer"
        });
        agents.second = second.agent;
        users.second = second.user;

        users.admin = await createUser({
            name: "Session Admin", email: emails.admin, role: "admin"
        });
        agents.admin = request.agent(app);
        const adminLogin = await agents.admin
            .post("/api/auth/login")
            .send({ email: emails.admin, password });

        if (adminLogin.status !== 200) {
            throw new Error(
                `Admin login failed (${adminLogin.status}): ${JSON.stringify(adminLogin.body)}`
            );
        }
    });

    // ══════════════════════════════════════════════════════════════════════
    test("1. Logging in creates a server-side session row", async () => {
        const sessions = await pool.query(
            "SELECT sid, expire FROM user_sessions WHERE sess->>'userId' = $1",
            [users.user.id]
        );

        expect(sessions.rows.length).toBeGreaterThan(0);
        expect(sessions.rows[0].sid).toEqual(expect.any(String));
        expect(new Date(sessions.rows[0].expire).getTime()).toBeGreaterThan(Date.now());
    });

    // ══════════════════════════════════════════════════════════════════════
    test("2. The session id changes on login (session fixation defence)", async () => {
        const anonymous = request.agent(app);

        const before = await anonymous.get("/api/auth/csrf-token");
        expect(before.status).toBe(200);

        const cookieBefore = extractSessionCookie(before.headers["set-cookie"]);

        const sessionsBefore = await countRows(
            "user_sessions",
            "sess->>'userId' = $1",
            [users.second.id]
        );

        const login = await anonymous.post("/api/auth/login").send({
            email: emails.second,
            password
        });
        expect(login.status).toBe(200);

        const cookieAfter = extractSessionCookie(login.headers["set-cookie"]);

        expect(cookieAfter).toBeDefined();
        if (cookieBefore) {
            expect(cookieAfter).not.toBe(cookieBefore);
        }

        // Database state: the login created exactly one additional session.
        const sessions = await countRows(
            "user_sessions",
            "sess->>'userId' = $1",
            [users.second.id]
        );
        expect(sessions).toBe(sessionsBefore + 1);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("3. Logging out destroys the session row", async () => {
        const email = `session.logout.${testRunId}@trustvault.test`;
        const temporary = request.agent(app);

        await temporary.post("/api/auth/register").send({
            name: "Logout User", email, password, role: "viewer"
        });
        await temporary.post("/api/auth/login").send({ email, password });

        const account = await fetchRow("users", "email = $1", [email]);
        expect(await countRows("user_sessions", "sess->>'userId' = $1", [account.id])).toBe(1);

        const logout = await temporary.post("/api/auth/logout");
        expect(logout.status).toBe(200);

        // Database state: the session row is gone.
        expect(await countRows("user_sessions", "sess->>'userId' = $1", [account.id])).toBe(0);

        // The cookie is worthless now.
        const after = await temporary.get("/api/auth/me");
        expect(after.status).toBe(401);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("4. Disabling an account removes all of its sessions", async () => {
        const email = `session.disable.${testRunId}@trustvault.test`;
        const target = await registerAndLogin(app, {
            name: "Disable Sessions", email, role: "document_owner"
        });

        expect(
            await countRows("user_sessions", "sess->>'userId' = $1", [target.user.id])
        ).toBe(1);

        const response = await agents.admin
            .patch(`/api/admin/users/${target.user.id}/disable`)
            .send({ disabled: true, reason: REASON });

        expect(response.status).toBe(200);
        expect(response.body.revokedSessions).toBeGreaterThan(0);

        // Database state: no session survived.
        expect(
            await countRows("user_sessions", "sess->>'userId' = $1", [target.user.id])
        ).toBe(0);

        const account = await fetchRow("users", "id = $1", [target.user.id]);
        expect(account.is_disabled).toBe(true);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("5. Re-enabling an account does not resurrect the sessions", async () => {
        const email = `session.reenable.${testRunId}@trustvault.test`;
        const target = await registerAndLogin(app, {
            name: "Reenable Sessions", email, role: "document_owner"
        });

        const disable = await agents.admin
            .patch(`/api/admin/users/${target.user.id}/disable`)
            .send({ disabled: true, reason: REASON });
        expect(disable.status).toBe(200);

        const enable = await agents.admin
            .patch(`/api/admin/users/${target.user.id}/disable`)
            .send({ disabled: false, reason: REASON });
        expect(enable.status).toBe(200);

        // Database state: the account is active again but has no session.
        const account = await fetchRow("users", "id = $1", [target.user.id]);
        expect(account.is_disabled).toBe(false);
        expect(
            await countRows("user_sessions", "sess->>'userId' = $1", [target.user.id])
        ).toBe(0);

        // The old cookie does not work any more ...
        const withOldCookie = await target.agent.get("/api/auth/me");
        expect(withOldCookie.status).toBe(401);

        // ... but the account can log in again.
        const reLogin = await request(app).post("/api/auth/login").send({ email, password });
        expect(reLogin.status).toBe(200);
        expect(
            await countRows("user_sessions", "sess->>'userId' = $1", [target.user.id])
        ).toBe(1);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("6. A password change revokes the other sessions of the account", async () => {
        const email = `session.password.${testRunId}@trustvault.test`;
        const target = await registerAndLogin(app, {
            name: "Password Sessions", email, role: "document_owner"
        });

        // A second browser session for the same account.
        const otherBrowser = request.agent(app);
        const login = await otherBrowser.post("/api/auth/login").send({ email, password });
        expect(login.status).toBe(200);

        expect(
            await countRows("user_sessions", "sess->>'userId' = $1", [target.user.id])
        ).toBe(2);

        const change = await target.agent.post("/api/auth/change-password").send({
            currentPassword: password,
            newPassword: "AnotherStrongPassword!2026"
        });

        expect(change.status).toBe(200);
        expect(change.body.revokedSessions).toBe(1);

        // Database state: only the session that performed the change survived.
        expect(
            await countRows("user_sessions", "sess->>'userId' = $1", [target.user.id])
        ).toBe(1);

        // The other browser session is invalid now.
        const otherAfter = await otherBrowser.get("/api/auth/me");
        expect(otherAfter.status).toBe(401);

        // The session that performed the change still works.
        const ownAfter = await target.agent.get("/api/auth/me");
        expect(ownAfter.status).toBe(200);

        // The old password no longer works, the new one does.
        const oldPassword = await request(app).post("/api/auth/login").send({ email, password });
        expect(oldPassword.status).toBe(401);

        const newPassword = await request(app)
            .post("/api/auth/login")
            .send({ email, password: "AnotherStrongPassword!2026" });
        expect(newPassword.status).toBe(200);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("7. A password change requires the correct current password", async () => {
        const email = `session.wrongpw.${testRunId}@trustvault.test`;
        const target = await registerAndLogin(app, {
            name: "Wrong Password", email, role: "viewer"
        });

        const response = await target.agent.post("/api/auth/change-password").send({
            currentPassword: "ThisIsNotThePassword!1",
            newPassword: "AnotherStrongPassword!2026"
        });

        expect(response.status).toBe(401);
        expect(response.body.message).toMatch(/current password is incorrect/i);

        // Database state: the hash was not changed and the session survived.
        const account = await fetchRow("users", "id = $1", [target.user.id]);
        expect(account.password_hash).toBeTruthy();
        expect(
            await countRows("user_sessions", "sess->>'userId' = $1", [target.user.id])
        ).toBe(1);

        const denials = await fetchAuditLogs({
            action: "auth_change_password",
            outcome: "denied"
        });
        expect(denials.length).toBeGreaterThan(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("8. The session cookie is hardened", async () => {
        const response = await request(app)
            .post("/api/auth/login")
            .send({ email: emails.user, password });

        expect(response.status).toBe(200);

        const cookies = response.headers["set-cookie"] || [];
        const sessionCookie = cookies.find((cookie) => cookie.startsWith("trustvault.sid="));

        expect(sessionCookie).toBeDefined();
        expect(sessionCookie).toMatch(/HttpOnly/i);
        expect(sessionCookie).toMatch(/SameSite=Lax/i);
        expect(sessionCookie).toMatch(/Path=\//i);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("9. Requests without a session are rejected", async () => {
        const anonymous = request(app);

        expect((await anonymous.get("/api/auth/me")).status).toBe(401);
        expect((await anonymous.get("/api/documents")).status).toBe(401);
        expect((await anonymous.get("/api/admin/users")).status).toBe(401);

        // Database state: no session was created by the anonymous requests.
        const total = await countRows("user_sessions");
        expect(total).toBeGreaterThan(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("10. A wrong password does not create a session", async () => {
        const email = `session.wrong.${testRunId}@trustvault.test`;
        await registerAndLogin(app, {
            name: "Wrong Login", email, role: "viewer"
        });

        const account = await fetchRow("users", "email = $1", [email]);
        const before = await countRows("user_sessions", "sess->>'userId' = $1", [account.id]);

        const response = await request(app)
            .post("/api/auth/login")
            .send({ email, password: "TotallyWrongPassword!1" });

        expect(response.status).toBe(401);
        expect(response.body.message).toMatch(/invalid email or password/i);

        // Database state: no new session.
        expect(await countRows("user_sessions", "sess->>'userId' = $1", [account.id])).toBe(
            before
        );
    });

    // ══════════════════════════════════════════════════════════════════════
    test("11. The account state is re-read on every request", async () => {
        const email = `session.liverole.${testRunId}@trustvault.test`;
        const target = await registerAndLogin(app, {
            name: "Live Role", email, role: "viewer"
        });

        const viewerUpload = await target.agent
            .post("/api/documents")
            .field("name", `LiveRoleBefore_${testRunId}`)
            .attach("file", VALID_PDF_BUFFER, "before.pdf");
        expect(viewerUpload.status).toBe(403);

        // Promote the account to Document Owner.
        const promote = await agents.admin
            .patch(`/api/admin/users/${target.user.id}/role`)
            .send({ role: "document_owner", reason: REASON });
        expect(promote.status).toBe(200);

        // The existing session immediately has the new rights.
        const ownerUpload = await target.agent
            .post("/api/documents")
            .field("name", `LiveRoleAfter_${testRunId}`)
            .attach("file", VALID_PDF_BUFFER, "after.pdf");
        expect(ownerUpload.status).toBe(201);

        // Demote again.
        const demote = await agents.admin
            .patch(`/api/admin/users/${target.user.id}/role`)
            .send({ role: "viewer", reason: REASON });
        expect(demote.status).toBe(200);

        const viewerUploadAfter = await target.agent
            .post("/api/documents")
            .field("name", `LiveRoleDemoted_${testRunId}`)
            .attach("file", VALID_PDF_BUFFER, "demoted.pdf");
        expect(viewerUploadAfter.status).toBe(403);

        const me = await target.agent.get("/api/auth/me");
        expect(me.status).toBe(200);
        expect(me.body.user.role).toBe("viewer");

        // The account never gained administrator rights.
        const adminAccessAfter = await target.agent.get("/api/admin/users");
        expect(adminAccessAfter.status).toBe(403);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("12. Distinguishes unauthenticated requests from expired sessions", async () => {
        const anonymous = request(app);

        // 1. Fresh visitor without cookie
        const freshVisit = await anonymous.get("/api/auth/me");
        expect(freshVisit.status).toBe(401);
        expect(freshVisit.body.code).toBe("UNAUTHENTICATED");
        expect(freshVisit.body.message).toMatch(/authentication required/i);

        // 2. Request with expired/invalid session cookie
        const expiredVisit = await anonymous
            .get("/api/auth/me")
            .set("Cookie", ["trustvault.sid=s%3Aexpired-session-id-12345.invalidsig"]);
        expect(expiredVisit.status).toBe(401);
        expect(expiredVisit.body.code).toBe("SESSION_EXPIRED");
        expect(expiredVisit.body.message).toMatch(/session expired/i);
    });
});
