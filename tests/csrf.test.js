/**
 * CSRF and request-protection suite.
 *
 * The main test-suite runs with CSRF protection disabled (the application
 * decides that automatically when NODE_ENV=test). This suite builds a second
 * application instance with the protection switched on and verifies that it
 * really works — the protection must not be broken in production.
 */

const request = require("supertest");
const { createApp } = require("../src/app");
const {
    TEST_PASSWORD,
    resetDatabase,
    createUser,
    fetchRow,
    countRows,
    fetchAuditLogs
} = require("./helpers");

describe("TrustVault CSRF protection", () => {
    const testRunId = Date.now().toString(36);
    const password = TEST_PASSWORD;

    const email = `csrf.user.${testRunId}@trustvault.test`;
    const otherEmail = `csrf.other.${testRunId}@trustvault.test`;

    let csrfApp = null;

    beforeAll(async () => {
        await resetDatabase();

        // A production-like application instance: CSRF protection enabled.
        csrfApp = createApp({ csrfEnabled: true });

        await createUser({
            name: "CSRF User", email, role: "document_owner"
        });
        await createUser({
            name: "CSRF Other", email: otherEmail, role: "document_owner"
        });
    });

    /** Registers, logs in and returns an agent with a fresh CSRF token. */
    async function authenticatedAgent(targetEmail) {
        const agent = request.agent(csrfApp);

        await agent.post("/api/auth/register").send({
            name: "CSRF User",
            email: targetEmail,
            password,
            role: "document_owner"
        });

        const login = await agent.post("/api/auth/login").send({
            email: targetEmail,
            password
        });

        if (login.status !== 200 && login.status !== 409) {
            throw new Error(`Login failed: ${login.status}`);
        }

        const tokenResponse = await agent.get("/api/auth/csrf-token");
        return { agent, token: tokenResponse.body.csrfToken };
    }

    // ══════════════════════════════════════════════════════════════════════
    test("1. The token endpoint returns a usable token and cookie", async () => {
        const agent = request.agent(csrfApp);
        const response = await agent.get("/api/auth/csrf-token");

        expect(response.status).toBe(200);
        expect(response.body.csrfToken).toEqual(expect.any(String));
        expect(response.body.csrfToken.length).toBeGreaterThan(20);

        const cookies = response.headers["set-cookie"] || [];
        const csrfCookie = cookies.find((cookie) => cookie.startsWith("trustvault.csrf="));

        expect(csrfCookie).toBeDefined();
        expect(csrfCookie).toMatch(/HttpOnly/i);
        expect(csrfCookie).toMatch(/SameSite=Lax/i);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("2. A state-changing request without a token is rejected", async () => {
        const { agent } = await authenticatedAgent(email);

        const response = await agent
            .put("/api/auth/me")
            .send({ name: "No Token" });

        expect(response.status).toBe(403);
        expect(response.body.message).toMatch(/csrf/i);

        // Database state: the profile was not changed.
        const account = await fetchRow("users", "email = $1", [email]);
        expect(account.name).toBe("CSRF User");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("3. The same request with a valid token succeeds", async () => {
        const { agent, token } = await authenticatedAgent(email);

        const response = await agent
            .put("/api/auth/me")
            .set("x-csrf-token", token)
            .send({ name: "Token Holder" });

        expect(response.status).toBe(200);
        expect(response.body.user.name).toBe("Token Holder");

        // Database state: the profile was updated.
        const account = await fetchRow("users", "email = $1", [email]);
        expect(account.name).toBe("Token Holder");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("4. A token of another session is rejected", async () => {
        const first = await authenticatedAgent(email);
        const second = await authenticatedAgent(otherEmail);

        // The token of the first session is replayed in the second session.
        const response = await second.agent
            .put("/api/auth/me")
            .set("x-csrf-token", first.token)
            .send({ name: "Replay Attempt" });

        expect(response.status).toBe(403);
        expect(response.body.message).toMatch(/csrf/i);

        // Database state: nothing was changed.
        const account = await fetchRow("users", "email = $1", [otherEmail]);
        expect(account.name).toBe("CSRF Other");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("5. A forged token is rejected", async () => {
        const { agent } = await authenticatedAgent(email);

        const response = await agent
            .put("/api/auth/me")
            .set("x-csrf-token", "not.a.valid.token")
            .send({ name: "Forged" });

        expect(response.status).toBe(403);

        const account = await fetchRow("users", "email = $1", [email]);
        expect(account.name).toBe("Token Holder");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("6. Login and registration are exempt from the token check", async () => {
        const agent = request.agent(csrfApp);

        const registration = await agent.post("/api/auth/register").send({
            name: "Exempt User",
            email: `csrf.exempt.${testRunId}@trustvault.test`,
            password,
            role: "viewer"
        });
        expect(registration.status).toBe(201);

        const login = await agent.post("/api/auth/login").send({
            email: `csrf.exempt.${testRunId}@trustvault.test`,
            password
        });
        expect(login.status).toBe(200);

        // Database state: the account exists and has a session.
        const account = await fetchRow("users", "email = $1", [
            `csrf.exempt.${testRunId}@trustvault.test`
        ]);
        expect(account).not.toBeNull();
        expect(
            await countRows("user_sessions", "sess->>'userId' = $1", [account.id])
        ).toBe(1);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("7. The rejection message stays recognisable for the frontend retry", async () => {
        const { agent } = await authenticatedAgent(email);

        const response = await agent.put("/api/auth/me").send({ name: "No Token" });

        // The frontend (`public/js/api.js`) retries once when it sees a 403
        // with a message mentioning the CSRF token.
        expect(response.status).toBe(403);
        expect(response.body.message).toBe("invalid csrf token");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("8. Read requests are not blocked by the CSRF protection", async () => {
        const { agent } = await authenticatedAgent(email);

        const response = await agent.get("/api/documents");
        expect(response.status).toBe(200);
    });
});

describe("TrustVault request protection", () => {
    const testRunId = Date.now().toString(36);

    beforeAll(async () => {
        await resetDatabase();
    });

    // ══════════════════════════════════════════════════════════════════════
    test("9. The authentication rate limiter blocks repeated attempts", async () => {
        const limitedApp = createApp({ csrfEnabled: false, authRateLimit: 3 });
        const email = `ratelimit.${testRunId}@trustvault.test`;

        const statuses = [];
        for (let attempt = 0; attempt < 5; attempt += 1) {
            const response = await request(limitedApp)
                .post("/api/auth/login")
                .send({ email, password: "WrongPassword!12345" });
            statuses.push(response.status);
        }

        expect(statuses[0]).toBe(401);
        expect(statuses).toContain(429);

        const limited = statuses.filter((status) => status === 429).length;
        expect(limited).toBeGreaterThanOrEqual(1);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("10. The per-account lockout protects against brute force", async () => {
        const app = require("../src/app");
        const email = `lockout.${testRunId}@trustvault.test`;

        await request(app).post("/api/auth/register").send({
            name: "Lockout User", email, password: "StrongTestPassword!2026", role: "viewer"
        });

        const statuses = [];
        for (let attempt = 0; attempt < 6; attempt += 1) {
            const response = await request(app)
                .post("/api/auth/login")
                .send({ email, password: "WrongPassword!12345" });
            statuses.push(response.status);
        }

        // The account is locked out after five failures.
        expect(statuses).toContain(429);
        expect(statuses[statuses.length - 1]).toBe(429);

        // Even the correct password is refused while the lock is active.
        const correct = await request(app)
            .post("/api/auth/login")
            .send({ email, password: "StrongTestPassword!2026" });
        expect(correct.status).toBe(429);

        // Database state: no session was created.
        const account = await fetchRow("users", "email = $1", [email]);
        expect(
            await countRows("user_sessions", "sess->>'userId' = $1", [account.id])
        ).toBe(0);

        // The lockout was audited.
        const denials = await fetchAuditLogs({ action: "auth_login", outcome: "denied" });
        expect(denials.length).toBeGreaterThan(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("11. Security headers are present", async () => {
        const app = require("../src/app");
        const response = await request(app).get("/api/health");

        expect(response.status).toBe(200);
        expect(response.headers["x-powered-by"]).toBeUndefined();
        expect(response.headers["x-content-type-options"]).toBe("nosniff");
        expect(response.headers["content-security-policy"]).toBeDefined();
        expect(response.headers["x-frame-options"]).toMatch(/SAMEORIGIN|DENY/i);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("12. The CSRF protection cannot be switched off in production", async () => {
        const config = require("../src/config");
        const originalIsProduction = config.IS_PRODUCTION;

        // Pretend to be a production instance and try to disable the
        // protection with the test-only option.
        config.IS_PRODUCTION = true;

        try {
            const productionApp = createApp({ csrfEnabled: false });

            // A state-changing request without a token must be refused.
            const withoutToken = await request(productionApp)
                .post("/api/auth/logout")
                .send({});
            expect(withoutToken.status).toBe(403);
            expect(withoutToken.body.message).toMatch(/csrf/i);

            // A request with a forged token must be refused as well.
            const withForgedToken = await request(productionApp)
                .post("/api/auth/logout")
                .set("x-csrf-token", "forged-token-value")
                .send({});
            expect(withForgedToken.status).toBe(403);
            expect(withForgedToken.body.message).toMatch(/csrf/i);

            // Database state: no session was destroyed by the refused requests.
            const sessions = await countRows("user_sessions");
            expect(sessions).toBeGreaterThanOrEqual(0);
        } finally {
            config.IS_PRODUCTION = originalIsProduction;
        }
    });
});
