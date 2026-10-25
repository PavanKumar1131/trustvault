/**
 * Viewer → Document Owner role-upgrade workflow.
 *
 * The suite exercises the real Express routes and the real PostgreSQL test
 * database. Every assertion checks the HTTP answer and the persisted state:
 * the request row, the account role and the append-only audit trail.
 *
 * The test database is isolated by `tests/setupEnv.js`; no development data is
 * touched.
 */

const request = require("supertest");
const app = require("../src/app");
const pool = require("../src/db");
const { verifyAuditChain } = require("../src/services/auditService");
const {
    TEST_PASSWORD,
    VALID_PDF_BUFFER,
    resetDatabase,
    createUser,
    registerAndLogin,
    uploadDocument,
    fetchRow,
    countRows,
    fetchAuditLogs
} = require("./helpers");

const ADMIN_LIST = "/api/admin/role-upgrade-requests";
const DECISION_REASON =
    "Approved after reviewing the submitted business need.";

function statusOf(agent) {
    return agent.get("/api/auth/role-upgrade-request");
}

function submitRequest(agent, body) {
    return agent.post("/api/auth/role-upgrade-request").send(body || {});
}

function approve(agent, requestId, decisionNote = DECISION_REASON) {
    return agent
        .post(`${ADMIN_LIST}/${encodeURIComponent(requestId)}/approve`)
        .send({ decisionNote });
}

function reject(agent, requestId) {
    return agent.post(
        `${ADMIN_LIST}/${encodeURIComponent(requestId)}/reject`
    );
}

/**
 * Installs a trigger that makes the audit append for one action fail.
 *
 * The trigger lives only in the isolated test database and is removed again in
 * the test that installed it. It proves that a failed audit append rolls the
 * critical state change back instead of committing an unauditable change.
 */
async function installAuditFailure(action) {
    await pool.query(`
        CREATE OR REPLACE FUNCTION test_fail_audit_insert() RETURNS trigger AS $$
        BEGIN
            IF NEW.action = '${action}' THEN
                RAISE EXCEPTION 'simulated audit failure';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
    `);

    await pool.query(
        "DROP TRIGGER IF EXISTS test_fail_audit_insert ON audit_logs"
    );
    await pool.query(`
        CREATE TRIGGER test_fail_audit_insert
        BEFORE INSERT ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION test_fail_audit_insert()
    `);
}

async function removeAuditFailure() {
    await pool.query(
        "DROP TRIGGER IF EXISTS test_fail_audit_insert ON audit_logs"
    );
    await pool.query("DROP FUNCTION IF EXISTS test_fail_audit_insert()");
}

describe("Viewer → Document Owner role upgrade", () => {
    const testRunId = Date.now().toString(36);
    const password = TEST_PASSWORD;

    const emails = {
        admin: `upgrade.admin.${testRunId}@trustvault.test`,
        requester: `upgrade.requester.${testRunId}@trustvault.test`,
        rejected: `upgrade.rejected.${testRunId}@trustvault.test`,
        duplicate: `upgrade.duplicate.${testRunId}@trustvault.test`,
        atomic: `upgrade.atomic.${testRunId}@trustvault.test`,
        audited: `upgrade.audited.${testRunId}@trustvault.test`,
        direct: `upgrade.direct.${testRunId}@trustvault.test`,
        session: `upgrade.session.${testRunId}@trustvault.test`,
        other: `upgrade.other.${testRunId}@trustvault.test`,
        owner: `upgrade.owner.${testRunId}@trustvault.test`
    };

    const agents = {};
    const users = {};

    beforeAll(async () => {
        await resetDatabase();

        for (const key of [
            "requester",
            "rejected",
            "duplicate",
            "atomic",
            "audited",
            "direct",
            "session",
            "other"
        ]) {
            const created = await registerAndLogin(app, {
                name: `Upgrade ${key}`,
                email: emails[key],
                role: "viewer"
            });
            agents[key] = created.agent;
            users[key] = created.user;
        }

        const owner = await registerAndLogin(app, {
            name: "Upgrade Owner",
            email: emails.owner,
            role: "document_owner"
        });
        agents.owner = owner.agent;
        users.owner = owner.user;

        users.admin = await createUser({
            name: "Upgrade Admin",
            email: emails.admin,
            role: "admin"
        });
        agents.admin = request.agent(app);
        const login = await agents.admin
            .post("/api/auth/login")
            .send({ email: emails.admin, password });
        expect(login.status).toBe(200);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("1. Registration still creates a Viewer and initial status allows a request", async () => {
        const registration = await request(app)
            .post("/api/auth/register")
            .send({
                name: "Sneaky Self Promotion",
                email: `upgrade.sneaky.${testRunId}@trustvault.test`,
                password,
                role: "admin"
            });

        expect(registration.status).toBe(201);
        expect(registration.body.user.role).toBe("viewer");

        const sneaky = await agents.admin
            .get("/api/admin/users")
            .query({ search: `upgrade.sneaky.${testRunId}` });
        expect(sneaky.status).toBe(200);
        expect(sneaky.body.users).toHaveLength(1);
        expect(sneaky.body.users[0].role).toBe("viewer");

        await pool.query("DELETE FROM users WHERE email = $1", [
            `upgrade.sneaky.${testRunId}@trustvault.test`
        ]);

        const response = await statusOf(agents.requester);
        expect(response.status).toBe(200);
        expect(response.body.currentRole).toBe("viewer");
        expect(response.body.request).toBeNull();
        expect(response.body.canSubmit).toBe(true);
        expect(response.body.cooldownEndsAt).toBeNull();
        expect(response.body.serverTime).toBeTruthy();
    });

    // ══════════════════════════════════════════════════════════════════════
    test("2. Submission persists a pending request and ignores client-supplied authority", async () => {
        const response = await submitRequest(agents.requester, {
            role: "document_owner",
            justification: "I publish the quarterly finance pack.",
            userId: users.other.id,
            approverId: users.admin.id,
            status: "approved",
            decidedBy: users.admin.id
        });

        expect(response.status).toBe(201);
        expect(response.body.request.status).toBe("pending");
        expect(response.body.request.requestedRole).toBe("document_owner");
        expect(response.body.request.justification).toBe(
            "I publish the quarterly finance pack."
        );
        expect(response.body.request).not.toHaveProperty("decidedBy");
        expect(response.body.canSubmit).toBe(false);

        const stored = await fetchRow(
            "requests",
            "id = $1",
            [response.body.request.id]
        );
        expect(stored.requester_id).toBe(users.requester.id);
        expect(stored.status).toBe("pending");
        expect(stored.decided_by).toBeNull();
        expect(stored.decided_at).toBeNull();
        expect(stored.submitted_at).toBeTruthy();

        // One pending request per account: a second submission is refused and
        // no competing row is inserted.
        const duplicate = await submitRequest(agents.requester, {
            justification: "Second try"
        });
        expect(duplicate.status).toBe(409);
        expect(duplicate.body.code).toBe("REQUEST_PENDING");
        expect(
            await countRows(
                "requests",
                "requester_id = $1",
                [users.requester.id]
            )
        ).toBe(1);

        // A client cannot request any other role.
        const invalidRole = await submitRequest(agents.other, { role: "admin" });
        expect(invalidRole.status).toBe(400);
        expect(invalidRole.body.code).toBe("INVALID_REQUESTED_ROLE");

        const tooLong = await submitRequest(agents.other, {
            justification: "x".repeat(501)
        });
        expect(tooLong.status).toBe(400);
        expect(tooLong.body.code).toBe("INVALID_JUSTIFICATION");

        // Non-viewers are not eligible to start the workflow.
        const ownerAttempt = await submitRequest(agents.owner, {});
        expect(ownerAttempt.status).toBe(409);
        expect(ownerAttempt.body.code).toBe("ROLE_NOT_ELIGIBLE");

        // The audit trail carries the server-derived actor and request.
        const logs = await fetchAuditLogs({
            action: "role_upgrade_request_submit"
        });
        const success = logs.find(
            (row) =>
                row.outcome === "success" &&
                row.details.requestId === response.body.request.id
        );
        expect(success).toBeTruthy();
        expect(success.actor_id).toBe(users.requester.id);
        expect(success.target_user_id).toBe(users.requester.id);
        expect(success.details.requestedRole).toBe("document_owner");
        expect(success.details.justificationProvided).toBe(true);
        expect(success.details.justification).toBeUndefined();
        expect(success.action).toBe("role_upgrade_request_submit");
        expect(success.created_at).toBeTruthy();

        const deniedDuplicate = logs.find(
            (row) =>
                row.outcome === "denied" &&
                row.details.reason === "request_already_pending" &&
                row.details.pendingRequestId === response.body.request.id
        );
        expect(deniedDuplicate).toBeTruthy();
        expect(deniedDuplicate.actor_id).toBe(users.requester.id);
        expect(deniedDuplicate.target_user_id).toBe(users.requester.id);
        expect(deniedDuplicate.created_at).toBeTruthy();
    });

    // ══════════════════════════════════════════════════════════════════════
    test("3. A requester sees only their own request history and admins can review it", async () => {
        const own = await statusOf(agents.requester);
        expect(own.status).toBe(200);
        expect(own.body.request.status).toBe("pending");
        expect(own.body.request.id).toBeTruthy();
        expect(own.body.request.submittedAt).toBeTruthy();

        const other = await statusOf(agents.other);
        expect(other.status).toBe(200);
        expect(other.body.request).toBeNull();
        expect(other.body.canSubmit).toBe(true);

        const list = await agents.admin
            .get(ADMIN_LIST)
            .query({ status: "pending" });
        expect(list.status).toBe(200);
        expect(list.body.requests.length).toBeGreaterThanOrEqual(1);

        const review = list.body.requests.find(
            (entry) => entry.requester.id === users.requester.id
        );
        expect(review).toBeTruthy();
        expect(review.requester.email).toBe(emails.requester);
        expect(review.status).toBe("pending");
        expect(review.justification).toBe(
            "I publish the quarterly finance pack."
        );

        // No requester identity may be supplied through the status endpoint:
        // querying with someone else's id still returns the caller's own state.
        const spoofed = await agents.other
            .get("/api/auth/role-upgrade-request")
            .query({ userId: users.requester.id });
        expect(spoofed.status).toBe(200);
        expect(spoofed.body.request).toBeNull();

        const invalidFilter = await agents.admin
            .get(ADMIN_LIST)
            .query({ status: "everything" });
        expect(invalidFilter.status).toBe(400);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("4. Only administrators may review or decide requests", async () => {
        const pending = await fetchRow(
            "requests",
            "requester_id = $1 AND status = 'pending'",
            [users.requester.id]
        );

        const anonymousList = await request(app).get(ADMIN_LIST);
        expect(anonymousList.status).toBe(401);

        const anonymousDecision = await request(app).post(
            `${ADMIN_LIST}/${pending.id}/approve`
        );
        expect(anonymousDecision.status).toBe(401);

        for (const key of ["requester", "other", "owner"]) {
            const list = await agents[key].get(ADMIN_LIST);
            expect(list.status).toBe(403);

            const decision = await approve(agents[key], pending.id);
            expect(decision.status).toBe(403);
        }

        const stillPending = await fetchRow(
            "requests",
            "id = $1",
            [pending.id]
        );
        expect(stillPending.status).toBe("pending");
        const unchangedRole = await fetchRow("users", "id = $1", [
            users.requester.id
        ]);
        expect(unchangedRole.role).toBe("viewer");

        const deniedAdminAccess = await fetchAuditLogs({
            action: "admin_console_access"
        });
        expect(
            deniedAdminAccess.some(
                (row) =>
                    row.outcome === "denied" &&
                    row.actor_id === users.requester.id &&
                    row.details.path.includes(pending.id)
            )
        ).toBe(true);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("5. Approval changes the role, records the decision and enforces it without re-login", async () => {
        const pending = await fetchRow(
            "requests",
            "requester_id = $1 AND status = 'pending'",
            [users.session.id]
        );
        expect(pending).toBeNull();

        const submitted = await submitRequest(agents.session, {
            justification: "I need to publish team documents."
        });
        expect(submitted.status).toBe(201);

        // The same session is still a Viewer until an administrator decides.
        const before = await agents.session.post("/api/documents").field(
            "name",
            "Should Not Upload"
        );
        expect(before.status).toBe(403);

        const decision = await approve(agents.admin, submitted.body.request.id);
        expect(decision.status).toBe(200);
        expect(decision.body.request.status).toBe("approved");
        expect(decision.body.request.decidedAt).toBeTruthy();
        expect(decision.body.user.role).toBe("document_owner");

        const storedUser = await fetchRow("users", "id = $1", [
            users.session.id
        ]);
        expect(storedUser.role).toBe("document_owner");

        const storedRequest = await fetchRow(
            "requests",
            "id = $1",
            [submitted.body.request.id]
        );
        expect(storedRequest.status).toBe("approved");
        expect(storedRequest.decided_by).toBe(users.admin.id);
        expect(storedRequest.decided_at).toBeTruthy();
        expect(
            new Date(storedRequest.decided_at).getTime()
        ).toBeGreaterThanOrEqual(
            new Date(storedRequest.submitted_at).getTime()
        );

        // The existing session carries no role claim: requireAuth re-reads the
        // account row, so the very next protected request is a Document Owner.
        const me = await agents.session.get("/api/auth/me");
        expect(me.status).toBe(200);
        expect(me.body.user.role).toBe("document_owner");

        const upload = await agents.session
            .post("/api/documents")
            .field("name", `Upgraded_${testRunId}`)
            .field("category", "General")
            .attach("file", VALID_PDF_BUFFER, "upgraded.pdf");
        expect(upload.status).toBe(201);

        const status = await statusOf(agents.session);
        expect(status.status).toBe(200);
        expect(status.body.currentRole).toBe("document_owner");
        expect(status.body.request.status).toBe("approved");
        expect(status.body.canSubmit).toBe(false);

        // Another user cannot discover or open the new owner's document.
        const otherStatus = await statusOf(agents.other);
        expect(otherStatus.body.request).toBeNull();
        const otherRead = await agents.other.get(
            `/api/documents/${upload.body.document.id}`
        );
        expect(otherRead.status).toBe(404);
        const otherSearch = await agents.other
            .get("/api/documents")
            .query({ q: `Upgraded_${testRunId}` });
        expect(otherSearch.status).toBe(200);
        expect(
            otherSearch.body.documents.some(
                (document) => document.id === upload.body.document.id
            )
        ).toBe(false);

        // The decision audit is server attributed and references the request.
        const logs = await fetchAuditLogs({
            action: "role_upgrade_request_approved"
        });
        const approval = logs.find(
            (row) =>
                row.outcome === "success" &&
                row.details.requestId === submitted.body.request.id
        );
        expect(approval).toBeTruthy();
        expect(approval.actor_id).toBe(users.admin.id);
        expect(approval.target_user_id).toBe(users.session.id);
        expect(approval.details.previousRole).toBe("viewer");
        expect(approval.details.newRole).toBe("document_owner");
        expect(approval.action).toBe("role_upgrade_request_approved");
        expect(approval.outcome).toBe("success");
        expect(approval.created_at).toBeTruthy();

        // Resolved requests cannot be decided again.
        const repeated = await approve(
            agents.admin,
            submitted.body.request.id
        );
        expect(repeated.status).toBe(409);
        expect(repeated.body.code).toBe("REQUEST_NOT_PENDING");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("6. Rejection is neutral, starts a seven-day cooldown and blocks retries", async () => {
        const submitted = await submitRequest(agents.rejected, {
            justification: "First attempt"
        });
        expect(submitted.status).toBe(201);

        const decision = await reject(agents.admin, submitted.body.request.id);
        expect(decision.status).toBe(200);
        expect(decision.body.request.status).toBe("rejected");
        expect(decision.body.request.decidedAt).toBeTruthy();
        expect(decision.body.user.role).toBe("viewer");
        expect(decision.body.message).toMatch(/rejected/i);

        const unchangedUser = await fetchRow("users", "id = $1", [
            users.rejected.id
        ]);
        expect(unchangedUser.role).toBe("viewer");
        const rejectionLog = (await fetchAuditLogs({
            action: "role_upgrade_request_rejected"
        })).find(
            (row) => row.details.requestId === submitted.body.request.id
        );
        expect(rejectionLog).toBeTruthy();
        expect(rejectionLog.actor_id).toBe(users.admin.id);
        expect(rejectionLog.target_user_id).toBe(users.rejected.id);
        expect(rejectionLog.outcome).toBe("success");
        expect(rejectionLog.created_at).toBeTruthy();

        const status = await statusOf(agents.rejected);
        expect(status.status).toBe(200);
        expect(status.body.currentRole).toBe("viewer");
        expect(status.body.request.status).toBe("rejected");
        expect(status.body.request).not.toHaveProperty("decidedBy");
        expect(status.body.canSubmit).toBe(false);
        expect(status.body.cooldownEndsAt).toBeTruthy();
        expect(status.body.request.nextEligibleAt).toBeTruthy();

        const retry = await submitRequest(agents.rejected, {
            justification: "Second attempt"
        });
        expect(retry.status).toBe(429);
        expect(retry.body.code).toBe("ROLE_UPGRADE_COOLDOWN");
        expect(retry.body.nextEligibleAt).toBeTruthy();
        expect(retry.headers["retry-after"]).toBeTruthy();
        expect(
            await countRows(
                "requests",
                "requester_id = $1",
                [users.rejected.id]
            )
        ).toBe(1);

        // The cooldown is trusted database time. Moving the recorded decision
        // into the past is how the test advances seven days without waiting.
        await pool.query(
            `UPDATE requests
             SET decided_at = NOW() - INTERVAL '8 days'
             WHERE id = $1`,
            [submitted.body.request.id]
        );

        const afterCooldown = await statusOf(agents.rejected);
        expect(afterCooldown.status).toBe(200);
        expect(afterCooldown.body.canSubmit).toBe(true);
        expect(afterCooldown.body.cooldownEndsAt).toBeNull();

        const resubmitted = await submitRequest(agents.rejected, {
            justification: "After the cooldown"
        });
        expect(resubmitted.status).toBe(201);
        expect(resubmitted.body.request.status).toBe("pending");

        const rejectionLogs = await fetchAuditLogs({
            action: "role_upgrade_request_rejected"
        });
        expect(
            rejectionLogs.some(
                (row) =>
                    row.outcome === "success" &&
                    row.details.requestId === submitted.body.request.id
            )
        ).toBe(true);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("7. Concurrent submissions create at most one pending request", async () => {
        const attempts = await Promise.all(
            Array.from({ length: 6 }, () =>
                submitRequest(agents.duplicate, {
                    justification: "Concurrent submission"
                })
            )
        );

        const statuses = attempts.map((attempt) => attempt.status).sort();
        expect(statuses.filter((status) => status === 201)).toHaveLength(1);
        expect(
            statuses.filter((status) => status === 409).length
        ).toBeGreaterThanOrEqual(5);

        const rows = await pool.query(
            `SELECT id, status FROM requests
             WHERE requester_id = $1`,
            [users.duplicate.id]
        );
        expect(rows.rows).toHaveLength(1);
        expect(rows.rows[0].status).toBe("pending");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("8. Concurrent decisions produce exactly one success", async () => {
        const submitted = await submitRequest(agents.atomic, {});
        expect(submitted.status).toBe(201);

        const results = await Promise.all([
            approve(agents.admin, submitted.body.request.id),
            reject(agents.admin, submitted.body.request.id)
        ]);

        const statuses = results.map((result) => result.status).sort();
        expect(statuses).toEqual([200, 409]);

        const requestRow = await fetchRow(
            "requests",
            "id = $1",
            [submitted.body.request.id]
        );
        const userRow = await fetchRow("users", "id = $1", [users.atomic.id]);

        expect(["approved", "rejected"]).toContain(requestRow.status);
        expect(requestRow.decided_by).toBe(users.admin.id);
        expect(requestRow.decided_at).toBeTruthy();

        if (requestRow.status === "approved") {
            expect(userRow.role).toBe("document_owner");
        } else {
            expect(userRow.role).toBe("viewer");

            const auditRows = await pool.query(
                `SELECT id FROM audit_logs
                 WHERE action = 'role_upgrade_request_approved'
                   AND details->>'requestId' = $1
                   AND outcome = 'success'`,
                [submitted.body.request.id]
            );
            expect(auditRows.rows).toHaveLength(0);
        }

        const successLogs = await pool.query(
            `SELECT action, outcome FROM audit_logs
             WHERE target_user_id = $1
               AND action IN ('role_upgrade_request_approved',
                              'role_upgrade_request_rejected')
               AND outcome = 'success'`,
            [users.atomic.id]
        );
        expect(successLogs.rows).toHaveLength(1);
        expect(successLogs.rows[0].action).toBe(
            requestRow.status === "approved"
                ? "role_upgrade_request_approved"
                : "role_upgrade_request_rejected"
        );

        const deniedLogs = await pool.query(
            `SELECT details FROM audit_logs
             WHERE action = 'role_upgrade_request_decision'
               AND outcome = 'denied'
               AND details->>'requestId' = $1`,
            [submitted.body.request.id]
        );
        expect(deniedLogs.rows).toHaveLength(1);
        expect(deniedLogs.rows[0].details.reason).toBe("request_not_pending");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("9. An administrator cannot approve their own request", async () => {
        const inserted = await pool.query(
            `INSERT INTO requests
                (requester_id, request_type, requested_role, status, reason, reviewer_role)
             VALUES ($1, 'document_owner_upgrade', 'document_owner', 'pending', 'Self approval attempt', 'admin')
             RETURNING id`,
            [users.admin.id]
        );
        const requestId = inserted.rows[0].id;

        try {
            const decision = await approve(agents.admin, requestId);
            expect(decision.status).toBe(403);
            expect(decision.body.code).toBe("SELF_DECISION");

            const stored = await fetchRow(
                "requests",
                "id = $1",
                [requestId]
            );
            expect(stored.status).toBe("pending");

            const admin = await fetchRow("users", "id = $1", [users.admin.id]);
            expect(admin.role).toBe("admin");

            const deniedDecision = (await fetchAuditLogs({
                action: "role_upgrade_request_decision"
            })).find(
                (row) =>
                    row.outcome === "denied" &&
                    row.details.requestId === requestId &&
                    row.details.reason === "self_decision"
            );
            expect(deniedDecision).toBeTruthy();
            expect(deniedDecision.actor_id).toBe(users.admin.id);
            expect(deniedDecision.target_user_id).toBe(users.admin.id);
            expect(deniedDecision.created_at).toBeTruthy();
        } finally {
            await pool.query("DELETE FROM requests WHERE id = $1", [
                requestId
            ]);
        }
    });

    // ══════════════════════════════════════════════════════════════════════
    test("10. A failed submission audit rolls the request back", async () => {
        await installAuditFailure("role_upgrade_request_submit");

        try {
            const response = await submitRequest(agents.audited, {
                justification: "Must not survive a failed audit"
            });

            expect(response.status).toBe(500);
            expect(
                await countRows(
                    "requests",
                    "requester_id = $1",
                    [users.audited.id]
                )
            ).toBe(0);
        } finally {
            await removeAuditFailure();
        }
    });

    // ══════════════════════════════════════════════════════════════════════
    test("11. Failed approval and rejection audits preserve the request and role", async () => {
        const submitted = await submitRequest(agents.audited, {});
        expect(submitted.status).toBe(201);

        await installAuditFailure("role_upgrade_request_approved");

        try {
            const response = await approve(
                agents.admin,
                submitted.body.request.id
            );
            expect(response.status).toBe(500);

            const requestRow = await fetchRow(
                "requests",
                "id = $1",
                [submitted.body.request.id]
            );
            expect(requestRow.status).toBe("pending");
            expect(requestRow.decided_at).toBeNull();
            expect(requestRow.decided_by).toBeNull();

            const userRow = await fetchRow("users", "id = $1", [
                users.audited.id
            ]);
            expect(userRow.role).toBe("viewer");
        } finally {
            await removeAuditFailure();
        }

        await installAuditFailure("role_upgrade_request_rejected");
        try {
            const rejected = await reject(
                agents.admin,
                submitted.body.request.id
            );
            expect(rejected.status).toBe(500);

            const requestAfterFailure = await fetchRow(
                "requests",
                "id = $1",
                [submitted.body.request.id]
            );
            expect(requestAfterFailure.status).toBe("pending");
            expect(requestAfterFailure.decided_at).toBeNull();

            const roleAfterFailure = await fetchRow("users", "id = $1", [
                users.audited.id
            ]);
            expect(roleAfterFailure.role).toBe("viewer");

            const rejectionAudits = await pool.query(
                `SELECT id FROM audit_logs
                 WHERE action = 'role_upgrade_request_rejected'
                   AND details->>'requestId' = $1
                   AND outcome = 'success'`,
                [submitted.body.request.id]
            );
            expect(rejectionAudits.rows).toHaveLength(0);
        } finally {
            await removeAuditFailure();
        }
    });

    // ══════════════════════════════════════════════════════════════════════
    test("12. A direct role change settles a pending request atomically", async () => {
        const submitted = await submitRequest(agents.direct, {
            justification: "Promote directly"
        });
        expect(submitted.status).toBe(201);

        // A same-role change is refused and leaves the pending request alone.
        const sameRole = await agents.admin
            .patch(`/api/admin/users/${users.direct.id}/role`)
            .send({ role: "viewer", reason: DECISION_REASON });
        expect(sameRole.status).toBe(409);

        const stillPending = await fetchRow(
            "requests",
            "id = $1",
            [submitted.body.request.id]
        );
        expect(stillPending.status).toBe("pending");
        expect(stillPending.decided_by).toBeNull();

        // A direct promotion settles the pending request atomically.
        const promoted = await agents.admin
            .patch(`/api/admin/users/${users.direct.id}/role`)
            .send({ role: "document_owner", reason: DECISION_REASON });
        expect(promoted.status).toBe(200);
        expect(promoted.body.user.role).toBe("document_owner");
        expect(promoted.body.request).toMatchObject({
            id: submitted.body.request.id,
            status: "approved"
        });

        const approvedRow = await fetchRow(
            "requests",
            "id = $1",
            [submitted.body.request.id]
        );
        expect(approvedRow.status).toBe("approved");
        expect(approvedRow.decided_by).toBe(users.admin.id);
        expect(approvedRow.decision_note).toBe(DECISION_REASON);

        // Both the role-change audit and the request decision audit exist.
        const roleChange = await fetchAuditLogs({
            action: "admin_user_role_change"
        });
        const directChange = roleChange.find(
            (row) =>
                row.outcome === "success" &&
                row.target_user_id === users.direct.id &&
                row.details.pendingRequestId === submitted.body.request.id
        );
        expect(directChange).toBeTruthy();
        expect(directChange.details.previousRole).toBe("viewer");
        expect(directChange.details.newRole).toBe("document_owner");
        expect(directChange.details.pendingRequestOutcome).toBe("approved");

        const decisionLog = await fetchAuditLogs({
            action: "role_upgrade_request_approved"
        });
        const viaDirect = decisionLog.find(
            (row) =>
                row.outcome === "success" &&
                row.details.requestId === submitted.body.request.id
        );
        expect(viaDirect).toBeTruthy();
        expect(viaDirect.details.viaDirectRoleChange).toBe(true);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("13. A failed role-change audit leaves the role and request untouched", async () => {
        // `direct` was promoted in test 12; use a fresh viewer for this case.
        const created = await registerAndLogin(app, {
            name: "Upgrade audit rollback",
            email: `upgrade.audit-rollback.${testRunId}@trustvault.test`,
            role: "viewer"
        });

        const submitted = await submitRequest(created.agent, {
            justification: "Role change must be auditable"
        });
        expect(submitted.status).toBe(201);

        await installAuditFailure("admin_user_role_change");

        try {
            const response = await agents.admin
                .patch(`/api/admin/users/${created.user.id}/role`)
                .send({ role: "document_owner", reason: DECISION_REASON });
            expect(response.status).toBe(500);

            const userRow = await fetchRow("users", "id = $1", [
                created.user.id
            ]);
            expect(userRow.role).toBe("viewer");

            const requestRow = await fetchRow(
                "requests",
                "id = $1",
                [submitted.body.request.id]
            );
            expect(requestRow.status).toBe("pending");
            expect(requestRow.decided_at).toBeNull();
        } finally {
            await removeAuditFailure();
            await pool.query("DELETE FROM requests WHERE requester_id = $1", [created.user.id]);
            await pool.query("DELETE FROM users WHERE id = $1", [created.user.id]);
        }
    });

    // ══════════════════════════════════════════════════════════════════════
    test("14. The audit chain remains valid after every workflow path", async () => {
        const verification = await verifyAuditChain();
        expect(verification.valid).toBe(true);
        expect(verification.reason).toBe("ok");
        expect(verification.totalEntries).toBeGreaterThan(0);
    });

    test("15. General request APIs isolate request history and return 404 for another user's ID", async () => {
        const created = await registerAndLogin(app, {
            name: "General requests owner",
            email: `upgrade.general.${testRunId}@trustvault.test`,
            role: "viewer"
        });
        const submitted = await created.agent.post("/api/requests").send({
            requestType: "document_owner_upgrade",
            requestedRole: "admin",
            reviewerUserId: users.admin.id,
            handler: "client-controlled",
            reason: "General API request"
        });
        expect(submitted.status).toBe(201);
        expect(submitted.body.request.requestedRole).toBe("document_owner");
        expect(submitted.body.request.reviewerUserId).toBeNull();

        const mine = await created.agent.get("/api/requests/mine");
        expect(mine.status).toBe(200);
        expect(mine.body.requests.map((item) => item.id)).toContain(submitted.body.request.id);

        const otherHistory = await agents.other
            .get("/api/requests/mine")
            .query({ requesterId: created.user.id, requestId: submitted.body.request.id });
        expect(otherHistory.status).toBe(200);
        expect(otherHistory.body.requests).toHaveLength(0);

        const manipulatedCancel = await agents.other.post(
            `/api/requests/${submitted.body.request.id}/cancel`
        );
        expect(manipulatedCancel.status).toBe(404);
        const stillPending = await fetchRow("requests", "id = $1", [submitted.body.request.id]);
        expect(stillPending.status).toBe("pending");

        const filtered = await agents.admin.get("/api/admin/requests")
            .query({ status: "pending", type: "document_owner_upgrade", search: "general requests owner" });
        expect(filtered.status).toBe(200);
        expect(filtered.body.total).toBe(1);
        expect(filtered.body.requests[0].id).toBe(submitted.body.request.id);
    });

    test("16. Requester cancellation is audited, preserves history and does not start cooldown", async () => {
        const created = await registerAndLogin(app, {
            name: "General request cancellation",
            email: `upgrade.cancel.${testRunId}@trustvault.test`,
            role: "viewer"
        });
        const submitted = await created.agent.post("/api/requests").send({
            requestType: "document_owner_upgrade",
            reason: "May cancel"
        });
        expect(submitted.status).toBe(201);

        const cancelled = await created.agent.post(
            `/api/requests/${submitted.body.request.id}/cancel`
        );
        expect(cancelled.status).toBe(200);
        expect(cancelled.body.request.status).toBe("cancelled");
        const stored = await fetchRow("requests", "id = $1", [submitted.body.request.id]);
        expect(stored.status).toBe("cancelled");
        expect(stored.decided_by).toBe(created.user.id);

        const role = await fetchRow("users", "id = $1", [created.user.id]);
        expect(role.role).toBe("viewer");
        const cancelledAudit = await pool.query(
            `SELECT actor_id, action, outcome, created_at, details
             FROM audit_logs WHERE details->>'requestId' = $1 AND outcome = 'success'
             ORDER BY id ASC`,
            [submitted.body.request.id]
        );
        expect(cancelledAudit.rows).toHaveLength(2);
        expect(cancelledAudit.rows[1].actor_id).toBe(created.user.id);
        expect(cancelledAudit.rows[1].action).toBe("role_upgrade_request_cancelled");
        expect(cancelledAudit.rows[1].created_at).toBeTruthy();

        const resubmitted = await created.agent.post("/api/requests").send({
            requestType: "document_owner_upgrade",
            reason: "Cancellation has no cooldown"
        });
        expect(resubmitted.status).toBe(201);
    });

    test("17. Concurrent approval, rejection and cancellation have one winner", async () => {
        const created = await registerAndLogin(app, {
            name: "Concurrent request decision",
            email: `upgrade.concurrent-decision.${testRunId}@trustvault.test`,
            role: "viewer"
        });
        const submitted = await created.agent.post("/api/requests").send({
            requestType: "document_owner_upgrade",
            reason: "Only one terminal transition may win"
        });
        expect(submitted.status).toBe(201);
        const id = submitted.body.request.id;

        const results = await Promise.all([
            agents.admin
                .post(`/api/admin/requests/${id}/approve`)
                .send({ decisionNote: DECISION_REASON }),
            agents.admin.post(`/api/admin/requests/${id}/reject`).send({ decisionNote: "Optional note" }),
            created.agent.post(`/api/requests/${id}/cancel`)
        ]);
        expect(results.filter((result) => result.status === 200)).toHaveLength(1);
        expect(results.filter((result) => result.status === 409)).toHaveLength(2);

        const stored = await fetchRow("requests", "id = $1", [id]);
        expect(["approved", "rejected", "cancelled"]).toContain(stored.status);
        const successful = await pool.query(
            `SELECT id FROM audit_logs
             WHERE details->>'requestId' = $1
               AND action IN ('role_upgrade_request_approved',
                              'role_upgrade_request_rejected',
                              'role_upgrade_request_cancelled')
               AND outcome = 'success'`,
            [id]
        );
        expect(successful.rows).toHaveLength(1);
    });

    test("18. Rejection notes are optional and capped at 500 characters", async () => {
        const created = await registerAndLogin(app, {
            name: "Rejection note validation",
            email: `upgrade.note.${testRunId}@trustvault.test`,
            role: "viewer"
        });
        const submitted = await created.agent.post("/api/requests").send({
            requestType: "document_owner_upgrade"
        });
        expect(submitted.status).toBe(201);
        const rejected = await agents.admin.post(
            `/api/admin/requests/${submitted.body.request.id}/reject`
        ).send({ decisionNote: "x".repeat(501) });
        expect(rejected.status).toBe(400);
        const stillPending = await fetchRow("requests", "id = $1", [submitted.body.request.id]);
        expect(stillPending.status).toBe("pending");

        const accepted = await agents.admin.post(
            `/api/admin/requests/${submitted.body.request.id}/reject`
        ).send({ decisionNote: "x".repeat(500) });
        expect(accepted.status).toBe(200);
        expect(accepted.body.request.decisionNote).toBe("x".repeat(500));
    });
});
