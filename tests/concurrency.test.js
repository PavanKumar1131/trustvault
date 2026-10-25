/**
 * Concurrency regressions for security-sensitive writes.
 *
 * The routes re-check the acting account and the document inside the write
 * transaction. These tests hold the account row with `FOR UPDATE`, start the
 * request, and wait until PostgreSQL reports the request's `FOR SHARE` wait.
 * The account is then demoted or disabled before the blocking transaction
 * commits, which is exactly the race the transactional re-check must close.
 */

const app = require("../src/app");
const pool = require("../src/db");
const {
    resetDatabase,
    createUser,
    login,
    registerAndLogin,
    uploadDocument,
    fetchRow,
    fetchAuditLogs
} = require("./helpers");

const LOCK_WAIT_TIMEOUT_MS = 15000;

/**
 * Waits until a backend other than this one is blocked on a lock and its
 * current statement contains `fragment`. The test connection itself is never
 * waiting, so the match is the application request.
 */
async function waitForLockWait(fragment) {
    const deadline = Date.now() + LOCK_WAIT_TIMEOUT_MS;

    while (Date.now() < deadline) {
        const result = await pool.query(
            `SELECT pid, query, wait_event_type, wait_event
               FROM pg_stat_activity
              WHERE datname = current_database()
                AND pid <> pg_backend_pid()
                AND wait_event_type = 'Lock'
                AND query ILIKE $1`,
            [`%${fragment}%`]
        );

        if (result.rows.length > 0) {
            return result.rows[0];
        }

        await new Promise((resolve) => setTimeout(resolve, 50));
    }

    throw new Error(
        `Timed out after ${LOCK_WAIT_TIMEOUT_MS} ms waiting for a lock on "${fragment}"`
    );
}

async function lockUser(client, userId) {
    await client.query("BEGIN");
    const result = await client.query(
        "SELECT id, role, is_disabled FROM users WHERE id = $1 FOR UPDATE",
        [userId]
    );
    return result.rows[0];
}

function startRequest(promiseFactory) {
    return promiseFactory().then((response) => response);
}

describe("TrustVault write concurrency", () => {
    const testRunId = Date.now().toString(36);

    beforeAll(async () => {
        await resetDatabase();
    });

    test("1. A demotion that commits while a delete waits prevents the delete", async () => {
        const owner = await registerAndLogin(app, {
            name: "Racing Demotion Owner",
            email: `concurrency.demotion.${testRunId}@trustvault.test`,
            role: "document_owner"
        });
        const document = await uploadDocument(owner.agent, {
            name: `DemotionRace_${testRunId}`,
            category: "Concurrency"
        });

        const locker = await pool.connect();
        let deletion = null;

        try {
            await lockUser(locker, owner.user.id);

            deletion = startRequest(() =>
                owner.agent.delete(`/api/documents/${document.id}`)
            );

            const waiting = await waitForLockWait("FOR SHARE");
            expect(waiting.query).toMatch(/FROM users/i);

            // The account-management service holds the same row lock while it
            // changes the role. Commit the demotion before the delete can
            // acquire its share lock.
            const demoted = await locker.query(
                `UPDATE users
                    SET role = 'viewer', updated_at = NOW()
                  WHERE id = $1
                  RETURNING role`,
                [owner.user.id]
            );
            expect(demoted.rows[0].role).toBe("viewer");
            await locker.query("COMMIT");

            const response = await deletion;

            expect(response.status).toBe(404);
            expect(response.body.message).toBe("Document not found");
            expect(
                await fetchRow("documents", "id = $1", [document.id])
            ).not.toBeNull();

            const successLogs = await fetchAuditLogs({
                action: "document_delete",
                outcome: "success",
                documentId: document.id
            });
            expect(successLogs).toHaveLength(0);

            const denialLogs = await fetchAuditLogs({
                action: "document_delete",
                outcome: "denied",
                documentId: document.id
            });
            expect(denialLogs).toHaveLength(1);
            expect(denialLogs[0].details.reason).toBe(
                "non_owner_attempted_delete"
            );
        } finally {
            await locker.query("ROLLBACK").catch(() => {});
            locker.release();
            if (deletion) {
                await deletion.catch(() => {});
            }
        }
    });

    test("2. A disable that commits while a delete waits prevents the delete", async () => {
        const owner = await registerAndLogin(app, {
            name: "Racing Disable Owner",
            email: `concurrency.disable.${testRunId}@trustvault.test`,
            role: "document_owner"
        });
        const document = await uploadDocument(owner.agent, {
            name: `DisableRace_${testRunId}`,
            category: "Concurrency"
        });

        const locker = await pool.connect();
        let deletion = null;

        try {
            await lockUser(locker, owner.user.id);

            deletion = startRequest(() =>
                owner.agent.delete(`/api/documents/${document.id}`)
            );

            const waiting = await waitForLockWait("FOR SHARE");
            expect(waiting.query).toMatch(/FROM users/i);

            const disabled = await locker.query(
                `UPDATE users
                    SET is_disabled = true, updated_at = NOW()
                  WHERE id = $1
                  RETURNING is_disabled`,
                [owner.user.id]
            );
            expect(disabled.rows[0].is_disabled).toBe(true);
            await locker.query("COMMIT");

            const response = await deletion;

            expect(response.status).toBe(404);
            expect(response.body.message).toBe("Document not found");
            expect(
                await fetchRow("documents", "id = $1", [document.id])
            ).not.toBeNull();

            const successLogs = await fetchAuditLogs({
                action: "document_delete",
                outcome: "success",
                documentId: document.id
            });
            expect(successLogs).toHaveLength(0);
        } finally {
            await locker.query("ROLLBACK").catch(() => {});
            locker.release();
            if (deletion) {
                await deletion.catch(() => {});
            }
        }
    });

    test("3. An administrator demoted during account creation cannot create the account", async () => {
        const admin = await createUser({
            name: "Racing Admin",
            email: `concurrency.admin.${testRunId}@trustvault.test`,
            role: "admin"
        });
        const adminLogin = await login(app, { email: admin.email });
        const newEmail = `concurrency.created.${testRunId}@trustvault.test`;

        const locker = await pool.connect();
        let creation = null;

        try {
            await lockUser(locker, admin.id);

            creation = startRequest(() =>
                adminLogin.agent.post("/api/admin/users").send({
                    name: "Should Not Exist",
                    email: newEmail,
                    role: "viewer"
                })
            );

            const waiting = await waitForLockWait("FOR SHARE");
            expect(waiting.query).toMatch(/FROM users/i);

            const demoted = await locker.query(
                `UPDATE users
                    SET role = 'viewer', updated_at = NOW()
                  WHERE id = $1
                  RETURNING role`,
                [admin.id]
            );
            expect(demoted.rows[0].role).toBe("viewer");
            await locker.query("COMMIT");

            const response = await creation;

            expect(response.status).toBe(403);
            expect(response.body.message).toBe(
                "Access denied: Administrator privileges required"
            );
            expect(
                await fetchRow("users", "email = $1", [newEmail])
            ).toBeNull();

            const denialLogs = await fetchAuditLogs({
                action: "admin_user_create",
                outcome: "denied"
            });
            expect(
                denialLogs.some(
                    (log) =>
                        log.details.email === newEmail &&
                        log.details.reason === "administrator_privilege_changed"
                )
            ).toBe(true);
        } finally {
            await locker.query("ROLLBACK").catch(() => {});
            locker.release();
            if (creation) {
                await creation.catch(() => {});
            }
        }
    });
});
