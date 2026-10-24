/**
 * Admin user-list search, filtering and pagination.
 *
 * The tests exercise the real Express application and the real PostgreSQL
 * test database. Every fixture is created directly in the database so the
 * role and disabled states are known exactly; the HTTP assertions then also
 * check the database state where an action changed it.
 */

const request = require("supertest");
const app = require("../src/app");
const pool = require("../src/db");
const {
    resetDatabase,
    createUser,
    login
} = require("./helpers");

describe("Admin users: search, filters, pagination and protections", () => {
    let adminAgent;
    let ownerAgent;
    let viewerAgent;
    let users;

    function getUsers(agent, query) {
        return agent.get("/api/admin/users").query(query || {});
    }

    function ids(response) {
        return response.body.users.map((user) => user.id);
    }

    beforeAll(async () => {
        await resetDatabase();

        users = {
            admin: await createUser({
                name: "Avery Admin",
                email: "avery.admin@trustvault.test",
                role: "admin"
            }),
            disabledAdmin: await createUser({
                name: "Dana Dormant",
                email: "dana.dormant@trustvault.test",
                role: "admin",
                isDisabled: true
            }),
            alice: await createUser({
                name: "Alice Owner",
                email: "alice.owner@trustvault.test",
                role: "document_owner"
            }),
            bob: await createUser({
                name: "Bob Builder",
                email: "bob.builder@trustvault.test",
                role: "document_owner",
                isDisabled: true
            }),
            carol: await createUser({
                name: "Carol Viewer",
                email: "carol.viewer@trustvault.test",
                role: "viewer"
            }),
            victor: await createUser({
                name: "Victor Viewer",
                email: "victor.viewer@trustvault.test",
                role: "viewer"
            }),
            derek: await createUser({
                name: "Derek Disabled",
                email: "derek.disabled@trustvault.test",
                role: "viewer",
                isDisabled: true
            }),
            roleTarget: await createUser({
                name: "Riley Role",
                email: "riley.role@trustvault.test",
                role: "viewer"
            }),
            statusTarget: await createUser({
                name: "Sam Status",
                email: "sam.status@trustvault.test",
                role: "viewer"
            })
        };

        adminAgent = (await login(app, { email: users.admin.email })).agent;
        ownerAgent = (await login(app, { email: users.alice.email })).agent;
        viewerAgent = (await login(app, { email: users.carol.email })).agent;
    });

    describe("search", () => {
        test("finds a user by exact name", async () => {
            const response = await getUsers(adminAgent, { search: "Alice Owner" });

            expect(response.status).toBe(200);
            expect(response.body.total).toBe(1);
            expect(ids(response)).toEqual([users.alice.id]);
        });

        test("finds a user by a partial name", async () => {
            const response = await getUsers(adminAgent, { search: "lic" });

            expect(response.status).toBe(200);
            expect(response.body.total).toBe(1);
            expect(ids(response)).toEqual([users.alice.id]);
        });

        test("finds a user by email address", async () => {
            const response = await getUsers(adminAgent, {
                search: "bob.builder@trustvault.test"
            });

            expect(response.status).toBe(200);
            expect(response.body.total).toBe(1);
            expect(ids(response)).toEqual([users.bob.id]);
        });

        test("matches names and email addresses case-insensitively", async () => {
            const byName = await getUsers(adminAgent, { search: "aLiCe OwNeR" });
            const byEmail = await getUsers(adminAgent, {
                search: "CAROL.VIEWER@TRUSTVAULT.TEST"
            });

            expect(byName.status).toBe(200);
            expect(byName.body.total).toBe(1);
            expect(ids(byName)).toEqual([users.alice.id]);

            expect(byEmail.status).toBe(200);
            expect(byEmail.body.total).toBe(1);
            expect(ids(byEmail)).toEqual([users.carol.id]);
        });

        test("trims leading and trailing whitespace from the search term", async () => {
            const response = await getUsers(adminAgent, {
                search: "   Alice Owner   "
            });

            expect(response.status).toBe(200);
            expect(response.body.total).toBe(1);
            expect(ids(response)).toEqual([users.alice.id]);
        });
    });

    describe("role and status filters", () => {
        test("filters by each canonical role", async () => {
            const admins = await getUsers(adminAgent, { role: "admin" });
            const owners = await getUsers(adminAgent, { role: "document_owner" });
            const viewers = await getUsers(adminAgent, { role: "viewer" });

            expect(admins.status).toBe(200);
            expect(admins.body.total).toBe(2);
            expect(ids(admins).sort()).toEqual(
                [users.admin.id, users.disabledAdmin.id].sort()
            );

            expect(owners.status).toBe(200);
            expect(owners.body.total).toBe(2);
            expect(ids(owners).sort()).toEqual(
                [users.alice.id, users.bob.id].sort()
            );

            expect(viewers.status).toBe(200);
            expect(viewers.body.total).toBe(5);
            expect(ids(viewers).sort()).toEqual(
                [
                    users.carol.id,
                    users.victor.id,
                    users.derek.id,
                    users.roleTarget.id,
                    users.statusTarget.id
                ].sort()
            );
        });

        test("filters by active and disabled account status", async () => {
            const active = await getUsers(adminAgent, { status: "active" });
            const disabled = await getUsers(adminAgent, { status: "disabled" });

            expect(active.status).toBe(200);
            expect(active.body.total).toBe(6);

            expect(disabled.status).toBe(200);
            expect(disabled.body.total).toBe(3);
            expect(ids(disabled).sort()).toEqual(
                [users.disabledAdmin.id, users.bob.id, users.derek.id].sort()
            );

            active.body.users.forEach((user) => expect(user.is_disabled).toBe(false));
            disabled.body.users.forEach((user) => expect(user.is_disabled).toBe(true));
        });

        test("combines search, role and status without clearing any filter", async () => {
            const response = await getUsers(adminAgent, {
                search: "trustvault.test",
                role: "document_owner",
                status: "active"
            });

            expect(response.status).toBe(200);
            expect(response.body.total).toBe(1);
            expect(ids(response)).toEqual([users.alice.id]);

            // Bob is a document owner too, but disabled; removing only the
            // status filter must bring him back.
            const withoutStatus = await getUsers(adminAgent, {
                search: "trustvault.test",
                role: "document_owner"
            });
            expect(withoutStatus.status).toBe(200);
            expect(withoutStatus.body.total).toBe(2);
            expect(ids(withoutStatus).sort()).toEqual(
                [users.alice.id, users.bob.id].sort()
            );
        });

        test("clearing filters restores the unfiltered list and count", async () => {
            const filtered = await getUsers(adminAgent, {
                search: "Alice",
                role: "document_owner",
                status: "active"
            });
            expect(filtered.body.total).toBe(1);

            const cleared = await getUsers(adminAgent, {});
            expect(cleared.status).toBe(200);
            expect(cleared.body.total).toBe(9);
            expect(cleared.body.users).toHaveLength(9);
        });
    });

    describe("pagination and validation", () => {
        test("reports the matching count, not the original total", async () => {
            const response = await getUsers(adminAgent, {
                search: "Viewer",
                status: "active"
            });

            expect(response.status).toBe(200);
            expect(response.body.total).toBe(2);
            expect(ids(response).sort()).toEqual(
                [users.carol.id, users.victor.id].sort()
            );
        });

        test("paginates with page/pageSize and reports hasMore", async () => {
            const first = await getUsers(adminAgent, { page: 1, pageSize: 4 });
            const second = await getUsers(adminAgent, { page: 2, pageSize: 4 });
            const third = await getUsers(adminAgent, { page: 3, pageSize: 4 });

            expect(first.status).toBe(200);
            expect(first.body.total).toBe(9);
            expect(first.body.users).toHaveLength(4);
            expect(first.body.limit).toBe(4);
            expect(first.body.offset).toBe(0);
            expect(first.body.page).toBe(1);
            expect(first.body.pageSize).toBe(4);
            expect(first.body.hasMore).toBe(true);

            expect(second.status).toBe(200);
            expect(second.body.users).toHaveLength(4);
            expect(second.body.offset).toBe(4);
            expect(second.body.hasMore).toBe(true);

            expect(third.status).toBe(200);
            expect(third.body.users).toHaveLength(1);
            expect(third.body.offset).toBe(8);
            expect(third.body.hasMore).toBe(false);

            const allIds = [...ids(first), ...ids(second), ...ids(third)];
            expect(new Set(allIds).size).toBe(9);
        });

        test("preserves the original limit/offset pagination contract", async () => {
            const response = await getUsers(adminAgent, { limit: 2, offset: 2 });

            expect(response.status).toBe(200);
            expect(response.body.total).toBe(9);
            expect(response.body.limit).toBe(2);
            expect(response.body.offset).toBe(2);
            expect(response.body.users).toHaveLength(2);
            expect(response.body.page).toBe(2);
            expect(response.body.pageSize).toBe(2);
        });

        test("rejects invalid search, role, status and pagination parameters", async () => {
            const requests = [
                { role: "root" },
                { status: "pending" },
                { search: "x".repeat(101) },
                { page: "abc" },
                { page: 0 },
                { pageSize: 0 },
                { pageSize: 101 }
            ];

            for (const query of requests) {
                const response = await getUsers(adminAgent, query);
                expect(response.status).toBe(400);
                expect(typeof response.body.message).toBe("string");
            }
        });

        test("treats SQL-injection-like search text as literal data", async () => {
            const injection = await getUsers(adminAgent, {
                search: "' OR 1=1 --"
            });
            const wildcard = await getUsers(adminAgent, { search: "%" });
            const roleInjection = await getUsers(adminAgent, {
                role: "admin' OR '1'='1"
            });

            expect(injection.status).toBe(200);
            expect(injection.body.total).toBe(0);

            expect(wildcard.status).toBe(200);
            expect(wildcard.body.total).toBe(0);

            expect(roleInjection.status).toBe(400);

            const unchanged = await pool.query("SELECT COUNT(*)::int AS total FROM users");
            expect(unchanged.rows[0].total).toBe(9);
        });
    });

    describe("authorization and response safety", () => {
        test("denies the user list to anonymous, owner and viewer callers", async () => {
            const anonymous = await request(app)
                .get("/api/admin/users")
                .query({ search: "Alice" });
            const owner = await getUsers(ownerAgent, { search: "Alice" });
            const viewer = await getUsers(viewerAgent, { search: "Alice" });

            expect(anonymous.status).toBe(401);
            expect(owner.status).toBe(403);
            expect(viewer.status).toBe(403);
        });

        test("returns only the fields the administrator screen needs", async () => {
            const response = await getUsers(adminAgent, { search: "Alice" });

            expect(response.status).toBe(200);
            expect(response.body.users).toHaveLength(1);
            expect(Object.keys(response.body.users[0]).sort()).toEqual(
                [
                    "created_at",
                    "document_count",
                    "email",
                    "id",
                    "is_disabled",
                    "name",
                    "role"
                ].sort()
            );

            const body = JSON.stringify(response.body);
            expect(body).not.toMatch(/password_hash/i);
            expect(body).not.toMatch(/password/i);
            expect(body).not.toMatch(/session/i);
            expect(body).not.toMatch(/secret/i);
        });
    });

    describe("user actions keep working and keep the filters", () => {
        test("changes the role of the intended account and the filtered list reflects it", async () => {
            const change = await adminAgent
                .patch(`/api/admin/users/${users.roleTarget.id}/role`)
                .send({ role: "document_owner" });

            expect(change.status).toBe(200);
            expect(change.body.user.id).toBe(users.roleTarget.id);
            expect(change.body.user.role).toBe("document_owner");

            const owners = await getUsers(adminAgent, {
                search: "Riley Role",
                role: "document_owner"
            });
            expect(owners.status).toBe(200);
            expect(ids(owners)).toEqual([users.roleTarget.id]);

            const viewers = await getUsers(adminAgent, {
                search: "Riley Role",
                role: "viewer"
            });
            expect(viewers.status).toBe(200);
            expect(viewers.body.total).toBe(0);
        });

        test("disables and re-enables the intended account, and status filters follow", async () => {
            const disable = await adminAgent
                .patch(`/api/admin/users/${users.statusTarget.id}/disable`)
                .send({ disabled: true });

            expect(disable.status).toBe(200);
            expect(disable.body.user.id).toBe(users.statusTarget.id);
            expect(disable.body.user.is_disabled).toBe(true);

            const disabled = await getUsers(adminAgent, {
                search: "Sam Status",
                status: "disabled"
            });
            expect(disabled.status).toBe(200);
            expect(ids(disabled)).toEqual([users.statusTarget.id]);

            const active = await getUsers(adminAgent, {
                search: "Sam Status",
                status: "active"
            });
            expect(active.status).toBe(200);
            expect(active.body.total).toBe(0);

            const enable = await adminAgent
                .patch(`/api/admin/users/${users.statusTarget.id}/disable`)
                .send({ disabled: false });
            expect(enable.status).toBe(200);
            expect(enable.body.user.id).toBe(users.statusTarget.id);
            expect(enable.body.user.is_disabled).toBe(false);

            const activeAgain = await getUsers(adminAgent, {
                search: "Sam Status",
                status: "active"
            });
            expect(activeAgain.status).toBe(200);
            expect(ids(activeAgain)).toEqual([users.statusTarget.id]);
        });

        test("keeps the self-disable and last-active-administrator guards intact", async () => {
            const selfDisable = await adminAgent
                .patch(`/api/admin/users/${users.admin.id}/disable`)
                .send({ disabled: true });
            const selfDemote = await adminAgent
                .patch(`/api/admin/users/${users.admin.id}/role`)
                .send({ role: "viewer" });
            const demoteLastAdmin = await adminAgent
                .patch(`/api/admin/users/${users.disabledAdmin.id}/role`)
                .send({ role: "viewer" });
            const disableLastAdmin = await adminAgent
                .patch(`/api/admin/users/${users.disabledAdmin.id}/disable`)
                .send({ disabled: true });

            expect(selfDisable.status).toBe(400);
            expect(selfDisable.body.message).toMatch(/cannot disable their own account/i);
            expect(selfDemote.status).toBe(400);
            expect(selfDemote.body.message).toMatch(/cannot change their own role/i);
            expect(demoteLastAdmin.status).toBe(409);
            expect(demoteLastAdmin.body.message).toMatch(/last active administrator/i);
            expect(disableLastAdmin.status).toBe(409);
            expect(disableLastAdmin.body.message).toMatch(/last active administrator/i);

            const stillActive = await pool.query(
                "SELECT COUNT(*)::int AS count FROM users WHERE role = 'admin' AND is_disabled = false"
            );
            expect(stillActive.rows[0].count).toBe(1);

            const adminAccount = await pool.query(
                "SELECT id, role, is_disabled FROM users WHERE id = $1",
                [users.admin.id]
            );
            expect(adminAccount.rows[0].role).toBe("admin");
            expect(adminAccount.rows[0].is_disabled).toBe(false);
        });
    });
});
