/**
 * Phase 1 security-hardening regressions.
 *
 * These tests describe the tightened contract before the implementation is
 * changed. They intentionally exercise the real Express application and the
 * isolated PostgreSQL test database: role/status changes, legacy grants,
 * session deletion, audit accuracy and rollback behaviour are all checked
 * against persisted state, not only against the HTTP response.
 */

const request = require("supertest");
const app = require("../src/app");
const pool = require("../src/db");
const {
    TEST_PASSWORD,
    VALID_PDF_BUFFER,
    resetDatabase,
    createUser,
    login,
    uploadDocument,
    fetchRow,
    countRows,
    fetchAuditLogs
} = require("./helpers");

const REASON = "Operational change approved for this account.";
const APPROVAL_REASON = "Approved after reviewing the submitted business need.";

function roleChange(agent, userId, role, reason) {
    const body = { role };
    if (reason !== undefined) body.reason = reason;
    return agent.patch(`/api/admin/users/${userId}/role`).send(body);
}

function setStatus(agent, userId, disabled, reason) {
    const body = { disabled };
    if (reason !== undefined) body.reason = reason;
    return agent.patch(`/api/admin/users/${userId}/disable`).send(body);
}

function approve(agent, requestId, decisionNote) {
    return agent
        .post(`/api/admin/requests/${requestId}/approve`)
        .send({ decisionNote });
}

function submitUpgrade(agent, reason) {
    return agent.post("/api/requests").send({
        requestType: "document_owner_upgrade",
        reason
    });
}

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
    await pool.query("DROP TRIGGER IF EXISTS test_fail_audit_insert ON audit_logs");
    await pool.query(`
        CREATE TRIGGER test_fail_audit_insert
        BEFORE INSERT ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION test_fail_audit_insert()
    `);
}

async function removeAuditFailure() {
    await pool.query("DROP TRIGGER IF EXISTS test_fail_audit_insert ON audit_logs");
    await pool.query("DROP FUNCTION IF EXISTS test_fail_audit_insert()");
}

describe("Phase 1 security hardening regressions", () => {
    const testRunId = Date.now().toString(36);
    let admin;
    let adminAgent;

    async function makeUser(label, role, isDisabled = false) {
        return createUser({
            name: `Hardening ${label}`,
            email: `hardening.${label}.${testRunId}@trustvault.test`,
            role,
            isDisabled
        });
    }

    async function loginUser(user) {
        return (await login(app, { email: user.email })).agent;
    }

    async function makeDocument(owner, name) {
        const agent = await loginUser(owner);
        return uploadDocument(agent, { name });
    }

    beforeAll(async () => {
        await resetDatabase();
        admin = await makeUser("admin", "admin");
        adminAgent = await loginUser(admin);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("manual role changes reject invalid reasons and never assign Admin", async () => {
        const target = await makeUser("reason-target", "viewer");

        for (const reason of [
            undefined,
            "too short",
            1234567890,
            "x".repeat(501),
            "contains a control\ncharacter"
        ]) {
            const response = await roleChange(
                adminAgent,
                target.id,
                "document_owner",
                reason
            );
            expect(response.status).toBe(400);
            const stored = await fetchRow("users", "id = $1", [target.id]);
            expect(stored.role).toBe("viewer");
        }

        const toAdmin = await roleChange(
            adminAgent,
            target.id,
            "admin",
            REASON
        );
        expect(toAdmin.status).toBe(400);
        expect((await fetchRow("users", "id = $1", [target.id])).role).toBe(
            "viewer"
        );

        const promoted = await roleChange(
            adminAgent,
            target.id,
            "document_owner",
            `  ${REASON}  `
        );
        expect(promoted.status).toBe(200);
        expect(promoted.body.user.role).toBe("document_owner");

        const persisted = await fetchRow("users", "id = $1", [target.id]);
        expect(persisted.role).toBe("document_owner");

        const audit = (await fetchAuditLogs({
            action: "admin_user_role_change"
        })).find(
            (row) =>
                row.outcome === "success" &&
                row.target_user_id === target.id
        );
        expect(audit).toBeTruthy();
        expect(audit.actor_id).toBe(admin.id);
        expect(audit.details.previousRole).toBe("viewer");
        expect(audit.details.newRole).toBe("document_owner");
        expect(audit.details.reason).toBe(REASON);
        expect(audit.created_at).toBeTruthy();
    });

    test("same-role, self and Admin-target role changes are rejected", async () => {
        const owner = await makeUser("same-role", "document_owner");
        const same = await roleChange(
            adminAgent,
            owner.id,
            "document_owner",
            REASON
        );
        expect(same.status).toBe(409);
        expect((await fetchRow("users", "id = $1", [owner.id])).role).toBe(
            "document_owner"
        );

        const self = await roleChange(
            adminAgent,
            admin.id,
            "viewer",
            REASON
        );
        expect(self.status).toBe(400);
        expect(self.body.message).toMatch(/cannot change their own role/i);
        expect((await fetchRow("users", "id = $1", [admin.id])).role).toBe(
            "admin"
        );

        const otherAdmin = await makeUser("protected-admin", "admin");
        const adminTarget = await roleChange(
            adminAgent,
            otherAdmin.id,
            "viewer",
            REASON
        );
        expect(adminTarget.status).toBe(409);
        expect((await fetchRow("users", "id = $1", [otherAdmin.id])).role).toBe(
            "admin"
        );
    });

    test("upgrade approval requires an administrator reason and preserves the requester reason", async () => {
        const requester = await makeUser("upgrade-requester", "viewer");
        const requesterAgent = await loginUser(requester);
        const requesterReason = "I publish the monthly compliance pack.";
        const submitted = await submitUpgrade(requesterAgent, requesterReason);
        expect(submitted.status).toBe(201);

        const missing = await adminAgent
            .post(`/api/admin/requests/${submitted.body.request.id}/approve`)
            .send({});
        expect(missing.status).toBe(400);
        expect((await fetchRow("users", "id = $1", [requester.id])).role).toBe(
            "viewer"
        );

        const short = await approve(
            adminAgent,
            submitted.body.request.id,
            "too short"
        );
        expect(short.status).toBe(400);
        expect((await fetchRow("users", "id = $1", [requester.id])).role).toBe(
            "viewer"
        );

        const approved = await approve(
            adminAgent,
            submitted.body.request.id,
            `  ${APPROVAL_REASON}  `
        );
        expect(approved.status).toBe(200);
        expect(approved.body.user.role).toBe("document_owner");

        const storedRequest = await fetchRow("requests", "id = $1", [
            submitted.body.request.id
        ]);
        expect(storedRequest.status).toBe("approved");
        expect(storedRequest.reason).toBe(requesterReason);
        expect(storedRequest.decision_note).toBe(APPROVAL_REASON);
        expect(storedRequest.decided_by).toBe(admin.id);

        const audit = (await fetchAuditLogs({
            action: "role_upgrade_request_approved"
        })).find(
            (row) =>
                row.details.requestId === submitted.body.request.id &&
                row.outcome === "success"
        );
        expect(audit).toBeTruthy();
        expect(audit.actor_id).toBe(admin.id);
        expect(audit.target_user_id).toBe(requester.id);
        expect(audit.details.reason).toBe(APPROVAL_REASON);
        expect(audit.details.requesterReason).toBe(requesterReason);
        expect(audit.details.previousRole).toBe("viewer");
        expect(audit.details.newRole).toBe("document_owner");
        expect(audit.created_at).toBeTruthy();
    });

    test("an approval reason cannot be supplied by the requester and Admin targets are not approvable", async () => {
        const requester = await makeUser("self-review", "viewer");
        const requesterAgent = await loginUser(requester);
        const inserted = await pool.query(
            `INSERT INTO requests
                (requester_id, request_type, requested_role, status, reason, reviewer_role)
             VALUES ($1, 'document_owner_upgrade', 'document_owner', 'pending',
                     'Self-review attempt', 'admin')
             RETURNING id`,
            [requester.id]
        );

        const selfRequest = await pool.query(
            `INSERT INTO requests
                (requester_id, request_type, requested_role, status, reason, reviewer_role)
             VALUES ($1, 'document_owner_upgrade', 'document_owner', 'pending',
                     'Admin self-review attempt', 'admin')
             RETURNING id`,
            [admin.id]
        );

        const adminRequester = await makeUser("approval-admin-target", "admin");
        const adminTargetRequest = await pool.query(
            `INSERT INTO requests
                (requester_id, request_type, requested_role, status, reason, reviewer_role)
             VALUES ($1, 'document_owner_upgrade', 'document_owner', 'pending',
                     'Admin target attempt', 'admin')
             RETURNING id`,
            [adminRequester.id]
        );

        try {
            // The requester never has an approval endpoint at all.
            const ownAttempt = await requesterAgent
                .post(`/api/admin/requests/${inserted.rows[0].id}/approve`)
                .send({ decisionNote: APPROVAL_REASON });
            expect(ownAttempt.status).toBe(403);

            // Admins cannot review their own request even with a valid reason.
            const adminAttempt = await approve(
                adminAgent,
                selfRequest.rows[0].id,
                APPROVAL_REASON
            );
            expect(adminAttempt.status).toBe(403);
            expect(adminAttempt.body.code).toBe("SELF_DECISION");

            // Another Admin cannot approve a request whose target is an Admin.
            const adminTargetAttempt = await approve(
                adminAgent,
                adminTargetRequest.rows[0].id,
                APPROVAL_REASON
            );
            expect(adminTargetAttempt.status).toBe(409);
            expect(
                (await fetchRow("users", "id = $1", [adminRequester.id])).role
            ).toBe("admin");
            expect(
                (
                    await fetchRow("requests", "id = $1", [
                        adminTargetRequest.rows[0].id
                    ])
                ).status
            ).toBe("pending");
        } finally {
            await pool.query("DELETE FROM requests WHERE requester_id = ANY($1::uuid[])", [
                [requester.id, admin.id, adminRequester.id]
            ]);
        }
    });

    test("demotion creates Read grants, downgrades conflicts and preserves other grants", async () => {
        const owner = await makeUser("demoted-owner", "document_owner");
        const other = await makeUser("other-user", "viewer");
        const first = await makeDocument(owner, `Legacy first ${testRunId}`);
        const second = await makeDocument(owner, `Legacy second ${testRunId}`);

        await pool.query(
            `INSERT INTO document_permissions (document_id, user_id, permission, granted_by)
             VALUES ($1, $2, 'edit', $3)`,
            [first.id, owner.id, owner.id]
        );
        await pool.query(
            `INSERT INTO document_permissions (document_id, user_id, permission, granted_by)
             VALUES ($1, $2, 'edit', $3)`,
            [second.id, other.id, owner.id]
        );

        const demotion = await roleChange(
            adminAgent,
            owner.id,
            "viewer",
            REASON
        );
        expect(demotion.status).toBe(200);
        expect(demotion.body.user.role).toBe("viewer");

        for (const document of [first, second]) {
            const grant = await fetchRow(
                "document_permissions",
                "document_id = $1 AND user_id = $2",
                [document.id, owner.id]
            );
            expect(grant).toBeTruthy();
            expect(grant.permission).toBe("read");
        }

        expect(
            await countRows(
                "document_permissions",
                "document_id = $1 AND user_id = $2",
                [first.id, owner.id]
            )
        ).toBe(1);

        const otherGrant = await fetchRow(
            "document_permissions",
            "document_id = $1 AND user_id = $2",
            [second.id, other.id]
        );
        expect(otherGrant).toBeTruthy();
        expect(otherGrant.permission).toBe("edit");

        const legacyAudits = await pool.query(
            `SELECT document_id, details FROM audit_logs
             WHERE action = 'document_permission_grant'
               AND target_user_id = $1
               AND details->>'source' = 'owner_demotion'
               AND outcome = 'success'
             ORDER BY document_id`,
            [owner.id]
        );
        expect(legacyAudits.rows).toHaveLength(2);
        expect(
            legacyAudits.rows.map((row) => row.document_id).sort()
        ).toEqual([first.id, second.id].sort());
        legacyAudits.rows.forEach((row) => {
            expect(row.details.permission).toBe("read");
            expect(row.details.reason).toBe(REASON);
        });

        const ownerAgent = await loginUser(owner);
        const shared = await ownerAgent
            .get("/api/documents")
            .query({ shared: "true", limit: 200 });
        expect(shared.status).toBe(200);
        expect(shared.body.documents.map((doc) => doc.id).sort()).toEqual(
            [first.id, second.id].sort()
        );
        shared.body.documents.forEach((doc) => {
            expect(doc.access_level).toBe("read");
        });

        const metadata = await ownerAgent.get(`/api/documents/${first.id}`);
        expect(metadata.status).toBe(200);
        expect(metadata.body.document.access_level).toBe("read");

        const download = await ownerAgent.get(
            `/api/documents/${first.id}/download`
        );
        expect(download.status).toBe(200);

        const edit = await ownerAgent
            .put(`/api/documents/${first.id}`)
            .send({ name: "Must not change" });
        expect(edit.status).toBe(403);

        const permissions = await ownerAgent.get(
            `/api/documents/${first.id}/permissions`
        );
        expect(permissions.status).toBe(404);

        const grant = await ownerAgent
            .post(`/api/documents/${first.id}/permissions`)
            .send({ email: other.email, permission: "read" });
        expect(grant.status).toBe(404);

        const revoke = await ownerAgent.delete(
            `/api/documents/${second.id}/permissions/${other.id}`
        );
        expect(revoke.status).toBe(404);

        const activity = await ownerAgent.get(
            `/api/documents/${first.id}/audit`
        );
        expect(activity.status).toBe(404);

        const deleteAttempt = await ownerAgent.delete(
            `/api/documents/${first.id}`
        );
        expect(deleteAttempt.status).toBe(403);

        const stillThere = await fetchRow("documents", "id = $1", [first.id]);
        expect(stillThere).toBeTruthy();

        const rePromotion = await roleChange(
            adminAgent,
            owner.id,
            "document_owner",
            "Returning the account to document ownership."
        );
        expect(rePromotion.status).toBe(200);
        expect(rePromotion.body.user.role).toBe("document_owner");

        // Re-promotion must not use the grant table as a role substitute:
        // the Read grants stay in place under the normal permission model.
        expect(
            await countRows(
                "document_permissions",
                "user_id = $1 AND document_id = ANY($2::uuid[])",
                [owner.id, [first.id, second.id]]
            )
        ).toBe(2);

        const metadataAgain = await ownerAgent.get(`/api/documents/${first.id}`);
        expect(metadataAgain.status).toBe(200);
        expect(metadataAgain.body.document.access_level).toBe("owner");

        const editAgain = await ownerAgent
            .put(`/api/documents/${first.id}`)
            .send({ name: `Legacy first updated ${testRunId}` });
        expect(editAgain.status).toBe(200);

        const otherStillThere = await fetchRow(
            "document_permissions",
            "document_id = $1 AND user_id = $2",
            [second.id, other.id]
        );
        expect(otherStillGranted(otherStillThere)).toBe(true);
    });

    test("disable/re-enable requires reasons, removes sessions and preserves records", async () => {
        const owner = await makeUser("disabled-owner", "document_owner");
        const viewer = await makeUser("grant-holder", "viewer");
        const document = await makeDocument(owner, `Disable record ${testRunId}`);
        await pool.query(
            `INSERT INTO document_permissions (document_id, user_id, permission, granted_by)
             VALUES ($1, $2, 'read', $3)`,
            [document.id, viewer.id, owner.id]
        );
        const ownerAgent = await loginUser(owner);

        const noReason = await setStatus(
            adminAgent,
            owner.id,
            true,
            undefined
        );
        expect(noReason.status).toBe(400);
        expect((await fetchRow("users", "id = $1", [owner.id])).is_disabled).toBe(
            false
        );
        expect(
            await countRows("user_sessions", "sess->>'userId' = $1", [owner.id])
        ).toBeGreaterThan(0);

        const disable = await setStatus(adminAgent, owner.id, true, REASON);
        expect(disable.status).toBe(200);
        expect(disable.body.user.is_disabled).toBe(true);
        expect(disable.body.revokedSessions).toBeGreaterThan(0);

        expect(
            await countRows("user_sessions", "sess->>'userId' = $1", [owner.id])
        ).toBe(0);
        expect(
            await countRows(
                "document_permissions",
                "document_id = $1 AND user_id = $2",
                [document.id, viewer.id]
            )
        ).toBe(1);
        expect(await fetchRow("documents", "id = $1", [document.id])).toBeTruthy();
        expect(await fetchRow("users", "id = $1", [owner.id])).toBeTruthy();

        const disabledRequest = await ownerAgent.get("/api/auth/me");
        expect(disabledRequest.status).toBe(401);

        const disabledLogin = await request(app)
            .post("/api/auth/login")
            .send({ email: owner.email, password: TEST_PASSWORD });
        expect(disabledLogin.status).toBe(403);
        expect(disabledLogin.body.code).toBe("ACCOUNT_DISABLED");

        const disabledMe = await ownerAgent.get("/api/auth/me");
        expect(disabledMe.status).toBe(401);

        const disableAudit = (await fetchAuditLogs({
            action: "admin_user_disabled"
        })).find(
            (row) =>
                row.outcome === "success" && row.target_user_id === owner.id
        );
        expect(disableAudit).toBeTruthy();
        expect(disableAudit.details.reason).toBe(REASON);
        expect(disableAudit.actor_id).toBe(admin.id);

        const enableWithoutReason = await setStatus(
            adminAgent,
            owner.id,
            false,
            undefined
        );
        expect(enableWithoutReason.status).toBe(400);

        const enabled = await setStatus(adminAgent, owner.id, false, REASON);
        expect(enabled.status).toBe(200);
        expect(enabled.body.user.is_disabled).toBe(false);
        expect(
            await countRows("user_sessions", "sess->>'userId' = $1", [owner.id])
        ).toBe(0);

        const relogin = await request(app)
            .post("/api/auth/login")
            .send({ email: owner.email, password: TEST_PASSWORD });
        expect(relogin.status).toBe(200);

        const enableAudit = (await fetchAuditLogs({
            action: "admin_user_enabled"
        })).find(
            (row) =>
                row.outcome === "success" && row.target_user_id === owner.id
        );
        expect(enableAudit).toBeTruthy();
        expect(enableAudit.details.reason).toBe(REASON);
    });

    test("Admin targets and self-disable are protected from status changes", async () => {
        const otherAdmin = await makeUser("status-admin", "admin");

        const adminTarget = await setStatus(
            adminAgent,
            otherAdmin.id,
            true,
            REASON
        );
        expect(adminTarget.status).toBe(409);
        expect(
            (await fetchRow("users", "id = $1", [otherAdmin.id])).is_disabled
        ).toBe(false);

        const self = await setStatus(adminAgent, admin.id, true, REASON);
        expect(self.status).toBe(400);
        expect(self.body.message).toMatch(/cannot disable their own account/i);
        expect((await fetchRow("users", "id = $1", [admin.id])).is_disabled).toBe(
            false
        );
    });

    test("a disabled account's grants stay inert and reactivation never restores Owner rights", async () => {
        const owner = await makeUser("reactivated-owner", "document_owner");
        const recipient = await makeUser("reactivated-recipient", "viewer");
        const document = await makeDocument(owner, `Reactivation ${testRunId}`);
        await pool.query(
            `INSERT INTO document_permissions (document_id, user_id, permission, granted_by)
             VALUES ($1, $2, 'read', $3)`,
            [document.id, recipient.id, owner.id]
        );
        const recipientAgent = await loginUser(recipient);

        const demotion = await roleChange(
            adminAgent,
            owner.id,
            "viewer",
            REASON
        );
        expect(demotion.status).toBe(200);

        const disable = await setStatus(adminAgent, owner.id, true, REASON);
        expect(disable.status).toBe(200);

        const whileDisabled = await recipientAgent.get(
            `/api/documents/${document.id}`
        );
        expect(whileDisabled.status).toBe(200);

        const ownerRequestWhileDisabled = await request(app)
            .post("/api/auth/login")
            .send({ email: owner.email, password: TEST_PASSWORD });
        expect(ownerRequestWhileDisabled.status).toBe(403);

        const enable = await setStatus(adminAgent, owner.id, false, REASON);
        expect(enable.status).toBe(200);

        const ownerAgent = await loginUser(owner);
        const me = await ownerAgent.get("/api/auth/me");
        expect(me.status).toBe(200);
        expect(me.body.user.role).toBe("viewer");

        const read = await ownerAgent.get(`/api/documents/${document.id}`);
        expect(read.status).toBe(200);
        expect(read.body.document.access_level).toBe("read");

        const edit = await ownerAgent
            .put(`/api/documents/${document.id}`)
            .send({ name: "Must stay read-only" });
        expect(edit.status).toBe(403);

        const deleteAttempt = await ownerAgent.delete(
            `/api/documents/${document.id}`
        );
        expect(deleteAttempt.status).toBe(403);

        const recipientRead = await recipientAgent.get(
            `/api/documents/${document.id}`
        );
        expect(recipientRead.status).toBe(200);
    });

    test("a failed status audit rolls back the status and session deletion", async () => {
        const target = await makeUser("status-audit-rollback", "document_owner");
        await loginUser(target);
        const sessionsBefore = await countRows(
            "user_sessions",
            "sess->>'userId' = $1",
            [target.id]
        );
        expect(sessionsBefore).toBeGreaterThan(0);

        await installAuditFailure("admin_user_disabled");
        try {
            const response = await setStatus(
                adminAgent,
                target.id,
                true,
                REASON
            );
            expect(response.status).toBe(500);
        } finally {
            await removeAuditFailure();
        }

        const stored = await fetchRow("users", "id = $1", [target.id]);
        expect(stored.is_disabled).toBe(false);
        expect(
            await countRows("user_sessions", "sess->>'userId' = $1", [target.id])
        ).toBe(sessionsBefore);
        expect(
            await countRows(
                "audit_logs",
                "action = 'admin_user_disabled' AND target_user_id = $1 AND outcome = 'success'",
                [target.id]
            )
        ).toBe(0);
    });

    test("a failed role-change audit rolls back role, grants and pending request", async () => {
        const target = await makeUser("role-audit-rollback", "viewer");
        const targetAgent = await loginUser(target);
        const submitted = await submitUpgrade(
            targetAgent,
            "Role change must be auditable."
        );
        expect(submitted.status).toBe(201);

        await installAuditFailure("admin_user_role_change");
        try {
            const response = await roleChange(
                adminAgent,
                target.id,
                "document_owner",
                REASON
            );
            expect(response.status).toBe(500);
        } finally {
            await removeAuditFailure();
        }

        expect((await fetchRow("users", "id = $1", [target.id])).role).toBe(
            "viewer"
        );
        const pending = await fetchRow("requests", "id = $1", [
            submitted.body.request.id
        ]);
        expect(pending.status).toBe("pending");
        expect(pending.decided_at).toBeNull();
    });
});

function otherStillGranted(row) {
    return Boolean(row) && row.permission === "edit";
}
