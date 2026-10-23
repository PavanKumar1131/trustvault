/**
 * Audit trail suite.
 *
 * Verifies the hash chain, the append-only protection, the detection of
 * tampering and truncation, and the behaviour under concurrent appends.
 */

const request = require("supertest");
const app = require("../src/app");
const pool = require("../src/db");
const {
    writeAuditLog,
    verifyAuditChain,
    rebuildAuditChainIfNeeded,
    canonicalJson,
    computeEntryHash,
    GENESIS_HASH
} = require("../src/services/auditService");
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

describe("TrustVault audit trail", () => {
    const testRunId = Date.now().toString(36);
    const password = TEST_PASSWORD;

    const emails = {
        owner: `audit.owner.${testRunId}@trustvault.test`,
        admin: `audit.admin.${testRunId}@trustvault.test`
    };

    const agents = {};
    const users = {};
    let documentId = null;

    beforeAll(async () => {
        await resetDatabase();

        const owner = await registerAndLogin(app, {
            name: "Audit Owner", email: emails.owner, role: "document_owner"
        });
        agents.owner = owner.agent;
        users.owner = owner.user;

        users.admin = await createUser({
            name: "Audit Admin", email: emails.admin, role: "admin"
        });
        agents.admin = request.agent(app);
        await agents.admin.post("/api/auth/login").send({ email: emails.admin, password });
    });

    // ══════════════════════════════════════════════════════════════════════
    test("1. Every entry links to its predecessor", async () => {
        documentId = (
            await uploadDocument(agents.owner, { name: `Audit_${testRunId}`, category: "Audit" })
        ).id;

        const rows = await pool.query(
            "SELECT id, prev_hash, entry_hash FROM audit_logs ORDER BY id ASC"
        );

        expect(rows.rows.length).toBeGreaterThan(0);
        expect(rows.rows[0].prev_hash).toBe(GENESIS_HASH);

        for (let index = 1; index < rows.rows.length; index += 1) {
            expect(rows.rows[index].prev_hash).toBe(rows.rows[index - 1].entry_hash);
            expect(rows.rows[index].entry_hash).toMatch(/^[0-9a-f]{64}$/);
        }

        const verification = await verifyAuditChain();
        expect(verification.valid).toBe(true);
        expect(verification.reason).toBe("ok");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("2. Concurrent appends keep the chain consistent", async () => {
        const before = await countRows("audit_logs");

        const appends = [];
        for (let index = 0; index < 25; index += 1) {
            appends.push(
                writeAuditLog(
                    { user: { id: users.owner.id }, ip: "127.0.0.1", get: () => "jest" },
                    "concurrency_probe",
                    "success",
                    documentId,
                    { index, nested: { batch: testRunId, order: index } }
                )
            );
        }

        const results = await Promise.all(appends);
        expect(results).toHaveLength(25);

        // Database state: 25 new rows, no duplicates, no gaps in the chain.
        expect(await countRows("audit_logs")).toBe(before + 25);

        const verification = await verifyAuditChain();
        expect(verification.valid).toBe(true);
        expect(verification.reason).toBe("ok");
        expect(verification.totalEntries).toBe(before + 25);

        const distinctHashes = await pool.query(
            "SELECT COUNT(DISTINCT entry_hash)::int AS count FROM audit_logs"
        );
        expect(distinctHashes.rows[0].count).toBe(before + 25);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("3. Nested detail objects keep the chain valid", async () => {
        await writeAuditLog(
            { user: { id: users.owner.id }, ip: "127.0.0.1", get: () => "jest" },
            "nested_details_probe",
            "success",
            documentId,
            {
                zebra: "last alphabetically",
                alpha: 1,
                nested: {
                    deeper: {
                        value: [1, 2, { z: true, a: false }],
                        when: "2026-01-01T00:00:00.000Z"
                    }
                }
            }
        );

        const verification = await verifyAuditChain();
        expect(verification.valid).toBe(true);

        // Database state: the details were stored as JSON.
        const row = await fetchRow("audit_logs", "action = $1", ["nested_details_probe"]);
        expect(row.details.nested.deeper.value[2].a).toBe(false);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("4. The canonical representation is stable across key order", async () => {
        const first = canonicalJson({ b: 1, a: { d: 2, c: 3 } });
        const second = canonicalJson({ a: { c: 3, d: 2 }, b: 1 });

        expect(first).toBe(second);
        expect(first).toBe('{"a":{"c":3,"d":2},"b":1}');
    });

    // ══════════════════════════════════════════════════════════════════════
    test("5. A modified row breaks the chain", async () => {
        const client = await pool.connect();
        try {
            // Temporarily remove the protection to simulate an attacker with
            // direct database access.
            await client.query("DROP TRIGGER IF EXISTS audit_logs_immutable_trigger ON audit_logs");
            await client.query(
                `UPDATE audit_logs SET details = '{"tampered":true}'::jsonb WHERE id = (
                    SELECT id FROM audit_logs WHERE action = 'nested_details_probe' LIMIT 1
                 )`
            );
        } finally {
            await client.release();
        }

        const verification = await verifyAuditChain();
        expect(verification.valid).toBe(false);
        expect(verification.reason).toBe("entry_hash_mismatch");

        // The chain can be repaired, and the repair is verified again.
        await rebuildAuditChainIfNeeded();

        const repaired = await verifyAuditChain();
        expect(repaired.valid).toBe(true);
        expect(repaired.reason).toBe("ok");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("6. Truncating the tail of the log is detected", async () => {
        // A dedicated entry at the very end of the log, so that removing the
        // tail does not affect the entries the other tests rely on.
        await writeAuditLog(
            { user: { id: users.owner.id }, ip: "127.0.0.1", get: () => "jest" },
            "truncation_probe",
            "success",
            documentId,
            { probe: true }
        );

        const before = await countRows("audit_logs");
        expect(before).toBeGreaterThan(0);

        const client = await pool.connect();
        try {
            await client.query("DROP TRIGGER IF EXISTS audit_logs_immutable_trigger ON audit_logs");
            await client.query(
                "DELETE FROM audit_logs WHERE id = (SELECT MAX(id) FROM audit_logs)"
            );
        } finally {
            await client.release();
        }

        // Database state: one row is missing.
        expect(await countRows("audit_logs")).toBe(before - 1);

        const verification = await verifyAuditChain();
        expect(verification.valid).toBe(false);
        expect(verification.reason).toBe("head_anchor_mismatch");
        expect(verification.detail).toMatch(/removed/i);

        // Restore the log and repair the chain.
        await rebuildAuditChainIfNeeded();
        expect((await verifyAuditChain()).valid).toBe(true);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("7. The database refuses updates and deletes on the audit log", async () => {
        const before = await countRows("audit_logs");

        await expect(pool.query("DELETE FROM audit_logs")).rejects.toThrow(/append-only/i);
        await expect(
            pool.query("UPDATE audit_logs SET outcome = 'success'")
        ).rejects.toThrow(/append-only/i);

        // Database state: nothing was deleted or modified.
        expect(await countRows("audit_logs")).toBe(before);
        expect((await verifyAuditChain()).valid).toBe(true);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("8. Denied actions are recorded with the document they concern", async () => {
        const stranger = await registerAndLogin(app, {
            name: "Audit Stranger",
            email: `audit.stranger.${testRunId}@trustvault.test`,
            role: "document_owner"
        });

        const response = await stranger.agent.get(`/api/documents/${documentId}`);
        expect(response.status).toBe(404);

        // Database state: a denial was recorded and points at the document.
        const denials = await fetchAuditLogs({
            action: "document_read",
            outcome: "denied",
            documentId
        });

        expect(denials.length).toBeGreaterThan(0);
        expect(denials[0].actor_id).toBe(stranger.user.id);
        expect(denials[0].outcome).toBe("denied");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("9. The administration console can filter the audit log", async () => {
        const denied = await agents.admin
            .get("/api/admin/audit-logs")
            .query({ outcome: "denied", limit: 20 });
        expect(denied.status).toBe(200);
        expect(
            denied.body.logs.every((log) => log.outcome === "denied")
        ).toBe(true);

        const byAction = await agents.admin
            .get("/api/admin/audit-logs")
            .query({ action: "document_read", limit: 20 });
        expect(byAction.status).toBe(200);
        expect(
            byAction.body.logs.every((log) => log.action === "document_read")
        ).toBe(true);

        const verification = await agents.admin.get("/api/admin/verify-chain");
        expect(verification.status).toBe(200);
        expect(verification.body.valid).toBe(true);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("10. The chain head matches the independently stored anchor", async () => {
        const verification = await verifyAuditChain();
        const anchor = await pool.query(
            "SELECT last_entry_id, last_hash FROM audit_chain_state WHERE id = 1"
        );
        const head = await pool.query(
            "SELECT COALESCE(MAX(id), 0)::bigint AS id FROM audit_logs"
        );

        expect(anchor.rows).toHaveLength(1);
        // The anchor stores the *id* of the newest entry, not the number of
        // entries (the ids are not contiguous when rows were removed).
        expect(Number(anchor.rows[0].last_entry_id)).toBe(Number(head.rows[0].id));
        expect(anchor.rows[0].last_hash).toBe(verification.headHash);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("11. The hash of an entry matches the documented definition", async () => {
        const row = await fetchRow("audit_logs", "action = $1", ["nested_details_probe"]);

        const expected = computeEntryHash({
            prevHash: row.prev_hash,
            actorId: row.actor_id,
            documentId: row.document_id,
            targetUserId: row.target_user_id,
            action: row.action,
            outcome: row.outcome,
            detailsJson: canonicalJson(row.details)
        });

        expect(row.entry_hash).toBe(expected);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("12. A TRUNCATE bypasses the row trigger but is still detected", async () => {
        // Documented limitation: the immutability trigger fires for UPDATE and
        // DELETE, not for TRUNCATE. The independent head anchor still detects
        // the removal.
        await expect(pool.query("TRUNCATE audit_logs")).resolves.toBeDefined();

        // Database state: the log is empty.
        expect(await countRows("audit_logs")).toBe(0);

        const verification = await verifyAuditChain();
        expect(verification.valid).toBe(false);
        expect(verification.reason).toBe("head_anchor_mismatch");

        // The chain can be reset to a consistent state again.
        await rebuildAuditChainIfNeeded();
        const repaired = await verifyAuditChain();
        expect(repaired.valid).toBe(true);
        expect(repaired.totalEntries).toBe(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("13. An out-of-sync or reset audit_chain_state does not create split chains or invalid prev_hash", async () => {
        // Append a known first entry
        const first = await writeAuditLog(
            { user: { id: users.owner.id }, ip: "127.0.0.1", get: () => "jest" },
            "pre_anchor_reset_probe",
            "success",
            null,
            { step: 1 }
        );

        const firstRow = await fetchRow("audit_logs", "id = $1", [first.id]);
        expect(firstRow).toBeDefined();

        // Simulate the root cause of the incident at entry 438:
        // audit_chain_state is reset to 0 / GENESIS while audit_logs has entries.
        await pool.query(
            "UPDATE audit_chain_state SET last_entry_id = 0, last_hash = 'GENESIS' WHERE id = 1"
        );

        // Write the next entry
        const second = await writeAuditLog(
            { user: { id: users.owner.id }, ip: "127.0.0.1", get: () => "jest" },
            "post_anchor_reset_probe",
            "success",
            null,
            { step: 2 }
        );

        const secondRow = await fetchRow("audit_logs", "id = $1", [second.id]);

        // Must link to the actual prior entry's hash, NEVER 'GENESIS'
        expect(secondRow.prev_hash).toBe(firstRow.entry_hash);
        expect(secondRow.prev_hash).not.toBe(GENESIS_HASH);

        // The entire chain must verify as valid
        const verification = await verifyAuditChain();
        expect(verification.valid).toBe(true);
        expect(verification.reason).toBe("ok");
        expect(verification.status).toBe("verified");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("14. Distinguishes a verified chain, a documented historical incident, and an undocumented failure", async () => {
        // 1. Fresh intact chain verifies as valid and status 'verified'
        const initial = await verifyAuditChain();
        expect(initial.valid).toBe(true);
        expect(initial.status).toBe("verified");

        // 2. Simulate historical break documented with an incident annotation
        const client = await pool.connect();
        try {
            await client.query("DROP TRIGGER IF EXISTS audit_logs_immutable_trigger ON audit_logs");
            // Set prev_hash of newest row to GENESIS simulating the incident
            const newestRes = await pool.query("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 1");
            const newest = newestRes.rows[0];
            expect(newest).toBeDefined();

            const simulatedHash = computeEntryHash({
                prevHash: "GENESIS",
                actorId: newest.actor_id,
                documentId: newest.document_id,
                targetUserId: newest.target_user_id,
                action: newest.action,
                outcome: newest.outcome,
                detailsJson: canonicalJson(newest.details || {})
            });

            await client.query(
                "UPDATE audit_logs SET prev_hash = 'GENESIS', entry_hash = $1 WHERE id = $2",
                [simulatedHash, newest.id]
            );
            await client.query(
                "UPDATE audit_chain_state SET last_hash = $1 WHERE id = 1",
                [simulatedHash]
            );

            // Without annotation: reports status 'failed'
            const unannotated = await verifyAuditChain();
            expect(unannotated.valid).toBe(false);
            expect(unannotated.status).toBe("failed");
            expect(unannotated.reason).toBe("broken_link");

            // Insert authorized integrity incident annotation
            await client.query(
                `INSERT INTO audit_incident_annotations
                    (incident_code, incident_type, broken_at_id, affected_range_start, affected_range_end, root_cause, authorized_disposition, authorized_by)
                 VALUES ('INC-TEST-1', 'anchor_desync_split_chain', $1, 1, $1, 'Test root cause', 'Preserve evidence', 'Test Admin')`,
                [newest.id]
            );

            // With annotation: reports status 'documented_incident', valid: false (never claims intact)
            const documented = await verifyAuditChain();
            expect(documented.valid).toBe(false);
            expect(documented.status).toBe("documented_incident");
            expect(documented.reason).toBe("documented_historical_incident");
            expect(documented.incident.code).toBe("INC-TEST-1");
            expect(documented.brokenAtId).toBe(newest.id);

            // rebuildAuditChainIfNeeded preserves documented incident without rewriting
            const rebuildResult = await rebuildAuditChainIfNeeded();
            expect(rebuildResult.rebuilt).toBe(false);
            expect(rebuildResult.preservedIncident).toBe(true);
        } finally {
            try {
                await client.query("DROP TRIGGER IF EXISTS audit_logs_immutable_trigger ON audit_logs");
                await client.query(
                    `CREATE TRIGGER audit_logs_immutable_trigger
                     BEFORE UPDATE OR DELETE ON audit_logs
                     FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_tampering()`
                );
            } catch (err) {
                // Ignore cleanup error if already restored
            } finally {
                client.release();
            }
        }
    });
});
