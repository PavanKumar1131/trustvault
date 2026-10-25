/**
 * Migration suite.
 *
 * Verifies that the canonical schema is applied consistently, that the
 * migration works on a completely empty database and that it is idempotent.
 *
 * The "fresh database" case creates a temporary database, migrates it and
 * drops it again. The database is always removed, even when a test fails.
 */

const fs = require("node:fs");
const path = require("node:path");
const { Pool } = require("pg");
const config = require("../src/config");
const { migrate, SCHEMA_PATH } = require("../src/scripts/migrate");
const { SOURCE: SCHEMA_SOURCE, TARGET: SCHEMA_TARGET } = require("../src/scripts/sync-schema");
const { assertSafeTestDatabase } = require("./testDatabaseGuard");

// The migration probe is a temporary derivative of the guarded test database.
// Refuse to create or drop it unless the base target is the loopback
// `trustvault_test` database.
assertSafeTestDatabase();

const PROBE_DATABASE = "trustvault_test_migration_probe";

function buildProbeConnectionString() {
    const url = new URL(config.DATABASE_URL);
    url.pathname = `/${PROBE_DATABASE}`;
    return url.toString();
}

function createPool(connectionString) {
    return new Pool({
        connectionString,
        ssl: config.SSL ? { rejectUnauthorized: true } : false,
        max: 2,
        connectionTimeoutMillis: 10000,
        application_name: "trustvault-migration-probe"
    });
}

describe("TrustVault schema and migrations", () => {
    // ══════════════════════════════════════════════════════════════════════
    test("1. The canonical schema and its copy are identical", () => {
        const canonical = fs.readFileSync(SCHEMA_SOURCE, "utf8");
        const copy = fs.readFileSync(SCHEMA_TARGET, "utf8");

        expect(copy).toBe(canonical);
        expect(fs.readFileSync(SCHEMA_PATH, "utf8")).toBe(canonical);
    });

    test("the migration never invokes an audit-chain rebuild", () => {
        const source = fs.readFileSync(
            path.join(__dirname, "..", "src", "scripts", "migrate.js"),
            "utf8"
        );
        expect(source).not.toMatch(/rebuildAuditChainIfNeeded/);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("2. The canonical schema contains every required object", () => {
        const schema = fs.readFileSync(SCHEMA_SOURCE, "utf8");

        for (const table of [
            "users",
            "documents",
            "document_blobs",
            "document_permissions",
            "audit_logs",
            "audit_chain_state",
            "audit_incident_annotations",
            "user_sessions",
            "requests"
        ]) {
            expect(schema).toContain(`CREATE TABLE IF NOT EXISTS ${table}`);
        }

        // The audit trail must be protected by the database itself.
        expect(schema).toContain("prevent_audit_log_tampering");
        expect(schema).toContain("audit_logs_immutable_trigger");

        // One permission level per user and document.
        expect(schema).toContain("UNIQUE (document_id, user_id)");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("3. A migration on an empty database creates a complete schema", async () => {
        const admin = createPool(config.DATABASE_URL);
        let probe = null;

        try {
            // Remove a leftover probe database from an earlier run.
            await admin.query(
                `DROP DATABASE IF EXISTS "${PROBE_DATABASE}" WITH (FORCE)`
            );
            await admin.query(`CREATE DATABASE "${PROBE_DATABASE}"`);

            probe = createPool(buildProbeConnectionString());

            // The database really is empty.
            const before = await probe.query(
                `SELECT COUNT(*)::int AS count
                 FROM information_schema.tables
                 WHERE table_schema = 'public'`
            );
            expect(before.rows[0].count).toBe(0);

            const result = await migrate({ pool: probe, rebuildChain: false });
            expect(result.ok).toBe(true);

            // Every object of the canonical schema exists.
            const tables = await probe.query(
                `SELECT table_name FROM information_schema.tables
                 WHERE table_schema = 'public' ORDER BY table_name`
            );
            const names = tables.rows.map((row) => row.table_name);

            for (const table of [
                "audit_chain_state",
                "audit_incident_annotations",
                "audit_logs",
                "document_blobs",
                "document_permissions",
                "documents",
                "requests",
                "user_sessions",
                "users"
            ]) {
                expect(names).toContain(table);
            }

            // The trigger protecting the audit trail is installed.
            const triggers = await probe.query(
                `SELECT tgname FROM pg_trigger
                 WHERE tgrelid = 'audit_logs'::regclass AND NOT tgisinternal`
            );
            expect(triggers.rows.map((row) => row.tgname)).toContain(
                "audit_logs_immutable_trigger"
            );

            // The one-permission-per-user constraint is present.
            const uniqueConstraints = await probe.query(
                `SELECT conname FROM pg_constraint
                 WHERE conrelid = 'document_permissions'::regclass AND contype = 'u'`
            );
            expect(uniqueConstraints.rows.length).toBeGreaterThan(0);

            const permissionCheck = await probe.query(
                `SELECT conname FROM pg_constraint
                 WHERE conrelid = 'document_permissions'::regclass AND contype = 'c'`
            );
            expect(permissionCheck.rows.length).toBeGreaterThan(0);
        } finally {
            if (probe) {
                await probe.end().catch(() => {});
            }
            await admin.query(
                `DROP DATABASE IF EXISTS "${PROBE_DATABASE}" WITH (FORCE)`
            ).catch(() => {});
            await admin.end().catch(() => {});
        }
    });

    // ══════════════════════════════════════════════════════════════════════
    test("4. The migration is idempotent", async () => {
        const admin = createPool(config.DATABASE_URL);
        let probe = null;

        try {
            await admin.query(
                `DROP DATABASE IF EXISTS "${PROBE_DATABASE}" WITH (FORCE)`
            );
            await admin.query(`CREATE DATABASE "${PROBE_DATABASE}"`);

            probe = createPool(buildProbeConnectionString());

            const first = await migrate({ pool: probe, rebuildChain: false });
            expect(first.ok).toBe(true);

            const second = await migrate({ pool: probe, rebuildChain: false });
            expect(second.ok).toBe(true);

            const third = await migrate({ pool: probe, rebuildChain: false });
            expect(third.ok).toBe(true);

            // Database state: the objects were not duplicated.
            const tables = await probe.query(
                `SELECT COUNT(*)::int AS count
                 FROM information_schema.tables
                 WHERE table_schema = 'public'`
            );
            expect(tables.rows[0].count).toBe(9);

            const uniqueConstraints = await probe.query(
                `SELECT COUNT(*)::int AS count FROM pg_constraint
                 WHERE conrelid = 'document_permissions'::regclass AND contype = 'u'`
            );
            expect(uniqueConstraints.rows[0].count).toBe(1);
        } finally {
            if (probe) {
                await probe.end().catch(() => {});
            }
            await admin.query(
                `DROP DATABASE IF EXISTS "${PROBE_DATABASE}" WITH (FORCE)`
            ).catch(() => {});
            await admin.end().catch(() => {});
        }
    });

    // ══════════════════════════════════════════════════════════════════════
    test("5. Legacy role-upgrade rows are preserved in requests and the old table is removed", async () => {
        const admin = createPool(config.DATABASE_URL);
        let probe = null;

        try {
            await admin.query(`DROP DATABASE IF EXISTS "${PROBE_DATABASE}" WITH (FORCE)`);
            await admin.query(`CREATE DATABASE "${PROBE_DATABASE}"`);
            probe = createPool(buildProbeConnectionString());
            await migrate({ pool: probe, rebuildChain: false });

            const user = await probe.query(
                `INSERT INTO users (name, email, password_hash, role)
                 VALUES ('Legacy requester', 'legacy-requester@example.com', 'hash', 'viewer')
                 RETURNING id`
            );
            await probe.query(`
                CREATE TABLE role_upgrade_requests (
                    id UUID PRIMARY KEY,
                    user_id UUID NOT NULL,
                    requested_role VARCHAR(30) NOT NULL,
                    status VARCHAR(20) NOT NULL,
                    justification TEXT,
                    decided_by UUID,
                    submitted_at TIMESTAMPTZ NOT NULL,
                    decided_at TIMESTAMPTZ
                )
            `);
            const legacy = await probe.query(
                `INSERT INTO role_upgrade_requests
                    (id, user_id, requested_role, status, justification, submitted_at, decided_at)
                 VALUES (gen_random_uuid(), $1, 'document_owner', 'rejected', 'retained reason',
                         NOW() - INTERVAL '10 days', NOW() - INTERVAL '9 days')
                 RETURNING id, user_id, submitted_at, decided_at`,
                [user.rows[0].id]
            );

            await migrate({ pool: probe, rebuildChain: false });

            const copied = await probe.query(
                `SELECT id, requester_id, request_type, requested_role, reason,
                        status, reviewer_role, submitted_at, decided_at
                 FROM requests WHERE id = $1`,
                [legacy.rows[0].id]
            );
            expect(copied.rows).toHaveLength(1);
            expect(copied.rows[0]).toMatchObject({
                id: legacy.rows[0].id,
                requester_id: user.rows[0].id,
                request_type: "document_owner_upgrade",
                requested_role: "document_owner",
                reason: "retained reason",
                status: "rejected",
                reviewer_role: "admin"
            });
            expect(copied.rows[0].submitted_at).toEqual(legacy.rows[0].submitted_at);
            expect(copied.rows[0].decided_at).toEqual(legacy.rows[0].decided_at);
            const legacyTable = await probe.query("SELECT to_regclass('public.role_upgrade_requests') AS name");
            expect(legacyTable.rows[0].name).toBeNull();
        } finally {
            if (probe) await probe.end().catch(() => {});
            await admin.query(`DROP DATABASE IF EXISTS "${PROBE_DATABASE}" WITH (FORCE)`).catch(() => {});
            await admin.end().catch(() => {});
        }
    });

    test("6. The audit trail of a fresh database starts empty but consistent", async () => {
        const admin = createPool(config.DATABASE_URL);
        let probe = null;

        try {
            await admin.query(
                `DROP DATABASE IF EXISTS "${PROBE_DATABASE}" WITH (FORCE)`
            );
            await admin.query(`CREATE DATABASE "${PROBE_DATABASE}"`);

            probe = createPool(buildProbeConnectionString());

            await migrate({ pool: probe, rebuildChain: false });

            const anchor = await probe.query(
                "SELECT last_entry_id, last_hash FROM audit_chain_state WHERE id = 1"
            );

            expect(anchor.rows).toHaveLength(1);
            expect(Number(anchor.rows[0].last_entry_id)).toBe(0);
            expect(anchor.rows[0].last_hash).toBe("GENESIS");

            const logs = await probe.query("SELECT COUNT(*)::int AS count FROM audit_logs");
            expect(logs.rows[0].count).toBe(0);
        } finally {
            if (probe) {
                await probe.end().catch(() => {});
            }
            await admin.query(
                `DROP DATABASE IF EXISTS "${PROBE_DATABASE}" WITH (FORCE)`
            ).catch(() => {});
            await admin.end().catch(() => {});
        }
    });

    // ══════════════════════════════════════════════════════════════════════
    test("6. The seed script refuses to run against the test database", () => {
        const seedSource = fs.readFileSync(
            path.join(__dirname, "..", "src", "scripts", "seed.js"),
            "utf8"
        );

        // The guard is checked statically so that the test never has to run
        // the destructive seed script.
        expect(seedSource).toMatch(/Refusing to seed while NODE_ENV=test/);
        expect(seedSource).toMatch(/Refusing to seed in production/);
        expect(seedSource).toMatch(/nodeEnv\s*===\s*"test"/);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("7. The blob foreign key is validated and dangling documents are repaired", async () => {
        const admin = createPool(config.DATABASE_URL);
        let probe = null;

        try {
            await admin.query(
                `DROP DATABASE IF EXISTS "${PROBE_DATABASE}" WITH (FORCE)`
            );
            await admin.query(`CREATE DATABASE "${PROBE_DATABASE}"`);

            probe = createPool(buildProbeConnectionString());
            await migrate({ pool: probe, rebuildChain: false });

            // The constraint exists and is fully validated.
            const constraint = await probe.query(
                `SELECT conname, convalidated FROM pg_constraint
                 WHERE conrelid = 'documents'::regclass
                   AND conname = 'documents_storage_key_fkey'`
            );
            expect(constraint.rows).toHaveLength(1);
            expect(constraint.rows[0].convalidated).toBe(true);

            // ── A legacy database ──────────────────────────────────────────
            // The constraint does not exist and a document points at a blob
            // that was lost — the state the migration has to repair.
            await probe.query(
                "ALTER TABLE documents DROP CONSTRAINT documents_storage_key_fkey"
            );

            const owner = await probe.query(
                `INSERT INTO users (name, email, password_hash, role)
                 VALUES ('Orphan Owner', 'orphan@example.com', 'not-a-real-hash', 'document_owner')
                 RETURNING id`
            );

            await probe.query(
                `INSERT INTO documents
                     (owner_id, name, category, storage_key, original_filename,
                      content_type, file_size)
                 VALUES ($1, 'Orphan', 'General',
                         '11111111-2222-4333-8444-555555555555',
                         'orphan.pdf', 'application/pdf', 10)`,
                [owner.rows[0].id]
            );

            const danglingBefore = await probe.query(
                `SELECT COUNT(*)::int AS count FROM documents d
                 WHERE NOT EXISTS (
                     SELECT 1 FROM document_blobs b WHERE b.storage_key = d.storage_key
                 )`
            );
            expect(danglingBefore.rows[0].count).toBe(1);

            // The migration repairs the dangling reference and validates the
            // constraint again.
            const result = await migrate({ pool: probe, rebuildChain: false });
            expect(result.ok).toBe(true);

            const danglingAfter = await probe.query(
                `SELECT COUNT(*)::int AS count FROM documents d
                 WHERE NOT EXISTS (
                     SELECT 1 FROM document_blobs b WHERE b.storage_key = d.storage_key
                 )`
            );
            expect(danglingAfter.rows[0].count).toBe(0);

            const repaired = await probe.query(
                `SELECT conname, convalidated FROM pg_constraint
                 WHERE conrelid = 'documents'::regclass
                   AND conname = 'documents_storage_key_fkey'`
            );
            expect(repaired.rows).toHaveLength(1);
            expect(repaired.rows[0].convalidated).toBe(true);
        } finally {
            if (probe) {
                await probe.end().catch(() => {});
            }
            await admin.query(
                `DROP DATABASE IF EXISTS "${PROBE_DATABASE}" WITH (FORCE)`
            ).catch(() => {});
            await admin.end().catch(() => {});
        }
    });
});
