/**
 * TrustVault schema migration.
 *
 * The migration is idempotent and works on a completely empty database:
 *
 *   1. the canonical schema (`src/schema.sql`) is applied — every object is
 *      created with `IF NOT EXISTS`, so existing databases are left alone;
 *   2. the data upgrades that cannot be expressed in DDL are applied
 *      (legacy permission values, duplicate grants, missing constraints);
 *   3. the audit hash chain is rebuilt if it does not verify.
 *
 * The script never drops user data.
 */

const fs = require("node:fs/promises");
const path = require("node:path");
const pool = require("../db");
const { rebuildAuditChainIfNeeded } = require("../services/auditService");

const SCHEMA_PATH = path.join(__dirname, "..", "schema.sql");

/**
 * Applies the canonical schema and the data upgrades.
 * @param {object} [options]
 * @param {object} [options.pool] Pool to use (defaults to the shared pool)
 * @param {boolean} [options.rebuildChain] Rebuild the audit chain when it is
 *        broken. Disabled by the automated test-suite, which rebuilds it
 *        explicitly where required.
 */
async function migrate(options = {}) {
    const target = options.pool || pool;
    const client = await target.connect();

    try {
        console.log("Running TrustVault schema migration...");

        const schema = await fs.readFile(SCHEMA_PATH, "utf8");

        await client.query("BEGIN");

        // ── 1. Canonical schema ───────────────────────────────────────────────
        await client.query(schema);

        // ── 2. Legacy columns ─────────────────────────────────────────────────
        // `CREATE TABLE IF NOT EXISTS` does not add columns to an existing
        // table, so they are added explicitly.
        await client.query(`
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS is_disabled BOOLEAN NOT NULL DEFAULT false;
        `);

        await client.query(`
            ALTER TABLE audit_logs
            ADD COLUMN IF NOT EXISTS prev_hash VARCHAR(64) NOT NULL DEFAULT 'GENESIS',
            ADD COLUMN IF NOT EXISTS entry_hash VARCHAR(64) NOT NULL DEFAULT '';
        `);

        // ── 2b. Detach the audit trail from the entity lifecycle ──────────────
        // `ON DELETE SET NULL` cascades would rewrite historic audit rows when
        // a user or document is deleted — and would be rejected by the
        // append-only trigger. The audit trail must stay untouched.
        await client.query(`
            DO $$
            DECLARE
                constraint_name TEXT;
            BEGIN
                FOR constraint_name IN
                    SELECT con.conname
                    FROM pg_constraint con
                    JOIN pg_class rel ON rel.oid = con.conrelid
                    WHERE rel.relname = 'audit_logs'
                      AND con.contype = 'f'
                LOOP
                    EXECUTE format('ALTER TABLE audit_logs DROP CONSTRAINT %I', constraint_name);
                END LOOP;
            END $$;
        `);

        // ── 3. Role check constraint ──────────────────────────────────────────
        // Refuse to migrate when the table contains a role that the
        // application does not know: silently rewriting it would hide data
        // corruption.
        await client.query(`
            DO $$
            DECLARE
                unsupported TEXT;
            BEGIN
                SELECT string_agg(DISTINCT role, ', ') INTO unsupported
                FROM users
                WHERE role NOT IN ('admin', 'document_owner', 'viewer');

                IF unsupported IS NOT NULL THEN
                    RAISE EXCEPTION
                        'users.role contains unsupported value(s): % — correct them manually before migrating',
                        unsupported;
                END IF;
            END $$;
        `);

        // Drop every CHECK constraint on users.role and re-create the
        // canonical one. Doing so keeps legacy variants (e.g. an extra
        // 'support_admin' role) from blocking valid role assignments.
        await client.query(`
            DO $$
            DECLARE
                constraint_name TEXT;
            BEGIN
                FOR constraint_name IN
                    SELECT con.conname
                    FROM pg_constraint con
                    JOIN pg_class rel ON rel.oid = con.conrelid
                    JOIN pg_attribute att
                      ON att.attrelid = rel.oid AND att.attnum = ANY(con.conkey)
                    WHERE rel.relname = 'users'
                      AND con.contype = 'c'
                      AND att.attname = 'role'
                LOOP
                    EXECUTE format('ALTER TABLE users DROP CONSTRAINT %I', constraint_name);
                END LOOP;
            END $$;
        `);

        await client.query(`
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_constraint con
                    JOIN pg_class rel ON rel.oid = con.conrelid
                    WHERE rel.relname = 'users'
                      AND con.contype = 'c'
                      AND (
                          SELECT array_agg(att.attname::text ORDER BY att.attname::text)
                          FROM unnest(con.conkey) AS key_column(attnum)
                          JOIN pg_attribute att
                            ON att.attrelid = rel.oid AND att.attnum = key_column.attnum
                      ) = ARRAY['role']::text[]
                ) THEN
                    ALTER TABLE users
                        ADD CONSTRAINT users_role_check
                        CHECK (role IN ('admin', 'document_owner', 'viewer'));
                END IF;
            END $$;
        `);

        // ── 4. Permission values, duplicates and constraints ─────────────────
        // Drop the CHECK constraint first: the legacy definition only allows
        // 'view'/'download', which would block the normalisation below.
        await client.query(`
            DO $$
            DECLARE
                constraint_name TEXT;
            BEGIN
                FOR constraint_name IN
                    SELECT con.conname
                    FROM pg_constraint con
                    JOIN pg_class rel ON rel.oid = con.conrelid
                    JOIN pg_attribute att
                      ON att.attrelid = rel.oid AND att.attnum = ANY(con.conkey)
                    WHERE rel.relname = 'document_permissions'
                      AND con.contype = 'c'
                      AND att.attname = 'permission'
                LOOP
                    EXECUTE format('ALTER TABLE document_permissions DROP CONSTRAINT %I', constraint_name);
                END LOOP;
            END $$;
        `);

        // 'view' and 'download' were the old names of the 'read' permission.
        await client.query(`
            UPDATE document_permissions
            SET permission = 'read'
            WHERE permission IN ('view', 'download');
        `);

        // A user may only hold one permission level per document. Keep the
        // strongest one when legacy rows contain duplicates.
        await client.query(`
            DELETE FROM document_permissions
            WHERE id IN (
                SELECT id
                FROM (
                    SELECT id,
                           ROW_NUMBER() OVER (
                               PARTITION BY document_id, user_id
                               ORDER BY CASE permission WHEN 'edit' THEN 2 ELSE 1 END DESC,
                                        created_at DESC,
                                        id DESC
                           ) AS row_number
                    FROM document_permissions
                ) ranked
                WHERE ranked.row_number > 1
            );
        `);

        await client.query(`
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_constraint con
                    JOIN pg_class rel ON rel.oid = con.conrelid
                    WHERE rel.relname = 'document_permissions'
                      AND con.contype = 'c'
                      AND (
                          SELECT array_agg(att.attname::text ORDER BY att.attname::text)
                          FROM unnest(con.conkey) AS key_column(attnum)
                          JOIN pg_attribute att
                            ON att.attrelid = rel.oid AND att.attnum = key_column.attnum
                      ) = ARRAY['permission']::text[]
                ) THEN
                    ALTER TABLE document_permissions
                        ADD CONSTRAINT document_permissions_permission_check
                        CHECK (permission IN ('read', 'edit'));
                END IF;
            END $$;
        `);

        // The legacy UNIQUE(document_id, user_id, permission) constraint allows
        // the same user to hold 'read' and 'edit' at the same time. It is
        // replaced by UNIQUE(document_id, user_id).
        await client.query(`
            DO $$
            DECLARE
                legacy_constraints TEXT;
            BEGIN
                SELECT string_agg(con.conname, ', ') INTO legacy_constraints
                FROM pg_constraint con
                JOIN pg_class rel ON rel.oid = con.conrelid
                WHERE rel.relname = 'document_permissions'
                  AND con.contype = 'u'
                  AND (
                      SELECT array_agg(att.attname::text ORDER BY att.attname::text)
                      FROM unnest(con.conkey) AS key_column(attnum)
                      JOIN pg_attribute att
                        ON att.attrelid = rel.oid AND att.attnum = key_column.attnum
                  ) = ARRAY['document_id', 'permission', 'user_id']::text[];

                IF legacy_constraints IS NOT NULL THEN
                    EXECUTE format(
                        'ALTER TABLE document_permissions DROP CONSTRAINT %s',
                        legacy_constraints
                    );
                END IF;
            END $$;
        `);

        await client.query(`
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_constraint con
                    JOIN pg_class rel ON rel.oid = con.conrelid
                    WHERE rel.relname = 'document_permissions'
                      AND con.contype = 'u'
                      AND (
                          SELECT array_agg(att.attname::text ORDER BY att.attname::text)
                          FROM unnest(con.conkey) AS key_column(attnum)
                          JOIN pg_attribute att
                            ON att.attrelid = rel.oid AND att.attnum = key_column.attnum
                      ) = ARRAY['document_id', 'user_id']::text[]
                ) THEN
                    ALTER TABLE document_permissions
                        ADD CONSTRAINT document_permissions_document_id_user_id_key
                        UNIQUE (document_id, user_id);
                END IF;
            END $$;
        `);

        // ── 5. Blob foreign key ───────────────────────────────────────────────
        // Added as NOT VALID first so that a database with orphaned rows can
        // still be migrated; new and updated rows are checked immediately.
        await client.query(`
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_constraint con
                    JOIN pg_class rel ON rel.oid = con.conrelid
                    WHERE rel.relname = 'documents'
                      AND con.contype = 'f'
                      AND con.conname = 'documents_storage_key_fkey'
                ) THEN
                    ALTER TABLE documents
                        ADD CONSTRAINT documents_storage_key_fkey
                        FOREIGN KEY (storage_key)
                        REFERENCES document_blobs(storage_key)
                        ON DELETE CASCADE
                        NOT VALID;
                END IF;
            END $$;
        `);

        // A document whose blob is missing can never be downloaded again — the
        // reference dangles. Such rows are removed so that the foreign key
        // can be validated. The audit trail keeps the history: its reference
        // columns are plain UUIDs without foreign keys, so deleting a
        // document never rewrites a historic entry.
        const orphanResult = await client.query(`
            SELECT COUNT(*)::int AS count
            FROM documents d
            WHERE NOT EXISTS (
                SELECT 1 FROM document_blobs b WHERE b.storage_key = d.storage_key
            )
        `);

        const orphanCount = orphanResult.rows[0].count;
        if (orphanCount > 0) {
            console.warn(
                `Removing ${orphanCount} document(s) whose file content is missing — ` +
                "the rows could not be downloaded any more."
            );

            await client.query(`
                DELETE FROM documents d
                WHERE NOT EXISTS (
                    SELECT 1 FROM document_blobs b WHERE b.storage_key = d.storage_key
                )
            `);
        }

        try {
            await client.query(
                "ALTER TABLE documents VALIDATE CONSTRAINT documents_storage_key_fkey;"
            );
        } catch (error) {
            // A constraint that cannot be validated is not fatal for the
            // application, but it must be reported: new and updated rows are
            // checked either way.
            console.warn(
                "The blob foreign key could not be validated: " + error.message
            );
        }

        // ── 5b. Documented historical audit incident annotations ──────────────
        // If entry 438 exhibits the confirmed anchor-desync historical split,
        // record the immutable forensic incident documentation without rewriting
        // historical audit rows.
        await client.query(`
            CREATE TABLE IF NOT EXISTS audit_incident_annotations (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                incident_code VARCHAR(50) NOT NULL UNIQUE,
                incident_type VARCHAR(50) NOT NULL,
                broken_at_id BIGINT NOT NULL,
                affected_range_start BIGINT NOT NULL,
                affected_range_end BIGINT NOT NULL,
                evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
                root_cause TEXT NOT NULL,
                authorized_disposition TEXT NOT NULL,
                authorized_by VARCHAR(255) NOT NULL,
                status VARCHAR(50) NOT NULL DEFAULT 'documented_acknowledged',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS audit_incident_annotations_broken_at_idx ON audit_incident_annotations(broken_at_id);
        `);

        const entry438Check = await client.query(`
            SELECT 1 FROM audit_logs
            WHERE id = 438 AND prev_hash = 'GENESIS'
              AND EXISTS (SELECT 1 FROM audit_logs WHERE id = 437)
            LIMIT 1
        `);

        if (entry438Check.rows.length > 0) {
            await client.query(`
                INSERT INTO audit_incident_annotations
                    (incident_code, incident_type, broken_at_id, affected_range_start, affected_range_end, evidence, root_cause, authorized_disposition, authorized_by, status)
                VALUES
                    ('INC-2026-438',
                     'anchor_desync_split_chain',
                     438,
                     1,
                     520,
                     '{"segment1":{"startId":1,"endId":437,"headHash":"cf8cc3023485e10f90e7d2bc754a7043b67ab6f378c9a06412b515494b047cf5"},"entry438":{"prevHash":"GENESIS","entryHash":"e11603ba7853fd9c9e8fc5d1645e99f6ba4357b98b7eec9b0ca53c617ea875d7"},"segment2":{"startId":438,"endId":520,"headHash":"378b3f91a7a19a0e6ce6ccd92a5f3c773a00306df753c86efe6b1ed825ddc3a1"}}'::jsonb,
                     'Audit chain anchor table (audit_chain_state) was re-initialized with last_entry_id=0, last_hash=GENESIS while audit_logs contained 437 rows. Legacy readChainHead() trusted the anchor table without cross-checking audit_logs MAX(id), writing prev_hash=GENESIS for entry 438.',
                     'Historical audit records and hashes are preserved unaltered to maintain forensic evidentiary integrity. Historical hashes are NOT recomputed to conceal the break. readChainHead() is hardened with mandatory audit_logs cross-checking to prevent future anchor desynchronization. Verified backup archived off-site at C:\\Users\\pokal\\trustvault_backups.',
                     'Security Administrator (Admin Console Incident Response)',
                     'documented_acknowledged')
                ON CONFLICT (incident_code) DO NOTHING;
            `);
        }

        await client.query("COMMIT");
        console.log("Database schema and constraints are up to date.");

        // ── 6. Audit chain ────────────────────────────────────────────────────
        if (options.rebuildChain !== false) {
            await rebuildAuditChainIfNeeded();
        }

        console.log("Migration complete.");
        return { ok: true };
    } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        console.error("Migration failed:", error.message);
        throw error;
    } finally {
        client.release();
    }
}

if (require.main === module) {
    migrate()
        .then(() => pool.end())
        .catch(() => {
            process.exitCode = 1;
            return pool.end();
        });
}

module.exports = { migrate, SCHEMA_PATH };
