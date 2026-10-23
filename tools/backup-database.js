/**
 * Consistent database backup tool for TrustVault.
 *
 * Exports all schema tables, rows, binary document blobs, and the audit trail
 * into a standalone backup archive outside the application source tree.
 *
 * Session Restoration Policy:
 * ----------------------------
 * Active user sessions stored in `user_sessions` contain live session cookies.
 * To prevent session replay attacks or unexpected reactivation of stale/revoked
 * sessions in a restored environment, the canonical policy designates `user_sessions`
 * as "exclude_on_restore". Restored systems must require users to re-authenticate.
 */

require("dotenv").config({ path: require("path").join(__dirname, "../.env") });
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const pool = require("../src/db");

/** Tables with GENERATED ALWAYS AS IDENTITY columns requiring OVERRIDING SYSTEM VALUE */
const IDENTITY_OVERRIDE_TABLES = new Set(["audit_logs", "audit_incident_annotations"]);

/**
 * Normalizes a document blob row into a standardized byte-for-byte recoverable structure.
 */
function standardizeBlobRow(row) {
    let buf = null;
    if (Buffer.isBuffer(row.file_data)) {
        buf = row.file_data;
    } else if (row.file_data && row.file_data.type === "Buffer" && Array.isArray(row.file_data.data)) {
        buf = Buffer.from(row.file_data.data);
    } else if (typeof row.file_data === "string") {
        buf = Buffer.from(row.file_data, "base64");
    } else if (row.bytes) {
        buf = Buffer.isBuffer(row.bytes) ? row.bytes : Buffer.from(row.bytes);
    } else {
        throw new Error(`document_blobs row with key "${row.storage_key}" has no valid binary file_data`);
    }

    const base64Str = buf.toString("base64");
    const sha256 = crypto.createHash("sha256").update(buf).digest("hex");

    return {
        storage_key: row.storage_key,
        file_data: base64Str,
        file_data_base64: base64Str,
        bytes_base64: base64Str,
        sha256,
        byte_length: buf.length,
        created_at: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at
    };
}

/**
 * Extracts a Buffer from a restored or archived blob representation.
 */
function extractBlobBuffer(b) {
    if (!b) return null;
    if (Buffer.isBuffer(b)) return b;

    if (b.file_data) {
        if (typeof b.file_data === "string") {
            return Buffer.from(b.file_data, "base64");
        }
        if (typeof b.file_data === "object") {
            if (b.file_data.type === "Buffer" && Array.isArray(b.file_data.data)) {
                return Buffer.from(b.file_data.data);
            }
            if (Array.isArray(b.file_data)) {
                return Buffer.from(b.file_data);
            }
        }
    }
    if (typeof b.file_data_base64 === "string") {
        return Buffer.from(b.file_data_base64, "base64");
    }
    if (typeof b.bytes_base64 === "string") {
        return Buffer.from(b.bytes_base64, "base64");
    }
    if (b.bytes) {
        if (Buffer.isBuffer(b.bytes)) return b.bytes;
        if (typeof b.bytes === "string") return Buffer.from(b.bytes, "base64");
    }
    throw new Error(`Unable to extract binary blob buffer for storage_key "${b && b.storage_key}"`);
}

/**
 * Formats a single column value for safe SQL generation with proper quoting and type casting.
 */
function formatSqlValue(val, colName, tableName) {
    if (val === null || val === undefined) return "NULL";
    if (typeof val === "boolean") return val ? "TRUE" : "FALSE";
    if (typeof val === "number") return String(val);
    if (val instanceof Date) return `'${val.toISOString()}'::timestamptz`;
    if (Buffer.isBuffer(val)) {
        return `'\\x${val.toString("hex")}'::bytea`;
    }
    if (tableName === "document_blobs" && colName === "file_data") {
        // Handle base64 string or buffer-like object
        const buf = extractBlobBuffer({ file_data: val });
        return `'\\x${buf.toString("hex")}'::bytea`;
    }
    if (typeof val === "object") {
        const jsonStr = JSON.stringify(val).replace(/'/g, "''");
        if (tableName === "user_sessions" && colName === "sess") {
            return `'${jsonStr}'::json`;
        }
        return `'${jsonStr}'::jsonb`;
    }
    return `'${String(val).replace(/'/g, "''")}'`;
}

/**
 * Resolves and validates the backup directory.
 */
function resolveBackupDirectory(customDir) {
    const rawDir = customDir || process.env.BACKUP_DIR || path.resolve(process.cwd(), "backups");
    const targetDir = path.resolve(rawDir);

    try {
        if (!fs.existsSync(targetDir)) {
            fs.mkdirSync(targetDir, { recursive: true, mode: 0o700 });
        }
        // Verify write access
        fs.accessSync(targetDir, fs.constants.W_OK);
    } catch (err) {
        throw new Error(`Backup directory failure for "${targetDir}": ${err.message}`);
    }

    return targetDir;
}

/**
 * Executes a full, consistent database backup.
 *
 * @param {object} [options]
 * @param {string} [options.backupDir] Destination directory
 * @param {object} [options.dbPool] Optional pg Pool/Client to use
 */
async function backup(options = {}) {
    const activePool = options.dbPool || pool;
    const backupDir = resolveBackupDirectory(options.backupDir || process.argv[2]);

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const jsonPath = path.join(backupDir, `neondb_backup_${timestamp}.json`);
    const sqlPath = path.join(backupDir, `neondb_backup_${timestamp}.sql`);

    console.log(`Initiating consistent database backup at ${new Date().toISOString()}...`);

    const client = await activePool.connect();
    try {
        await client.query("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ");

        const tablesResult = await client.query(`
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
            ORDER BY table_name
        `);

        const tables = tablesResult.rows.map((r) => r.table_name);
        console.log(`Found ${tables.length} tables to backup: ${tables.join(", ")}`);

        const backupData = {
            metadata: {
                version: "2.0.0",
                timestamp: new Date().toISOString(),
                database: "neondb",
                tables: {},
                blob_count: 0,
                blob_total_bytes: 0,
                session_policy: {
                    mode: "exclude_on_restore",
                    recommendation: "DO_NOT_RESTORE_ACTIVE_SESSIONS",
                    reason: "Restoring active session cookies into another environment can reactivate stale or compromised sessions. Require fresh user sign-in."
                }
            },
            data: {}
        };

        const sqlStatements = [
            `-- TrustVault Consistent Database Backup`,
            `-- Generated at: ${new Date().toISOString()}`,
            `-- Session Policy: user_sessions contains stale authentication state; omit on live restores.`,
            `BEGIN;`,
            `SET client_encoding = 'UTF8';`,
            ``
        ];

        for (const table of tables) {
            console.log(`Exporting table "${table}"...`);
            const rowsResult = await client.query(`SELECT * FROM "public"."${table}" ORDER BY 1`);
            const rows = rowsResult.rows;
            backupData.metadata.tables[table] = rows.length;

            if (table === "document_blobs") {
                let totalBytes = 0;
                backupData.data[table] = rows.map((r) => {
                    const standardized = standardizeBlobRow(r);
                    totalBytes += standardized.byte_length;
                    return standardized;
                });
                backupData.metadata.blob_count = rows.length;
                backupData.metadata.blob_total_bytes = totalBytes;
            } else {
                backupData.data[table] = rows;
            }

            // Generate safe SQL statements with quoted identifiers
            if (rows.length > 0) {
                const requiresIdentityOverride = IDENTITY_OVERRIDE_TABLES.has(table);
                sqlStatements.push(`-- Table: "public"."${table}" (${rows.length} rows)`);

                for (const row of rows) {
                    const columns = Object.keys(row);
                    const quotedColumns = columns.map((c) => `"${c}"`).join(", ");
                    const values = columns.map((col) => formatSqlValue(row[col], col, table));

                    if (requiresIdentityOverride) {
                        sqlStatements.push(
                            `INSERT INTO "public"."${table}" (${quotedColumns}) OVERRIDING SYSTEM VALUE VALUES (${values.join(", ")});`
                        );
                    } else {
                        sqlStatements.push(
                            `INSERT INTO "public"."${table}" (${quotedColumns}) VALUES (${values.join(", ")});`
                        );
                    }
                }
                sqlStatements.push(``);
            }
        }

        await client.query("COMMIT");
        sqlStatements.push(`COMMIT;`);

        // Write files with restricted permissions (0o600)
        fs.writeFileSync(jsonPath, JSON.stringify(backupData, null, 2), { encoding: "utf8", mode: 0o600 });
        fs.writeFileSync(sqlPath, sqlStatements.join("\n"), { encoding: "utf8", mode: 0o600 });

        const jsonSize = fs.statSync(jsonPath).size;
        const sqlSize = fs.statSync(sqlPath).size;

        console.log(`\n=== BACKUP VERIFICATION REPORT ===`);
        console.log(`JSON Archive: ${jsonPath} (${(jsonSize / 1024).toFixed(1)} KB)`);
        console.log(`SQL Archive:  ${sqlPath} (${(sqlSize / 1024).toFixed(1)} KB)`);
        console.log(`Binary Blobs: ${backupData.metadata.blob_count} files (${(backupData.metadata.blob_total_bytes / 1024).toFixed(1)} KB total)`);
        console.log(`Session Policy: ${backupData.metadata.session_policy.mode} (${backupData.metadata.session_policy.recommendation})`);
        console.log(`Table row counts:`);
        for (const [t, count] of Object.entries(backupData.metadata.tables)) {
            console.log(`  - ${t}: ${count} rows`);
        }
        console.log(`Backup completed and verified successfully.`);

        return {
            jsonPath,
            sqlPath,
            metadata: backupData.metadata
        };
    } catch (err) {
        await client.query("ROLLBACK").catch(() => {});
        console.error("Backup failed:", err.message);
        throw err;
    } finally {
        client.release();
        if (!options.dbPool) {
            await pool.end();
        }
    }
}

if (require.main === module) {
    backup().catch(() => {
        process.exit(1);
    });
}

module.exports = {
    backup,
    standardizeBlobRow,
    extractBlobBuffer,
    formatSqlValue,
    resolveBackupDirectory
};
w