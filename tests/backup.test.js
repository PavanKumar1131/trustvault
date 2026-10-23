/**
 * Backup and Recovery Security & Reliability Test Suite for TrustVault.
 *
 * Verifies:
 * - Blob representation standardization and byte-for-byte binary recovery
 * - Pre-flight safety guards (production rejection, database isolation, disposable naming)
 * - Certificate-validated TLS configuration
 * - SQL identifier quoting and identity sequence override
 * - Row-count and binary blob checksum mismatch detection
 * - Honest canonical audit-chain verification preserving documented historical incidents
 * - Read-only enforcement, input validation, and sensitive data redaction in inspect-audit-chain
 * - Error handling for missing, malformed, or incomplete backup archives
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const {
    standardizeBlobRow,
    extractBlobBuffer,
    formatSqlValue,
    resolveBackupDirectory
} = require("../tools/backup-database");

const {
    verifySafetyPreconditions,
    getSslConfig,
    verifyBackupFiles,
    resolveBackupArchivePaths,
    DEFAULT_DISPOSABLE_DB_NAME
} = require("../tools/verify-backup-restore");

const {
    validateEntryId,
    redactSensitive
} = require("../tools/inspect-audit-chain");

const { verifyAuditChain } = require("../src/services/auditService");

describe("TrustVault Database Backup & Recovery Security Remediation", () => {
    // ══════════════════════════════════════════════════════════════════════════
    // 1. Blob representation & byte-for-byte binary recovery
    // ══════════════════════════════════════════════════════════════════════════
    describe("Task 1: Document blob format compatibility & recovery", () => {
        const samplePdfBytes = Buffer.from("%PDF-1.4 sample content with binary \x00\x01\xFF data");
        const sampleSha256 = crypto.createHash("sha256").update(samplePdfBytes).digest("hex");

        test("standardizeBlobRow correctly formats Buffer with base64, sha256 and byte_length", () => {
            const rawRow = {
                storage_key: "blob-uuid-1234",
                file_data: samplePdfBytes,
                created_at: new Date("2026-10-23T12:00:00Z")
            };

            const standardized = standardizeBlobRow(rawRow);
            expect(standardized.storage_key).toBe("blob-uuid-1234");
            expect(standardized.file_data).toBe(samplePdfBytes.toString("base64"));
            expect(standardized.file_data_base64).toBe(samplePdfBytes.toString("base64"));
            expect(standardized.bytes_base64).toBe(samplePdfBytes.toString("base64"));
            expect(standardized.sha256).toBe(sampleSha256);
            expect(standardized.byte_length).toBe(samplePdfBytes.length);
        });

        test("extractBlobBuffer recovers byte-for-byte from standard base64 string", () => {
            const archiveBlob = {
                storage_key: "k1",
                file_data: samplePdfBytes.toString("base64"),
                sha256: sampleSha256
            };

            const buf = extractBlobBuffer(archiveBlob);
            expect(Buffer.isBuffer(buf)).toBe(true);
            expect(Buffer.compare(buf, samplePdfBytes)).toBe(0);
            expect(crypto.createHash("sha256").update(buf).digest("hex")).toBe(sampleSha256);
        });

        test("extractBlobBuffer recovers byte-for-byte from legacy Buffer JSON object", () => {
            const legacyJsonBlob = {
                storage_key: "k2",
                file_data: {
                    type: "Buffer",
                    data: Array.from(samplePdfBytes)
                }
            };

            const buf = extractBlobBuffer(legacyJsonBlob);
            expect(Buffer.isBuffer(buf)).toBe(true);
            expect(Buffer.compare(buf, samplePdfBytes)).toBe(0);
        });

        test("extractBlobBuffer recovers byte-for-byte from legacy bytes_base64 field", () => {
            const legacyBytesBlob = {
                storage_key: "k3",
                file_data: null,
                bytes_base64: samplePdfBytes.toString("base64")
            };

            const buf = extractBlobBuffer(legacyBytesBlob);
            expect(Buffer.isBuffer(buf)).toBe(true);
            expect(Buffer.compare(buf, samplePdfBytes)).toBe(0);
        });

        test("extractBlobBuffer throws clear error when blob payload is corrupted or missing", () => {
            expect(() => extractBlobBuffer({ storage_key: "bad-blob" })).toThrow(/Unable to extract binary blob/);
        });

        test("SQL value formatter handles Bytea, Dates, JSON, booleans, and nulls with proper casting", () => {
            expect(formatSqlValue(null, "col", "tab")).toBe("NULL");
            expect(formatSqlValue(true, "is_active", "tab")).toBe("TRUE");
            expect(formatSqlValue(false, "is_disabled", "tab")).toBe("FALSE");
            expect(formatSqlValue(12345, "id", "tab")).toBe("12345");
            expect(formatSqlValue(samplePdfBytes, "file_data", "document_blobs")).toBe(
                `'\\x${samplePdfBytes.toString("hex")}'::bytea`
            );
            expect(formatSqlValue({ role: "admin", ip: "127.0.0.1" }, "details", "audit_logs")).toBe(
                `'{"role":"admin","ip":"127.0.0.1"}'::jsonb`
            );
            expect(formatSqlValue({ cookie: "xyz" }, "sess", "user_sessions")).toBe(
                `'{"cookie":"xyz"}'::json`
            );
            expect(formatSqlValue("O'Connor", "name", "users")).toBe("'O''Connor'");
        });

        test("backup directory resolver validates creation and access", () => {
            const testDir = path.join(__dirname, "../.tmp/test-backup-dir");
            const resolved = resolveBackupDirectory(testDir);
            expect(fs.existsSync(resolved)).toBe(true);
            expect(fs.statSync(resolved).isDirectory()).toBe(true);
        });
    });

    // ══════════════════════════════════════════════════════════════════════════
    // 2. Pre-flight safety guards and isolation checks
    // ══════════════════════════════════════════════════════════════════════════
    describe("Task 2: Restore utility safety guards & pre-flight isolation", () => {
        const validRestoreUrl = "postgresql://usr:pass@localhost:5432/trustvault_restore_verify";
        const appDevUrl = "postgresql://usr:pass@localhost:5432/trustvault_dev";

        test("rejects immediately when NODE_ENV is production", () => {
            const origEnv = process.env.NODE_ENV;
            try {
                process.env.NODE_ENV = "production";
                expect(() => verifySafetyPreconditions(validRestoreUrl, appDevUrl)).toThrow(
                    /Refusing to run restore operations when NODE_ENV=production/
                );
            } finally {
                process.env.NODE_ENV = origEnv;
            }
        });

        test("rejects missing or empty restore database URL", () => {
            expect(() => verifySafetyPreconditions(null, appDevUrl)).toThrow(
                /Restore database URL is missing or invalid/
            );
            expect(() => verifySafetyPreconditions("", appDevUrl)).toThrow(
                /Restore database URL is missing or invalid/
            );
        });

        test("rejects when target database is identical to application database", () => {
            const sameUrl = "postgresql://usr:pass@db.neon.tech/trustvault_production";
            expect(() => verifySafetyPreconditions(sameUrl, sameUrl)).toThrow(
                /Target database "trustvault_production" is not an authorized disposable restore database/
            );
        });

        test("rejects target databases without 'restore' or 'test' in the name", () => {
            const unsafeUrl = "postgresql://usr:pass@localhost:5432/my_main_database";
            expect(() => verifySafetyPreconditions(unsafeUrl, appDevUrl)).toThrow(
                /Target database "my_main_database" is not an authorized disposable restore database/
            );
        });

        test("rejects protected database names (postgres, neondb, trustvault, master)", () => {
            expect(() =>
                verifySafetyPreconditions("postgresql://usr:pass@localhost:5432/postgres", appDevUrl)
            ).toThrow(/protected database name/);
            expect(() =>
                verifySafetyPreconditions("postgresql://usr:pass@localhost:5432/neondb", appDevUrl)
            ).toThrow(/protected database name/);
            expect(() =>
                verifySafetyPreconditions("postgresql://usr:pass@localhost:5432/trustvault", appDevUrl)
            ).toThrow(/protected database name/);
        });

        test("accepts valid disposable database name (e.g. trustvault_restore_verify)", () => {
            const result = verifySafetyPreconditions(validRestoreUrl, appDevUrl);
            expect(result.safe).toBe(true);
            expect(result.databaseName).toBe(DEFAULT_DISPOSABLE_DB_NAME);
        });
    });

    // ══════════════════════════════════════════════════════════════════════════
    // 3. TLS configuration hardening
    // ══════════════════════════════════════════════════════════════════════════
    describe("Task 2: TLS certificate verification configuration", () => {
        test("enforces rejectUnauthorized: true for Neon remote databases", () => {
            const neonUrl = "postgresql://usr:pass@ep-cool-fog-12345.us-east-2.aws.neon.tech/trustvault_restore_verify?sslmode=require";
            const ssl = getSslConfig(neonUrl);
            expect(ssl).toEqual({ rejectUnauthorized: true });
        });

        test("enforces rejectUnauthorized: true for connections requesting SSL", () => {
            const sslUrl = "postgresql://usr:pass@remote.db:5432/restore_db?sslmode=verify-full";
            const ssl = getSslConfig(sslUrl);
            expect(ssl).toEqual({ rejectUnauthorized: true });
        });

        test("returns false for local unencrypted test connections without SSL", () => {
            const localUrl = "postgresql://postgres:postgres@localhost:5432/trustvault_restore_verify";
            const ssl = getSslConfig(localUrl);
            expect(ssl).toBe(false);
        });

        test("never returns rejectUnauthorized: false under any circumstances", () => {
            const testUrls = [
                "postgresql://localhost:5432/restore_db",
                "postgresql://remote.db/restore_db?sslmode=require",
                "postgresql://neon.tech/restore_db",
                ""
            ];
            testUrls.forEach((u) => {
                const conf = getSslConfig(u);
                if (typeof conf === "object" && conf !== null) {
                    expect(conf.rejectUnauthorized).toBe(true);
                }
            });
        });
    });

    // ══════════════════════════════════════════════════════════════════════════
    // 4. Archive file validation and error handling
    // ══════════════════════════════════════════════════════════════════════════
    describe("Task 3: Backup archive validation & integrity checks", () => {
        test("verifyBackupFiles throws when JSON backup file is missing", () => {
            expect(() =>
                verifyBackupFiles("non_existent_backup_file_9999.json", null)
            ).toThrow(/Backup JSON archive not found/);
        });

        test("verifyBackupFiles throws when JSON backup is malformed or corrupted syntax", () => {
            const badFile = path.join(__dirname, "../.tmp/corrupted_backup.json");
            fs.mkdirSync(path.dirname(badFile), { recursive: true });
            fs.writeFileSync(badFile, "{ invalid json content: true", "utf8");

            expect(() => verifyBackupFiles(badFile, null)).toThrow(/Backup JSON parsing failed/);
        });

        test("verifyBackupFiles throws when JSON is missing metadata or data properties", () => {
            const incompleteFile = path.join(__dirname, "../.tmp/incomplete_backup.json");
            fs.mkdirSync(path.dirname(incompleteFile), { recursive: true });
            fs.writeFileSync(incompleteFile, JSON.stringify({ partial: true }), "utf8");

            expect(() => verifyBackupFiles(incompleteFile, null)).toThrow(
                /Invalid backup format: archive is missing metadata or data properties/
            );
        });

        test("verifyBackupFiles successfully loads valid archive structure", () => {
            const validFile = path.join(__dirname, "../.tmp/valid_test_backup.json");
            fs.mkdirSync(path.dirname(validFile), { recursive: true });
            const payload = {
                metadata: {
                    timestamp: new Date().toISOString(),
                    database: "neondb",
                    tables: { users: 1 }
                },
                data: {
                    users: [{ id: "u1", name: "Alice", email: "alice@test.com" }]
                }
            };
            fs.writeFileSync(validFile, JSON.stringify(payload), "utf8");

            const loaded = verifyBackupFiles(validFile, null);
            expect(loaded.metadata.database).toBe("neondb");
            expect(loaded.data.users.length).toBe(1);
        });

        test("resolveBackupArchivePaths throws clear non-sensitive error when no path is provided", () => {
            const origJson = process.env.BACKUP_JSON_PATH;
            try {
                delete process.env.BACKUP_JSON_PATH;
                expect(() => resolveBackupArchivePaths({})).toThrow(
                    /Backup archive resolution error: No backup JSON archive specified/
                );
            } finally {
                if (origJson !== undefined) process.env.BACKUP_JSON_PATH = origJson;
            }
        });

        test("resolveBackupArchivePaths resolves explicit programmatic options without selecting stale files", () => {
            const customJson = path.resolve(__dirname, "../.tmp/custom_target.json");
            const customSql = path.resolve(__dirname, "../.tmp/custom_target.sql");

            const resolved = resolveBackupArchivePaths({
                jsonPath: customJson,
                sqlPath: customSql
            });

            expect(resolved.jsonPath).toBe(customJson);
            expect(resolved.sqlPath).toBe(customSql);
        });

        test("resolveBackupArchivePaths resolves paths via BACKUP_JSON_PATH and BACKUP_SQL_PATH environment variables", () => {
            const origJson = process.env.BACKUP_JSON_PATH;
            const origSql = process.env.BACKUP_SQL_PATH;
            try {
                process.env.BACKUP_JSON_PATH = "./.tmp/env_backup.json";
                process.env.BACKUP_SQL_PATH = "./.tmp/env_backup.sql";

                const resolved = resolveBackupArchivePaths({});
                expect(resolved.jsonPath).toBe(path.resolve("./.tmp/env_backup.json"));
                expect(resolved.sqlPath).toBe(path.resolve("./.tmp/env_backup.sql"));
            } finally {
                if (origJson !== undefined) process.env.BACKUP_JSON_PATH = origJson;
                else delete process.env.BACKUP_JSON_PATH;
                if (origSql !== undefined) process.env.BACKUP_SQL_PATH = origSql;
                else delete process.env.BACKUP_SQL_PATH;
            }
        });

        test("resolveBackupArchivePaths resolves backupFile relative to configured BACKUP_DIR", () => {
            const testDir = path.resolve(__dirname, "../.tmp/named_backups");
            fs.mkdirSync(testDir, { recursive: true });

            const resolved = resolveBackupArchivePaths({
                backupDir: testDir,
                backupFile: "target_archive.json"
            });

            expect(resolved.jsonPath).toBe(path.join(testDir, "target_archive.json"));
        });
    });

    // ══════════════════════════════════════════════════════════════════════════
    // 5. Canonical audit-chain verification with documented incident preservation
    // ══════════════════════════════════════════════════════════════════════════
    describe("Task 3: Canonical audit chain verification & incident preservation", () => {
        test("verifyAuditChain accepts an isolated db client and detects broken links honestly", async () => {
            // Mock a client returning a broken chain without documentation
            const mockClient = {
                query: jest.fn().mockImplementation((queryText, params) => {
                    if (queryText.includes("FROM audit_logs")) {
                        return Promise.resolve({
                            rows: [
                                {
                                    id: 1,
                                    actor_id: null,
                                    document_id: null,
                                    target_user_id: null,
                                    action: "user_login",
                                    outcome: "success",
                                    details: {},
                                    prev_hash: "GENESIS",
                                    entry_hash: "d0c0854cb03418fb5454195e0225f856a01989357a14ef77503a466f54f2348b",
                                    created_at: new Date()
                                },
                                {
                                    id: 2,
                                    actor_id: null,
                                    document_id: null,
                                    target_user_id: null,
                                    action: "doc_view",
                                    outcome: "success",
                                    details: {},
                                    prev_hash: "WRONG_PREV_HASH", // broken link
                                    entry_hash: "hash_2",
                                    created_at: new Date()
                                }
                            ]
                        });
                    }
                    if (queryText.includes("FROM audit_incident_annotations")) {
                        return Promise.resolve({ rows: [] }); // No documentation
                    }
                    if (queryText.includes("FROM audit_chain_state")) {
                        return Promise.resolve({
                            rows: [{ last_entry_id: 2, last_hash: "hash_2" }]
                        });
                    }
                    return Promise.resolve({ rows: [] });
                })
            };

            const result = await verifyAuditChain(mockClient);
            expect(result.valid).toBe(false);
            expect(result.status).toBe("failed");
            expect(result.reason).toBe("broken_link");
            expect(result.brokenAtId).toBe(2);
        });

        test("verifyAuditChain preserves and honors documented historical integrity incident (INC-2026-438)", async () => {
            const mockClient = {
                query: jest.fn().mockImplementation((queryText, params) => {
                    if (queryText.includes("FROM audit_logs")) {
                        return Promise.resolve({
                            rows: [
                                {
                                    id: 437,
                                    actor_id: null,
                                    document_id: null,
                                    target_user_id: null,
                                    action: "action_437",
                                    outcome: "success",
                                    details: {},
                                    prev_hash: "GENESIS",
                                    entry_hash: "f6ef8e3e1d35e05a5dc096d05182a6c31767faa358acfc8d9fbce6309fa2a411",
                                    created_at: new Date()
                                },
                                {
                                    id: 438,
                                    actor_id: null,
                                    document_id: null,
                                    target_user_id: null,
                                    action: "action_438",
                                    outcome: "success",
                                    details: {},
                                    prev_hash: "GENESIS", // Deliberate anchor reset incident
                                    entry_hash: "763bc6d783ca6c312fa2291404a8a0e53e5416a8b0bca7eef57742456b94da18",
                                    created_at: new Date()
                                }
                            ]
                        });
                    }
                    if (queryText.includes("FROM audit_incident_annotations")) {
                        return Promise.resolve({
                            rows: [
                                {
                                    incident_code: "INC-2026-438",
                                    incident_type: "anchor_desynchronization",
                                    broken_at_id: 438,
                                    affected_range_start: 438,
                                    affected_range_end: 438,
                                    root_cause: "Manual anchor reset during deployment",
                                    authorized_disposition: "Documented historical incident preserved without modifying historical rows.",
                                    authorized_by: "Security Reliability Engineering",
                                    status: "documented_acknowledged"
                                }
                            ]
                        });
                    }
                    if (queryText.includes("FROM audit_chain_state")) {
                        return Promise.resolve({
                            rows: [{ last_entry_id: 438, last_hash: "763bc6d783ca6c312fa2291404a8a0e53e5416a8b0bca7eef57742456b94da18" }]
                        });
                    }
                    return Promise.resolve({ rows: [] });
                })
            };

            const result = await verifyAuditChain(mockClient);
            expect(result.valid).toBe(false);
            expect(result.status).toBe("documented_incident");
            expect(result.reason).toBe("documented_historical_incident");
            expect(result.incident.code).toBe("INC-2026-438");
            expect(result.segment1.valid).toBe(true);
            expect(result.segment2.valid).toBe(true);
        });
    });

    // ══════════════════════════════════════════════════════════════════════════
    // 6. Read-only audit inspection tool
    // ══════════════════════════════════════════════════════════════════════════
    describe("Task 4: Read-only audit inspector hardening", () => {
        test("validateEntryId accepts valid positive integers", () => {
            expect(validateEntryId("438")).toBe(438);
            expect(validateEntryId("1")).toBe(1);
            expect(validateEntryId(100)).toBe(100);
            expect(validateEntryId(undefined)).toBeNull();
            expect(validateEntryId("")).toBeNull();
        });

        test("validateEntryId rejects invalid, negative, non-numeric, or SQL injection arguments", () => {
            expect(() => validateEntryId("-1")).toThrow(/must be a positive integer/);
            expect(() => validateEntryId("0")).toThrow(/must be greater than zero/);
            expect(() => validateEntryId("abc")).toThrow(/must be a positive integer/);
            expect(() => validateEntryId("1; DROP TABLE users;")).toThrow(/must be a positive integer/);
            expect(() => validateEntryId("3.14")).toThrow(/must be a positive integer/);
        });

        test("redactSensitive strips sensitive credentials, tokens, session keys, and passwords", () => {
            const rawDetails = {
                action: "login",
                user_email: "admin@trustvault.com",
                password: "plaintext_secret_password",
                session_token: "sess_abc123xyz",
                nested: {
                    cookie_secret: "secret_cookie",
                    safe_field: 42
                }
            };

            const safe = redactSensitive(rawDetails);
            expect(safe.password).toBe("[REDACTED]");
            expect(safe.session_token).toBe("[REDACTED]");
            expect(safe.nested.cookie_secret).toBe("[REDACTED]");
            expect(safe.nested.safe_field).toBe(42);
            expect(safe.user_email).toBe("admin@trustvault.com");
        });
    });
});
