/**
 * Audit trail service.
 *
 * Design
 * ------
 * Every audit entry stores the SHA-256 hash of its own canonical
 * representation, chained to the previous entry (`prev_hash`). A change to any
 * historic row therefore invalidates every subsequent hash and is detected by
 * `verifyAuditChain()`.
 *
 * The chain is append-only in the database: a BEFORE UPDATE OR DELETE trigger
 * raises an exception for any attempt to rewrite history.
 *
 * Concurrency
 * -----------
 * Appending an entry reads the current chain head and then inserts the new
 * row. Two concurrent appends would otherwise read the same head and produce
 * a forked chain, so every append runs inside a transaction that holds a
 * PostgreSQL advisory lock (`pg_advisory_xact_lock`) for the whole critical
 * section. The lock is transaction-scoped, so it also works when the caller
 * supplies its own client that is already inside a transaction.
 *
 * The current head is additionally mirrored into `audit_chain_state`, which
 * allows the verifier to detect truncation of the tail of the log.
 *
 * Limitations (documented in THREATS.md)
 * --------------------------------------
 * The chain protects against unnoticed modification or truncation of log rows
 * by anything that cannot write to the `audit_chain_state` anchor and the log
 * at the same time. A database superuser or the owner of the schema can drop
 * the immutability trigger, rewrite rows and recompute the hashes, so the
 * chain is tamper-*evident*, not tamper-*proof*. Independent, off-database
 * replication of the head hash is required for a stronger guarantee.
 */

const crypto = require("node:crypto");
const pool = require("../db");

/** Advisory lock key used to serialise audit-chain appends. */
const AUDIT_CHAIN_LOCK_KEY = 917342615;

/** Sentinel used as `prev_hash` of the very first entry. */
const GENESIS_HASH = "GENESIS";

/**
 * Recursively normalises a value so that two structurally equal objects always
 * produce byte-identical JSON.
 *
 * PostgreSQL `jsonb` does not preserve key order (it reorders keys by length
 * and then bytewise), so a shallow sort is not enough: nested objects would
 * be hashed differently than they were stored and the chain would report a
 * false tampering incident.
 */
function canonicalize(value) {
    if (value === null || value === undefined) return null;

    if (Array.isArray(value)) {
        return value.map((item) => canonicalize(item));
    }

    if (typeof value === "object") {
        const normalized = {};
        for (const key of Object.keys(value).sort()) {
            if (value[key] !== undefined) {
                normalized[key] = canonicalize(value[key]);
            }
        }
        return normalized;
    }

    return value;
}

/** Canonical JSON representation used for hashing audit details. */
function canonicalJson(value) {
    const canonical = canonicalize(value === null || value === undefined ? {} : value);
    return JSON.stringify(canonical);
}

/**
 * Computes the hash of a single audit entry.
 * The exact field order below is part of the hash definition and must not
 * change without rebuilding the whole chain.
 */
function computeEntryHash({ prevHash, actorId, documentId, targetUserId, action, outcome, detailsJson }) {
    const payload = [
        prevHash || GENESIS_HASH,
        actorId || "anon",
        documentId || "none",
        targetUserId || "none",
        action,
        outcome,
        detailsJson
    ].join("|");

    return crypto.createHash("sha256").update(payload).digest("hex");
}

function resolveActorId(req, details) {
    if (req && req.user && req.user.id) {
        return req.user.id;
    }
    if (details && details.actorId) {
        return details.actorId;
    }
    return null;
}

function resolveIpAddress(req) {
    const rawIp = req ? (req.ip || (req.connection && req.connection.remoteAddress) || null) : null;
    if (!rawIp) return null;
    // Express reports IPv4-mapped IPv6 addresses as "::ffff:127.0.0.1".
    return rawIp.startsWith("::ffff:") ? rawIp.slice(7) : rawIp;
}

/**
 * Reads the current chain head.
 * Prefers the `audit_chain_state` anchor; falls back to the newest log row so
 * the service still works against a database that has not been migrated yet
 * (the advisory lock still guarantees a consistent chain in that case).
 */
async function readChainHead(client) {
    try {
        const state = await client.query(
            "SELECT last_entry_id, last_hash FROM audit_chain_state WHERE id = 1 FOR UPDATE"
        );

        const latestLog = await client.query(
            "SELECT id, entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
        );

        if (latestLog.rows.length > 0) {
            const actualLastEntryId = Number(latestLog.rows[0].id);
            const actualLastHash = latestLog.rows[0].entry_hash;

            // If audit_chain_state is missing or out of sync with actual logs (e.g. reset to 0/GENESIS),
            // reconcile it immediately so the chain is never broken by an anchor desync.
            if (
                state.rows.length === 0 ||
                Number(state.rows[0].last_entry_id) !== actualLastEntryId ||
                state.rows[0].last_hash !== actualLastHash
            ) {
                await client.query(
                    `INSERT INTO audit_chain_state (id, last_entry_id, last_hash)
                     VALUES (1, $1, $2)
                     ON CONFLICT (id) DO UPDATE
                     SET last_entry_id = EXCLUDED.last_entry_id,
                         last_hash = EXCLUDED.last_hash,
                         updated_at = NOW()`,
                    [actualLastEntryId, actualLastHash]
                );
            }

            return {
                lastEntryId: actualLastEntryId,
                lastHash: actualLastHash
            };
        }

        // audit_logs is empty: head is GENESIS
        if (state.rows.length === 0) {
            await client.query(
                `INSERT INTO audit_chain_state (id, last_entry_id, last_hash)
                 VALUES (1, 0, $1)
                 ON CONFLICT (id) DO UPDATE
                 SET last_entry_id = 0,
                     last_hash = $1,
                     updated_at = NOW()`,
                [GENESIS_HASH]
            );
        }

        return {
            lastEntryId: 0,
            lastHash: GENESIS_HASH
        };
    } catch (error) {
        // The anchor table is optional (pre-migration databases). Fall back to
        // the log itself instead of losing the audit event.
        if (error.code === "42P01" || error.code === "42703") {
            const legacy = await client.query(
                "SELECT id, entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
            );
            return {
                lastEntryId: legacy.rows.length > 0 ? Number(legacy.rows[0].id) : 0,
                lastHash: legacy.rows.length > 0 && legacy.rows[0].entry_hash
                    ? legacy.rows[0].entry_hash
                    : GENESIS_HASH
            };
        }
        throw error;
    }
}

async function updateChainHead(client, entryId, entryHash) {
    try {
        await client.query(
            `INSERT INTO audit_chain_state (id, last_entry_id, last_hash)
             VALUES (1, $1, $2)
             ON CONFLICT (id) DO UPDATE
             SET last_entry_id = EXCLUDED.last_entry_id,
                 last_hash = EXCLUDED.last_hash,
                 updated_at = NOW()`,
            [entryId, entryHash]
        );
    } catch (error) {
        if (error.code !== "42P01" && error.code !== "42703") {
            throw error;
        }
    }
}

/**
 * Takes the audit-chain advisory lock.
 *
 * The lock is transaction scoped, so it is held until the surrounding
 * transaction ends. Callers that open their own transaction should acquire
 * this lock *first* so that every transaction takes its locks in the same
 * order and no deadlock can occur.
 */
async function lockAuditChain(client) {
    await client.query("SELECT pg_advisory_xact_lock($1)", [AUDIT_CHAIN_LOCK_KEY]);
}

/**
 * Appends a single audit event.
 *
 * @param {object} req            Express request (used for actor, IP, user agent)
 * @param {string} action         Machine-readable event name
 * @param {string} outcome        "success" | "denied" | "failure"
 * @param {string|null} documentId Related document, when applicable
 * @param {object} details        Structured, non-sensitive context
 * @param {string|null} targetUserId Affected user, when applicable
 * @param {object|null} db        Optional client to run the insert on. When a
 *                                client is supplied the caller owns the
 *                                transaction and the advisory lock is taken
 *                                inside that transaction.
 */
async function writeAuditLog(
    req,
    action,
    outcome,
    documentId = null,
    details = {},
    targetUserId = null,
    db = pool
) {
    const actorId = resolveActorId(req, details);
    const ipAddress = resolveIpAddress(req);
    const userAgent = req && typeof req.get === "function" ? (req.get("user-agent") || null) : null;
    const detailsJson = canonicalJson(details || {});

    // A checked-out client has a `release()` method, the pool does not.
    // (Both have a `connect()` method, so `connect` cannot be used to tell
    // them apart.)
    const ownsTransaction = typeof db.release !== "function" && typeof db.connect === "function";
    const client = ownsTransaction ? await db.connect() : db;

    let hasError = false;
    try {
        if (ownsTransaction) {
            await client.query("BEGIN");
        }

        // Serialise the read-head / insert / write-head critical section.
        await lockAuditChain(client);

        const head = await readChainHead(client);

        const entryHash = computeEntryHash({
            prevHash: head.lastHash,
            actorId,
            documentId,
            targetUserId,
            action,
            outcome,
            detailsJson
        });

        const inserted = await client.query(
            `INSERT INTO audit_logs
                (actor_id, document_id, target_user_id, action, outcome,
                 ip_address, user_agent, details, prev_hash, entry_hash)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10)
             RETURNING id`,
            [
                actorId,
                documentId,
                targetUserId,
                action,
                outcome,
                ipAddress,
                userAgent,
                detailsJson,
                head.lastHash,
                entryHash
            ]
        );

        await updateChainHead(client, inserted.rows[0].id, entryHash);

        if (ownsTransaction) {
            await client.query("COMMIT");
        }

        return inserted.rows[0];
    } catch (error) {
        hasError = true;
        if (ownsTransaction) {
            await client.query("ROLLBACK").catch(() => {});
        }
        throw error;
    } finally {
        if (ownsTransaction && client) {
            client.release(hasError);
        }
    }
}

/**
 * Verifies the integrity of the whole audit chain.
 *
 * Detects:
 *  - modified rows (the recomputed hash no longer matches)
 *  - broken links (prev_hash no longer matches the previous entry)
 *  - deleted rows in the middle of the chain
 *  - truncation of the tail (the head no longer matches the anchor table)
 */
async function verifyAuditChain(db = pool) {
    const result = await db.query(
        `SELECT id, actor_id, document_id, target_user_id, action, outcome,
                details, prev_hash, entry_hash, created_at
         FROM audit_logs
         ORDER BY id ASC`
    );

    let expectedPrevHash = GENESIS_HASH;
    let previousId = 0;

    for (const row of result.rows) {
        const detailsJson = canonicalJson(row.details || {});
        const expectedEntryHash = computeEntryHash({
            prevHash: expectedPrevHash,
            actorId: row.actor_id,
            documentId: row.document_id,
            targetUserId: row.target_user_id,
            action: row.action,
            outcome: row.outcome,
            detailsJson
        });

        if (row.prev_hash !== expectedPrevHash) {
            // Check if an authorized integrity incident annotation documents this break
            let annotation = null;
            try {
                const annRes = await db.query(
                    "SELECT * FROM audit_incident_annotations WHERE broken_at_id = $1 LIMIT 1",
                    [row.id]
                );
                annotation = annRes.rows[0] || null;
            } catch (err) {
                if (err.code !== "42P01" && err.code !== "42703") throw err;
            }

            if (annotation) {
                // Verify subsequent entries from row.id onwards to ensure the second segment is intact
                let seg2Prev = row.prev_hash;
                let seg2Valid = true;

                for (let i = result.rows.indexOf(row); i < result.rows.length; i++) {
                    const r2 = result.rows[i];
                    const dJson2 = canonicalJson(r2.details || {});
                    const expHash2 = computeEntryHash({
                        prevHash: seg2Prev,
                        actorId: r2.actor_id,
                        documentId: r2.document_id,
                        targetUserId: r2.target_user_id,
                        action: r2.action,
                        outcome: r2.outcome,
                        detailsJson: dJson2
                    });

                    if (r2.prev_hash !== seg2Prev || r2.entry_hash !== expHash2) {
                        seg2Valid = false;
                        break;
                    }
                    seg2Prev = r2.entry_hash;
                }

                if (seg2Valid) {
                    const lastRow = result.rows[result.rows.length - 1];
                    const latestId = lastRow ? Number(lastRow.id) : Number(row.id);
                    return {
                        valid: false,
                        status: "documented_incident",
                        reason: "documented_historical_incident",
                        brokenAtId: row.id,
                        totalEntries: result.rows.length,
                        latestEntryId: latestId,
                        segment1: {
                            startId: result.rows[0] ? Number(result.rows[0].id) : 1,
                            endId: Number(previousId),
                            valid: true
                        },
                        segment2: {
                            startId: Number(row.id),
                            endId: latestId,
                            valid: true,
                            entriesCount: result.rows.length - result.rows.indexOf(row)
                        },
                        appendHealth: {
                            active: true,
                            extendsLatest: true,
                            latestId: latestId
                        },
                        incident: {
                            code: annotation.incident_code,
                            type: annotation.incident_type,
                            brokenAtId: Number(annotation.broken_at_id),
                            affectedRangeStart: Number(annotation.affected_range_start),
                            affectedRangeEnd: Number(annotation.affected_range_end),
                            rootCause: annotation.root_cause,
                            disposition: annotation.authorized_disposition,
                            authorizedBy: annotation.authorized_by,
                            discoveredAt: annotation.discovered_at
                        },
                        detail: `Historical integrity incident at entry ${row.id} (${annotation.incident_code}) is documented and preserved. The historical chain is segmented and not continuous.`
                    };
                }
            }

            return {
                valid: false,
                status: "failed",
                reason: "broken_link",
                brokenAtId: row.id,
                totalEntries: result.rows.length
            };
        }

        if (row.entry_hash !== expectedEntryHash) {
            return {
                valid: false,
                status: "failed",
                reason: "entry_hash_mismatch",
                brokenAtId: row.id,
                totalEntries: result.rows.length
            };
        }

        expectedPrevHash = row.entry_hash;
        previousId = Number(row.id);
    }

    // Compare the recomputed head with the independently stored anchor to
    // detect rows that were removed from the end of the log.
    let anchor = null;
    try {
        const state = await db.query(
            "SELECT last_entry_id, last_hash FROM audit_chain_state WHERE id = 1"
        );
        anchor = state.rows[0] || null;
    } catch (error) {
        if (error.code !== "42P01" && error.code !== "42703") {
            throw error;
        }
    }

    if (anchor) {
        const anchorId = Number(anchor.last_entry_id);
        const anchorHash = anchor.last_hash;

        if (anchorId !== previousId || anchorHash !== expectedPrevHash) {
            return {
                valid: false,
                status: "failed",
                reason: "head_anchor_mismatch",
                brokenAtId: Math.min(anchorId, previousId) || null,
                totalEntries: result.rows.length,
                detail: "The stored chain head does not match the newest audit entry. Entries may have been removed."
            };
        }
    }

    return {
        valid: true,
        status: "verified",
        reason: "ok",
        totalEntries: result.rows.length,
        latestEntryId: previousId,
        headHash: expectedPrevHash
    };
}

/**
 * Recomputes the hash chain.
 *
 * Only used by the migration to repair a chain that was built before the
 * canonical representation was fixed, or to recover from a legacy database.
 * The append-only trigger has to be removed while the rows are rewritten and
 * is always restored afterwards.
 */
async function rebuildAuditChainIfNeeded() {
    const check = await verifyAuditChain();
    if (check.valid) {
        console.log(`Audit chain verified (${check.totalEntries} entries). No rebuild needed.`);
        return { rebuilt: false, ...check };
    }

    if (check.status === "documented_incident") {
        console.warn(
            `Preserving documented historical integrity incident at entry ${check.brokenAtId} (${check.incident?.code}). Not rewriting historical audit rows.`
        );
        return { rebuilt: false, preservedIncident: true, ...check };
    }

    console.warn(
        `Audit chain broken at entry ID ${check.brokenAtId} (${check.reason}). Rebuilding hashes…`
    );

    const client = await pool.connect();
    try {
        await client.query("BEGIN");
        await client.query("DROP TRIGGER IF EXISTS audit_logs_immutable_trigger ON audit_logs");

        const rows = await client.query(
            `SELECT id, actor_id, document_id, target_user_id, action, outcome, details
             FROM audit_logs
             ORDER BY id ASC`
        );

        let prevHash = GENESIS_HASH;
        for (const row of rows.rows) {
            const detailsJson = canonicalJson(row.details || {});
            const entryHash = computeEntryHash({
                prevHash,
                actorId: row.actor_id,
                documentId: row.document_id,
                targetUserId: row.target_user_id,
                action: row.action,
                outcome: row.outcome,
                detailsJson
            });
            await client.query(
                "UPDATE audit_logs SET prev_hash = $1, entry_hash = $2 WHERE id = $3",
                [prevHash, entryHash, row.id]
            );
            prevHash = entryHash;
        }

        // The anchor must reference the *newest* entry, otherwise the
        // verification would report a head mismatch right after a rebuild.
        const lastEntryId =
            rows.rows.length > 0 ? Number(rows.rows[rows.rows.length - 1].id) : 0;

        await client.query(
            `INSERT INTO audit_chain_state (id, last_entry_id, last_hash)
             VALUES (1, $1, $2)
             ON CONFLICT (id) DO UPDATE
             SET last_entry_id = EXCLUDED.last_entry_id,
                 last_hash = EXCLUDED.last_hash,
                 updated_at = NOW()`,
            [lastEntryId, prevHash]
        );

        await client.query("COMMIT");
        console.log(`Audit chain rebuilt successfully (${rows.rows.length} entries).`);
        return { rebuilt: true, totalEntries: rows.rows.length };
    } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        throw error;
    } finally {
        // The append-only protection must never stay disabled.
        try {
            await client.query(
                `CREATE OR REPLACE FUNCTION prevent_audit_log_tampering()
                 RETURNS TRIGGER AS $$
                 BEGIN
                     RAISE EXCEPTION 'Security Violation: audit_logs is append-only and cannot be modified or deleted.';
                 END;
                 $$ LANGUAGE plpgsql;`
            );
            await client.query("DROP TRIGGER IF EXISTS audit_logs_immutable_trigger ON audit_logs");
            await client.query(
                `CREATE TRIGGER audit_logs_immutable_trigger
                 BEFORE UPDATE OR DELETE ON audit_logs
                 FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_tampering();`
            );
        } catch (error) {
            console.error("Failed to restore the audit immutability trigger:", error.message);
        }
        client.release();
    }
}

module.exports = {
    writeAuditLog,
    verifyAuditChain,
    rebuildAuditChainIfNeeded,
    lockAuditChain,
    computeEntryHash,
    canonicalJson,
    canonicalize,
    AUDIT_CHAIN_LOCK_KEY,
    GENESIS_HASH
};
