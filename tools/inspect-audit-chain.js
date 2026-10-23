/**
 * Read-only diagnostic tool for the TrustVault audit hash chain.
 *
 * Walks every audit_logs row in ID order, recomputes each entry hash using the
 * canonical hashing function, and reports the first detected inconsistency.
 *
 * Security and Reliability Constraints:
 * - Strictly read-only: runs in a READ ONLY transaction, never mutates database rows.
 * - Cannot invoke repair paths or re-hash historic records.
 * - Validates command-line arguments to prevent invalid or malicious inputs.
 * - Redacts sensitive fields (passwords, tokens, cookies, secrets) from diagnostics.
 * - Detects and honors documented historical integrity incidents (e.g., INC-2026-438).
 *
 * Usage: node tools/inspect-audit-chain.js [breakId]
 */

require("dotenv").config();

const pool = require("../src/db");
const { computeEntryHash, canonicalJson, GENESIS_HASH } = require("../src/services/auditService");

/**
 * Validates the command-line entry ID argument.
 * Returns the parsed positive integer or null if omitted.
 */
function validateEntryId(rawArg) {
    if (rawArg === undefined || rawArg === null || rawArg === "") {
        return null;
    }
    const trimmed = String(rawArg).trim();
    if (!/^\d+$/.test(trimmed)) {
        throw new Error(`Invalid entry ID "${rawArg}": must be a positive integer.`);
    }
    const parsed = Number.parseInt(trimmed, 10);
    if (!Number.isInteger(parsed) || parsed <= 0) {
        throw new Error(`Invalid entry ID "${rawArg}": must be greater than zero.`);
    }
    return parsed;
}

/**
 * Recursively redacts sensitive keys from audit log details objects.
 */
function redactSensitive(val) {
    if (val === null || val === undefined) return val;
    if (Array.isArray(val)) {
        return val.map(redactSensitive);
    }
    if (typeof val === "object") {
        const clean = {};
        for (const [k, v] of Object.entries(val)) {
            if (/password|token|secret|cookie|session|key|credential/i.test(k)) {
                clean[k] = "[REDACTED]";
            } else if (v && typeof v === "object") {
                clean[k] = redactSensitive(v);
            } else {
                clean[k] = v;
            }
        }
        return clean;
    }
    return val;
}

/**
 * Formats a bounded audit entry summary.
 */
function formatEntrySummary(row) {
    const safeDetails = redactSensitive(row.details || {});
    return (
        `  id=${row.id} action=${row.action} outcome=${row.outcome} ` +
        `actor=${row.actor_id || "anon"} doc=${row.document_id || "none"}\n` +
        `     prev_hash  = ${row.prev_hash}\n` +
        `     entry_hash = ${row.entry_hash}\n` +
        `     details    = ${JSON.stringify(safeDetails)}`
    );
}

/**
 * Executes the read-only audit inspection.
 *
 * @param {object} [options]
 * @param {number|null} [options.breakId] Optional entry ID to focus diagnostics on
 * @param {object} [options.dbClient] Optional pg Client/Pool for testing
 */
async function inspectAuditChain(options = {}) {
    const rawArg = options.breakId !== undefined ? options.breakId : process.argv[2];
    const breakId = validateEntryId(rawArg);
    const activePool = options.dbClient || pool;

    const client = await activePool.connect();
    try {
        // Enforce strict read-only transaction at database session level
        await client.query("BEGIN TRANSACTION READ ONLY");

        const { rows } = await client.query(
            `SELECT id, actor_id, document_id, target_user_id, action, outcome,
                    details, prev_hash, entry_hash, created_at
             FROM audit_logs
             ORDER BY id ASC`
        );

        console.log(`Total audit entries scanned: ${rows.length}`);

        let expectedPrev = GENESIS_HASH;
        let broken = null;
        let brokenIndex = -1;
        const idGaps = [];

        for (let i = 0; i < rows.length; i += 1) {
            const row = rows[i];
            if (i > 0 && Number(row.id) !== Number(rows[i - 1].id) + 1) {
                idGaps.push({ after: rows[i - 1].id, before: row.id });
            }

            const detailsJson = canonicalJson(row.details || {});
            const expectedHash = computeEntryHash({
                prevHash: expectedPrev,
                actorId: row.actor_id,
                documentId: row.document_id,
                targetUserId: row.target_user_id,
                action: row.action,
                outcome: row.outcome,
                detailsJson
            });

            if (row.prev_hash !== expectedPrev) {
                broken = {
                    id: Number(row.id),
                    reason: "broken_link",
                    detail: "prev_hash does not match the previous entry's entry_hash",
                    storedPrev: row.prev_hash,
                    expectedPrev
                };
                brokenIndex = i;
                break;
            }

            if (row.entry_hash !== expectedHash) {
                broken = {
                    id: Number(row.id),
                    reason: "entry_hash_mismatch",
                    detail: "stored entry_hash does not match recomputed hash",
                    storedHash: row.entry_hash,
                    expectedHash,
                    action: row.action,
                    outcome: row.outcome,
                    actor: row.actor_id
                };
                brokenIndex = i;
                break;
            }

            expectedPrev = row.entry_hash;
        }

        if (idGaps.length > 0) {
            console.log("ID sequence gaps detected:");
            idGaps.forEach((g) =>
                console.log(`  ... ID ${g.after} -> ${g.before} (${g.before - g.after - 1} rows missing)`)
            );
        } else {
            console.log("ID sequence: contiguous (no missing IDs).");
        }

        let incident = null;
        if (broken) {
            console.log(`\n=== AUDIT CHAIN DISCONTINUITY DETECTED AT ENTRY ${broken.id} ===`);
            console.log(`Reason: ${broken.reason} (${broken.detail})`);

            // Check if this discontinuity is an authorized, documented incident
            try {
                const annRes = await client.query(
                    `SELECT * FROM audit_incident_annotations WHERE broken_at_id = $1 LIMIT 1`,
                    [broken.id]
                );
                incident = annRes.rows[0] || null;
            } catch (annErr) {
                if (annErr.code !== "42P01") throw annErr;
            }

            if (incident) {
                console.log(`\nDocumented Incident Forensic Annotation:`);
                console.log(`  - Incident Code:   ${incident.incident_code}`);
                console.log(`  - Incident Type:   ${incident.incident_type}`);
                console.log(`  - Affected Range:  ${incident.affected_range_start} -> ${incident.affected_range_end}`);
                console.log(`  - Root Cause:      ${incident.root_cause}`);
                console.log(`  - Disposition:     ${incident.authorized_disposition}`);
                console.log(`  - Authorized By:   ${incident.authorized_by}`);
                console.log(`  - Chain Status:    Segmented historical chain preserved (not silently repaired)`);

                // Check subsequent segment health
                let seg2Prev = rows[brokenIndex].prev_hash;
                let seg2Valid = true;
                for (let k = brokenIndex; k < rows.length; k++) {
                    const r = rows[k];
                    const expH = computeEntryHash({
                        prevHash: seg2Prev,
                        actorId: r.actor_id,
                        documentId: r.document_id,
                        targetUserId: r.target_user_id,
                        action: r.action,
                        outcome: r.outcome,
                        detailsJson: canonicalJson(r.details || {})
                    });
                    if (r.prev_hash !== seg2Prev || r.entry_hash !== expH) {
                        seg2Valid = false;
                        break;
                    }
                    seg2Prev = r.entry_hash;
                }
                console.log(`  - Post-incident Segment 2 Health: ${seg2Valid ? "INTACT & VALID" : "COMPROMISED"}`);
            }

            // Bounded window diagnostic display around the break or target entry
            const targetId = breakId || broken.id;
            console.log(`\nBounded inspection window around entry ${targetId} (±3 entries):`);
            const windowRows = await client.query(
                `SELECT id, action, outcome, actor_id, document_id, target_user_id,
                        prev_hash, entry_hash, created_at, details
                 FROM audit_logs
                 WHERE id BETWEEN $1 AND $2
                 ORDER BY id ASC`,
                [Math.max(1, targetId - 3), targetId + 3]
            );

            windowRows.rows.forEach((r) => {
                console.log(formatEntrySummary(r));
            });
        } else {
            console.log("\nAudit Chain Status: CONTINUOUS & VALID (every entry hash and link verified).");
            if (breakId) {
                console.log(`\nBounded inspection window around entry ${breakId} (±3 entries):`);
                const windowRows = await client.query(
                    `SELECT id, action, outcome, actor_id, document_id, target_user_id,
                            prev_hash, entry_hash, created_at, details
                     FROM audit_logs
                     WHERE id BETWEEN $1 AND $2
                     ORDER BY id ASC`,
                    [Math.max(1, breakId - 3), breakId + 3]
                );
                windowRows.rows.forEach((r) => {
                    console.log(formatEntrySummary(r));
                });
            }
        }

        // Anchor check
        let anchor = null;
        try {
            const stateRes = await client.query(
                "SELECT last_entry_id, last_hash, updated_at FROM audit_chain_state WHERE id = 1"
            );
            anchor = stateRes.rows[0] || null;
            console.log("\nAudit Chain Anchor State:", JSON.stringify(anchor));
        } catch {
            console.log("\nAudit Chain Anchor: unavailable in schema");
        }

        await client.query("COMMIT");

        return {
            totalEntries: rows.length,
            broken,
            incident,
            anchor
        };
    } catch (err) {
        await client.query("ROLLBACK").catch(() => {});
        throw err;
    } finally {
        client.release();
        if (!options.dbClient) {
            await pool.end();
        }
    }
}

if (require.main === module) {
    inspectAuditChain().catch((err) => {
        console.error("Audit chain inspection failed:", err.message);
        process.exit(1);
    });
}

module.exports = {
    inspectAuditChain,
    validateEntryId,
    redactSensitive,
    formatEntrySummary
};
