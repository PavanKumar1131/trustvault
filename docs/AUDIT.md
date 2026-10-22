# TrustVault — Audit Trail & Cryptographic Chain Architecture

This document details the audit architecture, cryptographic hash-chain design, concurrency protections, incident preservation model, and real-world security boundaries implemented in TrustVault.

The canonical implementation is located in [`src/services/auditService.js`](file:///c:/trustvault/src/services/auditService.js).

---

## 1. Architectural Overview

Every state-changing operation in TrustVault produces an immutable record in the `audit_logs` table. Entries are cryptographically chained together using SHA-256 hashes, forming a verifiable, forward-linked hash chain.

### Audit Log Schema

```sql
CREATE TABLE audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    actor_id        UUID,
    document_id     UUID,
    target_user_id  UUID,
    action          VARCHAR(64) NOT NULL,
    outcome         VARCHAR(16) NOT NULL,
    ip_address      VARCHAR(45),
    user_agent      TEXT,
    details         JSONB DEFAULT '{}'::jsonb,
    prev_hash       VARCHAR(64) NOT NULL,
    entry_hash      VARCHAR(64) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

> [!NOTE]
> **Independent Entity References (Mitigation T-26)**
> The columns `actor_id`, `document_id`, and `target_user_id` are plain UUID columns without `FOREIGN KEY … ON DELETE CASCADE` or `SET NULL` constraints. If a document or user account is permanently deleted, historical audit entries are never modified or rewritten by database cascades.

---

## 2. Cryptographic Chaining Specification

### Canonical Serialization
PostgreSQL `jsonb` columns do not preserve JSON key order; PostgreSQL normalizes keys internally by length and byte value. To ensure hashes computed in Node.js match across database reads and verification passes, [`canonicalize()`](file:///c:/trustvault/src/services/auditService.js#L54) recursively sorts all JSON object keys before stringification (`canonicalJson()`).

### Entry Hash Formula
Each audit record's `entry_hash` is calculated via SHA-256 over a pipe-delimited payload:

$$\text{payload} = \text{prevHash} \parallel \text{"\|"} \parallel \text{actorId} \parallel \text{"\|"} \parallel \text{documentId} \parallel \text{"\|"} \parallel \text{targetUserId} \parallel \text{"\|"} \parallel \text{action} \parallel \text{"\|"} \parallel \text{outcome} \parallel \text{"\|"} \parallel \text{detailsJson}$$

- `prevHash`: The `entry_hash` of the immediately preceding audit record. For the very first entry (entry 1), this is the sentinel string `"GENESIS"`.
- `actorId`: The UUID of the authenticated actor, or `"anon"` if unauthenticated.
- `documentId`: The UUID of the related document, or `"none"`.
- `targetUserId`: The UUID of the affected user, or `"none"`.
- `action`: The machine-readable action identifier (e.g. `auth_login`, `document_upload`, `USER_ROLE_CHANGED`).
- `outcome`: `"success"`, `"denied"`, or `"failure"`.
- `detailsJson`: Canonicalized JSON string representation of the structured details payload.

```javascript
const payload = [
    prevHash || "GENESIS",
    actorId || "anon",
    documentId || "none",
    targetUserId || "none",
    action,
    outcome,
    detailsJson
].join("|");

const entryHash = crypto.createHash("sha256").update(payload).digest("hex");
```

---

## 3. Concurrency & Chain Head Protections

### Concurrency Advisory Locking
Audit logging frequently occurs concurrently (e.g. parallel document edits, simultaneous logins). Without synchronization, two transactions could read the same `prev_hash` from the current chain head, creating a fork.

TrustVault serializes all audit writes using a PostgreSQL transactional advisory lock:
```sql
SELECT pg_advisory_xact_lock(917342615);
```
- The lock is acquired inside the database transaction before reading the chain head.
- It is automatically released upon `COMMIT` or `ROLLBACK`.
- Callers that supply their own database client must acquire this lock within their transaction to ensure consistent lock ordering and avoid deadlocks.

### Anchor Table (`audit_chain_state`) & Tail Truncation Detection
To prevent an adversary from silently deleting the most recent audit records from the tail of the log, the chain head is mirrored in a single-row anchor table:

```sql
CREATE TABLE audit_chain_state (
    id              INTEGER PRIMARY KEY DEFAULT 1,
    last_entry_id   BIGINT NOT NULL,
    last_hash       VARCHAR(64) NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

During audit verification (`verifyAuditChain`), the verifier recomputes the expected head from the entire log and compares it against `audit_chain_state.last_hash` and `audit_chain_state.last_entry_id`. If records were dropped from the tail of the log, the verifier reports `head_anchor_mismatch` (`"Entries may have been removed"`).

### Append-Only Database Trigger
A row-level trigger blocks unauthorized direct modifications:

```sql
CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit logs are immutable. UPDATE and DELETE are prohibited.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_logs_immutability
BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_modification();
```

---

## 4. Historical Incident INC-2026-438 & Segment Verification

### The Break at Entry 438
The TrustVault audit log contains a documented historical break at **entry 438**. Entry 438's `prev_hash` does not match entry 437's `entry_hash`.

In accordance with strict security and auditing standards, **TrustVault does NOT claim the historical audit chain is fully verified**. The audit chain is honestly reported as **segmented and discontinuous**. Historical records are not rewritten or artificially rehashed to create a false appearance of perfection.

### Incident Annotation Table
The incident is formally documented in `audit_incident_annotations`:

| Field | Documented Value |
| --- | --- |
| `incident_code` | `INC-2026-438` |
| `broken_at_id` | `438` |
| `affected_range_start` | `438` |
| `affected_range_end` | `438` |
| `root_cause` | Legacy direct write / pre-canonical migration link discontinuity |
| `authorized_disposition` | Document and preserve historical integrity; do not rewrite history |
| `authorized_by` | Security & Compliance Engineering |

### Segment Verification Architecture
When [`verifyAuditChain()`](file:///c:/trustvault/src/services/auditService.js#L329) detects the link break at entry 438, it detects the authorized annotation and performs segment verification:

1. **Segment 1 (Historical Integrity)**: Verifies all entries from ID 1 through ID 437 from the genesis hash.
2. **Segment 2 (Post-Incident Verification)**: Verifies all entries from ID 438 through the latest entry (`latestEntryId`, currently #580+) using entry 438's actual `prev_hash` as the seed.
3. **Append Health**: Verifies that new audit entries continue to extend the latest head hash cleanly and without error.

When both segments are cryptographically intact, `verifyAuditChain()` returns:
```json
{
  "valid": false,
  "status": "documented_incident",
  "reason": "documented_historical_incident",
  "brokenAtId": 438,
  "totalEntries": 580,
  "latestEntryId": 580,
  "segment1": { "startId": 1, "endId": 437, "valid": true },
  "segment2": { "startId": 438, "endId": 580, "valid": true, "entriesCount": 143 },
  "appendHealth": { "active": true, "extendsLatest": true, "latestId": 580 },
  "incident": {
    "code": "INC-2026-438",
    "brokenAtId": 438,
    "rootCause": "Legacy direct write / pre-canonical migration link discontinuity",
    "disposition": "Document and preserve historical integrity; do not rewrite history"
  },
  "detail": "Historical integrity incident at entry 438 (INC-2026-438) is documented and preserved. The historical chain is segmented and not continuous."
}
```

### Protection Against Unwanted Rebuilds
The automated repair function [`rebuildAuditChainIfNeeded()`](file:///c:/trustvault/src/services/auditService.js#L503) checks for `status === "documented_incident"`. When detected, it **explicitly refuses to rewrite history**:
```javascript
if (check.status === "documented_incident") {
    console.warn(`Preserving documented historical integrity incident at entry ${check.brokenAtId} (${check.incident?.code}). Not rewriting historical audit rows.`);
    return { rebuilt: false, preservedIncident: true, ...check };
}
```

---

## 5. Verification States Summary

The audit verification subsystem evaluates the log into four distinct operational states:

| Status | `valid` | Meaning | User / Admin UI Representation |
| --- | :---: | --- | --- |
| `verified` | `true` | The chain is completely continuous and mathematically unbroken from `GENESIS` to the head anchor. | Displays green badge: **"Audit chain verified"** |
| `documented_incident` | `false` | A recognized, annotated historical break exists at entry 438. Segment 1 and Segment 2 are each mathematically valid, and append health is active. | Displays warning banner: **"Documented incident: INC-2026-438. Chain segmented (1–437, 438–head)."** |
| `failed` | `false` | An unexpected broken link, hash mismatch (tampered row data), or `head_anchor_mismatch` (tail truncation) was detected. | Displays critical error: **"Audit chain broken at entry ID X"** |
| `unavailable` | `null` | The database could not be reached, query timed out, or verification service encountered an unexpected database exception. | Displays neutral warning: **"Integrity check unavailable"** |

---

## 6. Real Security Guarantees & Limitations

In accordance with [`THREATS.md`](file:///c:/trustvault/THREATS.md) (threats T-12 and T-13), TrustVault makes explicit the boundaries of its audit protections:

### What the Implementation Guarantees
- **Accidental Tampering Detection**: Any accidental modification, out-of-order write, or manual SQL update on an individual audit row will invalidate all subsequent hashes and trigger an immediate verification failure.
- **Application-Level Immutability**: Application database connections lack permission to drop triggers and are blocked from executing `UPDATE` or `DELETE` on `audit_logs`.
- **Concurrent Integrity**: Advisory lock serializes writes, eliminating race-induced chain forks.
- **Tail Truncation Detection**: Silent dropping of rows from the end of the chain is caught by the `audit_chain_state` anchor table.

### What the Implementation Does Not Guarantee (Residual Risks)
- **Tamper-Evident, Not Tamper-Proof**: A database superuser or schema owner can drop the `audit_logs_immutability` trigger, alter audit rows, recalculate hashes, and update `audit_chain_state`. The database cannot defend itself against its own superuser.
- **`TRUNCATE` Bypass (Threat T-13)**: `TRUNCATE audit_logs` does not fire row-level `BEFORE DELETE` triggers in PostgreSQL. While this empties the log, the mismatch is immediately caught by `audit_chain_state` upon next verification.
- **No External Anchoring**: Head hashes are not currently notarized to an external blockchain, hardware security module (HSM), or offsite write-once storage sink.
