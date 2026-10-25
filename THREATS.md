# Threat model — TrustVault

This document describes the assets, the trust boundaries and the threats that
were identified during the security review of the backend. Every finding
lists its status: **mitigated** (the risk is handled in the current code and
covered by a test), **residual** (the risk still exists and is accepted or
has to be handled by the deployment), or **open** (the risk still exists and
has to be fixed).

---

## 1. Assets

| Asset | Why it matters |
| --- | --- |
| Document contents | The primary business data — confidential files |
| Account credentials | Password hashes, session ids |
| The access lists (`document_permissions`) | Define who may see which document |
| The audit trail | The evidence of what happened; the basis for incident response |
| The database connection string | Grants access to everything above |
| `SESSION_SECRET` | Forges session cookies and CSRF tokens |

---

## 2. Trust boundaries

```
        ┌──────────────────────────────────────────────┐
        │  Browser (public/js)                         │
        └───────────────────┬──────────────────────────┘
                            │  HTTPS  (must be terminated
                            │          by the reverse proxy)
        ┌───────────────────▼──────────────────────────┐
        │  Express application                         │
        │   helmet · rate limit · CSRF · session        │
        │   requireAuth → role → document access        │
        └───────────────────┬──────────────────────────┘
                            │  TLS (Neon)
        ┌───────────────────▼──────────────────────────┐
        │  PostgreSQL                                  │
        │   data · audit chain · append-only trigger    │
        └──────────────────────────────────────────────┘
```

Inside the application the two authorisation layers of
[`docs/PERMISSIONS.md`](docs/PERMISSIONS.md) separate the actors:

- **Administrators** manage accounts but have no access to document content.
- **Document owners** control their own documents.
- **Viewers** only work with what was explicitly shared with them.

---

## 3. Attacker models

| Model | Capability |
| --- | --- |
| **A — anonymous** | Can send arbitrary HTTP requests |
| **B — authenticated viewer** | Holds a valid session of a low-privilege account |
| **C — malicious owner** | Holds a valid session and owns documents; tries to reach foreign documents or to elevate the role |
| **D — compromised administrator session** | Holds a valid administrator session |
| **E — database reader** | Can read the database but not change it |
| **F — database writer** | Can change the database (including the schema owner) |

---

## 4. Findings

### T-01 — Credential stuffing and password brute force

| | |
| --- | --- |
| **Model** | A |
| **Severity** | High |
| **Status** | Mitigated |

**Risk.** An attacker tries a list of leaked credentials against the login
endpoint.

**Mitigation.** A per-account lockout after five failed attempts within a
15-minute sliding window, a dedicated rate limiter on `/api/auth/login` and
`/api/auth/register`, and a generic `Invalid email or password` message that
does not reveal whether the address exists. The password policy demands at
least 12 characters and at most 72 **bytes** (bcrypt truncates beyond 72
bytes, which would otherwise make two different passwords equivalent).

**Residual.** The lockout is per account, so an attacker can still try one
guess per account across many accounts. The IP-based rate limiter is the
counter-measure there.

**Tests.** `tests/csrf.test.js` (the rate limiter and the per-account
lockout), `tests/security.test.js` (the account lockout as well).

---

### T-02 — Session fixation

| | |
| --- | --- |
| **Model** | A, B |
| **Severity** | Medium |
| **Status** | Mitigated |

**Risk.** An attacker plants a session id in the victim's browser and
hijacks the session after the victim logs in.

**Mitigation.** `express-session` regenerates the session id on a successful
login, the cookie is `HttpOnly` and `SameSite=Lax`, the session lives in
PostgreSQL (`user_sessions`) and not in a signed cookie, and the cookie
carries `Secure` in production.

**Tests.** `tests/session.test.js` (session id changes on login).

---

### T-03 — Cross-site request forgery

| | |
| --- | --- |
| **Model** | A, B |
| **Severity** | High |
| **Status** | Mitigated |

**Risk.** A third-party page makes the browser perform a state-changing
request with the victim's session cookie.

**Mitigation.** The double-submit token of `csrf-csrf` (v4). The token is
bound to the session id, so a token from another session is rejected. The
login and the registration are exempt, because no authenticated session
exists yet that could be ridden; both are protected by the lockout and the
authentication rate limiter instead.

**Residual.** The exemption is the standard trade-off. A cross-origin login
CSRF (forcing a victim to log into the attacker's account) is possible in
principle; the `SameSite=Lax` cookie limits the practical impact.

**Tests.** `tests/csrf.test.js` builds a second application instance with
`csrfEnabled: true` and verifies the rejection, the successful request, the
cross-session replay and the forged token.

---

### T-04 — Privilege escalation through the role field

| | |
| --- | --- |
| **Model** | A, C |
| **Severity** | Critical |
| **Status** | Mitigated |

**Risk.** A user registers with `role: "admin"` or `role: "document_owner"` and
receives unauthorized elevated rights.

**Mitigation.** The public registration endpoint strictly ignores any client-supplied
`role` parameter and hardcodes all new accounts to the default role `viewer`.
Role escalation to `document_owner` or `admin` cannot be performed through
self-registration. Administrator account creation (`POST /api/admin/users`) is
limited to `viewer` and `document_owner` and never mints an Admin. The role
change endpoint (`PATCH /api/admin/users/:id/role`) accepts only the
`viewer` <-> `document_owner` transition, requires a 10-500 character reason,
forbids self-modification, protects Admin accounts, and keeps at least one
active administrator under an advisory lock. A Document Owner demotion creates
a Read grant for every document the account owns, so ownership does not remain
an implicit owner privilege. The acting administrator is re-read and locked
inside the account-creation and role-change transactions, and `requireAuth`
re-reads the authenticated role and status on every request.

**Tests.** `tests/security.test.js` (client role parameter ignored on registration,
default viewer assignment, role escalation attempts rejected),
`tests/authorization.test.js` (role change takes effect without a new login),
`tests/admin-users.test.js`, `tests/role-upgrade.test.js`,
`tests/hardening-regressions.test.js`, and `tests/concurrency.test.js`.

---

### T-05 — The last administrator can be removed

| | |
| --- | --- |
| **Model** | D |
| **Severity** | High |
| **Status** | Mitigated |

**Risk.** Two concurrent demotions, or a single demotion, leave the system
without any administrator — nobody can administer the accounts any more.

**Mitigation.** The check runs inside a transaction that holds the advisory
lock `pg_advisory_xact_lock(918273645)`, locks the affected row with
`SELECT … FOR UPDATE` and re-counts the active administrators **inside** the
transaction. The request is rejected with `409` and the change is rolled
back.

**Tests.** `tests/security.test.js` (demotion of the last administrator, and
three administrators demoting each other at the same time — the system keeps
at least one administrator).

---

### T-06 — Administrators read every document

| | |
| --- | --- |
| **Model** | D |
| **Severity** | Critical |
| **Status** | Mitigated |

**Risk.** The administrator role implicitly granted access to every document,
so a compromised administrator session could read all files.

**Mitigation.** Administrators have **no** implicit document access. The
document listing returns an empty list for them, and every document
endpoint — metadata, download, permissions, audit view, edit, delete —
returns `404` for an administrator who is not the owner and has no grant.
The decision is taken in one place, `src/services/accessService.js`.

**Tests.** `tests/authorization.test.js` (the complete administrator
matrix).

---

### T-07 — Insecure direct object reference (IDOR)

| | |
| --- | --- |
| **Model** | B, C |
| **Severity** | Critical |
| **Status** | Mitigated |

**Risk.** A user replaces the document id in the URL and reads or downloads a
foreign document.

**Mitigation.** Every document route resolves the access level against the
current database state before it touches the data. A user without access
receives `404` — not `403` — so the API never confirms that the document
exists.

**Tests.** `tests/security.test.js` (IDOR on read, download, delete and
permissions), `tests/authorization.test.js`.

---

### T-08 — Malicious uploads and content-type spoofing

| | |
| --- | --- |
| **Model** | B, C |
| **Severity** | High |
| **Status** | Mitigated |

**Risk.** A file is uploaded with the extension `.pdf` but contains an
executable or a script; the server trusts the extension or the client
supplied MIME type and later serves it.

**Mitigation.** The content type is detected from the bytes of the file
(`file-type`), not from the name or the client-supplied MIME type. Only PDF,
JPEG and PNG content is accepted; unsupported or spoofed content is rejected
with `415` before anything is stored. Downloads are served as an `attachment`
with `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`.

The API deliberately treats content as authoritative: a valid PNG named
`.pdf` is accepted and stored as `image/png`. The browser restricts the file
picker to `.pdf`, `.jpg`, `.jpeg`, and `.png`, but the server does not enforce
extension/content consistency.

**Residual.** Polyglot files (a valid PDF that also contains HTML) are still
possible; the `attachment` disposition and `nosniff` are what contain them.
A valid file with a misleading but allowed extension is stored according to
its detected content. This is a **Low** residual risk because the stored type
is derived from content and is never served inline.

**Proposed correction — not implemented.** Before changing the file-validation
contract, the safest correction is to reject an upload when the extension is
outside the allowed set or when the detected type's canonical extension does
not match the supplied extension. Magic-byte detection and the existing three
formats would remain unchanged; no new format would be added. This aligns the
browser and server rules but may reject legitimately misnamed files, so it
needs an explicit product decision.

**Tests.** `tests/security.test.js` (spoofed file),
`tests/documents.test.js` (JPEG/PNG handling, the exact 5 MiB boundary, a PNG
stored as `image/png` despite a `.pdf` name, and spoofed JPEG content rejected).

---

### T-09 — Enumeration of disabled accounts

| | |
| --- | --- |
| **Model** | A |
| **Severity** | Low |
| **Status** | **Residual — accepted** |

**Risk.** The login endpoint answers a disabled account with `403 This
account has been disabled. Contact an administrator.` while an unknown or
incorrectly entered address is answered with `401 Invalid email or
password`. The difference reveals that the address **exists** and that the
account was deliberately deactivated — which is exactly the state an attacker
is looking for when they enumerate an organisation's addresses.

**Why it is not changed.** The explicit message is a deliberate
usability decision: a disabled employee gets a clear instruction instead of
a generic error, and the support desk does not have to handle "my password
does not work any more". The lockout and the rate limiter limit the
enumeration rate.

**How to reduce it further.** If account enumeration is unacceptable in the
target environment, change the disabled branch in `src/routes/auth.js` to
the same `Invalid email or password` message (and keep the `403` for an
already-authenticated session in `src/middleware/auth.js`, where no
enumeration is possible because the caller already proved the identity).
The frontend then loses the "disabled" hint.

**Tests.** `tests/security.test.js` (disabled account), `tests/session.test.js`.

---

### T-10 — SQL injection

| | |
| --- | --- |
| **Model** | B, C |
| **Severity** | Critical |
| **Status** | Mitigated |

**Risk.** A search term or a path parameter is concatenated into SQL and
changes the meaning of the statement.

**Mitigation.** All queries use parameter placeholders. The only dynamic
parts are table and column names, which come from a fixed list in the
source. The `LIKE` patterns of the search are built from a user-supplied
value, so `%`, `_` and `\` are escaped and the statement uses
`ESCAPE '\'` — a search for `100%` matches the literal text and not every
document.

**Tests.** `tests/security.test.js` (injection payloads in the search, in the
path and in the body), `tests/documents.test.js` (the literal wildcard
semantics).

---

### T-11 — Path traversal through the storage key

| | |
| --- | --- |
| **Model** | E, F |
| **Severity** | High |
| **Status** | Mitigated |

**Risk.** A manipulated `storage_key` in the database makes the server read
or delete a file outside the upload directory (`../../etc/passwd`).

**Mitigation.** Storage keys are generated by the application as UUIDs and
are validated against a UUID pattern **before** they are used to build a
path. A key that does not match is rejected. The files are written with the
flag `wx` (no overwrite) and the mode `0600`.

**Tests.** `tests/security.test.js` (path traversal in the storage key).

---

### T-12 — The audit trail is tamper-evident, not tamper-proof

| | |
| --- | --- |
| **Model** | F |
| **Severity** | Medium |
| **Status** | **Residual — accepted with a documented limitation** |

**Risk.** An attacker with write access to the database — the schema owner,
a superuser or a compromised application credential — can drop the
append-only trigger, rewrite historic entries and recompute the hashes.
Nothing inside the database can prevent the owner of the schema from doing
that.

**What the implementation does provide.**

- Every entry is hashed together with its predecessor, so a modification
  breaks every following hash and is detected by `verifyAuditChain()`.
- A `BEFORE UPDATE OR DELETE` trigger rejects any rewrite of a historic
  entry.
- The head of the chain is mirrored into `audit_chain_state`, so the removal
  of the tail of the log is detected as well.

**Why it is not enough.** The chain and the anchor live in the same
database. An attacker who can change the log can change the anchor. The
guarantee is therefore *"nobody changed the log unnoticed"*, not *"nobody
changed the log"*.

**How to close it.** Replicate the head hash outside the database — a
separate table in another schema with different ownership, a file on a
append-only medium, or an external log sink — and compare it regularly. The
chain format does not have to change for that.

**Tests.** `tests/audit.test.js` (modified entry, broken link, concurrent
appends).

---

### T-13 — The audit trail can be truncated with `TRUNCATE`

| | |
| --- | --- |
| **Model** | F |
| **Severity** | Medium |
| **Status** | **Residual — accepted** |

**Risk.** `TRUNCATE` does **not** fire the row-level trigger, so the whole
log can be emptied with a single statement that raises no error. The
`BEFORE UPDATE OR DELETE` trigger only covers `UPDATE` and `DELETE`.

**Detection.** The independent head anchor in `audit_chain_state` still
points at the previous head. `verifyAuditChain()` reports
`head_anchor_mismatch` ("Entries may have been removed"), and the
administration console shows the chain as broken.

**Limit.** The detection is after the fact — the entries are gone. Only an
external copy of the head hash prevents the deletion itself (see T-12).

**Tests.** `tests/audit.test.js` (the `TRUNCATE` bypass and its detection).

---

### T-14 — Stored XSS through an uploaded document

| | |
| --- | --- |
| **Model** | C |
| **Severity** | Medium |
| **Status** | Mitigated |

**Risk.** A user uploads an HTML or SVG file; the server serves it inline
and the script runs in the origin of the application.

**Mitigation.** Only PDF, JPEG and PNG are accepted, the download is served
as an `attachment` with `nosniff`, and the CSP of `helmet` forbids inline
scripts. The original file name is sanitised before it is stored or used in
a header.

**Tests.** `tests/security.test.js` (a file whose content does not match its
extension is refused), `tests/documents.test.js` (the download carries the
`attachment` disposition and `nosniff`).

---

### T-15 — Disclosure of internal details in error messages

| | |
| --- | --- |
| **Model** | A, B |
| **Severity** | Medium |
| **Status** | Mitigated |

**Risk.** A database error is forwarded to the client and reveals the table
names, the query text or the internal structure.

**Mitigation.** The client only ever receives an allow-listed message. Every
other error is logged on the server and answered with a generic text. The
only message that is deliberately forwarded verbatim is
`invalid csrf token`, because the frontend uses it to detect a stale token
and to retry the request once.

**Tests.** `tests/security.test.js` (no SQL text in the response).

---

### T-16 — Denial of service through the upload endpoint

| | |
| --- | --- |
| **Model** | A, B |
| **Severity** | Medium |
| **Status** | Partially mitigated |

**Risk.** Large uploads exhaust the disk, the memory or the database.

**Mitigation.** `multer` keeps the upload in memory with a hard limit of
5 MiB (5,242,880 bytes), the JSON body limit is 1 MB, and the general rate
limiter caps the number of requests per client. An upload of exactly
5,242,880 bytes is accepted; one byte more is rejected with `413`.

**Residual.** The blobs are stored in the database, so the upload volume
grows the database. There is no per-user quota and no virus scanning.

**Tests.** `tests/security.test.js` (oversized body),
`tests/documents.test.js` (exact 5 MiB accepted, 5 MiB + 1 rejected).

---

### T-17 — Unbounded growth of the audit table

| | |
| --- | --- |
| **Model** | A, B |
| **Severity** | Low |
| **Status** | Open — operationally |

**Risk.** The audit log grows without limit and slows the application down.

**Mitigation.** The listing is paginated (cursor based for the
administration console, limit 1–500). Every document list and every read
also writes an entry, so the growth rate is proportional to the traffic.

**Needed.** An archiving strategy — a nightly export of the entries older
than N days into a separate table or an object store — and a monitoring
rule on the size of `audit_logs`.

---

### T-18 — The login lockout is per process

| | |
| --- | --- |
| **Model** | A |
| **Severity** | Low |
| **Status** | Open — deployment constraint |

**Risk.** With more than one application instance, the lockout map is not
shared: an attacker gets five attempts per instance, and a restart clears
the lockout completely.

**Mitigation.** The IP-based rate limiter is shared per client IP, and it is
configured per instance as well.

**Needed.** For a multi-instance deployment, move the lockout into the
database or into a shared cache (Redis). This is a deployment decision, not
a code defect.

---

### T-19 — Missing multi-factor authentication

| | |
| --- | --- |
| **Model** | E |
| **Severity** | Medium |
| **Status** | Open — out of scope |

**Risk.** A stolen password is enough to take over an account, including an
administrator account.

**Needed.** A second factor for the administration endpoints at least. This
is a feature, not a defect, and it is not implemented in the current
version.

---

### T-20 — Weak secret management

| | |
| --- | --- |
| **Model** | E |
| **Severity** | Critical |
| **Status** | Mitigated |

**Risk.** A hard-coded session secret lets an attacker forge session cookies
and CSRF tokens.

**Mitigation.** The secret comes from the environment. In production the
process **refuses to start** when `SESSION_SECRET` is missing, shorter than
32 characters, or still the development fallback value. `.env` is
git-ignored, and `.env.example` contains placeholders only. No secret is
written to a log, to a test report or to the documentation.

**Tests.** `tests/security.test.js` (no secret in the responses),
`tests/migrations.test.js`.

---

### T-21 — The seed script against a real database

| | |
| --- | --- |
| **Model** | E |
| **Severity** | High |
| **Status** | Mitigated |

**Risk.** `npm run seed` creates demo accounts with a **static, well-known
password** and demo documents. Running it against a production database
would create an account that everybody knows the password of.

**Mitigation.** The script refuses to run when `NODE_ENV` is `test` or
`production`, and the test-suite additionally verifies that the guard is
present in the source.

**Tests.** `tests/migrations.test.js` (the seed guard).

---

### T-22 — Clickjacking and missing security headers

| | |
| --- | --- |
| **Model** | A |
| **Severity** | Low |
| **Status** | Mitigated |

**Risk.** The application can be embedded in a frame of a hostile site, or a
browser feature can be abused.

**Mitigation.** `helmet` with a strict CSP (`frame-ancestors 'none'`),
`X-Frame-Options`, `nosniff`, `Referrer-Policy`, `X-Powered-By` removed,
and HSTS in production.

**Tests.** `tests/csrf.test.js` (the security headers).

---

### T-23 — Missing transport encryption

| | |
| --- | --- |
| **Model** | E |
| **Severity** | Critical |
| **Status** | Open — deployment requirement |

**Risk.** Session cookies, passwords and document contents travel in clear
text.

**Mitigation.** The application refuses to run in production without
`TRUST_PROXY` being configured correctly and sets the `Secure` flag on the
session cookie. The database connection uses TLS.

**Needed.** TLS must be terminated by the reverse proxy, and the proxy has
to pass `X-Forwarded-For` and `X-Forwarded-Proto`. This cannot be verified
from the application code and has to be checked during the deployment.

---

### T-24 — Race between an account role/status change and an in-flight security-sensitive write

| | |
| --- | --- |
| **Model** | D |
| **Severity** | Medium |
| **Status** | Mitigated |

**Risk.** A security-sensitive request that is already being processed when
the account is disabled or demoted still completes with its stale privilege.

**Mitigation.** Disabling an account deletes all of its sessions in the same
transaction, and `requireAuth` re-reads the account on **every** request and
refuses a disabled account even if a session row survived. Document upload,
grant, revoke, edit and delete now revalidate the actor inside their write
transaction after acquiring a `FOR SHARE` lock on the actor's `users` row and,
for document writes, a `FOR UPDATE` lock on the document. Administrator
account creation uses the same actor revalidation. The lock order is audit
chain -> actor -> document, matching the account-management service, so a
concurrent demotion or disable either commits before the write or waits until
it has finished. `tests/concurrency.test.js` holds the account row with
`FOR UPDATE`, waits for PostgreSQL to report the request's `FOR SHARE` lock
wait, then commits the demotion/disable and proves the write is refused.

**Residual.** A read or download that has already passed its authorization
check may still complete; aborting it would require cancelling an in-flight
database query. Self-service writes such as password change and request
cancellation are not transactionally revalidated. Both are **Low** residual
risks because they cannot create new document access or administrative
authority.

**Tests.** `tests/concurrency.test.js`, `tests/security.test.js` (the old
cookie is worthless), `tests/authorization.test.js` (a session that survived
is refused with `403`).

---

### T-25 — A duplicate grant row weakens the access list

| | |
| --- | --- |
| **Model** | C |
| **Severity** | Medium |
| **Status** | Mitigated |

**Risk.** With several rows per user and document, a revoked permission can
survive in a second row — the user keeps access after the "revocation".

**Mitigation.** `UNIQUE (document_id, user_id)` on `document_permissions`,
and the grant endpoint uses an atomic UPSERT that updates the existing row
instead of inserting a second one.

**Tests.** `tests/permissions.test.js` (a second grant is rejected by the
database, the upgrade updates the same row).

---

### T-26 — The audit trail is rewritten by the deletion of a document

| | |
| --- | --- |
| **Model** | E |
| **Severity** | Medium |
| **Status** | Mitigated |

**Risk.** The reference columns of the audit log were foreign keys with
`ON DELETE SET NULL`. Deleting a document therefore rewrote the historic
audit entries — and the append-only trigger rejected that, so the deletion
of a document failed with a database error.

**Mitigation.** The reference columns are plain UUID columns without foreign
keys. The audit trail is independent of the lifecycle of the users and the
documents it refers to; the names are resolved with `LEFT JOIN` at query
time.

Deletion is a permanent hard delete with no restore endpoint or UI. The
deletion audit entry, document metadata, cascaded grants, and the
`document_blobs` row are removed in one transaction, so the database cannot be
left with metadata but no blob or grants. Older audit rows and their hashes
are not rewritten, and the deletion event is retained with the deleted
document id.

The filesystem unlink runs after the commit. If it fails, the database
deletion remains complete, the API returns `storageCleanup: "pending"` with a
message that the stored file could not be removed, and an orphaned local file
may remain. The response never claims complete cleanup in that case. See T-31
for the cleanup limitation.

**Tests.** `tests/documents.test.js` (the deletion removes the document, its
blob and its grants), `tests/deletion-retention.test.js` (audit retention,
unchanged older hashes, verifier result, and a simulated unlink failure),
`tests/security.test.js` (normal cleanup and tampered storage key).

---

### T-27 — Production/test database confusion and test suite data destruction

| | |
| --- | --- |
| **Model** | A, E |
| **Severity** | Critical |
| **Status** | Mitigated |

**Risk.** Automated test suites perform destructive actions: resetting tables,
truncating data, and running triggers. Running tests against production or
development databases would destroy live records or corrupt data.

**Mitigation.** [`src/config.js`](src/config.js) refuses to start when
`NODE_ENV=test` and `TEST_DATABASE_URL` is missing, points at the protected
`neondb` database, equals the development database, or lacks the word `test`
in its database name. The destructive test runner then applies the stricter
guard in [`tests/testDatabaseGuard.js`](tests/testDatabaseGuard.js):
[`tests/globalSetup.js`](tests/globalSetup.js) prints only the resolved host
and database name, and aborts unless the host is a loopback address
(`127.0.0.1`, `localhost`, or `::1`) and the database name is exactly
`trustvault_test`. `resetDatabase()` calls the same guard again so an
individual helper cannot be repointed at another database.

**Residual.** The guard cannot distinguish a developer's own local database
named exactly `trustvault_test` from the dedicated test database; running the
suite against it is destructive by design. Use a dedicated local test
instance or database.

**Tests.** `tests/config.test.js` (fail-closed rejection and dedicated test
database verification), `tests/hardening-regressions.test.js` (the exact
loopback/exact-name guard and the printed target).

---

### T-28 — Backup data corruption, plaintext exposure, and unsafe database restoration

| | |
| --- | --- |
| **Model** | D, F |
| **Severity** | High |
| **Status** | Mitigated |

**Risk.** Document blobs exported in non-standard formats (Buffer JSON objects)
suffer byte corruption during recovery; restore scripts accidentally pointed
at production overwrite live business records; unencrypted remote connections
leak sensitive files in transit.

**Mitigation.** [`tools/backup-database.js`](tools/backup-database.js)
standardizes binary blobs with base64 encoding and SHA-256 integrity digests
(`standardizeBlobRow`), while maintaining backwards-compatibility for legacy
Buffer JSON structures (`extractBlobBuffer`).
[`tools/verify-backup-restore.js`](tools/verify-backup-restore.js)
enforces fail-closed pre-flight isolation: rejects when `NODE_ENV === "production"`,
rejects targets identical to `DATABASE_URL`, rejects databases without `"test"`
or `"restore"` in the name, and strictly blocks protected databases (`postgres`,
`neondb`, `trustvault`, `master`). Remote connections enforce TLS validation
(`rejectUnauthorized: true`). Non-destructive audit verification is performed
on the restored database without mutating records.

**Residual.** Backup archives stored on local disks rely on host filesystem
permissions for access control.

**Tests.** `tests/backup.test.js` (29 assertions validating blob round-tripping,
restore isolation guards, TLS rejection, and archive checksums).

---

### T-29 — Audit chain break obscuration and unauthorized chain rewriting

| | |
| --- | --- |
| **Model** | D, F |
| **Severity** | High |
| **Status** | Mitigated |

**Risk.** Audit verification utilities attempt to automatically "heal" or rebuild
the cryptographic hash chain when encountering a break, erasing historical
tampering evidence or concealing known incidents.

**Mitigation.** [`src/services/auditService.js`](src/services/auditService.js)
and [`tools/inspect-audit-chain.js`](tools/inspect-audit-chain.js)
report broken hash links honestly. For documented historical incident
`INC-2026-438` (entry 438), the verifier marks the overall status truthfully
as `documented_incident`, validates the post-incident segment (entries 439 onward),
and verifies that newly appended entries extend the latest recorded head. No
automatic re-anchoring, truncation, or history rewriting is ever performed during
verification.

**Residual.** A PostgreSQL database superuser with direct SQL access can bypass
the append-only trigger and recompute hash values directly in PostgreSQL.

**Tests.** `tests/audit.test.js` (incident preservation and tamper detection),
`tests/backup.test.js` (non-destructive audit checking), `tests/security.test.js`.

---

### T-30 — Unauthorized document viewing, editing, downloading and sharing (BOLA / IDOR)

| | |
| --- | --- |
| **Model** | B, C |
| **Severity** | Critical |
| **Status** | Mitigated |

**Risk.** An authenticated user guesses a document UUID and attempts to read
metadata, download binary files, edit contents, share permissions, or delete
documents belonging to another account.

**Mitigation.** Centralized authorization in [`src/services/accessService.js`](src/services/accessService.js)
resolves document access per request (`resolveDocumentAccess`). Users without
an explicit grant in `document_permissions` receive `404 Not Found` (preventing
IDOR existence leakage). An `edit` grant permits reading, downloading, and
replacing content, but returns `403 Forbidden` if the user attempts to share,
modify permissions, or delete the document. Administrators have zero implicit
access to documents (returning `404 Not Found`). Search filters are applied on
top of the same authorization predicate; a category-, owner-, or date-only
search cannot widen the caller's result set. Grant, revoke, edit, delete, and
upload revalidate the actor and document inside the write transaction after
locking them, closing the race between authorization and the protected write.

**Residual.** Document owners have full control over their documents. If an owner's
credentials are compromised, an attacker can access all documents owned by that
account.

**Tests.** `tests/authorization.test.js`, `tests/permissions.test.js`,
`tests/documents.test.js`, `tests/search.test.js` (filters preserve the
authorization scope), `tests/concurrency.test.js`.

---

### T-31 — Orphaned file after a failed post-commit unlink

| | |
| --- | --- |
| **Model** | E, F |
| **Severity** | Low |
| **Status** | **Residual — accepted** |

**Risk.** The database deletion commits, but the local file-system unlink fails
(for example because of permissions, a replaced directory, or an I/O error).
The file remains on disk after the document metadata is gone, consuming space
and retaining content that the database no longer references.

**Mitigation.** The unlink result is explicit rather than swallowed. A failed
removal returns `storageCleanup: "pending"` with a message that the stored file
could not be removed, logs only the operating-system error code, and never
claims complete cleanup. The database state remains consistent: metadata,
grants, and the blob row are removed atomically. A successful or already-absent
file returns `storageCleanup: "complete"`. Tests simulate the failure by
replacing the stored file with a directory.

**Residual.** There is no automatic retry, garbage-collection job, or operator
alert for the orphan. The application cannot identify the orphan after the
database row is deleted, so cleanup requires access to the configured upload
directory. The risk is **Low** because the database remains authoritative for
downloads and the file is not served after deletion.

**Tests.** `tests/deletion-retention.test.js` (simulated unlink failure and
honest response), `tests/security.test.js` (tampered storage key).

---

## 5. Summary

| Severity | Threat | Status |
| --- | --- | --- |
| Critical | T-04 Privilege escalation via the role field | Mitigated |
| Critical | T-06 Administrators read every document | Mitigated |
| Critical | T-07 IDOR on the document endpoints | Mitigated |
| Critical | T-10 SQL injection | Mitigated |
| Critical | T-20 Weak secret management | Mitigated |
| Critical | T-23 Missing transport encryption | **Open — deployment** |
| Critical | T-27 Production/test database confusion | Mitigated |
| Critical | T-30 Unauthorized document viewing, editing, downloading and sharing (BOLA/IDOR) | Mitigated |
| High | T-01 Brute force / credential stuffing | Mitigated |
| High | T-03 CSRF | Mitigated |
| High | T-05 The last administrator can be removed | Mitigated |
| High | T-08 Malicious uploads / content-type spoofing | Mitigated |
| High | T-11 Path traversal through the storage key | Mitigated |
| High | T-21 The seed script against a real database | Mitigated |
| High | T-28 Backup data corruption, plaintext exposure, and unsafe restoration | Mitigated |
| High | T-29 Audit chain break obscuration and unauthorized chain rewriting | Mitigated |
| Medium | T-02 Session fixation | Mitigated |
| Medium | T-12 The audit chain is not tamper-proof | **Residual — accepted** |
| Medium | T-13 `TRUNCATE` bypasses the append-only trigger | **Residual — accepted** |
| Medium | T-14 Stored XSS through an uploaded document | Mitigated |
| Medium | T-15 Disclosure of internal details | Mitigated |
| Medium | T-16 Denial of service through the upload endpoint | Partially mitigated |
| Medium | T-19 Missing multi-factor authentication | **Open — out of scope** |
| Medium | T-24 Race between an account role/status change and an in-flight write | Mitigated |
| Medium | T-25 A duplicate grant row weakens the access list | Mitigated |
| Medium | T-26 The audit trail is rewritten by a deletion | Mitigated |
| Low | T-09 Enumeration of disabled accounts | **Residual — accepted** |
| Low | T-17 Unbounded growth of the audit table | **Open — operationally** |
| Low | T-18 The login lockout is per process | **Open — deployment** |
| Low | T-22 Clickjacking and missing headers | Mitigated |
| Low | T-31 Orphaned file after a failed post-commit unlink | **Residual — accepted** |

---

## 6. Deployment checklist

Before the application goes live:

- [ ] `NODE_ENV=production` and a real `SESSION_SECRET` (≥ 32 characters,
      not the development fallback).
- [ ] `DATABASE_URL` points at the production database, `TEST_DATABASE_URL`
      at a different, empty database.
- [ ] TLS is terminated by the reverse proxy; `TRUST_PROXY` matches the
      number of proxies in front of the application.
- [ ] The `Secure` flag is active (implied by `NODE_ENV=production`).
- [ ] The database role of the application has **no** superuser rights and
      cannot drop the schema — that is the only way to make the audit chain
      more than tamper-evident.
- [ ] The database backups are in place and a restore has been tested.
- [ ] An archiving job for `audit_logs` is configured.
- [ ] A procedure exists to monitor `storageCleanup: "pending"` deletion results and remove orphaned files from the configured upload directory.
- [ ] The test target is a loopback host with the exact database name `trustvault_test`; the suite is never pointed at a hosted or development database.
- [ ] The rate limits (`RATE_LIMIT_API`, `RATE_LIMIT_AUTH`) are tuned for
      the expected traffic.
- [ ] `npm run seed` is never part of a production deployment.
