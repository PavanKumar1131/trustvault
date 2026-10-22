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
self-registration and is strictly restricted to authenticated administrators
using `PATCH /api/admin/users/:id/role`. The role change endpoint validates
against an explicit allow-list (`admin`, `document_owner`, `viewer`), forbids
self-demotion, and protects the last active administrator with concurrency locks.
The authenticated role is re-read from the database on every request, ensuring
role changes and account disablement take effect immediately.

**Tests.** `tests/security.test.js` (client role parameter ignored on registration,
default viewer assignment, role escalation attempts rejected),
`tests/authorization.test.js` (role change takes effect without a new login).

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
(`file-type`), not from the name. Only PDF, JPEG and PNG are accepted; a
mismatch is rejected with `415` before anything is stored. Downloads are
served as an `attachment` with `X-Content-Type-Options: nosniff` and
`Cache-Control: no-store`.

**Residual.** Polyglot files (a valid PDF that also contains HTML) are still
possible; the `attachment` disposition and `nosniff` are what contain them.

**Tests.** `tests/security.test.js` (spoofed file), `tests/documents.test.js`.

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

**Mitigation.** `multer` keeps the upload in memory with a hard size
limit, the JSON body limit is 1 MB, and the general rate limiter caps the
number of requests per client.

**Residual.** The blobs are stored in the database, so the upload volume
grows the database. There is no per-user quota and no virus scanning.

**Tests.** `tests/security.test.js` (oversized body).

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

### T-24 — Race between disabling an account and an in-flight request

| | |
| --- | --- |
| **Model** | D |
| **Severity** | Medium |
| **Status** | Mitigated |

**Risk.** A request that is already being processed when the account is
disabled still completes.

**Mitigation.** Disabling the account deletes all of its sessions in the
same transaction, and `requireAuth` re-reads the account on **every**
request and refuses a disabled account even if a session row survived. A
request that was already past the authorisation check is not aborted — that
would require cancelling the database query — but it cannot start a new
one.

**Tests.** `tests/security.test.js` (the old cookie is worthless),
`tests/authorization.test.js` (a session that survived is refused with
`403`).

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

**Tests.** `tests/documents.test.js` (the deletion removes the document, its
blob and its grants).

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
| High | T-01 Brute force / credential stuffing | Mitigated |
| High | T-03 CSRF | Mitigated |
| High | T-05 The last administrator can be removed | Mitigated |
| High | T-08 Malicious uploads / content-type spoofing | Mitigated |
| High | T-11 Path traversal through the storage key | Mitigated |
| High | T-21 The seed script against a real database | Mitigated |
| Medium | T-02 Session fixation | Mitigated |
| Medium | T-12 The audit chain is not tamper-proof | **Residual — accepted** |
| Medium | T-13 `TRUNCATE` bypasses the append-only trigger | **Residual — accepted** |
| Medium | T-14 Stored XSS through an uploaded document | Mitigated |
| Medium | T-15 Disclosure of internal details | Mitigated |
| Medium | T-16 Denial of service through the upload endpoint | Partially mitigated |
| Medium | T-19 Missing multi-factor authentication | **Open — out of scope** |
| Medium | T-24 Race between disabling and an in-flight request | Mitigated |
| Medium | T-25 A duplicate grant row weakens the access list | Mitigated |
| Medium | T-26 The audit trail is rewritten by a deletion | Mitigated |
| Low | T-09 Enumeration of disabled accounts | **Residual — accepted** |
| Low | T-17 Unbounded growth of the audit table | **Open — operationally** |
| Low | T-18 The login lockout is per process | **Open — deployment** |
| Low | T-22 Clickjacking and missing headers | Mitigated |

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
- [ ] The rate limits (`RATE_LIMIT_API`, `RATE_LIMIT_AUTH`) are tuned for
      the expected traffic.
- [ ] `npm run seed` is never part of a production deployment.
