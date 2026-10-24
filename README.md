# TrustVault

TrustVault is a secure, multi-tenant document vault web application built with security engineering principles at its core. Users upload confidential documents, maintain strict ownership, and grant granular, revocable access to specific accounts. Every state-changing action is permanently recorded in a tamper-evident, cryptographic SHA-256 hash-chained audit trail.

---

## Table of Contents

- [Architectural Overview](#architectural-overview)
- [Technology Stack](#technology-stack)
- [Documentation Index](#documentation-index)
- [Prerequisites](#prerequisites)
- [Local Installation & Configuration](#local-installation--configuration)
- [Safe Database Setup & Migrations](#safe-database-setup--migrations)
- [Running the Application](#running-the-application)
- [User Roles & Access Control Model](#user-roles--access-control-model)
- [Core Workflows](#core-workflows)
  - [Document Lifecycle: Upload, Sharing & Revocation](#document-lifecycle-upload-sharing--revocation)
  - [Role Upgrade & Generalized Requests](#role-upgrade--generalized-requests)
  - [Cryptographic Audit Chain & Incident Handling](#cryptographic-audit-chain--incident-handling)
- [Testing & Verification](#testing--verification)
- [Deployment Prerequisites & Operational Limitations](#deployment-prerequisites--operational-limitations)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Architectural Overview

TrustVault is structured with defense-in-depth security layers:

```
┌─────────────────────────────────────────────────────────────┐
│ Browser Client (public/js/app.js & api.js)                  │
│  - Vanilla JavaScript, CSS custom properties, zero bundlers │
│  - HttpOnly session cookies, dynamic CSRF double-submit     │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTPS / TLS
┌──────────────────────────────▼──────────────────────────────┐
│ Express Application Layer (src/app.js)                       │
│  - Helmet security headers & Content Security Policy (CSP)  │
│  - Tiered rate limiters (auth brute-force vs general API)   │
│  - Session authentication & fail-closed access checks       │
└──────────────────────────────┬──────────────────────────────┘
                               │ PostgreSQL wire protocol / TLS
┌──────────────────────────────▼──────────────────────────────┐
│ Database Layer (PostgreSQL / Neon)                          │
│  - Row-level consistency, advisory transaction locking     │
│  - Immutable audit trail with append-only triggers          │
│  - SHA-256 forward-linked cryptographic hash chain          │
└─────────────────────────────────────────────────────────────┘
```

---

## Technology Stack

- **Runtime**: Node.js `>= 20.0.0` (developed and verified on Node 24 LTS)
- **Web Framework**: Express 4.x
- **Database**: PostgreSQL (supports both local PostgreSQL and hosted serverless instances such as Neon)
- **Database Client**: `pg` (node-postgres) with connection pooling and SSL enforcement
- **Session Management**: `express-session` with PostgreSQL session storage (`connect-pg-simple`)
- **CSRF Defense**: `csrf-csrf` (v4) double-submit cookie protection bound to server-side session IDs
- **Password Hashing**: `bcrypt` (12 rounds) with strict byte-length limit enforcement
- **File Validation**: `file-type` for content sniffing via binary magic numbers (independent of file extensions)
- **Frontend**: Vanilla ES2022 JavaScript, semantic HTML5, and responsive CSS (zero external client framework dependencies)
- **Test Framework**: Jest with `supertest` for integration tests and `jest-environment-jsdom` for DOM testing

---

## Documentation Index

| Document | Purpose |
| :--- | :--- |
| [`docs/API.md`](docs/API.md) | Complete HTTP API reference, request/response formats, validation, and status codes |
| [`docs/PERMISSIONS.md`](docs/PERMISSIONS.md) | Role specifications, granular document authorization matrix, and owner demotion limits |
| [`docs/AUDIT.md`](docs/AUDIT.md) | Cryptographic hash-chain architecture, concurrency locks, and incident `INC-2026-438` |
| [`docs/TESTING.md`](docs/TESTING.md) | Test execution guide, test database isolation guards, and suite breakdown |
| [`THREATS.md`](THREATS.md) | Comprehensive 30-point threat model, attack vectors, mitigations, and residual risks |
| [`PROMPTS.md`](PROMPTS.md) | Verifiable log of genuine AI-assisted development prompts and engineering outcomes |

---

## Prerequisites

1. **Node.js**: Version 20.x or newer (`node --version`).
2. **PostgreSQL Server**: A running PostgreSQL instance (local or hosted, e.g., Neon).
3. **Dedicated Test Database**: A separate, isolated PostgreSQL database whose name contains `test` (e.g., `trustvault_test`). The test suite performs schema teardown and table truncations; testing against production or development databases is blocked by fail-closed code guards.

---

## Local Installation & Configuration

1. **Clone the repository and install dependencies**:
   ```bash
   git clone <repo-url>
   cd trustvault
   npm install
   ```

2. **Configure environment variables**:
   Copy the example environment template to `.env`:
   ```bash
   cp .env.example .env
   ```

3. **Generate a cryptographically secure session secret**:
   ```bash
   node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
   ```

4. **Populate `.env` with connection settings**:
   ```env
   PORT=3000
   NODE_ENV=development

   # Primary application database
   DATABASE_URL="postgresql://postgres:<password>@localhost:5432/trustvault?sslmode=disable"

   # Mandatory isolated test database (must include 'test' in the database name)
   TEST_DATABASE_URL="postgresql://postgres:<password>@localhost:5432/trustvault_test?sslmode=disable"

   # Secret used to sign session cookies and derive CSRF secrets (>= 32 chars)
   SESSION_SECRET="your-generated-session-secret-here"

   # Rate limiting parameters
   RATE_LIMIT_API=1000
   RATE_LIMIT_AUTH=30
   TRUST_PROXY=1
   ```

> [!WARNING]
> **Production Protection & Guard Rails**
> In `NODE_ENV=production`, the application refuses to start if `DATABASE_URL` or `SESSION_SECRET` is missing or uses the default development secret. Never commit `.env` or paste real database credentials into documentation.

---

## Safe Database Setup & Migrations

TrustVault uses an idempotent migration architecture:

### 1. Apply Canonical Schema & Upgrades
```bash
npm run migrate
```
- Applies [`src/schema.sql`](src/schema.sql) using `CREATE TABLE IF NOT EXISTS` and idempotent index declarations.
- Safely migrates legacy role-upgrade rows into the unified `requests` table.
- **Audit Safety Guarantee**: `migrate.js` **never** rewrites, truncates, re-hashes, or modifies existing records in `audit_logs` or `audit_chain_state`.

### 2. Verify Schema Synchronization
```bash
npm run schema:sync
```
Regenerates [`src/scripts/schema.sql`](src/scripts/schema.sql) to ensure it remains a byte-identical copy of [`src/schema.sql`](src/schema.sql). The automated test suite enforces this check to catch schema drift.

### 3. Development Seeding (Local Development ONLY)
```bash
npm run seed
```
> [!CAUTION]
> **Safety Restrictions on Database Seeding**
> - The seed script populates sample demo accounts (`admin@trustvault.local`, `owner@trustvault.local`, `viewer@trustvault.local`) with static credentials and uploads sample documents.
> - **Overwrites Existing Accounts**: `seed.js` updates credentials and roles of matching demo emails via `ON CONFLICT (LOWER(email)) DO UPDATE`.
> - **Audit Re-anchoring**: Calling `seed.js` invokes `rebuildAuditChainIfNeeded()`, re-anchoring the audit chain state.
> - **Strict Environment Guards**: `seed.js` **refuses to run** when `NODE_ENV=production` or `NODE_ENV=test`, and aborts if `DATABASE_URL` targets a test database. **Never execute `npm run seed` against production or customer databases.**

---

## Running the Application

### Development Server (with Auto-Restart)
```bash
npm run dev
```

### Production Start
```bash
npm start
```
The server binds by default to `http://localhost:3000`.

---

## User Roles & Access Control Model

TrustVault enforces role-based and document-level authorization across three distinct roles:

| Role | Core Purpose & Scope | Document Content Access | Admin Capabilities |
| :--- | :--- | :--- | :--- |
| **`viewer`** | Default self-registered role. Discovers and views documents explicitly shared with them. Can edit document contents only if granted explicit `edit` permission. | **Scoped**: Only explicitly shared documents | None |
| **`document_owner`** | Document author. Can upload new documents, update metadata, replace files, manage sharing grants, and permanently delete owned files. | **Full**: All owned files + shared files | None |
| **`admin`** | System administrator. Manages user accounts, enforces role modifications, disables accounts, reviews system audit logs, and monitors audit chain integrity. | **None**: No implicit access to private document contents or metadata (returns `404 Not Found`) | Full user administration & audit log inspection |

---

## Core Workflows

### Document Lifecycle: Upload, Sharing & Revocation

1. **Upload (`POST /api/documents/upload`)**:
   - Only accounts with role `document_owner` can upload. Attempted uploads by `viewer` or `admin` return `403 Forbidden`.
   - Multipart file payload must not exceed 5 MB.
   - The server inspects the binary magic bytes via `file-type` to detect the true MIME type (`application/pdf`, `image/png`, `image/jpeg`).
   - The file is saved to PostgreSQL `document_blobs` and written to local write-through cache.
   - An immutable audit entry `document_upload` is recorded.

2. **Granular Sharing (`POST /api/documents/:id/permissions`)**:
   - Document owners can grant `'read'` or `'edit'` access to other registered users by email or user ID.
   - Self-grants are rejected (`400 Bad Request`).
   - Database enforces `UNIQUE(document_id, user_id)`. Adding a grant for an existing user updates the permission level without duplicate rows.
   - **Principle of Least Privilege**: An `edit` grant allows content viewing, downloading, and replacing binary contents. **An edit grant never confers permission to share, modify permissions, or delete the document.**

3. **Immediate Access Revocation (`DELETE /api/documents/:id/permissions/:userId`)**:
   - When an owner revokes a grant, the permission row is deleted immediately from `document_permissions`.
   - Because [`src/services/accessService.js`](src/services/accessService.js) checks database state on every incoming request (`resolveDocumentAccess()`), the revoked user loses access on their immediate next HTTP call.

4. **Permanent Deletion (`DELETE /api/documents/:id`)**:
   - Only document owners can delete a document.
   - Deletion removes grants, document blobs, cached disk files, and the document record inside a single transaction.
   - A permanent `DOCUMENT_DELETED` audit event is logged. Reference columns in `audit_logs` use plain UUIDs without cascade constraints, ensuring past audit records remain completely intact.

### Role Upgrade & Generalized Requests

1. **Self-Registration Baseline**:
   - Self-registration (`POST /api/auth/register`) strictly sets `role = 'viewer'`. Client-supplied role parameters are ignored.

2. **Request Submission**:
   - Viewers can request promotion to Document Owner via their Profile page ("My Requests") or `POST /api/requests` with `requestType: "document_owner_upgrade"`.
   - Enforces a single pending request per user (`409 Conflict` on duplicates).
   - If previously rejected, a 7-day cooldown is enforced by server time (`429 Too Many Requests`).
   - Requesters can cancel their own pending requests via `POST /api/requests/:id/cancel`.

3. **Administrative Review**:
   - Administrators review pending requests in the Admin Requests view (`GET /api/admin/requests`).
   - Approval (`POST /api/admin/requests/:id/approve`) promotes the user to `document_owner` immediately.
   - Rejection (`POST /api/admin/requests/:id/reject`) initiates the 7-day cooldown.
   - Direct role changes in the User Console (`PATCH /api/admin/users/:id/role`) automatically settle pending requests in the same transaction.

### Cryptographic Audit Chain & Incident Handling

1. **Forward-Linked Hash Chain**:
   - Every state-changing action writes to `audit_logs`.
   - Each entry computes:
     $$\text{entry\_hash} = \text{SHA-256}(\text{prev\_hash} \parallel \text{actor\_id} \parallel \text{document\_id} \parallel \text{target\_user\_id} \parallel \text{action} \parallel \text{outcome} \parallel \text{canonicalJson(details)})$$
   - JSON keys are sorted recursively to guarantee canonical serialization across platforms.
   - PostgreSQL table triggers reject `UPDATE` and `DELETE` queries on `audit_logs`.

2. **Historical Incident `INC-2026-438`**:
   - Entry 438 contains a documented historical hash chain break.
   - The verification engine in [`src/services/auditService.js`](src/services/auditService.js) reports this status truthfully as `documented_incident`.
   - The verifier validates post-incident continuity (entries 439 to present) and confirms newly appended entries extend the head.
   - **Non-Destructive Guarantee**: Verifiers **never** attempt to rewrite history, recompute past hashes, or truncate entries.

---

## Testing & Verification

Automated regression tests run against the dedicated test database specified by `TEST_DATABASE_URL`:

```bash
# Execute complete regression test suite
npm test
```
*(Equivalent to `npx jest --runInBand`)*

### Test Suite Verification Results
- **Date Verified**: October 24–25, 2026
- **Test Suites**: **15 passed, 15 total**
- **Test Count**: **407 passed, 407 total (0 failures)**
- **Execution Time**: ~421.6 seconds

#### Test Suites Breakdown:
- `tests/config.test.js` — Test database safety guards and environment isolation
- `tests/request-policy.test.js` — Generalized request policies and parameter validation
- `tests/role-upgrade.test.js` — Role upgrade requests, cooldown, and approval lifecycles
- `tests/admin-users.test.js` — Admin user management, multi-parameter search, and filtering
- `tests/migrations.test.js` — Idempotent migrations and schema synchronization
- `tests/frontend.test.js` — UI role routing and client-side logic
- `tests/frontend.dom.test.js` — DOM interactions, modals, and accessibility assertions
- `tests/security.test.js` — Brute force lockout, role escalation defenses, and headers
- `tests/session.test.js` — Session lifecycle, rolling expiration, and cookie attributes
- `tests/csrf.test.js` — CSRF tokens, session binding, and mutating route validation
- `tests/authorization.test.js` — Role boundaries and Admin document isolation
- `tests/permissions.test.js` — Granular document Read/Edit grants and revocation immediacy
- `tests/documents.test.js` — Document CRUD, upload MIME sniffing, and blob deletion
- `tests/audit.test.js` — Cryptographic hash chaining and incident `INC-2026-438` preservation
- `tests/backup.test.js` — Database backup/restore fidelity, isolation guards, and TLS verification

---

## Deployment Prerequisites & Operational Limitations

### Deployment Requirements
1. **Reverse Proxy TLS Termination**: Terminate HTTPS at the reverse proxy (e.g., NGINX, Cloudflare) and configure `TRUST_PROXY=1` so Express accurately detects client IP addresses.
2. **Production Environment**: Set `NODE_ENV=production`. This activates `Secure` cookie attributes, enforces strict session secrets, and disables debug routes.
3. **Database Privileges**: Provision the application database user with least privilege. The user should not have superuser privileges or permissions to drop system schemas.

### Operational Limitations
- **In-Memory Lockouts**: Account lockout tracking (5 failed attempts per 15 minutes) resides in server process memory. Multi-instance horizontal scaling requires migrating lockout counters to a shared memory store (e.g., Redis).
- **Blob Storage Scalability**: Document binaries are stored in the PostgreSQL `document_blobs` table with write-through local caching. For high-throughput production installations with large volumes, migrating blob storage to an S3/GCS object store is recommended.
- **Tamper-Evident, Not Tamper-Proof**: Cryptographic hash chaining detects accidental alteration, partial tampering, or unauthorized record deletion. A database superuser with direct SQL write access could rewrite table records and recompute hashes. Immutable external log streaming provides additional defense.
- **Owner Demotion Limitation**: When an administrator demotes an account from `document_owner` to `viewer`, the user can no longer upload new files, but retains owner-level rights over previously authored documents because `documents.owner_id` remains unchanged. Administrators should reassign or delete an owner's documents prior to demoting the user if access must be revoked.

---

## Troubleshooting

| Problem | Root Cause | Solution |
| :--- | :--- | :--- |
| `Refusing to run tests against database ... does not contain 'test'` | `TEST_DATABASE_URL` points to development or production DB | Configure `TEST_DATABASE_URL` pointing to a distinct database containing `test` in its name (e.g. `trustvault_test`). |
| `relation "requests" does not exist` | Schema migration has not been applied | Run `npm run migrate` to apply canonical DDL and create missing tables. |
| `Invalid or missing CSRF token` (403) | Mutating request (`POST`, `PUT`, `DELETE`) sent without CSRF header | Fetch a token from `GET /api/auth/csrf-token` and supply it in the `x-csrf-token` header. |
| `Too many authentication attempts` (429) | Rate limiter or per-account lockout triggered after failed logins | Wait for the 15-minute sliding window to expire, or use a different client IP / account in local testing. |
| Audit status shows `documented_incident` | Documented break at historical entry 438 | Expected behavior. Incident `INC-2026-438` is preserved for forensic integrity. Entries 439 onward remain continuously verified. |

---

## License

ISC License. See package configuration for details.
