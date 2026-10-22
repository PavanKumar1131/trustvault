# TrustVault — Testing & Verification Guide

This guide describes how to configure, execute, and verify the TrustVault test suites safely, and how the test harness guarantees complete isolation from development and production databases.

---

## 1. Prerequisites & Environment

### Supported Node.js Version
- **Minimum Requirement**: Node.js `>= 20.0.0` (declared in `package.json`).
- **Validated Environment**: Node.js v24.x LTS.

Verify your installed Node version:
```bash
node --version
```

### Dependency Installation
Install runtime dependencies and developer test tooling (`jest`, `supertest`, `jest-environment-jsdom`):
```bash
npm install
```

---

## 2. Environment Configuration (`.env`)

TrustVault reads environment variables from `.env` via `dotenv`. A template is provided in [`.env.example`](file:///c:/trustvault/.env.example).

### Safe Configuration Steps
1. Copy the template to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Generate a secure, high-entropy 32+ byte string for `SESSION_SECRET`:
   ```bash
   node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
   ```
3. Set your development `DATABASE_URL` and dedicated `TEST_DATABASE_URL`.

> [!WARNING]
> **Never Commit Secrets**
> `.env` is ignored by Git in `.gitignore`. Never commit real passwords, database connection strings, or production secrets to version control or documentation.

---

## 3. Test Database Isolation & Safety Guards

Automated tests perform destructive operations: schema resets, table truncations, temporary user creation, mock uploads, and trigger violation checks. To protect production and development data, [`src/config.js`](file:///c:/trustvault/src/config.js) enforces strict, non-bypassable pre-flight safety checks when `NODE_ENV=test`.

### Mandatory Guard Rules
The test harness will **abort execution immediately** if:
1. `TEST_DATABASE_URL` is undefined or empty.
2. `TEST_DATABASE_URL` lacks an extractable database name.
3. `TEST_DATABASE_URL` matches `DATABASE_URL` (refuses to run against the main database).
4. The database name in `TEST_DATABASE_URL` does not contain the substring `test` (case-insensitive check `/test/i`).

### Creating the Dedicated Test Database
In your PostgreSQL instance (local or hosted):
```sql
CREATE DATABASE trustvault_test;
```

In `.env`, configure:
```env
# Development database
DATABASE_URL="postgresql://postgres:password@localhost:5432/trustvault?sslmode=disable"

# Dedicated, isolated test database
TEST_DATABASE_URL="postgresql://postgres:password@localhost:5432/trustvault_test?sslmode=disable"
```

The test runner automatically initializes schemas, tables, triggers, and indices on `trustvault_test` during global test setup via [`tests/globalSetup.js`](file:///c:/trustvault/tests/globalSetup.js).

---

## 4. Running the Test Suites

### Complete Test Suite
Run all automated unit, integration, security, and DOM tests:
```bash
npm test
```
*Note: `npm test` runs `jest --runInBand` to guarantee sequential test execution without concurrency conflicts on the test database.*

### Interactive Watch Mode
Run tests while developing:
```bash
npm run test:watch
```

### Coverage Report
Generate a detailed test coverage report:
```bash
npm run test:coverage
```

---

## 5. Targeted Test Execution

You can run individual test suites or categories directly using `npx jest`:

### Audit Trail & Hash-Chain Verification
Tests canonical JSON serialization, SHA-256 entry hashing, advisory lock serialization, trigger immutability, `TRUNCATE` anchor detection, and historical incident `INC-2026-438` segment verification:
```bash
npx jest tests/audit.test.js --runInBand
```

### Security & Threat Model Mitigations
Tests login brute-force lockouts, password complexity, registration role-escalation defenses, session invalidation on account disablement, security headers (`Helmet`, `CSP`, `nosniff`), and upload MIME validation:
```bash
npx jest tests/security.test.js --runInBand
```

### CSRF Protections
Tests double-submit cookie CSRF validation, session binding, safe read-only routes, and rejection of mutating requests lacking valid tokens:
```bash
npx jest tests/csrf.test.js --runInBand
```

### Authorization & Granular Permissions
Tests explicit Read vs. Edit grants, owner-only actions, revocation immediacy, upsert grant deduplication, and administrator isolation from document content:
```bash
npx jest tests/authorization.test.js tests/permissions.test.js --runInBand
```

### Document Management & Blob Storage
Tests document upload, file type checking, metadata updating, binary replacement, permanent deletion cascading, and download disposition:
```bash
npx jest tests/documents.test.js --runInBand
```

### Sessions & Lifecycle
Tests session generation, session destruction on logout, rolling expiration, and cookie attributes:
```bash
npx jest tests/session.test.js --runInBand
```

### Migrations & Schema Drift
Tests idempotent migration execution (`npm run migrate`), demo seed protection in production/test environments, and schema consistency between `src/schema.sql` and `src/scripts/schema.sql`:
```bash
npx jest tests/migrations.test.js --runInBand
```

### Frontend UI & DOM Interaction
Tests role-based navigation display, upload button hiding for Admin/Viewer, modal workflows, search filtering, and audit log rendering:
```bash
npx jest tests/frontend.dom.test.js tests/frontend.test.js --runInBand
```

---

## 6. Inspection & Operational Verification Tools

TrustVault includes maintenance tools located under `tools/`:

| Tool | Command | Description |
| --- | --- | --- |
| **Audit Inspector** | `node tools/inspect-audit-chain.js` | Connects to the configured database, validates cryptographic continuity, and prints chain head and incident status. |
| **Database Backup** | `node tools/backup-database.js` | Exports a point-in-time JSON snapshot of tables and blobs. |
| **Backup Verification** | `node tools/verify-backup-restore.js` | Verifies full backup and restore round-trip integrity against the test database. |
