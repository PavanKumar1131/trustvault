# TrustVault

### Secure Document Management with Role-Based Access Control and Tamper-Evident Auditing

TrustVault is a secure document vault web application built with security engineering principles at its core. It enables users to upload documents, maintain ownership, grant granular access to specific accounts, and revoke permissions when required. State-changing actions are recorded in a cryptographic SHA-256 hash-chained audit trail.

---

## Live Demo

- **Live Application**: [https://trustvault-mkco.onrender.com](https://trustvault-mkco.onrender.com/)

TrustVault is deployed on **Render** and uses **Neon PostgreSQL** for its hosted database. The live application demonstrates secure authentication, document ownership, controlled sharing, role-based authorization, and tamper-evident audit logging.

---

## Demo Accounts

Use these accounts to explore the primary application roles:

| Role | Email | Password |
|:---|:---|:---|
| **Admin** | `admin@trustvault.local` | `Admin#2026Demo` |
| **Document Owner** | `owner1@trustvault.local` | `Owner1#2026Demo` |
| **Viewer** | `viewer1@trustvault.local` | `Viewer1#2026Demo` |

These credentials are intended exclusively for the isolated demonstration environment. Additional demo accounts are available for multi-user document-sharing workflows.

> [!WARNING]
> **Security Notice**: These demo credentials are intended for public evaluation of the demo environment. Keep the demo database limited to synthetic data, and never reuse these passwords for real accounts. Do not commit `.env`, database connection strings, session secrets, or `demo-credentials.txt` to GitHub.

---

## Table of Contents

- [Project Features](#project-features)
- [Technology Stack](#technology-stack)
- [Architecture Overview](#architecture-overview)
- [Documentation](#documentation)
- [Prerequisites](#prerequisites)
- [Local Installation](#local-installation)
- [Database Setup and Migrations](#database-setup-and-migrations)
- [Running the Application](#running-the-application)
- [User Roles and Access Control](#user-roles-and-access-control)
- [Core Workflows](#core-workflows)
- [Audit Logging and Integrity](#audit-logging-and-integrity)
- [Testing and Verification](#testing-and-verification)
- [Deployment and Operational Limitations](#deployment-and-operational-limitations)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Project Features

- **Secure authentication**: Password hashing using bcrypt (12 rounds) and server-side session management.
- **Role-based access control**: Separate Admin, Document Owner, and Viewer roles, with authorization enforced by the backend.
- **Document ownership**: Owners can upload, manage, share, and delete their own documents.
- **Global document search**: A text term matches document names and descriptions; owner, category, and created-date filters can be combined with or without a text term, always within the caller's authorization scope.
- **Validated file uploads**: Supports PDF, JPEG, and PNG files with server-side magic-byte validation and a hard 5 MiB (5,242,880-byte) limit.
- **Granular document sharing**: Owners can grant individual users read or edit permissions.
- **Permission revocation**: Owners can revoke access, and authorization is checked against the current permission state.
- **Persistent document storage**: Document binaries are stored in PostgreSQL (`document_blobs`), with a local write-through cache.
- **Permanent document deletion**: Owner-only hard deletion removes metadata, grants, and the database blob in one transaction; audit history is retained. A failed post-commit filesystem cleanup is reported explicitly.
- **Role-upgrade requests**: Viewers can request promotion to Document Owner for administrator review.
- **Administrative dashboard**: Administrators can manage accounts, review requests, and inspect audit logs.
- **Tamper-evident audit trail**: SHA-256 hash chaining and database triggers provide integrity checks and protect audit records against updates and deletions.
- **Web security controls**: CSRF protection, Helmet security headers, Content Security Policy, rate limiting, input validation, and fail-closed authorization checks.
- **Automated regression tests**: Jest and Supertest cover authentication, permissions, document workflows, search filters, upload boundaries, deletion retention, concurrency, migrations, and audit behavior.

---

## Technology Stack

| Component | Technology |
|:---|:---|
| **Runtime** | Node.js 20 or newer |
| **Backend framework** | Express.js 5.x |
| **Database** | PostgreSQL / Neon |
| **Database client** | `pg` (node-postgres) |
| **Authentication** | Express sessions and `bcrypt` |
| **Session storage** | PostgreSQL with `connect-pg-simple` |
| **CSRF protection** | `csrf-csrf` |
| **File validation** | `file-type` |
| **Frontend** | HTML5, CSS, Vanilla JavaScript (ES2022) |
| **HTTP security** | Helmet, Content Security Policy, rate limiting |
| **Automated testing** | Jest, Supertest, Jest DOM environment |
| **Application hosting** | Render |
| **Database hosting** | Neon PostgreSQL |

---

## Architecture Overview

TrustVault uses a layered architecture to separate the browser interface, application logic, data persistence, and auditing:

```text
┌──────────────────────────────────────────────┐
│                Browser Client                │
│        HTML5, CSS, Vanilla JavaScript        │
│     Session cookies and CSRF protection      │
└──────────────────────┬───────────────────────┘
                       │ HTTPS / TLS
┌──────────────────────▼───────────────────────┐
│              Express Application             │
│    Authentication and session management     │
│    Validation and access-control middleware  │
│       Document and permission workflows      │
└──────────────────────┬───────────────────────┘
                       │ PostgreSQL / TLS
┌──────────────────────▼───────────────────────┐
│              PostgreSQL / Neon               │
│    Users, documents, blobs and permissions   │
│     Requests, sessions and audit records     │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│            Audit Integrity Layer             │
│   SHA-256 hash chain and database triggers   │
└──────────────────────────────────────────────┘
```

The frontend provides the user interface, but security-sensitive decisions are enforced by the backend. The database stores document metadata, file contents, permissions, sessions, and audit records.

---

## Documentation

| Document | Description |
|:---|:---|
| [`docs/API.md`](docs/API.md) | HTTP API reference, request and response formats, validation, and status codes |
| [`docs/PERMISSIONS.md`](docs/PERMISSIONS.md) | Role definitions and document authorization rules |
| [`docs/AUDIT.md`](docs/AUDIT.md) | Cryptographic audit-chain design, concurrency controls, and historical incident documentation |
| [`docs/TESTING.md`](docs/TESTING.md) | Automated test instructions and database isolation safeguards |
| [`THREATS.md`](THREATS.md) | Threat model, attack vectors, mitigations, and residual risks |
| [`PROMPTS.md`](PROMPTS.md) | Documentation of AI-assisted development prompts and engineering outcomes |

---

## Prerequisites

Before running TrustVault locally, install:

- **Node.js**: Version 20 or newer (`node --version`).
- **PostgreSQL**: A local PostgreSQL server or a hosted PostgreSQL database.
- **Git**: For source control and repository management.
- **A dedicated test database**: A local PostgreSQL database named exactly `trustvault_test` on a loopback host (`127.0.0.1`, `localhost`, or `::1`).

The test suite uses a fail-closed database isolation guard. Before any migration or truncation it prints only the resolved host and database name, and it aborts unless the target is a loopback host and the database name is exactly `trustvault_test`.

---

## Local Installation

### 1. Clone the repository
```bash
git clone <repo-url>
cd trustvault
npm install
```
*(Replace `<repo-url>` with the actual Git repository URL).*

### 2. Configure environment variables
Copy the example environment template:
```bash
cp .env.example .env
```
On Windows PowerShell, you can use:
```powershell
Copy-Item .env.example .env
```
Configure the database URLs and other required settings in `.env`.

### 3. Generate a secure session secret
Run:
```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```
Use the generated value as `SESSION_SECRET`. Keep it private and never commit it to source control.

### 4. Configure the environment
Use the following as a reference and replace the example database connection values with your own local development settings:

```env
PORT=3000
NODE_ENV=development
DATABASE_URL="postgresql://postgres:<password>@localhost:5432/trustvault?sslmode=disable"
TEST_DATABASE_URL="postgresql://postgres:<password>@localhost:5432/trustvault_test?sslmode=disable"
SESSION_SECRET="<your-generated-session-secret>"
RATE_LIMIT_API=1000
RATE_LIMIT_AUTH=30
TRUST_PROXY=1
```

The local application database and test database must be separate. Never use a production database as the test database.

> [!IMPORTANT]
> **Production protection**: In production, TrustVault requires a valid database connection and a strong session secret. Never include real database credentials or secrets in the README.

---

## Database Setup and Migrations

TrustVault uses an idempotent migration architecture.

### Apply the database schema
```bash
npm run migrate
```
The migration process applies the canonical schema and supported upgrades. Its audit-safety design avoids rewriting, truncating, or rehashing existing records in `audit_logs` or `audit_chain_state`.

### Verify schema synchronization
```bash
npm run schema:sync
```
This command checks synchronization between the canonical schema and its maintained copy.

### Development seeding
The seed script is intended for local development only:
```bash
npm run seed
```

> [!CAUTION]
> **Warning**: Do not run `npm run seed` against the hosted demo database or any production database. The script can overwrite matching demo-account credentials and roles and may invoke audit-chain re-anchoring logic. Use the dedicated test database for automated test execution.

---

## Running the Application

### Development server
```bash
npm run dev
```

### Production-style start
```bash
npm start
```

The default local address is: `http://localhost:3000`

---

## User Roles and Access Control

TrustVault enforces role-based authorization and document-level permissions:

| Role | Capabilities | Document Access |
|:---|:---|:---|
| **Viewer** | View documents explicitly shared with the account. Edit only when explicitly granted. | Limited to authorized documents |
| **Document Owner** | Upload and manage owned documents, update metadata, manage permissions, and delete owned files. | Owned documents and documents shared with the account |
| **Admin** | Manage user accounts and roles, review role-upgrade requests, and inspect audit logs. | No automatic access to private document contents |

### Security principles
- New self-registered users receive the Viewer role.
- Clients cannot elevate their own role by changing request parameters.
- Document access is checked by the backend.
- Administrators do not automatically receive private document access.
- Sharing and revocation are scoped to the document owner's authorization.
- Account management supports only Viewer <-> Document Owner transitions. Admin accounts are protected from role and status changes, and an administrator cannot change their own role or status.
- Every role or status change requires a 10-500 character reason and is recorded in the audit trail.
- Demoting a Document Owner does not reassign document ownership. Instead, the demotion creates a Read grant for every document the account owns, so the former owner keeps only explicit read access and cannot rely on the ownership column for owner privileges.

---

## Core Workflows

### 1. Document Upload
Only users with the `document_owner` role can upload documents.
The upload workflow includes:
- Server-side validation of uploaded content using binary magic-number detection, not the file extension or client-supplied MIME type.
- Support for PDF, PNG, and JPEG files only.
- A hard maximum upload size of 5 MiB (5,242,880 bytes) per file; larger uploads are rejected with `413`.
- Storage of document binaries in PostgreSQL's `document_blobs` table.
- Storage of the content type detected from the file bytes. A valid file with a different allowed extension is accepted and typed by its content (for example, a PNG named `.pdf` is stored as `image/png`).
- Audit logging for document upload actions.
- Attempts by unauthorized roles to upload documents are rejected.

The browser file picker also restricts the extension to `.pdf`, `.jpg`, `.jpeg`, and `.png`. The API deliberately treats content, not the extension, as authoritative; extension/content consistency is discussed as a residual risk in [`THREATS.md`](THREATS.md) (T-08).

### 2. Search and Filtering
The Search screen accepts any combination of the following filters:
- **Text term (`q`)**: matches the document name or description. It does not match the category.
- **Category**: exact match, case-insensitive.
- **Owner**: matches the owner's name or email address.
- **From / To dates**: filter on `created_at`. A date-only `to` value includes the whole UTC day.

A category-only, owner-only, date-only, or combined search does not require a text term. The completely empty form shows guidance instead of listing every accessible document. Every search remains limited to documents the caller owns or has been granted, and pagination applies to filtered results.

### 3. Document Sharing
Owners can grant specific registered users read or edit access to a document.
The application prevents self-grants and enforces authorization on the server. An edit permission allows the permitted document operations supported by the application, but does not automatically grant the ability to share the document, manage permissions, or delete it.

### 4. Permission Revocation
Owners can revoke a user's document permissions.
Access is evaluated against current database state, so a revoked user loses access to the affected document on subsequent requests.

### 5. Document Deletion
Only an authorized owner can delete an owned document. Deletion is permanent; there is no restore endpoint or restore UI.
The deletion workflow removes the document metadata, its cascaded permission grants, and its `document_blobs` row in one database transaction, and records a deletion audit event. Older audit entries and their hashes are retained unchanged.
The file-system copy is removed after the transaction commits. If that unlink fails, the database deletion remains complete, the API returns `storageCleanup: "pending"` with a message that the stored file could not be removed, and an orphaned file may remain for operator cleanup. The application does not claim complete cleanup in that case.

### 6. Role-Upgrade Requests
Viewers can request promotion to Document Owner through the application's request interface.
Administrators can review requests and approve or reject them. Approval promotes the user to the requested role, subject to the application's authorization and transaction rules.
Users cannot grant themselves elevated privileges. Direct role changes resolve any pending upgrade request in the same transaction, and a Document Owner demotion creates the legacy Read grants described above.

---

## Audit Logging and Integrity

TrustVault records state-changing actions in a cryptographic SHA-256 hash-chained audit log.

Each record incorporates a hash derived from the previous record and relevant event data. Canonical JSON serialization ensures that details are encoded consistently.
Database triggers reject updates and deletions against audit records, helping preserve historical evidence.

### Historical incident handling
TrustVault documents a historical audit-chain break identified as `INC-2026-438`.
The verifier reports this documented incident transparently and checks continuity after the incident. It does not automatically rewrite historical hashes or truncate audit records to conceal the incident.

The audit chain provides tamper evidence; it should not be described as absolutely tamper-proof against a sufficiently privileged database administrator.

---

## Testing and Verification

Run the automated regression suite:
```bash
npm test
```

Tests must run against the isolated database configured by `TEST_DATABASE_URL`.
The global setup prints only the resolved host and database name before any migration or truncation. The suite aborts unless the target is a loopback host (`127.0.0.1`, `localhost`, or `::1`) and the database name is exactly `trustvault_test`.

The latest Phase 2 local verification on October 25, 2026 recorded:
- **Test suites**: 19 passed
- **Tests**: 448 passed
- **Failures**: 0

The suite covers:
- Authentication and session lifecycle
- CSRF protection and security headers
- Role boundaries, administrator permissions, and guarded account transitions
- Document CRUD and upload validation, including JPEG/PNG handling and the exact 5 MiB boundary
- Document sharing and permission revocation
- Search filters with and without a text term, including owner, category, date, authorization scope, and pagination
- Permanent deletion, audit retention, and explicit filesystem-cleanup reporting
- Concurrency between account demotion/disable and security-sensitive writes
- Role-upgrade requests and approval workflows
- Database migrations and schema synchronization
- Audit-chain verification and historical incident preservation
- Backup and restore safeguards

---

## Deployment and Operational Limitations

### Production configuration
The hosted application uses Render, with Neon PostgreSQL as the database.
The production environment requires the correct configuration for:
- `NODE_ENV=production`
- `DATABASE_URL` pointing to the dedicated application database
- A strong, unique `SESSION_SECRET`
- `TRUST_PROXY=1` when running behind the configured HTTPS reverse proxy

Keep production secrets in the hosting provider's environment settings, not in GitHub.

### Document storage persistence
Document binaries are stored in PostgreSQL (`document_blobs`), with a local write-through cache. Render's local filesystem is ephemeral, but documents remain available after local cache files are lost because the database-backed storage and retrieval workflow serves binary data directly from PostgreSQL.

For high-volume production deployments, an object storage service such as Amazon S3 or Google Cloud Storage may be more suitable for large document collections.

### Operational limitations
- Account lockout counters are held in server-process memory. Multi-instance deployments require a shared store to keep lockout behavior consistent.
- Hash chaining provides tamper evidence, but a sufficiently privileged database administrator may be able to rewrite records and recompute hashes.
- Administrators do not automatically gain access to private document contents.
- Demoting a Document Owner does not reassign document ownership. The demotion creates a Read grant for every document the account owns; owner privileges additionally require the Document Owner role.
- Document deletion is permanent and has no restore workflow. The database metadata, grants, and blob are removed atomically, but the post-commit filesystem unlink is best-effort. If it fails, an orphaned local file can remain and the API reports `storageCleanup: "pending"`; an operator must remove the orphan.
- The API determines the stored file type from content rather than the filename extension. Extension/content consistency is not enforced server-side; the browser restricts the picker to the supported extensions. See T-08 in [`THREATS.md`](THREATS.md).
- Search uses SQL `LIKE` predicates and has no dedicated full-text index. Large document collections may need an index or a dedicated search service.

---

## Troubleshooting

| Problem | Possible Cause | Resolution |
|:---|:---|:---|
| Test database safety check fails | `TEST_DATABASE_URL` does not point at a loopback host and the exact database `trustvault_test` | Use a local PostgreSQL database named exactly `trustvault_test`; do not point the suite at development, production, or hosted databases. |
| A required table does not exist | Migrations have not been applied | Check the database target, then run `npm run migrate` in the appropriate environment. |
| Request rejected with a CSRF error | Missing or invalid CSRF token | Obtain a token using the application's CSRF-token endpoint and submit it using the expected header. |
| Login attempts are rate-limited | Rate limiter or account lockout is active | Follow the configured lockout policy and retry after the applicable interval. |
| Audit verifier reports a documented incident | Historical incident `INC-2026-438` | Consult [`docs/AUDIT.md`](docs/AUDIT.md); do not rewrite historical audit records. |
| A viewer cannot open a document | No valid sharing permission exists, or permission was revoked | Verify the document owner and current permission grant. |
| Deletion response reports `storageCleanup: "pending"` | The database deletion committed, but the local file unlink failed | The document is permanently deleted from the database. Locate the orphaned file in the configured upload directory and remove it with filesystem tooling; no restore is available. |

---

## License

This project is licensed under the ISC License. Refer to the package configuration for details.
