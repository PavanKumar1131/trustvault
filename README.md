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
- **Validated file uploads**: Supports PDF, JPEG, and PNG files with server-side content validation.
- **Granular document sharing**: Owners can grant individual users read or edit permissions.
- **Permission revocation**: Owners can revoke access, and authorization is checked against the current permission state.
- **Persistent document storage**: Document binaries are stored in PostgreSQL (`document_blobs`), with a local write-through cache.
- **Role-upgrade requests**: Viewers can request promotion to Document Owner for administrator review.
- **Administrative dashboard**: Administrators can manage accounts, review requests, and inspect audit logs.
- **Tamper-evident audit trail**: SHA-256 hash chaining and database triggers provide integrity checks and protect audit records against updates and deletions.
- **Web security controls**: CSRF protection, Helmet security headers, Content Security Policy, rate limiting, input validation, and fail-closed authorization checks.
- **Automated regression tests**: Jest and Supertest cover authentication, permissions, document workflows, migrations, and audit behavior.

---

## Technology Stack

| Component | Technology |
|:---|:---|
| **Runtime** | Node.js 20 or newer |
| **Backend framework** | Express.js 4.x |
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
- **A dedicated test database**: A separate database whose name contains `test`, such as `trustvault_test`.

The test suite uses database isolation safeguards to prevent accidental execution against development or production databases.

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
- Administrative role changes require appropriate authorization.

---

## Core Workflows

### 1. Document Upload
Only users with the `document_owner` role can upload documents.
The upload workflow includes:
- Server-side validation of uploaded content.
- Binary magic-number detection rather than reliance on file extensions alone.
- Support for PDF, PNG, and JPEG files.
- A maximum upload size of 5 MB per file.
- Storage of document binaries in PostgreSQL's `document_blobs` table.
- Audit logging for document upload actions.
- Attempts by unauthorized roles to upload documents are rejected.

### 2. Document Sharing
Owners can grant specific registered users read or edit access to a document.
The application prevents self-grants and enforces authorization on the server. An edit permission allows the permitted document operations supported by the application, but does not automatically grant the ability to share the document, manage permissions, or delete it.

### 3. Permission Revocation
Owners can revoke a user's document permissions.
Access is evaluated against current database state, so a revoked user loses access to the affected document on subsequent requests.

### 4. Document Deletion
Only an authorized owner can delete an owned document. The application removes the associated document data and permission records through its supported deletion workflow and records a deletion audit event.

### 5. Role-Upgrade Requests
Viewers can request promotion to Document Owner through the application's request interface.
Administrators can review requests and approve or reject them. Approval promotes the user to the requested role, subject to the application's authorization and transaction rules.
Users cannot grant themselves elevated privileges.

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

The recorded test results in the project documentation for October 24–25, 2026, are:
- **Test suites**: 15 passed
- **Tests**: 407 passed
- **Failures**: 0

*(These are the project's previously recorded results, not a claim that tests were rerun while preparing this README).*

The suite covers:
- Authentication and session lifecycle
- CSRF protection and security headers
- Role boundaries and administrator permissions
- Document CRUD and upload validation
- Document sharing and permission revocation
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
- Demoting a Document Owner does not automatically reassign ownership of previously created documents.

---

## Troubleshooting

| Problem | Possible Cause | Resolution |
|:---|:---|:---|
| Test database safety check fails | `TEST_DATABASE_URL` points to a non-test database | Configure a dedicated database whose name contains `test`. |
| A required table does not exist | Migrations have not been applied | Check the database target, then run `npm run migrate` in the appropriate environment. |
| Request rejected with a CSRF error | Missing or invalid CSRF token | Obtain a token using the application's CSRF-token endpoint and submit it using the expected header. |
| Login attempts are rate-limited | Rate limiter or account lockout is active | Follow the configured lockout policy and retry after the applicable interval. |
| Audit verifier reports a documented incident | Historical incident `INC-2026-438` | Consult [`docs/AUDIT.md`](docs/AUDIT.md); do not rewrite historical audit records. |
| A viewer cannot open a document | No valid sharing permission exists, or permission was revoked | Verify the document owner and current permission grant. |

---

## License

This project is licensed under the ISC License. Refer to the package configuration for details.
