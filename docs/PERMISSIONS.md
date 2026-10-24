# TrustVault — Permissions & Authorization Model

This document specifies the server-enforced permissions, role models, and document access control rules implemented in TrustVault.

The single source of truth for document authorization in the backend is [`src/services/accessService.js`](../src/services/accessService.js). System-level role and authentication checks are enforced by [`src/middleware/auth.js`](../src/middleware/auth.js).

---

## 1. System Roles

TrustVault recognizes three mutually exclusive user roles stored in the `users.role` column:

| Role | Intended Audience | Core Purpose |
| --- | --- | --- |
| `viewer` | Standard recipient | Discovers and reads documents explicitly shared with them. Can edit document contents only if granted explicit `edit` permission. Cannot upload, share, or delete documents. |
| `document_owner` | Document author / creator | Creates and manages their own documents. Grants and revokes granular permissions to other users. Has no administrative privileges over accounts or the global audit trail. |
| `admin` | System administrator | Manages user accounts (roles, disable/enable status), reviews global system audit logs, and monitors cryptographic audit chain integrity. **Receives no implicit access to document content or metadata.** |

---

## 2. Public Registration & Role Assignment

Public self-registration is handled via `POST /api/auth/register`:

- **Strict Default Role**: The registration handler in [`src/routes/auth.js`](../src/routes/auth.js) strictly assigns the `viewer` role to every new account.
- **Client Role Parameter Ignored**: Any `role` parameter supplied in the registration request payload is ignored. Users cannot self-promote to `document_owner` or `admin`.
- **Administrative Role Elevation**: Account promotion to `document_owner` or `admin` must be performed by an existing administrator through the protected endpoint `PATCH /api/admin/users/:id/role`.

### Viewer → Document Owner Upgrade Workflow

A Viewer may ask for Document Owner access directly from their Profile page instead of waiting for an administrator to initiate a role change:

- **Unified Request Store**: The upgrade workflow is managed through the generalized `requests` table (`request_type = 'document_owner_upgrade'`). Viewers submit via `POST /api/requests` (or legacy `POST /api/auth/role-upgrade-request`) and check status via `GET /api/requests/mine` (or legacy `GET /api/auth/role-upgrade-request`).
- **Request Scope & Immutability**: Only `document_owner` can be requested. The server strictly fixes the requested role (`document_owner`), the requester ID, reviewer role (`admin`), and submission timestamps. Client-supplied IDs, roles, or status values are ignored.
- **One Pending Request**: A partial unique index on `(requester_id, request_type) WHERE status = 'pending'` mathematically prevents concurrent duplicate submissions. Subsequent submissions while a request is pending return `409 Conflict` (`REQUEST_PENDING`).
- **Requester Cancellation**: A requester can cancel their own active pending request at any time via `POST /api/requests/:id/cancel`. Once cancelled, the request cannot be approved or rejected.
- **Status is Server-Authoritative**: `GET /api/requests/mine` returns only requests belonging to the authenticated caller. The reviewing administrator's user ID is omitted from requester views.
- **Rejection Cooldown**: If an administrator rejects a request, a 7-day cooldown is initiated based on server time (`NOW()`). Any submission attempt within 7 days is rejected with `429 Too Many Requests` (`REQUEST_COOLDOWN` or legacy `ROLE_UPGRADE_COOLDOWN`) and includes `nextEligibleAt` and a `Retry-After` header.
- **Atomic Administrative Review**: Only active administrators may list (`GET /api/admin/requests`) and decide requests (`POST /api/admin/requests/:id/approve` or `:id/reject`). Administrators cannot decide their own requests. A decision locks the requester row, request row, and audit chain in a single transaction; concurrent decisions yield exactly one winner.
- **Direct Role Changes Settle Pending Requests**: Executing `PATCH /api/admin/users/:id/role` automatically resolves any pending request for that user in the same transaction: assigning `document_owner` approves it; assigning any other role rejects it. If an administrator alters the role directly, a later request approval cannot overwrite the independently assigned role.
- **Cryptographic Audit Logging**: Submission, cancellation, approval, rejection, and denied attempts are appended to `audit_logs` with server-derived actor and target IDs. If the audit append fails, the entire transaction rolls back. Existing audit records and historical incident `INC-2026-438` remain untouched.
- **Immediate Effect Without Re-login**: The `requireAuth` middleware re-queries the `users` table on each incoming request, so an approved role takes effect on the very next HTTP call without requiring the user to log out.

---

## 3. Document Authorization Matrix

Document access is computed dynamically per request by `resolveDocumentAccess(user, documentId)` in [`src/services/accessService.js`](../src/services/accessService.js). Because the database is queried on every request, permissions changes and revocations take effect immediately.

### Action Permissions by Effective Access Level

| Capability / Action | Document Owner (`owner`) | Explicit Edit Grant (`edit`) | Explicit Read Grant (`read`) | No Grant / Unrelated User (`none`) | Admin (without explicit grant) |
| --- | :---: | :---: | :---: | :---: | :---: |
| View metadata & detail | Yes | Yes | Yes | No (404) | No (404) |
| Download binary file | Yes | Yes | Yes | No (404) | No (404) |
| Edit title & description | Yes | Yes | No (403) | No (404) | No (404) |
| Replace binary file content | Yes | Yes | No (403) | No (404) | No (404) |
| Manage permissions (grant/revoke) | Yes | No (403) | No (403) | No (404) | No (404) |
| View document activity audit log | Yes | No (403) | No (403) | No (404) | No (404) |
| Permanently delete document | Yes | No (403) | No (403) | No (404) | No (404) |

> [!IMPORTANT]
> **Administrator Document Isolation**
> Administrators receive **no implicit access** to document contents or document metadata. If an administrator attempts to access a document that has not been explicitly shared with their user account by the document owner, the server responds with `404 Not Found`.

---

## 4. Document Ownership & Lifecycle

### Upload (`POST /api/documents/upload`)
- Restricted by middleware `requireRole("document_owner")`.
- Accepts multipart form data with a single binary file (`.pdf`, `.jpg`, `.jpeg`, `.png`, max 5 MB).
- Validates the actual MIME type against file magic numbers using `file-type`.
- Sets `d.owner_id = req.user.id`.
- Stores the binary payload in `document_blobs` and updates the local write-through cache.
- Records an audit event `document_upload` with outcome `success`.

### Document Deletion (`DELETE /api/documents/:id`)
- Only the document owner (`canDelete = true`) can delete the document.
- Deletion is permanent and executes in a single transaction:
  1. Deletes associated grants from `document_permissions`.
  2. Deletes binary content from `document_blobs`.
  3. Deletes local cached file from disk if present.
  4. Deletes the document record from `documents`.
  5. Records an immutable audit log entry `DOCUMENT_DELETED`.
- Historical audit rows in `audit_logs` referencing this document remain intact because foreign key constraints do not use `ON DELETE CASCADE` or `ON DELETE SET NULL` on audit log reference columns.

### Known Owner-Demotion Limitation
When an administrator demotes an account from `document_owner` to `viewer` using `PATCH /api/admin/users/:id/role`:
- **Upload access disabled**: The account loses the ability to upload new documents (`POST /api/documents/upload` requires `requireRole("document_owner")`), and the "Upload" button and "My Documents" navigation entries are hidden in the UI.
- **Retained ownership of previously uploaded documents**: In the database schema, existing records in `documents` retain their original `owner_id = user.id`. Because `resolveDocumentAccess()` checks `isOwner = (document.owner_id === user.id)`, the demoted account **retains owner privileges** (read, download, edit, share, delete) over all documents it authored prior to demotion.
- **Operational guidance**: If an administrator intends to revoke access to existing documents when demoting an owner, the administrator should either:
  1. Transfer ownership or delete the documents prior to demoting the user; or
  2. Disable the account entirely via `PATCH /api/admin/users/:id/disable` if all system access must be terminated immediately.

---

## 5. Sharing, Grants & Revocation

Document sharing is controlled exclusively by document owners via `POST /api/documents/:id/permissions` and `DELETE /api/documents/:id/permissions/:userId`.

### Explicit Grant Semantics
- **Allowed Permissions**: `'read'` or `'edit'`. Any other value is rejected with `400 Bad Request`.
- **Target Resolution**: Identified by `userId` or `email`. The target user must exist in the database.
- **Self-Grant Prevention**: Owners cannot grant permissions to themselves (rejected with `400 Bad Request`).
- **Upsert Deduplication**: The `document_permissions` table enforces a `UNIQUE(document_id, user_id)` constraint. Granting permission to a user who already holds a grant updates the existing row rather than inserting duplicate records (`ON CONFLICT (document_id, user_id) DO UPDATE`).
- **Principle of Least Privilege**: An `edit` grant permits reading, downloading, metadata edits, and file replacement. **An edit grant never implies permission to share, change permissions, or delete the document.**

### Revocation Semantics
- Document owners can revoke grants by sending `DELETE /api/documents/:id/permissions/:userId`.
- The database row in `document_permissions` is deleted immediately.
- Because `resolveDocumentAccess()` queries `document_permissions` on every incoming HTTP request, the revoked user loses access on their next request without needing a session restart or token invalidation.

---

## 6. User Administration Safeguards

Administrators manage users through `/api/admin/*`, guarded by `requireAuth` and `requireRole("admin")`.

### Role Changes (`PATCH /api/admin/users/:id/role`)
- Accepts `role` in `["admin", "document_owner", "viewer"]`.
- **Self-Demotion Guard**: An administrator cannot change their own role (rejected with `400 Bad Request`).
- **Last Active Admin Guard**: The system prevents demoting the last active administrator. Inside a database transaction locked with `pg_advisory_xact_lock(918273645)`, the count of active admins (`role = 'admin' AND is_disabled = FALSE`) is verified. If the count is 1 and the target is that admin, the change is rejected with `409 Conflict`.
- Records an audit event `USER_ROLE_CHANGED`.

### Account Disabling (`PATCH /api/admin/users/:id/disable`)
- Accepts `{ "disabled": true | false }`.
- **Self-Disable Guard**: An administrator cannot disable their own account (rejected with `400 Bad Request`).
- **Last Active Admin Guard**: An administrator cannot disable the last active administrator (rejected with `409 Conflict`).
- **Session Revocation**: Disabling an account immediately deletes all active server sessions from `session` where the session payload references the target user ID.
- **Immediate Denial**: The `requireAuth` middleware re-reads `is_disabled` from the `users` table on every request. Even if an in-flight request presents a valid session cookie, `requireAuth` destroys the session and returns `403 Forbidden` with error code `ACCOUNT_DISABLED`.
- Records an audit event `USER_DISABLED` or `USER_ENABLED`.

---

## 7. Frontend Role Navigation Alignment

The client-side interface in [`public/js/app.js`](../public/js/app.js) and [`public/index.html`](../public/index.html) aligns with the server authorization matrix:

| Navigation Item / Control | `admin` | `document_owner` | `viewer` | Server Enforcement |
| --- | :---: | :---: | :---: | --- |
| **Dashboard** (`#nav-dashboard`) | Visible (Admin Overview) | Visible (Owner Overview) | **Hidden** | `GET /api/admin/overview` requires `admin`; `GET /api/documents/my` requires `document_owner` |
| **My Documents** (`#nav-documents`) | **Hidden** | Visible | **Hidden** | `GET /api/documents/my` returns `403` for non-owners |
| **Upload Nav** (`#nav-upload`) | **Hidden** | Visible | **Hidden** | `POST /api/documents/upload` returns `403` for non-owners |
| **Upload Button** (`#btn-new-upload`) | **Hidden** | Visible | **Hidden** | Embedded in My Documents view; guarded by backend |
| **Shared With Me** (`#nav-shared`) | Visible | Visible | Visible | `GET /api/documents/shared` requires authentication |
| **Search** (`#nav-search`) | Visible | Visible | Visible | `GET /api/documents/search` scopes results to authorized files |
| **Profile "My Requests"** (`#my-requests-section`) | Visible | Visible | Visible | `GET /api/requests/mine` scoped strictly to caller's own account |
| **Admin Section** (`#nav-section-admin`) | Visible | **Hidden** | **Hidden** | Entire `/api/admin/*` subtree returns `403` for non-admins |
| **Audit Log** (`#nav-admin-audit`) | Visible | **Hidden** | **Hidden** | `GET /api/admin/audit` returns `403` for non-admins |
| **Users Console** (`#nav-admin-users`) | Visible | **Hidden** | **Hidden** | `GET /api/admin/users` returns `403` for non-admins |
| **Admin Requests** (`#nav-admin-requests`) | Visible | **Hidden** | **Hidden** | `GET /api/admin/requests` returns `403` for non-admins |

### Default Views on Sign-In
- **`admin`**: Lands on `dashboard` (System stats, chain integrity card, recent audit events).
- **`document_owner`**: Lands on `dashboard` (Owned documents summary, upload CTA, recent activity).
- **`viewer`**: Lands on `shared` (Shared document list, read/edit status indicators).
