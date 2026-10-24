# TrustVault — API Documentation

This document describes the HTTP API surface of TrustVault. All endpoints are served under `/api` by Express.js.

---

## 1. Global Conventions

### Content Types and Encodings
- All JSON requests must supply `Content-Type: application/json`.
- All JSON responses are UTF-8 encoded with `Content-Type: application/json; charset=utf-8`.
- File upload requests must use `multipart/form-data` with field name `file`.

### Authentication
- Authentication is session-based using an `httpOnly`, `SameSite=Lax` cookie named `trustvault_session`.
- Sessions are maintained server-side in the `user_sessions` PostgreSQL table and use rolling expiration.
- Requests without a valid session cookie receive `401 Unauthorized` with `{ "code": "UNAUTHENTICATED", "message": "Authentication required" }`.
- When an existing session expires or is terminated, the endpoint responds with `401 Unauthorized` and `{ "code": "SESSION_EXPIRED", "message": "Your session has ended. Sign in again to continue." }`.
- A disabled account receives `403 Forbidden` with `{ "code": "ACCOUNT_DISABLED", "message": "This account is disabled. Contact an administrator." }`.

### CSRF Protection
- Mutating HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`) require a CSRF token.
- Fetch the token from `GET /api/auth/csrf-token` and supply it in either the `x-csrf-token` request header or `_csrf` body property.
- Safe read-only methods (`GET`, `HEAD`, `OPTIONS`) and initial authentication entry points (`POST /api/auth/login`, `POST /api/auth/register`, `GET /api/auth/csrf-token`) are exempt from CSRF checks.
- Invalid or missing CSRF tokens return `403 Forbidden` with `{ "message": "Invalid or missing CSRF token" }`.

### Rate Limiting
- **API routes**: By default, limited to 1,000 requests per 15-minute window per IP.
- **Auth routes** (`/api/auth/login`, `/api/auth/register`): Limited to 30 requests per 15-minute window per IP. Exceeding limits returns `429 Too Many Requests`.

---

## 2. Authentication & Profile Routes (`/api/auth`)

### `GET /api/auth/csrf-token`
- **Auth**: None (public).
- **Description**: Generates and returns a double-submit CSRF token bound to the current session cookie.
- **Response `200 OK`**:
  ```json
  {
    "csrfToken": "string"
  }
  ```

### `POST /api/auth/register`
- **Auth**: None (public; rate-limited).
- **Description**: Creates a new user account. Any client-supplied `role` is ignored; all self-registered accounts are assigned the default role `viewer`.
- **Request Body**:
  ```json
  {
    "name": "Jane Smith",
    "email": "jane@company.com",
    "password": "Min12CharsLong!"
  }
  ```
- **Validation**:
  - `name`: String, 1–100 characters.
  - `email`: Valid email format, maximum 255 characters.
  - `password`: String, minimum 12 characters, maximum 72 bytes.
- **Responses**:
  - `201 Created`: User created successfully.
    ```json
    {
      "message": "Registration successful",
      "user": {
        "id": "uuid",
        "name": "Jane Smith",
        "email": "jane@company.com",
        "role": "viewer",
        "created_at": "ISO-8601"
      }
    }
    ```
  - `400 Bad Request`: Validation failure.
  - `409 Conflict`: An account with this email already exists.
  - `429 Too Many Requests`: Rate limit exceeded.

### `POST /api/auth/login`
- **Auth**: None (public; rate-limited).
- **Description**: Authenticates user credentials, clears prior failed attempts upon success, issues a session token, and sets the `trustvault_session` cookie. Implements sliding-window lockout after 5 consecutive failed attempts per email within 15 minutes.
- **Request Body**:
  ```json
  {
    "email": "user@company.com",
    "password": "Password123!"
  }
  ```
- **Responses**:
  - `200 OK`: Successful login.
    ```json
    {
      "message": "Login successful",
      "user": {
        "id": "uuid",
        "name": "User Name",
        "email": "user@company.com",
        "role": "viewer | document_owner | admin"
      }
    }
    ```
  - `400 Bad Request`: Missing email or password.
  - `401 Unauthorized`: Invalid credentials.
  - `403 Forbidden`: Account is disabled.
  - `429 Too Many Requests`: Account temporarily locked or IP rate limit exceeded.

### `GET /api/auth/me`
- **Auth**: Required (`viewer`, `document_owner`, or `admin`).
- **Description**: Returns the identity and role of the currently authenticated session.
- **Responses**:
  - `200 OK`:
    ```json
    {
      "user": {
        "id": "uuid",
        "name": "User Name",
        "email": "user@company.com",
        "role": "viewer | document_owner | admin",
        "created_at": "ISO-8601"
      }
    }
    ```
  - `401 Unauthorized`: Missing, invalid, or expired session.

### `PUT /api/auth/me`
- **Auth**: Required.
- **CSRF**: Required.
- **Description**: Updates the profile name of the authenticated user.
- **Request Body**:
  ```json
  {
    "name": "Updated Name"
  }
  ```
- **Responses**:
  - `200 OK`: Updated user profile.
  - `400 Bad Request`: Name is empty or exceeds 100 characters.

### `POST /api/auth/change-password`
- **Auth**: Required.
- **CSRF**: Required.
- **Description**: Verifies the current password and sets a new password. Terminates all other active sessions for this user.
- **Request Body**:
  ```json
  {
    "currentPassword": "OldPassword123!",
    "newPassword": "NewPassword123!"
  }
  ```
- **Responses**:
  - `200 OK`: `{ "message": "Password changed successfully" }`
  - `400 Bad Request`: New password fails length requirements (12–72 bytes) or matches current password.
  - `401 Unauthorized`: Current password verification failed.

### `GET /api/auth/users`
- **Auth**: Required.
- **Description**: Returns a lightweight list of active users (`id`, `name`, `email`) for sharing autocompletion.
- **Responses**:
  - `200 OK`: `{ "users": [{ "id": "uuid", "name": "...", "email": "..." }] }`

### `GET /api/auth/role-upgrade-request`
- **Auth**: Required.
- **Description**: Returns the authenticated account's own Viewer → Document Owner request. There is no user-id parameter: an account can only ever read its own request. The deciding administrator's identity is not exposed.
- **Response `200 OK`**:
  ```json
  {
    "currentRole": "viewer",
    "request": {
      "id": "uuid",
      "status": "pending | approved | rejected",
      "requestedRole": "document_owner",
      "justification": "Optional text",
      "submittedAt": "2026-10-24T10:00:00.000Z",
      "decidedAt": null,
      "nextEligibleAt": null
    },
    "canSubmit": false,
    "cooldownEndsAt": null,
    "serverTime": "2026-10-24T10:00:01.000Z"
  }
  ```
  `request` is `null` when the account has never submitted one. `canSubmit` is `false` while a request is pending, during the seven-day rejection cooldown, or when the account is not a Viewer. All timestamps are server values.

### `POST /api/auth/role-upgrade-request`
- **Auth**: Required.
- **Permission**: Active `viewer` accounts only.
- **CSRF**: Required.
- **Request Body**:
  ```json
  {
    "role": "document_owner",
    "justification": "Optional, maximum 500 characters"
  }
  ```
  `role` is optional and may only name `document_owner`; any other value is rejected. Every other field (`userId`, `approverId`, `status`, `decidedBy`, …) is ignored. The server always assigns the requesting account and the `pending` status.
- **Responses**:
  - `201 Created`: Request stored as `pending`.
  - `400 Bad Request`: `INVALID_REQUESTED_ROLE` or `INVALID_JUSTIFICATION`.
  - `409 Conflict`: `ROLE_NOT_ELIGIBLE` (account is not a Viewer) or `REQUEST_PENDING` (one request is already pending).
  - `429 Too Many Requests`: `ROLE_UPGRADE_COOLDOWN` after a rejection. The body contains `nextEligibleAt` and the response carries `Retry-After`. The cooldown is evaluated with PostgreSQL's clock; `GET` values are informational only.

### `POST /api/auth/logout`
- **Auth**: Optional (cleans up state regardless).
- **CSRF**: Required if authenticated.
- **Description**: Invalidates the active session in `user_sessions` and clears the cookie.
- **Response `200 OK`**: `{ "message": "Logged out successfully" }`

---

## 3. Document Routes (`/api/documents`)

### `POST /api/documents`
- **Auth**: Required.
- **Permission**: Role `document_owner` only.
- **CSRF**: Required.
- **Request Type**: `multipart/form-data`
  - `file`: Binary file (PDF, JPEG, PNG, max 5 MB).
  - `name`: String, 1–255 characters.
  - `category`: Optional string, max 100 characters.
  - `description`: Optional string, max 2,000 characters.
- **Validation**: Magic bytes are inspected server-side. File extension alone is never trusted.
- **Responses**:
  - `201 Created`: Document created and stored.
  - `400 Bad Request`: Missing file, disallowed MIME type, file exceeds 5 MB.
  - `403 Forbidden`: Caller lacks `document_owner` role (viewers and admins receive 403).

### `GET /api/documents`
- **Auth**: Required.
- **Description**: Returns documents available to the caller.
  - `document_owner`: Owned documents and documents explicitly shared with caller.
  - `viewer` & `admin`: Only documents explicitly shared with caller with active grant.
- **Query Parameters**:
  - `owned`: Boolean string (`"true"` | `"false"`).
  - `q`: Search string matching document name.
  - `category`: Filter by category name.
  - `owner`: Filter by owner user ID.
  - `from`: ISO start date for upload timestamp.
  - `to`: ISO end date for upload timestamp.
  - `page`: Page index (1-based, default 1).
  - `limit`: Page size (1–100, default 20).
- **Response `200 OK`**:
  ```json
  {
    "documents": [
      {
        "id": "uuid",
        "name": "quarterly-report.pdf",
        "category": "Finance",
        "size_bytes": 1048576,
        "owner_id": "uuid",
        "owner_name": "Alice Johnson",
        "owner_email": "alice@company.com",
        "permission": "owner | edit | read",
        "created_at": "ISO-8601"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 42,
      "pages": 3
    }
  }
  ```

### `GET /api/documents/filters`
- **Auth**: Required.
- **Description**: Returns distinct categories and owners accessible to the caller for populating filter controls.
- **Response `200 OK`**:
  ```json
  {
    "categories": ["Finance", "Legal", "Operations"],
    "owners": [{ "id": "uuid", "name": "Alice Johnson", "email": "alice@company.com" }]
  }
  ```

### `GET /api/documents/summary`
- **Auth**: Required.
- **Description**: Aggregates role-appropriate document counters:
  - `ownedCount`: Number of documents owned.
  - `sharedOutCount`: Total active outbound grants issued by caller.
  - `sharedInCount`: Documents shared with the caller.
  - `refusedCount`: Number of refused access attempts on caller's owned documents.
- **Response `200 OK`**: JSON object of counters.

### `GET /api/documents/:id`
- **Auth**: Required.
- **Access Rule**: Caller must be the document owner or hold an active `read` or `edit` grant.
- **Responses**:
  - `200 OK`: Metadata object and caller's permission level.
  - `404 Not Found`: Returned when the document does not exist OR when the caller lacks access (prevents document enumeration).

### `PUT /api/documents/:id`
- **Auth**: Required.
- **CSRF**: Required.
- **Access Rule**: Caller must be the document owner or hold an active `edit` grant.
- **Request Type**: `multipart/form-data` or `application/json`
  - `name`: Updated document name.
  - `category`: Updated category.
  - `description`: Updated description.
  - `file`: Optional replacement file (PDF/JPEG/PNG, max 5 MB).
- **Responses**:
  - `200 OK`: Updated document object.
  - `400 Bad Request`: Invalid input or unacceptable replacement file.
  - `404 Not Found`: Document not found or caller lacks edit permissions.

### `DELETE /api/documents/:id`
- **Auth**: Required.
- **CSRF**: Required.
- **Access Rule**: Document owner only. An `edit` grant holder or administrator cannot delete a document.
- **Responses**:
  - `200 OK`: `{ "message": "Document deleted successfully" }`
  - `403 Forbidden`: Caller holds edit grant or admin role, but is not the owner.
  - `404 Not Found`: Document does not exist or caller lacks access.

### `GET /api/documents/:id/download`
- **Auth**: Required.
- **Access Rule**: Caller must be document owner or hold active `read` or `edit` grant.
- **Responses**:
  - `200 OK`: File binary stream with correct `Content-Type`, `Content-Length`, and `Content-Disposition`.
  - `404 Not Found`: Document does not exist, file blob missing, or caller unauthorized.

### `GET /api/documents/:id/permissions`
- **Auth**: Required.
- **Access Rule**: Document owner only.
- **Responses**:
  - `200 OK`: Array of active permission grants (`user_id`, `name`, `email`, `permission`, `created_at`).
  - `404 Not Found`: Caller is not the document owner.

### `POST /api/documents/:id/permissions`
- **Auth**: Required.
- **CSRF**: Required.
- **Access Rule**: Document owner only.
- **Request Body**:
  ```json
  {
    "email": "colleague@company.com",
    "permission": "read | edit"
  }
  ```
- **Responses**:
  - `200 OK` or `201 Created`: Active grant created or upgraded.
  - `400 Bad Request`: Disallowed permission value or owner attempting to grant to self.
  - `404 Not Found`: Target user email not found or caller is not owner.

### `DELETE /api/documents/:id/permissions/:userId`
### `DELETE /api/documents/:id/permissions/:userId/:permission`
- **Auth**: Required.
- **CSRF**: Required.
- **Access Rule**: Document owner only.
- **Responses**:
  - `200 OK`: `{ "message": "Access revoked successfully" }`
  - `404 Not Found`: Grant does not exist or caller is not owner.

### `GET /api/documents/:id/audit`
- **Auth**: Required.
- **Access Rule**: Document owner only.
- **Description**: Returns recent audit log events scoped specifically to this document (including allowed access and refused attempts).
- **Responses**:
  - `200 OK`: Array of audit events.
  - `404 Not Found`: Caller is not owner.

---

## 4. Generalized Requests Routes (`/api/requests`)

All endpoints under `/api/requests` require an authenticated session (`requireAuth`) and are subject to CSRF protection on mutating requests (`POST`).

### `GET /api/requests/mine`
- **Auth**: Required (`viewer`, `document_owner`, or `admin`).
- **Description**: Returns the caller's complete request history (newest first) along with rejection cooldown indicators.
- **Headers**: Responses include `Cache-Control: no-store, no-cache, must-revalidate, private`.
- **Response `200 OK`**:
  ```json
  {
    "requests": [
      {
        "id": "uuid",
        "requesterId": "uuid",
        "requestType": "document_owner_upgrade",
        "requestedRole": "document_owner",
        "reason": "Need owner privileges to author project documentation.",
        "status": "pending",
        "decisionNote": null,
        "reviewerRole": "admin",
        "decidedBy": null,
        "submittedAt": "2026-10-24T10:00:00.000Z",
        "decidedAt": null,
        "nextEligibleAt": null
      }
    ]
  }
  ```
- **Responses**:
  - `200 OK`: Request array returned.
  - `401 Unauthorized`: Authentication required.
  - `500 Internal Server Error`: Database query failed.

### `POST /api/requests`
- **Auth**: Required (`viewer` for `document_owner_upgrade`).
- **Rate Limit**: Maximum 20 submissions per 15-minute sliding window per client IP.
- **CSRF**: Required (`x-csrf-token` header or `_csrf` body parameter).
- **Description**: Submits a new request. Currently supported `requestType` is `"document_owner_upgrade"`.
- **Request Body**:
  ```json
  {
    "requestType": "document_owner_upgrade",
    "reason": "Brief justification (optional, max 500 characters)"
  }
  ```
- **Validation**:
  - `requestType`: Mandatory string. Currently only `"document_owner_upgrade"` is supported.
  - `reason`: Optional text up to 500 characters.
  - `targetResourceId` / `requestedPermission`: Must be omitted for role upgrade requests.
- **Responses**:
  - `201 Created`: Request submitted successfully.
    ```json
    {
      "message": "Request submitted",
      "request": {
        "id": "uuid",
        "requestType": "document_owner_upgrade",
        "requestedRole": "document_owner",
        "reason": "Brief justification",
        "status": "pending",
        "submittedAt": "ISO-8601"
      },
      "currentRole": "viewer",
      "canSubmit": false
    }
    ```
  - `400 Bad Request`: Invalid request type, invalid payload, or reason exceeding 500 characters.
  - `409 Conflict`: `REQUEST_PENDING` — caller already has an unresolved pending request.
  - `409 Conflict`: `ROLE_NOT_ELIGIBLE` — account role is not eligible to submit this request.
  - `429 Too Many Requests`: `REQUEST_COOLDOWN` — a prior request was rejected within the past 7 days (`Retry-After` header included).

### `POST /api/requests/:id/cancel`
- **Auth**: Required (caller must be the original requester).
- **CSRF**: Required.
- **Description**: Cancels a pending request submitted by the caller. Resolved requests cannot be cancelled.
- **Responses**:
  - `200 OK`:
    ```json
    {
      "message": "Request cancelled",
      "request": {
        "id": "uuid",
        "status": "cancelled",
        "decidedAt": "ISO-8601"
      }
    }
    ```
  - `400 Bad Request`: Request is already resolved (approved, rejected, or cancelled).
  - `404 Not Found`: Request ID does not exist or was submitted by another user.

---

## 5. Administration Routes (`/api/admin`)

All routes under `/api/admin` require an authenticated user with `role === "admin"`. Non-admin callers receive `403 Forbidden` (`{ "message": "Access denied: Administrator privileges required" }`).

### `GET /api/admin/overview`
- **Description**: Returns system-wide metrics and health indicators:
  - `stats`: Total users, total documents, active grants, total audit events, denied events, permission changes.
  - `today`: Permission changes and denied events recorded since start of day UTC.
  - `latestEvents`: Most recent 8 audit events.
  - `worthALook`: Account with most refusals in the past 60 seconds (or `null`).
  - `chainIntegrity`: Verification payload from `verifyAuditChain()`.
- **Response `200 OK`**: JSON metrics payload.

### `GET /api/admin/verify-chain`
- **Description**: Runs live cryptographic verification of the SHA-256 audit log hash chain.
- **Responses**:
  - `200 OK`:
    - Intact chain: `{ "valid": true, "status": "verified", "totalEntries": 580, "latestEntryId": 580 }`
    - Documented break: `{ "valid": false, "status": "documented_incident", "brokenAtId": 438, "incident": { "code": "INC-2026-438" }, "segment2": { "valid": true, "startId": 438, "endId": 580 }, "appendHealth": { "active": true, "extendsLatest": true } }`
  - `503 Service Unavailable`: Database or verifier unreachable (`{ "valid": false, "status": "unavailable" }`).

### `GET /api/admin/audit-logs`
- **Description**: Cursor-paginated audit trail query.
- **Query Parameters**: `limit` (default 50, max 200), `before` (cursor id), `action`, `user`, `outcome` (`success` | `denied` | `failure`), `from`, `to`.
- **Response `200 OK`**:
  ```json
  {
    "logs": [
      {
        "id": 580,
        "action": "document_read",
        "outcome": "success",
        "actor_email": "alice@company.com",
        "document_name": "specs.pdf",
        "created_at": "ISO-8601"
      }
    ],
    "nextCursor": 529
  }
  ```

### `GET /api/admin/audit-filters`
- **Description**: Returns all distinct actions and users currently present in `audit_logs` for filter dropdowns.
- **Response `200 OK`**: `{ "actions": [...], "users": [...] }`

### `GET /api/admin/requests`
- **Description**: Returns paginated list of generalized user requests with search and status filtering. Pending requests sort oldest-first; resolved requests sort newest-first.
- **Query Parameters**:
  - `status`: `pending` (default), `approved`, `rejected`, `cancelled`, `resolved` (all decided states), or `all`.
  - `type`: Filter by request type (e.g. `document_owner_upgrade`).
  - `search`: Case-insensitive substring match against requester name or email.
  - `limit`: 1–100 (default 50).
  - `offset`: 0 or greater (default 0).
- **Response `200 OK`**:
  ```json
  {
    "requests": [
      {
        "id": "uuid",
        "requesterId": "uuid",
        "requester": { "id": "uuid", "name": "...", "email": "...", "role": "viewer", "isDisabled": false },
        "requestType": "document_owner_upgrade",
        "requestedRole": "document_owner",
        "reason": "Need owner privileges to author project documentation.",
        "status": "pending",
        "decisionNote": null,
        "reviewerRole": "admin",
        "decidedBy": null,
        "submittedAt": "2026-10-24T10:00:00.000Z",
        "decidedAt": null,
        "nextEligibleAt": null
      }
    ],
    "total": 1,
    "status": "pending",
    "type": null,
    "limit": 50,
    "offset": 0
  }
  ```

### `POST /api/admin/requests/:id/approve`
- **CSRF**: Required.
- **Description**: Approves a pending request. For `document_owner_upgrade`, promotes the requester to `document_owner`. The account row, request row, and audit append commit atomically within a single transaction.
- **Request Body**:
  ```json
  {
    "decisionNote": "Approved for project documentation lead (optional, max 500 chars)"
  }
  ```
- **Responses**:
  - `200 OK`:
    ```json
    {
      "message": "Request approved",
      "request": {
        "id": "uuid",
        "status": "approved",
        "decisionNote": "Approved for project documentation lead",
        "decidedAt": "ISO-8601"
      },
      "user": {
        "id": "uuid",
        "role": "document_owner"
      }
    }
    ```
  - `400 Bad Request`: Invalid request ID format, decision note exceeding 500 chars, or invalid role transition.
  - `403 Forbidden`: `SELF_DECISION` — an administrator cannot approve their own request.
  - `404 Not Found`: Request does not exist.
  - `409 Conflict`: `REQUEST_NOT_PENDING` (already resolved) or `REQUESTER_ROLE_CHANGED` (the requester is no longer in the prerequisite role).

### `POST /api/admin/requests/:id/reject`
- **CSRF**: Required.
- **Description**: Rejects a pending request without changing the requester's role and initiates a 7-day cooldown on re-requesting.
- **Request Body**:
  ```json
  {
    "decisionNote": "Reason for rejection (optional, max 500 chars)"
  }
  ```
- **Responses**: Same status codes as approval. Returns `nextEligibleAt` timestamp set to 7 days after decision.

### `GET /api/admin/role-upgrade-requests` (Legacy Compatibility)
- **Description**: Backward-compatible route forwarding to the generalized request store filtered by `type=document_owner_upgrade`.
- **Query Parameters**: Same as `GET /api/admin/requests`.
- **Response `200 OK`**: Serialized requests matching legacy shape.

### `POST /api/admin/role-upgrade-requests/:id/approve` (Legacy Compatibility)
- **Description**: Backward-compatible approval route; proxies to `POST /api/admin/requests/:id/approve`.

### `POST /api/admin/role-upgrade-requests/:id/reject` (Legacy Compatibility)
- **Description**: Backward-compatible rejection route; proxies to `POST /api/admin/requests/:id/reject`.

### `GET /api/admin/users`
- **Description**: Returns paginated user directory with document counts, active grants, and account status. Supports multi-field search and filtering.
- **Query Parameters**:
  - `search`: Substring match on name or email (case-insensitive, trimmed).
  - `role`: Filter by role (`admin`, `document_owner`, `viewer`).
  - `status`: Filter by status (`active`, `disabled`).
  - `limit`: 1–100 (default 50).
  - `offset`: 0 or greater (default 0).
  - `page`: Optional 1-based page index (alternative to offset).
  - `pageSize`: Optional page size (alternative to limit).
- **Response `200 OK`**:
  ```json
  {
    "users": [
      {
        "id": "uuid",
        "name": "Jane Smith",
        "email": "jane@company.com",
        "role": "document_owner",
        "is_disabled": false,
        "created_at": "ISO-8601",
        "document_count": 5
      }
    ],
    "total": 14,
    "limit": 50,
    "offset": 0,
    "page": 1,
    "pageSize": 50,
    "hasMore": false
  }
  ```

### `POST /api/admin/users`
- **CSRF**: Required.
- **Description**: Administratively creates a new user with role `viewer` or `document_owner`. The `admin` role cannot be provisioned via this endpoint.
- **Request Body**:
  ```json
  {
    "name": "Robert Taylor",
    "email": "robert@company.com",
    "role": "viewer | document_owner",
    "password": "TemporaryPassword123!"
  }
  ```
- **Responses**:
  - `201 Created`: User created.
  - `400 Bad Request`: Disallowed role (`admin`), duplicate email, or invalid parameters.

### `PATCH /api/admin/users/:id/role`
- **CSRF**: Required.
- **Description**: Changes the role of an existing account. If the account has a pending role-upgrade request, the direct change settles it atomically: assigning `document_owner` approves the request, and any other role rejects it. The role change, the request resolution and both audit entries commit together.
- **Request Body**: `{ "role": "viewer | document_owner | admin" }`
- **Safety Checks**:
  - Administrator cannot change their own role.
  - Demoting an administrator is rejected if they are the last active administrator.
- **Responses**:
  - `200 OK`: Role updated. If a pending request was settled, the body also contains `request: { id, status, decidedAt }`.
  - `400 Bad Request`: Self-demotion rejected or invalid role.
  - `409 Conflict`: Last administrator protection triggered.
  - `500 Internal Server Error`: The transaction was rolled back; neither the role nor the request changed.

### `PATCH /api/admin/users/:id/disable`
- **CSRF**: Required.
- **Description**: Disables or enables a user account. Disabling immediately terminates all active sessions in `user_sessions`.
- **Request Body**: `{ "is_disabled": true | false }`
- **Safety Checks**:
  - Administrator cannot disable their own account.
  - Cannot disable the last active administrator.
- **Responses**:
  - `200 OK`: Updated account state.
  - `400 Bad Request`: Self-disable rejected.
  - `409 Conflict`: Last active administrator protection triggered.

---

## 6. System Health Routes

### `GET /api/health`
- **Auth**: None.
- **Description**: Lightweight liveness probe. Returns `200 OK` with `{ "status": "ok", "uptime": 1234 }`.

### `GET /api/health/db`
- **Auth**: None.
- **Description**: Database readiness probe. Performs a `SELECT 1` query.
- **Responses**:
  - `200 OK`: Database connected and responsive.
  - `503 Service Unavailable`: Database connection failed.
