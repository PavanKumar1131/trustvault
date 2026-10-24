const express = require("express");
const bcrypt = require("bcrypt");
const pool = require("../db");
const { requireAuth } = require("../middleware/auth");
const {
    writeAuditLog,
    verifyAuditChain,
    lockAuditChain
} = require("../services/auditService");
const { escapeLikePattern } = require("../services/documentService");
const {
    passwordProblem: validatePassword,
    generateTemporaryPassword
} = require("../services/passwordPolicy");
const { resolvePendingUpgradeRequest } = require("../services/requestService");

const router = express.Router();

const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** Roles that may be assigned through the administration API. */
const VALID_ROLES = new Set(["admin", "document_owner", "viewer"]);

/**
 * Roles an administrator may assign when *creating* an account.
 *
 * The admin role is intentionally absent: new administrators are promoted
 * from an existing account, never minted directly.
 */
const CREATEABLE_ROLES = new Set(["document_owner", "viewer"]);

/** Account-status values accepted by the user-list filter. */
const VALID_USER_STATUSES = new Set(["active", "disabled"]);

/** Bounds for the user-list search and pagination parameters. */
const MAX_USER_SEARCH_LENGTH = 100;
const MAX_USER_PAGE_SIZE = 100;
const MAX_USER_PAGE = 10000;
const MAX_USER_OFFSET = 1000000;
const DEFAULT_USER_PAGE_SIZE = 50;

/** Advisory lock guarding the "at least one active administrator" invariant. */
const ADMIN_INVARIANT_LOCK_KEY = 918273645;

function validUuid(id) {
    return typeof id === "string" && UUID_PATTERN.test(id);
}

/**
 * Builds an error that the user-list route answers with 400 instead of 500.
 * The message is deliberately about the query parameter, never about SQL.
 */
function invalidUserQuery(message) {
    const error = new Error(message);
    error.status = 400;
    return error;
}

/**
 * Validates the query string of GET /api/admin/users.
 *
 * The endpoint historically accepted `limit` and `offset`; those stay
 * supported. `page` and `pageSize` are an additive, easier to reason about
 * alternative. Supplying either page parameter selects the page-based mode.
 * Every user supplied value is checked before it reaches a query.
 */
function parseUserListQuery(query) {
    const input = query || {};

    const readText = (name) => {
        const value = input[name];
        if (value === undefined) return "";
        if (typeof value !== "string") {
            throw invalidUserQuery(name + " must be a single text value");
        }
        return value.trim();
    };

    const search = readText("search");
    if (search.length > MAX_USER_SEARCH_LENGTH) {
        throw invalidUserQuery(
            "search must be at most " + MAX_USER_SEARCH_LENGTH + " characters"
        );
    }

    const role = readText("role").toLowerCase();
    if (role && !VALID_ROLES.has(role)) {
        throw invalidUserQuery("role must be one of: admin, document_owner, viewer");
    }

    const status = readText("status").toLowerCase();
    if (status && !VALID_USER_STATUSES.has(status)) {
        throw invalidUserQuery("status must be one of: active, disabled");
    }

    const pageMode = input.page !== undefined || input.pageSize !== undefined;
    let limit;
    let offset;
    let page;
    let pageSize;

    if (pageMode) {
        const readPageNumber = (name, fallback, max) => {
            const value = input[name];
            if (value === undefined || value === "") return fallback;
            if (typeof value !== "string" || !/^\d+$/.test(value)) {
                throw invalidUserQuery(name + " must be a positive integer");
            }
            const parsed = Number(value);
            if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > max) {
                throw invalidUserQuery(name + " must be between 1 and " + max);
            }
            return parsed;
        };

        page = readPageNumber("page", 1, MAX_USER_PAGE);
        pageSize = readPageNumber("pageSize", DEFAULT_USER_PAGE_SIZE, MAX_USER_PAGE_SIZE);
        limit = pageSize;
        offset = (page - 1) * pageSize;

        if (offset > MAX_USER_OFFSET) {
            throw invalidUserQuery("page is out of range");
        }
    } else {
        // Preserve the original contract: values that cannot be parsed fall
        // back to the defaults, and the result is clamped to a safe bound.
        limit = Math.min(
            Math.max(parseInt(input.limit || "100", 10) || 100, 1),
            500
        );
        offset = Math.min(
            Math.max(parseInt(input.offset || "0", 10) || 0, 0),
            MAX_USER_OFFSET
        );
        page = Math.floor(offset / limit) + 1;
        pageSize = limit;
    }

    return { search, role, status, limit, offset, page, pageSize };
}

/**
 * Validates the query string of GET /api/admin/role-upgrade-requests.
 *
 * The review panel asks for `pending` and then for the most recent
 * `resolved` entries, so both filters are supported. An invalid status is
 * rejected rather than silently widened to "all".
 */
function parseDateFilter(value) {
    if (typeof value !== "string" || !value.trim()) return null;
    const parsed = new Date(value.trim());
    return Number.isNaN(parsed.getTime()) ? null : parsed;
}

/**
 * Counts the administrators that are still able to administer the system.
 */
async function countActiveAdmins(client = pool) {
    const result = await client.query(
        "SELECT COUNT(*)::int AS cnt FROM users WHERE role = 'admin' AND is_disabled = false"
    );
    return result.rows[0].cnt;
}

/**
 * Removes every server-side session of a user.
 *
 * Called when an account is disabled so that an already issued session cookie
 * stops working immediately instead of only being refused by the next
 * request. The rows are removed from the session store; the cookie itself
 * becomes meaningless because it no longer resolves to a session.
 */
async function invalidateUserSessions(client, userId) {
    const result = await client.query(
        "DELETE FROM user_sessions WHERE sess->>'userId' = $1",
        [userId]
    );
    return result.rowCount || 0;
}

// ── Admin auth guard ──────────────────────────────────────────────────────────
async function requireAdminWithAudit(req, res, next) {
    if (!req.user || req.user.role !== "admin") {
        await writeAuditLog(req, "admin_console_access", "denied", null, {
            path: req.originalUrl,
            role: req.user ? req.user.role : "unauthenticated"
        });
        return res.status(403).json({
            message: "Access denied: Administrator privileges required"
        });
    }
    return next();
}

router.use(requireAuth, requireAdminWithAudit);

// ── GET /api/admin/audit-logs ─────────────────────────────────────────────────
// Supports filtering by outcome, action, and free-text search (q).
// Supports cursor-based pagination: pass ?before=<id> to fetch older entries.
router.get("/audit-logs", async (req, res) => {
    try {
        const params = [];
        const where = [];

        if (
            typeof req.query.outcome === "string" &&
            ["success", "denied", "failure"].includes(req.query.outcome)
        ) {
            params.push(req.query.outcome);
            where.push("al.outcome = $" + params.length);
        }

        if (typeof req.query.action === "string" && req.query.action.trim()) {
            // The wildcards of the search term are matched literally, so that
            // a search for "%" does not return the whole log.
            params.push("%" + escapeLikePattern(req.query.action.trim()) + "%");
            where.push("al.action ILIKE $" + params.length + " ESCAPE '\\'");
        }

        if (typeof req.query.q === "string" && req.query.q.trim()) {
            params.push("%" + escapeLikePattern(req.query.q.trim()) + "%");
            const idx = "$" + params.length;
            where.push(
                "(" +
                "COALESCE(actor.email, '') ILIKE " + idx + " ESCAPE '\\'" +
                " OR COALESCE(actor.name, '') ILIKE " + idx + " ESCAPE '\\'" +
                " OR COALESCE(target.email, '') ILIKE " + idx + " ESCAPE '\\'" +
                " OR COALESCE(doc.name, '') ILIKE " + idx + " ESCAPE '\\'" +
                " OR al.action ILIKE " + idx + " ESCAPE '\\'" +
                ")"
            );
        }

        // "All users" filter: narrows the log to one actor or one target.
        if (typeof req.query.user === "string" && req.query.user.trim()) {
            params.push("%" + escapeLikePattern(req.query.user.trim()) + "%");
            const idx = "$" + params.length;
            where.push(
                "(" +
                "COALESCE(actor.email, '') ILIKE " + idx + " ESCAPE '\\'" +
                " OR COALESCE(actor.name, '') ILIKE " + idx + " ESCAPE '\\'" +
                " OR COALESCE(target.email, '') ILIKE " + idx + " ESCAPE '\\'" +
                " OR COALESCE(target.name, '') ILIKE " + idx + " ESCAPE '\\'" +
                ")"
            );
        }

        // "Date range" filter. A malformed date is rejected instead of being
        // silently ignored, so the screen never shows more than the user asked
        // for.
        const fromDate = parseDateFilter(req.query.from);
        const toDate = parseDateFilter(req.query.to);

        if (req.query.from && fromDate === null) {
            return res.status(400).json({ message: "from must be a valid date" });
        }
        if (req.query.to && toDate === null) {
            return res.status(400).json({ message: "to must be a valid date" });
        }
        if (fromDate && toDate && fromDate.getTime() > toDate.getTime()) {
            return res.status(400).json({ message: "from must not be later than to" });
        }

        if (fromDate) {
            params.push(fromDate.toISOString());
            where.push("al.created_at >= $" + params.length + "::timestamptz");
        }

        if (toDate) {
            if (/^\d{4}-\d{2}-\d{2}$/.test(String(req.query.to).trim())) {
                toDate.setUTCHours(23, 59, 59, 999);
            }
            params.push(toDate.toISOString());
            where.push("al.created_at <= $" + params.length + "::timestamptz");
        }

        // Cursor-based pagination: fetch entries with id < before (older records)
        if (typeof req.query.before === "string" && /^\d+$/.test(req.query.before.trim())) {
            params.push(parseInt(req.query.before.trim(), 10));
            where.push("al.id < $" + params.length);
        }

        const limit = Math.min(
            Math.max(parseInt(req.query.limit || "150", 10) || 150, 1),
            500
        );
        params.push(limit);
        const limitIdx = "$" + params.length;

        const whereSql = where.length > 0 ? "WHERE " + where.join(" AND ") : "";

        const sql =
            "SELECT al.id, al.actor_id, actor.name AS actor_name, actor.email AS actor_email, actor.role AS actor_role, " +
            "al.document_id, doc.name AS document_name, doc.category AS document_category, " +
            "al.target_user_id, target.name AS target_user_name, target.email AS target_user_email, " +
            "al.action, al.outcome, al.ip_address, al.user_agent, al.details, al.prev_hash, al.entry_hash, al.created_at " +
            "FROM audit_logs al " +
            "LEFT JOIN users actor ON actor.id = al.actor_id " +
            "LEFT JOIN users target ON target.id = al.target_user_id " +
            "LEFT JOIN documents doc ON doc.id = al.document_id " +
            whereSql + " " +
            "ORDER BY al.id DESC LIMIT " + limitIdx;

        const result = await pool.query(sql, params);
        const logs = result.rows;

        // "Worth a look": the account with the most refusals in the last
        // minute. It is counted from the real audit log, so the banner stays
        // hidden when nothing was refused. The count is never estimated.
        const refusedRes = await pool.query(`
            SELECT actor.email AS actor_email, actor.name AS actor_name,
                   COUNT(*)::int AS refused_count
            FROM audit_logs al
            LEFT JOIN users actor ON actor.id = al.actor_id
            WHERE al.outcome = 'denied'
              AND al.created_at >= NOW() - INTERVAL '1 minute'
            GROUP BY actor.email, actor.name
            ORDER BY refused_count DESC, actor.email ASC
            LIMIT 1
        `);

        const refused = refusedRes.rows[0] || null;

        return res.json({
            logs,
            // nextCursor allows the client to page backward in time.
            nextCursor: logs.length === limit ? String(logs[logs.length - 1].id) : null,
            worthALook: refused && refused.actor_email
                ? {
                    email: refused.actor_email,
                    name: refused.actor_name,
                    count: refused.refused_count,
                    windowMinutes: 1
                }
                : null
        });
    } catch (error) {
        console.error("Admin audit logs query failed:", error.message);
        return res.status(500).json({ message: "Unable to retrieve audit logs" });
    }
});

// ── GET /api/admin/audit-filters — Distinct actions and users for the filters ─
// The "All actions" and "All users" dropdowns are populated from the real
// values that occur in the audit log, never from a hard-coded list.
router.get("/audit-filters", async (req, res) => {
    try {
        const [actionsRes, usersRes] = await Promise.all([
            pool.query(
                "SELECT DISTINCT action FROM audit_logs ORDER BY action ASC"
            ),
            pool.query(
                `SELECT DISTINCT email, name FROM users ORDER BY email ASC`
            )
        ]);

        return res.json({
            actions: actionsRes.rows.map((row) => row.action).filter(Boolean),
            users: usersRes.rows
                .filter((row) => row.email)
                .map((row) => ({ email: row.email, name: row.name }))
        });
    } catch (error) {
        console.error("Admin audit filters failed:", error.message);
        return res.status(500).json({ message: "Unable to retrieve audit filters" });
    }
});

// ── GET /api/admin/verify-chain ───────────────────────────────────────────────
router.get("/verify-chain", async (req, res) => {
    try {
        const verification = await verifyAuditChain();
        return res.json(verification);
    } catch (error) {
        console.error("Audit chain verification failed:", error.message);
        return res.status(503).json({
            valid: false,
            status: "unavailable",
            message: "Unable to verify audit chain: database or verifier unavailable"
        });
    }
});

// ── GET /api/admin/overview ───────────────────────────────────────────────────
router.get("/overview", async (req, res) => {
    try {
        const [statsRes, grantsRes, todayRes, eventsRes, refusedRes, chainStatus] = await Promise.all([
            pool.query(`
                SELECT
                    (SELECT COUNT(*)::int FROM users) AS total_users,
                    (SELECT COUNT(*)::int FROM documents) AS total_documents,
                    (SELECT COUNT(*)::int FROM document_permissions) AS active_grants,
                    (SELECT COUNT(*)::int FROM audit_logs) AS total_audit_events,
                    (SELECT COUNT(*)::int FROM audit_logs WHERE outcome = 'denied') AS denied_events,
                    (SELECT COUNT(*)::int FROM audit_logs WHERE action LIKE 'document_permission_%') AS permission_events
            `),
            pool.query(`
                SELECT
                    dp.id,
                    dp.document_id,
                    d.name AS document_name,
                    d.category AS document_category,
                    owner.name AS owner_name,
                    owner.email AS owner_email,
                    grantee.name AS grantee_name,
                    grantee.email AS grantee_email,
                    dp.permission,
                    dp.created_at
                FROM document_permissions dp
                JOIN documents d ON d.id = dp.document_id
                JOIN users owner ON owner.id = d.owner_id
                JOIN users grantee ON grantee.id = dp.user_id
                ORDER BY dp.created_at DESC
                LIMIT 100
            `),
            // The dashboard shows "today" counters. They are counted in the
            // server's own timezone, which is the same clock the timestamps
            // in the audit log are written with.
            pool.query(`
                SELECT
                    (SELECT COUNT(*)::int FROM audit_logs
                      WHERE action LIKE 'document_permission_%'
                        AND created_at >= date_trunc('day', NOW())) AS permission_changes_today,
                    (SELECT COUNT(*)::int FROM audit_logs
                      WHERE outcome = 'denied'
                        AND created_at >= date_trunc('day', NOW())) AS denied_events_today
            `),
            // "Latest events" for the dashboard table.
            pool.query(`
                SELECT al.id, al.action, al.outcome, al.created_at,
                       actor.email AS actor_email, actor.name AS actor_name,
                       doc.name AS document_name
                FROM audit_logs al
                LEFT JOIN users actor ON actor.id = al.actor_id
                LEFT JOIN documents doc ON doc.id = al.document_id
                ORDER BY al.id DESC
                LIMIT 8
            `),
            // "Worth a look": the account with the most refusals in the last
            // minute. It is counted from the real audit log, so it stays
            // empty when nothing happened.
            pool.query(`
                SELECT actor.email AS actor_email, actor.name AS actor_name,
                       COUNT(*)::int AS refused_count
                FROM audit_logs al
                LEFT JOIN users actor ON actor.id = al.actor_id
                WHERE al.outcome = 'denied'
                  AND al.created_at >= NOW() - INTERVAL '1 minute'
                GROUP BY actor.email, actor.name
                ORDER BY refused_count DESC, actor.email ASC
                LIMIT 1
            `),
            verifyAuditChain()
        ]);

        const refused = refusedRes.rows[0] || null;
        return res.json({
            stats: statsRes.rows[0],
            today: todayRes.rows[0],
            activeGrants: grantsRes.rows,
            activeGrantsTotal: grantsRes.rows.length,
            latestEvents: eventsRes.rows,
            worthALook: refused
                ? {
                    email: refused.actor_email,
                    name: refused.actor_name,
                    count: refused.refused_count,
                    windowMinutes: 1
                }
                : null,
            chainIntegrity: chainStatus
        });
    } catch (error) {
        console.error("Admin overview failed:", error.message);
        return res.status(500).json({ message: "Unable to retrieve admin overview" });
    }
});

// ── GET /api/admin/users — Filtered, paginated user list ──────────────────────
// Filters: search (name/email, case-insensitive, trimmed), role, status.
// Pagination: page/pageSize (page-based) or the original limit/offset pair.
// Both are server-side; the response `total` is the number of matching users.
router.get("/users", async (req, res) => {
    try {
        const query = parseUserListQuery(req.query);
        const params = [];
        const where = [];

        if (query.search) {
            // The wildcards in the search term are matched literally. The
            // value itself still travels as a bound parameter.
            params.push("%" + escapeLikePattern(query.search) + "%");
            const idx = "$" + params.length;
            where.push(
                "(u.name ILIKE " + idx + " ESCAPE '\\'" +
                " OR u.email ILIKE " + idx + " ESCAPE '\\')"
            );
        }

        if (query.role) {
            params.push(query.role);
            where.push("u.role = $" + params.length);
        }

        if (query.status) {
            params.push(query.status === "disabled");
            where.push("u.is_disabled = $" + params.length);
        }

        const whereSql = where.length > 0 ? " WHERE " + where.join(" AND ") : "";
        const countParams = params.slice();
        const listParams = params.concat([query.limit, query.offset]);

        const [usersRes, totalRes] = await Promise.all([
            pool.query(
                `SELECT
                    u.id,
                    u.name,
                    u.email,
                    u.role,
                    u.is_disabled,
                    u.created_at,
                    COUNT(d.id)::int AS document_count
                 FROM users u
                 LEFT JOIN documents d ON d.owner_id = u.id
                 ${whereSql}
                 GROUP BY u.id
                 ORDER BY u.created_at DESC, u.id ASC
                 LIMIT $${listParams.length - 1} OFFSET $${listParams.length}`,
                listParams
            ),
            pool.query(
                "SELECT COUNT(*)::int AS total FROM users u" + whereSql,
                countParams
            )
        ]);

        const total = totalRes.rows[0].total;

        return res.json({
            users: usersRes.rows,
            total,
            limit: query.limit,
            offset: query.offset,
            page: query.page,
            pageSize: query.pageSize,
            hasMore: query.offset + usersRes.rows.length < total
        });
    } catch (error) {
        if (error.status === 400) {
            return res.status(400).json({ message: error.message });
        }
        console.error("Admin user list failed:", error.message);
        return res.status(500).json({ message: "Unable to retrieve user list" });
    }
});

// ── POST /api/admin/users — Create a user account ─────────────────────────────
// Backs the "Add user" flow of the Admin console.
//
// Role policy: the Admin console can only create Viewer or Document Owner
// accounts. The admin role is deliberately not offered here — an administrator
// can still promote a user to admin later through PATCH /api/admin/users/:id/role.
//
// Initial credential handling (documented decision, the design spec leaves it
// open): the caller may pass an explicit `password`. When it does not, the
// server generates a cryptographically random one-time password and returns it
// **once** in the response body. It is never stored in plaintext, never written
// to the audit log, and never returned by any other endpoint. The administrator
// is responsible for handing it to the new user over an out-of-band channel;
// the user can rotate it with POST /api/auth/change-password.
router.post("/users", async (req, res) => {
    try {
        const { name, email, role, password } = req.body || {};

        if (typeof name !== "string" || typeof email !== "string") {
            return res.status(400).json({
                message: "Name and email are required"
            });
        }

        const cleanName = name.trim();
        const cleanEmail = email.trim().toLowerCase();

        if (!cleanName || cleanName.length > 100) {
            return res.status(400).json({
                message: "Name must be between 1 and 100 characters"
            });
        }

        if (
            cleanEmail.length > 255 ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)
        ) {
            return res.status(400).json({
                message: "Enter a valid email address"
            });
        }

        // Role is mandatory and restricted: admin accounts are never created
        // from this endpoint.
        const requestedRole =
            typeof role === "string" ? role.trim().toLowerCase() : "";

        if (!CREATEABLE_ROLES.has(requestedRole)) {
            await writeAuditLog(req, "admin_user_create", "denied", null, {
                email: cleanEmail,
                reason: "invalid_role",
                requestedRole: typeof role === "string" ? role.slice(0, 40) : null
            });
            return res.status(400).json({
                message: "Role must be one of: document_owner, viewer"
            });
        }

        // An explicit password is validated against the same policy that
        // protects self-registration.
        let plainPassword = null;
        let passwordWasGenerated = false;

        if (password !== undefined && password !== null && password !== "") {
            const passwordError = validatePassword(password);
            if (passwordError) {
                return res.status(400).json({ message: passwordError });
            }
            plainPassword = password;
        } else {
            plainPassword = generateTemporaryPassword();
            passwordWasGenerated = true;
        }

        const passwordHash = await bcrypt.hash(plainPassword, 12);

        const result = await pool.query(
            `INSERT INTO users (name, email, password_hash, role)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT DO NOTHING
             RETURNING id, name, email, role, is_disabled, created_at`,
            [cleanName, cleanEmail, passwordHash, requestedRole]
        );

        if (result.rows.length === 0) {
            await writeAuditLog(req, "admin_user_create", "denied", null, {
                email: cleanEmail,
                reason: "duplicate_email"
            });
            return res.status(409).json({
                message: "An account with this email already exists"
            });
        }

        const createdUser = result.rows[0];

        await writeAuditLog(
            req,
            "admin_user_create",
            "success",
            null,
            {
                targetUserId: createdUser.id,
                targetEmail: createdUser.email,
                newRole: createdUser.role,
                // Never the credential itself — only whether one was generated.
                temporaryPasswordGenerated: passwordWasGenerated
            },
            createdUser.id
        );

        return res.status(201).json({
            message: "User created",
            user: createdUser,
            // Shown once so the administrator can pass it on. It is never
            // recoverable from the server afterwards. When the caller supplied
            // the password itself there is nothing to hand over, so the field
            // is omitted instead of echoing the caller's own secret back.
            ...(passwordWasGenerated ? { temporaryPassword: plainPassword } : {})
        });
    } catch (error) {
        console.error("Admin user creation failed:", error.message);
        return res.status(500).json({
            message: "The user was not created. The server returned an error. Try again."
        });
    }
});

// ── GET /api/admin/role-upgrade-requests — Review queue ──────────────────────
// Defaults to pending requests (oldest first). `status=resolved` returns the
// most recently decided requests so the Admin console can show who resolved
// them and when.
router.patch("/users/:id/role", async (req, res) => {
    const targetId = req.params.id;

    if (!validUuid(targetId)) {
        return res.status(400).json({ message: "Invalid user ID" });
    }

    const { role } = req.body || {};
    const targetRole = typeof role === "string" ? role.trim().toLowerCase() : "";

    if (!VALID_ROLES.has(targetRole)) {
        await writeAuditLog(req, "admin_user_role_change", "denied", null, {
            targetUserId: targetId,
            reason: "invalid_role",
            requestedRole: typeof role === "string" ? role.slice(0, 40) : null
        });
        return res.status(400).json({
            message: "Role must be one of: admin, document_owner, viewer"
        });
    }

    if (targetId === req.user.id) {
        await writeAuditLog(req, "admin_user_role_change", "denied", null, {
            targetUserId: targetId,
            reason: "self_modification"
        });
        return res.status(400).json({
            message: "Administrators cannot change their own role"
        });
    }

    const client = await pool.connect();

    try {
        await client.query("BEGIN");

        // Keep the workflow lock order consistent: audit chain → administrator
        // invariant → account row → request row. Submissions and decisions
        // start with the audit lock, so acquiring it here prevents a deadlock
        // between a direct role change and a concurrent review.
        await lockAuditChain(client);

        // Serialise every role/status change so the "at least one active
        // administrator" invariant cannot be broken by concurrent requests.
        await client.query("SELECT pg_advisory_xact_lock($1)", [ADMIN_INVARIANT_LOCK_KEY]);

        const targetResult = await client.query(
            "SELECT id, name, email, role, is_disabled FROM users WHERE id = $1 FOR UPDATE",
            [targetId]
        );

        if (targetResult.rows.length === 0) {
            await client.query("ROLLBACK");
            await writeAuditLog(req, "admin_user_role_change", "denied", null, {
                targetUserId: targetId,
                reason: "user_not_found"
            });
            return res.status(404).json({ message: "User not found" });
        }

        const target = targetResult.rows[0];
        const previousRole = target.role;

        if (previousRole === "admin" && targetRole !== "admin") {
            const activeAdmins = await countActiveAdmins(client);
            if (activeAdmins <= 1) {
                await client.query("ROLLBACK");
                await writeAuditLog(req, "admin_user_role_change", "denied", null, {
                    targetUserId: targetId,
                    reason: "last_active_admin",
                    previousRole
                });
                return res.status(409).json({
                    message: "Cannot demote the last active administrator"
                });
            }
        }

        const updated = await client.query(
            `UPDATE users
             SET role = $1, updated_at = NOW()
             WHERE id = $2
             RETURNING id, name, email, role, is_disabled`,
            [targetRole, targetId]
        );

        // A direct role change also settles any request that is still pending,
        // so the account can never end up with a pending request whose outcome
        // contradicts the actual role. Promoting to document_owner approves it;
        // every other assignment rejects it.
        const requestDecision =
            targetRole === "document_owner" ? "approved" : "rejected";
        const resolvedRequest = await resolvePendingUpgradeRequest(client, {
            userId: targetId,
            status: requestDecision,
            decidedBy: req.user.id
        });

        const auditDetails = {
            targetUserId: targetId,
            targetEmail: updated.rows[0].email,
            previousRole,
            newRole: targetRole
        };

        if (resolvedRequest) {
            auditDetails.pendingRequestId = resolvedRequest.id;
            auditDetails.pendingRequestOutcome = requestDecision;
        }

        // The role update, the pending-request resolution and both audit
        // events commit together. If an append fails, nothing is changed.
        await writeAuditLog(
            req,
            "admin_user_role_change",
            "success",
            null,
            auditDetails,
            targetId,
            client
        );

        if (resolvedRequest) {
            await writeAuditLog(
                req,
                requestDecision === "approved"
                    ? "role_upgrade_request_approved"
                    : "role_upgrade_request_rejected",
                "success",
                null,
                {
                    requestId: resolvedRequest.id,
                    requestedRole: resolvedRequest.requested_role,
                    previousRole,
                    newRole: targetRole,
                    viaDirectRoleChange: true
                },
                targetId,
                client
            );
        }

        await client.query("COMMIT");

        return res.json({
            message: resolvedRequest
                ? "User role updated and pending upgrade request resolved"
                : "User role updated",
            user: updated.rows[0],
            request: resolvedRequest
                ? {
                      id: resolvedRequest.id,
                      status: requestDecision,
                      decidedAt: resolvedRequest.decided_at
                  }
                : null
        });
    } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        console.error("Admin role change failed:", error.message);
        return res.status(500).json({
            message: "Unable to update user role. Nothing was changed."
        });
    } finally {
        client.release();
    }
});

// ── PATCH /api/admin/users/:id/disable — Disable or re-enable a user account ──
// Disabling an account blocks the next login and invalidates every session
// that the account currently holds. Re-enabling restores the ability to log
// in, but it never resurrects the invalidated sessions: the user has to
// authenticate again.
router.patch("/users/:id/disable", async (req, res) => {
    const targetId = req.params.id;

    if (!validUuid(targetId)) {
        return res.status(400).json({ message: "Invalid user ID" });
    }

    if (targetId === req.user.id) {
        await writeAuditLog(req, "admin_user_disabled", "denied", null, {
            targetUserId: targetId,
            reason: "self_modification"
        });
        return res.status(400).json({ message: "Administrators cannot disable their own account" });
    }

    const { disabled } = req.body || {};
    if (typeof disabled !== "boolean") {
        return res.status(400).json({ message: "Provide disabled: true or false" });
    }

    const client = await pool.connect();

    try {
        await client.query("BEGIN");
        await client.query("SELECT pg_advisory_xact_lock($1)", [ADMIN_INVARIANT_LOCK_KEY]);

        const targetResult = await client.query(
            "SELECT id, name, email, role, is_disabled FROM users WHERE id = $1 FOR UPDATE",
            [targetId]
        );

        if (targetResult.rows.length === 0) {
            await client.query("ROLLBACK");
            await writeAuditLog(req, "admin_user_disabled", "denied", null, {
                targetUserId: targetId,
                reason: "user_not_found"
            });
            return res.status(404).json({ message: "User not found" });
        }

        const target = targetResult.rows[0];

        if (disabled && target.role === "admin") {
            const activeAdmins = await countActiveAdmins(client);
            if (activeAdmins <= 1) {
                await client.query("ROLLBACK");
                await writeAuditLog(req, "admin_user_disabled", "denied", null, {
                    targetUserId: targetId,
                    reason: "last_active_admin"
                });
                return res.status(409).json({
                    message: "Cannot disable the last active administrator"
                });
            }
        }

        const updated = await client.query(
            `UPDATE users
             SET is_disabled = $1, updated_at = NOW()
             WHERE id = $2
             RETURNING id, name, email, role, is_disabled`,
            [disabled, targetId]
        );

        // Invalidate the account's live sessions as part of the same
        // transaction: after this commit the old cookies are worthless.
        const revokedSessions = disabled ? await invalidateUserSessions(client, targetId) : 0;

        await client.query("COMMIT");

        await writeAuditLog(
            req,
            disabled ? "admin_user_disabled" : "admin_user_enabled",
            "success",
            null,
            {
                targetUserId: targetId,
                targetEmail: updated.rows[0].email,
                disabled,
                revokedSessions
            },
            targetId
        );

        return res.json({
            message: disabled ? "Account disabled" : "Account enabled",
            user: updated.rows[0],
            revokedSessions
        });
    } catch (error) {
        await client.query("ROLLBACK").catch(() => {});

        // is_disabled column missing means the migration hasn't added it yet.
        if (error.code === "42703") {
            return res.status(501).json({
                message: "Account disable feature requires running: npm run migrate"
            });
        }

        console.error("Admin account disable failed:", error.message);
        return res.status(500).json({ message: "Unable to update account status" });
    } finally {
        client.release();
    }
});

module.exports = router;
