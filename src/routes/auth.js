const express = require("express");
const bcrypt = require("bcrypt");
const pool = require("../db");
const { requireAuth } = require("../middleware/auth");
const { writeAuditLog } = require("../services/auditService");
const { DISABLED_MESSAGE } = require("../middleware/auth");
const { passwordProblem } = require("../services/passwordPolicy");

const router = express.Router();

// ── Password policy ───────────────────────────────────────────────────────────
// The policy itself lives in services/passwordPolicy.js so that the admin
// console can reuse exactly the same rules when it creates an account.

// ── Login brute-force protection (in-memory, per-email sliding window) ────────
// After FAILED_ATTEMPT_LIMIT failures within ATTEMPT_WINDOW_MS the account is
// locked for LOCKOUT_MS.  A periodic GC keeps the Map from growing unbounded.
const FAILED_ATTEMPT_LIMIT = 5;
const LOCKOUT_MS = 15 * 60 * 1000;       // 15-minute lockout
const ATTEMPT_WINDOW_MS = 15 * 60 * 1000; // 15-minute sliding window
const loginAttempts = new Map();

// Garbage-collect expired entries every 5 minutes.
setInterval(() => {
    const now = Date.now();
    for (const [email, record] of loginAttempts) {
        const windowExpired = now > (record.windowStart || 0) + ATTEMPT_WINDOW_MS;
        const lockExpired = !record.lockedUntil || now > record.lockedUntil;
        if (windowExpired && lockExpired) loginAttempts.delete(email);
    }
}, 5 * 60 * 1000).unref(); // .unref() so the timer never keeps the process alive

function checkLoginLock(email) {
    const record = loginAttempts.get(email);
    if (!record) return { locked: false };
    const now = Date.now();
    if (record.lockedUntil && now < record.lockedUntil) {
        return {
            locked: true,
            retryAfterSeconds: Math.ceil((record.lockedUntil - now) / 1000)
        };
    }
    // Window expired — treat as a fresh slate
    if (now > (record.windowStart || 0) + ATTEMPT_WINDOW_MS) {
        loginAttempts.delete(email);
    }
    return { locked: false };
}

function recordLoginFailure(email) {
    const now = Date.now();
    let record = loginAttempts.get(email);
    if (!record || now > (record.windowStart || 0) + ATTEMPT_WINDOW_MS) {
        record = { count: 0, windowStart: now, lockedUntil: null };
    }
    record.count += 1;
    if (record.count >= FAILED_ATTEMPT_LIMIT) {
        record.lockedUntil = now + LOCKOUT_MS;
    }
    loginAttempts.set(email, record);
}

function clearLoginAttempts(email) {
    loginAttempts.delete(email);
}

// ── POST /api/auth/register ───────────────────────────────────────────────────
router.post("/register", async (req, res) => {
    try {
        // The public registration form deliberately offers no role choice, so a
        // client-supplied role is ignored rather than trusted. Every account
        // created from the public sign-up form starts as a Viewer; the
        // document_owner and admin roles can only be granted later by an
        // administrator through PATCH /api/admin/users/:id/role.
        const { name, email, password } = req.body || {};

        if (
            typeof name !== "string" ||
            typeof email !== "string" ||
            typeof password !== "string"
        ) {
            return res.status(400).json({
                message: "Name, email, and password are required"
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

        const passwordError = passwordProblem(password);
        if (passwordError) {
            return res.status(400).json({ message: passwordError });
        }

        // Public registration may only create Viewer accounts.
        // The document_owner and admin roles are privileged and must be
        // assigned by an existing admin via PATCH /api/admin/users/:id/role —
        // never through self-registration.
        const assignedRole = "viewer";

        const passwordHash = await bcrypt.hash(password, 12);

        const result = await pool.query(
            `INSERT INTO users (name, email, password_hash, role)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT DO NOTHING
             RETURNING id, name, email, role, created_at`,
            [cleanName, cleanEmail, passwordHash, assignedRole]
        );

        if (result.rows.length === 0) {
            return res.status(409).json({
                message: "An account with this email already exists"
            });
        }

        const createdUser = result.rows[0];
        await writeAuditLog(req, "auth_register", "success", null, {
            actorId: createdUser.id,
            email: createdUser.email,
            role: createdUser.role
        });

        return res.status(201).json({
            message: "Registration successful",
            user: createdUser
        });
    } catch (error) {
        console.error("Registration failed:", error.message);
        return res.status(500).json({
            message: "Unable to register user"
        });
    }
});

// ── POST /api/auth/login ──────────────────────────────────────────────────────
router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body || {};

        if (
            typeof email !== "string" ||
            typeof password !== "string" ||
            !email.trim() ||
            !password
        ) {
            return res.status(400).json({
                message: "Email and password are required"
            });
        }

        const cleanEmail = email.trim().toLowerCase();

        // ── Brute-force gate ──────────────────────────────────────────────────
        const lockStatus = checkLoginLock(cleanEmail);
        if (lockStatus.locked) {
            await writeAuditLog(req, "auth_login", "denied", null, {
                attemptedEmail: cleanEmail,
                reason: "account_locked",
                retryAfterSeconds: lockStatus.retryAfterSeconds
            });
            return res.status(429).json({
                message: `Too many failed login attempts. Please try again in ${lockStatus.retryAfterSeconds} seconds.`
            });
        }

        const result = await pool.query(
            `SELECT id, name, email, password_hash, role, is_disabled
             FROM users
             WHERE LOWER(email) = $1`,
            [cleanEmail]
        );

        if (result.rows.length === 0) {
            recordLoginFailure(cleanEmail);
            await writeAuditLog(req, "auth_login", "denied", null, {
                attemptedEmail: cleanEmail,
                reason: "user_not_found"
            });
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        const user = result.rows[0];

        // Disabled accounts are rejected before the password comparison.
        // The distinct message is a deliberate usability trade-off: the
        // account holder is told exactly why the login fails. See
        // THREATS.md (T-09) for the accepted enumeration risk.
        if (user.is_disabled) {
            recordLoginFailure(cleanEmail);
            await writeAuditLog(req, "auth_login", "denied", null, {
                actorId: user.id,
                attemptedEmail: cleanEmail,
                reason: "account_disabled"
            });
            return res.status(403).json({
                message: DISABLED_MESSAGE,
                code: "ACCOUNT_DISABLED"
            });
        }

        const passwordMatches = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordMatches) {
            recordLoginFailure(cleanEmail);
            await writeAuditLog(req, "auth_login", "denied", null, {
                actorId: user.id,
                attemptedEmail: cleanEmail,
                reason: "invalid_password"
            });
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        // Successful login — clear any lockout record
        clearLoginAttempts(cleanEmail);

        // Regenerating the session defeats session fixation: the session id
        // that an attacker may have planted before the login is discarded.
        req.session.regenerate((error) => {
            if (error) {
                console.error("Session regeneration failed:", error.message);
                return res.status(500).json({
                    message: "Unable to log in"
                });
            }

            req.session.userId = user.id;

            req.session.save(async (saveError) => {
                if (saveError) {
                    console.error("Session save failed:", saveError.message);
                    return res.status(500).json({
                        message: "Unable to log in"
                    });
                }

                await writeAuditLog(req, "auth_login", "success", null, {
                    actorId: user.id,
                    email: user.email,
                    role: user.role
                }).catch(() => {});

                return res.json({
                    message: "Login successful",
                    user: {
                        id: user.id,
                        name: user.name,
                        email: user.email,
                        role: user.role
                    }
                });
            });
        });
    } catch (error) {
        console.error("Login failed:", error.message);
        return res.status(500).json({
            message: "Unable to log in"
        });
    }
});

// ── GET /api/auth/me ──────────────────────────────────────────────────────────
// `requireAuth` re-reads the account on every request, so a role change or a
// disable takes effect immediately.
router.get("/me", requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, name, email, role, is_disabled, created_at
             FROM users
             WHERE id = $1`,
            [req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ message: "Authentication required" });
        }

        const user = result.rows[0];

        return res.json({
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role,
                created_at: user.created_at
            }
        });
    } catch (error) {
        console.error("Current user lookup failed:", error.message);
        return res.status(500).json({
            message: "Unable to retrieve current user"
        });
    }
});

// ── PUT /api/auth/me — Update profile (name and/or email) ────────────────────
router.put("/me", requireAuth, async (req, res) => {
    try {
        const { name, email } = req.body || {};
        const setClauses = [];
        const params = [];
        const updatedFields = [];

        if (typeof name === "string") {
            const cleanName = name.trim();
            if (!cleanName || cleanName.length > 100) {
                return res.status(400).json({
                    message: "Name must be between 1 and 100 characters"
                });
            }
            params.push(cleanName);
            setClauses.push(`name = $${params.length}`);
            updatedFields.push("name");
        }

        if (typeof email === "string") {
            const cleanEmail = email.trim().toLowerCase();
            if (
                cleanEmail.length > 255 ||
                !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)
            ) {
                return res.status(400).json({ message: "Enter a valid email address" });
            }
            params.push(cleanEmail);
            setClauses.push(`email = $${params.length}`);
            updatedFields.push("email");
        }

        if (setClauses.length === 0) {
            return res.status(400).json({ message: "Provide name or email to update" });
        }

        setClauses.push("updated_at = NOW()");
        params.push(req.user.id);

        const result = await pool.query(
            `UPDATE users
             SET ${setClauses.join(", ")}
             WHERE id = $${params.length}
             RETURNING id, name, email, role, updated_at`,
            params
        );

        await writeAuditLog(req, "auth_profile_update", "success", null, {
            updatedFields
        });

        return res.json({ message: "Profile updated", user: result.rows[0] });
    } catch (error) {
        if (error.code === "23505") {
            return res.status(409).json({ message: "Email already in use by another account" });
        }
        console.error("Profile update failed:", error.message);
        return res.status(500).json({ message: "Unable to update profile" });
    }
});

// ── POST /api/auth/change-password ────────────────────────────────────────────
router.post("/change-password", requireAuth, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body || {};

        if (typeof currentPassword !== "string" || typeof newPassword !== "string") {
            return res.status(400).json({
                message: "currentPassword and newPassword are required"
            });
        }

        const passwordError = passwordProblem(newPassword);
        if (passwordError) {
            return res.status(400).json({ message: passwordError });
        }

        if (currentPassword === newPassword) {
            return res.status(400).json({
                message: "New password must differ from the current password"
            });
        }

        const userResult = await pool.query(
            "SELECT password_hash FROM users WHERE id = $1",
            [req.user.id]
        );

        if (userResult.rows.length === 0) {
            return res.status(401).json({ message: "Authentication required" });
        }

        const passwordMatches = await bcrypt.compare(
            currentPassword,
            userResult.rows[0].password_hash
        );

        if (!passwordMatches) {
            await writeAuditLog(req, "auth_change_password", "denied", null, {
                reason: "invalid_current_password"
            });
            return res.status(401).json({ message: "Current password is incorrect" });
        }

        const newHash = await bcrypt.hash(newPassword, 12);

        await pool.query(
            "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
            [newHash, req.user.id]
        );

        // A password change invalidates every *other* session of the account,
        // so a stolen session cannot survive the rotation. The session that
        // performed the change stays usable.
        const revoked = await pool.query(
            `DELETE FROM user_sessions
             WHERE sess->>'userId' = $1 AND sid <> $2`,
            [req.user.id, req.sessionID]
        ).catch(() => null);

        await writeAuditLog(req, "auth_change_password", "success", null, {
            revokedSessions: revoked ? revoked.rowCount : 0
        });

        return res.json({
            message: "Password changed successfully",
            revokedSessions: revoked ? revoked.rowCount : 0
        });
    } catch (error) {
        console.error("Password change failed:", error.message);
        return res.status(500).json({ message: "Unable to change password" });
    }
});

// ── GET /api/auth/users — User directory ─────────────────────────────────────
// The directory exposes the names and e-mail addresses of every account, so it
// is restricted to the roles that legitimately need to share a document
// (document owners) and administrators. Viewers have no use for it.
router.get("/users", requireAuth, async (req, res) => {
    try {
        if (!["admin", "document_owner"].includes(req.user.role)) {
            await writeAuditLog(req, "auth_user_directory", "denied", null, {
                reason: "insufficient_role",
                role: req.user.role
            });

            return res.status(403).json({
                message: "Access denied"
            });
        }

        const result = await pool.query(
            `SELECT id, name, email, role
             FROM users
             WHERE id <> $1 AND is_disabled = false
             ORDER BY name ASC`,
            [req.user.id]
        );
        return res.json({ users: result.rows });
    } catch (error) {
        console.error("Users directory lookup failed:", error.message);
        return res.status(500).json({ message: "Unable to load users list" });
    }
});

// ── POST /api/auth/logout ─────────────────────────────────────────────────────
router.post("/logout", (req, res) => {
    if (!req.session) {
        return res.status(204).end();
    }

    const userId = req.session.userId || null;

    req.session.destroy(async (error) => {
        if (error) {
            console.error("Logout failed:", error.message);
            return res.status(500).json({
                message: "Unable to log out"
            });
        }

        if (userId) {
            await writeAuditLog(req, "auth_logout", "success", null, { actorId: userId }).catch(() => {});
        }

        res.clearCookie("trustvault.sid", {
            httpOnly: true,
            secure: require("../config").IS_PRODUCTION,
            sameSite: "lax",
            path: "/"
        });

        return res.json({
            message: "Logout successful"
        });
    });
});

module.exports = router;
