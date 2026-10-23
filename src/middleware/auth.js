/**
 * Authentication and role middleware.
 *
 * `requireAuth` re-reads the account from the database on every request, so a
 * role change or an account disable takes effect immediately instead of
 * waiting for the session to expire.
 */

const pool = require("../db");

// The wording is fixed by the approved role designs ("States: system"):
// "This account is disabled. Contact an administrator."
const DISABLED_MESSAGE = "This account is disabled. Contact an administrator.";

/**
 * Destroys the current session without leaking the reason to the client.
 * The response is sent by the caller.
 */
function destroySession(req) {
    return new Promise((resolve) => {
        if (!req.session) {
            return resolve();
        }
        req.session.destroy(() => resolve());
    });
}

async function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
        const rawCookie = req.headers && req.headers.cookie;
        const hadSessionCookie = Boolean(
            (rawCookie && rawCookie.includes("trustvault.sid")) ||
            (req.cookies && req.cookies["trustvault.sid"]) ||
            (req.signedCookies && req.signedCookies["trustvault.sid"])
        );

        if (hadSessionCookie) {
            return res.status(401).json({
                message: "Session expired",
                code: "SESSION_EXPIRED"
            });
        }

        return res.status(401).json({
            message: "Authentication required",
            code: "UNAUTHENTICATED"
        });
    }

    try {
        const result = await pool.query(
            `SELECT id, name, email, role, is_disabled
             FROM users
             WHERE id = $1`,
            [req.session.userId]
        );

        if (result.rows.length === 0) {
            // The account was deleted while the session was still alive.
            await destroySession(req);
            return res.status(401).json({
                message: "Authentication required"
            });
        }

        const user = result.rows[0];

        if (user.is_disabled) {
            // Defence in depth: disabling an account also removes its server
            // side sessions, but a request that is already in flight (or a
            // session created in a narrow race window) must still be refused.
            await destroySession(req);
            return res.status(403).json({
                message: DISABLED_MESSAGE,
                // A machine-readable marker so the browser can tell a disabled
                // account apart from any other 403 (for example a CSRF
                // rejection) without parsing the human-readable message.
                code: "ACCOUNT_DISABLED"
            });
        }

        req.user = user;
        return next();
    } catch (error) {
        console.error("Authentication check failed:", error.message);
        return res.status(500).json({
            message: "Internal server error"
        });
    }
}

function requireRole(...allowedRoles) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                message: "Authentication required"
            });
        }

        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({
                message: "Access denied"
            });
        }

        return next();
    };
}

module.exports = { requireAuth, requireRole, DISABLED_MESSAGE };
