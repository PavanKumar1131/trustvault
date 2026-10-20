
const pool = require("../db");

async function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({
            message: "Authentication required"
        });
    }

    try {
        const result = await pool.query(
            `SELECT id, name, email, role
             FROM users
             WHERE id = $1`,
            [req.session.userId]
        );

        if (result.rows.length === 0) {
            req.session.destroy(() => { });
            return res.status(401).json({
                message: "Invalid session"
            });
        }

        req.user = result.rows[0];
        next();
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

        next();
    };
}

module.exports = { requireAuth, requireRole };
