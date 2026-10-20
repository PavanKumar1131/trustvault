const express = require("express");
const bcrypt = require("bcrypt");
const pool = require("../db");

const router = express.Router();

// Register
router.post("/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;

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

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
            return res.status(400).json({
                message: "Enter a valid email address"
            });
        }

        if (password.length < 12 || password.length > 72) {
            return res.status(400).json({
                message: "Password must be between 12 and 72 characters"
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const result = await pool.query(
            `INSERT INTO users (name, email, password_hash)
             VALUES ($1, $2, $3)
             ON CONFLICT DO NOTHING
             RETURNING id, name, email, role, created_at`,
            [cleanName, cleanEmail, passwordHash]
        );

        if (result.rows.length === 0) {
            return res.status(409).json({
                message: "An account with this email already exists"
            });
        }

        return res.status(201).json({
            message: "Registration successful",
            user: result.rows[0]
        });
    } catch (error) {
        console.error("Registration failed:", error.message);
        return res.status(500).json({
            message: "Unable to register user"
        });
    }
});

// Login
router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

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

        const result = await pool.query(
            `SELECT id, name, email, password_hash, role
             FROM users
             WHERE LOWER(email) = $1`,
            [email.trim().toLowerCase()]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        const user = result.rows[0];
        const passwordMatches = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordMatches) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        // Prevent session fixation by regenerating the session ID.
        req.session.regenerate((error) => {
            if (error) {
                console.error("Session regeneration failed:", error.message);
                return res.status(500).json({
                    message: "Unable to log in"
                });
            }

            req.session.userId = user.id;

            req.session.save((saveError) => {
                if (saveError) {
                    console.error("Session save failed:", saveError.message);
                    return res.status(500).json({
                        message: "Unable to log in"
                    });
                }

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

// Get current logged-in user
router.get("/me", async (req, res) => {
    try {
        if (!req.session || !req.session.userId) {
            return res.status(401).json({
                message: "Authentication required"
            });
        }

        const result = await pool.query(
            `SELECT id, name, email, role, created_at
             FROM users
             WHERE id = $1`,
            [req.session.userId]
        );

        if (result.rows.length === 0) {
            return req.session.destroy(() => {
                res.status(401).json({
                    message: "Authentication required"
                });
            });
        }

        return res.json({ user: result.rows[0] });
    } catch (error) {
        console.error("Current user lookup failed:", error.message);
        return res.status(500).json({
            message: "Unable to retrieve current user"
        });
    }
});

// Logout
router.post("/logout", (req, res) => {
    if (!req.session) {
        return res.status(204).end();
    }

    req.session.destroy((error) => {
        if (error) {
            console.error("Logout failed:", error.message);
            return res.status(500).json({
                message: "Unable to log out"
            });
        }

        res.clearCookie("trustvault.sid", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            path: "/"
        });

        return res.json({
            message: "Logout successful"
        });
    });
});

module.exports = router;