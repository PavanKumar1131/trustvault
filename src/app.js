const path = require("node:path");
const express = require("express");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const connectPgSimple = require("connect-pg-simple");
const { doubleCsrf } = require("csrf-csrf");
const pool = require("./db");
const config = require("./config");
const authRoutes = require("./routes/auth");
const documentRoutes = require("./routes/documents");
const adminRoutes = require("./routes/admin");
const {
    requestsRouter,
    adminRequestsRouter,
    legacyAuthRouter
} = require("./routes/requests");

/**
 * Client-safe error messages.
 *
 * Only a small, explicitly allow-listed set of messages may ever reach a
 * client. Everything else (SQL text, stack traces, driver internals) stays in
 * the server log. The CSRF message is kept verbatim because the frontend uses
 * it to detect a stale token and transparently retry.
 */
const SAFE_ERROR_MESSAGES = {
    EBADCSRFTOKEN: "invalid csrf token"
};

function clientSafeMessage(err, status) {
    if (err && SAFE_ERROR_MESSAGES[err.code]) {
        return SAFE_ERROR_MESSAGES[err.code];
    }

    if (err && err.type === "entity.parse.failed") {
        return "Malformed request body";
    }

    if (err && err.type === "entity.too.large") {
        return "Request payload too large";
    }

    switch (status) {
        case 400:
            return "Invalid request";
        case 401:
            return "Authentication required";
        case 403:
            return "Access denied";
        case 404:
            return "Not found";
        case 405:
            return "Method not allowed";
        case 413:
            return "Request payload too large";
        case 429:
            return "Too many requests";
        default:
            return "Request could not be processed";
    }
}

function createRateLimiter({ limit, message }) {
    return rateLimit({
        windowMs: 15 * 60 * 1000,
        limit,
        standardHeaders: "draft-8",
        legacyHeaders: false,
        message: { message }
    });
}

/**
 * Builds the Express application.
 *
 * @param {object}  [options]
 * @param {boolean} [options.csrfEnabled]  Force CSRF protection on/off.
 *                                          Defaults to "on outside the test-suite".
 * @param {number}  [options.apiRateLimit]  Requests per 15 minutes for the API limiter.
 * @param {number}  [options.authRateLimit] Requests per 15 minutes for the auth limiter.
 */
function createApp(options = {}) {
    // The CSRF protection is a hard requirement in production. The option
    // exists for the test-suite only and can never switch it off there.
    const csrfEnabled = config.IS_PRODUCTION
        ? true
        : options.csrfEnabled !== undefined
            ? options.csrfEnabled
            : config.CSRF_ENABLED;
    const apiRateLimit = options.apiRateLimit || config.RATE_LIMIT_API;
    const authRateLimit = options.authRateLimit || config.RATE_LIMIT_AUTH;

    const app = express();

    app.disable("x-powered-by");
    app.set("trust proxy", config.TRUST_PROXY);

    app.use(
        helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    scriptSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
                    fontSrc: ["'self'", "https://fonts.gstatic.com"],
                    imgSrc: ["'self'", "data:", "blob:"],
                    connectSrc: ["'self'"],
                    objectSrc: ["'none'"],
                    frameAncestors: ["'none'"]
                }
            }
        })
    );

    app.use(express.json({ limit: "1mb" }));
    app.use(express.urlencoded({ extended: false, limit: "100kb" }));

    app.use(cookieParser(config.SESSION_SECRET));

    // General API limiter. Authentication endpoints additionally use the much
    // stricter `authLimiter` below.
    app.use(
        "/api",
        createRateLimiter({
            limit: apiRateLimit,
            message: "Too many requests. Please try again later."
        })
    );

    const PgSession = connectPgSimple(session);

    app.use(
        session({
            store: new PgSession({
                pool,
                tableName: "user_sessions",
                // The table is created by the migration. Creating it implicitly
                // is only allowed outside production.
                createTableIfMissing: !config.IS_PRODUCTION,
                // The prune timer keeps the session table small. It is
                // disabled in the test environment: the tests end the pool
                // before the timer fires, which would only produce noise.
                pruneSessionInterval: config.IS_TEST ? false : 60
            }),
            name: "trustvault.sid",
            secret: config.SESSION_SECRET,
            resave: false,
            saveUninitialized: false,
            rolling: true,
            cookie: {
                httpOnly: true,
                secure: config.IS_PRODUCTION,
                sameSite: "lax",
                maxAge: config.SESSION_MAX_AGE_MS
            }
        })
    );

    // ── CSRF protection ───────────────────────────────────────────────────────
    // Double-submit cookie: the client fetches a token from
    // GET /api/auth/csrf-token and sends it back in the `x-csrf-token` header.
    // The token is bound to the current session id, so a token issued for one
    // session cannot be replayed in another.
    //
    // Login and registration are skipped because no authenticated session
    // exists yet that could be ridden; both endpoints are protected by the
    // per-account lockout and the dedicated authentication rate limiter.
    let generateCsrfToken = null;

    if (csrfEnabled) {
        const csrf = doubleCsrf({
            getSecret: () => config.SESSION_SECRET,
            getSessionIdentifier: (req) => req.sessionID || "",
            cookieName: "trustvault.csrf",
            cookieOptions: {
                sameSite: "lax",
                secure: config.IS_PRODUCTION,
                httpOnly: true,
                path: "/"
            },
            skipCsrfProtection: (req) => {
                const path = req.path;
                return path === "/auth/login" || path === "/auth/register";
            },
            getCsrfTokenFromRequest: (req) => {
                const header = req.headers["x-csrf-token"];
                if (typeof header === "string" && header.length > 0) {
                    return header;
                }
                if (req.body && typeof req.body._csrf === "string" && req.body._csrf.length > 0) {
                    return req.body._csrf;
                }
                return null;
            }
        });

        generateCsrfToken = csrf.generateCsrfToken;
        app.use("/api", csrf.doubleCsrfProtection);
    }

    // ── Static assets ─────────────────────────────────────────────────────────
    // Only the `public` directory is exposed. Uploaded documents live in the
    // private upload directory and the database blob store and are never
    // served statically.
    const publicDir = path.join(__dirname, "../public");
    app.use(express.static(publicDir));

    // ── CSRF token vending endpoint ───────────────────────────────────────────
    app.get("/api/auth/csrf-token", (req, res) => {
        if (!generateCsrfToken) {
            // CSRF protection is disabled (automated test-suite only).
            return res.json({ csrfToken: null });
        }

        try {
            const token = generateCsrfToken(req, res);
            return res.json({ csrfToken: token });
        } catch (error) {
            console.error("Error generating CSRF token:", error.message);
            return res.status(500).json({ message: "Unable to generate CSRF token" });
        }
    });

    // ── API routes ────────────────────────────────────────────────────────────
    // The strict authentication limiter only guards the credential endpoints;
    // the remaining /api/auth routes (profile, CSRF token, ...) stay under the
    // general API budget so ordinary navigation is never throttled.
    const authLimiter = createRateLimiter({
        limit: authRateLimit,
        message: "Too many authentication attempts. Please try again later."
    });

    app.use("/api/auth/login", authLimiter);
    app.use("/api/auth/register", authLimiter);
    app.use("/api/auth", legacyAuthRouter);
    app.use("/api/auth", authRoutes);

    if (config.MOUNT_TEST_ROUTES) {
        // Local debugging helpers are never mounted in production.
        const testRoutes = require("./routes/test");
        app.use("/api/test", testRoutes);
    }

    app.use("/api/documents", documentRoutes);
    app.use("/api/requests", requestsRouter);
    app.use("/api/admin", adminRequestsRouter);
    app.use("/api/admin", adminRoutes);

    // ── Health endpoints ──────────────────────────────────────────────────────
    app.get("/api/health", (req, res) => {
        res.json({
            status: "ok",
            application: "TrustVault",
            timestamp: new Date().toISOString()
        });
    });

    app.get("/api/health/db", async (req, res) => {
        try {
            const result = await pool.query("SELECT NOW() AS database_time");

            res.json({
                status: "ok",
                database: "connected",
                timestamp: result.rows[0].database_time
            });
        } catch (error) {
            console.error("Database health check failed:", error.message);

            res.status(503).json({
                status: "error",
                database: "unavailable"
            });
        }
    });

    app.get("/", (req, res) => {
        res.sendFile(path.join(publicDir, "index.html"), (err) => {
            if (err) {
                res.send("Welcome to TrustVault API!");
            }
        });
    });

    // ── Global error handling middleware ──────────────────────────────────────
    // Guarantees that every error (CSRF, validation, database, multer) is
    // reported as clean JSON without leaking implementation details.
    app.use((err, req, res, next) => {
        if (res.headersSent) {
            return next(err);
        }

        const status = Number(err.status || err.statusCode) || 500;

        if (status >= 500) {
            // Full detail stays in the server log only.
            console.error("Unhandled server error:", err);
            return res.status(500).json({ message: "Internal server error" });
        }

        console.error(`Request rejected (${status}): ${err.message}`);

        return res.status(status).json({ message: clientSafeMessage(err, status) });
    });

    return app;
}

const app = createApp();

module.exports = app;
module.exports.createApp = createApp;
