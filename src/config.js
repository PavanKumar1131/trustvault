/**
 * Centralised runtime configuration and environment validation.
 *
 * Every module that needs environment information imports this file so the
 * validation rules live in exactly one place. Importing this module in the
 * `test` environment performs the test-database isolation guard: the process
 * refuses to start when the automated test-suite would run against the
 * development or production database.
 */

require("dotenv").config({ quiet: true });

const path = require("node:path");

const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PRODUCTION = NODE_ENV === "production";
const IS_TEST = NODE_ENV === "test";
const IS_DEVELOPMENT = NODE_ENV === "development";

/** Fallback used only for local development. Rejected in production. */
const DEV_SESSION_SECRET = "trustvault-dev-fallback-secret-change-in-prod";

const MIN_SESSION_SECRET_LENGTH = 32;

/**
 * Extracts the database name from a PostgreSQL connection string.
 * Returns null when the value cannot be parsed.
 */
function databaseNameFromUrl(connectionString) {
    if (typeof connectionString !== "string" || !connectionString.trim()) {
        return null;
    }

    try {
        const parsed = new URL(connectionString);
        const name = decodeURIComponent(parsed.pathname.replace(/^\//, ""));
        return name || null;
    } catch {
        return null;
    }
}

function requireProductionEnv() {
    const missing = [];

    if (!process.env.DATABASE_URL) {
        missing.push("DATABASE_URL");
    }

    if (!process.env.SESSION_SECRET) {
        missing.push("SESSION_SECRET");
    }

    if (missing.length > 0) {
        throw new Error(
            `FATAL: Missing required environment variable(s): ${missing.join(", ")}. ` +
            "Configure them before starting TrustVault in production."
        );
    }

    if (process.env.SESSION_SECRET === DEV_SESSION_SECRET) {
        throw new Error(
            "FATAL: SESSION_SECRET is still the development fallback value. " +
            "Generate a unique secret before starting TrustVault in production."
        );
    }

    if (process.env.SESSION_SECRET.length < MIN_SESSION_SECRET_LENGTH) {
        throw new Error(
            `FATAL: SESSION_SECRET must be at least ${MIN_SESSION_SECRET_LENGTH} characters long.`
        );
    }
}

function resolveSessionSecret() {
    const secret = process.env.SESSION_SECRET;

    if (secret) {
        return secret;
    }

    if (IS_PRODUCTION) {
        // requireProductionEnv() already ran and throws in this case.
        throw new Error("FATAL: SESSION_SECRET is required.");
    }

    return DEV_SESSION_SECRET;
}

function resolveDatabaseUrl() {
    if (IS_TEST) {
        // --- Test isolation guard -------------------------------------------------
        // The automated suite is destructive (it truncates tables and creates
        // users/documents). It must never be pointed at a shared development or
        // production database, so the process refuses to start otherwise.
        const testUrl = process.env.TEST_DATABASE_URL;

        if (!testUrl) {
            throw new Error(
                "FATAL: TEST_DATABASE_URL is required when NODE_ENV=test.\n" +
                "The test-suite is destructive and must never run against the " +
                "development or production database.\n" +
                "Create an empty database dedicated to testing and point " +
                "TEST_DATABASE_URL at it (see .env.example)."
            );
        }

        const testDatabase = databaseNameFromUrl(testUrl);
        const devDatabase = databaseNameFromUrl(process.env.DATABASE_URL);

        if (!testDatabase) {
            throw new Error(
                "FATAL: TEST_DATABASE_URL must contain a database name so the " +
                "test harness can verify it is isolated from the development database."
            );
        }

        if (devDatabase && testDatabase === devDatabase) {
            throw new Error(
                `FATAL: Refusing to run tests against the development database "${testDatabase}".\n` +
                "TEST_DATABASE_URL must point at a separate, empty test database."
            );
        }

        if (!/test/i.test(testDatabase)) {
            throw new Error(
                `FATAL: Refusing to run tests against database "${testDatabase}".\n` +
                "The test database name must contain the word \"test\" so it cannot " +
                "be mistaken for the development or production database."
            );
        }

        return testUrl;
    }

    return process.env.DATABASE_URL;
}

function toPositiveInt(value, fallback) {
    const parsed = Number.parseInt(value, 10);
    return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

if (IS_PRODUCTION) {
    requireProductionEnv();
}

const DATABASE_URL = resolveDatabaseUrl();

/** Remote databases (Neon, or anything demanding TLS) must use SSL. */
function shouldUseSsl(connectionString) {
    if (!connectionString) return false;
    return (
        connectionString.includes("neon.tech") ||
        connectionString.includes("sslmode=require") ||
        connectionString.includes("sslmode=verify-full") ||
        connectionString.includes("sslmode=verify-ca")
    );
}

const SESSION_SECRET = resolveSessionSecret();

const UPLOAD_DIR = process.env.UPLOAD_DIR
    ? path.resolve(process.env.UPLOAD_DIR)
    : path.join(__dirname, "..", "uploads");

module.exports = {
    NODE_ENV,
    IS_PRODUCTION,
    IS_TEST,
    IS_DEVELOPMENT,

    DATABASE_URL,
    SESSION_SECRET,
    UPLOAD_DIR,
    SSL: shouldUseSsl(DATABASE_URL),

    /** CSRF protection is enabled everywhere except the automated test-suite. */
    CSRF_ENABLED: !IS_TEST,
    /** Route helpers used for local debugging are never mounted in production. */
    MOUNT_TEST_ROUTES: IS_DEVELOPMENT || IS_TEST,

    TRUST_PROXY: toPositiveInt(process.env.TRUST_PROXY, 1),
    SESSION_MAX_AGE_MS: 1000 * 60 * 60 * 8,

    RATE_LIMIT_API: toPositiveInt(process.env.RATE_LIMIT_API, IS_TEST ? 100000 : 1000),
    RATE_LIMIT_AUTH: toPositiveInt(process.env.RATE_LIMIT_AUTH, IS_TEST ? 100000 : 30),

    DEV_SESSION_SECRET,
    MIN_SESSION_SECRET_LENGTH,
    databaseNameFromUrl
};
