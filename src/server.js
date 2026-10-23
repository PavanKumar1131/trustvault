/**
 * TrustVault HTTP server.
 *
 * The environment validation lives in `src/config.js`, which is imported
 * before the application so that a misconfigured production environment
 * aborts the process instead of starting with insecure defaults.
 */

const config = require("./config");
const app = require("./app");

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
    console.log(`TrustVault API:    http://localhost:${PORT}`);
    console.log(`Health check:      http://localhost:${PORT}/api/health`);
    console.log(`Database check:    http://localhost:${PORT}/api/health/db`);
    console.log(`Environment:       ${config.NODE_ENV}`);
    console.log(`CSRF protection:   ${config.CSRF_ENABLED ? "enabled" : "disabled (test-suite only)"}`);
});

/**
 * Graceful shutdown: stop accepting new connections and close the database
 * pool so that in-flight requests finish cleanly.
 */
function shutdown(signal) {
    console.log(`\n${signal} received, shutting down TrustVault...`);

    server.close(() => {
        const pool = require("./db");
        pool.end().finally(() => process.exit(0));
    });

    // Do not hang forever if a connection refuses to close.
    setTimeout(() => process.exit(1), 10000).unref();
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

module.exports = server;
