/**
 * PostgreSQL connection pool.
 *
 * The connection string is resolved by `src/config.js`, which performs the
 * test/production isolation guard. In the `test` environment the pool always
 * points at the dedicated TEST_DATABASE_URL and refuses to start when that
 * database is missing or identical to the development database.
 */

const { Pool } = require("pg");
const config = require("./config");

const pool = new Pool({
    connectionString: config.DATABASE_URL,
    ssl: config.SSL ? { rejectUnauthorized: true } : false,
    max: config.IS_TEST ? 25 : 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 20000,
    keepAlive: true,
    keepAliveInitialDelayMillis: 10000,
    application_name: config.IS_TEST ? "trustvault-test" : "trustvault"
});

// A pool-level error (e.g. an idle client dropped by the server) must not
// crash the process, but it has to be visible in the logs.
pool.on("error", (error) => {
    console.error("Unexpected error on an idle PostgreSQL client:", error.message);
});

module.exports = pool;
