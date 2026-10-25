/**
 * Jest `globalSetup` entry point.
 *
 * Runs once before the whole suite. It verifies that the configured database
 * really is a dedicated test database and brings its schema up to date, so
 * every test file starts from a known, identical structure.
 */

process.env.NODE_ENV = "test";

require("dotenv").config({ quiet: true });

const path = require("node:path");

process.env.UPLOAD_DIR =
    process.env.TEST_UPLOAD_DIR ||
    path.join(__dirname, "..", ".tmp", "test-uploads");

const config = require("../src/config");
const { assertSafeTestDatabase } = require("./testDatabaseGuard");

module.exports = async () => {
    if (!config.IS_TEST) {
        throw new Error("The test-suite must run with NODE_ENV=test.");
    }

    // Prints the loopback host and exact database name before anything is
    // truncated or migrated. Throws for any other host or database.
    const target = assertSafeTestDatabase({ print: true });

    const { migrate } = require("../src/scripts/migrate");
    const pool = require("../src/db");

    try {
        await migrate();
        console.log(
            `\n[tests] schema ready on test database "${target.database}"\n`
        );
    } finally {
        await pool.end().catch(() => {});
    }
};
