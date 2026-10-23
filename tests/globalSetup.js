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

module.exports = async () => {
    if (!config.IS_TEST) {
        throw new Error("The test-suite must run with NODE_ENV=test.");
    }

    const databaseName = config.databaseNameFromUrl(config.DATABASE_URL);

    if (!databaseName || !/test/i.test(databaseName)) {
        throw new Error(
            `Refusing to prepare "${databaseName}" for testing. The test database ` +
            "name must contain the word \"test\"."
        );
    }

    const { migrate } = require("../src/scripts/migrate");
    const pool = require("../src/db");

    try {
        await migrate();
        console.log(`\n[tests] schema ready on test database "${databaseName}"\n`);
    } finally {
        await pool.end().catch(() => {});
    }
};
