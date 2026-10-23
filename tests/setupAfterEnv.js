/**
 * Jest `setupFilesAfterEnv` entry point.
 *
 * Runs after the test framework is installed, once per test file.
 */

jest.setTimeout(60000);

// Every test file owns its own connection pool; closing it here keeps Jest
// from hanging on open sockets after the last test of a file.
afterAll(async () => {
    const pool = require("../src/db");
    await pool.end().catch(() => {});
});
