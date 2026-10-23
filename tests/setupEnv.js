/**
 * Jest `setupFiles` entry point.
 *
 * Runs before the test framework is installed and before any application
 * module is loaded. It guarantees two things:
 *
 *  1. `NODE_ENV` is "test" - so the application reads TEST_DATABASE_URL
 *     instead of the development database;
 *  2. the upload directory used by the suite is isolated from the directory
 *     used by the development environment.
 *
 * Requiring `src/config.js` performs the fail-closed isolation check: if
 * TEST_DATABASE_URL is missing, points at the development database, or names
 * a database that does not contain "test", the whole suite refuses to run
 * instead of destroying development data.
 */

process.env.NODE_ENV = "test";

require("dotenv").config({ quiet: true });

const path = require("node:path");

// Isolated upload directory for the test-suite.
process.env.UPLOAD_DIR =
    process.env.TEST_UPLOAD_DIR ||
    path.join(__dirname, "..", ".tmp", "test-uploads");

// Throws a descriptive error when the environment is not safe to test in.
require("../src/config");
