"use strict";

/**
 * Fail-closed guard for every destructive test run.
 *
 * The suite truncates users, documents, sessions and the audit log, so it may
 * only ever run against a database that is both:
 *
 *   1. on a loopback host (127.0.0.1, localhost or ::1), and
 *   2. named exactly `trustvault_test`.
 *
 * The guard deliberately does not print credentials. `globalSetup` calls it
 * with `print: true` once per run; `resetDatabase()` calls it again without
 * printing so an individual helper cannot be repointed at another database.
 */

const config = require("../src/config");

const LOCAL_HOSTS = new Set(["127.0.0.1", "localhost", "::1"]);
const EXPECTED_DATABASE = "trustvault_test";

function parseTarget(connectionString) {
    const parsed = new URL(connectionString);
    const host = parsed.hostname.replace(/^\[|\]$/g, "");
    const database = decodeURIComponent(parsed.pathname.replace(/^\//, ""));
    return { host, database };
}

function assertSafeTestDatabase({ print = false } = {}) {
    if (!config.IS_TEST) {
        throw new Error(
            "FATAL: destructive test guard requires NODE_ENV=test."
        );
    }

    const connectionString = config.DATABASE_URL;

    if (!connectionString) {
        throw new Error("FATAL: no test database URL is configured.");
    }

    let target;
    try {
        target = parseTarget(connectionString);
    } catch {
        throw new Error(
            "FATAL: TEST_DATABASE_URL is not a valid PostgreSQL URL."
        );
    }

    if (!LOCAL_HOSTS.has(target.host)) {
        throw new Error(
            `FATAL: refusing destructive tests against non-local host "${target.host}". ` +
            "TEST_DATABASE_URL must use 127.0.0.1, localhost or ::1."
        );
    }

    if (target.database !== EXPECTED_DATABASE) {
        throw new Error(
            `FATAL: refusing destructive tests against database "${target.database}". ` +
            `The test database must be named exactly "${EXPECTED_DATABASE}".`
        );
    }

    if (print) {
        console.log(
            `\n[tests] destructive target: ${target.host}/${target.database}\n`
        );
    }

    return target;
}

module.exports = { assertSafeTestDatabase, EXPECTED_DATABASE, LOCAL_HOSTS };
