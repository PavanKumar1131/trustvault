/**
 * Jest configuration.
 *
 * The suite is executed with `--runInBand` (see package.json) because every
 * test file shares one PostgreSQL database: running the files in parallel
 * would let them truncate each other's fixtures.
 *
 * `NODE_ENV` is set to "test" by Jest itself; `tests/setupEnv.js` makes the
 * same guarantee explicit and isolates the upload directory.
 */
module.exports = {
    testEnvironment: "node",
    testMatch: ["<rootDir>/tests/**/*.test.js"],
    globalSetup: "<rootDir>/tests/globalSetup.js",
    setupFiles: ["<rootDir>/tests/setupEnv.js"],
    setupFilesAfterEnv: ["<rootDir>/tests/setupAfterEnv.js"],
    testTimeout: 60000,
    verbose: true,
    collectCoverageFrom: [
        "src/**/*.js",
        "!src/scripts/**",
        "!src/routes/test.js"
    ],
    coverageReporters: ["text-summary", "lcov"]
};
