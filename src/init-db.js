/**
 * Initialises a TrustVault database.
 *
 * The script applies the canonical schema (`src/schema.sql`) and then runs
 * the data upgrades, which is exactly what `npm run migrate` does. It exists
 * as a separate entry point for deployments that provision an empty database.
 */

const { migrate } = require("./scripts/migrate");
const pool = require("./db");

async function initializeDatabase() {
    try {
        await migrate();
        console.log("TrustVault database initialized successfully.");
    } catch (error) {
        console.error("Database initialization failed:", error.message);
        process.exitCode = 1;
    } finally {
        await pool.end();
    }
}

if (require.main === module) {
    initializeDatabase();
}

module.exports = { initializeDatabase };
