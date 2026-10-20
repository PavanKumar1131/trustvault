
require("dotenv").config();

const fs = require("node:fs/promises");
const path = require("node:path");
const pool = require("./db");

async function initializeDatabase() {
    try {
        const schemaPath = path.join(__dirname, "schema.sql");
        const schema = await fs.readFile(schemaPath, "utf8");

        await pool.query(schema);

        console.log("TrustVault database schema created successfully.");
    } catch (error) {
        console.error("Database initialization failed:", error.message);
        process.exitCode = 1;
    } finally {
        await pool.end();
    }
}

initializeDatabase();
