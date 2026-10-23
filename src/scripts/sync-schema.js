/**
 * Keeps `src/scripts/schema.sql` byte-identical to the canonical
 * `src/schema.sql`.
 *
 * The project historically contained two copies of the schema which drifted
 * apart. Rather than deleting one of them (and breaking anything that
 * references it), the copy is now generated from the canonical file. The
 * test-suite asserts that both files are identical, so a manual edit that
 * forgets to re-run this script fails the build.
 *
 * Usage: npm run schema:sync
 */

const fs = require("node:fs");
const path = require("node:path");

const SOURCE = path.join(__dirname, "..", "schema.sql");
const TARGET = path.join(__dirname, "schema.sql");

function syncSchema() {
    const content = fs.readFileSync(SOURCE, "utf8");
    fs.writeFileSync(TARGET, content, "utf8");
    console.log(`Synced ${path.relative(process.cwd(), TARGET)} from ${path.relative(process.cwd(), SOURCE)}`);
}

if (require.main === module) {
    syncSchema();
}

module.exports = { syncSchema, SOURCE, TARGET };
