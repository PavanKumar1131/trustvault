/**
 * Shared helpers for the TrustVault test-suite.
 *
 * Every helper asserts on real database state — the tests never trust the
 * HTTP response alone.
 */

const request = require("supertest");
const bcrypt = require("bcrypt");
const fs = require("node:fs/promises");
const path = require("node:path");
const pool = require("../../src/db");
const config = require("../../src/config");

/** Password used by every test account. */
const TEST_PASSWORD = "StrongTestPassword!2026";

/** A minimal but structurally valid PDF. */
const VALID_PDF_BUFFER = Buffer.from(
    "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n",
    "utf-8"
);

/** A minimal PNG (signature + IHDR). */
const VALID_PNG_BUFFER = Buffer.from(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c6360000002000100" +
        "05fe02fea7b1a1a40000000049454e44ae426082",
    "hex"
);

/** A file that pretends to be a PDF but is not. */
const SPOOFED_MALICIOUS_BUFFER = Buffer.from(
    "MZ\x90\x00<script>alert('stolen_document')</script>",
    "utf-8"
);

/**
 * Empties the test database and resets the audit chain anchor.
 *
 * TRUNCATE is not blocked by the append-only trigger (that trigger only
 * fires for UPDATE/DELETE), so the audit log can be reset without dropping
 * the protection.
 */
async function resetDatabase() {
    await pool.query(`
        TRUNCATE TABLE
            audit_incident_annotations,
            audit_logs,
            audit_chain_state,
            document_permissions,
            documents,
            document_blobs,
            user_sessions,
            users
        RESTART IDENTITY CASCADE
    `);

    await pool.query(`
        INSERT INTO audit_chain_state (id, last_entry_id, last_hash)
        VALUES (1, 0, 'GENESIS')
        ON CONFLICT (id) DO NOTHING
    `);

    await clearUploadDirectory();
}

/** Removes every file the test-suite wrote to the upload directory. */
async function clearUploadDirectory() {
    const directory = config.UPLOAD_DIR;
    await fs.mkdir(directory, { recursive: true });

    const entries = await fs.readdir(directory);

    await Promise.all(
        entries.map((entry) =>
            fs.rm(path.join(directory, entry), { recursive: true, force: true })
        )
    );
}

/**
 * Creates a user directly in the database.
 * Used for accounts that cannot be created through the public registration
 * endpoint (administrators, disabled accounts).
 */
async function createUser({
    name,
    email,
    role = "viewer",
    password = TEST_PASSWORD,
    isDisabled = false
}) {
    // A low cost factor keeps the suite fast; bcrypt accepts any cost.
    const passwordHash = await bcrypt.hash(password, 4);

    const result = await pool.query(
        `INSERT INTO users (name, email, password_hash, role, is_disabled)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, name, email, role, is_disabled`,
        [name, email, passwordHash, role, isDisabled]
    );

    return result.rows[0];
}

/**
 * Registers an account through the public API and logs it in.
 *
 * The public registration endpoint always creates a **Viewer**: it ignores a
 * client supplied role on purpose, so that nobody can self-assign the
 * document_owner or admin role. A role other than "viewer" therefore has to be
 * granted afterwards by an administrator. The fixture performs exactly that
 * step directly in the database, which is what
 * `PATCH /api/admin/users/:id/role` does in production.
 *
 * @returns {{agent: object, user: object}}
 */
async function registerAndLogin(app, { name, email, role = "viewer", password = TEST_PASSWORD }) {
    const agent = request.agent(app);

    const registration = await agent.post("/api/auth/register").send({
        name,
        email,
        password
    });

    if (registration.status !== 201) {
        throw new Error(
            `Registration failed (${registration.status}): ${JSON.stringify(registration.body)}`
        );
    }

    let registeredUser = registration.body.user;

    if (role && role !== registeredUser.role) {
        const promoted = await pool.query(
            `UPDATE users SET role = $1 WHERE id = $2
             RETURNING id, name, email, role, is_disabled, created_at`,
            [role, registeredUser.id]
        );
        registeredUser = promoted.rows[0];
    }

    const login = await agent.post("/api/auth/login").send({ email, password });

    if (login.status !== 200) {
        throw new Error(`Login failed (${login.status}): ${JSON.stringify(login.body)}`);
    }

    return { agent, user: registeredUser };
}

/** Logs an existing account in and returns the agent. */
async function login(app, { email, password = TEST_PASSWORD }) {
    const agent = request.agent(app);

    const response = await agent.post("/api/auth/login").send({ email, password });

    if (response.status !== 200) {
        throw new Error(`Login failed (${response.status}): ${JSON.stringify(response.body)}`);
    }

    return { agent, user: response.body.user };
}

/** Uploads a document through the API and returns the created document. */
async function uploadDocument(agent, { name, category = "General", description = null, buffer = VALID_PDF_BUFFER, filename = "document.pdf" }) {
    let requestBuilder = agent
        .post("/api/documents")
        .field("name", name)
        .field("category", category);

    if (description !== null) {
        requestBuilder = requestBuilder.field("description", description);
    }

    const response = await requestBuilder.attach("file", buffer, filename);

    if (response.status !== 201) {
        throw new Error(
            `Upload failed (${response.status}): ${JSON.stringify(response.body)}`
        );
    }

    return response.body.document;
}

/** Reads a single row from a table. */
async function fetchRow(table, where, params) {
    const result = await pool.query(
        `SELECT * FROM ${table} WHERE ${where} LIMIT 1`,
        params
    );
    return result.rows[0] || null;
}

/** Counts rows in a table. */
async function countRows(table, where = "TRUE", params = []) {
    const result = await pool.query(
        `SELECT COUNT(*)::int AS count FROM ${table} WHERE ${where}`,
        params
    );
    return result.rows[0].count;
}

/** Returns the audit rows matching the given filter, newest first. */
async function fetchAuditLogs({ action, outcome, documentId, limit = 200 } = {}) {
    const params = [];
    const where = [];

    if (action) {
        params.push(action);
        where.push(`action = $${params.length}`);
    }

    if (outcome) {
        params.push(outcome);
        where.push(`outcome = $${params.length}`);
    }

    if (documentId) {
        params.push(documentId);
        where.push(`document_id = $${params.length}`);
    }

    params.push(limit);

    const result = await pool.query(
        `SELECT * FROM audit_logs
         ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
         ORDER BY id DESC
         LIMIT $${params.length}`,
        params
    );

    return result.rows;
}

module.exports = {
    TEST_PASSWORD,
    VALID_PDF_BUFFER,
    VALID_PNG_BUFFER,
    SPOOFED_MALICIOUS_BUFFER,
    resetDatabase,
    clearUploadDirectory,
    createUser,
    registerAndLogin,
    login,
    uploadDocument,
    fetchRow,
    countRows,
    fetchAuditLogs,
    pool
};
