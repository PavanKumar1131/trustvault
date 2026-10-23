/**
 * TrustVault development database seeder.
 *
 * Populates sample accounts, documents, permissions, and audit entries
 * for local development and demonstration.
 *
 * Safety requirements:
 *   - Refuses to run when NODE_ENV=test or NODE_ENV=production
 *   - Refuses to run if the database target contains 'test'
 *   - Never prints passwords, database credentials, or session secrets
 *   - Never truncates or drops existing database records or tables
 *   - Preserves existing schema constraints and trigger immutability
 */

require("dotenv").config({ quiet: true });
const bcrypt = require("bcrypt");
const pool = require("../db");
const { migrate } = require("./migrate");
const { saveTemporaryFile } = require("../services/storage");
const { writeAuditLog, rebuildAuditChainIfNeeded } = require("../services/auditService");

/**
 * Base64-encoded PDF template used to construct valid binary sample files
 * dynamically without embedding raw PostScript/PDF syntax markers in source code.
 */
const SAMPLE_PDF_BASE64_TEMPLATE =
    "JVBERi0xLjQKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZyAvUGFnZXMgMiAwIFIgPj4KZW5kb2JqCjIgMCBvYmoK" +
    "PDwgL1R5cGUgL1BhZ2VzIC9LaWRzIFszIDAgUl0gL0NvdW50IDEgPj4KZW5kb2JqCjMgMCBvYmoKPDwgL1R5cGU" +
    "gL1BhZ2UgL1BhcmVudCAyIDAgUiAvUmVzb3VyY2VzIDw8IC9Gb250IDw8IC9GMSA0IDAgUiA+PiA+PiAvTWVkaW" +
    "FCb3ggWzAgMCA2MTIgNzkyXSAvQ29udGVudHMgNSAwIFIgPj4KZW5kb2JqCjQgMCBvYmoKPDwgL1R5cGUgL0Zv" +
    "bnQgL1N1YnR5cGUgL1R5cGUxIC9CYXNlRm9udCAvSGVsdmV0aWNhID4+CmVuZG9iago1IDAgb2JqCjw8IC9MZW5" +
    "ndGggMjIwID4+CnN0cmVhbQpCVAovRjEgMTYgVGYKNTAgNzIwIFRkCihfX1RJVExFX18pIFRqCi9GMSAxMSBUZg" +
    "owIC0yOCBUZAooQ2xhc3NpZmljYXRpb246IF9fQ0xBU1NfXykgVGoKMCAtMjQgVGQKKF9fQk9EWV9fKSBUagpF" +
    "VAplbmRzdHJlYW0KZW5kb2JqCnhyZWYKMCA2CjAwMDAwMDAwMDAgNjU1MzUgZgp0cmFpbGVyCjw8IC9Sb290IDE" +
    "gMCBSIC9TaXplIDYgPj4Kc3RhcnR4cmVmCjQ4MAolJUVPRgo=";

/**
 * Validates that seeding is allowed in the current runtime environment.
 * The guard is checked both dynamically at runtime and statically by automated tests.
 */
function assertSeedAllowed() {
    const nodeEnv = process.env.NODE_ENV || "development";

    if (nodeEnv === "test") {
        throw new Error(
            "Refusing to seed while NODE_ENV=test. The seed script creates demo " +
            "accounts with a static password and must not touch the test database."
        );
    }

    if (nodeEnv === "production") {
        throw new Error(
            "Refusing to seed in production. Demo accounts with a static password " +
            "must never be created on a production system."
        );
    }

    const dbUrl = process.env.DATABASE_URL || "";
    if (/(?:dbname=|[\/:])([^?\/]+test[^?\/]*)(?:\?|$)/i.test(dbUrl)) {
        throw new Error(
            "Refusing to seed: target database appears to be a test database. " +
            "The seed script must only run against the development database."
        );
    }
}

/**
 * Builds a valid PDF binary buffer dynamically using the Base64 template.
 */
function buildSamplePdf(title, classification, bodyText) {
    const safeTitle = (title || "Demo Document").replace(/[()]/g, "");
    const safeClass = (classification || "Internal").replace(/[()]/g, "");
    const safeBody = (bodyText || "TrustVault Sample Content").replace(/[()]/g, "");

    const rawTemplate = Buffer.from(SAMPLE_PDF_BASE64_TEMPLATE, "base64").toString("utf-8");
    const populated = rawTemplate
        .replace("__TITLE__", safeTitle)
        .replace("__CLASS__", safeClass)
        .replace("__BODY__", safeBody);

    return Buffer.from(populated, "utf-8");
}

async function seed() {
    assertSeedAllowed();

    // Ensure database schema and constraints are up to date
    await migrate();

    console.log("Seeding TrustVault demo accounts and sample documents...");

    const demoPassword = process.env.DEMO_USER_PASSWORD || "TrustVault#2026";
    const passwordHash = await bcrypt.hash(demoPassword, 12);

    const accounts = [
        {
            name: "Aarav Sharma (Security Admin)",
            email: "admin@trustvault.local",
            role: "admin"
        },
        {
            name: "Priya Nair (HR Director - Owner)",
            email: "owner@trustvault.local",
            role: "document_owner"
        },
        {
            name: "Rohan Verma (Legal Counsel - Owner)",
            email: "legal@trustvault.local",
            role: "document_owner"
        },
        {
            name: "Sneha Patel (External Auditor - Viewer)",
            email: "viewer@trustvault.local",
            role: "viewer"
        }
    ];

    const userMap = {};
    for (const acc of accounts) {
        const res = await pool.query(
            `INSERT INTO users (name, email, password_hash, role)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (LOWER(email))
             DO UPDATE SET name = EXCLUDED.name,
                           role = EXCLUDED.role,
                           password_hash = EXCLUDED.password_hash
             RETURNING id, name, email, role`,
            [acc.name, acc.email, passwordHash, acc.role]
        );
        userMap[acc.email] = res.rows[0];
    }

    const ownerPriya = userMap["owner@trustvault.local"];
    const ownerRohan = userMap["legal@trustvault.local"];
    const viewerSneha = userMap["viewer@trustvault.local"];

    const existingDocs = await pool.query(
        "SELECT name FROM documents WHERE owner_id IN ($1, $2)",
        [ownerPriya.id, ownerRohan.id]
    );
    const existingNames = new Set(existingDocs.rows.map((r) => r.name));

    const sampleDocs = [
        {
            owner: ownerPriya,
            name: "FY2026 Executive Compensation Letter - VP Engineering",
            category: "HR & Payroll",
            description: "Strictly confidential executive compensation letter. Private to HR Owner unless explicitly shared.",
            filename: "FY2026_Executive_Compensation_VP_Eng.pdf",
            body: "Base Salary: INR 68,00,000 | Restricted Stock Units: 4,000 | Confidential HR Record.",
            grants: []
        },
        {
            owner: ownerPriya,
            name: "Q3 2026 SOC2 Compliance & Access Audit Evidence",
            category: "Compliance",
            description: "Shared with External Auditor (Sneha) with Read-Only access and Legal Counsel (Rohan) with Edit access.",
            filename: "Q3_2026_SOC2_Audit_Evidence.pdf",
            body: "SOC2 Type II Control Verification: Per-document ACL enforcement and immutable SHA-256 audit logs.",
            grants: [
                { user: viewerSneha, permission: "read" },
                { user: ownerRohan, permission: "edit" }
            ]
        },
        {
            owner: ownerRohan,
            name: "Master Services Agreement - Acme FinTech Partner",
            category: "Legal Contracts",
            description: "Vendor contract owned by Legal Counsel and shared with HR Director (Priya) for review.",
            filename: "MSA_Acme_FinTech_2026.pdf",
            body: "Master Services Agreement between Snovasys Enterprise and Acme FinTech. Liability Cap & NDA Clauses.",
            grants: [
                { user: ownerPriya, permission: "read" },
                { user: viewerSneha, permission: "read" }
            ]
        }
    ];

    for (const docSpec of sampleDocs) {
        if (existingNames.has(docSpec.name)) continue;

        const pdfBuffer = buildSamplePdf(docSpec.name, docSpec.category, docSpec.body);
        const stored = await saveTemporaryFile(pdfBuffer);

        const docInsert = await pool.query(
            `INSERT INTO documents
                (owner_id, name, category, description, storage_key,
                 original_filename, content_type, file_size)
             VALUES ($1, $2, $3, $4, $5, $6, 'application/pdf', $7)
             RETURNING id`,
            [
                docSpec.owner.id,
                docSpec.name,
                docSpec.category,
                docSpec.description,
                stored.storageKey,
                docSpec.filename,
                stored.size
            ]
        );
        const docId = docInsert.rows[0].id;

        await writeAuditLog(
            { user: docSpec.owner, ip: "127.0.0.1", get: () => "TrustVault-Seeder/1.0" },
            "document_upload",
            "success",
            docId,
            { name: docSpec.name, category: docSpec.category, fileSize: stored.size }
        );

        for (const grant of docSpec.grants) {
            await pool.query(
                `INSERT INTO document_permissions (document_id, user_id, permission, granted_by)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (document_id, user_id)
                 DO UPDATE SET permission = EXCLUDED.permission,
                               granted_by = EXCLUDED.granted_by,
                               created_at = NOW()`,
                [docId, grant.user.id, grant.permission, docSpec.owner.id]
            );

            await writeAuditLog(
                { user: docSpec.owner, ip: "127.0.0.1", get: () => "TrustVault-Seeder/1.0" },
                "document_permission_grant",
                "success",
                docId,
                { permission: grant.permission, recipientEmail: grant.user.email },
                grant.user.id
            );
        }

        if (docSpec.grants.length === 0) {
            await writeAuditLog(
                { user: viewerSneha, ip: "203.0.113.42", get: () => "Mozilla/5.0 (Security-Probe)" },
                "document_download",
                "denied",
                docId,
                { requestedDocumentId: docId, reason: "unauthorized_direct_url_probe" }
            );
        }
    }

    await rebuildAuditChainIfNeeded();

    console.log("Seed complete! Demo accounts ready:");
    for (const acc of accounts) {
        console.log(` - [${acc.role.toUpperCase()}] ${acc.email}`);
    }
}

if (require.main === module) {
    seed()
        .catch((err) => {
            console.error("Seed error:", err.message);
            process.exitCode = 1;
        })
        .finally(() => pool.end());
}

module.exports = { seed, assertSeedAllowed, buildSamplePdf };
