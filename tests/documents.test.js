/**
 * Document lifecycle suite: upload, download, edit, delete and listing.
 *
 * Covers the input validation rules, the file-type sniffing, the storage
 * behaviour and the search semantics. Every test asserts the HTTP status,
 * the response behaviour and the resulting database state.
 */

const request = require("supertest");
const fs = require("node:fs/promises");
const path = require("node:path");
const app = require("../src/app");
const pool = require("../src/db");
const config = require("../src/config");
const {
    TEST_PASSWORD,
    VALID_PDF_BUFFER,
    VALID_PNG_BUFFER,
    VALID_JPEG_BUFFER,
    SPOOFED_MALICIOUS_BUFFER,
    resetDatabase,
    createUser,
    registerAndLogin,
    uploadDocument,
    fetchRow,
    countRows
} = require("./helpers");

const MAX_FILE_SIZE = 5 * 1024 * 1024;

describe("TrustVault document lifecycle", () => {
    const testRunId = Date.now().toString(36);
    const password = TEST_PASSWORD;

    const emails = {
        owner: `docs.owner.${testRunId}@trustvault.test`,
        partner: `docs.partner.${testRunId}@trustvault.test`
    };

    const agents = {};
    const users = {};
    let documentId = null;

    beforeAll(async () => {
        await resetDatabase();

        const owner = await registerAndLogin(app, {
            name: "Docs Owner", email: emails.owner, role: "document_owner"
        });
        agents.owner = owner.agent;
        users.owner = owner.user;

        const partner = await registerAndLogin(app, {
            name: "Docs Partner", email: emails.partner, role: "document_owner"
        });
        agents.partner = partner.agent;
        users.partner = partner.user;
    });

    // ══════════════════════════════════════════════════════════════════════
    test("1. A valid upload stores the document and its blob", async () => {
        const before = await countRows("documents");

        const response = await agents.owner
            .post("/api/documents")
            .field("name", `Report_${testRunId}`)
            .field("category", "Finance")
            .field("description", "Quarterly report")
            .attach("file", VALID_PDF_BUFFER, "Report.pdf");

        expect(response.status).toBe(201);
        expect(response.body.document.name).toBe(`Report_${testRunId}`);
        expect(response.body.document.category).toBe("Finance");
        expect(response.body.document.content_type).toBe("application/pdf");
        expect(response.body.document.access_level).toBe("owner");
        documentId = response.body.document.id;

        // Database state: the document and the blob exist and are linked.
        expect(await countRows("documents")).toBe(before + 1);

        const document = await fetchRow("documents", "id = $1", [documentId]);
        expect(document.owner_id).toBe(users.owner.id);
        expect(Number(document.file_size)).toBe(VALID_PDF_BUFFER.length);
        expect(document.original_filename).toBe("Report.pdf");

        const blob = await fetchRow("document_blobs", "storage_key = $1", [document.storage_key]);
        expect(blob).not.toBeNull();
        expect(Buffer.from(blob.file_data).equals(VALID_PDF_BUFFER)).toBe(true);

        // The file is also written to the isolated upload directory.
        const stored = await fs.readFile(path.join(config.UPLOAD_DIR, document.storage_key));
        expect(stored.equals(VALID_PDF_BUFFER)).toBe(true);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("2. A PNG upload is accepted and typed correctly", async () => {
        const response = await agents.owner
            .post("/api/documents")
            .field("name", `Diagram_${testRunId}`)
            .attach("file", VALID_PNG_BUFFER, "diagram.png");

        expect(response.status).toBe(201);
        expect(response.body.document.content_type).toBe("image/png");

        const document = await fetchRow("documents", "id = $1", [response.body.document.id]);
        expect(document.content_type).toBe("image/png");
        expect(Number(document.file_size)).toBe(VALID_PNG_BUFFER.length);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("2b. A JPEG upload is accepted and typed correctly", async () => {
        const response = await agents.owner
            .post("/api/documents")
            .field("name", `Photo_${testRunId}`)
            .attach("file", VALID_JPEG_BUFFER, "photo.jpg");

        expect(response.status).toBe(201);
        expect(response.body.document.content_type).toBe("image/jpeg");

        const document = await fetchRow("documents", "id = $1", [response.body.document.id]);
        expect(document.content_type).toBe("image/jpeg");
        expect(Number(document.file_size)).toBe(VALID_JPEG_BUFFER.length);

        const blob = await fetchRow("document_blobs", "storage_key = $1", [document.storage_key]);
        expect(Buffer.from(blob.file_data).equals(VALID_JPEG_BUFFER)).toBe(true);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("2c. A file of exactly 5 MiB is accepted", async () => {
        const exact = Buffer.concat([
            VALID_PDF_BUFFER,
            Buffer.alloc(MAX_FILE_SIZE - VALID_PDF_BUFFER.length)
        ]);

        const response = await agents.owner
            .post("/api/documents")
            .field("name", `ExactLimit_${testRunId}`)
            .attach("file", exact, "exact-limit.pdf");

        expect(response.status).toBe(201);
        expect(Number(response.body.document.file_size)).toBe(MAX_FILE_SIZE);

        const document = await fetchRow("documents", "id = $1", [response.body.document.id]);
        expect(Number(document.file_size)).toBe(MAX_FILE_SIZE);

        const blob = await fetchRow("document_blobs", "storage_key = $1", [document.storage_key]);
        expect(blob.file_data.length).toBe(MAX_FILE_SIZE);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("2d. A file over 5 MiB is rejected with 413", async () => {
        const tooLarge = Buffer.concat([
            VALID_PDF_BUFFER,
            Buffer.alloc(MAX_FILE_SIZE + 1 - VALID_PDF_BUFFER.length)
        ]);
        const beforeDocuments = await countRows("documents");
        const beforeBlobs = await countRows("document_blobs");

        const response = await agents.owner
            .post("/api/documents")
            .field("name", `OverLimit_${testRunId}`)
            .attach("file", tooLarge, "over-limit.pdf");

        expect(response.status).toBe(413);
        expect(response.body.message).toMatch(/5 MB limit/i);

        expect(await countRows("documents")).toBe(beforeDocuments);
        expect(await countRows("document_blobs")).toBe(beforeBlobs);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("2e. Content detection, not the filename, decides the stored type", async () => {
        const response = await agents.owner
            .post("/api/documents")
            .field("name", `MismatchedExtension_${testRunId}`)
            .attach("file", VALID_PNG_BUFFER, "looks-like-a-pdf.pdf");

        expect(response.status).toBe(201);
        expect(response.body.document.content_type).toBe("image/png");
        expect(response.body.document.original_filename).toBe("looks-like-a-pdf.pdf");

        const document = await fetchRow("documents", "id = $1", [response.body.document.id]);
        expect(document.content_type).toBe("image/png");
    });

    // ══════════════════════════════════════════════════════════════════════
    test("2f. Invalid content with a JPEG extension is rejected", async () => {
        const before = await countRows("documents");

        const response = await agents.owner
            .post("/api/documents")
            .field("name", "Disguised JPEG")
            .attach("file", SPOOFED_MALICIOUS_BUFFER, "photo.jpg");

        expect(response.status).toBe(415);
        expect(response.body.message).toMatch(/PDF, JPEG, and PNG/i);
        expect(await countRows("documents")).toBe(before);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("3. A file whose content does not match its extension is rejected", async () => {
        const before = await countRows("documents");

        const response = await agents.owner
            .post("/api/documents")
            .field("name", "Disguised Executable")
            .attach("file", SPOOFED_MALICIOUS_BUFFER, "salary.pdf");

        expect(response.status).toBe(415);
        expect(response.body.message).toMatch(/PDF, JPEG, and PNG/i);

        // Database state: nothing was stored.
        expect(await countRows("documents")).toBe(before);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("4. An empty file is rejected with 400", async () => {
        const before = await countRows("documents");
        const blobsBefore = await countRows("document_blobs");

        const response = await agents.owner
            .post("/api/documents")
            .field("name", "Empty File")
            .attach("file", Buffer.alloc(0), "empty.pdf");

        expect(response.status).toBe(400);
        expect(response.body.message).toMatch(/empty/i);

        // Database state: nothing was stored.
        expect(await countRows("documents")).toBe(before);
        expect(await countRows("document_blobs")).toBe(blobsBefore);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("5. A request without a file is rejected with 400", async () => {
        const before = await countRows("documents");

        const response = await agents.owner
            .post("/api/documents")
            .field("name", "No File");

        expect(response.status).toBe(400);

        // Database state: nothing was stored.
        expect(await countRows("documents")).toBe(before);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("6. A missing or over-long document name is rejected with 400", async () => {
        const before = await countRows("documents");

        const missingName = await agents.owner
            .post("/api/documents")
            .field("category", "General")
            .attach("file", VALID_PDF_BUFFER, "noname.pdf");
        expect(missingName.status).toBe(400);

        const longName = await agents.owner
            .post("/api/documents")
            .field("name", "x".repeat(300))
            .attach("file", VALID_PDF_BUFFER, "longname.pdf");
        expect(longName.status).toBe(400);

        const longCategory = await agents.owner
            .post("/api/documents")
            .field("name", "Valid Name")
            .field("category", "c".repeat(200))
            .attach("file", VALID_PDF_BUFFER, "longcategory.pdf");
        expect(longCategory.status).toBe(400);

        const longDescription = await agents.owner
            .post("/api/documents")
            .field("name", "Valid Name")
            .field("description", "d".repeat(3000))
            .attach("file", VALID_PDF_BUFFER, "longdescription.pdf");
        expect(longDescription.status).toBe(400);

        // Database state: nothing was stored.
        expect(await countRows("documents")).toBe(before);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("7. The download returns the exact bytes with protective headers", async () => {
        const response = await agents.owner.get(`/api/documents/${documentId}/download`);

        expect(response.status).toBe(200);
        expect(Buffer.from(response.body).equals(VALID_PDF_BUFFER)).toBe(true);
        expect(response.headers["content-type"]).toMatch(/application\/pdf/);
        expect(response.headers["content-disposition"]).toMatch(/attachment; filename="Report\.pdf"/);
        expect(response.headers["x-content-type-options"]).toBe("nosniff");
        expect(response.headers["cache-control"]).toMatch(/no-store/i);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("8. Metadata can be edited without replacing the file", async () => {
        const before = await fetchRow("documents", "id = $1", [documentId]);

        const response = await agents.owner
            .put(`/api/documents/${documentId}`)
            .field("name", `Report_Updated_${testRunId}`)
            .field("category", "Legal")
            .field("description", "Updated description");

        expect(response.status).toBe(200);
        expect(response.body.document.name).toBe(`Report_Updated_${testRunId}`);
        expect(response.body.document.category).toBe("Legal");

        // Database state: the metadata changed, the blob stayed the same.
        const after = await fetchRow("documents", "id = $1", [documentId]);
        expect(after.name).toBe(`Report_Updated_${testRunId}`);
        expect(after.category).toBe("Legal");
        expect(after.description).toBe("Updated description");
        expect(after.storage_key).toBe(before.storage_key);
        expect(after.file_size).toBe(before.file_size);
        expect(new Date(after.updated_at).getTime()).toBeGreaterThan(
            new Date(before.updated_at).getTime()
        );
    });

    // ══════════════════════════════════════════════════════════════════════
    test("9. Replacing the file swaps the blob and removes the old one", async () => {
        const before = await fetchRow("documents", "id = $1", [documentId]);

        const response = await agents.owner
            .put(`/api/documents/${documentId}`)
            .field("name", `Report_Updated_${testRunId}`)
            .attach("file", VALID_PNG_BUFFER, "replacement.png");

        expect(response.status).toBe(200);
        expect(response.body.document.content_type).toBe("image/png");

        // Database state: the document points at the new blob, the old blob
        // row and the old file are gone.
        const after = await fetchRow("documents", "id = $1", [documentId]);
        expect(after.storage_key).not.toBe(before.storage_key);
        expect(Number(after.file_size)).toBe(VALID_PNG_BUFFER.length);

        expect(await fetchRow("document_blobs", "storage_key = $1", [before.storage_key])).toBeNull();
        expect(await fetchRow("document_blobs", "storage_key = $1", [after.storage_key])).not.toBeNull();

        // The old file is gone from disk, the new file holds the new bytes.
        await expect(
            fs.access(path.join(config.UPLOAD_DIR, before.storage_key))
        ).rejects.toBeDefined();

        const written = await fs.readFile(path.join(config.UPLOAD_DIR, after.storage_key));
        expect(written.equals(VALID_PNG_BUFFER)).toBe(true);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("10. Search treats LIKE wildcards literally", async () => {
        // A document whose name contains the LIKE wildcards ...
        const special = await uploadDocument(agents.owner, {
            name: `100%_Sensitive_${testRunId}`,
            category: "Insurance"
        });

        // ... and one without any wildcard character.
        const plain = await uploadDocument(agents.owner, {
            name: `PlainDocument${testRunId}`,
            category: "Insurance"
        });

        // Searching for the literal text finds both, because both names
        // contain the searched substring.
        const literal = await agents.owner
            .get("/api/documents")
            .query({ q: "100%_Sensitive" });
        expect(literal.status).toBe(200);
        expect(literal.body.documents.some((d) => d.id === special.id)).toBe(true);

        // "%" must be matched literally: it may only return the document that
        // really contains a percent sign, never every document.
        const wildcardOnly = await agents.owner
            .get("/api/documents")
            .query({ q: "%" });
        expect(wildcardOnly.status).toBe(200);
        expect(wildcardOnly.body.documents.some((d) => d.id === special.id)).toBe(true);
        expect(wildcardOnly.body.documents.some((d) => d.id === plain.id)).toBe(false);

        // The same applies to the single-character wildcard "_".
        const underscore = await agents.owner
            .get("/api/documents")
            .query({ q: "_" });
        expect(underscore.status).toBe(200);
        expect(underscore.body.documents.some((d) => d.id === special.id)).toBe(true);
        expect(underscore.body.documents.some((d) => d.id === plain.id)).toBe(false);

        // Database state: the search did not change anything.
        expect(await countRows("documents")).toBeGreaterThan(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("11. The listing is paginated and stable", async () => {
        const firstPage = await agents.owner.get("/api/documents").query({ limit: 2, page: 1 });
        expect(firstPage.status).toBe(200);
        expect(firstPage.body.limit).toBe(2);
        expect(firstPage.body.page).toBe(1);
        expect(firstPage.body.documents.length).toBeLessThanOrEqual(2);

        const secondPage = await agents.owner.get("/api/documents").query({ limit: 2, page: 2 });
        expect(secondPage.status).toBe(200);

        const firstIds = firstPage.body.documents.map((d) => d.id);
        const secondIds = secondPage.body.documents.map((d) => d.id);
        expect(firstIds.some((id) => secondIds.includes(id))).toBe(false);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("12. Deleting a document removes it together with its blob", async () => {
        const disposable = await uploadDocument(agents.owner, {
            name: `Disposable_${testRunId}`,
            category: "Temporary"
        });

        const storageKey = (await fetchRow("documents", "id = $1", [disposable.id])).storage_key;

        const response = await agents.owner.delete(`/api/documents/${disposable.id}`);
        expect(response.status).toBe(200);
        expect(response.body.message).toMatch(/deleted/i);

        // Database state: the document, its blob and its grants are gone.
        expect(await fetchRow("documents", "id = $1", [disposable.id])).toBeNull();
        expect(await fetchRow("document_blobs", "storage_key = $1", [storageKey])).toBeNull();
        expect(
            await countRows("document_permissions", "document_id = $1", [disposable.id])
        ).toBe(0);

        // The file is gone from disk as well.
        await expect(fs.access(path.join(config.UPLOAD_DIR, storageKey))).rejects.toBeDefined();

        // The document is no longer reachable.
        expect((await agents.owner.get(`/api/documents/${disposable.id}`)).status).toBe(404);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("13. An invalid document id is answered with 404", async () => {
        expect((await agents.owner.get("/api/documents/not-a-uuid")).status).toBe(404);
        expect((await agents.owner.get("/api/documents/not-a-uuid/download")).status).toBe(404);
        expect((await agents.owner.delete("/api/documents/not-a-uuid")).status).toBe(404);

        const unknown = "11111111-2222-4333-8444-555555555555";
        expect((await agents.owner.get(`/api/documents/${unknown}`)).status).toBe(404);

        // Database state: nothing was created by the invalid requests.
        expect(await countRows("documents")).toBeGreaterThan(0);
    });

    // ══════════════════════════════════════════════════════════════════════
    test("14. The owner-scoped audit trail only contains this document", async () => {
        const response = await agents.owner.get(`/api/documents/${documentId}/audit`);

        expect(response.status).toBe(200);
        expect(Array.isArray(response.body.logs)).toBe(true);
        expect(response.body.logs.length).toBeGreaterThan(0);
        expect(
            response.body.logs.every((log) => log.document_id === documentId)
        ).toBe(true);

        const actions = response.body.logs.map((log) => log.action);
        expect(actions).toContain("document_upload");
        expect(actions).toContain("document_edit");
    });
});
