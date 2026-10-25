/**
 * Backend search integration tests.
 *
 * The global Search screen may send any combination of the supported filters
 * without a text term. These tests exercise the real route and the real SQL,
 * including owner matching, exact category matching, date boundaries and the
 * authorization scope that every search must preserve.
 */

const app = require("../src/app");
const pool = require("../src/db");
const {
    resetDatabase,
    registerAndLogin,
    uploadDocument
} = require("./helpers");

function ids(response) {
    return response.body.documents.map((document) => document.id).sort();
}

describe("TrustVault search filters", () => {
    const testRunId = Date.now().toString(36);
    const emails = {
        ownerA: `search.owner.a.${testRunId}@trustvault.test`,
        ownerB: `search.owner.b.${testRunId}@trustvault.test`,
        viewer: `search.viewer.${testRunId}@trustvault.test`
    };

    const agents = {};
    let alpha;
    let beta;
    let gamma;

    beforeAll(async () => {
        await resetDatabase();

        const ownerA = await registerAndLogin(app, {
            name: "Alice Anderson",
            email: emails.ownerA,
            role: "document_owner"
        });
        agents.ownerA = ownerA.agent;

        const ownerB = await registerAndLogin(app, {
            name: "Bob Brown",
            email: emails.ownerB,
            role: "document_owner"
        });
        agents.ownerB = ownerB.agent;

        const viewer = await registerAndLogin(app, {
            name: "Vera Viewer",
            email: emails.viewer,
            role: "viewer"
        });
        agents.viewer = viewer.agent;

        alpha = await uploadDocument(agents.ownerA, {
            name: `Alpha_Report_${testRunId}`,
            category: "Finance",
            description: "Quarterly budget"
        });
        gamma = await uploadDocument(agents.ownerA, {
            name: `Gamma_Report_${testRunId}`,
            category: "Finance",
            description: "Yearly budget"
        });
        beta = await uploadDocument(agents.ownerB, {
            name: `Beta_Contract_${testRunId}`,
            category: "Legal",
            description: "Signed contract"
        });

        // Deterministic timestamps so the date boundaries are unambiguous.
        await pool.query(
            "UPDATE documents SET created_at = $2::timestamptz WHERE id = $1",
            [alpha.id, "2026-01-15T12:00:00.000Z"]
        );
        await pool.query(
            "UPDATE documents SET created_at = $2::timestamptz WHERE id = $1",
            [beta.id, "2026-02-15T12:00:00.000Z"]
        );
        await pool.query(
            "UPDATE documents SET created_at = $2::timestamptz WHERE id = $1",
            [gamma.id, "2026-03-15T12:00:00.000Z"]
        );

        // The viewer may discover only Alpha and Beta. Gamma stays private to
        // its owner and must never appear in a filtered search.
        const alphaGrant = await agents.ownerA
            .post(`/api/documents/${alpha.id}/permissions`)
            .send({ email: emails.viewer, permission: "read" });
        expect(alphaGrant.status).toBe(200);

        const betaGrant = await agents.ownerB
            .post(`/api/documents/${beta.id}/permissions`)
            .send({ email: emails.viewer, permission: "read" });
        expect(betaGrant.status).toBe(200);
    });

    test("1. The owner filter matches an owner name or email", async () => {
        const byName = await agents.viewer
            .get("/api/documents")
            .query({ owner: "Alice Anderson" });
        expect(byName.status).toBe(200);
        expect(ids(byName)).toEqual([alpha.id]);

        const byEmail = await agents.viewer
            .get("/api/documents")
            .query({ owner: emails.ownerA });
        expect(byEmail.status).toBe(200);
        expect(ids(byEmail)).toEqual([alpha.id]);

        const otherOwner = await agents.viewer
            .get("/api/documents")
            .query({ owner: "Bob Brown" });
        expect(otherOwner.status).toBe(200);
        expect(ids(otherOwner)).toEqual([beta.id]);
    });

    test("2. A category-only search is exact and case-insensitive", async () => {
        const lowerCase = await agents.viewer
            .get("/api/documents")
            .query({ category: "finance" });
        expect(lowerCase.status).toBe(200);
        expect(ids(lowerCase)).toEqual([alpha.id]);

        const legal = await agents.viewer
            .get("/api/documents")
            .query({ category: "LEGAL" });
        expect(legal.status).toBe(200);
        expect(ids(legal)).toEqual([beta.id]);

        // Category is not a substring search.
        const partial = await agents.viewer
            .get("/api/documents")
            .query({ category: "Finan" });
        expect(partial.status).toBe(200);
        expect(ids(partial)).toEqual([]);
    });

    test("3. Start and end dates include and exclude the right rows", async () => {
        const afterAlpha = await agents.viewer
            .get("/api/documents")
            .query({ from: "2026-01-16" });
        expect(afterAlpha.status).toBe(200);
        expect(ids(afterAlpha)).toEqual([beta.id]);

        const beforeAlpha = await agents.viewer
            .get("/api/documents")
            .query({ to: "2026-01-14" });
        expect(beforeAlpha.status).toBe(200);
        expect(ids(beforeAlpha)).toEqual([]);

        const january = await agents.viewer
            .get("/api/documents")
            .query({ from: "2026-01-01", to: "2026-01-31" });
        expect(january.status).toBe(200);
        expect(ids(january)).toEqual([alpha.id]);

        const february = await agents.viewer
            .get("/api/documents")
            .query({ from: "2026-02-01", to: "2026-02-28" });
        expect(february.status).toBe(200);
        expect(ids(february)).toEqual([beta.id]);
    });

    test("4. A date-only end value covers the whole UTC day", async () => {
        const endOfAlphaDay = await agents.viewer
            .get("/api/documents")
            .query({ to: "2026-01-15" });
        expect(endOfAlphaDay.status).toBe(200);
        expect(ids(endOfAlphaDay)).toEqual([alpha.id]);

        const sameDay = await agents.viewer
            .get("/api/documents")
            .query({ from: "2026-01-15", to: "2026-01-15" });
        expect(sameDay.status).toBe(200);
        expect(ids(sameDay)).toEqual([alpha.id]);
    });

    test("5. Category, owner and date filters combine without a text term", async () => {
        const response = await agents.viewer
            .get("/api/documents")
            .query({
                category: "Finance",
                owner: "Alice Anderson",
                from: "2026-01-01",
                to: "2026-01-31"
            });

        expect(response.status).toBe(200);
        expect(ids(response)).toEqual([alpha.id]);
        expect(response.body.page).toBe(1);
        expect(response.body.count).toBe(1);
    });

    test("6. The text term matches name or description, never category", async () => {
        const byDescription = await agents.ownerA
            .get("/api/documents")
            .query({ q: "Quarterly budget" });
        expect(byDescription.status).toBe(200);
        expect(ids(byDescription)).toEqual([alpha.id]);

        const byName = await agents.ownerA
            .get("/api/documents")
            .query({ q: "Gamma_Report" });
        expect(byName.status).toBe(200);
        expect(ids(byName)).toEqual([gamma.id]);

        // "Finance" is the category of two documents, but it is not part of
        // either name or description, so the text term must not match them.
        const byCategoryText = await agents.ownerA
            .get("/api/documents")
            .query({ q: "Finance" });
        expect(byCategoryText.status).toBe(200);
        expect(ids(byCategoryText)).toEqual([]);
    });

    test("7. Filters never widen the caller's authorization scope", async () => {
        const viewerEverything = await agents.viewer.get("/api/documents");
        expect(viewerEverything.status).toBe(200);
        expect(ids(viewerEverything)).toEqual([alpha.id, beta.id].sort());

        const viewerAlice = await agents.viewer
            .get("/api/documents")
            .query({ owner: "Alice Anderson" });
        expect(viewerAlice.status).toBe(200);
        expect(ids(viewerAlice)).toEqual([alpha.id]);
        expect(ids(viewerAlice)).not.toContain(gamma.id);

        const ownerSearchingForAnotherOwner = await agents.ownerA
            .get("/api/documents")
            .query({ owner: "Bob Brown" });
        expect(ownerSearchingForAnotherOwner.status).toBe(200);
        expect(ids(ownerSearchingForAnotherOwner)).toEqual([]);
    });

    test("8. Pagination still applies to a filtered result", async () => {
        const first = await agents.ownerA
            .get("/api/documents")
            .query({ category: "Finance", limit: 1, page: 1 });
        expect(first.status).toBe(200);
        expect(first.body.documents).toHaveLength(1);

        const second = await agents.ownerA
            .get("/api/documents")
            .query({ category: "Finance", limit: 1, page: 2 });
        expect(second.status).toBe(200);
        expect(second.body.documents).toHaveLength(1);

        const firstId = first.body.documents[0].id;
        const secondId = second.body.documents[0].id;
        expect(firstId).not.toBe(secondId);
        expect([firstId, secondId].sort()).toEqual([alpha.id, gamma.id].sort());
    });
});
