const app = require("../src/app");
const pool = require("../src/db");
const {
    REQUEST_TYPES,
    REQUEST_POLICIES,
    getRequestPolicy,
    canSubmitRequest,
    canReviewRequest,
    canReviewerActOnRequest,
    resolveRequestReviewer
} = require("../src/services/requestPolicyRegistry");
const {
    resetDatabase,
    registerAndLogin,
    uploadDocument,
    VALID_PDF_BUFFER
} = require("./helpers");

describe("request policy registry", () => {
    test("Document Owner upgrade has a server-owned handler and bounded transitions", () => {
        const policy = getRequestPolicy(REQUEST_TYPES.DOCUMENT_OWNER_UPGRADE);
        expect(policy.handler).toBe("documentOwnerUpgrade");
        expect(policy.submitterRoles).toEqual(["viewer"]);
        expect(policy.reviewerRoles).toEqual(["admin"]);
        expect(policy.permissionChanges).toContain("users.role:viewer->document_owner");
        expect(policy.allowedTransitions).toEqual(["approved", "rejected", "cancelled"]);
        expect(canSubmitRequest(policy.type, "viewer")).toBe(true);
        expect(canReviewRequest(policy.type, "admin")).toBe(true);
        expect(canReviewerActOnRequest(policy.type, "admin", "admin-1", "viewer-1")).toBe(true);
        expect(canReviewerActOnRequest(policy.type, "admin", "same-user", "same-user")).toBe(false);
    });

    test("document access policy is defined but has no executable handler", () => {
        const policy = getRequestPolicy(REQUEST_TYPES.DOCUMENT_ACCESS, { requireEnabled: false });
        expect(policy.enabled).toBe(false);
        expect(policy.handler).toBeNull();
        expect(policy.reviewerResolver).toBe("target_resource_owner");
        expect(policy.reviewerRoles).toEqual(["document_owner"]);
        expect(getRequestPolicy(REQUEST_TYPES.DOCUMENT_ACCESS)).toBeNull();
        expect(canSubmitRequest(REQUEST_TYPES.DOCUMENT_ACCESS, "viewer")).toBe(false);
        expect(canReviewRequest(REQUEST_TYPES.DOCUMENT_ACCESS, "admin")).toBe(false);
        expect(REQUEST_POLICIES[REQUEST_TYPES.DOCUMENT_ACCESS].permissionChanges)
            .toEqual(["document_permissions:read", "document_permissions:edit"]);
    });
});

describe("document access reviewer resolution policy", () => {
    let ownerAgent;
    let owner;
    let requesterAgent;
    let document;

    beforeAll(async () => {
        await resetDatabase();
        const createdOwner = await registerAndLogin(app, {
            name: "Private document owner",
            email: "policy.owner@trustvault.test",
            role: "document_owner"
        });
        ownerAgent = createdOwner.agent;
        owner = createdOwner.user;
        const requester = await registerAndLogin(app, {
            name: "Private document requester",
            email: "policy.requester@trustvault.test",
            role: "viewer"
        });
        requesterAgent = requester.agent;
        document = await uploadDocument(ownerAgent, {
            name: "Policy-private-document",
            buffer: VALID_PDF_BUFFER
        });
    });

    test("a private resource request routes to its actual owner and grants nothing", async () => {
        const reviewer = await resolveRequestReviewer(
            pool,
            REQUEST_TYPES.DOCUMENT_ACCESS,
            document.id
        );
        expect(reviewer).toEqual({ reviewerRole: "document_owner", reviewerUserId: owner.id });

        const unsupported = await requesterAgent.post("/api/requests").send({
            requestType: REQUEST_TYPES.DOCUMENT_ACCESS,
            targetResourceId: document.id,
            requestedPermission: "read",
            reason: "Please share this private file"
        });
        expect(unsupported.status).toBe(400);

        const grant = await pool.query(
            "SELECT id FROM document_permissions WHERE document_id = $1 AND user_id = $2",
            [document.id, (await pool.query("SELECT id FROM users WHERE email = $1", ["policy.requester@trustvault.test"])).rows[0].id]
        );
        expect(grant.rows).toHaveLength(0);
    });
});
