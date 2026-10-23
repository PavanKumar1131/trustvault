/**
 * Frontend DOM behaviour tests.
 *
 * The real public/index.html is loaded into a JSDOM document and the real
 * public/js/app.js is executed inside it. Only the network layer is replaced,
 * so every assertion is about the shipped controller, not about a copy of it.
 *
 * A fresh JSDOM window is created for every test, which keeps the state of
 * one test from leaking into the next.
 */

const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const indexHtml = fs.readFileSync(
    path.join(__dirname, "../public/index.html"),
    "utf8"
);
const appJs = fs.readFileSync(path.join(__dirname, "../public/js/app.js"), "utf8");

/** The markup without the two <script> tags — they are executed manually. */
const markup = indexHtml.replace(/<script[\s\S]*?<\/script>/g, "");

/**
 * Builds a stub for window.API.
 *
 * `handler(method, url, body)` returns `{status, body}`; anything it does not
 * answer is answered with an empty 200 so that a loader never fails just
 * because the test does not care about it.
 */
function createApiStub(handler) {
    const calls = [];

    function call(method, url, body) {
        calls.push({ method, url, body });

        const result = handler(method, url, body) || { status: 200, body: {} };
        const status = result.status === undefined ? 200 : result.status;

        const response = {
            ok: status >= 200 && status < 300,
            status,
            json: async () => result.body,
            text: async () => JSON.stringify(result.body),
            clone() {
                return response;
            }
        };

        return Promise.resolve(response);
    }

    /**
     * The download path of the controller reads the raw response: the status,
     * the blob and the `Content-Disposition` header. This stub answers all
     * three without touching the network.
     */
    function download(url) {
        calls.push({ method: "GET", url, download: true });

        const result = handler("GET", url) || { status: 200, body: {} };
        const status = result.status === undefined ? 200 : result.status;
        const headers = result.headers || {
            get: () => null
        };

        const response = {
            ok: status >= 200 && status < 300,
            status,
            headers,
            blob: async () => result.blob || null,
            json: async () => result.body,
            text: async () => JSON.stringify(result.body),
            clone() {
                return response;
            }
        };

        return Promise.resolve(response);
    }

    return {
        calls,
        get: (url) => call("GET", url),
        postJson: (url, body) => call("POST", url, body),
        putJson: (url, body) => call("PUT", url, body),
        patchJson: (url, body) => call("PATCH", url, body),
        postForm: (url, body) => call("POST", url, body),
        putForm: (url, body) => call("PUT", url, body),
        del: (url) => call("DELETE", url),
        download
    };
}

/**
 * Boots the application inside a fresh JSDOM window.
 *
 * @param {(method: string, url: string, body: any) => {status?: number, body?: any}} handler
 */
function boot(handler) {
    const dom = new JSDOM("<!DOCTYPE html><html><body></body></html>", {
        url: "https://trustvault.test/",
        runScripts: "outside-only",
        pretendToBeVisual: true
    });

    const { window } = dom;

    window.document.open();
    window.document.write(markup);
    window.document.close();

    window.API = createApiStub(handler);

    window.eval(appJs);
    window.document.dispatchEvent(new window.Event("DOMContentLoaded"));

    return { dom, window, document: window.document };
}

/** Lets the pending promises inside the controller settle. */
function flush(window, times = 4) {
    let chain = Promise.resolve();
    for (let index = 0; index < times; index += 1) {
        chain = chain.then(() => new Promise((resolve) => window.setTimeout(resolve, 0)));
    }
    return chain;
}

const USER = {
    admin: { id: "11111111-1111-4111-8111-111111111111", name: "Rathna Iyer", email: "rathna@example.com", role: "admin" },
    document_owner: { id: "22222222-2222-4222-8222-222222222222", name: "Alice Nair", email: "alice@example.com", role: "document_owner" },
    viewer: { id: "33333333-3333-4333-8333-333333333333", name: "Arjun Rao", email: "arjun@example.com", role: "viewer" }
};

/** A default API handler that serves a signed-in user of the given role. */
function signedIn(role) {
    return (method, url) => {
        if (url.startsWith("/api/auth/me")) {
            return { status: 200, body: { user: USER[role] } };
        }
        if (url.startsWith("/api/documents/filters")) {
            return { status: 200, body: FILTERS };
        }
        return { status: 200, body: {} };
    };
}

/** The filter options the server would really offer. */
const FILTERS = {
    categories: ["Finance", "Legal"],
    owners: [{ name: "Alice Nair", email: "alice@example.com" }]
};

function visible(element) {
    if (!element) return false;
    if (element.hasAttribute("hidden")) return false;
    return !element.classList.contains("hidden");
}

describe("TrustVault Frontend: DOM behaviour", () => {
    // ── Role gating ───────────────────────────────────────────────────────────

    describe("1. Role gating of the navigation", () => {
        it("shows a Viewer only Shared with me and Search", async () => {
            const { window, document } = boot(signedIn("viewer"));
            await flush(window);

            expect(visible(document.getElementById("nav-shared"))).toBe(true);
            expect(visible(document.getElementById("nav-search"))).toBe(true);

            expect(visible(document.getElementById("nav-dashboard"))).toBe(false);
            expect(visible(document.getElementById("nav-documents"))).toBe(false);
            expect(visible(document.getElementById("nav-upload"))).toBe(false);
            expect(visible(document.getElementById("nav-admin-audit"))).toBe(false);
            expect(visible(document.getElementById("nav-admin-users"))).toBe(false);
            expect(visible(document.getElementById("nav-section-admin"))).toBe(false);
        });

        it("shows a Document Owner Dashboard, My documents, Shared with me, Upload and Search", async () => {
            const { window, document } = boot(signedIn("document_owner"));
            await flush(window);

            expect(visible(document.getElementById("nav-dashboard"))).toBe(true);
            expect(visible(document.getElementById("nav-documents"))).toBe(true);
            expect(visible(document.getElementById("nav-shared"))).toBe(true);
            expect(visible(document.getElementById("nav-upload"))).toBe(true);
            expect(visible(document.getElementById("nav-search"))).toBe(true);

            expect(visible(document.getElementById("nav-admin-audit"))).toBe(false);
            expect(visible(document.getElementById("nav-admin-users"))).toBe(false);
        });

        it("shows an Admin Dashboard, Shared with me, Search, Audit log and Users — but no Upload", async () => {
            const { window, document } = boot(signedIn("admin"));
            await flush(window);

            expect(visible(document.getElementById("nav-dashboard"))).toBe(true);
            expect(visible(document.getElementById("nav-shared"))).toBe(true);
            expect(visible(document.getElementById("nav-search"))).toBe(true);
            expect(visible(document.getElementById("nav-admin-audit"))).toBe(true);
            expect(visible(document.getElementById("nav-admin-users"))).toBe(true);
            expect(visible(document.getElementById("nav-section-admin"))).toBe(true);

            expect(visible(document.getElementById("nav-upload"))).toBe(false);
            expect(visible(document.getElementById("nav-documents"))).toBe(false);
        });

        it("shows the signed-in identity and the role in the sidebar footer", async () => {
            const { window, document } = boot(signedIn("admin"));
            await flush(window);

            expect(document.getElementById("sidebar-user-email").textContent).toBe(
                "rathna@example.com"
            );
            expect(document.getElementById("sidebar-role").textContent).toBe("Role: Admin");
        });
    });

    // ── Escaping ──────────────────────────────────────────────────────────────

    describe("2. User content is never executed as markup", () => {
        const hostileName = '<img src=x onerror="window.__pwned=1">';

        it("renders a hostile document name as plain text", async () => {
            const handler = (method, url) => {
                if (url.startsWith("/api/auth/me")) {
                    return { status: 200, body: { user: USER.document_owner } };
                }
                if (url.startsWith("/api/documents/filters")) {
                    return { status: 200, body: { categories: [], owners: [] } };
                }
                if (url.startsWith("/api/documents?")) {
                    return {
                        status: 200,
                        body: {
                            documents: [
                                {
                                    id: "44444444-4444-4444-8444-444444444444",
                                    name: hostileName,
                                    category: "General",
                                    file_size: 1024,
                                    created_at: "2026-01-01T00:00:00.000Z",
                                    access_level: "owner"
                                }
                            ],
                            page: 1,
                            limit: 20,
                            count: 1
                        }
                    };
                }
                return { status: 200, body: {} };
            };

            const { window, document } = boot(handler);
            await flush(window);

            document.getElementById("nav-documents").click();
            await flush(window);

            const tbody = document.getElementById("documents-tbody");
            expect(tbody.textContent).toContain(hostileName);
            expect(tbody.querySelectorAll("img").length).toBe(0);
            expect(window.__pwned).toBeUndefined();
        });

        it("renders a hostile audit user name as plain text", async () => {
            const handler = (method, url) => {
                if (url.startsWith("/api/auth/me")) {
                    return { status: 200, body: { user: USER.admin } };
                }
                if (url.startsWith("/api/admin/audit-logs")) {
                    return {
                        status: 200,
                        body: {
                            logs: [
                                {
                                    id: 1,
                                    created_at: "2026-01-01T00:00:00.000Z",
                                    action: "auth_login",
                                    outcome: "success",
                                    actor_email: '<script>window.__x=1</script>'
                                }
                            ],
                            nextCursor: null,
                            worthALook: null
                        }
                    };
                }
                return { status: 200, body: {} };
            };

            const { window, document } = boot(handler);
            await flush(window);

            document.getElementById("nav-admin-audit").click();
            await flush(window);

            const tbody = document.getElementById("audit-tbody");
            expect(tbody.textContent).toContain("<script>window.__x=1</script>");
            expect(tbody.querySelectorAll("script").length).toBe(0);
            expect(window.__x).toBeUndefined();
        });
    });

    // ── Duplicate submit guard ────────────────────────────────────────────────

    describe("3. A button cannot submit twice", () => {
        it("sends only one sign-in request when the form is submitted twice", async () => {
            const handler = (method, url) => {
                if (url === "/api/auth/login") {
                    return { status: 200, body: { message: "Login successful" } };
                }
                if (url.startsWith("/api/auth/me")) {
                    return { status: 200, body: { user: USER.viewer } };
                }
                return { status: 200, body: {} };
            };

            const { window, document } = boot(handler);

            document.getElementById("login-email").value = "arjun@example.com";
            document.getElementById("login-password").value = "StrongTestPassword!2026";

            const form = document.getElementById("login-form");
            form.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
            form.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));

            await flush(window);

            const logins = window.API.calls.filter((entry) => entry.url === "/api/auth/login");
            expect(logins.length).toBe(1);
        });

        it("disables the submit button while the request is running", async () => {
            const handler = (method, url) => {
                if (url === "/api/auth/login") {
                    return { status: 200, body: { message: "Login successful" } };
                }
                return { status: 200, body: {} };
            };

            const { window, document } = boot(handler);

            document.getElementById("login-email").value = "arjun@example.com";
            document.getElementById("login-password").value = "StrongTestPassword!2026";

            const button = document.getElementById("login-btn");
            const form = document.getElementById("login-form");
            form.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));

            expect(button.disabled).toBe(true);

            await flush(window);

            expect(button.disabled).toBe(false);
        });
    });

    // ── Sign-in failures ──────────────────────────────────────────────────────

    describe("4. Sign-in failures are reported truthfully", () => {
        it("shows the server's own message for a wrong password", async () => {
            const handler = (method, url) => {
                if (url === "/api/auth/login") {
                    return { status: 401, body: { message: "Invalid email or password" } };
                }
                return { status: 200, body: {} };
            };

            const { window, document } = boot(handler);

            document.getElementById("login-email").value = "arjun@example.com";
            document.getElementById("login-password").value = "wrong-password";

            document
                .getElementById("login-form")
                .dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
            await flush(window);

            const error = document.getElementById("login-error");
            expect(error.classList.contains("hidden")).toBe(false);
            expect(error.textContent).toBe("Invalid email or password");
            expect(error.textContent).not.toMatch(/session/i);
        });

        it("shows the disabled message when the account is disabled", async () => {
            const handler = (method, url) => {
                if (url === "/api/auth/login") {
                    return {
                        status: 403,
                        body: {
                            message: "This account is disabled. Contact an administrator.",
                            code: "ACCOUNT_DISABLED"
                        }
                    };
                }
                return { status: 200, body: {} };
            };

            const { window, document } = boot(handler);

            document.getElementById("login-email").value = "arjun@example.com";
            document.getElementById("login-password").value = "StrongTestPassword!2026";

            document
                .getElementById("login-form")
                .dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
            await flush(window);

            expect(document.getElementById("login-error").textContent).toBe(
                "This account is disabled. Contact an administrator."
            );
        });

        it("returns to the sign-in screen when a session has expired", async () => {
            const handler = (method, url) => {
                if (url.startsWith("/api/auth/me")) {
                    return { status: 200, body: { user: USER.viewer } };
                }
                if (url.startsWith("/api/documents?")) {
                    return { status: 401, body: { message: "Authentication required" } };
                }
                return { status: 200, body: {} };
            };

            const { window, document } = boot(handler);
            await flush(window);

            document.getElementById("nav-shared").click();
            await flush(window);

            expect(visible(document.getElementById("auth-screen"))).toBe(true);
            expect(visible(document.getElementById("app-shell"))).toBe(false);
            expect(document.getElementById("login-error").textContent).toMatch(/session/i);
        });
    });

    // ── The confirmation wording ──────────────────────────────────────────────

    describe("5. The confirmation dialogs state what will happen", () => {
        it("warns that deleting is permanent and that audit records are kept", async () => {
            const handler = (method, url) => {
                if (url.startsWith("/api/auth/me")) {
                    return { status: 200, body: { user: USER.document_owner } };
                }
                if (url.startsWith("/api/documents?")) {
                    return {
                        status: 200,
                        body: {
                            documents: [
                                {
                                    id: "55555555-5555-4555-8555-555555555555",
                                    name: "report.pdf",
                                    category: "General",
                                    file_size: 1024,
                                    created_at: "2026-01-01T00:00:00.000Z",
                                    access_level: "owner"
                                }
                            ],
                            page: 1,
                            limit: 20,
                            count: 1
                        }
                    };
                }
                return { status: 200, body: {} };
            };

            const { window, document } = boot(handler);
            await flush(window);

            document.getElementById("nav-documents").click();
            await flush(window);

            const deleteButton = Array.from(
                document.getElementById("documents-tbody").querySelectorAll("button")
            ).find((button) => button.textContent === "Delete");
            expect(deleteButton).toBeTruthy();

            deleteButton.click();
            await flush(window);

            const message = document.getElementById("confirm-message").textContent;
            expect(message).toContain(
                "report.pdf will be permanently deleted and access for everyone it was shared with ends."
            );
            expect(message).toContain("This cannot be undone.");
            expect(message).toContain("Audit records about this document are kept.");
            expect(visible(document.getElementById("confirm-modal"))).toBe(true);
        });

        it("states what disabling an account does", async () => {
            const handler = (method, url) => {
                if (url.startsWith("/api/auth/me")) {
                    return { status: 200, body: { user: USER.admin } };
                }
                if (url.startsWith("/api/admin/users")) {
                    return {
                        status: 200,
                        body: {
                            users: [
                                {
                                    id: USER.viewer.id,
                                    name: "John Doe",
                                    email: "john@example.com",
                                    role: "viewer",
                                    is_disabled: false
                                }
                            ],
                            total: 1,
                            limit: 50,
                            offset: 0
                        }
                    };
                }
                return { status: 200, body: {} };
            };

            const { window, document } = boot(handler);
            await flush(window);

            document.getElementById("nav-admin-users").click();
            await flush(window);

            const disableButton = Array.from(
                document.getElementById("admin-users-tbody").querySelectorAll("button")
            ).find((button) => button.textContent === "Disable");
            expect(disableButton).toBeTruthy();

            disableButton.click();
            await flush(window);

            const message = document.getElementById("confirm-message").textContent;
            expect(message).toContain(
                "John Doe (john@example.com) is signed out now and cannot sign in until an Admin enables the account."
            );
            expect(message).toContain("The action is recorded in the audit log.");
        });
    });

    // ── The truthful integrity status ─────────────────────────────────────────

    describe("6. The integrity status tells the truth", () => {
        async function verifyWith(body) {
            const handler = (method, url) => {
                if (url.startsWith("/api/auth/me")) {
                    return { status: 200, body: { user: USER.admin } };
                }
                if (url.startsWith("/api/admin/verify-chain")) {
                    return { status: 200, body };
                }
                return { status: 200, body: {} };
            };

            const context = boot(handler);
            await flush(context.window);

            context.document.getElementById("nav-admin-audit").click();
            await flush(context.window);

            context.document.getElementById("btn-verify-chain").click();
            await flush(context.window);

            return context;
        }

        it("says VERIFIED when the server reports a valid chain", async () => {
            const { document } = await verifyWith({
                valid: true,
                totalEntries: 452,
                reason: null,
                brokenAtId: null
            });

            expect(document.getElementById("audit-integrity-title").textContent).toBe(
                "INTEGRITY: VERIFIED"
            );
            expect(document.getElementById("audit-integrity-text").textContent).toContain("452");
        });

        it("says FAILED and names the broken entry when the chain is broken", async () => {
            const { document } = await verifyWith({
                valid: false,
                totalEntries: 452,
                reason: "broken_link",
                brokenAtId: 438
            });

            expect(document.getElementById("audit-integrity-title").textContent).toBe(
                "INTEGRITY: FAILED"
            );
            expect(document.getElementById("audit-integrity-text").textContent).toContain("438");
        });

        it("says NOT VERIFIED when the server reports nothing", async () => {
            const { document } = await verifyWith({});

            expect(document.getElementById("audit-integrity-title").textContent).toBe(
                "INTEGRITY: NOT VERIFIED"
            );
            expect(document.getElementById("audit-integrity-text").textContent).toMatch(
                /did not report a verification result/
            );
        });
    });

    // ── The worth-a-look banner ───────────────────────────────────────────────

    describe("7. The worth-a-look banner only appears with real data", () => {
        it("stays hidden while the server reports no refusals", async () => {
            const handler = (method, url) => {
                if (url.startsWith("/api/auth/me")) {
                    return { status: 200, body: { user: USER.admin } };
                }
                if (url.startsWith("/api/admin/audit-logs")) {
                    return { status: 200, body: { logs: [], nextCursor: null, worthALook: null } };
                }
                return { status: 200, body: {} };
            };

            const { window, document } = boot(handler);
            await flush(window);

            document.getElementById("nav-admin-audit").click();
            await flush(window);

            expect(visible(document.getElementById("audit-worth-look"))).toBe(false);
        });

        it("names the account and the number of refusals the server reported", async () => {
            const handler = (method, url) => {
                if (url.startsWith("/api/auth/me")) {
                    return { status: 200, body: { user: USER.admin } };
                }
                if (url.startsWith("/api/admin/audit-logs")) {
                    return {
                        status: 200,
                        body: {
                            logs: [],
                            nextCursor: null,
                            worthALook: {
                                email: "arjun@example.com",
                                name: "Arjun Rao",
                                count: 2,
                                windowMinutes: 1
                            }
                        }
                    };
                }
                return { status: 200, body: {} };
            };

            const { window, document } = boot(handler);
            await flush(window);

            document.getElementById("nav-admin-audit").click();
            await flush(window);

            expect(visible(document.getElementById("audit-worth-look"))).toBe(true);
            expect(document.getElementById("audit-worth-look-text").textContent).toBe(
                "arjun@example.com was refused 2 times in 1 minute"
            );
        });
    });

    // ── The filters really reach the API ──────────────────────────────────────

    describe("8. The list filters are sent to the server", () => {
        it("sends the search term, the category and the date range of My documents", async () => {
            const handler = (method, url) => {
                if (url.startsWith("/api/auth/me")) {
                    return { status: 200, body: { user: USER.document_owner } };
                }
                if (url.startsWith("/api/documents/filters")) {
                    return { status: 200, body: FILTERS };
                }
                if (url.startsWith("/api/documents?")) {
                    return { status: 200, body: { documents: [], page: 1, limit: 20, count: 0 } };
                }
                return { status: 200, body: {} };
            };

            const { window, document } = boot(handler);
            await flush(window);

            document.getElementById("doc-search").value = "report";
            document.getElementById("doc-category-filter").value = "Finance";
            document.getElementById("doc-from-filter").value = "2026-01-01";
            document.getElementById("doc-to-filter").value = "2026-02-01";

            document.getElementById("nav-documents").click();
            await flush(window);

            const call = window.API.calls
                .filter((entry) => entry.url.startsWith("/api/documents?"))
                .pop();

            expect(call).toBeTruthy();
            expect(call.url).toContain("owned=true");
            expect(call.url).toContain("q=report");
            expect(call.url).toContain("category=Finance");
            expect(call.url).toContain("from=2026-01-01");
            expect(call.url).toContain("to=2026-02-01");
        });

        it("sends the owner filter of Shared with me", async () => {
            const handler = (method, url) => {
                if (url.startsWith("/api/auth/me")) {
                    return { status: 200, body: { user: USER.viewer } };
                }
                if (url.startsWith("/api/documents/filters")) {
                    return { status: 200, body: FILTERS };
                }
                if (url.startsWith("/api/documents?")) {
                    return { status: 200, body: { documents: [], page: 1, limit: 20, count: 0 } };
                }
                return { status: 200, body: {} };
            };

            const { window, document } = boot(handler);
            await flush(window);

            document.getElementById("shared-search").value = "salary";
            document.getElementById("shared-owner-filter").value = "alice@example.com";

            document.getElementById("nav-shared").click();
            await flush(window);

            const call = window.API.calls
                .filter((entry) => entry.url.startsWith("/api/documents?"))
                .pop();

            expect(call).toBeTruthy();
            expect(call.url).toContain("shared=true");
            expect(call.url).toContain("q=salary");
            expect(call.url).toContain("owner=alice%40example.com");
        });
    });

    // ── The admin user actions ────────────────────────────────────────────────

    describe("9. The admin console calls the real endpoints", () => {
        it("creates a user with the chosen role and reports it", async () => {
            const handler = (method, url) => {
                if (url.startsWith("/api/auth/me")) {
                    return { status: 200, body: { user: USER.admin } };
                }
                if (method === "POST" && url === "/api/admin/users") {
                    return {
                        status: 201,
                        body: {
                            message: "User created",
                            user: {
                                id: "66666666-6666-4666-8666-666666666666",
                                name: "Priya Nair",
                                email: "priya@example.com",
                                role: "viewer"
                            },
                            temporaryPassword: "abcdEFGH1234ijklMNOP"
                        }
                    };
                }
                return { status: 200, body: {} };
            };

            const { window, document } = boot(handler);
            await flush(window);

            document.getElementById("nav-admin-users").click();
            await flush(window);

            document.getElementById("btn-add-user").click();
            document.getElementById("add-user-name").value = "Priya Nair";
            document.getElementById("add-user-email").value = "priya@example.com";
            document.getElementById("add-user-role").value = "viewer";

            document
                .getElementById("add-user-form")
                .dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
            await flush(window);

            const create = window.API.calls.find(
                (entry) => entry.method === "POST" && entry.url === "/api/admin/users"
            );
            expect(create).toBeTruthy();
            expect(create.body).toEqual({
                name: "Priya Nair",
                email: "priya@example.com",
                role: "viewer"
            });

            const success = document.getElementById("add-user-success");
            expect(success.textContent).toContain("Priya Nair was created as Viewer.");
            expect(success.textContent).toContain("abcdEFGH1234ijklMNOP");
        });

        it("disables an account with the documented body", async () => {
            const handler = (method, url) => {
                if (url.startsWith("/api/auth/me")) {
                    return { status: 200, body: { user: USER.admin } };
                }
                if (url.startsWith("/api/admin/users?")) {
                    return {
                        status: 200,
                        body: {
                            users: [
                                {
                                    id: USER.viewer.id,
                                    name: "John Doe",
                                    email: "john@example.com",
                                    role: "viewer",
                                    is_disabled: false
                                }
                            ],
                            total: 1
                        }
                    };
                }
                if (method === "PATCH" && url.includes("/disable")) {
                    return { status: 200, body: { message: "Account disabled" } };
                }
                return { status: 200, body: {} };
            };

            const { window, document } = boot(handler);
            await flush(window);

            document.getElementById("nav-admin-users").click();
            await flush(window);

            const disableButton = Array.from(
                document.getElementById("admin-users-tbody").querySelectorAll("button")
            ).find((button) => button.textContent === "Disable");

            disableButton.click();
            await flush(window);

            document.getElementById("confirm-ok").click();
            await flush(window);

            const patch = window.API.calls.find(
                (entry) => entry.method === "PATCH" && entry.url.includes("/disable")
            );
            expect(patch).toBeTruthy();
            expect(patch.url).toBe(`/api/admin/users/${USER.viewer.id}/disable`);
            expect(patch.body).toEqual({ disabled: true });
        });

        it("changes a role through the admin API", async () => {
            const handler = (method, url) => {
                if (url.startsWith("/api/auth/me")) {
                    return { status: 200, body: { user: USER.admin } };
                }
                if (url.startsWith("/api/admin/users?")) {
                    return {
                        status: 200,
                        body: {
                            users: [
                                {
                                    id: USER.viewer.id,
                                    name: "John Doe",
                                    email: "john@example.com",
                                    role: "viewer",
                                    is_disabled: false
                                }
                            ],
                            total: 1
                        }
                    };
                }
                return { status: 200, body: {} };
            };

            const { window, document } = boot(handler);
            await flush(window);

            document.getElementById("nav-admin-users").click();
            await flush(window);

            const changeRoleButton = Array.from(
                document.getElementById("admin-users-tbody").querySelectorAll("button")
            ).find((button) => button.textContent === "Change role");

            changeRoleButton.click();
            await flush(window);

            document.getElementById("role-select").value = "document_owner";
            document
                .getElementById("role-form")
                .dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
            await flush(window);

            const patch = window.API.calls.find(
                (entry) => entry.method === "PATCH" && entry.url.includes("/role")
            );
            expect(patch).toBeTruthy();
            expect(patch.body).toEqual({ role: "document_owner" });
        });
    });

    // ── Modal focus handling ──────────────────────────────────────────────────

    describe("10. Dialogs manage the focus", () => {
        it("moves the focus into the dialog and back to the trigger", async () => {
            const { window, document } = boot(signedIn("admin"));
            await flush(window);

            document.getElementById("nav-admin-users").click();
            await flush(window);

            const trigger = document.getElementById("btn-add-user");
            trigger.focus();
            trigger.click();
            await flush(window);

            expect(visible(document.getElementById("add-user-modal"))).toBe(true);
            expect(document.activeElement).toBe(document.getElementById("add-user-name"));

            document.dispatchEvent(new window.KeyboardEvent("keydown", { key: "Escape" }));
            await flush(window);

            expect(visible(document.getElementById("add-user-modal"))).toBe(false);
            expect(document.activeElement).toBe(trigger);
        });
    });

    // ── The ten Viewer screens of the v3 design ───────────────────────────────

    describe("11. The Viewer screens of the v3 design", () => {
        const SHARED_DOCS = [
            {
                id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                name: "marketing-plan.pdf",
                category: "Work",
                owner_email: "alice@example.com",
                file_size: 2516582,
                content_type: "application/pdf",
                original_filename: "marketing-plan.pdf",
                created_at: "2026-10-01T00:00:00.000Z",
                shared_at: "2026-10-20T00:00:00.000Z",
                access_level: "read"
            },
            {
                id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                name: "team-image.png",
                category: "Work",
                owner_email: "john@example.com",
                file_size: 2516582,
                content_type: "image/png",
                original_filename: "team-image.png",
                created_at: "2026-10-02T00:00:00.000Z",
                shared_at: "2026-10-18T00:00:00.000Z",
                access_level: "edit"
            }
        ];

        /**
         * A handler that serves a signed-in account and its documents.
         *
         * @param {object[]} documents
         * @param {string} [role]
         * @param {Function} [extra] answers anything the defaults do not
         */
        function withDocuments(documents, role, extra) {
            const user = USER[role || "viewer"];

            return (method, url, body) => {
                if (url.startsWith("/api/auth/me")) {
                    return { status: 200, body: { user } };
                }
                if (url.startsWith("/api/documents/filters")) {
                    return { status: 200, body: FILTERS };
                }
                if (url.startsWith("/api/documents?")) {
                    return {
                        status: 200,
                        body: { documents, page: 1, limit: 20, count: documents.length }
                    };
                }

                const single = /^\/api\/documents\/([^/?]+)$/.exec(url);
                if (method === "GET" && single) {
                    const doc = documents.find((entry) => entry.id === single[1]);
                    return doc
                        ? { status: 200, body: { document: doc } }
                        : { status: 404, body: { message: "Document not found" } };
                }
                if (/^\/api\/documents\/[^/]+\/audit$/.test(url)) {
                    return { status: 200, body: { logs: [] } };
                }
                if (/^\/api\/documents\/[^/]+\/permissions$/.test(url)) {
                    return { status: 200, body: { permissions: [] } };
                }
                if (extra) {
                    const answered = extra(method, url, body);
                    if (answered) return answered;
                }
                return { status: 200, body: {} };
            };
        }

        /** The buttons of a table row, by their label. */
        function actionsOf(row) {
            return Array.from(row.querySelectorAll("td.td-actions button")).map(
                (button) => button.textContent
            );
        }

        it("explains an empty Shared-with-me list without counting anything", async () => {
            const { window, document } = boot(withDocuments([]));
            await flush(window);

            const tbody = document.getElementById("shared-tbody");
            expect(tbody.textContent).toContain("No documents shared with you");
            expect(tbody.textContent).toContain("An owner must grant you access first.");
        });

        it("explains an empty search without revealing hidden documents", async () => {
            const { window, document } = boot(withDocuments([]));
            await flush(window);

            document.getElementById("global-search-input").value = "payroll";
            document.getElementById("btn-search").click();
            await flush(window);

            const tbody = document.getElementById("search-results-tbody");
            expect(tbody.textContent).toContain("No documents found");
            expect(tbody.textContent).toContain(
                "Only documents you are authorized to discover are searched."
            );
        });

        it("offers Download on every shared row and Edit only on an Edit grant", async () => {
            const { window, document } = boot(withDocuments(SHARED_DOCS));
            await flush(window);

            const rows = document.querySelectorAll("#shared-tbody tr");
            expect(rows.length).toBe(2);
            expect(actionsOf(rows[0])).toEqual(["Open", "Download"]);
            expect(actionsOf(rows[1])).toEqual(["Open", "Download", "Edit"]);
        });

        it("hides the Owner-only search columns from a Viewer", async () => {
            const { window, document } = boot(withDocuments(SHARED_DOCS));
            await flush(window);

            document.getElementById("global-search-input").value = "plan";
            document.getElementById("btn-search").click();
            await flush(window);

            expect(visible(document.getElementById("search-th-name"))).toBe(true);
            expect(visible(document.getElementById("search-th-owner"))).toBe(true);
            expect(visible(document.getElementById("search-th-access"))).toBe(true);
            expect(visible(document.getElementById("search-th-category"))).toBe(false);
            expect(visible(document.getElementById("search-th-uploaded"))).toBe(false);

            const row = document.querySelector("#search-results-tbody tr");
            expect(row.querySelector('td[data-col="access"]').textContent).toBe("Read");
            expect(visible(row.querySelector('td[data-col="category"]'))).toBe(false);
            expect(visible(row.querySelector('td[data-col="uploaded"]'))).toBe(false);
            expect(actionsOf(row)).toEqual(["Open"]);
        });

        it("shows a Document Owner the Category and Uploaded columns in Search", async () => {
            const { window, document } = boot(withDocuments(SHARED_DOCS, "document_owner"));
            await flush(window);

            document.getElementById("nav-search").click();
            await flush(window);

            document.getElementById("global-search-input").value = "plan";
            document.getElementById("btn-search").click();
            await flush(window);

            expect(visible(document.getElementById("search-th-category"))).toBe(true);
            expect(visible(document.getElementById("search-th-uploaded"))).toBe(true);
            expect(visible(document.getElementById("search-th-access"))).toBe(false);

            const row = document.querySelector("#search-results-tbody tr");
            expect(visible(row.querySelector('td[data-col="category"]'))).toBe(true);
            expect(visible(row.querySelector('td[data-col="access"]'))).toBe(false);
        });

        it("labels the access list of a Read grant the way the design does", async () => {
            const { window, document } = boot(withDocuments(SHARED_DOCS));
            await flush(window);

            const openButton = document
                .querySelectorAll("#shared-tbody tr")[0]
                .querySelectorAll("td.td-actions button")[0];
            openButton.click();
            await flush(window);

            expect(document.getElementById("detail-access-description").textContent).toBe(
                "Your access: Read"
            );

            const caps = Array.from(
                document.querySelectorAll("#detail-access-caps li")
            ).map((item) => item.textContent);
            expect(caps).toEqual([
                "Open and download",
                "Edit (needs an Edit grant)",
                "Share",
                "Delete"
            ]);

            const items = document.querySelectorAll("#detail-access-caps li");
            expect(items[0].className).toBe("allowed");
            expect(items[1].className).toBe("denied");
            expect(items[2].className).toBe("denied");
            expect(items[3].className).toBe("denied");

            const meta = document.getElementById("detail-meta").textContent;
            expect(meta).toContain("Shared with you");
            expect(meta).not.toContain("Original file");
        });

        it("labels the access list of an Edit grant the way the design does", async () => {
            const { window, document } = boot(withDocuments(SHARED_DOCS));
            await flush(window);

            const editRow = document.querySelectorAll("#shared-tbody tr")[1];
            const openButton = Array.from(editRow.querySelectorAll("button")).find(
                (button) => button.textContent === "Open"
            );
            openButton.click();
            await flush(window);

            const caps = Array.from(
                document.querySelectorAll("#detail-access-caps li")
            ).map((item) => item.textContent);
            expect(caps).toEqual([
                "Open and download",
                "Edit this document",
                "Share",
                "Delete"
            ]);

            const actions = Array.from(
                document.querySelectorAll("#detail-actions button")
            ).map((button) => button.textContent);
            expect(actions).toEqual(["Download", "Edit"]);
        });

        it("shows the stored file and the Edit-grant policy on the edit screen", async () => {
            const { window, document } = boot(withDocuments(SHARED_DOCS));
            await flush(window);

            const row = document.querySelectorAll("#shared-tbody tr")[1];
            const editButton = Array.from(row.querySelectorAll("button")).find(
                (button) => button.textContent === "Edit"
            );
            editButton.click();
            await flush(window);

            expect(document.getElementById("edit-current-file").textContent).toBe(
                "team-image.png · 2.4 MB"
            );
            expect(document.getElementById("edit-file-hint").textContent).toBe(
                "PDF, JPEG or PNG, up to 5 MB. The server validates every file. Allowed because you hold an Edit grant."
            );
        });

        it("shows the owner policy when the owner edits an own document", async () => {
            const own = Object.assign({}, SHARED_DOCS[1], { access_level: "owner" });
            const { window, document } = boot(withDocuments([own], "document_owner"));
            await flush(window);

            document.getElementById("nav-documents").click();
            await flush(window);

            const editButton = Array.from(
                document.querySelector("#documents-tbody").querySelectorAll("button")
            ).find((button) => button.textContent === "Edit");
            editButton.click();
            await flush(window);

            expect(document.getElementById("edit-file-hint").textContent).toBe(
                "PDF, JPEG or PNG, up to 5 MB. The server validates every file. Changes are written to Activity."
            );
        });

        it("confirms a save only after the server confirmed it", async () => {
            const saved = Object.assign({}, SHARED_DOCS[1], { name: "team-image.png" });

            const handler = withDocuments(SHARED_DOCS, "viewer", (method, url) => {
                if (method === "PUT" && url === "/api/documents/" + SHARED_DOCS[1].id) {
                    return { status: 200, body: { message: "Document updated", document: saved } };
                }
                return null;
            });

            const { window, document } = boot(handler);
            await flush(window);

            const row = document.querySelectorAll("#shared-tbody tr")[1];
            const editButton = Array.from(row.querySelectorAll("button")).find(
                (button) => button.textContent === "Edit"
            );
            editButton.click();
            await flush(window);

            document.getElementById("edit-name").value = "team-image.png";
            document.getElementById("edit-form").dispatchEvent(
                new window.Event("submit", { bubbles: true, cancelable: true })
            );
            await flush(window, 8);

            const put = window.API.calls.find((entry) => entry.method === "PUT");
            expect(put).toBeTruthy();

            expect(visible(document.getElementById("app-banner"))).toBe(true);
            expect(document.getElementById("app-banner-text").textContent).toBe(
                "The server saved your changes to team-image.png."
            );
            expect(
                document.getElementById("app-banner").classList.contains("app-banner-success")
            ).toBe(true);
            expect(document.getElementById("view-doc-detail").classList.contains("active")).toBe(
                true
            );
        });

        it("names the file the server refused and keeps the current file", async () => {
            const handler = withDocuments(SHARED_DOCS, "viewer", (method, url) => {
                if (method === "PUT" && url === "/api/documents/" + SHARED_DOCS[1].id) {
                    return {
                        status: 415,
                        body: { message: "Only valid PDF, JPEG, and PNG files are allowed" }
                    };
                }
                return null;
            });

            const { window, document } = boot(handler);
            await flush(window);

            const row = document.querySelectorAll("#shared-tbody tr")[1];
            const editButton = Array.from(row.querySelectorAll("button")).find(
                (button) => button.textContent === "Edit"
            );
            editButton.click();
            await flush(window);

            const input = document.getElementById("edit-file");
            const file = new window.File(["not really a pdf"], "report.pdf", {
                type: "application/pdf"
            });
            Object.defineProperty(input, "files", { value: [file], configurable: true });

            document.getElementById("edit-form").dispatchEvent(
                new window.Event("submit", { bubbles: true, cancelable: true })
            );
            await flush(window, 8);

            expect(document.getElementById("edit-file-error").textContent).toBe(
                "report.pdf: only PDF, JPEG and PNG are accepted."
            );
            expect(document.getElementById("app-banner-text").textContent).toBe(
                "The server rejected the replacement. The current file was not changed."
            );

            // The stored file is still the one that was there before.
            expect(document.getElementById("edit-current-file").textContent).toBe(
                "team-image.png · 2.4 MB"
            );
        });

        it("refuses an obviously wrong file before it is uploaded", async () => {
            const { window, document } = boot(withDocuments(SHARED_DOCS));
            await flush(window);

            const row = document.querySelectorAll("#shared-tbody tr")[1];
            const editButton = Array.from(row.querySelectorAll("button")).find(
                (button) => button.textContent === "Edit"
            );
            editButton.click();
            await flush(window);

            const input = document.getElementById("edit-file");
            const file = new window.File(["x"], "report.docx", {
                type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            });
            Object.defineProperty(input, "files", { value: [file], configurable: true });

            document.getElementById("edit-form").dispatchEvent(
                new window.Event("submit", { bubbles: true, cancelable: true })
            );
            await flush(window, 8);

            expect(document.getElementById("edit-file-error").textContent).toBe(
                "report.docx: only PDF, JPEG and PNG are accepted."
            );
            expect(document.getElementById("app-banner-text").textContent).toBe(
                "The server rejected the replacement. The current file was not changed."
            );
            expect(window.API.calls.some((entry) => entry.method === "PUT")).toBe(false);
        });

        it("shows the download-failed banner when the server returns no file", async () => {
            const handler = withDocuments(SHARED_DOCS, "viewer", (method, url) => {
                if (url.endsWith("/download")) {
                    return { status: 500, body: { message: "Internal error" } };
                }
                return null;
            });

            const { window, document } = boot(handler);
            await flush(window);

            const downloadButton = Array.from(
                document.querySelectorAll("#shared-tbody tr")[0].querySelectorAll("button")
            ).find((button) => button.textContent === "Download");
            downloadButton.click();
            await flush(window);

            const banner = document.getElementById("app-banner");
            expect(visible(banner)).toBe(true);
            expect(banner.classList.contains("app-banner-error")).toBe(true);
            expect(document.getElementById("app-banner-text").textContent).toBe(
                "Download failed. The server did not return the file. Try again."
            );
        });

        it("opens Document not found when a download is refused", async () => {
            const handler = withDocuments(SHARED_DOCS, "viewer", (method, url) => {
                if (url.endsWith("/download")) {
                    return { status: 404, body: { message: "Document not found" } };
                }
                return null;
            });

            const { window, document } = boot(handler);
            await flush(window);

            const downloadButton = Array.from(
                document.querySelectorAll("#shared-tbody tr")[0].querySelectorAll("button")
            ).find((button) => button.textContent === "Download");
            downloadButton.click();
            await flush(window);

            expect(document.getElementById("view-doc-not-found").classList.contains("active")).toBe(
                true
            );
            expect(visible(document.getElementById("app-banner"))).toBe(false);
            expect(document.getElementById("not-found-title").textContent).toBe(
                "Document not found"
            );
        });

        it("opens Document not found when a document is gone, with no form left", async () => {
            // The grant is revoked between opening the edit form and saving:
            // the server answers 404 and no editable form may survive.
            const handler = withDocuments(SHARED_DOCS, "viewer", (method, url) => {
                if (method === "PUT" && url === "/api/documents/" + SHARED_DOCS[1].id) {
                    return { status: 404, body: { message: "Document not found" } };
                }
                return null;
            });

            const { window, document } = boot(handler);
            await flush(window);

            const row = document.querySelectorAll("#shared-tbody tr")[1];
            const editButton = Array.from(row.querySelectorAll("button")).find(
                (button) => button.textContent === "Edit"
            );
            editButton.click();
            await flush(window);

            expect(document.getElementById("view-doc-edit").classList.contains("active")).toBe(true);
            expect(document.getElementById("edit-doc-id").value).toBe(SHARED_DOCS[1].id);

            document.getElementById("edit-form").dispatchEvent(
                new window.Event("submit", { bubbles: true, cancelable: true })
            );
            await flush(window, 8);

            const notFound = document.getElementById("view-doc-not-found");
            expect(notFound.classList.contains("active")).toBe(true);

            // Nothing is left that could be saved again.
            expect(document.getElementById("edit-doc-id").value).toBe("");
            expect(document.getElementById("edit-name").value).toBe("");
            expect(document.getElementById("edit-current-file").textContent).toBe("—");
            expect(notFound.querySelectorAll("form").length).toBe(0);

            // And the screen offers both ways back.
            document.getElementById("btn-notfound-search").click();
            await flush(window);
            expect(document.getElementById("view-search").classList.contains("active")).toBe(true);
        });

        it("offers the two ways back from the not-found screen", async () => {
            const { window, document } = boot(signedIn("viewer"));
            await flush(window);
            expect(document.getElementById("btn-notfound-shared").textContent).toBe(
                "Back to Shared with me"
            );
            expect(document.getElementById("btn-notfound-search").textContent).toBe("Go to Search");
            expect(document.getElementById("not-found-title").textContent).toBe("Document not found");
            expect(document.getElementById("view-doc-not-found").textContent).toContain(
                "It may not exist, or you may not have access. The message is the same either way."
            );
            expect(document.getElementById("view-doc-not-found").textContent).toContain(
                "This attempt was recorded."
            );
        });

        it("shows the ended-session banner when the session is gone", async () => {
            const handler = (method, url) => {
                if (url.startsWith("/api/auth/me")) {
                    return { status: 200, body: { user: USER.viewer } };
                }
                if (url.startsWith("/api/documents?")) {
                    return { status: 401, body: { message: "Authentication required" } };
                }
                return { status: 200, body: {} };
            };

            const { window, document } = boot(handler);
            await flush(window);

            document.getElementById("nav-shared").click();
            await flush(window);

            const banner = document.getElementById("auth-banner");
            expect(visible(banner)).toBe(true);
            expect(banner.classList.contains("auth-banner-warning")).toBe(true);
            expect(document.getElementById("auth-banner-text").textContent).toBe(
                "Your session has ended. Sign in again to continue."
            );
        });

        it("shows the disabled-account banner in error colours", async () => {
            const handler = (method, url) => {
                if (url === "/api/auth/login") {
                    return {
                        status: 403,
                        body: {
                            message: "This account is disabled. Contact an administrator.",
                            code: "ACCOUNT_DISABLED"
                        }
                    };
                }
                return { status: 200, body: {} };
            };

            const { window, document } = boot(handler);

            document.getElementById("login-email").value = "arjun@example.com";
            document.getElementById("login-password").value = "StrongTestPassword!2026";
            document.getElementById("login-form").dispatchEvent(
                new window.Event("submit", { bubbles: true, cancelable: true })
            );
            await flush(window);

            const banner = document.getElementById("auth-banner");
            expect(visible(banner)).toBe(true);
            expect(banner.classList.contains("auth-banner-error")).toBe(true);
            expect(document.getElementById("auth-banner-text").textContent).toBe(
                "This account is disabled. Contact an administrator."
            );
        });
    });
});
