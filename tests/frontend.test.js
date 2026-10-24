/**
 * Frontend contract tests.
 *
 * These tests read the shipped static files (public/index.html,
 * public/js/app.js, public/css/styles.css) and check them against the
 * approved TrustVault v3 PDF specifications:
 *
 *   Phase 1 — split-panel sign-in / register, no public role choice.
 *   Phase 2 — the exact role → navigation matrix.
 *   Phase 3 — every number comes from the API, no fabricated content.
 *   Phase 5 — no unsafe HTML, no secrets in browser storage.
 *
 * The DOM behaviour of the controller is covered separately in
 * tests/frontend.dom.test.js.
 */

const fs = require("node:fs");
const path = require("node:path");
const request = require("supertest");
const app = require("../src/app");

describe("TrustVault Frontend: static contract against the approved v3 PDFs", () => {
    const indexPath = path.join(__dirname, "../public/index.html");
    const appJsPath = path.join(__dirname, "../public/js/app.js");
    const apiJsPath = path.join(__dirname, "../public/js/api.js");
    const stylesPath = path.join(__dirname, "../public/css/styles.css");

    let indexHtml = "";
    let appJs = "";
    let apiJs = "";
    let stylesCss = "";
    let navMatrix = {};

    beforeAll(() => {
        indexHtml = fs.readFileSync(indexPath, "utf8");
        appJs = fs.readFileSync(appJsPath, "utf8");
        apiJs = fs.readFileSync(apiJsPath, "utf8");
        stylesCss = fs.readFileSync(stylesPath, "utf8");
        navMatrix = readNavMatrix(indexHtml);
    });

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Returns the sidebar navigation matrix: { view: [roles] }. */
    function readNavMatrix(html) {
        const matrix = {};
        const pattern = /<a[^>]*class="nav-item"[^>]*>/g;
        let match = pattern.exec(html);

        while (match !== null) {
            const tag = match[0];
            const view = /data-view="([^"]+)"/.exec(tag);
            const roles = /data-roles="([^"]+)"/.exec(tag);

            if (view) {
                matrix[view[1]] = roles
                    ? roles[1].split(",").map((role) => role.trim()).filter(Boolean)
                    : [];
            }

            match = pattern.exec(html);
        }

        return matrix;
    }

    /**
     * Removes the comments from a source file.
     *
     * The controller documents its own rules in a header comment; the safety
     * checks below look at executable code only.
     */
    function stripComments(source) {
        return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^[ \t]*\/\/.*$/gm, "");
    }

    /** Returns the body of a media query block. */
    function mediaBlock(query) {
        const index = stylesCss.indexOf(query);
        if (index === -1) return "";
        const start = stylesCss.indexOf("{", index);
        let depth = 0;

        for (let position = start; position < stylesCss.length; position += 1) {
            if (stylesCss[position] === "{") depth += 1;
            if (stylesCss[position] === "}") {
                depth -= 1;
                if (depth === 0) return stylesCss.slice(start, position);
            }
        }

        return stylesCss.slice(start);
    }

    // ── 1. Static file delivery ───────────────────────────────────────────────

    describe("1. Static file delivery", () => {
        it("serves index.html at root", async () => {
            const res = await request(app).get("/");
            expect(res.status).toBe(200);
            expect(res.headers["content-type"]).toMatch(/html/);
            expect(res.text).toContain("TrustVault");
        });

        it("serves styles.css", async () => {
            const res = await request(app).get("/css/styles.css");
            expect(res.status).toBe(200);
            expect(res.headers["content-type"]).toMatch(/css/);
        });

        it("serves app.js and api.js", async () => {
            const resApp = await request(app).get("/js/app.js");
            expect(resApp.status).toBe(200);
            expect(resApp.headers["content-type"]).toMatch(/javascript/);

            const resApi = await request(app).get("/js/api.js");
            expect(resApi.status).toBe(200);
            expect(resApi.headers["content-type"]).toMatch(/javascript/);
        });
    });

    // ── 2. Phase 1 — split-panel auth, no public role choice ─────────────────

    describe("2. Phase 1: split-panel sign in / register", () => {
        it("renders the two-column split panel", () => {
            expect(indexHtml).toContain("auth-layout");
            expect(indexHtml).toContain("auth-panel-brand");
            expect(indexHtml).toContain("auth-panel-form");
        });

        it("puts the sign-in and create-account forms in the same split layout", () => {
            const layoutStart = indexHtml.indexOf('class="auth-layout"');
            const formPanel = indexHtml.indexOf('class="auth-panel-form"');
            const loginForm = indexHtml.indexOf('id="login-form"');
            const registerForm = indexHtml.indexOf('id="register-form"');
            const appShell = indexHtml.indexOf('id="app-shell"');

            expect(layoutStart).toBeGreaterThan(-1);
            expect(formPanel).toBeGreaterThan(layoutStart);
            expect(loginForm).toBeGreaterThan(formPanel);
            expect(registerForm).toBeGreaterThan(loginForm);
            expect(registerForm).toBeLessThan(appShell);
        });

        it("offers no role choice anywhere in the public registration form", () => {
            expect(indexHtml).not.toContain('id="register-role"');

            const registerForm = /<form id="register-form"[\s\S]*?<\/form>/.exec(indexHtml);
            expect(registerForm).toBeTruthy();
            expect(registerForm[0]).not.toContain("<select");
            expect(registerForm[0]).not.toContain('value="document_owner"');
            expect(registerForm[0]).not.toContain('value="admin"');
        });

        it("tells the user that a new account starts as Viewer", () => {
            expect(indexHtml).toMatch(/New accounts start as\s*<strong>Viewer<\/strong>/);
        });

        it("never sends a role to the registration endpoint", () => {
            const call = /api\("POST", "\/api\/auth\/register",\s*\{([^}]*)\}\)/.exec(appJs);
            expect(call).toBeTruthy();
            expect(call[1]).not.toMatch(/\brole\b/);
        });

        it("keeps both forms complete with their error and success states", () => {
            expect(indexHtml).toContain('id="login-error"');
            expect(indexHtml).toContain('id="login-btn"');
            expect(indexHtml).toContain('id="register-error"');
            expect(indexHtml).toContain('id="register-success"');
            expect(indexHtml).toContain('id="register-btn"');
            expect(indexHtml).toContain('id="register-name"');
            expect(indexHtml).toContain('id="register-email"');
            expect(indexHtml).toContain('id="register-password"');
        });
    });

    // ── 3. Phase 2 — the role navigation matrix ───────────────────────────────

    describe("3. Phase 2: role navigation matrix", () => {
        it("exposes exactly the approved set of navigation entries", () => {
            expect(Object.keys(navMatrix).sort()).toEqual(
                [
                    "dashboard",
                    "documents",
                    "shared",
                    "upload",
                    "search",
                    "admin-audit",
                    "admin-users",
                    "admin-requests"
                ].sort()
            );
        });

        it("gives Admin: Dashboard, Shared with me, Search, Audit log, Users — and no Upload", () => {
            expect(navMatrix.dashboard).toEqual(["admin", "document_owner"]);
            expect(navMatrix.shared).toEqual(["admin", "document_owner", "viewer"]);
            expect(navMatrix.search).toEqual(["admin", "document_owner", "viewer"]);
            expect(navMatrix["admin-audit"]).toEqual(["admin"]);
            expect(navMatrix["admin-users"]).toEqual(["admin"]);
            expect(navMatrix["admin-requests"]).toEqual(["admin"]);
            expect(navMatrix.upload).toEqual(["document_owner"]);
            expect(navMatrix.upload).not.toContain("admin");
            expect(navMatrix.documents).not.toContain("admin");
        });

        it("gives Document Owner: Dashboard, My documents, Shared with me, Upload, Search", () => {
            expect(navMatrix.dashboard).toContain("document_owner");
            expect(navMatrix.documents).toEqual(["document_owner"]);
            expect(navMatrix.shared).toContain("document_owner");
            expect(navMatrix.upload).toEqual(["document_owner"]);
            expect(navMatrix.search).toContain("document_owner");
            expect(navMatrix["admin-audit"]).not.toContain("document_owner");
            expect(navMatrix["admin-users"]).not.toContain("document_owner");
        });

        it("gives Viewer: Shared with me and Search only", () => {
            const viewerViews = Object.keys(navMatrix).filter((view) =>
                navMatrix[view].includes("viewer")
            );
            expect(viewerViews.sort()).toEqual(["search", "shared"]);
        });

        it("has no Profile and no Admin entry in the sidebar", () => {
            expect(navMatrix.profile).toBeUndefined();
            expect(navMatrix.admin).toBeUndefined();
            expect(indexHtml).not.toContain('data-view="profile"');
            expect(indexHtml).not.toContain('data-view="admin"');
        });

        it("puts the signed-in identity and the role in the sidebar footer", () => {
            expect(indexHtml).toContain("Signed in as");
            expect(indexHtml).toContain('id="user-avatar-char"');
            expect(indexHtml).toContain('id="sidebar-user-email"');
            expect(indexHtml).toContain('id="sidebar-role"');
            expect(indexHtml).toContain('id="sidebar-role-text"');
            expect(appJs).toContain('setAttribute("data-role", role)');
        });

        it("gives the sidebar account block visible Profile and Sign out actions", () => {
            expect(indexHtml).toMatch(
                /id="btn-account"[\s\S]*?<span>Profile<\/span>/
            );
            expect(indexHtml).toMatch(
                /id="logout-btn"[\s\S]*?<span>Sign out<\/span>/
            );
            expect(appJs).toContain('el("btn-account").addEventListener("click"');
            expect(appJs).toContain('el("logout-btn").addEventListener("click", signOut)');
        });

        it("hides every navigation item until the role is known", () => {
            const navItems = indexHtml.match(/<a[^>]*class="nav-item"[^>]*>/g) || [];
            expect(navItems.length).toBeGreaterThan(0);
            navItems.forEach((tag) => {
                expect(tag).toMatch(/hidden/);
            });
        });
    });

    // ── 4. Required elements ──────────────────────────────────────────────────

    describe("4. Required elements and hooks", () => {
        const requiredIds = [
            "auth-screen",
            "login-form",
            "register-form",
            "app-shell",
            "sidebar",
            "sidebar-user-email",
            "sidebar-role",
            "live-region",
            "toast-container",
            "app-banner",
            "app-banner-text",
            "app-banner-close",
            "auth-banner",
            "auth-banner-text",
            "view-dashboard",
            "view-documents",
            "view-shared",
            "view-upload",
            "view-search",
            "view-doc-detail",
            "view-doc-edit",
            "view-doc-not-found",
            "view-profile",
            "view-admin-audit",
            "view-admin-users",
            "view-admin-requests",
            "tab-details",
            "tab-access",
            "tab-activity",
            "panel-details",
            "panel-access",
            "panel-activity",
            "add-user-modal",
            "role-modal",
            "confirm-modal",
            "audit-integrity-title",
            "audit-integrity-text",
            "audit-worth-look",
            "audit-worth-look-text",
            "doc-search",
            "doc-category-filter",
            "doc-from-filter",
            "doc-to-filter",
            "shared-search",
            "shared-owner-filter",
            "global-search-input",
            "search-category-filter",
            "search-owner-filter",
            "search-from-filter",
            "search-to-filter",
            "btn-search",
            "not-found-title",
            "btn-notfound-shared",
            "btn-notfound-search",
            "edit-current-file",
            "edit-file-button",
            "edit-file-hint",
            "audit-action-filter",
            "audit-user-filter",
            "audit-outcome-filter",
            "audit-from-filter",
            "audit-to-filter",
            "admin-users-search",
            "admin-users-role-filter",
            "admin-users-status-filter",
            "admin-users-clear-filters",
            "admin-users-result-count",
            "my-requests",
            "my-requests-tbody",
            "my-requests-retry",
            "role-request-form",
            "role-request-justification",
            "role-request-submit",
            "requests-count-pending",
            "requests-count-approved",
            "requests-count-rejected",
            "admin-requests-tbody",
            "user-avatar-char",
            "sidebar-role-text",
            "btn-account",
            "logout-btn",
            "btn-verify-chain",
            "audit-chain-status-ext"
        ];

        requiredIds.forEach((id) => {
            it(`provides #${id}`, () => {
                expect(indexHtml).toContain(`id="${id}"`);
            });
        });

        it("declares a polite live region for screen readers", () => {
            expect(indexHtml).toMatch(
                /id="live-region"[^>]*role="status"[^>]*aria-live="polite"/
            );
        });

        it("labels every interactive control that has no visible label", () => {
            // Icon-only buttons carry an accessible name.
            const iconButtons =
                indexHtml.match(/<button[^>]*class="btn-icon[^"]*"[^>]*>/g) || [];
            expect(iconButtons.length).toBeGreaterThan(0);
            iconButtons.forEach((tag) => {
                expect(tag).toMatch(/aria-label=/);
            });
        });

        it("labels the admin user search and filters visibly", () => {
            expect(indexHtml).toMatch(
                /<label for="admin-users-search">Search users<\/label>/
            );
            expect(indexHtml).toMatch(
                /<label for="admin-users-role-filter">Role<\/label>/
            );
            expect(indexHtml).toMatch(
                /<label for="admin-users-status-filter">Account status<\/label>/
            );
            expect(indexHtml).toContain('id="admin-users-clear-filters"');
            expect(indexHtml).toContain('id="admin-users-result-count"');
        });

        it("uses the canonical role and status values in the admin filters", () => {
            expect(indexHtml).toMatch(
                /id="admin-users-role-filter"[\s\S]*?<option value="admin">/
            );
            expect(indexHtml).toMatch(
                /id="admin-users-role-filter"[\s\S]*?<option value="document_owner">/
            );
            expect(indexHtml).toMatch(
                /id="admin-users-role-filter"[\s\S]*?<option value="viewer">/
            );
            expect(indexHtml).toMatch(
                /id="admin-users-status-filter"[\s\S]*?<option value="active">/
            );
            expect(indexHtml).toMatch(
                /id="admin-users-status-filter"[\s\S]*?<option value="disabled">/
            );
        });

        it("gives every filter the wording of the approved design", () => {
            // "My documents" filters by category, "Shared with me" by owner and
            // "Search" by owner and category — each with its own wording.
            expect(indexHtml).toMatch(
                /id="doc-category-filter"[^>]*>\s*<option value="">All categories<\/option>/
            );
            expect(indexHtml).toMatch(
                /id="shared-owner-filter"[^>]*data-empty-label="All owners"[^>]*>\s*<option value="">All owners<\/option>/
            );
            expect(indexHtml).toMatch(
                /id="search-owner-filter"[^>]*data-empty-label="Any owner"[^>]*>\s*<option value="">Any owner<\/option>/
            );
            expect(indexHtml).toMatch(
                /id="search-category-filter"[^>]*data-empty-label="Any category"[^>]*>\s*<option value="">Any category<\/option>/
            );
        });

        it("keeps the shared list free of a category filter, as the design says", () => {
            // The approved "Shared with me" screen filters by name and owner.
            expect(indexHtml).not.toContain('id="shared-category-filter"');
            expect(appJs).not.toContain("shared-category-filter");
        });
    });

    // ── 5. The PDF palette ────────────────────────────────────────────────────

    describe("5. The approved colour palette", () => {
        it("uses the dark navy sidebar", () => {
            expect(stylesCss).toContain("--sidebar-bg:");
            expect(stylesCss).toContain("#151b26");
        });

        it("uses the light slate workspace", () => {
            expect(stylesCss).toContain("#f4f5f6");
            expect(stylesCss).toContain("#f1f3f6");
        });

        it("uses the teal accent", () => {
            expect(stylesCss).toContain("#0b6b63");
            expect(stylesCss).toContain("#0a6a62");
        });

        it("uses the success, error and warning colours", () => {
            expect(stylesCss).toContain("#047857");
            expect(stylesCss).toContain("#b42318");
            expect(stylesCss).toContain("#8a5a00");
            expect(stylesCss).toContain("#fff1d5");
        });

        it("uses the audit banner colours from the Admin PDF", () => {
            expect(stylesCss).toContain("#fdece9");
        });

        it("loads the Inter typeface", () => {
            expect(stylesCss).toContain("'Inter'");
            expect(indexHtml).toContain("family=Inter");
        });
    });

    // ── 6. Responsive design ──────────────────────────────────────────────────

    describe("6. Responsive design", () => {
        it("includes the viewport meta tag", () => {
            expect(indexHtml).toMatch(
                /<meta\s+name="viewport"\s+content="width=device-width,\s*initial-scale=1\.0"/
            );
        });

        it("lets tables scroll sideways instead of squashing", () => {
            expect(stylesCss).toMatch(/\.table-container\s*\{[^}]*overflow-x:\s*auto;/);
            expect(stylesCss).toMatch(/\.data-table\s*\{[^}]*min-width:\s*\d+px;/);
        });

        it("defines breakpoints for desktop, tablet and mobile", () => {
            expect(stylesCss).toContain("@media (max-width: 1180px)");
            expect(stylesCss).toContain("@media (max-width: 1024px)");
            expect(stylesCss).toContain("@media (max-width: 900px)");
            expect(stylesCss).toContain("@media (max-width: 768px)");
            expect(stylesCss).toContain("@media (max-width: 600px)");
            expect(stylesCss).toContain("@media (max-width: 480px)");
        });

        it("uses the requested 60:40 desktop split for sign in and sign up", () => {
            const layout = /\.auth-layout\s*\{[^}]*grid-template-columns:\s*60%\s+40%/;
            expect(stylesCss).toMatch(layout);
        });

        it("keeps the authentication form at a readable width in the 40% panel", () => {
            expect(stylesCss).toMatch(
                /\.auth-form-container\s*\{[^}]*max-width:\s*420px/
            );
            expect(stylesCss).toMatch(
                /\.auth-panel-form\s*\{[^}]*padding:\s*clamp\(24px,\s*3vw,\s*48px\)/
            );
        });

        it("collapses the auth split panel before the form becomes too narrow", () => {
            expect(mediaBlock("@media (max-width: 1180px)")).toMatch(
                /\.auth-layout\s*\{[^}]*grid-template-columns:\s*1fr/
            );
        });

        it("keeps the sidebar account block inside its width for long emails", () => {
            expect(stylesCss).toMatch(
                /\.user-email\s*\{[^}]*overflow:\s*hidden;[^}]*text-overflow:\s*ellipsis;/
            );
            expect(stylesCss).toMatch(
                /\.sidebar-actions\s*\{[^}]*grid-template-columns:\s*1fr\s+1fr;/
            );
            expect(mediaBlock("@media (max-width: 768px)")).toMatch(
                /\.sidebar-action\s+span\s*\{\s*display:\s*none;/
            );
        });
    });

    // ── 7. Compact, truthful audit summary ──────────────────────────────────────

    describe("7. Compact and truthful audit summary", () => {
        it("keeps the warning compact with a secondary outlined Verify now action", () => {
            expect(indexHtml).toMatch(
                /id="audit-integrity-card"[^>]*role="status"/
            );
            expect(indexHtml).toContain("integrity-head");
            expect(indexHtml).toContain("integrity-action");
            expect(stylesCss).toMatch(
                /\.audit-banner-card\.integrity\s*\{[^}]*padding:\s*14px 16px;/
            );
            expect(stylesCss).toMatch(
                /\.integrity-action\s*\{[^}]*background:\s*#ffffff;/
            );
        });

        it("never hardcodes the historical incident or a successful status", () => {
            const code = stripComments(appJs);
            expect(code).not.toContain("INC-2026-438");
            expect(code).not.toMatch(/brokenAtId\s*\?\?\s*438/);
        });
    });

    // ── 7. Safety ─────────────────────────────────────────────────────────────

    describe("8. Safety of the browser code", () => {
        it("never writes user content as HTML", () => {
            const code = stripComments(appJs);

            expect(code).not.toContain("innerHTML");
            expect(code).not.toContain("outerHTML");
            expect(code).not.toContain("insertAdjacentHTML");
            expect(code).not.toContain("document.write");
        });

        it("uses textContent for every user supplied value", () => {
            expect(appJs).toContain("textContent");
            expect(appJs).toContain("createElement");
        });

        it("keeps the session in a cookie and never in browser storage", () => {
            const code = stripComments(appJs);
            const apiCode = stripComments(apiJs);

            expect(code).not.toContain("sessionStorage");
            expect(code).not.toMatch(/localStorage\.\s*setItem/);
            expect(apiCode).not.toContain("localStorage");
            expect(apiCode).not.toContain("sessionStorage");
        });

        it("never stores a password, token or CSRF value in the browser", () => {
            const code = stripComments(appJs);
            const apiCode = stripComments(apiJs);

            expect(code).not.toMatch(/localStorage[\s\S]{0,80}(password|token|csrf)/i);
            expect(apiCode).not.toMatch(/localStorage[\s\S]{0,80}(password|token|csrf)/i);
        });
    });

    // ── 8. Exact wording from the PDFs ────────────────────────────────────────

    describe("9. The wording the PDFs fix verbatim", () => {
        it("states that a delete is permanent and that audit records are kept", () => {
            expect(appJs).toContain(
                "will be permanently deleted and access for everyone it was shared with ends."
            );
            expect(appJs).toContain("This cannot be undone. Audit records about this document are kept.");
        });

        it("states what disabling an account does", () => {
            expect(appJs).toContain(
                "is signed out now and cannot sign in until an Admin enables the account."
            );
            expect(appJs).toContain("The action is recorded in the audit log.");
        });

        it("confirms that a created user got the requested role", () => {
            expect(appJs).toContain('" was created as "');
        });

        it("uses the four approved add-user error messages", () => {
            expect(appJs).toContain('"Name is required."');
            expect(appJs).toContain('"Enter a valid email address."');
            expect(appJs).toContain(
                '"The user was not created. The server returned an error. Try again."'
            );
        });

        it("labels the audit results Allowed / Refused", () => {
            expect(appJs).toContain('makeBadge("Allowed"');
            expect(appJs).toContain('makeBadge("Refused"');
        });

        it("shows the three truthful integrity states", () => {
            expect(appJs).toContain("INTEGRITY: VERIFIED");
            expect(appJs).toContain("INTEGRITY: FAILED");
            expect(appJs).toContain("INTEGRITY: NOT VERIFIED");
        });

        it("uses the empty-state wording of the Viewer design", () => {
            expect(appJs).toContain("No documents shared with you");
            expect(appJs).toContain("An owner must grant you access first.");
            expect(appJs).toContain("No documents found");
            expect(appJs).toContain(
                "Only documents you are authorized to discover are searched. Try another name, owner, category or date."
            );
        });

        it("uses the wording of the document-not-found screen", () => {
            expect(appJs).toContain("Document not found");
            expect(appJs).toContain(
                "It may not exist, or you may not have access. The message is the same either way."
            );
            expect(appJs).toContain("This attempt was recorded.");
            expect(indexHtml).toContain("It may not exist, or you may not have access.");
            expect(indexHtml).toContain("This attempt was recorded.");
        });

        it("uses the wording of the download-failed and session states", () => {
            expect(appJs).toContain(
                "Download failed. The server did not return the file. Try again."
            );
            expect(appJs).toContain("Your session has ended. Sign in again to continue.");
            expect(appJs).toContain("This account is disabled. Contact an administrator.");
        });

        it("uses the wording of the edit states", () => {
            expect(appJs).toContain(
                "The server rejected the replacement. The current file was not changed."
            );
            expect(appJs).toContain("The server saved your changes to ");
            expect(appJs).toContain(
                "PDF, JPEG or PNG, up to 5 MB. The server validates every file. Allowed because you hold an Edit grant."
            );
            expect(appJs).toContain(
                "PDF, JPEG or PNG, up to 5 MB. The server validates every file. Changes are written to Activity."
            );
        });

        it("uses the wording of the access list of the Viewer design", () => {
            expect(appJs).toContain("Edit this document");
            expect(appJs).toContain("Edit (needs an Edit grant)");
            expect(appJs).toContain('"Your access: "');
        });

        it("names the file that the server refused, in the design's wording", () => {
            expect(appJs).toContain(": only PDF, JPEG and PNG are accepted.");
            expect(appJs).toContain(": the file is larger than the 5 MB limit.");
        });
    });

    // ── 8b. The Viewer screens of the v3 PDF ───────────────────────────────────

    describe("8b. The Viewer screens of the v3 PDF", () => {
        it("gives the Viewer only Shared with me and Search", () => {
            const viewerViews = Object.keys(navMatrix).filter((view) =>
                navMatrix[view].includes("viewer")
            );
            expect(viewerViews.sort()).toEqual(["search", "shared"]);
        });

        it("says on the Shared-with-me screen what the list holds", () => {
            expect(indexHtml).toContain('id="shared-desc"');
            expect(appJs).toContain(
                "Documents people shared with you. Your access level is shown for each; Edit appears only where you hold an Edit grant."
            );
        });

        it("says on the Search screen what may be found", () => {
            expect(indexHtml).toContain('id="search-desc"');
            expect(appJs).toContain(
                "Searches only documents you can access through an active grant."
            );
        });

        it("gives the search table the columns of the role, and hides the rest", () => {
            expect(indexHtml).toContain('id="search-th-name"');
            expect(indexHtml).toContain('id="search-th-owner"');
            expect(indexHtml).toContain('id="search-th-access"');
            expect(indexHtml).toContain('id="search-th-category"');
            expect(indexHtml).toContain('id="search-th-uploaded"');
            expect(indexHtml).toContain('id="search-th-actions"');
            expect(appJs).toContain("SEARCH_COLUMNS_BY_ROLE");
            expect(appJs).toContain('viewer: ["name", "owner", "access"]');
        });

        it("shows the current file of the edit screen", () => {
            expect(indexHtml).toContain('id="edit-current-file"');
            expect(appJs).toContain("currentFileLabel");
        });

        it("keeps the not-found screen free of an editable form", () => {
            const notFound = /<section id="view-doc-not-found"[\s\S]*?<\/section>/.exec(indexHtml);
            expect(notFound).toBeTruthy();
            expect(notFound[0]).not.toContain('id="edit-form"');
            expect(notFound[0]).not.toContain("<form");
        });
    });

    // ── 9. The API the frontend talks to ──────────────────────────────────────

    describe("10. The API surface the frontend depends on", () => {
        it("reads the counters of the owner dashboard from /api/documents/summary", () => {
            expect(appJs).toContain('api("GET", "/api/documents/summary")');
        });

        it("reads the filter options from /api/documents/filters", () => {
            expect(appJs).toContain('api("GET", "/api/documents/filters")');
            expect(appJs).toContain("rememberOwners(");
        });

        it("asks the server for the owned and shared lists", () => {
            expect(appJs).toContain("owned: true");
            expect(appJs).toContain("shared: true");
        });

        it("reads the admin dashboard from /api/admin/overview", () => {
            expect(appJs).toContain('api("GET", "/api/admin/overview")');
        });

        it("reads the audit log and its filters from the admin API", () => {
            expect(appJs).toContain('api("GET", "/api/admin/audit-logs');
            expect(appJs).toContain('api("GET", "/api/admin/audit-filters")');
            expect(appJs).toContain('api("GET", "/api/admin/verify-chain")');
        });

        it("reads the document activity from the document scoped audit endpoint", () => {
            expect(appJs).toContain('/audit"');
            expect(appJs).toContain('"/api/documents/" + encodeURIComponent(documentId) + "/audit"');
        });

        it("creates, re-roles and disables accounts through the admin API", () => {
            expect(appJs).toContain('api("POST", "/api/admin/users"');
            expect(appJs).toContain(
                '"/api/admin/users/" + encodeURIComponent(userId) + "/role"'
            );
            expect(appJs).toContain(
                '"/api/admin/users/" + encodeURIComponent(user.id) + "/disable"'
            );
        });

        it("never invents a counter: every number is written from an API value", () => {
            // No literal dashboard numbers may be hard-coded.
            expect(appJs).not.toMatch(/stat-value[^]*=\s*"\d+"/);
            expect(appJs).toContain("?? 0");
        });
    });

    // ── 11. Role upgrade request UI ───────────────────────────────────────────

    describe("11. The Requests UI", () => {
        it("puts My Requests and Owner access submission on Profile", () => {
            const profile = /<section id="view-profile"[\s\S]*?<\/section>/.exec(indexHtml);
            expect(profile).toBeTruthy();
            expect(profile[0]).toContain('id="my-requests"');
            expect(profile[0]).toContain('id="role-request-submit"');
            expect(indexHtml).toContain('id="my-requests-retry"');
            expect(indexHtml).toMatch(/id="role-request-justification"[^>]*maxlength="500"/);
        });

        it("uses authenticated general request endpoints", () => {
            expect(appJs).toContain('api("GET", "/api/requests/mine")');
            expect(appJs).toContain('api("POST", "/api/requests"');
            expect(appJs).toContain('requestType: "document_owner_upgrade"');
            expect(appJs).toContain('"/api/requests/" + encodeURIComponent(request.id) + "/cancel"');
        });

        it("has a separate Admin Requests view and uses the general admin endpoints", () => {
            expect(navMatrix["admin-requests"]).toEqual(["admin"]);
            expect(indexHtml).toContain('id="nav-admin-requests-count"');
            expect(indexHtml).toContain('id="view-admin-requests"');
            expect(appJs).toContain('"/api/admin/requests?" + params.toString()');
            expect(appJs).toContain('"/api/admin/requests/" + encodeURIComponent(request.id) + "/" + action');
        });

        it("renders request-supplied content using text nodes", () => {
            expect(appJs).toContain("cell.textContent = content === null");
            expect(appJs).not.toMatch(/innerHTML\s*=/);
        });
    });
});
