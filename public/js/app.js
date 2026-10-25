/* ═══════════════════════════════════════════════════════════════════════════
   TrustVault — Frontend controller

   Rules that this file follows without exception:
     • Every number and every row on screen comes from a real API response.
       Nothing is estimated, invented or hard-coded.
     • All user-supplied content is written with textContent (never innerHTML),
       so a document called "<img onerror=…>" cannot become markup.
     • No secret is ever written to localStorage or sessionStorage.
     • A view that the signed-in role may not open is never reachable.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
    "use strict";

    // ── Constants ──────────────────────────────────────────────────────────────

    const ROLE_LABELS = {
        admin: "Admin",
        document_owner: "Document Owner",
        viewer: "Viewer"
    };

    const DEFAULT_VIEW_BY_ROLE = {
        admin: "dashboard",
        document_owner: "dashboard",
        viewer: "shared"
    };

    /** Views that are reachable but are not listed in the sidebar. */
    const EXTRA_VIEW_ACCESS = {
        profile: ["admin", "document_owner", "viewer"],
        "doc-detail": ["admin", "document_owner", "viewer"],
        "doc-edit": ["admin", "document_owner", "viewer"],
        "doc-not-found": ["admin", "document_owner", "viewer"]
    };

    const PAGE_SIZE = 20;
    const MAX_FILE_SIZE = 5 * 1024 * 1024;
    const ALLOWED_EXTENSIONS = [".pdf", ".jpg", ".jpeg", ".png"];

    // ── The wording the v3 designs fix verbatim ────────────────────────────────
    //
    // The approved PDFs fix these sentences word for word, so they are not
    // paraphrased anywhere: every screen quotes them from this one place.

    const SESSION_EXPIRED_MESSAGE = "Your session has ended. Sign in again to continue.";
    const DISABLED_MESSAGE = "This account is disabled. Contact an administrator.";
    const DOWNLOAD_FAILED_MESSAGE = "Download failed. The server did not return the file. Try again.";
    const NOT_FOUND_TITLE = "Document not found";
    const NOT_FOUND_HINT =
        "It may not exist, or you may not have access. The message is the same either way.";
    const NOT_FOUND_NOTE = "This attempt was recorded.";
    const EDIT_REJECTED_MESSAGE = "The server rejected the replacement. The current file was not changed.";
    const EMPTY_SHARED_TITLE = "No documents shared with you";
    const EMPTY_SHARED_HINT = "An owner must grant you access first.";
    const EMPTY_SEARCH_TITLE = "No documents found";
    const EMPTY_SEARCH_HINT =
        "Only documents you are authorized to discover are searched. Try another name, owner, category or date.";
    const FILE_POLICY_OWNER =
        "PDF, JPEG or PNG, up to 5 MB. The server validates every file. Changes are written to Activity.";
    const FILE_POLICY_EDIT_GRANT =
        "PDF, JPEG or PNG, up to 5 MB. The server validates every file. Allowed because you hold an Edit grant.";

    /**
     * The description of the Shared-with-me screen, per role.
     *
     * The screen itself is the same for everybody; only the sentence that
     * explains where the rows come from follows the role.
     */
    const SHARED_DESCRIPTIONS = {
        viewer:
            "Documents people shared with you. Your access level is shown for each; Edit appears only where you hold an Edit grant.",
        document_owner: "Documents others granted you. Access can end at any time.",
        admin:
            "Documents an owner explicitly shared with you. The Admin role alone gives no document access."
    };

    /**
     * The description of the Search screen, per role.
     *
     * Every sentence says what the role is allowed to find. None of them
     * hints at the existence of documents the role may not see.
     */
    const SEARCH_DESCRIPTIONS = {
        viewer: "Searches only documents you can access through an active grant.",
        document_owner:
            "Your documents plus documents you are explicitly authorized to access.",
        admin: "Searches only documents you are authorized to discover."
    };

    /**
     * The columns of the Search table, per role.
     *
     * The markup always carries the same six columns in the same order; the
     * ones a role may not see are hidden, so the table never shifts.
     */
    const SEARCH_COLUMNS_BY_ROLE = {
        viewer: ["name", "owner", "access"],
        admin: ["name", "owner", "access"],
        document_owner: ["name", "owner", "category", "uploaded"]
    };

    /**
     * Endpoints that are the way back into the product. A 401 from one of
     * them is an ordinary authentication failure (wrong password, unknown
     * account) and must never be reported as "your session expired".
     */
    const AUTH_ENTRY_POINTS = [
        "/api/auth/login",
        "/api/auth/register",
        "/api/auth/csrf-token",
        "/api/auth/me"
    ];

    function isAuthEntryPoint(url) {
        const path = String(url || "");
        return AUTH_ENTRY_POINTS.some((entry) => path.indexOf(entry) === 0);
    }

    // ── State ──────────────────────────────────────────────────────────────────

    const state = {
        user: null,
        view: null,
        navAccess: {},
        currentDocument: null,
        returnView: null,
        grantDocumentId: null,
        pages: {
            documents: 1,
            shared: 1,
            search: 1
        },
        // Audit log pagination is cursor based. `auditCursorStack` holds the
        // cursor of every page that has been visited, newest first; index 0 is
        // always the newest page (cursor null).
        auditCursorStack: [null],
        auditPageIndex: 0,
        auditCursor: null,
        auditNextCursor: null,
        usersOffset: 0,
        categories: [],
        owners: [],
        // The reason the sign-in screen is showing a banner, if any.
        sessionNotice: null,
        busy: new Set()
    };

    // ── DOM helpers ────────────────────────────────────────────────────────────

    function el(id) {
        return document.getElementById(id);
    }

    function show(node) {
        if (node) node.classList.remove("hidden");
    }

    function hide(node) {
        if (node) node.classList.add("hidden");
    }

    /**
     * Shows or hides an element.
     *
     * Both mechanisms are used on the same attribute: some elements are
     * marked with the `hidden` attribute in the markup, others carry the
     * `hidden` class. Only one of them would leave a stale class behind, so
     * both are always applied together.
     */
    function setHidden(node, hidden) {
        if (!node) return;
        if (hidden) {
            node.setAttribute("hidden", "");
            node.classList.add("hidden");
        } else {
            node.removeAttribute("hidden");
            node.classList.remove("hidden");
        }
    }

    function clear(node) {
        if (!node) return;
        while (node.firstChild) node.removeChild(node.firstChild);
    }

    /**
     * Writes a message into a container. `text` is always inserted as text,
     * never as markup.
     */
    function setMessage(node, text, isError) {
        if (!node) return;
        clear(node);
        if (!text) {
            node.classList.add("hidden");
            return;
        }
        node.textContent = text;
        node.classList.remove("hidden");
        node.classList.toggle("form-error", Boolean(isError));
        node.classList.toggle("form-success", !isError);
    }

    function setFieldError(inputId, errorId, message) {
        const errorNode = el(errorId);
        if (!errorNode) return;
        errorNode.textContent = message || "";
        errorNode.classList.toggle("hidden", !message);
        if (inputId) {
            const input = el(inputId);
            if (input) {
                input.setAttribute("aria-invalid", message ? "true" : "false");
            }
        }
    }

    function clearFieldErrors(ids) {
        ids.forEach((entry) => setFieldError(entry[0], entry[1], ""));
    }

    const REASON_MIN_LENGTH = 10;
    const REASON_MAX_LENGTH = 500;
    const REASON_CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;

    /** Mirrors the server-side reason contract so the form can fail early. */
    function validateReason(value, fieldName) {
        const normalized = typeof value === "string" ? value.trim() : "";
        if (!normalized) return fieldName + " is required";
        if (REASON_CONTROL_CHARACTERS.test(normalized)) {
            return fieldName + " must not contain control characters";
        }
        const length = Array.from(normalized).length;
        if (length < REASON_MIN_LENGTH || length > REASON_MAX_LENGTH) {
            return fieldName + " must be between " + REASON_MIN_LENGTH +
                " and " + REASON_MAX_LENGTH + " characters";
        }
        return null;
    }

    // ── Banners ────────────────────────────────────────────────────────────────

    /**
     * Shows the page level banner above the current screen.
     *
     * The banner carries the states of the v3 designs that belong to the
     * page and not to a single form: a failed download, a refused
     * replacement, a saved change and an ended session.
     *
     * @param {string} message
     * @param {"error"|"warning"|"success"|"info"} kind
     */
    function showAppBanner(message, kind) {
        const banner = el("app-banner");
        const text = el("app-banner-text");
        if (!banner || !text) return;

        text.textContent = message || "";
        banner.classList.remove(
            "app-banner-error",
            "app-banner-warning",
            "app-banner-success",
            "app-banner-info"
        );
        banner.classList.add("app-banner-" + (kind || "info"));
        setHidden(banner, false);
        announce(message);
    }

    function hideAppBanner() {
        setHidden(el("app-banner"), true);
    }

    /**
     * Shows the banner of the sign-in screen.
     *
     * @param {string} message
     * @param {"error"|"warning"} kind
     */
    function showAuthBanner(message, kind) {
        const banner = el("auth-banner");
        const text = el("auth-banner-text");
        if (!banner || !text) return;

        text.textContent = message || "";
        banner.classList.remove("auth-banner-error", "auth-banner-warning");
        banner.classList.add("auth-banner-" + (kind || "warning"));
        setHidden(banner, false);
    }

    function hideAuthBanner() {
        setHidden(el("auth-banner"), true);
    }

    // ── Formatting ─────────────────────────────────────────────────────────────

    function formatBytes(bytes) {
        const value = Number(bytes);
        if (!Number.isFinite(value) || value < 0) return "—";
        if (value < 1024) return value + " B";
        const units = ["KB", "MB", "GB"];
        let size = value / 1024;
        let unitIndex = 0;
        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex += 1;
        }
        return (size >= 10 ? size.toFixed(0) : size.toFixed(1)) + " " + units[unitIndex];
    }

    function formatDate(value) {
        if (!value) return "—";
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return "—";
        return date.toLocaleDateString(undefined, {
            year: "numeric",
            month: "short",
            day: "numeric"
        });
    }

    function formatTime(value) {
        if (!value) return "—";
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return "—";
        return date.toLocaleString(undefined, {
            year: "numeric",
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit"
        });
    }

    function formatRelative(value) {
        if (!value) return "—";
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return "—";
        const diffMs = Date.now() - date.getTime();
        const minutes = Math.round(diffMs / 60000);
        if (minutes < 1) return "just now";
        if (minutes < 60) return minutes + " min ago";
        const hours = Math.round(minutes / 60);
        if (hours < 24) return hours + " h ago";
        const days = Math.round(hours / 24);
        if (days < 30) return days + " d ago";
        return formatDate(value);
    }

    function roleLabel(role) {
        return ROLE_LABELS[role] || "Viewer";
    }

    // ── DOM builders (text only — never markup) ───────────────────────────────

    function makeCell(content, className) {
        const cell = document.createElement("td");
        if (className) cell.className = className;
        if (content instanceof Node) {
            cell.appendChild(content);
        } else {
            cell.textContent = content === null || content === undefined ? "—" : String(content);
        }
        return cell;
    }

    /**
     * A table cell that belongs to a named column.
     *
     * The search table carries the same columns for every role; the ones a
     * role may not see are hidden by name, so the table never shifts.
     */
    function makeColumnCell(column, content, className) {
        const cell = makeCell(content, className);
        cell.setAttribute("data-col", column);
        return cell;
    }

    function makeBadge(text, className) {
        const badge = document.createElement("span");
        badge.className = className;
        badge.textContent = text;
        return badge;
    }

    function accessBadge(level) {
        if (level === "owner") return makeBadge("Owner", "badge-owner");
        if (level === "edit") return makeBadge("Edit", "badge-edit");
        return makeBadge("Read", "badge-read");
    }

    function resultBadge(outcome) {
        if (outcome === "success") return makeBadge("Allowed", "result-badge result-allowed");
        if (outcome === "denied") return makeBadge("Refused", "result-badge result-refused");
        return makeBadge("Failure", "result-badge result-failure");
    }

    function actionButton(label, className, onClick) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = className || "btn-action";
        button.textContent = label;
        button.addEventListener("click", onClick);
        return button;
    }

    function emptyRow(tbody, message, colSpan) {
        clear(tbody);
        const row = document.createElement("tr");
        row.className = "empty-row";
        const cell = document.createElement("td");
        cell.colSpan = colSpan;
        const wrapper = document.createElement("div");
        wrapper.className = "empty-state";
        const text = document.createElement("p");
        text.textContent = message;
        wrapper.appendChild(text);
        cell.appendChild(wrapper);
        row.appendChild(cell);
        tbody.appendChild(row);
    }

    /**
     * Writes an empty state into a table body.
     *
     * The v3 designs give every empty list a title and a hint: the title
     * says what is missing, the hint says what to do about it. Neither of
     * them ever reveals how many documents the role may not see.
     *
     * @param {HTMLElement} tbody
     * @param {string} title
     * @param {string} hint
     * @param {number} colSpan
     */
    function emptyState(tbody, title, hint, colSpan) {
        clear(tbody);
        const row = document.createElement("tr");
        row.className = "empty-row";
        const cell = document.createElement("td");
        cell.colSpan = colSpan;
        const wrapper = document.createElement("div");
        wrapper.className = "empty-state";

        const titleNode = document.createElement("p");
        titleNode.className = "empty-title";
        titleNode.textContent = title || "";
        wrapper.appendChild(titleNode);

        if (hint) {
            const hintNode = document.createElement("p");
            hintNode.className = "empty-hint";
            hintNode.textContent = hint;
            wrapper.appendChild(hintNode);
        }

        cell.appendChild(wrapper);
        row.appendChild(cell);
        tbody.appendChild(row);
    }

    function loadingRow(tbody, message, colSpan) {
        emptyRow(tbody, message, colSpan);
    }

    // ── Announcements (toast + live region) ───────────────────────────────────

    function announce(message) {
        const region = el("live-region");
        if (region) region.textContent = message;
    }

    function toast(message, kind) {
        const container = el("toast-container");
        if (!container) return;
        const node = document.createElement("div");
        node.className = "toast toast-" + (kind || "info");
        node.textContent = message;
        container.appendChild(node);
        announce(message);
        window.setTimeout(() => {
            node.classList.add("toast-out");
            window.setTimeout(() => {
                if (node.parentNode) node.parentNode.removeChild(node);
            }, 220);
        }, 4200);
    }

    // ── Modal manager (focus management + Escape + focus trap) ────────────────

    const modalState = {
        openId: null,
        lastFocused: null
    };

    const FOCUSABLE =
        'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), ' +
        "select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex=\"-1\"])";

    /** The controls a dialog wants the keyboard to start on. */
    const FORM_FIELDS = 'input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled])';

    function openModal(id) {
        const overlay = el(id);
        if (!overlay) return;

        modalState.lastFocused = document.activeElement;
        modalState.openId = id;
        overlay.classList.remove("hidden");

        // The first field of the form is where the keyboard has to start, not
        // the small "×" button in the header.
        const marked = overlay.querySelector("[data-modal-initial-focus]");
        const field = overlay.querySelector(FORM_FIELDS);
        const focusable = overlay.querySelectorAll(FOCUSABLE);
        const target = marked || field || focusable[0];

        if (target) {
            target.focus();
        } else {
            overlay.setAttribute("tabindex", "-1");
            overlay.focus();
        }
    }

    function closeModal(id) {
        const overlay = el(id);
        if (!overlay) return;
        overlay.classList.add("hidden");
        if (modalState.openId === id) {
            modalState.openId = null;
            if (modalState.lastFocused && typeof modalState.lastFocused.focus === "function") {
                modalState.lastFocused.focus();
            }
            modalState.lastFocused = null;
        }
    }

    function trapFocus(event) {
        if (!modalState.openId) return;
        const overlay = el(modalState.openId);
        if (!overlay) return;
        const focusable = Array.prototype.slice.call(overlay.querySelectorAll(FOCUSABLE));
        if (focusable.length === 0) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {
            event.preventDefault();
            last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first.focus();
        }
    }

    /**
     * Opens the generic confirmation dialog.
     *
     * @param {{title:string,message:string,confirmLabel?:string,danger?:boolean,onConfirm:Function}} options
     */
    function confirmDialog(options) {
        const titleNode = el("confirm-title");
        const messageNode = el("confirm-message");
        const okButton = el("confirm-ok");
        const reasonGroup = el("confirm-reason-group");
        const reasonInput = el("confirm-reason");
        const reasonLabel = el("confirm-reason-label");
        const requiresReason = Boolean(options.requireReason);

        if (titleNode) titleNode.textContent = options.title || "Confirm";
        if (messageNode) messageNode.textContent = options.message || "";

        if (reasonGroup) reasonGroup.classList.toggle("hidden", !requiresReason);
        if (reasonLabel) reasonLabel.textContent = options.reasonLabel || "Reason";
        if (reasonInput) {
            reasonInput.value = "";
            reasonInput.setAttribute("aria-required", requiresReason ? "true" : "false");
        }
        setFieldError("confirm-reason", "confirm-reason-error", "");

        const previousHandler = okButton ? okButton.onclick : null;
        if (okButton) {
            okButton.textContent = options.confirmLabel || "Confirm";
            okButton.className = options.danger === false ? "btn btn-primary" : "btn btn-danger";
            okButton.onclick = async () => {
                let reason;
                if (requiresReason) {
                    reason = reasonInput ? reasonInput.value : "";
                    const reasonError = validateReason(reason, options.reasonLabel || "Reason");
                    if (reasonError) {
                        setFieldError("confirm-reason", "confirm-reason-error", reasonError);
                        if (reasonInput) reasonInput.focus();
                        return;
                    }
                    reason = reason.trim();
                }

                if (okButton) {
                    okButton.disabled = true;
                }
                try {
                    await options.onConfirm(reason);
                } finally {
                    if (okButton) {
                        okButton.disabled = false;
                    }
                    okButton.onclick = previousHandler;
                }
            };
        }

        openModal("confirm-modal");
        if (requiresReason && reasonInput) reasonInput.focus();
    }

    // ── API layer ──────────────────────────────────────────────────────────────

    class ApiError extends Error {
        constructor(status, message, data) {
            super(message);
            this.name = "ApiError";
            this.status = status;
            this.data = data || null;
        }
    }

    async function readBody(res) {
        try {
            return await res.json();
        } catch {
            return null;
        }
    }

    /**
     * Performs an API request and normalises the outcome.
     *
     * @param {string} method
     * @param {string} url
     * @param {*} body
     * @param {{form?:boolean, raw?:boolean}} options
     */
    async function api(method, url, body, options) {
        const opts = options || {};
        let res;

        const verb = method.toUpperCase();
        if (verb === "GET") {
            res = await window.API.get(url);
        } else if (verb === "POST") {
            res = opts.form ? await window.API.postForm(url, body) : await window.API.postJson(url, body);
        } else if (verb === "PUT") {
            res = opts.form ? await window.API.putForm(url, body) : await window.API.putJson(url, body);
        } else if (verb === "PATCH") {
            res = await window.API.patchJson(url, body);
        } else if (verb === "DELETE") {
            res = await window.API.del(url);
        } else {
            throw new ApiError(0, "Unsupported method: " + method);
        }

        // The body is read before the status is inspected: a 401 from the
        // sign-in form carries the real reason ("Invalid email or password")
        // and that message has to reach the form.
        const data = await readBody(res);

        if (res.status === 401) {
            if (data && data.code === "SESSION_EXPIRED") {
                handleSessionExpired();
                throw new ApiError(401, SESSION_EXPIRED_MESSAGE, data);
            }
            if (!isAuthEntryPoint(url)) {
                handleSessionExpired();
                throw new ApiError(401, SESSION_EXPIRED_MESSAGE, data);
            }
            // Fall through: the sign-in and registration forms show the
            // server's own message, and initial unauthenticated check does not trigger warning.
        }

        if (!res.ok) {
            const message =
                data && typeof data.message === "string"
                    ? data.message
                    : "The server returned an error. Try again.";

            if (res.status === 403 && data && data.code === "ACCOUNT_DISABLED") {
                handleDisabledAccount();
            }

            throw new ApiError(res.status, message, data);
        }

        return data;
    }

    /**
     * The session is gone: the app is closed and the sign-in screen explains
     * why. The page level banner carries the same sentence, so the state is
     * visible in the app as well.
     */
    function handleSessionExpired() {
        state.user = null;
        state.sessionNotice = { message: SESSION_EXPIRED_MESSAGE, kind: "warning" };
        showAppBanner(SESSION_EXPIRED_MESSAGE, "warning");
        showAuthScreen(SESSION_EXPIRED_MESSAGE, { banner: "warning" });
    }

    /**
     * The account exists but is switched off: the sign-in screen says so and
     * the banner is an error.
     */
    function handleDisabledAccount() {
        state.user = null;
        state.sessionNotice = { message: DISABLED_MESSAGE, kind: "error" };
        showAuthScreen(DISABLED_MESSAGE, { banner: "error" });
    }

    // ── Duplicate-submit guard ─────────────────────────────────────────────────

    /**
     * Runs `task` while `button` is disabled, so that a double click cannot
     * send the same request twice.
     */
    async function withBusy(button, task) {
        const key = button ? button.id || "anonymous" : "anonymous";
        if (state.busy.has(key)) return null;
        state.busy.add(key);

        if (button) {
            button.disabled = true;
        }

        try {
            return await task();
        } finally {
            state.busy.delete(key);
            if (button) {
                button.disabled = false;
            }
        }
    }

    // ── Auth screen ────────────────────────────────────────────────────────────

    /**
     * Shows the sign-in screen.
     *
     * The message of a state that belongs to the whole screen (an ended
     * session, a disabled account) is written to the banner. It is also
     * written to the form error, so that a screen reader announces it where
     * the user is looking.
     *
     * @param {string|null} message
     * @param {{banner?: "error"|"warning"}} options
     */
    function showAuthScreen(message, options) {
        const opts = options || {};

        hide(el("app-shell"));
        show(el("auth-screen"));
        // A message that is already on screen is never wiped by a later
        // "you are not signed in" event: the user must still be able to read
        // why the last attempt failed.
        hideAuthBanner();

        if (message) {
            setMessage(el("login-error"), message, true);
            if (opts.banner) showAuthBanner(message, opts.banner);
        }
        const email = el("login-email");
        if (email) email.focus();
    }

    /** Removes every message from the sign-in screen. */
    function resetAuthMessages() {
        hide(el("login-error"));
        hide(el("register-error"));
        hide(el("register-success"));
        hideAuthBanner();
    }

    function switchAuthTab(which) {
        const isLogin = which === "login";
        const loginForm = el("login-form");
        const registerForm = el("register-form");
        const loginTab = el("auth-tab-login");
        const registerTab = el("auth-tab-register");

        if (loginForm) loginForm.classList.toggle("hidden", !isLogin);
        if (registerForm) registerForm.classList.toggle("hidden", isLogin);
        if (loginTab) {
            loginTab.classList.toggle("active", isLogin);
            loginTab.setAttribute("aria-selected", isLogin ? "true" : "false");
        }
        if (registerTab) {
            registerTab.classList.toggle("active", !isLogin);
            registerTab.setAttribute("aria-selected", isLogin ? "false" : "true");
        }
        const focusTarget = isLogin ? el("login-email") : el("register-name");
        if (focusTarget) focusTarget.focus();
    }

    function initAuth() {
        el("auth-tab-login").addEventListener("click", () => switchAuthTab("login"));
        el("auth-tab-register").addEventListener("click", () => switchAuthTab("register"));
        el("show-register").addEventListener("click", () => switchAuthTab("register"));
        el("show-login").addEventListener("click", () => switchAuthTab("login"));

        el("login-form").addEventListener("submit", async (event) => {
            event.preventDefault();
            clearFieldErrors([
                ["login-email", "login-email-error"],
                ["login-password", "login-password-error"]
            ]);
            setMessage(el("login-error"), null);
            hideAuthBanner();

            const email = el("login-email").value.trim();
            const password = el("login-password").value;

            let valid = true;
            if (!email) {
                setFieldError("login-email", "login-email-error", "Email address is required.");
                valid = false;
            }
            if (!password) {
                setFieldError("login-password", "login-password-error", "Password is required.");
                valid = false;
            }
            if (!valid) return;

            const button = el("login-btn");
            await withBusy(button, async () => {
                try {
                    await api("POST", "/api/auth/login", { email, password });
                    el("login-password").value = "";
                    await enterApp();
                } catch (error) {
                    const message = error.message || "Unable to sign in";
                    setMessage(el("login-error"), message, true);
                    announce(message);
                }
            });
        });

        el("register-form").addEventListener("submit", async (event) => {
            event.preventDefault();
            clearFieldErrors([
                ["register-name", "register-name-error"],
                ["register-email", "register-email-error"],
                ["register-password", "register-password-error"]
            ]);
            setMessage(el("register-error"), null);
            setMessage(el("register-success"), null);

            const name = el("register-name").value.trim();
            const email = el("register-email").value.trim();
            const password = el("register-password").value;

            let valid = true;
            if (!name) {
                setFieldError("register-name", "register-name-error", "Name is required.");
                valid = false;
            }
            if (!email) {
                setFieldError("register-email", "register-email-error", "Email address is required.");
                valid = false;
            } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
                setFieldError("register-email", "register-email-error", "Enter a valid email address.");
                valid = false;
            }
            if (!password) {
                setFieldError("register-password", "register-password-error", "Password is required.");
                valid = false;
            } else if (password.length < 12) {
                setFieldError("register-password", "register-password-error", "Password must be at least 12 characters");
                valid = false;
            }
            if (!valid) return;

            const button = el("register-btn");
            await withBusy(button, async () => {
                try {
                    // No role is sent: the server assigns Viewer to every
                    // self-registered account.
                    await api("POST", "/api/auth/register", { name, email, password });
                    setMessage(
                        el("register-success"),
                        "Your account was created as Viewer. You can sign in now.",
                        false
                    );
                    announce("Your account was created as Viewer.");
                    el("register-form").reset();
                    window.setTimeout(() => switchAuthTab("login"), 1200);
                } catch (error) {
                    const message = error.message || "Unable to register";
                    setMessage(el("register-error"), message, true);
                    announce(message);
                }
            });
        });
    }

    // ── Role application ──────────────────────────────────────────────────────

    function readNavAccess() {
        const map = {};
        document.querySelectorAll(".nav-item[data-view]").forEach((item) => {
            const view = item.getAttribute("data-view");
            const roles = (item.getAttribute("data-roles") || "")
                .split(",")
                .map((role) => role.trim())
                .filter(Boolean);
            map[view] = roles;
        });
        return map;
    }

    function allowedRolesFor(view) {
        if (state.navAccess[view]) return state.navAccess[view];
        return EXTRA_VIEW_ACCESS[view] || [];
    }

    function canAccess(view) {
        if (!state.user) return false;
        return allowedRolesFor(view).indexOf(state.user.role) !== -1;
    }

    function applyRole() {
        const role = state.user.role;
        const label = roleLabel(role);

        document.querySelectorAll(".nav-item[data-view]").forEach((item) => {
            const view = item.getAttribute("data-view");
            setHidden(item, !canAccess(view));
        });

        setHidden(el("nav-section-admin"), role !== "admin");

        const emailNode = el("sidebar-user-email");
        if (emailNode) {
            emailNode.textContent = state.user.email;
            // The address may be visually truncated in the sidebar; the
            // native tooltip keeps the complete value available.
            emailNode.title = state.user.email;
        }

        const roleText = el("sidebar-role-text");
        if (roleText) roleText.textContent = label;
        const roleNode = el("sidebar-role");
        if (roleNode) {
            roleNode.setAttribute("data-role", role);
            roleNode.title = label + " role";
        }

        const avatar = el("user-avatar-char");
        if (avatar) {
            const identity = (state.user.name || state.user.email || "?").trim();
            avatar.textContent = (identity.charAt(0) || "?").toUpperCase();
            avatar.title = state.user.name || state.user.email || "";
        }

        applyRoleCopy();
    }

    /**
     * Writes the sentences and the columns that follow the signed-in role.
     *
     * The screens are the same for everybody; what changes is what the
     * screen promises. A Viewer is told that the list holds granted
     * documents, a Document Owner that it holds their own documents too, and
     * an Admin that the role alone gives no access at all.
     */
    function applyRoleCopy() {
        const role = state.user ? state.user.role : "viewer";

        const sharedDesc = el("shared-desc");
        if (sharedDesc) {
            sharedDesc.textContent = SHARED_DESCRIPTIONS[role] || SHARED_DESCRIPTIONS.viewer;
        }

        const searchDesc = el("search-desc");
        if (searchDesc) {
            searchDesc.textContent = SEARCH_DESCRIPTIONS[role] || SEARCH_DESCRIPTIONS.viewer;
        }

        const columns = SEARCH_COLUMNS_BY_ROLE[role] || SEARCH_COLUMNS_BY_ROLE.viewer;
        document.querySelectorAll("#search-results-table thead th[data-col]").forEach((th) => {
            const column = th.getAttribute("data-col");
            setHidden(th, column !== "actions" && columns.indexOf(column) === -1);
        });
    }

    // ── View routing ───────────────────────────────────────────────────────────

    function switchView(viewName, options) {
        const opts = options || {};

        if (!canAccess(viewName)) {
            const fallback = DEFAULT_VIEW_BY_ROLE[state.user ? state.user.role : "viewer"];
            viewName = fallback;
        }

        document.querySelectorAll(".view").forEach((section) => {
            section.classList.toggle("active", section.id === "view-" + viewName);
        });

        document.querySelectorAll(".nav-item[data-view]").forEach((item) => {
            const isActive = item.getAttribute("data-view") === viewName;
            item.classList.toggle("active", isActive);
            if (isActive) {
                item.setAttribute("aria-current", "page");
            } else {
                item.removeAttribute("aria-current");
            }
        });

        state.view = viewName;

        const loader = loaders[viewName];
        if (loader) {
            loader();
        }

        const main = el("main-content");
        if (main && !opts.keepScroll) {
            main.scrollTop = 0;
        }
    }

    // ── Data loaders ───────────────────────────────────────────────────────────

    const loaders = {};

    loaders.dashboard = function loadDashboard() {
        if (!state.user) return;
        const isAdmin = state.user.role === "admin";

        hide(el("dash-owner"));
        hide(el("dash-admin"));
        setHidden(el("btn-dash-upload"), true);

        if (isAdmin) {
            el("dash-title").textContent = "Dashboard";
            el("dash-desc").textContent = "System-wide activity and permission changes.";
            show(el("dash-admin"));
            loadAdminDashboard();
        } else {
            const firstName = (state.user.name || "").split(" ")[0] || "there";
            el("dash-title").textContent = "Welcome back, " + firstName;
            el("dash-desc").textContent = "Your documents and what happened to them.";
            show(el("dash-owner"));
            setHidden(el("btn-dash-upload"), false);
            loadOwnerDashboard();
        }
    };

    async function loadOwnerDashboard() {
        const tbody = el("owner-activity-tbody");
        loadingRow(tbody, "Loading activity…", 5);

        try {
            const data = await api("GET", "/api/documents/summary");
            const stats = data.stats || {};

            el("owner-stat-owned").textContent = String(stats.ownedDocuments ?? 0);
            el("owner-stat-shared-out").textContent = String(stats.sharedWithOthers ?? 0);
            el("owner-stat-shared-in").textContent = String(stats.sharedWithMe ?? 0);
            el("owner-stat-refused").textContent = String(stats.refusedAttempts ?? 0);

            renderActivityTable(tbody, data.recentActivity || [], "No activity on your documents yet.", 5);
            rememberCategories(data.categories || []);
        } catch (error) {
            el("owner-stat-owned").textContent = "—";
            el("owner-stat-shared-out").textContent = "—";
            el("owner-stat-shared-in").textContent = "—";
            el("owner-stat-refused").textContent = "—";
            emptyRow(tbody, error.message || "Unable to load the dashboard.", 5);
        }
    }

    function renderActivityTable(tbody, rows, emptyMessage, colSpan) {
        clear(tbody);
        if (!rows || rows.length === 0) {
            emptyRow(tbody, emptyMessage, colSpan);
            return;
        }
        rows.forEach((row) => {
            const tr = document.createElement("tr");
            tr.appendChild(makeCell(formatRelative(row.created_at)));
            tr.appendChild(makeCell(row.actor_email || row.actor_name || "System"));
            tr.appendChild(makeCell(humanAction(row.action)));
            tr.appendChild(makeCell(row.document_name || "—"));
            const cell = document.createElement("td");
            cell.appendChild(resultBadge(row.outcome));
            tr.appendChild(cell);
            tbody.appendChild(tr);
        });
    }

    async function loadAdminDashboard() {
        const tbody = el("admin-latest-tbody");
        loadingRow(tbody, "Loading events…", 5);

        try {
            const data = await api("GET", "/api/admin/overview");
            const stats = data.stats || {};
            const today = data.today || {};

            el("admin-stat-users").textContent = String(stats.total_users ?? 0);
            el("admin-stat-documents").textContent = String(stats.total_documents ?? 0);
            el("admin-stat-perm-today").textContent = String(today.permission_changes_today ?? 0);
            el("admin-stat-denied-today").textContent = String(today.denied_events_today ?? 0);

            renderActivityTable(tbody, data.latestEvents || [], "No audit events recorded yet.", 5);
            renderChainStatus(el("admin-chain-status"), data.chainIntegrity);
        } catch (error) {
            el("admin-stat-users").textContent = "—";
            el("admin-stat-documents").textContent = "—";
            el("admin-stat-perm-today").textContent = "—";
            el("admin-stat-denied-today").textContent = "—";
            emptyRow(tbody, error.message || "Unable to load the dashboard.", 5);
        }
    }

    loaders.documents = function loadMyDocuments() {
        loadDocumentList({
            owned: true,
            page: state.pages.documents,
            q: valueOf("doc-search"),
            category: valueOf("doc-category-filter"),
            from: valueOf("doc-from-filter"),
            to: valueOf("doc-to-filter"),
            tbody: el("documents-tbody"),
            pagination: el("doc-pagination"),
            colSpan: 5,
            mode: "owned"
        });
    };

    loaders.shared = function loadShared() {
        applyRoleCopy();
        loadDocumentList({
            shared: true,
            page: state.pages.shared,
            q: valueOf("shared-search"),
            owner: valueOf("shared-owner-filter"),
            tbody: el("shared-tbody"),
            pagination: el("shared-pagination"),
            colSpan: 5,
            mode: "shared"
        });
    };

    loaders.search = function loadSearch() {
        applyRoleCopy();
        const term = valueOf("global-search-input");
        const category = valueOf("search-category-filter");
        const owner = valueOf("search-owner-filter");
        const from = valueOf("search-from-filter");
        const to = valueOf("search-to-filter");
        const tbody = el("search-results-tbody");

        // Every supported filter is optional. A category, owner or date range
        // on its own is a valid search; only the completely empty form needs a
        // hint instead of an API call that would list every accessible file.
        if (!term && !category && !owner && !from && !to) {
            emptyState(
                tbody,
                "Enter a search term or choose a filter.",
                "",
                6
            );
            clear(el("search-pagination"));
            return;
        }

        loadDocumentList({
            q: term,
            page: state.pages.search,
            category: category,
            owner: owner,
            from: from,
            to: to,
            tbody: tbody,
            pagination: el("search-pagination"),
            colSpan: 6,
            mode: "search"
        });
    };

    /** Reads the trimmed value of a form control, or "" when it is absent. */
    function valueOf(id) {
        const node = el(id);
        if (!node) return "";
        return String(node.value || "").trim();
    }

    /**
     * Fetches a page of documents from the real API and renders it.
     */
    async function loadDocumentList(config) {
        const tbody = config.tbody;
        loadingRow(tbody, "Loading documents…", config.colSpan);

        const params = new URLSearchParams();
        params.set("page", String(config.page || 1));
        params.set("limit", String(PAGE_SIZE));
        if (config.owned) params.set("owned", "true");
        if (config.shared) params.set("shared", "true");
        if (config.q) params.set("q", config.q);
        if (config.category) params.set("category", config.category);
        if (config.owner) params.set("owner", config.owner);
        if (config.from) params.set("from", config.from);
        if (config.to) params.set("to", config.to);

        try {
            const data = await api("GET", "/api/documents?" + params.toString());
            const documents = data.documents || [];
            renderDocumentTable(tbody, documents, config);
            renderPagination(config.pagination, config.page, documents.length, (page) => {
                if (config.mode === "owned") state.pages.documents = page;
                else if (config.mode === "shared") state.pages.shared = page;
                else state.pages.search = page;
                // The page number is copied into a fresh config, otherwise the
                // request would be sent with the page that was already shown.
                loadDocumentList(Object.assign({}, config, { page: page }));
            });
        } catch (error) {
            emptyRow(tbody, error.message || "Unable to load documents.", config.colSpan);
            clear(config.pagination);
        }
    }

    /**
     * The empty states of the v3 designs.
     *
     * They are the same for every role: a title that says what is missing
     * and a hint that never counts the documents the role may not see.
     */
    const EMPTY_STATES = {
        owned: { title: "No documents yet", hint: "Upload your first document." },
        shared: { title: EMPTY_SHARED_TITLE, hint: EMPTY_SHARED_HINT },
        search: { title: EMPTY_SEARCH_TITLE, hint: EMPTY_SEARCH_HINT }
    };

    function renderDocumentTable(tbody, documents, config) {
        clear(tbody);

        if (!documents || documents.length === 0) {
            const empty = EMPTY_STATES[config.mode];
            if (empty) {
                emptyState(tbody, empty.title, empty.hint, config.colSpan);
            } else {
                emptyRow(tbody, "No documents found.", config.colSpan);
            }
            return;
        }

        const role = state.user ? state.user.role : "viewer";
        const searchColumns = SEARCH_COLUMNS_BY_ROLE[role] || SEARCH_COLUMNS_BY_ROLE.viewer;

        documents.forEach((doc) => {
            const tr = document.createElement("tr");

            // Name cell — a real button so it is keyboard reachable.
            const nameCell = document.createElement("td");
            nameCell.setAttribute("data-col", "name");
            const openButton = document.createElement("button");
            openButton.type = "button";
            openButton.className = "doc-name-cell";
            openButton.style.background = "none";
            openButton.style.border = "none";
            openButton.style.padding = "0";
            openButton.style.font = "inherit";
            openButton.style.textAlign = "left";
            openButton.style.cursor = "pointer";
            openButton.textContent = doc.name;
            openButton.addEventListener("click", () => openDocument(doc.id));
            nameCell.appendChild(openButton);
            tr.appendChild(nameCell);

            if (config.mode === "shared") {
                // Name, Owner, Your access, Shared on — the same for every role.
                tr.appendChild(makeColumnCell("owner", doc.owner_email || doc.owner_name || "—"));
                tr.appendChild(makeColumnCell("access", accessBadge(doc.access_level)));
                tr.appendChild(
                    makeColumnCell("shared", formatDate(doc.shared_at || doc.created_at))
                );
            } else if (config.mode === "search") {
                // The columns always keep this order; the ones this role may
                // not see are hidden below.
                tr.appendChild(makeColumnCell("owner", doc.owner_email || doc.owner_name || "—"));
                tr.appendChild(makeColumnCell("category", doc.category || "—"));
                tr.appendChild(makeColumnCell("access", accessBadge(doc.access_level)));
                tr.appendChild(makeColumnCell("uploaded", formatDate(doc.created_at)));
            } else {
                tr.appendChild(makeColumnCell("category", doc.category || "—"));
                tr.appendChild(makeColumnCell("size", formatBytes(doc.file_size)));
                tr.appendChild(makeColumnCell("uploaded", formatDate(doc.created_at)));
            }

            const actionsCell = document.createElement("td");
            actionsCell.className = "td-actions";
            actionsCell.setAttribute("data-col", "actions");
            actionsCell.appendChild(actionButton("Open", "btn-action", () => openDocument(doc.id)));

            if (config.mode === "shared") {
                // A shared document is never owned by the person it is shared
                // with, so it can always be downloaded.
                if (doc.access_level !== "owner") {
                    actionsCell.appendChild(
                        actionButton("Download", "btn-action", () => downloadDocument(doc.id))
                    );
                }
                // Edit appears only where an Edit grant is held.
                if (doc.access_level === "edit") {
                    actionsCell.appendChild(
                        actionButton("Edit", "btn-action", () => openEdit(doc.id))
                    );
                }
            } else if (config.mode === "search") {
                // Search opens a document; it never downloads or edits one.
                // The document screen itself offers the actions the grant
                // allows.
            } else {
                actionsCell.appendChild(actionButton("Edit", "btn-action", () => openEdit(doc.id)));
                actionsCell.appendChild(actionButton("Share", "btn-action", () => openGrant(doc.id)));
                actionsCell.appendChild(
                    actionButton("Delete", "btn-action danger", () => confirmDelete(doc))
                );
            }

            tr.appendChild(actionsCell);

            if (config.mode === "search") {
                tr.querySelectorAll("td[data-col]").forEach((cell) => {
                    const column = cell.getAttribute("data-col");
                    if (column === "actions" || column === "name") return;
                    setHidden(cell, searchColumns.indexOf(column) === -1);
                });
            }

            tbody.appendChild(tr);
        });
    }

    function renderPagination(container, page, count, onPage) {
        if (!container) return;
        clear(container);
        if (!count) return;

        const info = document.createElement("span");
        info.textContent = "Page " + page;
        container.appendChild(info);

        if (page > 1) {
            const previous = actionButton("Previous", "btn btn-ghost btn-sm", () => onPage(page - 1));
            container.appendChild(previous);
        }
        if (count >= PAGE_SIZE) {
            const next = actionButton("Next", "btn btn-ghost btn-sm", () => onPage(page + 1));
            container.appendChild(next);
        }
    }

    // ── Categories and owners (for the filter dropdowns) ───────────────────────

    /**
     * The label of the empty option of a filter.
     *
     * Each dropdown says in its own words what "no filter" means: "All
     * owners" on the list screens, "Any owner" on the search screen.
     */
    function emptyOptionLabel(select, fallback) {
        if (!select) return fallback;
        const label = select.getAttribute("data-empty-label");
        return label || fallback;
    }

    function rememberCategories(categories) {
        if (!categories || categories.length === 0) return;
        state.categories = categories;
        ["doc-category-filter", "search-category-filter"].forEach((id) => {
            const select = el(id);
            if (!select) return;
            const current = select.value;
            clear(select);
            const all = document.createElement("option");
            all.value = "";
            all.textContent = emptyOptionLabel(select, "All categories");
            select.appendChild(all);
            categories.forEach((category) => {
                const option = document.createElement("option");
                option.value = category;
                option.textContent = category;
                select.appendChild(option);
            });
            select.value = current;
        });
    }

    function rememberOwners(owners) {
        if (!owners || owners.length === 0) return;
        state.owners = owners;
        ["shared-owner-filter", "search-owner-filter"].forEach((id) => {
            const select = el(id);
            if (!select) return;
            const current = select.value;
            clear(select);
            const all = document.createElement("option");
            all.value = "";
            all.textContent = emptyOptionLabel(select, "All owners");
            select.appendChild(all);
            owners.forEach((owner) => {
                const option = document.createElement("option");
                option.value = owner.email || owner.name || "";
                option.textContent = owner.name ? owner.name + " (" + owner.email + ")" : owner.email;
                select.appendChild(option);
            });
            select.value = current;
        });
    }

    // ── Document detail ────────────────────────────────────────────────────────

    async function openDocument(documentId) {
        state.returnView = state.view;
        switchView("doc-detail");
        const tbody = el("doc-activity-tbody");
        loadingRow(tbody, "Loading activity…", 4);

        try {
            const payload = await api("GET", "/api/documents/" + encodeURIComponent(documentId));
            const doc = payload && payload.document ? payload.document : payload;
            state.currentDocument = doc;
            renderDocumentDetail(doc);
        } catch (error) {
            if (error && error.status === 404) {
                showDocumentNotFound();
                return;
            }
            state.currentDocument = null;
            el("detail-doc-name").textContent = "Document";
            el("detail-breadcrumb").textContent = "";
            emptyRow(tbody, error.message || NOT_FOUND_TITLE, 4);
            setMessage(
                el("detail-access-description"),
                error.message || NOT_FOUND_TITLE,
                true
            );
            show(el("detail-access-card"));
            clear(el("detail-actions"));
            clear(el("detail-meta"));
        }
    }

    function renderDocumentDetail(doc) {
        const isOwner = doc.access_level === "owner";

        el("detail-doc-name").textContent = doc.name;
        el("detail-breadcrumb").textContent =
            (isOwner ? "My documents" : "Shared with me") + " / " + doc.name;

        // ── Details metadata ──
        const meta = el("detail-meta");
        clear(meta);

        // A document that was shared with the viewer carries the date it was
        // shared instead of the date it was uploaded: that is the date the
        // viewer can act on.
        const entries = isOwner
            ? [
                  ["Owner", doc.owner_email || doc.owner_name || "—"],
                  ["Category", doc.category || "—"],
                  ["Size", formatBytes(doc.file_size)],
                  ["Uploaded", formatDate(doc.created_at)],
                  ["Type", doc.content_type || "—"],
                  ["Original file", doc.original_filename || "—"],
                  ["Description", doc.description || "—"]
              ]
            : [
                  ["Owner", doc.owner_email || doc.owner_name || "—"],
                  ["Category", doc.category || "—"],
                  ["Size", formatBytes(doc.file_size)],
                  ["Shared with you", formatDate(doc.shared_at || doc.created_at)]
              ];

        entries.forEach((entry) => {
            const dt = document.createElement("dt");
            dt.textContent = entry[0];
            const dd = document.createElement("dd");
            dd.textContent = entry[1];
            meta.appendChild(dt);
            meta.appendChild(dd);
        });

        // ── Header actions ──
        const actions = el("detail-actions");
        clear(actions);
        if (isOwner || doc.access_level === "edit") {
            if (doc.access_level === "edit") {
                actions.appendChild(actionButton("Download", "btn btn-primary", () => downloadDocument(doc.id)));
                actions.appendChild(actionButton("Edit", "btn btn-ghost", () => openEdit(doc.id)));
            } else {
                actions.appendChild(actionButton("Download", "btn btn-primary", () => downloadDocument(doc.id)));
                actions.appendChild(actionButton("Edit", "btn btn-ghost", () => openEdit(doc.id)));
                actions.appendChild(actionButton("Share", "btn btn-ghost", () => openGrant(doc.id)));
                actions.appendChild(
                    actionButton("Delete", "btn btn-danger", () => confirmDelete(doc))
                );
            }
        } else {
            actions.appendChild(actionButton("Download", "btn btn-primary", () => downloadDocument(doc.id)));
        }

        // ── "Your access" panel ──
        const accessCard = el("detail-access-card");
        const caps = el("detail-access-caps");
        clear(caps);

        const level = doc.access_level;
        const mayEdit = level === "owner" || level === "edit";
        const capabilities = [
            ["Open and download", level === "owner" || level === "edit" || level === "read"],
            [
                mayEdit ? "Edit this document" : "Edit (needs an Edit grant)",
                mayEdit
            ],
            ["Share", level === "owner"],
            ["Delete", level === "owner"]
        ];
        capabilities.forEach((capability) => {
            const item = document.createElement("li");
            item.className = capability[1] ? "allowed" : "denied";
            item.textContent = capability[0];
            caps.appendChild(item);
        });

        el("detail-access-description").textContent =
            "Your access: " + (level === "owner" ? "Owner" : level === "edit" ? "Edit" : "Read");
        el("detail-access-note").textContent = isOwner
            ? "You own this document, so you control who else can open it."
            : "The owner can end this at any time. It stops working on your next request.";
        show(accessCard);

        // ── Tabs: Access and Activity are owner-only ──
        // A non-owner must not be able to reach the owner-only panels, so the
        // tab buttons and their panels are hidden together.
        setHidden(el("tab-access"), !isOwner);
        setHidden(el("panel-access"), !isOwner);
        setHidden(el("tab-activity"), !isOwner);
        setHidden(el("panel-activity"), !isOwner);
        selectTab("details");

        if (isOwner) {
            loadPermissions(doc.id);
            loadDocumentActivity(doc.id);
        }
    }

    function selectTab(name) {
        ["details", "access", "activity"].forEach((tab) => {
            const button = el("tab-" + tab);
            const panel = el("panel-" + tab);
            if (!button || !panel) return;
            const active = tab === name;
            button.classList.toggle("active", active);
            button.setAttribute("aria-selected", active ? "true" : "false");
            panel.classList.toggle("active", active);
        });
    }

    async function loadPermissions(documentId) {
        const tbody = el("permissions-tbody");
        loadingRow(tbody, "Loading access list…", 4);

        try {
            const data = await api(
                "GET",
                "/api/documents/" + encodeURIComponent(documentId) + "/permissions"
            );
            const permissions = data.permissions || [];
            clear(tbody);

            if (permissions.length === 0) {
                emptyRow(tbody, "Nobody else can open this document yet.", 4);
                return;
            }

            permissions.forEach((permission) => {
                const tr = document.createElement("tr");
                tr.appendChild(makeCell(permission.user_email || permission.user_name || "—"));

                const permissionCell = document.createElement("td");
                permissionCell.appendChild(
                    permission.permission === "edit"
                        ? makeBadge("Edit", "badge-edit")
                        : makeBadge("Read", "badge-read")
                );
                tr.appendChild(permissionCell);

                tr.appendChild(makeCell(formatDate(permission.created_at)));

                const actionsCell = document.createElement("td");
                actionsCell.className = "td-actions";
                actionsCell.appendChild(
                    actionButton("Revoke access", "btn-action danger", () =>
                        confirmRevoke(documentId, permission)
                    )
                );
                tr.appendChild(actionsCell);

                tbody.appendChild(tr);
            });
        } catch (error) {
            emptyRow(tbody, error.message || "Unable to load the access list.", 4);
        }
    }

    async function loadDocumentActivity(documentId) {
        const tbody = el("doc-activity-tbody");
        loadingRow(tbody, "Loading activity…", 4);

        try {
            const data = await api(
                "GET",
                "/api/documents/" + encodeURIComponent(documentId) + "/audit"
            );
            const logs = data.logs || [];
            clear(tbody);

            if (logs.length === 0) {
                emptyRow(tbody, "No activity has been recorded for this document yet.", 4);
                return;
            }

            logs.forEach((log) => {
                const tr = document.createElement("tr");
                tr.appendChild(makeCell(formatTime(log.created_at)));
                tr.appendChild(makeCell(log.actor_email || log.actor_name || "System"));
                tr.appendChild(makeCell(humanAction(log.action)));
                const resultCell = document.createElement("td");
                resultCell.appendChild(resultBadge(log.outcome));
                tr.appendChild(resultCell);
                tbody.appendChild(tr);
            });
        } catch (error) {
            // If the document cannot be read, the screen switches to the
            // not-found view. The API layer also does this for 404s.
            if (error && error.status === 404) {
                showDocumentNotFound();
                return;
            }
            emptyRow(tbody, error.message || "Unable to load the activity log.", 4);
        }
    }

    function humanAction(action) {
        if (!action) return "—";
        const map = {
            document_upload: "Uploaded",
            document_view: "Opened",
            document_open: "Opened",
            document_download: "Downloaded",
            document_update: "Edited",
            document_delete: "Deleted",
            document_permission_grant: "Granted access",
            document_permission_revoke: "Revoked access",
            document_list: "Listed documents",
            document_audit_view: "Viewed activity",
            auth_login: "Signed in",
            auth_logout: "Signed out",
            auth_register: "Registered",
            auth_profile_update: "Updated profile",
            auth_password_change: "Changed password",
            admin_user_create: "Created user",
            admin_user_role_change: "Changed role",
            admin_user_disabled: "Disabled account",
            admin_user_enabled: "Enabled account",
            admin_console_access: "Opened admin console"
        };
        if (map[action]) return map[action];
        return action.replace(/^document_/, "").replace(/_/g, " ");
    }

    // ── Document actions ───────────────────────────────────────────────────────

    /**
     * Downloads a document.
     *
     * The file is fetched instead of being opened in a new tab, so that a
     * failure can be reported. A document that is gone (404) opens the
     * not-found screen; any other failure shows the download-failed banner.
     */
    async function downloadDocument(documentId) {
        const url = "/api/documents/" + encodeURIComponent(documentId) + "/download";

        try {
            const res = await window.API.download(url);

            if (res.status === 404) {
                showDocumentNotFound();
                return;
            }

            if (!res.ok) {
                showAppBanner(DOWNLOAD_FAILED_MESSAGE, "error");
                return;
            }

            const blob = await res.blob();
            const disposition =
                res.headers && typeof res.headers.get === "function"
                    ? res.headers.get("content-disposition")
                    : null;
            const filename = filenameFromDisposition(disposition) || "document";

            if (typeof URL !== "undefined" && typeof URL.createObjectURL === "function") {
                const objectUrl = URL.createObjectURL(blob);
                const link = document.createElement("a");
                link.href = objectUrl;
                link.download = filename;
                link.rel = "noopener";
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                if (typeof URL.revokeObjectURL === "function") URL.revokeObjectURL(objectUrl);
            }

            announce("Download started.");
        } catch {
            showAppBanner(DOWNLOAD_FAILED_MESSAGE, "error");
        }
    }

    /**
     * Reads the file name out of a `Content-Disposition` header.
     *
     * @param {string|null} disposition
     * @returns {string|null}
     */
    function filenameFromDisposition(disposition) {
        if (!disposition) return null;

        const encoded = /filename\*=UTF-8''([^;]+)/i.exec(disposition);
        if (encoded) {
            try {
                return decodeURIComponent(encoded[1]);
            } catch {
                /* Fall through to the plain form. */
            }
        }

        const plain = /filename="?([^";]+)"?/i.exec(disposition);
        return plain ? plain[1] : null;
    }

    /**
     * The not-found screen of the v3 designs.
     *
     * It is shown after the server refuses a request for a document that may
     * have been revoked, or when opening/downloading/saving fails in the
     * same way. It says the same thing either way and offers a way back.
     */
    function showDocumentNotFound() {
        hideAppBanner();
        // No editable form may survive a refusal: the fields that could be
        // saved again are emptied before the screen changes.
        clearEditForm();
        state.currentDocument = null;
        switchView("doc-not-found");
    }
    async function openGrant(documentId) {
        state.grantDocumentId = documentId;

        const isOpen =
            state.currentDocument &&
            state.currentDocument.id === documentId &&
            state.view === "doc-detail";

        if (!isOpen) {
            await openDocument(documentId);
            if (!state.currentDocument || state.currentDocument.id !== documentId) {
                return;
            }
        }

        selectTab("access");
        openGrantDialog(documentId);
    }

    function openGrantDialog(documentId) {
        state.grantDocumentId = documentId;
        const email = el("grant-email");
        if (email) {
            email.value = "";
            email.focus();
        }
        setFieldError("grant-email", "grant-email-error", "");
        const card = el("detail-grant-card");
        if (card && typeof card.scrollIntoView === "function") {
            card.scrollIntoView({ behavior: "smooth", block: "nearest" });
        }
    }

    function confirmDelete(doc) {
        confirmDialog({
            title: "Delete " + doc.name + "?",
            message:
                doc.name +
                " will be permanently deleted and access for everyone it was shared with ends. " +
                "This cannot be undone. Audit records about this document are kept.",
            confirmLabel: "Delete document",
            onConfirm: async () => {
                try {
                    await api("DELETE", "/api/documents/" + encodeURIComponent(doc.id));
                    closeModal("confirm-modal");
                    toast(doc.name + " was deleted.", "success");
                    announce(doc.name + " was deleted.");
                    if (state.view === "doc-detail") {
                        switchView(state.returnView || "documents");
                    } else {
                        loaders[state.view] && loaders[state.view]();
                    }
                } catch (error) {
                    closeModal("confirm-modal");
                    toast(error.message || "The document was not deleted.", "error");
                }
            }
        });
    }

    function confirmRevoke(documentId, permission) {
        const who = permission.user_email || permission.user_name || "this person";
        confirmDialog({
            title: "Revoke access?",
            message:
                who + " will lose " + permission.permission + " access to this document. " +
                "It stops working on their next request. The change is recorded in the audit log.",
            confirmLabel: "Revoke access",
            onConfirm: async () => {
                try {
                    await api(
                        "DELETE",
                        "/api/documents/" +
                            encodeURIComponent(documentId) +
                            "/permissions/" +
                            encodeURIComponent(permission.user_id) +
                            "/" +
                            encodeURIComponent(permission.permission)
                    );
                    closeModal("confirm-modal");
                    toast("Access revoked for " + who + ".", "success");
                    announce("Access revoked for " + who + ".");
                    loadPermissions(documentId);
                } catch (error) {
                    closeModal("confirm-modal");
                    toast(error.message || "Access was not revoked.", "error");
                }
            }
        });
    }

    // ── Edit document ──────────────────────────────────────────────────────────

    async function openEdit(documentId) {
        state.returnView = state.view;
        switchView("doc-edit");
        setMessage(el("edit-error"), null);
        setMessage(el("edit-success"), null);
        setFieldError("edit-name", "edit-name-error", "");
        setFieldError("edit-file", "edit-file-error", "");
        el("edit-file").value = "";
        el("edit-file-info").textContent = "";

        try {
            const payload = await api("GET", "/api/documents/" + encodeURIComponent(documentId));
            const doc = payload && payload.document ? payload.document : payload;
            state.currentDocument = doc;
            el("edit-doc-id").value = doc.id;
            el("edit-name").value = doc.name || "";
            el("edit-category").value = doc.category || "";
            el("edit-desc").value = doc.description || "";

            // The file that is stored today, and the policy that applies to
            // the person who may replace it.
            const current = el("edit-current-file");
            if (current) current.textContent = currentFileLabel(doc);

            const hint = el("edit-file-hint");
            if (hint) {
                hint.textContent =
                    doc.access_level === "owner" ? FILE_POLICY_OWNER : FILE_POLICY_EDIT_GRANT;
            }
        } catch (error) {
            if (error && error.status === 404) {
                showDocumentNotFound();
                return;
            }
            setMessage(el("edit-error"), error.message || "Unable to load the document.", true);
        }
    }

    /**
     * The name and the size of the file that is stored today.
     *
     * @param {object} doc
     * @returns {string}
     */
    function currentFileLabel(doc) {
        const name = doc.original_filename || doc.name || "—";
        return name + " · " + formatBytes(doc.file_size);
    }

    /**
     * Empties the edit form.
     *
     * After the server refuses a document, no editable form may remain: the
     * screen that is left has no fields that could be saved again.
     */
    function clearEditForm() {
        const form = el("edit-form");
        if (form && typeof form.reset === "function") form.reset();

        const fileInput = el("edit-file");
        if (fileInput) fileInput.value = "";

        const info = el("edit-file-info");
        if (info) info.textContent = "";

        const current = el("edit-current-file");
        if (current) current.textContent = "—";

        const id = el("edit-doc-id");
        if (id) id.value = "";

        setFieldError("edit-file", "edit-file-error", "");
        setMessage(el("edit-error"), null);
        setMessage(el("edit-success"), null);
    }

    // ── Upload ─────────────────────────────────────────────────────────────────

    function validateFile(file) {
        if (!file) return "Choose a PDF, JPEG or PNG file up to 5 MB.";
        const name = (file.name || "").toLowerCase();
        const ok = ALLOWED_EXTENSIONS.some((extension) => name.endsWith(extension));
        if (!ok) return "Only PDF, JPEG and PNG files are accepted.";
        if (file.size > MAX_FILE_SIZE) return "The file is larger than the 5 MB limit.";
        if (file.size === 0) return "The selected file is empty.";
        return null;
    }

    /**
     * Why a replacement file would be refused, in the wording of the design.
     *
     * The v3 "Edit: replacement file rejected" screen fixes both sentences
     * verbatim: the name of the refused file, then the reason.
     *
     * @param {File} file
     * @returns {string} the message, or "" when the file is acceptable
     */
    function describeFileProblem(file) {
        if (!file) return "";
        const name = file.name || "The file";
        const lower = name.toLowerCase();
        const allowed = ALLOWED_EXTENSIONS.some((extension) => lower.endsWith(extension));
        if (!allowed) return name + ": only PDF, JPEG and PNG are accepted.";
        if (file.size > MAX_FILE_SIZE) return name + ": the file is larger than the 5 MB limit.";
        return "";
    }

    /**
     * The message for a file the server itself refused.
     *
     * @param {File} file
     * @param {number} status
     * @returns {string}
     */
    function refusedFileMessage(file, status) {
        const name = (file && file.name) || "The file";
        if (status === 413) return name + ": the file is larger than the 5 MB limit.";
        return name + ": only PDF, JPEG and PNG are accepted.";
    }

    function describeFile(file) {
        if (!file) return "";
        return file.name + " — " + formatBytes(file.size);
    }

    // ── Admin: users ───────────────────────────────────────────────────────────

    const USERS_PAGE_SIZE = 50;

    // Only the newest user-list request may render. A debounced search and a
    // quickly changed filter can otherwise finish out of order.
    let usersRequestSerial = 0;

    function currentUserFilters() {
        const searchNode = el("admin-users-search");
        const roleNode = el("admin-users-role-filter");
        const statusNode = el("admin-users-status-filter");

        return {
            search: searchNode ? searchNode.value.trim() : "",
            role: roleNode ? roleNode.value : "",
            status: statusNode ? statusNode.value : ""
        };
    }

    function hasUserFilters(filters) {
        return Boolean(filters.search || filters.role || filters.status);
    }

    function setUsersTableBusy(busy) {
        const table = el("admin-users-table");
        if (!table) return;
        if (busy) {
            table.setAttribute("aria-busy", "true");
        } else {
            table.removeAttribute("aria-busy");
        }
    }

    function setUsersResultCount(message) {
        const node = el("admin-users-result-count");
        if (node) node.textContent = message;
    }

    /**
     * Shows how many users the current query matched. The number is always
     * the API's `total` for the active filters, never a client-side estimate.
     */
    function renderUsersResultCount(total, shown, filters) {
        if (!hasUserFilters(filters)) {
            setUsersResultCount(total === 1 ? "1 user" : total + " users");
            return;
        }

        if (total === 0) {
            setUsersResultCount("No matching users");
            return;
        }

        const word = total === 1 ? "user" : "users";
        if (state.usersOffset > 0 || shown < total) {
            setUsersResultCount(
                "Showing " +
                (state.usersOffset + 1) +
                "–" +
                (state.usersOffset + shown) +
                " of " +
                total +
                " matching " +
                word
            );
            return;
        }

        setUsersResultCount(total + " matching " + word);
    }

    // ── Admin: unified Requests page ───────────────────────────────────────────
    let adminRequestsSerial = 0;
    let adminRequestFiltersTimer = null;

    function requestStatusLabel(status) {
        return ({ pending: "Pending", approved: "Approved", rejected: "Rejected", cancelled: "Cancelled" })[status] || status || "Unknown";
    }

    function renderAdminRequestRows(requests) {
        const tbody = el("admin-requests-tbody");
        clear(tbody);
        if (!requests.length) {
            emptyRow(tbody, "No requests match these filters.", 7);
            return;
        }
        requests.forEach((request) => {
            const tr = document.createElement("tr");
            const requester = request.requester || {};
            const identity = [requester.name || requester.email || "—", requester.email && requester.name ? requester.email : ""].filter(Boolean).join(" · ");
            tr.appendChild(makeCell(identity));
            tr.appendChild(makeCell(request.requestType === "document_owner_upgrade" ? "Document Owner upgrade" : request.requestType || "—"));
            tr.appendChild(makeCell(request.requestedRole ? roleLabel(request.requestedRole) : [request.targetResourceId, request.requestedPermission].filter(Boolean).join(" · ") || "—"));
            tr.appendChild(makeCell(formatTime(request.submittedAt)));
            const status = makeBadge(requestStatusLabel(request.status), "badge-status badge-" + (request.status || "pending"));
            const statusCell = document.createElement("td"); statusCell.appendChild(status); tr.appendChild(statusCell);
            const details = [request.reason ? "Reason: " + request.reason : "", request.decisionNote ? "Note: " + request.decisionNote : "", request.decidedAt ? "Decided " + formatTime(request.decidedAt) : "", request.decidedBy && (request.decidedBy.name || request.decidedBy.email) ? "by " + (request.decidedBy.name || request.decidedBy.email) : request.reviewerRole ? "Reviewer: " + roleLabel(request.reviewerRole) : ""].filter(Boolean).join(" · ");
            tr.appendChild(makeCell(details || "—", "request-decision-details"));
            const actions = document.createElement("td"); actions.className = "td-actions";
            if (request.status === "pending" && request.requesterId !== state.user.id && request.requestType === "document_owner_upgrade") {
                const approve = actionButton("Approve", "btn-action", () => showApproveEditor(actions, request));
                approve.setAttribute("aria-label", "Approve request from " + (requester.name || requester.email || "requester"));
                const reject = actionButton("Reject", "btn-action danger", () => showRejectEditor(actions, request));
                reject.setAttribute("aria-label", "Reject request from " + (requester.name || requester.email || "requester"));
                actions.append(approve, reject);
            } else if (request.status === "pending") {
                actions.textContent = request.requesterId === state.user.id ? "Self-review is not allowed" : "No enabled review action";
            } else actions.textContent = "—";
            tr.appendChild(actions);
            tbody.appendChild(tr);
        });
    }

    function showApproveEditor(container, request) {
        clear(container);
        const form = document.createElement("form"); form.className = "request-approve-form";
        const label = document.createElement("label"); label.textContent = "Approval reason (required)";
        const input = document.createElement("textarea"); input.id = "request-approval-reason-" + request.id; label.htmlFor = input.id; input.maxLength = 500; input.rows = 2;
        const error = document.createElement("p"); error.className = "field-error hidden"; error.setAttribute("aria-live", "polite");
        const confirm = document.createElement("button"); confirm.type = "submit"; confirm.className = "btn-action"; confirm.textContent = "Confirm approve";
        const cancel = actionButton("Cancel", "btn-action", () => { container.textContent = ""; });
        form.append(label, input, error, confirm, cancel); container.appendChild(form);
        form.addEventListener("submit", (event) => {
            event.preventDefault();
            const reason = input.value;
            const reasonError = validateReason(reason, "Approval reason");
            if (reasonError) {
                error.textContent = reasonError;
                error.classList.remove("hidden");
                input.focus();
                return;
            }
            error.textContent = "";
            error.classList.add("hidden");
            decideAdminRequest(request, "approve", reason.trim(), confirm);
        });
        input.focus();
    }

    function showRejectEditor(container, request) {
        clear(container);
        const form = document.createElement("form"); form.className = "request-reject-form";
        const label = document.createElement("label"); label.textContent = "Rejection note (optional)";
        const input = document.createElement("textarea"); input.id = "request-rejection-note-" + request.id; label.htmlFor = input.id; input.maxLength = 500; input.rows = 2;
        const confirm = document.createElement("button"); confirm.type = "submit"; confirm.className = "btn-action danger"; confirm.textContent = "Confirm reject";
        const cancel = actionButton("Cancel", "btn-action", () => { container.textContent = ""; });
        form.append(label, input, confirm, cancel); container.appendChild(form);
        form.addEventListener("submit", (event) => { event.preventDefault(); decideAdminRequest(request, "reject", input.value.trim(), confirm); });
        input.focus();
    }

    async function decideAdminRequest(request, action, decisionNote, button) {
        await withBusy(button, async () => {
            try {
                const result = await api("POST", "/api/admin/requests/" + encodeURIComponent(request.id) + "/" + action, { decisionNote });
                const expected = action === "approve" ? "approved" : "rejected";
                if (!result || !result.request || result.request.status !== expected) throw new Error("The server did not confirm the decision. Refresh to check the request status.");
                toast("Request " + expected + ".", "success");
                await loaders["admin-requests"]();
            } catch (error) {
                setMessage(el("admin-requests-error"), error.message || "The request was not changed.", true);
            }
        });
    }

    async function loadAdminRequestCounts() {
        const statuses = ["pending", "approved", "rejected"];
        statuses.forEach((status) => { el("requests-count-" + status).textContent = "Loading…"; });
        try {
            const values = await Promise.all(statuses.map((status) => api("GET", "/api/admin/requests?status=" + status + "&limit=1")));
            statuses.forEach((status, index) => {
                if (!Number.isFinite(Number(values[index].total))) throw new Error("Invalid request count response");
                el("requests-count-" + status).textContent = String(Number(values[index].total));
            });
            const pending = Number(values[0].total);
            const badge = el("nav-admin-requests-count");
            badge.textContent = pending > 99 ? "99+" : String(pending);
            badge.setAttribute("aria-label", pending + " pending requests");
            setHidden(badge, pending === 0);
        } catch (error) {
            ["pending", "approved", "rejected"].forEach((status) => { el("requests-count-" + status).textContent = "Unavailable"; });
            const badge = el("nav-admin-requests-count"); badge.textContent = "!"; badge.setAttribute("aria-label", "Pending request count unavailable"); setHidden(badge, false);
            throw error;
        }
    }

    loaders["admin-requests"] = async function loadAdminRequests() {
        if (!state.user || state.user.role !== "admin") return;
        const serial = ++adminRequestsSerial;
        setMessage(el("admin-requests-error"), null);
        loadingRow(el("admin-requests-tbody"), "Loading requests…", 7);
        el("requests-result-count").textContent = "Loading requests…";
        try {
            const params = new URLSearchParams({ status: el("requests-status-filter").value, limit: "100" });
            const type = el("requests-type-filter").value; const search = el("requests-search").value.trim();
            if (type) params.set("type", type); if (search) params.set("search", search);
            const [list] = await Promise.all([api("GET", "/api/admin/requests?" + params.toString()), loadAdminRequestCounts()]);
            if (serial !== adminRequestsSerial) return;
            if (!Array.isArray(list.requests) || !Number.isFinite(Number(list.total))) throw new Error("The server returned an invalid request list.");
            renderAdminRequestRows(list.requests);
            el("requests-result-count").textContent = list.total + (Number(list.total) === 1 ? " request" : " requests");
        } catch (error) {
            if (serial !== adminRequestsSerial) return;
            emptyRow(el("admin-requests-tbody"), "Requests could not be loaded.", 7);
            el("requests-result-count").textContent = "Request list unavailable";
            setMessage(el("admin-requests-error"), error.message || "Unable to load requests. Use Refresh to retry.", true);
        }
    };

    loaders["admin-users"] = function loadAdminUsers() {
        const tbody = el("admin-users-tbody");
        const filters = currentUserFilters();
        const filtered = hasUserFilters(filters);
        const requestId = ++usersRequestSerial;

        setUsersTableBusy(true);
        loadingRow(tbody, "Loading users…", 5);
        setUsersResultCount("Loading users…");

        const params = new URLSearchParams();
        params.set("limit", String(USERS_PAGE_SIZE));
        params.set("offset", String(state.usersOffset));
        if (filters.search) params.set("search", filters.search);
        if (filters.role) params.set("role", filters.role);
        if (filters.status) params.set("status", filters.status);

        api("GET", "/api/admin/users?" + params.toString())
            .then((data) => {
                if (requestId !== usersRequestSerial) return;

                const users = data.users || [];
                const total = Number(data.total) || 0;

                // A filter change or an action can make the current page too
                // high. Move to the last page that still has results.
                if (users.length === 0 && total > 0 && state.usersOffset > 0) {
                    state.usersOffset =
                        Math.floor((total - 1) / USERS_PAGE_SIZE) * USERS_PAGE_SIZE;
                    loaders["admin-users"]();
                    return;
                }

                clear(tbody);

                if (users.length === 0) {
                    if (filtered) {
                        emptyState(
                            tbody,
                            "No users match your search and filters",
                            "Try a different name, email, role or status, or clear the filters.",
                            5
                        );
                    } else {
                        emptyRow(tbody, "No users have registered yet.", 5);
                    }
                    clear(el("admin-users-pagination"));
                    renderUsersResultCount(total, 0, filters);
                    return;
                }

                users.forEach((user) => {
                    const tr = document.createElement("tr");

                    const nameCell = document.createElement("td");
                    const nameText = document.createElement("span");
                    nameText.style.fontWeight = "600";
                    nameText.textContent = user.name || "—";
                    nameCell.appendChild(nameText);
                    if (user.id === state.user.id) {
                        const marker = document.createElement("span");
                        marker.className = "you-marker";
                        marker.textContent = " (you)";
                        nameCell.appendChild(marker);
                    }
                    tr.appendChild(nameCell);

                    tr.appendChild(makeCell(user.email || "—"));

                    const roleCell = document.createElement("td");
                    roleCell.appendChild(roleBadge(user.role));
                    tr.appendChild(roleCell);

                    const statusCell = document.createElement("td");
                    statusCell.appendChild(
                        user.is_disabled
                            ? makeBadge("Disabled", "badge-status badge-disabled")
                            : makeBadge("Active", "badge-status badge-active")
                    );
                    tr.appendChild(statusCell);

                    const actionsCell = document.createElement("td");
                    actionsCell.className = "td-actions";

                    if (user.id !== state.user.id && user.role !== "admin") {
                        actionsCell.appendChild(
                            actionButton("Change role", "btn-action", () => openRoleModal(user))
                        );
                        actionsCell.appendChild(
                            user.is_disabled
                                ? actionButton("Enable", "btn-action", () => confirmEnable(user))
                                : actionButton("Disable", "btn-action danger", () => confirmDisable(user))
                        );
                    } else if (user.id === state.user.id) {
                        const note = document.createElement("span");
                        note.className = "you-marker";
                        note.textContent = "Your account";
                        actionsCell.appendChild(note);
                    } else {
                        const note = document.createElement("span");
                        note.className = "you-marker";
                        note.textContent = "Protected Admin account";
                        actionsCell.appendChild(note);
                    }

                    tr.appendChild(actionsCell);
                    tbody.appendChild(tr);
                });

                renderUsersPagination(total, users.length, filtered);
                renderUsersResultCount(total, users.length, filters);
            })
            .catch((error) => {
                if (requestId !== usersRequestSerial) return;
                const message = error.message || "Unable to load users.";
                emptyRow(tbody, message, 5);
                clear(el("admin-users-pagination"));
                setUsersResultCount("Unable to load users.");
            })
            .finally(() => {
                if (requestId === usersRequestSerial) setUsersTableBusy(false);
            });
    };

    /**
     * Renders the user list pagination.
     *
     * The counters come from the API (`total`, the number of matching users)
     * and from the number of rows that were actually returned, never from an
     * estimate.
     */
    function renderUsersPagination(total, shown, filtered) {
        const container = el("admin-users-pagination");
        if (!container) return;
        clear(container);

        if (!total || !shown) return;

        const page = Math.floor(state.usersOffset / USERS_PAGE_SIZE) + 1;
        const pages = Math.max(Math.ceil(total / USERS_PAGE_SIZE), 1);

        const info = document.createElement("span");
        info.textContent =
            "Page " + page + " of " + pages + " · " + total +
            (filtered ? " matching " : " ") +
            "user" + (total === 1 ? "" : "s");
        container.appendChild(info);

        if (state.usersOffset > 0) {
            container.appendChild(
                actionButton("Previous", "btn btn-ghost btn-sm", () => {
                    state.usersOffset = Math.max(state.usersOffset - USERS_PAGE_SIZE, 0);
                    loaders["admin-users"]();
                })
            );
        }

        if (state.usersOffset + shown < total) {
            container.appendChild(
                actionButton("Next", "btn btn-ghost btn-sm", () => {
                    state.usersOffset += USERS_PAGE_SIZE;
                    loaders["admin-users"]();
                })
            );
        }
    }

    function roleBadge(role) {
        if (role === "admin") return makeBadge("Admin", "badge-status badge-admin");
        if (role === "document_owner") {
            return makeBadge("Owner", "badge-status badge-owner-role");
        }
        return makeBadge("Viewer", "badge-status badge-viewer-role");
    }

    function openRoleModal(user) {
        el("role-user-id").value = user.id;
        el("role-user-info").textContent =
            "Account: " + (user.name || "—") + " (" + (user.email || "—") + ")";
        el("role-current").value = roleLabel(user.role);

        const select = el("role-select");
        Array.from(select.options).forEach((option) => {
            option.disabled = option.value === user.role;
        });
        select.value = user.role === "viewer" ? "document_owner" : "viewer";

        el("role-reason").value = "";
        setFieldError("role-reason", "role-reason-error", "");
        setMessage(el("role-error"), null);
        openModal("role-modal");
    }

    function confirmDisable(user) {
        const who = user.name
            ? user.name + (user.email ? " (" + user.email + ")" : "")
            : user.email || "";

        confirmDialog({
            title: "Disable " + (user.name || user.email) + "?",
            message:
                who +
                " is signed out now and cannot sign in until an Admin enables the account. " +
                "The action is recorded in the audit log.",
            confirmLabel: "Disable account",
            requireReason: true,
            reasonLabel: "Reason for disabling this account",
            onConfirm: async (reason) => {
                try {
                    await api("PATCH", "/api/admin/users/" + encodeURIComponent(user.id) + "/disable", {
                        disabled: true,
                        reason
                    });
                    closeModal("confirm-modal");
                    toast((user.name || user.email) + " was disabled.", "success");
                    announce((user.name || user.email) + " was disabled.");
                    loaders["admin-users"]();
                } catch (error) {
                    closeModal("confirm-modal");
                    toast(error.message || "The account was not disabled.", "error");
                }
            }
        });
    }

    function confirmEnable(user) {
        confirmDialog({
            title: "Enable " + (user.name || user.email) + "?",
            message:
                (user.name || user.email) +
                " will be able to sign in again. Sessions that were ended when the account was " +
                "disabled are not restored, so the user has to sign in again.",
            confirmLabel: "Enable account",
            requireReason: true,
            reasonLabel: "Reason for enabling this account",
            onConfirm: async (reason) => {
                try {
                    await api("PATCH", "/api/admin/users/" + encodeURIComponent(user.id) + "/disable", {
                        disabled: false,
                        reason
                    });
                    closeModal("confirm-modal");
                    toast((user.name || user.email) + " was enabled.", "success");
                    announce((user.name || user.email) + " was enabled.");
                    loaders["admin-users"]();
                } catch (error) {
                    closeModal("confirm-modal");
                    toast(error.message || "The account was not enabled.", "error");
                }
            }
        });
    }

    // ── Admin: audit log ───────────────────────────────────────────────────────

    loaders["admin-audit"] = function loadAdminAudit() {
        const tbody = el("audit-tbody");
        loadingRow(tbody, "Loading audit log…", 5);

        const params = new URLSearchParams();
        params.set("limit", "150");

        const action = el("audit-action-filter").value;
        const user = el("audit-user-filter").value;
        const outcome = el("audit-outcome-filter").value;
        const from = el("audit-from-filter").value;
        const to = el("audit-to-filter").value;

        if (action) params.set("action", action);
        if (user) params.set("user", user);
        if (outcome) params.set("outcome", outcome);
        if (from) params.set("from", from);
        if (to) params.set("to", to);
        if (state.auditCursor) params.set("before", state.auditCursor);

        // The filter dropdowns are filled from the values that really occur in
        // the log. It is a separate call so that a failure there never hides
        // the log itself.
        loadAuditFilters();

        api("GET", "/api/admin/audit-logs?" + params.toString())
            .then((data) => {
                const logs = data.logs || [];
                state.auditNextCursor = data.nextCursor || null;
                clear(tbody);

                if (logs.length === 0) {
                    emptyRow(tbody, "No audit entries match the current filters.", 5);
                } else {
                    logs.forEach((log) => {
                        const tr = document.createElement("tr");
                        tr.appendChild(makeCell(formatTime(log.created_at)));
                        tr.appendChild(makeCell(log.actor_email || log.actor_name || "System"));
                        tr.appendChild(makeCell(humanAction(log.action)));
                        tr.appendChild(makeCell(log.document_name || log.target_user_email || "—"));
                        const resultCell = document.createElement("td");
                        resultCell.appendChild(resultBadge(log.outcome));
                        tr.appendChild(resultCell);
                        tbody.appendChild(tr);
                    });
                }

                renderWorthALook(data.worthALook);
                renderAuditPagination();
            })
            .catch((error) => {
                emptyRow(tbody, error.message || "Unable to load the audit log.", 5);
            });
    };

    /**
     * Shows the "worth a look" banner.
     *
     * The banner is only shown when the server actually reports refused
     * attempts; it is never filled with an invented number.
     */
    function renderWorthALook(alert) {
        const card = el("audit-worth-look");
        const text = el("audit-worth-look-text");
        if (!card || !text) return;

        if (!alert || !alert.email || !alert.count) {
            text.textContent = "";
            card.classList.add("hidden");
            return;
        }

        const count = Number(alert.count) || 0;
        const minutes = Number(alert.windowMinutes) || 1;
        text.textContent =
            alert.email +
            " was refused " +
            count +
            (count === 1 ? " time" : " times") +
            " in " +
            minutes +
            (minutes === 1 ? " minute" : " minutes");
        card.classList.remove("hidden");
    }

    function renderAuditPagination() {
        const container = el("audit-pagination");
        if (!container) return;
        clear(container);

        if (state.auditPageIndex > 0) {
            container.appendChild(
                actionButton("Newest", "btn btn-ghost btn-sm", () => {
                    state.auditCursorStack = [null];
                    state.auditPageIndex = 0;
                    state.auditCursor = null;
                    state.auditNextCursor = null;
                    loaders["admin-audit"]();
                })
            );
        }

        if (state.auditNextCursor) {
            container.appendChild(
                actionButton("Older", "btn btn-ghost btn-sm", () => {
                    // The stack keeps every cursor that was visited, so that
                    // "Newest" always goes back to the first page.
                    state.auditCursorStack = state.auditCursorStack.slice(
                        0,
                        state.auditPageIndex + 1
                    );
                    state.auditCursorStack.push(state.auditNextCursor);
                    state.auditPageIndex = state.auditCursorStack.length - 1;
                    state.auditCursor = state.auditNextCursor;
                    loaders["admin-audit"]();
                })
            );
        }
    }

    /** Resets the audit log back to the newest page. */
    function resetAuditPaging() {
        state.auditCursorStack = [null];
        state.auditPageIndex = 0;
        state.auditCursor = null;
        state.auditNextCursor = null;
    }

    /**
     * Turns the server's verification result into the one status the UI shows.
     *
     * The backend decides: `valid: true` → Verified, `valid: false` → Failed,
     * no answer or `status: "unavailable"` → Not Verified. No state is ever
     * inferred from the presence of a historical incident alone.
     */
    function describeChainStatus(verification) {
        if (!verification || typeof verification.valid !== "boolean") {
            return {
                state: "unknown",
                title: "INTEGRITY: NOT VERIFIED",
                detail: "The server did not report a verification result."
            };
        }

        if (verification.status === "unavailable") {
            return {
                state: "unknown",
                title: "INTEGRITY: NOT VERIFIED",
                detail:
                    verification.message ||
                    "Verification service unavailable: database or verifier could not be reached."
            };
        }

        if (verification.valid === true) {
            return {
                state: "valid",
                title: "INTEGRITY: VERIFIED",
                detail:
                    "All " +
                    (verification.totalEntries ?? 0) +
                    " entries hash-chain correctly. No entry has been altered or removed."
            };
        }

        if (verification.status === "documented_incident") {
            const incident = verification.incident || {};
            const code = typeof incident.code === "string" ? incident.code : "";
            const brokenAt =
                verification.brokenAtId ?? incident.brokenAtId ?? null;
            const codePrefix = code ? code + " · " : "";
            const location =
                brokenAt !== null
                    ? "Historical chain break at entry " + brokenAt + ". "
                    : "Historical chain break. ";

            return {
                state: "incident",
                title: "INTEGRITY: FAILED",
                detail:
                    codePrefix +
                    location +
                    "Historical records are preserved; the chain is segmented and not continuous."
            };
        }

        const reason = verification.reason ? " (" + verification.reason + ")" : "";
        const location =
            verification.brokenAtId !== null && verification.brokenAtId !== undefined
                ? " at entry " + verification.brokenAtId
                : "";

        return {
            state: "failed",
            title: "INTEGRITY: FAILED",
            detail:
                "The hash chain is broken" +
                location +
                reason +
                ". " +
                (verification.totalEntries ?? 0) +
                " entries were checked. No documented incident explains this break; it needs a server-side investigation."
        };
    }

    /** Appends one compact, server-driven verification row. */
    function appendChainDetailRow(container, labelText, badgeText, badgeClass) {
        const card = document.createElement("div");
        card.className = "chain-status-card is-compact";

        const row = document.createElement("div");
        row.className = "chain-status-row";

        const label = document.createElement("span");
        label.className = "chain-status-label";
        label.textContent = labelText;

        const badge = document.createElement("span");
        badge.className = "chain-badge " + badgeClass;
        badge.textContent = badgeText;

        row.appendChild(label);
        row.appendChild(badge);
        card.appendChild(row);
        container.appendChild(card);
    }

    /**
     * Renders the post-incident rows only from fields the server actually
     * returned. A missing segment or append-health object stays silent.
     */
    function renderIncidentDetails(container, verification) {
        if (!container) return;
        clear(container);

        if (!verification || verification.status !== "documented_incident") {
            return;
        }

        const segment = verification.segment2;
        if (segment && typeof segment === "object") {
            const start = segment.startId ?? "—";
            const end = segment.endId ?? verification.latestEntryId ?? "—";
            const count = Number.isFinite(Number(segment.entriesCount))
                ? " (" + Number(segment.entriesCount) + " entries)"
                : "";
            const segmentValid = segment.valid === true;

            appendChainDetailRow(
                container,
                "Post-incident segment " + start + " → " + end + count,
                segmentValid ? "✓ Verified intact" : "✕ Not verified",
                segmentValid ? "badge-success" : "badge-danger"
            );
        }

        const health = verification.appendHealth;
        if (health && typeof health === "object") {
            const latest = health.latestId ?? verification.latestEntryId;
            const healthy =
                health.active === true && health.extendsLatest === true;

            appendChainDetailRow(
                container,
                "Append health" + (latest !== undefined && latest !== null ? " (latest " + latest + ")" : ""),
                healthy ? "✓ Active & continuous" : "✕ Not confirmed",
                healthy ? "badge-success" : "badge-warning"
            );
        }
    }

    /**
     * Renders the complete verification result into any status container.
     * The dashboard card and the audit summary both use this renderer.
     */
    function renderChainStatus(container, verification) {
        if (!container) return;
        clear(container);

        const summary = describeChainStatus(verification);
        const line = document.createElement("div");
        line.className =
            summary.state === "valid"
                ? "chain-status-line is-valid"
                : summary.state === "failed" || summary.state === "incident"
                  ? "chain-status-line is-invalid"
                  : "chain-status-line is-unknown";
        line.textContent = summary.title;

        const detail = document.createElement("div");
        detail.className = "chain-status-detail";
        detail.textContent = summary.detail;

        container.appendChild(line);
        container.appendChild(detail);
        renderIncidentDetails(container, verification);
    }

    /** Applies the same verification result to the compact audit alert. */
    function renderAuditBanner(verification) {
        const title = el("audit-integrity-title");
        const text = el("audit-integrity-text");
        const card = el("audit-integrity-card");
        const summary = describeChainStatus(verification);

        if (title) title.textContent = summary.title;
        if (text) text.textContent = summary.detail;

        if (card) {
            card.classList.remove("is-valid", "is-invalid", "is-incident");
            if (summary.state === "valid") {
                card.classList.add("is-valid");
            } else if (summary.state === "incident") {
                card.classList.add("is-invalid", "is-incident");
            } else if (summary.state === "failed") {
                card.classList.add("is-invalid");
            }
        }

        renderIncidentDetails(el("audit-chain-status-ext"), verification);
    }

    async function verifyChain() {
        const bannerTitle = el("audit-integrity-title");
        const bannerText = el("audit-integrity-text");
        const bannerCard = el("audit-integrity-card");
        const bannerExt = el("audit-chain-status-ext");
        const dashStatus = el("admin-chain-status");
        const dashCard = el("admin-chain-card");
        const buttons = [el("btn-verify-chain"), el("btn-verify-chain-dash")].filter(Boolean);

        if (bannerTitle) bannerTitle.textContent = "INTEGRITY: NOT VERIFIED";
        if (bannerText) bannerText.textContent = "Checking the hash chain…";
        if (bannerCard) {
            bannerCard.classList.remove("is-valid", "is-invalid", "is-incident");
            bannerCard.setAttribute("aria-busy", "true");
        }
        if (bannerExt) clear(bannerExt);
        if (dashStatus) {
            clear(dashStatus);
            const line = document.createElement("div");
            line.className = "chain-status-line";
            line.textContent = "Checking the hash chain…";
            dashStatus.appendChild(line);
        }
        if (dashCard) {
            dashCard.setAttribute("aria-busy", "true");
        }
        buttons.forEach((button) => {
            button.disabled = true;
        });

        try {
            const verification = await api("GET", "/api/admin/verify-chain");
            renderChainStatus(dashStatus, verification);
            renderAuditBanner(verification);
        } catch (error) {
            const unavailable = {
                valid: false,
                status: "unavailable",
                message:
                    error && error.message
                        ? error.message
                        : "Verification service unavailable: database or verifier could not be reached."
            };
            renderChainStatus(dashStatus, unavailable);
            renderAuditBanner(unavailable);
        } finally {
            buttons.forEach((button) => {
                button.disabled = false;
            });
            if (bannerCard) bannerCard.removeAttribute("aria-busy");
            if (dashCard) dashCard.removeAttribute("aria-busy");
        }
    }

    async function loadAuditFilters() {
        try {
            const data = await api("GET", "/api/admin/audit-filters");

            const actionSelect = el("audit-action-filter");
            if (actionSelect) {
                const current = actionSelect.value;
                clear(actionSelect);
                const all = document.createElement("option");
                all.value = "";
                all.textContent = "All actions";
                actionSelect.appendChild(all);
                (data.actions || []).forEach((action) => {
                    const option = document.createElement("option");
                    option.value = action;
                    option.textContent = humanAction(action);
                    actionSelect.appendChild(option);
                });
                actionSelect.value = current;
            }

            const userSelect = el("audit-user-filter");
            if (userSelect) {
                const current = userSelect.value;
                clear(userSelect);
                const all = document.createElement("option");
                all.value = "";
                all.textContent = "All users";
                userSelect.appendChild(all);
                (data.users || []).forEach((user) => {
                    const option = document.createElement("option");
                    option.value = user.email || user.name || "";
                    option.textContent = user.email || user.name || "";
                    userSelect.appendChild(option);
                });
                userSelect.value = current;
            }
        } catch {
            /* The filters are optional; the log still works without them. */
        }
    }

    // ── Profile: authenticated request history ──────────────────────────────────
    let myRequestsSerial = 0;

    function renderMyRequests(requests) {
        const tbody = el("my-requests-tbody"); clear(tbody);
        const roleRequests = requests.filter((request) => request.requestType === "document_owner_upgrade");
        setHidden(el("my-requests-empty"), requests.length !== 0);
        requests.forEach((request) => {
            const tr = document.createElement("tr");
            const type = request.requestType === "document_owner_upgrade" ? "Document Owner upgrade" : request.requestType || "Request";
            tr.appendChild(makeCell(type));
            tr.appendChild(makeCell(request.requestedRole ? roleLabel(request.requestedRole) : request.targetResourceId || request.requestedPermission || "—"));
            const statusCell = document.createElement("td"); statusCell.appendChild(makeBadge(requestStatusLabel(request.status), "badge-status badge-" + request.status)); tr.appendChild(statusCell);
            tr.appendChild(makeCell(formatTime(request.submittedAt)));
            tr.appendChild(makeCell(request.decidedAt ? formatTime(request.decidedAt) : "—"));
            const detail = [request.decisionNote ? "Note: " + request.decisionNote : "", request.reviewerRole ? "Reviewer role: " + roleLabel(request.reviewerRole) : "", request.reviewerUserId ? "Reviewer ID: " + request.reviewerUserId : "", request.nextEligibleAt ? "Eligible to re-request: " + formatTime(request.nextEligibleAt) : ""].filter(Boolean).join(" · ");
            tr.appendChild(makeCell(detail || "—", "request-decision-details"));
            const action = document.createElement("td");
            if (request.status === "pending" && request.requestType === "document_owner_upgrade") {
                const cancel = actionButton("Cancel", "btn-action danger", (event) => cancelMyRequest(request, event.currentTarget));
                cancel.setAttribute("aria-label", "Cancel your pending Document Owner request"); action.appendChild(cancel);
            } else action.textContent = "—";
            tr.appendChild(action); tbody.appendChild(tr);
        });
        const pending = roleRequests.some((request) => request.status === "pending");
        const cooldownRequest = roleRequests.find((request) => request.status === "rejected" && request.nextEligibleAt && new Date(request.nextEligibleAt).getTime() > Date.now());
        const formAllowed = state.user && state.user.role === "viewer" && !pending && !cooldownRequest;
        el("role-request-submit").disabled = !formAllowed;
        const reason = el("role-request-disabled-reason");
        reason.textContent = pending ? "A request is pending review. You can submit another after it is resolved or cancelled." : cooldownRequest ? "You can request again after " + formatTime(cooldownRequest.nextEligibleAt) + ". This time is informational; the server decides eligibility." : state.user && state.user.role !== "viewer" ? "Only Viewer accounts can request Document Owner access." : "The server enforces request eligibility.";
        el("my-requests-eligibility").textContent = cooldownRequest ? "Next eligible re-request time: " + formatTime(cooldownRequest.nextEligibleAt) + "." : "";
    }

    async function loadMyRequests() {
        if (!state.user) return;
        const serial = ++myRequestsSerial;
        setHidden(el("my-requests-loading"), false); setHidden(el("my-requests-content"), true); setHidden(el("my-requests-retry"), true); setMessage(el("my-requests-error"), null);
        try {
            const data = await api("GET", "/api/requests/mine");
            if (serial !== myRequestsSerial) return;
            if (!data || !Array.isArray(data.requests)) throw new Error("The server returned an invalid request list.");
            renderMyRequests(data.requests); setHidden(el("my-requests-loading"), true); setHidden(el("my-requests-content"), false);
        } catch (error) {
            if (serial !== myRequestsSerial) return;
            setHidden(el("my-requests-loading"), true); setHidden(el("my-requests-content"), true); setMessage(el("my-requests-error"), error.message || "Unable to load your requests.", true); setHidden(el("my-requests-retry"), false);
        }
    }

    async function cancelMyRequest(request, button) {
        await withBusy(button, async () => {
            try {
                const result = await api("POST", "/api/requests/" + encodeURIComponent(request.id) + "/cancel", {});
                if (!result || !result.request || result.request.status !== "cancelled") throw new Error("The server did not confirm cancellation. Refresh to check the request status.");
                await loadMyRequests();
            } catch (error) { setMessage(el("my-requests-error"), error.message || "The request could not be cancelled.", true); }
        });
    }

    // ── Profile ────────────────────────────────────────────────────────────────

    loaders.profile = function loadProfile() {
        if (!state.user) return;
        el("profile-name").value = state.user.name || "";
        el("profile-email").value = state.user.email || "";
        el("profile-role").value = roleLabel(state.user.role);
        el("profile-created").value = formatDate(state.user.created_at);
        setMessage(el("profile-error"), null);
        setMessage(el("profile-success"), null);
        loadMyRequests();
    };

    // ── Enter / leave the app ──────────────────────────────────────────────────

    /**
     * Shows the sign-in screen, restoring the reason it was last shown.
     *
     * A boot that finds no session must not wipe the message from an
     * expired session or a disabled account: that is the sentence the user
     * needs to read.
     */
    function showStoredSessionNotice() {
        const notice = state.sessionNotice;
        if (notice) {
            showAuthScreen(notice.message, { banner: notice.kind });
        } else {
            showAuthScreen(null);
        }
    }

    async function enterApp() {
        let data;
        try {
            data = await api("GET", "/api/auth/me");
        } catch (error) {
            showStoredSessionNotice();
            return;
        }

        if (!data || !data.user) {
            // The server answered without a user: nobody is signed in.
            showStoredSessionNotice();
            return;
        }

        state.user = data.user;
        state.navAccess = readNavAccess();
        state.sessionNotice = null;

        hide(el("auth-screen"));
        show(el("app-shell"));
        hideAuthBanner();
        hideAppBanner();
        applyRole();
        if (state.user.role === "admin") loadAdminRequestCounts().catch(() => {});

        const start = DEFAULT_VIEW_BY_ROLE[state.user.role] || "shared";
        switchView(start);

        announce("Signed in as " + state.user.email + " with the " + roleLabel(state.user.role) + " role.");

        // Warm the filter dropdowns with real data: the categories and owners
        // of the documents this account may actually open.
        api("GET", "/api/documents/filters")
            .then((filters) => {
                rememberCategories(filters.categories || []);
                rememberOwners(filters.owners || []);
            })
            .catch(() => {
                /* The dropdowns stay on their defaults when this fails. */
            });
    }

    async function signOut() {
        try {
            await api("POST", "/api/auth/logout", {});
        } catch {
            /* The session is ended locally even if the call failed. */
        }
        state.user = null;
        state.currentDocument = null;
        state.sessionNotice = null;
        hideAppBanner();
        document.querySelectorAll(".nav-item[data-view]").forEach((item) => setHidden(item, true));
        setHidden(el("nav-section-admin"), true);
        resetAuthMessages();
        showAuthScreen(null);
        announce("You have been signed out.");
    }

    // ── Event wiring ───────────────────────────────────────────────────────────

    function initAppShell() {
        document.querySelectorAll(".nav-item[data-view]").forEach((item) => {
            item.addEventListener("click", (event) => {
                event.preventDefault();
                const view = item.getAttribute("data-view");
                if (!canAccess(view)) {
                    toast("Your role does not have access to that screen.", "error");
                    return;
                }
                switchView(view);
            });
        });

        el("logout-btn").addEventListener("click", signOut);
        el("btn-account").addEventListener("click", () => switchView("profile"));

        // ── Page banner ──
        const bannerClose = el("app-banner-close");
        if (bannerClose) {
            bannerClose.addEventListener("click", hideAppBanner);
        }

        // ── The not-found screen offers the two ways back ──
        const notFoundShared = el("btn-notfound-shared");
        if (notFoundShared) {
            notFoundShared.addEventListener("click", () => switchView("shared"));
        }
        const notFoundSearch = el("btn-notfound-search");
        if (notFoundSearch) {
            notFoundSearch.addEventListener("click", () => switchView("search"));
        }

        // api.js reports a gone session through this event, so that a request
        // that failed before the response was read still ends on the sign-in
        // screen instead of on a half-loaded view.
        window.addEventListener("trustvault:session-expired", () => {
            handleSessionExpired();
        });

        el("btn-new-upload").addEventListener("click", () => {
            if (!state.user || state.user.role !== "document_owner") {
                toast("Only document owners can upload documents.", "error");
                return;
            }
            switchView("upload");
        });

        el("btn-dash-upload").addEventListener("click", () => switchView("upload"));

        // ── Document tabs ──
        ["details", "access", "activity"].forEach((tab) => {
            const button = el("tab-" + tab);
            if (!button) return;
            button.addEventListener("click", () => selectTab(tab));
        });

        // ── My documents filters ──
        const docSearch = el("doc-search");
        docSearch.addEventListener("input", debounce(() => {
            state.pages.documents = 1;
            loaders.documents();
        }, 350));
        el("doc-category-filter").addEventListener("change", () => {
            state.pages.documents = 1;
            loaders.documents();
        });
        el("doc-from-filter").addEventListener("change", () => {
            state.pages.documents = 1;
            loaders.documents();
        });
        el("doc-to-filter").addEventListener("change", () => {
            state.pages.documents = 1;
            loaders.documents();
        });

        // ── Shared filters ──
        // The "Shared with me" screen filters by name and by owner only; the
        // approved design has no category filter on this screen.
        el("shared-search").addEventListener("input", debounce(() => {
            state.pages.shared = 1;
            loaders.shared();
        }, 350));
        el("shared-owner-filter").addEventListener("change", () => {
            state.pages.shared = 1;
            loaders.shared();
        });

        // ── Search filters ──
        el("global-search-input").addEventListener("input", debounce(() => {
            state.pages.search = 1;
            loaders.search();
        }, 400));
        const searchButton = el("btn-search");
        if (searchButton) {
            searchButton.addEventListener("click", () => {
                state.pages.search = 1;
                loaders.search();
            });
        }
        ["search-category-filter", "search-owner-filter", "search-from-filter", "search-to-filter"].forEach(
            (id) => {
                const node = el(id);
                if (!node) return;
                node.addEventListener("change", () => {
                    state.pages.search = 1;
                    loaders.search();
                });
            }
        );

        // ── Upload ──
        const uploadFile = el("upload-file");
        uploadFile.addEventListener("change", () => {
            const file = uploadFile.files && uploadFile.files[0];
            el("upload-file-info").textContent = describeFile(file);
            const problem = file ? validateFile(file) : null;
            setFieldError("upload-file", "upload-file-error", problem || "");
        });

        const dropzone = el("upload-dropzone");
        dropzone.addEventListener("dragover", (event) => {
            event.preventDefault();
            dropzone.classList.add("is-dragover");
        });
        dropzone.addEventListener("dragleave", () => dropzone.classList.remove("is-dragover"));
        dropzone.addEventListener("drop", (event) => {
            event.preventDefault();
            dropzone.classList.remove("is-dragover");
            if (event.dataTransfer && event.dataTransfer.files.length > 0) {
                uploadFile.files = event.dataTransfer.files;
                uploadFile.dispatchEvent(new Event("change"));
            }
        });

        el("upload-form").addEventListener("submit", async (event) => {
            event.preventDefault();
            setMessage(el("upload-error"), null);
            setMessage(el("upload-success"), null);
            setFieldError("upload-name", "upload-name-error", "");
            setFieldError("upload-file", "upload-file-error", "");

            if (!state.user || state.user.role !== "document_owner") {
                setMessage(
                    el("upload-error"),
                    "Access denied: only document owners can upload documents.",
                    true
                );
                return;
            }

            const name = el("upload-name").value.trim();
            const file = uploadFile.files && uploadFile.files[0];

            let valid = true;
            if (!name) {
                setFieldError("upload-name", "upload-name-error", "Document name is required.");
                valid = false;
            }
            const fileProblem = validateFile(file);
            if (fileProblem) {
                setFieldError("upload-file", "upload-file-error", fileProblem);
                valid = false;
            }
            if (!valid) return;

            const form = new FormData();
            form.append("name", name);
            form.append("category", el("upload-category").value.trim() || "General");
            form.append("description", el("upload-desc").value.trim());
            form.append("file", file);

            const button = el("upload-btn");
            await withBusy(button, async () => {
                try {
                    const data = await api("POST", "/api/documents", form, { form: true });
                    const uploadedName = data && data.document ? data.document.name : name;
                    setMessage(el("upload-success"), uploadedName + " was uploaded.", false);
                    announce(uploadedName + " was uploaded.");
                    el("upload-form").reset();
                    el("upload-file-info").textContent = "";
                    window.setTimeout(() => switchView("documents"), 900);
                } catch (error) {
                    setMessage(el("upload-error"), error.message || "The file was not uploaded.", true);
                    announce(error.message || "The file was not uploaded.");
                }
            });
        });

        el("upload-cancel").addEventListener("click", () => switchView("documents"));

        // ── Edit ──
        el("edit-form").addEventListener("submit", async (event) => {
            event.preventDefault();
            hideAppBanner();
            setMessage(el("edit-error"), null);
            setMessage(el("edit-success"), null);
            setFieldError("edit-name", "edit-name-error", "");
            setFieldError("edit-file", "edit-file-error", "");

            const documentId = el("edit-doc-id").value;
            const name = el("edit-name").value.trim();
            if (!name) {
                setFieldError("edit-name", "edit-name-error", "Document name is required.");
                return;
            }

            const fileInput = el("edit-file");
            const file = fileInput.files && fileInput.files[0];

            // The server validates every file, but an obviously invalid one is
            // refused here first so that no pointless upload is sent. The
            // wording is the one the design fixes for the refused screen.
            if (file) {
                const problem = describeFileProblem(file);
                if (problem) {
                    setFieldError("edit-file", "edit-file-error", problem);
                    showAppBanner(EDIT_REJECTED_MESSAGE, "error");
                    return;
                }
            }

            const form = new FormData();
            form.append("name", name);
            form.append("category", el("edit-category").value.trim() || "General");
            form.append("description", el("edit-desc").value.trim());
            if (file) form.append("file", file);

            const button = el("edit-btn");
            await withBusy(button, async () => {
                try {
                    const data = await api(
                        "PUT",
                        "/api/documents/" + encodeURIComponent(documentId),
                        form,
                        { form: true }
                    );

                    const savedName =
                        data && data.document && data.document.name ? data.document.name : name;

                    // The confirmation is shown only after the server
                    // confirmed the change, and the page then shows the
                    // updated document.
                    const returnView = state.returnView;
                    clearEditForm();
                    showAppBanner("The server saved your changes to " + savedName + ".", "success");
                    announce("The server saved your changes to " + savedName + ".");
                    await openDocument(documentId);
                    state.returnView = returnView;
                } catch (error) {
                    if (error && error.status === 404) {
                        showDocumentNotFound();
                        return;
                    }

                    // A refused replacement leaves the stored file untouched:
                    // the banner says so and the field says which file.
                    if (file && error && (error.status === 413 || error.status === 415)) {
                        setFieldError(
                            "edit-file",
                            "edit-file-error",
                            refusedFileMessage(file, error.status)
                        );
                        showAppBanner(EDIT_REJECTED_MESSAGE, "error");
                        return;
                    }

                    setMessage(el("edit-error"), error.message || "The document was not saved.", true);
                    announce(error.message || "The document was not saved.");
                }
            });
        });

        // The file control is hidden: the "Replace file" button opens it.
        const editFileButton = el("edit-file-button");
        if (editFileButton) {
            editFileButton.addEventListener("click", () => el("edit-file").click());
        }

        const editFile = el("edit-file");
        if (editFile) {
            editFile.addEventListener("change", () => {
                const file = editFile.files && editFile.files[0];
                const info = el("edit-file-info");
                if (info) {
                    info.textContent = file
                        ? file.name + " — " + formatBytes(file.size)
                        : "";
                }
                setFieldError(
                    "edit-file",
                    "edit-file-error",
                    file ? describeFileProblem(file) : ""
                );
            });
        }

        el("edit-cancel-btn").addEventListener("click", () => {
            if (state.returnView === "doc-detail" && state.currentDocument) {
                openDocument(state.currentDocument.id);
            } else {
                switchView(state.returnView || "shared");
            }
        });

        // ── Grant access ──
        el("grant-form").addEventListener("submit", async (event) => {
            event.preventDefault();
            setFieldError("grant-email", "grant-email-error", "");

            const email = el("grant-email").value.trim();
            const permission = el("grant-permission").value;
            const documentId = state.grantDocumentId;

            if (!email) {
                setFieldError("grant-email", "grant-email-error", "An email address is required.");
                return;
            }
            if (!documentId) return;

            const button = el("grant-btn");
            await withBusy(button, async () => {
                try {
                    await api(
                        "POST",
                        "/api/documents/" + encodeURIComponent(documentId) + "/permissions",
                        { email, permission }
                    );
                    el("grant-email").value = "";
                    toast("Access granted to " + email + ".", "success");
                    announce("Access granted to " + email + ".");
                    loadPermissions(documentId);
                } catch (error) {
                    setFieldError(
                        "grant-email",
                        "grant-email-error",
                        error.message || "Access was not granted."
                    );
                    announce(error.message || "Access was not granted.");
                }
            });
        });

        // ── Profile ──
        el("profile-form").addEventListener("submit", async (event) => {
            event.preventDefault();
            setMessage(el("profile-error"), null);
            setMessage(el("profile-success"), null);

            const name = el("profile-name").value.trim();
            const email = el("profile-email").value.trim();

            const button = el("profile-btn");
            await withBusy(button, async () => {
                try {
                    const data = await api("PUT", "/api/auth/me", { name, email });
                    if (data && data.user) state.user = Object.assign({}, state.user, data.user);
                    applyRole();
                    setMessage(el("profile-success"), "Your profile was updated.", false);
                    announce("Your profile was updated.");
                } catch (error) {
                    setMessage(el("profile-error"), error.message || "Your profile was not updated.", true);
                }
            });
        });

        const roleRequestForm = el("role-request-form");
        roleRequestForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            setMessage(el("role-request-feedback"), null);
            const reason = el("role-request-justification").value.trim();
            if (reason.length > 500) {
                setMessage(el("role-request-feedback"), "Reason must be at most 500 characters.", true);
                return;
            }
            const button = el("role-request-submit");
            await withBusy(button, async () => {
                try {
                    const result = await api("POST", "/api/requests", { requestType: "document_owner_upgrade", reason });
                    if (!result || !result.request || result.request.status !== "pending") throw new Error("The server did not confirm submission. Refresh your requests to check status.");
                    roleRequestForm.reset(); toast("Your Owner access request was submitted.", "success"); await loadMyRequests();
                } catch (error) {
                    setMessage(el("role-request-feedback"), error.message || "Your request was not submitted.", true);
                    if (error.status === 409 || error.status === 429) await loadMyRequests();
                }
            });
        });
        el("my-requests-retry").addEventListener("click", loadMyRequests);
        el("admin-requests-retry").addEventListener("click", () => loaders["admin-requests"]());
        el("requests-status-filter").addEventListener("change", () => loaders["admin-requests"]());
        el("requests-type-filter").addEventListener("change", () => loaders["admin-requests"]());
        el("requests-search").addEventListener("input", () => {
            window.clearTimeout(adminRequestFiltersTimer);
            adminRequestFiltersTimer = window.setTimeout(() => loaders["admin-requests"](), 300);
        });
        el("requests-search").addEventListener("keydown", (event) => {
            if (event.key === "Enter") { event.preventDefault(); window.clearTimeout(adminRequestFiltersTimer); loaders["admin-requests"](); }
        });

        el("password-form").addEventListener("submit", async (event) => {
            event.preventDefault();
            setMessage(el("password-error"), null);
            setMessage(el("password-success"), null);
            setFieldError("pw-new", "pw-new-error", "");

            const currentPassword = el("pw-current").value;
            const newPassword = el("pw-new").value;

            if (newPassword && newPassword.length < 12) {
                setFieldError("pw-new", "pw-new-error", "Password must be at least 12 characters");
                return;
            }

            const button = el("password-btn");
            await withBusy(button, async () => {
                try {
                    await api("POST", "/api/auth/change-password", { currentPassword, newPassword });
                    el("password-form").reset();
                    setMessage(el("password-success"), "Your password was changed.", false);
                    announce("Your password was changed.");
                } catch (error) {
                    setMessage(el("password-error"), error.message || "Your password was not changed.", true);
                }
            });
        });

        // ── Admin: users search and filters ──
        const adminUsersSearch = el("admin-users-search");
        const runAdminUsersSearch = debounce(() => {
            state.usersOffset = 0;
            loaders["admin-users"]();
        }, 300);

        if (adminUsersSearch) {
            adminUsersSearch.addEventListener("input", runAdminUsersSearch);
            adminUsersSearch.addEventListener("keydown", (event) => {
                if (event.key !== "Enter") return;
                event.preventDefault();
                runAdminUsersSearch.cancel();
                state.usersOffset = 0;
                loaders["admin-users"]();
            });
        }

        ["admin-users-role-filter", "admin-users-status-filter"].forEach((id) => {
            const node = el(id);
            if (!node) return;
            node.addEventListener("change", () => {
                state.usersOffset = 0;
                loaders["admin-users"]();
            });
        });

        const clearAdminUserFilters = el("admin-users-clear-filters");
        if (clearAdminUserFilters) {
            clearAdminUserFilters.addEventListener("click", () => {
                runAdminUsersSearch.cancel();
                if (adminUsersSearch) adminUsersSearch.value = "";
                el("admin-users-role-filter").value = "";
                el("admin-users-status-filter").value = "";
                state.usersOffset = 0;
                loaders["admin-users"]();
                if (adminUsersSearch) adminUsersSearch.focus();
            });
        }

        // ── Admin: add user ──
        el("btn-add-user").addEventListener("click", () => {
            el("add-user-form").reset();
            setMessage(el("add-user-error"), null);
            setMessage(el("add-user-success"), null);
            clearFieldErrors([
                ["add-user-name", "add-user-name-error"],
                ["add-user-email", "add-user-email-error"]
            ]);
            openModal("add-user-modal");
        });

        el("add-user-form").addEventListener("submit", async (event) => {
            event.preventDefault();
            setMessage(el("add-user-error"), null);
            setMessage(el("add-user-success"), null);
            clearFieldErrors([
                ["add-user-name", "add-user-name-error"],
                ["add-user-email", "add-user-email-error"]
            ]);

            const name = el("add-user-name").value.trim();
            const email = el("add-user-email").value.trim();
            const role = el("add-user-role").value;

            let valid = true;
            if (!name) {
                setFieldError("add-user-name", "add-user-name-error", "Name is required.");
                valid = false;
            }
            if (!email) {
                setFieldError("add-user-email", "add-user-email-error", "Email address is required.");
                valid = false;
            } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
                setFieldError("add-user-email", "add-user-email-error", "Enter a valid email address.");
                valid = false;
            }
            if (!valid) return;

            const button = el("add-user-btn");
            await withBusy(button, async () => {
                try {
                    const data = await api("POST", "/api/admin/users", { name, email, role });
                    const created = data && data.user ? data.user : null;
                    const createdRole = created ? roleLabel(created.role) : roleLabel(role);
                    const message =
                        (created ? created.name : name) + " was created as " + createdRole + ".";
                    if (data && data.temporaryPassword) {
                        setMessage(
                            el("add-user-success"),
                            message +
                                " One-time password (shown once): " +
                                data.temporaryPassword,
                            false
                        );
                    } else {
                        setMessage(el("add-user-success"), message, false);
                    }
                    announce(message);
                    el("add-user-name").value = "";
                    el("add-user-email").value = "";
                    loaders["admin-users"]();
                } catch (error) {
                    const message = error.message || "The user was not created. The server returned an error. Try again.";
                    if (error.status === 409) {
                        setFieldError("add-user-email", "add-user-email-error", message);
                        setMessage(el("add-user-error"), null);
                    } else {
                        setMessage(el("add-user-error"), message, true);
                    }
                    announce(message);
                }
            });
        });

        // ── Admin: change role ──
        el("role-form").addEventListener("submit", async (event) => {
            event.preventDefault();
            setMessage(el("role-error"), null);

            const userId = el("role-user-id").value;
            const role = el("role-select").value;
            const reason = el("role-reason").value;
            const button = el("role-save-btn");

            const reasonError = validateReason(reason, "Reason");
            if (reasonError) {
                setFieldError("role-reason", "role-reason-error", reasonError);
                return;
            }
            setFieldError("role-reason", "role-reason-error", "");

            await withBusy(button, async () => {
                try {
                    await api("PATCH", "/api/admin/users/" + encodeURIComponent(userId) + "/role", {
                        role,
                        reason: reason.trim()
                    });
                    closeModal("role-modal");
                    toast("The role was updated.", "success");
                    announce("The role was updated.");
                    loaders["admin-users"]();
                } catch (error) {
                    setMessage(el("role-error"), error.message || "The role was not updated.", true);
                }
            });
        });

        // ── Admin: audit log filters ──
        ["audit-action-filter", "audit-user-filter", "audit-outcome-filter"].forEach((id) => {
            const node = el(id);
            if (!node) return;
            node.addEventListener("change", () => {
                resetAuditPaging();
                loaders["admin-audit"]();
            });
        });
        ["audit-from-filter", "audit-to-filter"].forEach((id) => {
            const node = el(id);
            if (!node) return;
            node.addEventListener("change", () => {
                resetAuditPaging();
                loaders["admin-audit"]();
            });
        });
        el("audit-clear-filters").addEventListener("click", () => {
            el("audit-action-filter").value = "";
            el("audit-user-filter").value = "";
            el("audit-outcome-filter").value = "";
            el("audit-from-filter").value = "";
            el("audit-to-filter").value = "";
            resetAuditPaging();
            loaders["admin-audit"]();
        });

        el("btn-verify-chain").addEventListener("click", verifyChain);
        el("btn-verify-chain-dash").addEventListener("click", verifyChain);

        // ── Modal dismissal ──
        document.querySelectorAll("[data-close-modal]").forEach((button) => {
            button.addEventListener("click", () => {
                closeModal(button.getAttribute("data-close-modal"));
            });
        });

        document.querySelectorAll(".modal-overlay").forEach((overlay) => {
            overlay.addEventListener("mousedown", (event) => {
                if (event.target === overlay) {
                    closeModal(overlay.id);
                }
            });
        });

        document.addEventListener("keydown", (event) => {
            if (event.key === "Escape" && modalState.openId) {
                closeModal(modalState.openId);
                return;
            }
            if (event.key === "Tab") {
                trapFocus(event);
            }
        });
    }

    function debounce(fn, delay) {
        let timer = null;
        const debounced = function () {
            const args = arguments;
            const context = this;
            window.clearTimeout(timer);
            timer = window.setTimeout(() => fn.apply(context, args), delay);
        };
        debounced.cancel = function () {
            window.clearTimeout(timer);
            timer = null;
        };
        return debounced;
    }

    // ── Boot ───────────────────────────────────────────────────────────────────

    /**
     * Starts the controller.
     *
     * It runs exactly once: a second call would attach every listener a
     * second time, and every click would then send its request twice.
     */
    let booted = false;

    async function boot() {
        if (booted) return;
        booted = true;

        initAuth();
        initAppShell();
        state.navAccess = readNavAccess();

        try {
            await enterApp();
        } catch {
            showStoredSessionNotice();
        }

        // The public landing page links to /app?mode=register. Only switch
        // when the authentication screen is visible; a signed-in account
        // keeps the role-appropriate view that enterApp restored.
        if (!state.user) {
            const requestedMode = new URLSearchParams(window.location.search).get("mode");
            if (requestedMode === "register") switchAuthTab("register");
        }
    }

    document.addEventListener("DOMContentLoaded", boot);

    if (document.readyState !== "loading") {
        // The script was evaluated after the document was already parsed.
        boot();
    }
})();
