/* ═══════════════════════════════════════════════════════════════════════════
   TrustVault — API client with built-in CSRF handling
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
    "use strict";

    let csrfToken = null;

    // ── Fetch a fresh CSRF token from the server ──────────────────────────────
    async function refreshCsrfToken() {
        try {
            const res = await fetch("/api/auth/csrf-token", { credentials: "same-origin" });
            if (res.ok) {
                const data = await res.json();
                csrfToken = data.csrfToken || null;
            }
        } catch {
            csrfToken = null;
        }
    }

    // ── Core request helper ───────────────────────────────────────────────────
    async function request(url, options = {}) {
        const method = (options.method || "GET").toUpperCase();
        const headers = options.headers || {};

        // If mutating request and no CSRF token present, fetch one first
        if (!csrfToken && method !== "GET" && method !== "HEAD") {
            await refreshCsrfToken();
        }

        // Attach CSRF token on state-changing requests
        if (csrfToken && method !== "GET" && method !== "HEAD") {
            headers["x-csrf-token"] = csrfToken;
        }

        const fetchOpts = {
            method,
            credentials: "same-origin",
            ...options,
            headers
        };

        const res = await fetch(url, fetchOpts);

        // If we get a 403 that looks like a CSRF rejection, refresh the token
        // and retry once.
        if (res.status === 403) {
            const clone = res.clone();
            try {
                const body = await clone.json();
                if (body && typeof body.message === "string" && /csrf/i.test(body.message)) {
                    await refreshCsrfToken();
                    if (csrfToken) {
                        headers["x-csrf-token"] = csrfToken;
                        const retry = await fetch(url, { ...fetchOpts, headers });
                        return retry;
                    }
                }
            } catch { /* not JSON, return original response */ }
        }

        // A 401 means the session is gone (expired, signed out or the account
        // was removed). The sign-in and registration endpoints are exempt:
        // they are the way back in.
        if (res.status === 401 && !isAuthEntryPoint(url)) {
            notifySessionExpired();
        }

        return res;
    }

    /** Endpoints that must never trigger the "session expired" state. */
    function isAuthEntryPoint(url) {
        return /\/api\/auth\/(login|register|csrf-token|session-expired|me)\b/.test(String(url));
    }

    /**
     * Tells the application that the server session is gone.
     * The listener in app.js shows the "Your session has ended" state.
     */
    function notifySessionExpired() {
        try {
            window.dispatchEvent(new CustomEvent("trustvault:session-expired"));
        } catch { /* no listener */ }
    }

    // ── Convenience wrappers ──────────────────────────────────────────────────
    async function get(url) {
        return request(url);
    }

    async function postJson(url, data) {
        return request(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });
    }

    async function putJson(url, data) {
        return request(url, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });
    }

    async function patchJson(url, data) {
        return request(url, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });
    }

    async function postForm(url, formData) {
        return request(url, {
            method: "POST",
            body: formData
        });
    }

    async function putForm(url, formData) {
        return request(url, {
            method: "PUT",
            body: formData
        });
    }

    async function del(url) {
        return request(url, { method: "DELETE" });
    }

    /**
     * Downloads a file.
     *
     * The raw response is returned instead of the parsed body, so that the
     * caller can tell a document that is gone (404) from a server that
     * answered with an error page (anything else that is not `ok`).
     */
    async function download(url) {
        return request(url);
    }

    // ── Expose globally ───────────────────────────────────────────────────────
    window.API = {
        refreshCsrfToken,
        get,
        postJson,
        putJson,
        patchJson,
        postForm,
        putForm,
        del,
        download
    };
})();
