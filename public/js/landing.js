/**
 * TrustVault public landing page.
 *
 * This script only handles presentation: the mobile navigation panel and the
 * active-section marker in the desktop navigation. It never calls the API and
 * never loads document data. The authenticated application remains in
 * public/js/app.js and is served separately at /app.
 */
(function () {
    "use strict";

    const toggle = document.querySelector(".nav-toggle");
    const panel = document.getElementById("mobile-nav");

    if (toggle && panel) {
        const setOpen = (open) => {
            toggle.setAttribute("aria-expanded", String(open));
            toggle.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
            panel.hidden = !open;
            panel.classList.toggle("is-open", open);
        };

        toggle.addEventListener("click", () => {
            setOpen(toggle.getAttribute("aria-expanded") !== "true");
        });

        panel.querySelectorAll("a").forEach((link) => {
            link.addEventListener("click", () => setOpen(false));
        });

        document.addEventListener("keydown", (event) => {
            if (event.key === "Escape" && toggle.getAttribute("aria-expanded") === "true") {
                setOpen(false);
                toggle.focus();
            }
        });

        window.addEventListener("resize", () => {
            if (window.innerWidth > 900) setOpen(false);
        });
    }

    const sections = Array.from(document.querySelectorAll("main section[id]"));
    const navLinks = Array.from(document.querySelectorAll(".site-nav a[href^='#']"));

    if (sections.length > 0 && navLinks.length > 0 && "IntersectionObserver" in window) {
        const byId = new Map(
            navLinks.map((link) => [link.getAttribute("href").slice(1), link])
        );
        const observed = sections.filter((section) => byId.has(section.id));

        const setActive = (id) => {
            navLinks.forEach((link) => link.classList.remove("is-active"));
            const link = byId.get(id);
            if (link) link.classList.add("is-active");
        };

        const observer = new IntersectionObserver(
            (entries) => {
                const visible = entries.filter((entry) => entry.isIntersecting);
                if (visible.length > 0) setActive(visible[0].target.id);
            },
            { rootMargin: "-40% 0px -55% 0px", threshold: 0 }
        );

        observed.forEach((section) => observer.observe(section));
    }
})();
