// Shared behaviour for every SAYNO page: mobile menu, current-page marker, footer email request.
// SY.base is "" on a server and "/sayno" on GitHub Pages: the folder that holds assets/, v1/ and the pages.
(() => {
  const base = new URL("..", document.currentScript.src).pathname.replace(/\/$/, "");
  window.SY = { base, data: location.origin + base };

  // mark the current page in the main navigation
  const path = location.pathname.replace(base, "").replace(/index\.html$/, "");
  const key = path === "/" || path === "" ? "product" : path.split("/").filter(Boolean)[0];
  document.querySelectorAll("#nav a[data-nav]").forEach(a => { if (a.dataset.nav === key) a.setAttribute("aria-current", "page"); });

  const btn = document.getElementById("menu-btn"), nav = document.getElementById("nav");
  if (btn && nav) {
    btn.addEventListener("click", () => { const open = nav.classList.toggle("open"); btn.setAttribute("aria-expanded", String(open)); });
    document.addEventListener("keydown", e => { if (e.key === "Escape" && nav.classList.contains("open")) { nav.classList.remove("open"); btn.setAttribute("aria-expanded", "false"); btn.focus(); } });
  }

  // footer "stay informed": no mailing service behind it, so it opens the visitor's own email app
  const sub = document.getElementById("subscribe");
  if (sub) sub.addEventListener("submit", e => {
    e.preventDefault();
    const addr = document.getElementById("sub-email").value.trim();
    if (!addr) return;
    location.href = "mailto:sayoshield@gmail.com?subject=" + encodeURIComponent("SAYNO updates") +
      "&body=" + encodeURIComponent("Please send me SAYNO updates at: " + addr);
  });
})();
