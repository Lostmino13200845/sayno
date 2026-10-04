// Website navigation: the search icon opens a box that checks a link or message
// in the web scanner (/app). The text is passed in the #hash, so it never reaches server logs.
(() => {
  const BASE = new URL("..", document.currentScript.src).pathname.replace(/\/$/, "");  // "" on a server, "/sayno" on Pages
  const btn = document.getElementById("searchBtn");
  const panel = document.getElementById("searchPanel");
  const input = document.getElementById("searchInput");
  if (!btn || !panel) return;

  const setOpen = open => {
    panel.hidden = !open;
    btn.setAttribute("aria-expanded", String(open));
    if (open) input.focus();
  };
  btn.addEventListener("click", () => setOpen(panel.hidden));
  document.addEventListener("keydown", e => { if (e.key === "Escape" && !panel.hidden) { setOpen(false); btn.focus(); } });
  panel.addEventListener("submit", e => {
    e.preventDefault();
    const q = input.value.trim();
    if (q) location.href = BASE + "/app/#q=" + encodeURIComponent(q);
  });
})();
