// The Card Guard demo: a safe, simulated fake bank page with the same warning the extension shows.
(() => {
  const $ = id => document.getElementById(id);
  const views = { warning: $("v-warning"), blocked: $("v-blocked"), continued: $("v-continued") };
  const focusTarget = { warning: "w-title", blocked: "b-title" };
  function show(name) {
    Object.entries(views).forEach(([k, el]) => { el.hidden = k !== name; });
    const id = focusTarget[name];
    if (id) $(id).focus({ preventScroll: true });
  }
  $("leave").addEventListener("click", () => show("blocked"));
  $("continue").addEventListener("click", () => show("continued"));
  $("reset-1").addEventListener("click", () => show("warning"));
})();
