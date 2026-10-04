const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const DEFAULTS = { enabled: true, newcomerMode: true, myBanks: [] };

function findingsOf(r) {
  return [...r.text.findings, ...r.urls.flatMap(u => u.findings), ...r.emails.flatMap(e => e.findings)]
    .filter(f => f.weight).slice(0, 5);
}
function render(r) {
  const f = findingsOf(r);
  return `<span class="ss-level ss-level--${r.level}">${r.level} · ${r.score}/100</span>
    <ul class="ss-findings">${f.map(x => `<li class="${x.severity === "danger" ? "is-danger" : ""}">${esc(x.message)}</li>`).join("")
      || '<li class="is-ok">No warning signs found.</li>'}</ul>
    ${r.reported ? `<div class="pp-reported">🚩 ${r.reported} dangerous link(s) reported automatically.</div>` : ""}`;
}

// server status
chrome.runtime.sendMessage({ type: "status" }, s => {
  $("#srv").textContent = s ? `🟢 ${s.protection.threats.toLocaleString()} threats` : "🔴 server offline";
});

// current site verdict
// A safe page says so in words: a bare "SAFE 0/100" reads like a contradiction above a scam result.
function renderSite(v) {
  if (v.level !== "safe" && v.level !== "low") return render(v);
  return '<span class="ss-level ss-level--safe">This page looks safe</span><p class="ss-muted">No warning signs found on this page.</p>';
}
chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  chrome.runtime.sendMessage({ type: "getVerdict", tabId: tab.id }, v => {
    $("#site").innerHTML = v ? `<div class="pp-host">${esc(new URL(tab.url).host)}</div>${renderSite(v)}`
      : /^https?:/.test(tab.url || "") ? '<span class="ss-level">not rated</span> <span class="ss-muted">Local page, or the SAYNO server is offline.</span>' : "Not a web page.";
  });
});

// server address (default comes from config.js; a store build points it at the public SAYNO server)
chrome.storage.local.get({ shareReports: false }, ({ shareReports }) => { $("#shareReports").checked = shareReports; });
$("#shareReports").onchange = e => chrome.storage.local.set({ shareReports: e.target.checked });
(async () => {
  const { DEFAULT_API } = await import("./config.js");
  // Community reporting only exists on a self-hosted server: the public server keeps no reports, so the switch is hidden there.
  $("#shareReports").closest("label").hidden = new URL(DEFAULT_API).hostname !== "127.0.0.1";
  const { apiBase } = await chrome.storage.local.get("apiBase");
  $("#apiBase").value = apiBase || DEFAULT_API;
  $("#apiBase").addEventListener("change", async e => {
    const hint = $("#apiHint");
    let u;
    try { u = new URL(e.target.value.trim() || DEFAULT_API); } catch { u = null; }
    const local = u && u.protocol === "http:" && ["127.0.0.1", "localhost"].includes(u.hostname);
    if (!u || !(u.protocol === "https:" || local)) {
      e.target.value = apiBase || DEFAULT_API;
      hint.textContent = "Use an https:// address (or http://127.0.0.1:PORT for a server on this computer).";
      hint.hidden = false;
      return;
    }
    if (!(await chrome.permissions.request({ origins: [u.origin + "/*"] }))) {  // resolves at once if already granted
      e.target.value = apiBase || DEFAULT_API;
      hint.textContent = "Permission to contact that server was not granted.";
      hint.hidden = false;
      return;
    }
    await chrome.storage.local.set({ apiBase: u.origin === new URL(DEFAULT_API).origin ? "" : u.origin });
    location.reload();
  });
})();

// paste-to-scan
let t = null;
async function scanNow() {
  const text = $("#txt").value.trim();
  if (!text) return ($("#out").innerHTML = "");
  $("#out").innerHTML = '<p class="ss-muted">Checking…</p>';
  chrome.runtime.sendMessage({ type: "scan", text }, res => {
    $("#out").innerHTML = res?.result ? render(res.result) : `<p>${esc(res?.error || "Server offline")}</p>`;
  });
}
$("#txt").addEventListener("paste", () => setTimeout(scanNow, 30));
$("#txt").addEventListener("input", () => { clearTimeout(t); t = setTimeout(scanNow, 700); });

// settings
chrome.storage.local.get(DEFAULTS, s => {
  $("#enabled").checked = s.enabled;
  $("#newcomerMode").checked = s.newcomerMode;
  $("#banks").innerHTML = Object.entries(SS_BANKS).map(([k, b]) =>
    `<label><input type="checkbox" class="bank" value="${k}" ${s.myBanks.includes(k) ? "checked" : ""}>${esc(b.name)}</label>`).join("");
  const save = () => chrome.storage.local.set({
    enabled: $("#enabled").checked, newcomerMode: $("#newcomerMode").checked,
    myBanks: [...document.querySelectorAll("#banks input:checked")].map(i => i.value),
  });
  document.querySelectorAll("input[type=checkbox]:not(#notifyInsecure):not(#shareReports)").forEach(i => i.onchange = save);
});

// On-screen notifications: an optional permission, requested only when the user switches it on.
const PERM = { permissions: ["notifications"] };
chrome.storage.local.get({ notifyInsecure: true }, ({ notifyInsecure }) => {
  chrome.permissions.contains(PERM, granted => { $("#notifyInsecure").checked = granted && notifyInsecure; });
});
$("#notifyInsecure").onchange = e => {
  const hint = $("#notifyHint");
  if (!e.target.checked) {
    chrome.storage.local.set({ notifyInsecure: false });
    hint.hidden = true;
    return;
  }
  // Save first: the popup may close while the browser's permission prompt is open.
  // Harmless if denied - the background worker checks the real permission before notifying.
  chrome.storage.local.set({ notifyInsecure: true });
  chrome.permissions.request(PERM, granted => {  // called straight from the click = user gesture
    e.target.checked = granted;
    chrome.storage.local.set({ notifyInsecure: granted });
    hint.hidden = granted;
    hint.textContent = "Notifications weren't allowed. Switch it on again to be asked once more.";
  });
};
