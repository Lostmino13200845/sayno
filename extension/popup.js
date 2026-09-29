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
chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  chrome.runtime.sendMessage({ type: "getVerdict", tabId: tab.id }, v => {
    $("#site").innerHTML = v ? `<div class="pp-host">${esc(new URL(tab.url).host)}</div>${render(v)}`
      : /^https?:/.test(tab.url || "") ? '<span class="ss-level">not rated</span> <span class="ss-muted">Local page, or the Scam Shield server is offline.</span>' : "Not a web page.";
  });
});

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
  document.querySelectorAll("input[type=checkbox]:not(#notifyInsecure)").forEach(i => i.onchange = save);
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
