// SAYNO background worker. Every page the user opens is rated ON THE DEVICE: link heuristics (heuristics.js)
// plus a hash-prefix check against the global block lists (lookup.js). Pages are never sent to a server; the
// server is asked only when a 4-byte hash prefix matches locally, and for text the user explicitly checks
// (right-click or the paste box).
import { DEFAULT_API } from "./config.js";
import { checkUrl as listCheck, syncPrefixes } from "./lookup.js";
import { analyzeUrl, levelFor } from "./heuristics.js";

async function apiBase() {
  const { apiBase } = await chrome.storage.local.get("apiBase");
  return (apiBase || DEFAULT_API).replace(/\/+$/, "");
}
async function api(path) { return (await apiBase()) + path; }

// Keep the local block-list index fresh (an unchanged list costs one tiny 304 response).
async function syncLists() {
  try {
    const r = await syncPrefixes(await apiBase());
    if (r.updated) {  // a new list may cover pages that are already open: check them again
      cache.clear();
      for (const t of await chrome.tabs.query({})) if (t.url && /^https?:/.test(t.url)) assess(t.id, t.url);
    }
  } catch { /* offline: keep the old list */ }
}
chrome.alarms.create("sync-lists", { periodInMinutes: 30 });
chrome.alarms.onAlarm.addListener(a => { if (a.name === "sync-lists") syncLists(); });
syncLists();
const cache = new Map();          // host+path -> {result, at}
const TTL = 10 * 60 * 1000;
const tabVerdicts = new Map();    // tabId -> result (also mirrored in chrome.storage.session)
const saveVerdict = (tabId, result) => {
  if (result) tabVerdicts.set(tabId, result); else tabVerdicts.delete(tabId);
  const key = "v" + tabId;
  (result ? chrome.storage.session.set({ [key]: result }) : chrome.storage.session.remove(key)).catch(() => {});
};
async function loadVerdict(tabId) {
  if (tabVerdicts.has(tabId)) return tabVerdicts.get(tabId);
  const o = await chrome.storage.session.get("v" + tabId).catch(() => ({}));
  return o["v" + tabId] || null;
}

const BADGE = {
  safe: ["", "#1a8f4c"], low: ["", "#6b9e1f"], medium: ["!", "#c98a00"],
  high: ["!!", "#d9541e"], critical: ["✖", "#c11b2e"], offline: ["off", "#777"],
};

async function scan(text, online = true) {
  const r = await fetch(await api("/api/scan"), {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text, online }),
  });
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
}

// A refused connection surfaces as "Failed to fetch": say what it means and what to do about it.
function friendlyError(e) {
  return e instanceof TypeError ? "SAYNO server is not running. Start it (start.bat on Windows, ./start.sh on Mac/Linux), then try again."
    : "SAYNO server problem (" + e.message + "). Try again.";
}

async function checkUrl(url) {
  const u = new URL(url);
  const key = u.host + u.pathname;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < TTL) return hit.result;
  const { ready, listed, unresolved } = await listCheck(url, await apiBase());  // hashes locally; server only on a prefix match
  if (!ready) syncLists();                                          // first run / list not downloaded yet
  const r = analyzeUrl(u.origin + u.pathname, listed);              // no query string or fragment: they can hold tokens
  if (unresolved) {  // matches a block-list fingerprint but the server could not confirm: warn, do not guess "safe"
    r.findings.push({ weight: 36, severity: "warn",
      message: "Matches a block-list fingerprint, but SAYNO could not reach its server to confirm" });
    r.score = Math.min(100, r.findings.reduce((n, f) => n + f.weight, 0));
    r.level = levelFor(r.score);
  }
  const result = { score: r.score, level: r.level, text: { score: 0, findings: [] }, urls: [r], emails: [],
                   advice: [], local: true, listsReady: ready, unresolved: !!unresolved, checkedAt: Date.now() };
  if (!unresolved) cache.set(key, { result, at: Date.now() });      // an unconfirmed match is retried next time
  return result;
}

function setBadge(tabId, level, score) {
  const [text, color] = BADGE[level] || BADGE.safe;
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
  chrome.action.setTitle({ tabId, title: level === "offline" ? "SAYNO: server offline"
    : `SAYNO: ${level} (${score}/100)` });
}

// Intranet / local development addresses are not rated (they can't be on public blocklists).
const PRIVATE_HOST = /^(localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|\[::1\])$/;

async function assess(tabId, url) {
  if (!/^https?:/.test(url)) return;
  if (PRIVATE_HOST.test(new URL(url).hostname)) {
    saveVerdict(tabId, null);
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }
  let result = null;
  try {
    result = await checkUrl(url);
    saveVerdict(tabId, result);
    setBadge(tabId, result.level, result.score);
    chrome.tabs.sendMessage(tabId, { type: "verdict", result }).catch(() => {});
  } catch {
    saveVerdict(tabId, null);
    setBadge(tabId, "offline", 0);
  }
  checkSecurity(tabId, url, result);  // the https check works even when the server is offline
}

// ================= on-screen security notifications =================
// Notifications are an OPTIONAL permission: nothing is shown until the user clicks
// "Allow notifications" (welcome page or popup) and the browser grants it.
const COOLDOWN = 30 * 60 * 1000;          // one notification per site + reason per 30 min
const lastNotified = new Map();           // "host|reason" -> time
const notifTabs = new Map();              // notification id -> tabId

async function notificationsAllowed() {
  const { notifyInsecure = true } = await chrome.storage.local.get("notifyInsecure");
  return notifyInsecure && chrome.permissions.contains({ permissions: ["notifications"] });
}

async function notify(tabId, host, reason, title, message, urgent = false) {
  if (!(await notificationsAllowed())) return;
  const key = `${host}|${reason}`;
  if (Date.now() - (lastNotified.get(key) || 0) < COOLDOWN) return;
  lastNotified.set(key, Date.now());
  attachNotificationListeners();
  const id = `ss-${reason}-${tabId}-${Date.now()}`;
  notifTabs.set(id, tabId);
  chrome.notifications.create(id, {
    type: "basic", iconUrl: "icons/128.png", title: "🛡️ " + title, message,
    contextMessage: host, priority: urgent ? 2 : 1, requireInteraction: urgent,
    buttons: [{ title: "Leave this page" }, { title: "Keep browsing" }],
  });
}

function checkSecurity(tabId, url, result) {
  const { protocol, hostname: host } = new URL(url);
  const risky = result && ["medium", "high", "critical"].includes(result.level);
  if (risky) {
    const why = [...result.urls.flatMap(u => u.findings), ...result.text.findings].find(f => f.weight)?.message || "";
    const insecure = protocol === "http:" ? " It also isn't encrypted." : "";
    notify(tabId, host, "risky",
      result.level === "critical" ? "Known scam site" : "This site looks risky",
      `Rated ${result.level.toUpperCase()} (${result.score}/100). ${why}.${insecure} Don't enter passwords or card details.`,
      result.level !== "medium");
  } else if (protocol === "http:") {
    notify(tabId, host, "http", "This page is not secure",
      "The connection isn't encrypted (http). Anyone on the network could read what you type. Don't enter passwords, card numbers or personal details here.");
  }
}

// chrome.notifications only exists once the permission is granted, so listeners are attached
// at start-up (if already granted) or right before the first notification is shown.
let listenersOn = false;
function attachNotificationListeners() {
  if (listenersOn || !chrome.notifications) return;
  listenersOn = true;
  chrome.notifications.onClicked.addListener(id => {
    const tabId = notifTabs.get(id);
    if (tabId != null) chrome.tabs.update(tabId, { active: true }).then(t => chrome.windows.update(t.windowId, { focused: true })).catch(() => {});
    chrome.notifications.clear(id);
  });
  chrome.notifications.onButtonClicked.addListener((id, button) => {
    const tabId = notifTabs.get(id);
    if (button === 0 && tabId != null) chrome.tabs.goBack(tabId).catch(() => chrome.tabs.update(tabId, { url: "about:blank" }));
    chrome.notifications.clear(id);
    notifTabs.delete(id);
  });
}
attachNotificationListeners();

// Check on page load AND on in-page navigation (single-page apps change the URL without a reload).
const lastAssessed = new Map();   // tabId -> "url@time", so one navigation is not checked twice
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (!tab.url || !(info.status === "loading" || info.url)) return;
  const prev = lastAssessed.get(tabId);
  if (prev && prev.url === tab.url && Date.now() - prev.at < 3000) return;
  lastAssessed.set(tabId, { url: tab.url, at: Date.now() });
  assess(tabId, tab.url);
});
chrome.tabs.onRemoved.addListener(tabId => { saveVerdict(tabId, null); lastAssessed.delete(tabId); });

// ---- right-click: scan selected text / a link
chrome.runtime.onInstalled.addListener(details => {
  chrome.contextMenus.create({ id: "ss-text", title: "Check this text with SAYNO", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "ss-link", title: "Check this link with SAYNO", contexts: ["link"] });
  if (details.reason === "install") chrome.tabs.create({ url: chrome.runtime.getURL("welcome.html") });
});
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const text = info.menuItemId === "ss-link" ? info.linkUrl : info.selectionText;
  try {
    const result = await scan(text);
    chrome.tabs.sendMessage(tab.id, { type: "scanResult", result, text });
  } catch {
    chrome.tabs.sendMessage(tab.id, { type: "scanResult", error: "SAYNO server is not running. Start it (start.bat on Windows, ./start.sh on Mac/Linux), then try again." });
  }
});

// ---- messages from content script / popup
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg.type === "getVerdict") {
    loadVerdict(msg.tabId ?? sender.tab?.id).then(reply);
    return true;
  } else if (msg.type === "scan") {
    scan(msg.text).then(r => reply({ result: r }), e => reply({ error: friendlyError(e) }));
    return true;
  } else if (msg.type === "status") {
    api("/api/status").then(u => fetch(u)).then(r => r.json()).then(reply, () => reply(null));
    return true;
  } else if (msg.type === "testNotification") {
    chrome.permissions.contains({ permissions: ["notifications"] }).then(ok => {
      if (!ok || !chrome.notifications) return reply(false);
      attachNotificationListeners();
      chrome.notifications.create("ss-test-" + Date.now(), {
        type: "basic", iconUrl: "icons/128.png", title: "🛡️ SAYNO is watching",
        message: "This is how a warning looks. You'll see one when a page isn't secure or looks like a scam.",
        priority: 1,
      }, () => reply(!chrome.runtime.lastError));
    });
    return true;
  } else if (msg.type === "insecureField" && sender.tab) {
    notify(sender.tab.id, new URL(sender.tab.url).hostname, "field", "Don't type that here",
      `You're about to enter your ${msg.what} on a page that isn't secure (no https). It could be read by others on the network.`, true);
  } else if (msg.type === "cardGuard" && sender.tab) {
    // The content script blocked a card form. Only if the user switched on "Help protect others" in the popup,
    // report the page address (no query string or fragment, never card data) so it can be logged and reported.
    chrome.storage.local.get({ shareReports: false }, ({ shareReports }) => {
      if (!shareReports) return;
      const pu = new URL(sender.tab.url);
      scan(`${msg.reason}\n${pu.origin + pu.pathname}`, false).catch(() => {});
    });
  }
});
