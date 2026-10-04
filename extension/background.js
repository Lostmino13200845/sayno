// SAYNO background worker. Everything is rated ON THE DEVICE: pages with link heuristics (heuristics.js), text
// the user checks with the message rules (engine.js), both together with a hash-prefix check against the
// global block lists (lookup.js). Nothing the user browses or selects is ever sent anywhere. The only network
// traffic is downloading the block-list files, and a small shard file when a 4-byte prefix matches locally.
import { DEFAULT_API } from "./config.js";
import { checkUrl as listCheck, checkEmailDomain, fetchMeta, syncPrefixes } from "./lookup.js";
import { analyzeUrl, levelFor } from "./heuristics.js";
import { analyzeText } from "./engine.js";

// Where the block-list files come from (config.js default; changeable under "Advanced" in the popup).
async function apiBase() {
  const { apiBase } = await chrome.storage.local.get("apiBase");
  return (apiBase || DEFAULT_API).replace(/\/+$/, "");
}

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
// Changing the block-list source (popup, Advanced) downloads the new lists straight away.
chrome.storage.onChanged.addListener((changes, area) => { if (area === "local" && changes.apiBase) syncLists(); });
chrome.alarms.create("sync-lists", { periodInMinutes: 15 });
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

// Check a text, link or e-mail address the user chose to check. Done locally, so it also works offline;
// block-list lookups are used when the lists are downloaded, and quietly skipped when they are not.
async function scan(text) {
  const base = await apiBase();
  return analyzeText(text, {
    listUrl: async u => (await listCheck(u, base)).listed,
    listEmailDomain: async d => { const r = await checkEmailDomain(d, base); return { disposable: r.disposable, listed: r.listed }; },
  });
}

async function checkUrl(url) {
  const u = new URL(url);
  const key = u.host + u.pathname;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < TTL) return hit.result;
  const { ready, listed, unresolved } = await listCheck(url, await apiBase());  // hashes locally; a shard is fetched only on a prefix match
  if (!ready) syncLists();                                          // first run / list not downloaded yet
  const r = analyzeUrl(u.origin + u.pathname, listed);              // no query string or fragment: they can hold tokens
  if (unresolved) {  // matches a block-list fingerprint but the server could not confirm: warn, do not guess "safe"
    r.findings.push({ weight: 36, severity: "warn",
      message: "Matches a block-list fingerprint, but SAYNO could not download the details to confirm" });
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
  chrome.action.setTitle({ tabId, title: level === "offline" ? "SAYNO: could not check this page"
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
  if (info.status === "complete" && tab.url && /^https?:/.test(tab.url)) {
    // Browsers reset a tab's badge when a navigation commits. A local check can finish before that, so put the
    // rating back once the page has loaded (only if it is the rating for this very page).
    loadVerdict(tabId).then(v => {
      const u = new URL(tab.url);
      if (v && v.urls?.[0]?.url === u.origin + u.pathname) setBadge(tabId, v.level, v.score);
    });
  }
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
  } catch (e) {
    chrome.tabs.sendMessage(tab.id, { type: "scanResult", error: "SAYNO could not check that text (" + (e && e.message || e) + ")." });
  }
});

// ---- messages from content script / popup
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg.type === "getVerdict") {
    loadVerdict(msg.tabId ?? sender.tab?.id).then(reply);
    return true;
  } else if (msg.type === "scan") {
    scan(msg.text).then(r => reply({ result: r }), e => reply({ error: "SAYNO could not check that (" + (e && e.message || e) + ")." }));
    return true;
  } else if (msg.type === "status") {
    // Block-list size and health. Offline: the numbers saved last time, flagged as stale.
    apiBase().then(fetchMeta).then(async m => {
      if (m) { chrome.storage.local.set({ lastMeta: m }); return reply({ ...m, online: true }); }
      const { lastMeta } = await chrome.storage.local.get("lastMeta");
      reply(lastMeta ? { ...lastMeta, online: false } : null);
    });
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
  }
});
