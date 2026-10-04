/**
 * SAYNO report relay (Google Apps Script).
 *
 * Runs as the SAYNO team Google account, so every report is emailed FROM that account. The website posts the
 * structured fields of the "Report a scam" form here; this script validates them, builds the email itself (it never
 * trusts text built by the browser) and sends it. It never sees the reporter's name, email address or IP address.
 *
 * Setup: see docs/REPORT_BACKEND.md. Deploy as a Web app: Execute as "Me", Who has access "Anyone".
 */

var CONFIG = {
  // Always receives a copy of every report (this is also the account the script runs as).
  TEAM_ADDRESS: "sayoshield@gmail.com",
  // Anti-phishing organisations that take reports by email. Only reports that contain a link or are scam emails go here.
  EXTERNAL_RECIPIENTS: ["reportphishing@apwg.org"],
  SITE: "https://lostmino13200845.github.io/sayno/report-scam/",
  MAX_PER_HOUR: 40,   // global ceiling, so a flood cannot use up the Gmail daily quota
  DEDUPE_HOURS: 6     // the same link or number is only sent once in this time (Apps Script cache holds at most 6 hours)
};

var TYPES = {
  website: "Scam website or link",
  text: "Scam text message (SMS)",
  email: "Scam email",
  call: "Scam phone call",
  social: "Fake social media, marketplace or ad"
};
var ALLOWED_FIELDS = ["url", "sender", "subject", "message", "who", "via", "notes"];
var MAX = { url: 600, sender: 200, subject: 200, message: 2000, who: 80, via: 80, notes: 2000 };

function clean(s, max) {
  // plain text only: drop control characters (this also stops header injection), trim, cap the length
  return String(s == null ? "" : s).replace(/\r\n/g, "\n").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "").trim().slice(0, max);
}

/** Validates the posted object and builds the email. Pure function, so it can be tested without Google services. */
function buildReport(data, now) {
  if (!data || typeof data !== "object" || !TYPES[data.type]) return { ok: false, error: "Unknown report type." };
  var f = {}, i;
  for (i = 0; i < ALLOWED_FIELDS.length; i++) {
    var k = ALLOWED_FIELDS[i];
    f[k] = clean(data.fields && data.fields[k], MAX[k]);
  }
  if (f.url && !/^https?:\/\/[^\s\/$.?#][^\s]*$/i.test(f.url)) return { ok: false, error: "That link does not look valid." };
  if (data.type === "email" && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(f.sender)) return { ok: false, error: "That email address does not look valid." };
  if ((data.type === "website" || data.type === "social") && !f.url) return { ok: false, error: "A link is needed." };
  if ((data.type === "text" || data.type === "call") && !f.sender) return { ok: false, error: "A phone number is needed." };
  if ((data.type === "text" || data.type === "email") && !f.message) return { ok: false, error: "The message text is needed." };

  var asked = [];
  var rawAsked = Object.prototype.toString.call(data.asked) === "[object Array]" ? data.asked.slice(0, 12) : [];
  for (i = 0; i < rawAsked.length; i++) { var a = clean(rawAsked[i], 80); if (a) asked.push(a); }

  var key = f.url ? f.url.replace(/^https?:\/\//i, "").split(/[\/?#]/)[0] : f.sender;
  var subject = ("[SAYNO report] " + TYPES[data.type] + (key ? ": " + key : "")).replace(/[\r\n]+/g, " ").slice(0, 120);

  var L = [];
  L.push("Scam report from the SAYNO team, sent on behalf of a member of the public.");
  L.push("The reporter's name and email address are not included.", "");
  L.push("Type: " + TYPES[data.type]);
  if (f.who && f.who !== "Not sure") L.push("Pretending to be: " + f.who);
  if (f.via) L.push("Received via: " + f.via);
  L.push("Reported: " + now.toISOString().slice(0, 10) + " (UTC)", "");
  var ind = [];
  if (f.url) ind.push("Link: " + f.url);
  if (f.sender) ind.push((data.type === "email" ? "Sender address: " : "Phone number: ") + f.sender);
  if (f.subject) ind.push("Subject: " + f.subject);
  if (ind.length) { L.push("Details to block or investigate:"); for (i = 0; i < ind.length; i++) L.push("  " + ind[i]); L.push(""); }
  if (asked.length) { L.push("What the scammer asked for:"); for (i = 0; i < asked.length; i++) L.push("  - " + asked[i]); L.push(""); }
  if (f.message) { L.push(data.type === "call" ? "What they said:" : "Message text:"); var m = f.message.split("\n"); for (i = 0; i < m.length; i++) L.push("  " + m[i]); L.push(""); }
  if (f.notes) { L.push("Notes:"); var n = f.notes.split("\n"); for (i = 0; i < n.length; i++) L.push("  " + n[i]); L.push(""); }
  L.push("Sent through " + CONFIG.SITE);

  // Links and scam emails go to the anti-phishing organisations too; phone numbers and texts without a link stay with the team.
  var external = (f.url || data.type === "email") ? CONFIG.EXTERNAL_RECIPIENTS.slice() : [];
  return { ok: true, subject: subject, body: L.join("\n"), to: [CONFIG.TEAM_ADDRESS].concat(external), dedupeKey: data.type + "|" + (f.url || f.sender).toLowerCase() };
}

function reply(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}

function doGet() { return reply({ ok: true, service: "SAYNO report relay" }); }

function doPost(e) {
  try {
    var raw = e && e.postData && e.postData.contents;
    if (!raw || raw.length > 12000) return reply({ ok: false, error: "That report is too large." });
    var data = JSON.parse(raw);
    if (data && data.trap) return reply({ ok: true });              // bots fill the hidden field: pretend it worked

    var r = buildReport(data, new Date());
    if (!r.ok) return reply(r);

    var cache = CacheService.getScriptCache(), lock = LockService.getScriptLock();
    lock.waitLock(10000);
    try {
      var hourKey = "h" + Utilities.formatDate(new Date(), "UTC", "yyyyMMddHH");
      var used = Number(cache.get(hourKey) || 0);
      if (used >= CONFIG.MAX_PER_HOUR) return reply({ ok: false, error: "Too many reports right now. Please try again later." });
      var dk = "d" + Utilities.base64EncodeWebSafe(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, r.dedupeKey)).slice(0, 40);
      if (cache.get(dk)) return reply({ ok: true, duplicate: true });  // already reported recently
      cache.put(hourKey, String(used + 1), 3700);
      cache.put(dk, "1", Math.min(21600, CONFIG.DEDUPE_HOURS * 3600));
    } finally { lock.releaseLock(); }

    MailApp.sendEmail({ to: r.to.join(","), subject: r.subject, body: r.body, name: "SAYNO Reports" });
    return reply({ ok: true });
  } catch (err) {
    return reply({ ok: false, error: "The report could not be sent." });
  }
}
