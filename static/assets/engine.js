// On-device message analysis: the same scoring as analyze() in server/shieldlib/engine.py, so a text, link or
// e-mail address can be checked without sending it anywhere. Rules and word lists come from heuristics-data.js
// (generated from the Python code); tests/parity_vectors.json checks both give identical answers.
//
//   analyzeText(text, lookups?) -> { score, level, text:{score,findings}, urls:[...], emails:[...], advice:[...] }
//
// lookups (all optional, async) bring in the block lists: { listUrl(url) -> {category, how}|null,
//   listEmailDomain(domain) -> { disposable: bool, listed: {category, how}|null } }
import D from "./heuristics-data.js";
import { analyzeUrl, brandTokens, isOfficial, levelFor, registeredDomain } from "./heuristics.js";

const TEXT_RULES = D.textRules.map(([cat, weight, message, pattern]) => ({ cat, weight, message, rx: new RegExp(pattern, "i") }));
const RISKY_TLDS = new Set(D.riskyTlds);
const SHORTENERS = new Set(D.shorteners);
const FREE_MAIL = new Set(D.freeMail);

const PRESSURE = ["urgency", "threat"];
const DATA_REQUEST = ["credentials", "payment", "remote_access", "card_request", "etransfer", "gov_impersonation", "new_account"];
const IMPERSONATION_CONTEXT = ["urgency", "threat", "credentials", "card_request", "etransfer", "new_account", "payment"];
const CLICK_RAISERS = ["credentials", "payment", "threat", "urgency"];
const intersects = (set, list) => list.some(x => set.has(x));

// Python's round() rounds halves to the nearest even number; Math.round() rounds them up. Match Python.
function pyRound(x) {
  const r = Math.round(x);
  return Math.abs(x % 1) === 0.5 && r % 2 !== 0 ? r - 1 : r;
}

export function extract(text) {
  const urls = [], seen = new Set();
  for (const m of text.matchAll(new RegExp(D.urlRe, "gi"))) {
    let u = m[0].replace(/[.,;:!?)\]}>'"]+$/, "");
    if (u.split("/")[0].includes("@") && !u.includes("://")) continue;  // an e-mail address, handled separately
    u = u.replace(/^hxxp/i, "http").split("[.]").join(".");
    if (!seen.has(u.toLowerCase())) { seen.add(u.toLowerCase()); urls.push(u); }
  }
  const emails = [...new Set([...text.matchAll(new RegExp(D.emailRe, "g"))].map(m => m[0].toLowerCase()))].sort();
  const emailDomains = new Set(emails.map(e => e.split("@")[1]));
  return { urls: urls.filter(u => !emailDomains.has(u.toLowerCase())), emails };
}

export function analyzeEmail(addr, info = {}) {
  const findings = [];
  const add = (weight, message, severity = "warn", extra = {}) => findings.push({ weight, message, severity, ...extra });
  const at = addr.indexOf("@");
  const local = addr.slice(0, at), domain = addr.slice(at + 1);
  if (info.listed) add(80, `Sender domain is a known ${info.listed.category} threat (${info.listed.how})`, "danger");
  if (info.disposable) add(18, "Disposable / throwaway e-mail provider");
  const brands = { ...brandTokens(local), ...brandTokens(domain) };
  for (const [brand, kind] of Object.entries(brands)) {
    if (isOfficial(domain, brand)) continue;
    if (FREE_MAIL.has(domain)) add(22, `Claims to be '${brand}' but uses free webmail (${domain})`, "danger");
    else if (kind === "lookalike") add(30, `Look-alike of '${brand}' in the address`, "danger", { brand, lookalike: true });
    else add(20, `Mentions '${brand}' but domain is not official`, "danger", { brand });
  }
  const tld = domain.slice(domain.lastIndexOf(".") + 1);
  if (RISKY_TLDS.has(tld)) add(8, `Top-level domain '.${tld}' is heavily abused`);
  if (/\d{4,}/.test(local)) add(4, "Address contains a long random-looking number");
  const score = Math.min(100, findings.reduce((s, f) => s + f.weight, 0));
  return { email: addr, score, level: levelFor(score), findings };
}

export function adviceFor(level, matched, urls) {
  const tips = [];
  if (level === "critical" || level === "high") {
    tips.push("Do NOT click any link, open attachments, reply, or call numbers in this message.");
    tips.push("Delete it after reporting. If you already clicked or entered data, see 'If you were hit' in the guide.");
  } else if (level === "medium") {
    tips.push("Treat with caution: contact the organization through its official app or website you type yourself.");
  } else {
    tips.push("No strong scam signals found - but a clean result is not a guarantee. Stay alert.");
  }
  if (matched.has("credentials")) tips.push("Legitimate companies never ask for passwords, PINs or one-time codes by message.");
  if (matched.has("payment")) tips.push("Gift cards, crypto and wire transfers are the scammer's favourite - they can't be reversed.");
  if (matched.has("remote_access")) tips.push("Never install AnyDesk / TeamViewer for someone who contacted you first.");
  if (matched.has("family_emergency")) tips.push("Call your family member on their OLD, known number before sending anything.");
  if (urls.some(u => SHORTENERS.has(u.host))) tips.push("Expand short links with a preview service (e.g. unshorten.it) before trusting them.");
  return tips;
}

export async function analyzeText(text, lookups = {}) {
  const { listUrl = async () => null, listEmailDomain = async () => ({ disposable: false, listed: null }) } = lookups;
  const { urls, emails } = extract(text);
  const textFindings = [], matched = new Set();
  for (const { cat, weight, message, rx } of TEXT_RULES) {
    const m = rx.exec(text);
    if (m) { matched.add(cat); textFindings.push({ weight, message, severity: "warn", evidence: m[0] }); }
  }
  // Combination bonus: pressure + a request for data / money is the classic scam shape.
  if (intersects(matched, PRESSURE) && intersects(matched, DATA_REQUEST)) {
    textFindings.push({ weight: 15, severity: "danger", message: "Pressure combined with a request for data or money (classic scam pattern)" });
  }

  const urlResults = await Promise.all(urls.map(async u => analyzeUrl(u, await listUrl(u))));
  const emailResults = await Promise.all(emails.map(async e => analyzeEmail(e, await listEmailDomain(e.split("@")[1]))));

  // Bank-phishing shape: a link or sender imitating a brand, in a message that pressures you and names that brand.
  let impersonated = null;
  if (intersects(matched, IMPERSONATION_CONTEXT)) {
    outer: for (const r of [...urlResults, ...emailResults]) {
      for (const f of r.findings) {
        if (f.brand && (f.lookalike || new RegExp("\\b" + f.brand.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b", "i").test(text))) {
          impersonated = f.brand;
          break outer;
        }
      }
    }
  }
  if (impersonated) {
    textFindings.push({ weight: 20, severity: "danger",
      message: `A link or sender imitates '${impersonated}' while the message pushes you to act (typical bank-phishing pattern)` });
  }

  let textScore = Math.min(100, textFindings.reduce((s, f) => s + f.weight, 0));
  if (urls.length && intersects(matched, CLICK_RAISERS)) textScore = Math.min(100, textScore + 8);  // a link to click raises the stakes
  const worst = Math.max(0, ...urlResults.map(r => r.score), ...emailResults.map(r => r.score));
  const [hi, lo] = [textScore, worst].sort((a, b) => b - a);
  let overall = Math.min(100, pyRound(hi + 0.35 * lo));
  if (impersonated) overall = Math.max(overall, 70);  // never leave this pattern at "medium"
  const level = levelFor(overall);
  return { score: overall, level, text: { score: textScore, findings: textFindings }, urls: urlResults, emails: emailResults,
           advice: adviceFor(level, matched, urlResults) };
}
