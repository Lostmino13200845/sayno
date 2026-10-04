// On-device link analysis: the same rules as analyze_url() in server/shieldlib/engine.py, so a page can be
// rated without sending it anywhere. The word and brand lists come from heuristics-data.js (generated from
// the server code); tests/parity_vectors.json checks that this file and the Python agree on every example.
import D from "./heuristics-data.js";

const SHORTENERS = new Set(D.shorteners);
const RISKY_TLDS = new Set(D.riskyTlds);
const TWO_LEVEL = new Set(D.twoLevelSuffixes);
const SUSPICIOUS = new RegExp(D.suspiciousWords, "i");
const IP_TRICK = new RegExp("^(?:" + D.ipTrick + ")$", "i");
const IPV4 = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;  // strict, like Python's ipaddress
const EXEC_RE = /\.(exe|scr|apk|msi|bat|cmd|ps1|sh|dll|js|vbs|jar|iso|img|lnk|hta)(\?|$)/i;
const BRAND_NAMES = Object.keys(D.brands);
const OFFICIAL_DOMAINS = [...new Set(Object.values(D.brands).flat())].sort((a, b) => b.length - a.length || (a < b ? -1 : a > b ? 1 : 0));

export function levelFor(score) {
  for (const [threshold, name] of D.levels) if (score >= threshold) return name;
  return "safe";
}

export function registeredDomain(host) {
  const labels = host.toLowerCase().replace(/^\.+|\.+$/g, "").split(".");
  if (labels.length >= 3 && TWO_LEVEL.has(labels.slice(-2).join("."))) return labels.slice(-3).join(".");
  return labels.slice(-2).join(".");
}

// A real brand address used inside someone else's domain (rbcroyalbank.com.verify-login.net, paypal.com-login.net).
// A bare two-letter ending (google.com.au) is a country site, so it is skipped. Same rule as embedded_official() in engine.py.
export function embeddedOfficial(host) {
  for (const d of OFFICIAL_DOMAINS) {
    const re = new RegExp("(?:^|\\.)" + d.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(?=$|[.-])", "g");
    let m;
    while ((m = re.exec(host)) !== null) {
      if (/^\.[a-z]{2}$/.test(host.slice(m.index + m[0].length))) continue;
      return d;
    }
  }
  return "";
}

export function isOfficial(host, brand) {
  const reg = registeredDomain(host);
  return D.brands[brand].some(d => reg === d || host === d || host.endsWith("." + d));
}

const fold = t => [...t].map(c => D.homoglyphs[c] ?? c).join("").split("rn").join("m").split("vv").join("w");

export function brandTokens(text) {
  const raw = text.toLowerCase().split(/[.\-_+]/);
  // A capital "I" is easily mistaken for a lowercase "l" (paypaI.com), so fold it before lowercasing.
  const folded = text.replace(/I/g, "l").toLowerCase().split(/[.\-_+]/).map(fold);
  const hit = (tokens, brand) => tokens.includes(brand)
    || (brand.length >= 5 && tokens.some(t => t.startsWith(brand) && t.length - brand.length <= 8));
  const found = {};
  for (const brand of BRAND_NAMES) {
    if (hit(raw, brand)) found[brand] = "exact";
    else if (hit(folded, brand)) found[brand] = "lookalike";
  }
  return found;
}

// Python's urlsplit() semantics, so "http://3232235777/" keeps its disguised IP (the URL class would rewrite it).
function split(full) {
  const rest = full.replace(/^[a-z]+:\/\//i, "");
  const cut = rest.search(/[\/?#]/);
  const netloc = cut < 0 ? rest : rest.slice(0, cut);
  const tail = cut < 0 ? "" : rest.slice(cut);
  const path = tail.split("#")[0].split("?")[0];
  const hostport = netloc.slice(netloc.lastIndexOf("@") + 1);
  let host, portText = "";
  if (hostport.startsWith("[")) {
    const end = hostport.indexOf("]");
    if (end < 0) throw new Error("bad ipv6");
    host = hostport.slice(1, end);
    portText = hostport.slice(end + 1).replace(/^:/, "");
  } else {
    const i = hostport.lastIndexOf(":");
    host = i < 0 ? hostport : hostport.slice(0, i);
    portText = i < 0 ? "" : hostport.slice(i + 1);
  }
  let port = null;
  if (portText !== "") {
    if (!/^\d+$/.test(portText) || Number(portText) > 65535) throw new Error("bad port");
    port = Number(portText);
  }
  return { netloc, path, hostport, host: host.toLowerCase(), rawHost: hostport.replace(/:\d*$/, ""), port };
}

/** listed: optional {category, how} from the block-list lookup (lookup.js). */
export function analyzeUrl(url, listed = null) {
  const findings = [];
  const add = (weight, message, severity = "warn", extra = {}) => findings.push({ weight, message, severity, ...extra });
  const full = /^[a-z]+:\/\//i.test(url) ? url : "http://" + url;
  let p;
  try { p = split(full); } catch {
    add(20, "Malformed URL", "danger");
    return { url, host: "", score: 20, level: levelFor(20), findings };
  }
  const { host, port, path } = p;

  if (listed) add(95, `Known ${listed.category} threat in the global threat database (${listed.how})`, "danger");

  if (IPV4.test(host) || host.includes(":")) {
    add(22, "Uses a raw IP address instead of a domain name", "danger");
  } else if (IP_TRICK.test(host)) {
    add(30, "Disguised IP address (number or hex form) instead of a domain name", "danger");
  }
  if (host.includes("xn--") || [...host].some(ch => ch.codePointAt(0) > 127)) {
    add(22, "Punycode / internationalized domain (possible look-alike characters)", "danger");
  }
  if (p.netloc.includes("@")) add(22, "Contains '@' before the host - the real destination is hidden", "danger");
  if (SHORTENERS.has(host) || SHORTENERS.has(registeredDomain(host))) add(10, "Link shortener hides the real destination");
  const tld = host.includes(".") ? host.slice(host.lastIndexOf(".") + 1) : "";
  if (RISKY_TLDS.has(tld)) add(10, `Top-level domain '.${tld}' is heavily abused by scammers`);
  if (full.toLowerCase().startsWith("http://")) add(6, "Not encrypted (http, not https)");
  if (host.split(".").length - 1 >= 4) add(8, "Unusually many sub-domains");
  if (host.split("-").length - 1 >= 3) add(6, "Many hyphens in the domain name");
  if (port && port !== 80 && port !== 443) add(8, `Non-standard port ${port}`);
  if (url.length > 120) add(4, "Very long URL");
  const official = BRAND_NAMES.some(b => isOfficial(host, b));
  if (!official) {
    if (SUSPICIOUS.test(host)) add(8, "Domain contains words like login / verify / secure / account");
    else if (SUSPICIOUS.test(path)) add(4, "Path contains words like login / verify / account");
  }
  if (EXEC_RE.test(path)) add(25, "Link points directly to an executable / installer file", "danger");

  const onFreeHosting = D.freeHosting.some(d => host === d || host.endsWith("." + d));
  for (const [brand, kind] of Object.entries(brandTokens(p.rawHost))) {
    if (isOfficial(host, brand)) continue;
    if (kind === "lookalike") add(36, `Look-alike of '${brand}' (character substitution) on a non-${brand} domain`, "danger", { brand, lookalike: true });
    else add(24, `Mentions '${brand}' but is not an official ${brand} domain`, "danger", { brand });
    if (onFreeHosting) add(14, `Uses the name '${brand}' on a free / shared hosting domain, not the real company`, "danger");
  }
  if (!official) {
    const real = embeddedOfficial(host);
    if (real) add(55, `Contains the real address '${real}' inside a different website, a common disguise`, "danger");
  }
  const score = Math.min(100, findings.reduce((s, f) => s + f.weight, 0));
  return { url, host, score, level: levelFor(score), findings };
}
