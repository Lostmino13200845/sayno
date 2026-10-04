// Private block-list lookups. The page a person is on is hashed HERE, on the device, and checked against a
// local list of 4-byte hash prefixes downloaded from the SAYNO server. Only when a prefix matches (rare for
// an ordinary site) does the extension ask the server for the full hashes behind that prefix. The server
// learns a 4-byte fragment, never the page. Hash inputs are documented in server/shieldlib/hashindex.py.

const DB = "sayno-lists", STORE = "kv";

function idb() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}
async function kv(mode, fn) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, mode), out = fn(tx.objectStore(STORE));
    tx.oncomplete = () => resolve(out?.result);
    tx.onerror = () => reject(tx.error);
  });
}

let state = null;  // { version, prefixes: Uint32Array (sorted) }
let loading = null;

export async function loadState() {
  if (state) return state;
  loading ||= (async () => {
    try {
      const saved = await kv("readonly", s => s.get("prefixes"));
      if (saved) state = { version: saved.version, prefixes: new Uint32Array(saved.buffer) };
    } catch { /* no saved list yet */ }
    return state;
  })();
  return loading;
}

/** Download the prefix list if it changed. Safe to call often: an unchanged list costs one 304 response. */
export async function syncPrefixes(apiBase) {
  const have = await loadState();
  const headers = have ? { "If-None-Match": `"${have.version}"` } : {};
  const r = await fetch(apiBase + "/api/v1/prefixes", { headers });
  if (r.status === 304) return { updated: false, version: have.version };
  if (!r.ok) throw new Error("HTTP " + r.status);
  const version = r.headers.get("X-Index-Version") || (r.headers.get("ETag") || "").replace(/"/g, "");
  const bytes = new Uint8Array(await r.arrayBuffer());
  const view = new DataView(bytes.buffer);
  const prefixes = new Uint32Array(bytes.length >> 2);
  for (let i = 0; i < prefixes.length; i++) prefixes[i] = view.getUint32(i * 4);  // big-endian, ascending
  state = { version, prefixes };
  await kv("readwrite", s => s.put({ version, buffer: prefixes.buffer }, "prefixes"));
  return { updated: true, version, count: prefixes.length };
}

const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
async function sha(s) { return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))); }

// Same normalisation as normalize_url() in server/shieldlib/intel.py.
export function normalizeUrl(raw) {
  let url = raw.trim().replace(/[.,;:!?)\]}>'"]+$/, "");
  let u;
  try { u = new URL(url.includes("://") ? url : "http://" + url); } catch { return url.toLowerCase(); }
  const host = u.hostname.toLowerCase().replace(/\.+$/, "");
  const path = u.pathname.replace(/\/+$/, "");
  const q = u.search.length > 1 ? u.search : "";
  const port = u.port && u.port !== "80" && u.port !== "443" ? ":" + u.port : "";
  return `${host}${port}${path}${q}`;
}

/** Everything about this page that could be on a block list: exact link, host, and each parent domain. */
export function candidates(url) {
  const norm = normalizeUrl(url);
  let host;
  try { host = new URL(url).hostname.toLowerCase().replace(/\.+$/, ""); } catch { return []; }
  const out = [{ s: "u:" + norm, how: "exact link" }, { s: "h:" + host, how: "site hosts known-bad link(s)" }];
  if (!/^[\d.]+$/.test(host) && !host.includes(":")) {
    const labels = host.split(".");
    for (let i = 0; i < labels.length - 1; i++) out.push({ s: "d:" + labels.slice(i).join("."), how: i === 0 ? "domain" : "parent domain" });
  }
  return out;
}

function hasPrefix(sorted, p) {
  let lo = 0, hi = sorted.length;
  while (lo < hi) { const mid = (lo + hi) >>> 1; if (sorted[mid] < p) lo = mid + 1; else hi = mid; }
  return lo < sorted.length && sorted[lo] === p;
}

/**
 * -> { ready: false } while no list is downloaded yet
 *    { ready: true, listed: null } for a clean page
 *    { ready: true, listed: { category, how } } for a known-bad page
 * apiBase is contacted only when a local prefix matches.
 */
export async function checkUrl(url, apiBase) {
  const st = await loadState();
  if (!st) return { ready: false, listed: null };
  const cands = await Promise.all(candidates(url).map(async c => ({ ...c, hash: await sha(c.s) })));
  const hits = cands.filter(c => hasPrefix(st.prefixes, parseInt(c.hash.slice(0, 8), 16)));
  if (!hits.length) return { ready: true, listed: null };
  try {
    const r = await fetch(apiBase + "/api/v1/hashes", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prefixes: [...new Set(hits.map(c => c.hash.slice(0, 8)))] }),
    });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const { matches } = await r.json();
    const byHash = new Map(matches.map(m => [m.h, m.c]));
    for (const c of cands) if (byHash.has(c.hash)) return { ready: true, listed: { category: byHash.get(c.hash), how: c.how } };
    return { ready: true, listed: null };  // the prefix matched, the full hash did not: not listed
  } catch {
    return { ready: true, listed: null, unresolved: true };  // server unreachable: no verdict rather than a guess
  }
}
