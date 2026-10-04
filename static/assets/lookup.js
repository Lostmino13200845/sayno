// Private block-list lookups. The page a person is on is hashed HERE, on the device, and checked against a
// local list of 4-byte hash prefixes. Only when a prefix matches (rare for an ordinary site) is one small
// shard file fetched (the full hashes that start with the same byte) and compared locally. The file host learns
// "someone fetched shard 3f" and nothing else. Hash inputs are documented in server/shieldlib/hashindex.py.
//
// The files are static: v1/prefixes.bin, v1/shards/<xx>.json, v1/meta.json under the data source address
// (GitHub Pages for the public build, or your own SAYNO server).

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
    tx.oncomplete = () => { db.close(); resolve(out?.result); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

let state = null;  // { version, prefixes: Uint32Array (sorted) }
let loading = null;
const shards = new Map();  // "<version>/<xx>" -> parsed shard (kept for this worker's lifetime)

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

/**
 * Download the prefix list if it changed. The tiny meta.json says which version is published, so an unchanged
 * list costs a few hundred bytes (not 2.4 MB). Safe to call often.
 */
export async function syncPrefixes(base) {
  const have = await loadState();
  const meta = await fetchMeta(base);
  if (meta && have && meta.version === have.version) return { updated: false, version: have.version };
  const r = await fetch(base + "/v1/prefixes.bin", { cache: "no-cache" });
  if (!r.ok) throw new Error("HTTP " + r.status);
  const bytes = new Uint8Array(await r.arrayBuffer());
  if (bytes.length < 4 || bytes.length % 4) throw new Error("bad prefix list");
  const view = new DataView(bytes.buffer);
  const prefixes = new Uint32Array(bytes.length >> 2);
  for (let i = 0; i < prefixes.length; i++) prefixes[i] = view.getUint32(i * 4);  // big-endian, ascending
  const version = meta?.version || (r.headers.get("ETag") || "").replace(/^W\//, "").replace(/"/g, "") || String(bytes.length);
  if (have && have.version === version) return { updated: false, version };
  state = { version, prefixes };
  shards.clear();
  await kv("readwrite", s => s.put({ version, buffer: prefixes.buffer }, "prefixes"));
  return { updated: true, version, count: prefixes.length };
}

/** Block-list size and health, for the popup. Returns null when the source is unreachable. */
export async function fetchMeta(base) {
  try {
    const r = await fetch(base + "/v1/meta.json", { cache: "no-cache" });
    return r.ok ? await r.json() : null;
  } catch { return null; }
}

const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
async function sha(s) { return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))); }

// Same normalisation as normalize_url() in server/shieldlib/intel.py.
export function normalizeUrl(raw) {
  const url = raw.trim().replace(/[.,;:!?)\]}>'"]+$/, "");
  let u;
  try { u = new URL(url.includes("://") ? url : "http://" + url); } catch { return url.toLowerCase(); }
  const host = u.hostname.toLowerCase().replace(/\.+$/, "");
  const path = u.pathname.replace(/\/+$/, "");
  const q = u.search.length > 1 ? u.search : "";
  const port = u.port && u.port !== "80" && u.port !== "443" ? ":" + u.port : "";
  return `${host}${port}${path}${q}`;
}

function hostOf(url) {
  try { return new URL(url.includes("://") ? url : "http://" + url).hostname.toLowerCase().replace(/\.+$/, ""); } catch { return null; }
}

function domainCandidates(host) {
  if (!host || /^[\d.]+$/.test(host) || host.includes(":")) return [];
  const labels = host.split("."), out = [];
  for (let i = 0; i < labels.length - 1; i++) out.push({ s: "d:" + labels.slice(i).join("."), how: i === 0 ? "domain" : "parent domain" });
  return out;
}

/** Everything about this page that could be on a block list: exact link, host, and each parent domain. */
export function candidates(url) {
  const host = hostOf(url);
  if (!host) return [];
  return [{ s: "u:" + normalizeUrl(url), how: "exact link" }, { s: "h:" + host, how: "site hosts known-bad link(s)" }, ...domainCandidates(host)];
}

function hasPrefix(sorted, p) {
  let lo = 0, hi = sorted.length;
  while (lo < hi) { const mid = (lo + hi) >>> 1; if (sorted[mid] < p) lo = mid + 1; else hi = mid; }
  return lo < sorted.length && sorted[lo] === p;
}

async function shard(base, version, xx) {
  const key = version + "/" + xx;
  if (shards.has(key)) return shards.get(key);
  const r = await fetch(`${base}/v1/shards/${xx}.json?v=${encodeURIComponent(version)}`);
  if (!r.ok) throw new Error("HTTP " + r.status);
  const data = await r.json();
  shards.set(key, data);
  return data;
}

/**
 * Looks the candidate strings up. -> { ready: false } while no list is downloaded yet; otherwise
 * { ready: true, hits: [{category, how}], unresolved?: true } where unresolved means a prefix matched
 * but the shard could not be fetched (so we cannot say yes or no).
 */
async function lookup(cands, base) {
  const st = await loadState();
  if (!st) return { ready: false, hits: [] };
  const hashed = await Promise.all(cands.map(async c => ({ ...c, hash: await sha(c.s) })));
  const near = hashed.filter(c => hasPrefix(st.prefixes, parseInt(c.hash.slice(0, 8), 16)));
  if (!near.length) return { ready: true, hits: [] };
  const hits = [];
  try {
    for (const c of near) {
      const data = await shard(base, st.version, c.hash.slice(0, 2));
      const idx = data.h[c.hash.slice(2)];
      if (idx !== undefined) hits.push({ category: data.c[idx], how: c.how });
    }
    return { ready: true, hits };  // a prefix matched but no full hash did: not listed
  } catch {
    return { ready: true, hits, unresolved: true };  // source unreachable: no verdict rather than a guess
  }
}

/** Is this page / link on a block list? -> { ready, listed: {category, how} | null, unresolved? } */
export async function checkUrl(url, base) {
  const r = await lookup(candidates(url), base);
  return { ready: r.ready, listed: r.hits[0] || null, unresolved: r.unresolved };
}

/** Is this e-mail domain a known-bad or disposable provider? -> { ready, listed, disposable, unresolved? } */
export async function checkEmailDomain(domain, base) {
  const d = domain.toLowerCase();
  const r = await lookup([{ s: "x:" + d, how: "disposable" }, ...domainCandidates(d)], base);
  return { ready: r.ready, disposable: r.hits.some(h => h.category === "disposable"),
           listed: r.hits.find(h => h.category !== "disposable") || null, unresolved: r.unresolved };
}
