"""Privacy-preserving block-list lookups (the idea behind Google Safe Browsing's update API).

Nobody has to tell SAYNO which pages they visit. The block lists are published as plain static files:

  v1/prefixes.bin        4-byte hash PREFIXES of every known-bad entry, sorted (about 2.4 MB)
  v1/shards/<xx>.json    the full hashes whose first byte is <xx> (256 files)
  v1/meta.json           version, entry count, categories and feed health

The extension downloads prefixes.bin, hashes the page it is on ON THE DEVICE and looks for the prefix locally.
Only if a prefix matches (rare for a normal site) does it fetch one shard, and it compares the full hash locally.
A static file server therefore learns at most "someone fetched shard 3f", never a page.

Hash inputs (SHA-256), built identically in extension/lookup.js:
    "u:" + normalized URL     exact bad link         (normalize_url in intel.py)
    "h:" + host               a host that serves known-bad links, except big shared platforms
    "d:" + domain             a domain from a domain feed (the extension also tries its parent domains)
    "x:" + domain             a disposable e-mail provider
"""
import hashlib
import json
import os
import threading
import time

from .intel import is_shared_host

CATEGORIES = ["malware", "phishing", "phishing / fraud", "disposable"]
REC = 33  # 32-byte hash + 1 category byte


def sha(s):
    return hashlib.sha256(s.encode("utf-8", "replace")).digest()


class HashIndex:
    def __init__(self):
        self._lock = threading.Lock()
        self._records = b""      # sorted by hash, REC bytes each
        self._prefixes = b""     # sorted unique 4-byte prefixes
        self.version = "0"
        self.count = 0

    def rebuild(self, intel):
        """Rebuild from the current threat feeds. Takes about a second for ~700k entries."""
        best = {}  # hash -> category index (the first feed to list it wins)
        for kind, category, d in intel.snapshot():
            ci = CATEGORIES.index(category) if category in CATEGORIES else 0
            if kind == "urls":
                for u in d["urls"]:
                    best.setdefault(sha("u:" + u), ci)
                for h in d["hosts"]:
                    if not is_shared_host(h):
                        best.setdefault(sha("h:" + h), ci)
            elif kind == "domains":
                for dom in d["domains"]:
                    best.setdefault(sha("d:" + dom), ci)
            elif kind == "email_domains":
                for dom in d["domains"]:
                    best.setdefault(sha("x:" + dom), ci)
        hashes = sorted(best)
        records = b"".join(h + bytes([best[h]]) for h in hashes)
        prefixes, last = [], None
        for h in hashes:
            if h[:4] != last:
                last = h[:4]
                prefixes.append(last)
        blob = b"".join(prefixes)
        version = hashlib.sha256(blob).hexdigest()[:12]
        with self._lock:
            self._records, self._prefixes, self.version, self.count = records, blob, version, len(hashes)

    def prefix_list(self):
        with self._lock:
            return self.version, self._prefixes

    def shard(self, first_byte):
        """-> {remaining 62 hex chars: category index} for every entry whose hash starts with this byte."""
        with self._lock:
            rec = self._records
        n = len(rec) // REC
        lo, hi = 0, n
        while lo < hi:  # first record >= first_byte
            mid = (lo + hi) // 2
            if rec[mid * REC] < first_byte:
                lo = mid + 1
            else:
                hi = mid
        out, i = {}, lo
        while i < n and rec[i * REC] == first_byte:
            r = rec[i * REC: (i + 1) * REC]
            out[r[1:32].hex()] = r[32]
            i += 1
        return out

    def shard_json(self, first_byte):
        return json.dumps({"v": self.version, "c": CATEGORIES, "h": self.shard(first_byte)}, separators=(",", ":")).encode()

    def meta(self, intel=None):
        m = {"version": self.version, "entries": self.count, "categories": CATEGORIES,
             "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        if intel is not None:
            s = intel.stats()
            m.update(sourcesOk=s["sources_ok"], sourcesTotal=s["sources_total"], lastChange=s["last_change"])
        return m

    def write_static(self, outdir, intel=None):
        """Write the whole index as static files under outdir/v1 (what GitHub Pages serves)."""
        root = os.path.join(outdir, "v1")
        os.makedirs(os.path.join(root, "shards"), exist_ok=True)
        _, blob = self.prefix_list()
        with open(os.path.join(root, "prefixes.bin"), "wb") as f:
            f.write(blob)
        for b in range(256):
            with open(os.path.join(root, "shards", f"{b:02x}.json"), "wb") as f:
                f.write(self.shard_json(b))
        with open(os.path.join(root, "meta.json"), "w", encoding="utf-8") as f:
            json.dump(self.meta(intel), f, indent=1)
