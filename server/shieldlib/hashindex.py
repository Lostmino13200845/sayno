"""Privacy-preserving block-list lookups (the idea behind Google Safe Browsing's update API).

The extension never sends the pages a person visits. Instead:
  1. It downloads a compact list of 4-byte hash PREFIXES of every known-bad entry (about 3 MB).
  2. It hashes the page it is on, ON THE DEVICE, and looks for the prefix in that list.
  3. Only if a prefix matches (rare for a normal site) does it ask the server for the full hashes
     behind that prefix, and compares them locally. The server learns a 4-byte fragment, not a page.

Hash inputs (SHA-256), built identically in extension/lookup.js:
    "u:" + normalized URL     exact bad link         (normalize_url in intel.py)
    "h:" + host               a host that serves known-bad links, except big shared platforms
    "d:" + domain             a domain from a domain feed (the extension also tries its parent domains)
"""
import hashlib
import threading

from .intel import is_shared_host

_CATEGORIES = ["malware", "phishing", "phishing / fraud"]
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
            ci = _CATEGORIES.index(category) if category in _CATEGORIES else 0
            if kind == "urls":
                for u in d["urls"]:
                    best.setdefault(sha("u:" + u), ci)
                for h in d["hosts"]:
                    if not is_shared_host(h):
                        best.setdefault(sha("h:" + h), ci)
            else:
                for dom in d["domains"]:
                    best.setdefault(sha("d:" + dom), ci)
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

    def lookup(self, prefixes):
        """prefix (4 bytes) list -> [(full hash hex, category)] for every entry behind those prefixes."""
        with self._lock:
            rec, n = self._records, len(self._records) // REC
        out = []
        for p in prefixes[:50]:
            lo, hi = 0, n
            while lo < hi:  # first record >= prefix
                mid = (lo + hi) // 2
                if rec[mid * REC: mid * REC + 4] < p:
                    lo = mid + 1
                else:
                    hi = mid
            i = lo
            while i < n and rec[i * REC: i * REC + 4] == p and len(out) < 500:
                r = rec[i * REC: (i + 1) * REC]
                out.append((r[:32].hex(), _CATEGORIES[r[32]]))
                i += 1
        return out
