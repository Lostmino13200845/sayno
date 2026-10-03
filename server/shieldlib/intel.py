"""Private threat-intelligence store.

Pulls the world's major public blocklists, keeps them compressed in a hidden
folder, and refreshes them every few minutes using conditional requests
(ETag / Last-Modified), so unchanged feeds cost a few hundred bytes.

Nothing outside this module sees the raw lists - callers only get
`lookup_url()` / `lookup_email_domain()` verdicts and aggregate stats.
"""
import gzip
import json
import os
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from ._store import DATA_DIR, USER_AGENT

# kind: "urls" = full URL per line; "domains" = domain per line (hosts-file format ok);
#       "email_domains" = disposable mail providers
_SOURCES = {
    "urlhaus":        ("https://urlhaus.abuse.ch/downloads/text_online/", "urls", "malware"),
    "threatfox":      ("https://threatfox.abuse.ch/downloads/hostfile/", "domains", "malware"),
    "openphish":      ("https://openphish.com/feed.txt", "urls", "phishing"),
    "phishing_army":  ("https://phishing.army/download/phishing_army_blocklist.txt", "domains", "phishing"),
    "cert_pl":        ("https://hole.cert.pl/domains/v2/domains.txt", "domains", "phishing / fraud"),
    "phishing_db":    ("https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/"
                       "master/phishing-domains-ACTIVE.txt", "domains", "phishing"),
    "disposable":     ("https://raw.githubusercontent.com/disposable-email-domains/"
                       "disposable-email-domains/master/disposable_email_blocklist.conf",
                       "email_domains", "disposable"),
}


def normalize_url(url):
    url = url.strip().rstrip(".,;:!?)]}>'\"")
    try:
        parts = urlsplit(url if "://" in url else "http://" + url)
        port = parts.port
    except ValueError:
        return url.lower()
    host = (parts.hostname or "").lower().rstrip(".")
    path = parts.path.rstrip("/")
    q = ("?" + parts.query) if parts.query else ""
    port = f":{port}" if port and port not in (80, 443) else ""
    return f"{host}{port}{path}{q}"


def host_of(url):
    try:
        return (urlsplit(url if "://" in url else "http://" + url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _parse(kind, raw):
    urls, hosts, domains = set(), {}, set()
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line[0] in "#!;":
            continue
        if kind == "urls":
            urls.add(normalize_url(line))
            h = host_of(line)
            if h:
                hosts[h] = hosts.get(h, 0) + 1
        else:
            d = line.split()[-1].lower().rstrip(".")  # tolerate "127.0.0.1 domain" hosts format
            if d not in ("localhost", "0.0.0.0") and "." in d:
                domains.add(d)
    return {"urls": urls, "hosts": hosts, "domains": domains}


class ThreatIntel:
    def __init__(self, interval_sec=300):
        self.interval = interval_sec
        self._lock = threading.Lock()
        self._data = {}          # source -> parsed sets
        self._meta = self._read_meta()
        self._stop = threading.Event()
        self.last_cycle = None

    # ---------- persistence (compressed, hidden folder)
    def _path(self, name):
        return os.path.join(DATA_DIR, name + ".bin")

    def _read_meta(self):
        try:
            with open(os.path.join(DATA_DIR, "meta.json"), encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _write_meta(self):
        with open(os.path.join(DATA_DIR, "meta.json"), "w", encoding="utf-8") as f:
            json.dump(self._meta, f)

    # ---------- updating
    def _fetch(self, name):
        url, kind, _ = _SOURCES[name]
        m = self._meta.setdefault(name, {})
        headers = {"User-Agent": USER_AGENT}
        have_cache = os.path.exists(self._path(name))
        if have_cache and m.get("etag"):
            headers["If-None-Match"] = m["etag"]
        if have_cache and m.get("modified"):
            headers["If-Modified-Since"] = m["modified"]
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=90) as r:
                raw = r.read()
                m["etag"], m["modified"] = r.headers.get("ETag"), r.headers.get("Last-Modified")
        except urllib.error.HTTPError as e:
            if e.code == 304:
                m["checked"] = time.time()
                m.pop("error", None)
                return False
            m["error"] = f"HTTP {e.code}"
            return False
        except Exception as e:
            m["error"] = str(e)[:200]
            return False
        tmp = self._path(name) + ".tmp"
        with gzip.open(tmp, "wb", compresslevel=6) as f:
            f.write(raw)
        os.replace(tmp, self._path(name))
        parsed = _parse(kind, raw)
        with self._lock:
            self._data[name] = parsed
        m.update(checked=time.time(), changed=time.time(),
                 count=len(parsed["urls"]) + len(parsed["domains"]))
        m.pop("error", None)
        return True

    def _load_cached(self, name):
        try:
            with gzip.open(self._path(name), "rb") as f:
                parsed = _parse(_SOURCES[name][1], f.read())
            with self._lock:
                self._data[name] = parsed
        except OSError:
            pass

    def refresh(self):
        """One update cycle over all sources. Returns names that changed."""
        changed = [n for n in _SOURCES if self._fetch(n)]
        self.last_cycle = time.time()
        self._write_meta()
        return changed

    def start(self, on_cycle=None):
        """Load cache immediately, then update in the background forever."""
        for name in _SOURCES:
            self._load_cached(name)

        def loop():
            while not self._stop.is_set():
                changed = self.refresh()
                if on_cycle:
                    on_cycle(changed)
                self._stop.wait(self.interval)
        threading.Thread(target=loop, name="intel-updater", daemon=True).start()

    def stop(self):
        self._stop.set()

    # ---------- lookups (the only way data leaves this module)
    def _domain_hit(self, host):
        labels = host.split(".")
        for i in range(len(labels) - 1):
            cand = ".".join(labels[i:])
            for name, d in self._data.items():
                if _SOURCES[name][1] == "domains" and cand in d["domains"]:
                    return _SOURCES[name][2], ("domain" if i == 0 else "parent domain")
        return None

    def lookup_url(self, url):
        """-> list of (threat_category, match_type)"""
        n, host = normalize_url(url), host_of(url)
        hits = []
        with self._lock:
            for name, d in self._data.items():
                if _SOURCES[name][1] != "urls":
                    continue
                if n in d["urls"]:
                    hits.append((_SOURCES[name][2], "exact link"))
                elif host in d["hosts"]:
                    hits.append((_SOURCES[name][2], f"site hosts {d['hosts'][host]} known-bad link(s)"))
            dh = self._domain_hit(host)
            if dh:
                hits.append(dh)
        # de-duplicate by category
        seen, out = set(), []
        for cat, how in hits:
            if cat not in seen:
                seen.add(cat)
                out.append((cat, how))
        return out

    def lookup_email_domain(self, domain):
        domain = domain.lower()
        with self._lock:
            disp = any(_SOURCES[n][1] == "email_domains" and domain in d["domains"]
                       for n, d in self._data.items())
            return {"disposable": disp, "blocklisted": self._domain_hit(domain)}

    def stats(self):
        """Aggregate numbers only - no source list, no entries."""
        with self._lock:
            total = sum(len(d["urls"]) + len(d["domains"]) for n, d in self._data.items()
                        if _SOURCES[n][1] != "email_domains")
        changed = [m.get("changed") for m in self._meta.values() if m.get("changed")]
        errors = sum(1 for m in self._meta.values() if m.get("error"))
        return {"threats": total,
                "last_check": self.last_cycle,
                "last_change": max(changed) if changed else None,
                "interval_sec": self.interval,
                "sources_ok": len(_SOURCES) - errors,
                "sources_total": len(_SOURCES)}
