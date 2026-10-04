"""SAYNO - local web app.  Run start.bat (Windows) or ./start.sh (macOS/Linux), then open http://127.0.0.1:8765"""
import sys
if sys.version_info < (3, 10):
    sys.exit("SAYNO needs Python 3.10 or newer: https://www.python.org/downloads/")
import hmac
import json
import os
import re
import secrets
import shutil
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from shieldlib import (OnlineChecker, ReportStore, ThreatIntel, analyze, auto_report, is_reportable,
                       manual_links, pwned_range, record_scan)
from shieldlib.hashindex import HashIndex

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # project root (server/ is one level down)
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
EXAMPLE_PATH = os.path.join(BASE_DIR, "config.example.json")
if not os.path.exists(CONFIG_PATH):
    try:
        shutil.copy(EXAMPLE_PATH, CONFIG_PATH)
    except OSError:  # read-only install (some hosts): run on the defaults instead of refusing to start
        CONFIG_PATH = EXAMPLE_PATH
with open(CONFIG_PATH, encoding="utf-8") as f:
    CFG = json.load(f)
if not CFG.get("admin_token"):  # generated once, protects the back-office pages
    CFG["admin_token"] = secrets.token_urlsafe(24)
    try:
        if CONFIG_PATH != EXAMPLE_PATH:  # never write a secret into the shipped example file
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(CFG, f, indent=2)
            os.chmod(CONFIG_PATH, 0o600)  # holds the admin token: owner-only on macOS/Linux
    except OSError:
        pass  # the token then lives only for this run

INTEL = ThreatIntel(interval_sec=int(CFG.get("update_interval_sec", 300)))
INDEX = HashIndex()  # hash-prefix index of the block lists, for private on-device lookups
STORE = ReportStore()
ONLINE = OnlineChecker(CFG)
STATIC = os.path.join(BASE_DIR, "static")
MAX_BODY = 200_000

# ---- public mode: the same server, hosted on the internet for everyone's extension and the website.
# Locally (default) it only listens on 127.0.0.1 and trusts nothing but this computer.
PUBLIC = bool(CFG.get("public_mode")) or os.environ.get("SAYNO_PUBLIC") == "1"
PORT = int(os.environ.get("PORT") or CFG.get("port", 8765))
HOST = os.environ.get("HOST") or CFG.get("host") or ("0.0.0.0" if PUBLIC else "127.0.0.1")
ALLOWED_HOSTS = {h.lower() for h in (CFG.get("allowed_hosts") or []) if h}
if PUBLIC:  # a public server never keeps what people scan, never files reports on their behalf, has no admin page
    CFG.update(auto_log=False, auto_report=False, store_message_text=False)
ADMIN_ENABLED = bool(CFG.get("admin_enabled")) if PUBLIC else True


class RateLimiter:
    """Per-client sliding window. Only enforced in public mode; a single PC talking to itself is never limited."""

    def __init__(self):
        self._lock = threading.Lock()
        self._hits = {}

    def allow(self, key, limit, window=60.0):
        if not PUBLIC:
            return True
        now = time.time()
        with self._lock:
            hits = [t for t in self._hits.get(key, ()) if now - t < window]
            if len(hits) >= limit:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            if len(self._hits) > 20000:  # keep memory bounded under a flood of distinct addresses
                self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < window}
        return True


LIMITER = RateLimiter()
LIMITS = {"scan": 30, "hashes": 120, "prefixes": 60, "pwned": 20, "status": 120}  # requests per minute per client
REPORT_NOW = threading.Event()  # wakes the back-end reporter right after a suspicious scan


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # keep the console quiet
        pass

    def _send(self, code, body, ctype="application/json", extra=None):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if ctype.startswith("text/html"):
            self.send_header("X-Frame-Options", "DENY")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ValueError("Bad request")
        if n < 0 or n > MAX_BODY:
            raise ValueError("Input too large" if n > 0 else "Bad request")
        body = json.loads(self.rfile.read(n) or b"{}")
        if not isinstance(body, dict):
            raise ValueError("Bad request")
        return body

    def _client(self):
        # Behind a hosting platform's proxy the real client is the last X-Forwarded-For entry (added by the proxy).
        fwd = self.headers.get("X-Forwarded-For", "") if PUBLIC else ""
        return fwd.split(",")[-1].strip() or self.client_address[0]

    def _limited(self, bucket):
        if LIMITER.allow((bucket, self._client()), LIMITS[bucket]):
            return False
        self._send(429, {"error": "Too many requests. Please wait a minute."}, extra={"Retry-After": "60"})
        return True

    def _same_origin(self):
        if PUBLIC:  # no DNS-rebinding risk for a public API; only insist on a known host name if one is configured
            return not ALLOWED_HOSTS or self.headers.get("Host", "").split(":")[0].lower() in ALLOWED_HOSTS
        # Block other websites from driving this local API (CSRF / DNS rebinding).
        # The browser extension calls in with a chrome-extension:// / moz-extension:// origin.
        ok_hosts = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
        origin = self.headers.get("Origin")
        return (self.headers.get("Host", "") in ok_hosts
                and (origin is None or origin.split("//", 1)[-1] in ok_hosts
                     or origin.startswith(("chrome-extension://", "moz-extension://", "extension://"))))

    def _admin(self):
        # The token travels only in the X-Admin-Token header, never in a URL (URLs end up in browser
        # history, logs and screenshots). compare_digest on bytes also copes with non-ASCII input.
        token = (self.headers.get("X-Admin-Token") or "").encode("utf-8", "replace")
        return hmac.compare_digest(token, CFG["admin_token"].encode())

    def do_GET(self):
        if not self._same_origin():
            return self._send(403, {"error": "forbidden"})
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        pages = {"/": "site/index.html", "/index.html": "site/index.html",
                 "/app": "index.html", "/app/": "index.html", "/design": "site/design.html", "/design/": "site/design.html",
                 "/tutorial": "site/index.html", "/tutorial/": "site/index.html"}
        if u.path in pages:
            with open(os.path.join(STATIC, pages[u.path]), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        m = re.fullmatch(r"/assets/([a-z0-9-]+\.(css|js|png|svg))", u.path)
        if m and os.path.exists(os.path.join(STATIC, "assets", m.group(1))):
            with open(os.path.join(STATIC, "assets", m.group(1)), "rb") as f:
                ctype = {"css": "text/css; charset=utf-8", "js": "text/javascript; charset=utf-8",
                         "png": "image/png", "svg": "image/svg+xml"}[m.group(2)]
                return self._send(200, f.read(), ctype)
        if u.path == "/healthz":
            return self._send(200, {"ok": True, "index": INDEX.count > 0})
        if u.path == "/api/status":
            if self._limited("status"):
                return
            return self._send(200, {"protection": INTEL.stats(), "index": {"version": INDEX.version, "entries": INDEX.count}})
        # Block-list files, laid out exactly like the static copy published on GitHub Pages (see shieldlib/hashindex.py).
        if u.path in ("/v1/prefixes.bin", "/v1/meta.json") or re.fullmatch(r"/v1/shards/[0-9a-f]{2}\.json", u.path):
            if self._limited("prefixes"):
                return
            if not INDEX.count:  # still loading the feeds after a cold start: never hand out an empty list as "all clear"
                return self._send(503, {"error": "Block lists are still loading, try again shortly."}, extra={"Retry-After": "30"})
            version, blob = INDEX.prefix_list()
            if u.path == "/v1/meta.json":
                return self._send(200, INDEX.meta(INTEL), "application/json", {"Access-Control-Allow-Origin": "*"})
            etag = {"ETag": f'"{version}"', "Access-Control-Allow-Origin": "*"}
            if self.headers.get("If-None-Match") == f'"{version}"':
                return self._send(304, b"", "application/octet-stream", etag)
            if u.path == "/v1/prefixes.bin":
                return self._send(200, blob, "application/octet-stream", etag)
            return self._send(200, INDEX.shard_json(int(u.path[11:13], 16)), "application/json", etag)
        m = re.fullmatch(r"/demo/([a-z0-9-]+\.html)", u.path)
        if m and os.path.exists(os.path.join(STATIC, "demo", m.group(1))):
            with open(os.path.join(STATIC, "demo", m.group(1)), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")

        # ---- back office (admin token required; unknown paths look like 404s)
        if u.path in ("/privacy", "/privacy/", "/privacy.html"):
            with open(os.path.join(STATIC, "site", "privacy.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if not ADMIN_ENABLED and u.path.startswith(("/admin", "/api/admin/")):
            return self._send(404, {"error": "not found"})
        if u.path == "/admin":  # the page only holds a login box; all data needs the header token
            with open(os.path.join(STATIC, "admin.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if u.path.startswith("/api/admin/") and not self._admin():
            return self._send(404, {"error": "not found"})
        if u.path == "/api/admin/items":
            return self._send(200, {"items": STORE.list(q.get("status"), q.get("kind"), q.get("limit", 200)),
                                    "counts": STORE.counts(),
                                    "history": STORE.report_history(100),
                                    "reporter_email_set": bool(CFG.get("reporter_email"))})
        if u.path == "/api/admin/export":
            data = json.dumps(STORE.list(q.get("status"), q.get("kind"), 100_000), indent=2).encode()
            name = f"sayno-{time.strftime('%Y%m%d-%H%M')}.json"
            return self._send(200, data, extra={"Content-Disposition": f'attachment; filename="{name}"'})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._same_origin():
            return self._send(403, {"error": "forbidden"})
        try:
            body = self._json()
            if self.path == "/api/scan":
                if self._limited("scan"):
                    return
                text = str(body.get("text", ""))[:(20_000 if PUBLIC else 100_000)]
                result = analyze(text, INTEL, STORE, ONLINE if body.get("online", True) else None)
                threshold = CFG.get("auto_report_threshold", 60)
                if body.get("log") is False:  # tutorial / practice scans: analyse only, never store or report
                    result["reported"] = 0
                    return self._send(200, result)
                if CFG.get("auto_log", True):
                    record_scan(result, text, STORE, CFG.get("auto_log_threshold", 35),
                                CFG.get("store_message_text", False), threshold)
                result["reported"] = sum(1 for u in result["urls"] if CFG.get("auto_report", True)
                                         and CFG.get("auto_log", True) and is_reportable(u, result, threshold)
                                         and not INTEL.lookup_url(u["url"]))
                if result["reported"]:
                    REPORT_NOW.set()
                if result["level"] in ("medium", "high", "critical"):
                    result["manual"] = manual_links([u["url"] for u in result["urls"]])
                return self._send(200, result)
            if self.path == "/api/pwned-range":
                if self._limited("pwned"):
                    return
                prefix = str(body.get("prefix", ""))
                if not re.fullmatch(r"[0-9A-Fa-f]{5}", prefix):
                    return self._send(400, {"error": "prefix must be 5 hex chars"})
                return self._send(200, {"range": pwned_range(prefix)})
            if self.path == "/api/admin/status":
                if not ADMIN_ENABLED or not self._admin():
                    return self._send(404, {"error": "not found"})
                if body.get("status") not in ("auto", "confirmed", "dismissed"):
                    return self._send(400, {"error": "bad status"})
                try:
                    item_id = int(body["id"])
                except (KeyError, TypeError, ValueError):
                    return self._send(400, {"error": "bad id"})
                STORE.set_status(item_id, body["status"])
                return self._send(200, {"ok": True})
        except ValueError as e:  # bad input from the client: safe to explain
            return self._send(400, {"error": str(e) if str(e) in ("Bad request", "Input too large") else "Bad request"})
        except Exception as e:  # anything else: log here, never show internals to the client
            log(f"[server] error on {self.path}: {e!r}")
            return self._send(500, {"error": "Internal error"})
        self._send(404, {"error": "not found"})


def reporter_loop():
    """Back-end process: reports new high-risk links to external services.
    Runs shortly after each suspicious scan (batched), and every cycle as a sweep."""
    while True:
        if REPORT_NOW.wait(timeout=INTEL.interval):
            time.sleep(20)  # collect a few scans into one batch
            REPORT_NOW.clear()
        try:
            auto_report(STORE, INTEL, CFG, log=log)
        except Exception as e:
            log(f"[auto-report] error: {e}")


def on_cycle(changed):
    if changed or not INDEX.count:
        INDEX.rebuild(INTEL)
    s = INTEL.stats()
    what = f"updated: {', '.join(changed)}" if changed else "no changes"
    log(f"threat database {s['threats']:,} entries ({s['sources_ok']}/{s['sources_total']} sources ok, {what})")


if __name__ == "__main__":
    print("SAYNO starting - loading threat database...", flush=True)
    INTEL.start(on_cycle=on_cycle)
    INDEX.rebuild(INTEL)  # from the cached feeds, so the extension can sync straight away
    threading.Thread(target=reporter_loop, name="auto-reporter", daemon=True).start()
    url = f"http://127.0.0.1:{PORT}"
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"SAYNO running at {url}  (updates every {INTEL.interval // 60} min, Ctrl+C to stop)")
    if PUBLIC:
        print(f"PUBLIC MODE on {HOST}:{PORT}: no scan logging, no auto-reporting, "
              f"admin {'ON' if ADMIN_ENABLED else 'off'}, rate limits on", flush=True)
    else:
        print(f"Admin page: {url}/admin", flush=True)
        print(f"Admin token (keep private, paste it into the login box): {CFG['admin_token']}", flush=True)
        if not CFG.get("reporter_email"):
            print("NOTE: auto-reporting is waiting for 'reporter_email' in config.json (required by Netcraft).",
                  flush=True)
    if "--no-browser" not in sys.argv and not PUBLIC:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
