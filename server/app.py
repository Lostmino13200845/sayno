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

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # project root (server/ is one level down)
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
if not os.path.exists(CONFIG_PATH):
    shutil.copy(os.path.join(BASE_DIR, "config.example.json"), CONFIG_PATH)
with open(CONFIG_PATH, encoding="utf-8") as f:
    CFG = json.load(f)
if not CFG.get("admin_token"):  # generated once, protects the back-office pages
    CFG["admin_token"] = secrets.token_urlsafe(24)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(CFG, f, indent=2)
    try:
        os.chmod(CONFIG_PATH, 0o600)  # holds the admin token: owner-only on macOS/Linux
    except OSError:
        pass

INTEL = ThreatIntel(interval_sec=int(CFG.get("update_interval_sec", 300)))
STORE = ReportStore()
ONLINE = OnlineChecker(CFG)
STATIC = os.path.join(BASE_DIR, "static")
MAX_BODY = 200_000
PORT = int(CFG.get("port", 8765))
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

    def _same_origin(self):
        # Block other websites from driving this local API (CSRF / DNS rebinding).
        # The browser extension calls in with a chrome-extension:// / moz-extension:// origin.
        ok_hosts = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
        origin = self.headers.get("Origin")
        return (self.headers.get("Host", "") in ok_hosts
                and (origin is None or origin.split("//", 1)[-1] in ok_hosts
                     or origin.startswith(("chrome-extension://", "moz-extension://", "extension://"))))

    def _admin(self, q):
        token = self.headers.get("X-Admin-Token") or q.get("token", "")
        return hmac.compare_digest(token, CFG["admin_token"])

    def do_GET(self):
        if not self._same_origin():
            return self._send(403, {"error": "forbidden"})
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        pages = {"/": "site/index.html", "/index.html": "site/index.html",
                 "/app": "index.html", "/design": "site/design.html",
                 "/tutorial": "site/index.html"}
        if u.path in pages:
            with open(os.path.join(STATIC, pages[u.path]), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        m = re.fullmatch(r"/assets/([a-z0-9-]+\.(css|js|png|svg))", u.path)
        if m and os.path.exists(os.path.join(STATIC, "assets", m.group(1))):
            with open(os.path.join(STATIC, "assets", m.group(1)), "rb") as f:
                ctype = {"css": "text/css; charset=utf-8", "js": "text/javascript; charset=utf-8",
                         "png": "image/png", "svg": "image/svg+xml"}[m.group(2)]
                return self._send(200, f.read(), ctype)
        if u.path == "/api/status":
            return self._send(200, {"protection": INTEL.stats()})
        m = re.fullmatch(r"/demo/([a-z0-9-]+\.html)", u.path)
        if m and os.path.exists(os.path.join(STATIC, "demo", m.group(1))):
            with open(os.path.join(STATIC, "demo", m.group(1)), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")

        # ---- back office (admin token required; unknown paths look like 404s)
        if u.path.startswith(("/admin", "/api/admin/")) and not self._admin(q):
            return self._send(404, {"error": "not found"})
        if u.path == "/admin":
            with open(os.path.join(STATIC, "admin.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
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
                text = str(body.get("text", ""))[:100_000]
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
                prefix = str(body.get("prefix", ""))
                if not re.fullmatch(r"[0-9A-Fa-f]{5}", prefix):
                    return self._send(400, {"error": "prefix must be 5 hex chars"})
                return self._send(200, {"range": pwned_range(prefix)})
            if self.path == "/api/admin/status":
                if not self._admin({}):
                    return self._send(404, {"error": "not found"})
                if body.get("status") not in ("auto", "confirmed", "dismissed"):
                    return self._send(400, {"error": "bad status"})
                STORE.set_status(int(body["id"]), body["status"])
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
    s = INTEL.stats()
    what = f"updated: {', '.join(changed)}" if changed else "no changes"
    log(f"threat database {s['threats']:,} entries ({s['sources_ok']}/{s['sources_total']} sources ok, {what})")


if __name__ == "__main__":
    print("SAYNO starting - loading threat database...", flush=True)
    INTEL.start(on_cycle=on_cycle)
    threading.Thread(target=reporter_loop, name="auto-reporter", daemon=True).start()
    url = f"http://127.0.0.1:{PORT}"
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"SAYNO running at {url}  (updates every {INTEL.interval // 60} min, Ctrl+C to stop)")
    print(f"Admin (keep private): {url}/admin?token={CFG['admin_token']}", flush=True)
    if not CFG.get("reporter_email"):
        print("NOTE: auto-reporting is waiting for 'reporter_email' in config.json (required by Netcraft).",
              flush=True)
    if "--no-browser" not in sys.argv:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
