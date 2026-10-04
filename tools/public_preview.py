"""Read-only preview server for sharing the SAYNO website through a tunnel.

Serves ONLY the website, the practice tutorial, the style guide and the demo pages.
There is no scan API, no admin page and no database here, so exposing it to the internet
shows visitors the site and nothing else (the tutorial falls back to its built-in sample results).

Run:  python tools/public_preview.py [port]      (listens on 127.0.0.1; point a tunnel at it)
"""
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
PAGES = {"/": "site/index.html", "/index.html": "site/index.html", "/tutorial": "site/index.html",
         "/design": "site/design.html", "/privacy": "site/privacy.html"}
TYPES = {"css": "text/css; charset=utf-8", "js": "text/javascript; charset=utf-8", "png": "image/png",
         "svg": "image/svg+xml"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _file(self, rel, ctype):
        with open(os.path.join(STATIC, rel), "rb") as f:
            self._send(200, f.read(), ctype)

    def do_GET(self):
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        if path in PAGES:
            return self._file(PAGES[path], "text/html; charset=utf-8")
        m = re.fullmatch(r"/assets/([a-z0-9-]+\.(css|js|png|svg))", path)
        if m and os.path.exists(os.path.join(STATIC, "assets", m.group(1))):
            return self._file("assets/" + m.group(1), TYPES[m.group(2)])
        m = re.fullmatch(r"/demo/([a-z0-9-]+\.html)", path)
        if m and os.path.exists(os.path.join(STATIC, "demo", m.group(1))):
            return self._file("demo/" + m.group(1), "text/html; charset=utf-8")
        self._send(404, "Not found")

    do_HEAD = do_GET

    def do_POST(self):  # nothing to post to: the scan API is deliberately not part of the preview
        self._send(404, "Not found")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8790
    print(f"SAYNO website preview on http://127.0.0.1:{port} (read-only, no API, no admin)", flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
