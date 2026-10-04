"""End-to-end smoke test: starts the real server on a spare port, checks the pages and the scan API,
then stops it. Works on Windows, macOS and Linux.   Run:  python tests/smoke.py"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def request(base, path, body=None, raw=None, headers=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(base + path, data=data, headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def main():
    port = free_port()
    work = tempfile.mkdtemp(prefix="sayno-smoke-")
    # Run from a throw-away copy so the test never touches the real config.json or report database.
    for name in ("server", "static"):
        shutil.copytree(os.path.join(ROOT, name), os.path.join(work, name),
                        ignore=shutil.ignore_patterns(".data", "__pycache__"))
    with open(os.path.join(ROOT, "config.example.json"), encoding="utf-8") as f:
        cfg = json.load(f)
    cfg.update(port=port, auto_report=False)
    with open(os.path.join(work, "config.example.json"), "w", encoding="utf-8") as f:
        json.dump(cfg, f)

    proc = subprocess.Popen([sys.executable, os.path.join(work, "server", "app.py"), "--no-browser"],
                            cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, ok, detail=""):
        print(("PASS " if ok else "FAIL ") + name + (f"  {detail}" if detail and not ok else ""))
        if not ok:
            failures.append(name)

    try:
        for _ in range(60):  # up to ~30 s for the server to come up
            try:
                if request(base, "/api/status")[0] == 200:
                    break
            except OSError:
                time.sleep(0.5)
        else:
            check("server starts", False, "no answer on " + base)
            return 1
        check("server starts", True)

        for path in ("/", "/app", "/design", "/demo/inbox.html", "/demo/fake-bank.html", "/demo/shop.html",
                     "/assets/site.css", "/assets/tokens.css"):
            code, _ = request(base, path)
            check(f"GET {path}", code == 200, f"-> {code}")
        with open(os.path.join(work, "config.json"), encoding="utf-8") as f:
            token = json.load(f)["admin_token"]
        code, blob = request(base, "/api/v1/prefixes")
        # A cold server has no block lists yet and answers 503 ("still loading") instead of an empty all-clear list.
        check("prefix list endpoint: 4-byte records, or 503 while the lists load",
              (code == 200 and len(blob) % 4 == 0) or code == 503, str(code))
        check("hash lookup validates its input", request(base, "/api/v1/hashes", {"prefixes": ["zz"]})[0] == 400
              and request(base, "/api/v1/hashes", {"prefixes": []})[0] == 400
              and request(base, "/api/v1/hashes", {"prefixes": ["00000000"] * 51})[0] == 400)
        code, body = request(base, "/api/v1/hashes", {"prefixes": ["00000000"]})
        check("hash lookup answers with matches only", code == 200 and "matches" in json.loads(body))
        check("admin page is only a login box (no data)", request(base, "/admin")[0] == 200
              and b"Admin token" in request(base, "/admin")[1])
        check("admin API refused without token", request(base, "/api/admin/items")[0] == 404)
        check("token in the URL is NOT accepted", request(base, "/api/admin/items?token=" + token)[0] == 404
              and request(base, "/api/admin/export?token=" + token)[0] == 404)
        check("wrong token header refused", request(base, "/api/admin/items", headers={"X-Admin-Token": "nope"})[0] == 404)
        check("non-ASCII token header does not crash", request(base, "/api/admin/items",
                                                              headers={"X-Admin-Token": "café"})[0] == 404)
        code, body = request(base, "/api/admin/items", headers={"X-Admin-Token": token})
        check("admin API works with the header token", code == 200 and "items" in json.loads(body))
        check("path traversal refused", request(base, "/assets/../server/app.py")[0] in (403, 404))

        code, body = request(base, "/api/scan", {"text": "RBC: Your debit card has been temporarily locked. Verify your card "
                                                         "within 24 hours at https://rbc-secure-verify.help/login",
                                                 "online": False, "log": False})
        result = json.loads(body) if code == 200 else {}
        check("scan flags a bank scam as HIGH or worse", result.get("level") in ("high", "critical"), str(result.get("score")))
        code, body = request(base, "/api/scan", {"text": "Lunch at 1pm tomorrow?", "online": False, "log": False})
        check("scan keeps a normal message SAFE", code == 200 and json.loads(body)["level"] == "safe")
        check("malformed JSON -> 400", request(base, "/api/scan", raw=b"{nope")[0] == 400)
        check("non-object JSON -> 400", request(base, "/api/scan", raw=b"[1]")[0] == 400)
        code, body = request(base, "/api/status")
        check("status reports 7 sources", code == 200 and json.loads(body)["protection"]["sources_total"] == 7)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(work, ignore_errors=True)

    print("ALL PASS" if not failures else f"FAILED: {', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
