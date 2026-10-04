"""Copies the on-device engine from extension/ into static/assets/ so the website's scanner and tutorial run the
very same code as the browser extension (one source of truth).

Run after editing the extension's engine files:   python tools/sync_engine.py
CI runs it with --check and fails if the copies are out of date.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = ["engine.js", "heuristics.js", "heuristics-data.js", "lookup.js"]


def main(check):
    stale = []
    for name in FILES:
        src = os.path.join(ROOT, "extension", name)
        dst = os.path.join(ROOT, "static", "assets", name)
        data = open(src, "rb").read().replace(b"\r\n", b"\n")
        have = open(dst, "rb").read().replace(b"\r\n", b"\n") if os.path.exists(dst) else None
        if have != data:
            stale.append(name)
            if not check:
                with open(dst, "wb") as f:
                    f.write(data)
    if check:
        if stale:
            sys.exit("static/assets copies are out of date (" + ", ".join(stale) + "): run python tools/sync_engine.py")
        print("static/assets engine copies are up to date")
    else:
        print("synced:", ", ".join(stale) if stale else "nothing to do")


if __name__ == "__main__":
    main("--check" in sys.argv)
