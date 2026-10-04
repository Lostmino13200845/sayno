"""Builds the whole public SAYNO website as static files (for GitHub Pages, or any static host):

    python tools/build_site.py --out _site --base /sayno            project site: https://<user>.github.io/sayno/
    python tools/build_site.py --out _site --base "" --refresh      site at the root of its own domain, fresh feeds

  * the website, web scanner, tutorial, demo pages, privacy policy and style guide (links rewritten for --base)
  * the block-list files the extension and the scanner use: v1/prefixes.bin, v1/shards/*.json, v1/meta.json
    (built from the public threat feeds; --refresh downloads them now, otherwise the cached copy is used)
  * no server, no database, no admin page: nothing here ever receives what a visitor pastes or browses

GitHub Actions (.github/workflows/pages.yml) runs this every few hours and publishes the result.
"""
import argparse
import os
import re
import shutil
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))
STATIC = os.path.join(ROOT, "static")

# source page -> folder in the build (every page becomes <folder>/index.html, so URLs work without ".html")
PAGES = {"site/index.html": ["", "tutorial"], "index.html": ["app"], "site/design.html": ["design"],
         "site/privacy.html": ["privacy"]}
ROUTES = {"/app": "/app/", "/design": "/design/", "/tutorial": "/tutorial/", "/privacy": "/privacy/"}


def rewrite(html, base):
    """Point the absolute links (href="/assets/..", src="/..", "/app#guide") at --base."""
    def link(m):
        attr, path = m.group(1), m.group(2)
        frag = ""
        if "#" in path:
            path, frag = path.split("#", 1)
            frag = "#" + frag
        path = ROUTES.get(path, path)
        return f'{attr}="{base}{path}{frag}"'
    return re.sub(r'\b(href|src)="(/[^"]*)"', link, html)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(ROOT, "_site"))
    ap.add_argument("--base", default="", help='path the site is served under, e.g. "/sayno" (default: domain root)')
    ap.add_argument("--refresh", action="store_true", help="download the threat feeds now (CI does this)")
    args = ap.parse_args()
    base = args.base.rstrip("/")
    out = args.out
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out)

    # ---- pages
    for src, folders in PAGES.items():
        with open(os.path.join(STATIC, src), encoding="utf-8") as f:
            html = rewrite(f.read(), base)
        for folder in folders:
            dest = os.path.join(out, folder)
            os.makedirs(dest, exist_ok=True)
            with open(os.path.join(dest, "index.html"), "w", encoding="utf-8", newline="\n") as f:
                f.write(html)
    shutil.copytree(os.path.join(STATIC, "assets"), os.path.join(out, "assets"))
    os.makedirs(os.path.join(out, "demo"))
    for name in os.listdir(os.path.join(STATIC, "demo")):
        with open(os.path.join(STATIC, "demo", name), encoding="utf-8") as f:
            html = rewrite(f.read(), base)
        with open(os.path.join(out, "demo", name), "w", encoding="utf-8", newline="\n") as f:
            f.write(html)
    with open(os.path.join(out, "404.html"), "w", encoding="utf-8", newline="\n") as f:
        f.write('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                '<title>Page not found</title><body style="font:16px system-ui;max-width:32rem;margin:15vh auto;padding:0 1rem">'
                f'<h1>Page not found</h1><p><a href="{base}/">Go to the SAYNO home page</a></p></body>')
    open(os.path.join(out, ".nojekyll"), "w").close()

    # ---- block lists
    from shieldlib.hashindex import HashIndex
    from shieldlib.intel import ThreatIntel
    intel = ThreatIntel()
    if args.refresh:
        t = time.time()
        intel.refresh()
        s = intel.stats()
        print(f"downloaded feeds in {time.time() - t:.0f}s: {s['sources_ok']}/{s['sources_total']} sources ok")
        if s["sources_ok"] < s["sources_total"] - 2:
            sys.exit("too many threat feeds failed to download; not publishing a thin block list")
    else:
        from shieldlib.intel import _SOURCES
        for name in _SOURCES:
            intel._load_cached(name)
    index = HashIndex()
    index.rebuild(intel)
    if index.count < 100_000:
        sys.exit(f"block list has only {index.count} entries; refusing to publish it")
    index.write_static(out, intel)
    size = sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(out) for f in fs)
    print(f"built {os.path.relpath(out, ROOT)} for base '{base}': {index.count:,} block-list entries, {size / 1e6:.0f} MB")


if __name__ == "__main__":
    main()
