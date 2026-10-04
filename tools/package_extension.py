"""Builds the zip you upload to the Chrome Web Store / Edge Add-ons.

    python tools/package_extension.py --api https://your-sayno-server.example

What it does to a copy of extension/ (the source folder is never modified):
  * writes the address of the published block-list files into config.js (users can change it under "Advanced")
  * limits the always-on network permission to that one host; any other address is asked for when needed
  * leaves out development-only files and checks that every file the manifest points to is in the zip
Output: dist/sayno-extension-<version>.zip  (forward-slash paths, ready to upload)
"""
import argparse
import json
import os
import shutil
import sys
import tempfile
import zipfile
from urllib.parse import urlsplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "extension")
SKIP = {"package.json", ".DS_Store", "Thumbs.db"}


def manifest_files(m):
    files = {m["background"]["service_worker"], m["action"]["default_popup"]}
    files.update(m.get("icons", {}).values())
    files.update(m["action"].get("default_icon", {}).values())
    for cs in m.get("content_scripts", []):
        files.update(cs.get("js", []))
        files.update(cs.get("css", []))
    for war in m.get("web_accessible_resources", []):
        files.update(war.get("resources", []))
    return files


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", required=True, help="public SAYNO server, e.g. https://sayno.example (https only)")
    ap.add_argument("--out", default=os.path.join(ROOT, "dist"))
    ap.add_argument("--stable-name", action="store_true", help="name the zip sayno-extension.zip (for a fixed website download link)")
    args = ap.parse_args()

    u = urlsplit(args.api)
    if u.scheme != "https" or not u.hostname or u.query or u.fragment:
        sys.exit("--api must be an https address such as https://you.github.io/sayno (no query or #fragment)")
    origin = f"https://{u.netloc.lower()}"  # host names are case-insensitive; match patterns want lower case
    base = origin + u.path.rstrip("/")  # the folder that holds v1/ (GitHub Pages serves a project under /<name>)

    work = tempfile.mkdtemp(prefix="sayno-pack-")
    try:
        build = os.path.join(work, "extension")
        shutil.copytree(SRC, build, ignore=shutil.ignore_patterns(*SKIP, "__pycache__"))

        with open(os.path.join(build, "config.js"), "w", encoding="utf-8", newline="\n") as f:
            f.write("// Written by tools/package_extension.py for the store build.\n"
                    f'export const DEFAULT_API = "{base}";\n')

        mpath = os.path.join(build, "manifest.json")
        with open(mpath, encoding="utf-8") as f:
            m = json.load(f)
        m["host_permissions"] = [origin + "/*"]
        m["optional_host_permissions"] = ["https://*/*", "http://127.0.0.1/*"]
        with open(mpath, "w", encoding="utf-8", newline="\n") as f:
            json.dump(m, f, indent=2, ensure_ascii=False)
            f.write("\n")

        missing = sorted(p for p in manifest_files(m) if not os.path.exists(os.path.join(build, p)))
        if missing:
            sys.exit("manifest points to files that are not in the extension folder: " + ", ".join(missing))

        os.makedirs(args.out, exist_ok=True)
        out = os.path.join(args.out, "sayno-extension.zip" if args.stable_name else f"sayno-extension-{m['version']}.zip")
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for folder, _, names in os.walk(build):
                for n in sorted(names):
                    full = os.path.join(folder, n)
                    z.write(full, os.path.relpath(full, build).replace(os.sep, "/"))
        size = os.path.getsize(out)
        print(f"built {os.path.relpath(out, ROOT)}  ({size / 1024:.0f} KB)")
        print(f"  version {m['version']}, block lists from {base}")
        print(f"  host permissions: {m['host_permissions']}   optional: {m['optional_host_permissions']}")
        print("Next: upload this zip in the Chrome Web Store developer dashboard (see docs/PUBLISHING.md).")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
