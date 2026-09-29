"""Copy the design system (design/*.css) to every place that uses it.

    py tools/sync_design.py

The extension can't load files from the website, so it keeps its own copy.
Never edit the copies - edit the files in design/.
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(ROOT, "static", "assets")
EXT = os.path.join(ROOT, "extension", "ui")
# design file -> where it is used
FILES = {
    "tokens.css":     [SITE, EXT],
    "components.css": [SITE, EXT],
    "popup.css":      [SITE, EXT],   # website tutorial shows a replica of the popup
    "overlay.css":    [SITE, EXT],   # ...and of the Card Guard screens
    "site.css":       [SITE],
}
HEADER = "/* GENERATED COPY - edit design/{name} and run py tools/sync_design.py */\n"

for name, targets in FILES.items():
    with open(os.path.join(ROOT, "design", name), encoding="utf-8") as f:
        css = f.read().lstrip("﻿")  # editors on Windows may add a BOM
    for target in targets:
        os.makedirs(target, exist_ok=True)
        with open(os.path.join(target, name), "w", encoding="utf-8") as f:
            f.write(HEADER.format(name=name) + css)
        print("synced", os.path.relpath(os.path.join(target, name), ROOT))
