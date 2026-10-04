"""Tiny page templating for the SAYNO website: pages in static/pages/ pull in shared partials from static/partials/.

    <!--#include head title="Page title" description="One sentence." -->

Used by the local server (on request) and by tools/build_site.py (for the GitHub Pages build), so both serve identical HTML.
"""
import os
import re

_INCLUDE = re.compile(r'<!--#include\s+([\w-]+)((?:\s+\w+="[^"]*")*)\s*-->')
_ATTR = re.compile(r'(\w+)="([^"]*)"')


def render(static_dir, page):
    """Return the finished HTML of static/pages/<page>.html."""
    def read(*parts):
        with open(os.path.join(static_dir, *parts), encoding="utf-8") as f:
            return f.read()

    def fill(m):
        html = read("partials", m.group(1) + ".html")
        for key, value in _ATTR.findall(m.group(2)):
            html = html.replace("{{" + key + "}}", value)
        return html

    return _INCLUDE.sub(fill, read("pages", page + ".html"))
