# Publishing SAYNO so anyone can use it

SAYNO needs no server. Everything is checked on the user's device; the only thing published is a set of static files
(the website, the web scanner, and the block lists as hashed files). GitHub Pages hosts them for free.

```
GitHub Actions (every 15 minutes + on every push)
  └─ tools/build_site.py --refresh  → downloads the public threat feeds, hashes them, builds the site
       └─ GitHub Pages: https://<user>.github.io/<repo>/
            ├─ /                    website            ├─ /v1/meta.json        version + size (tiny)
            ├─ /message-check/ …    the checks         ├─ /v1/prefixes.bin     4-byte hash prefixes (~2.4 MB)
            ├─ /tutorial/ /privacy/ …                   └─ /v1/shards/<xx>.json full hashes by first byte (256 files)
Browser extension  ──downloads──▶  the files above, checks pages and text locally
```

## 1. Website and block lists (done once, then automatic)

1. The repo must be public, or on a GitHub plan that allows Pages for private repos.
2. Turn on Pages with the **GitHub Actions** source: *Settings → Pages → Source → GitHub Actions*
   (or `gh api -X POST repos/<user>/<repo>/pages -f build_type=workflow`).
3. Push to `main`. `.github/workflows/pages.yml` builds and publishes. You get `https://<user>.github.io/<repo>/`.
4. The same workflow re-runs every 15 minutes to refresh the block lists. GitHub pauses scheduled workflows in a repo with no
   activity for 60 days: open the *Actions* tab and re-enable it if that ever happens.

Check it: open the site, `…/message-check/` (paste a scam message), `…/v1/meta.json` (version and entry count) and `…/privacy/`.

Bandwidth note: each device downloads the 2.4 MB list only when it changed (it checks the tiny `meta.json` first).
GitHub Pages has a soft limit of 100 GB/month. If SAYNO grows past that, put the same `_site` folder on Cloudflare Pages
or Netlify (also free, more bandwidth) and pass the new address to the packager below. Nothing else changes.

## 2. Build the extension for the store

```
python tools/package_extension.py --api https://<user>.github.io/<repo>
```
This writes `dist/sayno-extension-<version>.zip` with that address built in, limits the always-on network permission to
that one host, and checks every file the manifest needs is present. Load the unpacked copy once (`chrome://extensions` →
Developer mode → Load unpacked on `extension/`) and try it before uploading.

## 3. Chrome Web Store

1. Register at https://chrome.google.com/webstore/devconsole (one-time US$5 fee, 2-step verification required).
2. *New item* → upload the zip.
3. Fill the listing from `docs/STORE_LISTING.md` (description, single purpose, permission justifications, data-use answers).
4. Privacy policy URL: `https://<user>.github.io/<repo>/privacy/` (the contact email in `static/pages/privacy.html` is already filled in).
5. Screenshots: `python tools/store_screenshots.py` (needs the local server running and Playwright) → `dist/screenshots/`.
6. Submit for review (usually a few days). Broad "all websites" access gets a closer look, so the justifications matter.

Tip: publish as **Unlisted** first. Only people with the link can install it: a good final round of testing with friends.

## 4. Edge Add-ons (free)

https://partner.microsoft.com/dashboard/microsoftedge → upload the same zip. No code changes needed.

## 5. After launch

- Bump `version` in `extension/manifest.json` and re-run the packager for every update.
- If you change detection rules in `server/shieldlib/engine.py`, run `python tools/gen_heuristics.py`, `python tools/gen_parity_vectors.py`
  and `python tools/sync_engine.py` (CI fails if the on-device rules drift from the Python ones).
- Watch `…/v1/meta.json`: `sourcesOk` should stay 7 of 7 and `generatedAt` should be recent.

## Optional: run your own server

`server/app.py` (plain Python, no dependencies) serves the same files plus the website, for local development or
self-hosting: `start.bat` / `./start.sh`, or `SAYNO_PUBLIC=1 python server/app.py` (public mode: no logging, no admin page,
rate limits; a `Dockerfile` and `render.yaml` are included). Point the extension at it under *Advanced → block-list source*.
