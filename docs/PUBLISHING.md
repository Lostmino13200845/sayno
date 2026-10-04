# Publishing SAYNO so anyone can use it

Two parts go public: the **server** (block lists, scan API, website) and the **extension** (in the Chrome Web Store).
The extension rates pages on the user's device, so the server never sees what people browse (see `static/site/privacy.html`).

## 1. Deploy the server

The server is plain Python with no dependencies. In public mode (`SAYNO_PUBLIC=1`) it listens on `0.0.0.0:$PORT`,
keeps no scan history, files no reports, has no admin page and rate-limits each client.

**Render (easiest, free tier available)**
1. Push this repo to GitHub (done) and sign in at https://render.com.
2. *New → Blueprint* → pick the repo. `render.yaml` and the `Dockerfile` do the rest.
3. When it is live you get an address like `https://sayno-xxxx.onrender.com`.

Free instances sleep after about 15 minutes idle and take ~30 s to wake and reload the block lists. The extension
copes (it keeps its local list and only needs the server on a rare match), but use a paid instance if you want instant answers.

**Anywhere else:** `docker build -t sayno . && docker run -p 8765:8765 sayno`, or run `SAYNO_PUBLIC=1 PORT=8080 python server/app.py`
behind any HTTPS reverse proxy. Optional settings in `config.json`: `allowed_hosts` (your domain names), `admin_enabled`.

**Check it:** open `https://<your-server>/healthz` (should say `"index": true` once the lists have loaded, about a minute after a cold start),
`/privacy`, and `/api/status`.

## 2. Build the extension for the store

```
python tools/package_extension.py --api https://<your-server>
```
This writes `dist/sayno-extension-<version>.zip` with your server address built in, limits the always-on permission to that one address,
and checks every file the manifest needs is present. Load the unpacked copy once (`chrome://extensions` → Developer mode → Load unpacked on
`extension/`) and try it before uploading.

## 3. Chrome Web Store

1. Register at https://chrome.google.com/webstore/devconsole (one-time US$5 fee, 2-step verification required).
2. *New item* → upload the zip.
3. Fill the listing from `docs/STORE_LISTING.md` (description, single purpose, permission justifications, data-use answers).
4. Privacy policy URL: `https://<your-server>/privacy` (replace `[CONTACT EMAIL]` in `static/site/privacy.html` first).
5. Screenshots: run `python tools/store_screenshots.py` (needs the local server and Playwright) and upload the 1280×800 images from `dist/screenshots/`.
6. Submit for review. First reviews typically take a few days; broad "all websites" access gets a closer look, which is why the justifications matter.

Tip: publish as **Unlisted** first. Only people with the link can install it, which is good for a final round of testing with friends.

## 4. Edge Add-ons (free)

https://partner.microsoft.com/dashboard/microsoftedge → upload the same zip. No code changes needed.

## 5. After launch

- Bump `version` in `extension/manifest.json` and re-run the packager for every update.
- If you change `server/shieldlib/engine.py` rules, run `python tools/gen_heuristics.py` so the extension's on-device rules follow
  (CI fails if they drift).
- Watch `https://<your-server>/api/status`: `sources_ok` should stay 7 of 7.
