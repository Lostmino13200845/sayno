# 🛡️ SAYNO

A scam, phishing and malicious-link scanner with a private, self-updating threat database and a server-side report database.

## Architecture

```
sayno/
├── server/
│   ├── app.py            web server + API (127.0.0.1 only)
│   └── shieldlib/        core library
│       ├── intel.py      private global threat database (auto-updates every 5 min)
│       ├── engine.py     analysis + 0-100 danger score
│       ├── reports.py    server-side database of suspicious / confirmed scams
│       ├── services.py   optional reputation APIs + external abuse reporting
│       └── .data/        (hidden, gitignored) feed cache, meta.json, reports.db
├── extension/            Chrome / Edge extension (Manifest V3)
├── static/               website, web scanner, demo pages, assets
├── design/ · tools/      design-system sources and sync_design.py
├── config.example.json   copied to config.json on first start
├── requirements.txt      (standard library only, nothing to install)
└── start.bat / start.sh  one-command start
```

### Threat database (`shieldlib.intel`)
Pulls about 730,000 known threats from 7 public sources: abuse.ch URLhaus and ThreatFox (malware); OpenPhish, Phishing Army, CERT Polska and Phishing.Database (phishing/fraud); and disposable e-mail domains.

- It checks every source every **5 minutes** (`update_interval_sec`). It uses ETag / If-Modified-Since, so an unchanged feed costs one tiny 304 response, and only changed feeds are downloaded and swapped in live.
- Feeds are stored gzip-compressed in the hidden `server/shieldlib/.data/` folder.
- **The lists are never exposed.** The API and UI only show verdicts ("known phishing threat") and aggregate counts. Source names and entries are not served.

### Report database (`shieldlib.reports`, SQLite) - back end only
- **Auto-logged:** every link, address or message that scores >= `auto_log_threshold` (35) is recorded automatically when a user scans it.
- **Not visible to users.** It is only shown on the private back office at `/admin?token=<admin_token>`. The token is generated on first start, saved in config.json and printed in the console; without it, the admin URLs return 404.
- In the back office you can **confirm** an item (it is then blocked in every future scan and reported) or **dismiss** a false alarm. You can also view the reporting log and **export JSON**.

### Automatic external reporting (back-end job)
Users never have to press anything. When a user pastes a message, it is scanned automatically. A qualifying link is queued, and the reporter thread sends it to **Netcraft** about 20 seconds later (in a batch), with a full sweep every 5 minutes.
- **Qualifies:** link score >= `auto_report_threshold` (60), or link score >= 35 inside a message scoring >= 60. Items an admin confirmed also qualify.
- **Skipped:** links already in the global threat database (the services know them), dismissed items, and links already sent.
- Failures are retried up to 3 times. Every attempt is logged in `report_log`.
- **Netcraft requires a reporter e-mail:** set `reporter_email` in config.json. Until then, links queue up.
- **URLhaus** (optional `api_keys.urlhaus`) also receives links that point to executable downloads.
- Users see a notice that dangerous links were reported, plus optional links to authorities (FTC, IC3, NCSC, ...).

## Browser extension (`extension/`, Chrome / Edge, Manifest V3)
Protection for **new bank customers and high-balance accounts**, the people scammers target with "activate your new card", "verify your account" and "pending e-Transfer" messages.

| Feature | How |
|---|---|
| **Site check** | Every page's address is checked against the SAYNO server; the verdict shows on the toolbar badge (`!`, `!!`, `✖`) |
| **Card Guard** | Detects card number / CVV / expiry / **PIN** / SIN fields and Luhn-valid card numbers being typed. It blocks the page when it asks for a PIN, uses bank-style pressure off a real bank domain, is rated risky, or isn't encrypted. Card data **never leaves the page**. |
| **My bank** | Users pick their bank(s). Official Canadian bank domains and big payment processors are trusted, and look-alikes are not. |
| **New-account mode** | Extra warnings while an account is new or holds a large balance |
| **Check a message** | Paste into the popup, or select text / right-click a link → "Check with SAYNO" |
| **On-screen warnings** | Optional `notifications` permission, requested on the welcome page (or via the popup switch) after a click. System notifications cover: page not encrypted (http), rated medium+ or known scam, and focusing a password/card/PIN/SIN field on an http page. At most one per site and reason every 30 min, with *Leave this page* / *Keep browsing* buttons. |
| **Auto-reporting** | Blocked pages are sent to the back end (URL + reason only) and qualify for automatic Netcraft reporting. Local / private addresses are never reported. |

Install: `edge://extensions` or `chrome://extensions` → Developer mode → **Load unpacked** → select the `extension` folder. The server must be running.

Demo pages (fictional bank): `/demo/fake-bank.html` (blocked), `/demo/shop.html` (normal checkout, not blocked), `/demo/inbox.html` (scam SMS examples to right-click → check).

## Website, tutorial & design system
| URL | |
|---|---|
| `/` | Landing page with a 6-step **"Try now" demo** (one step per main feature, pulsing "click here" rings, live scans that are never stored or reported) |
| `/tutorial` · `/tutorial#tutorial-9` | Tutorial only, full-screen or jump to a step (for presenting) |
| `/app` | Web scanner (paste-and-scan, password breach check, safety checklist) |
| `/design` | Living style guide: tokens, components, every extension screen and state |

All visual styling comes from `design/*.css`; run `py tools/sync_design.py` after editing. See **DESIGN.md**.

## Run
Python 3.10 or newer is the only requirement (standard library only, nothing to install). Then open http://127.0.0.1:8765 (website); the scanner is at `/app`.

| OS | Start |
|---|---|
| Windows | Double-click `start.bat` |
| macOS / Linux | `./start.sh` (if needed: `chmod +x start.sh`) |
| Any | `python server/app.py` (use `py` or `python3` as your system names it) |

On first start `config.json` is created from `config.example.json` and an admin token is generated. Add `--no-browser` to stop it opening a browser tab. The extension is loaded separately: `chrome://extensions` → Developer mode → Load unpacked → pick the `extension/` folder.

## config.json
| Key | Default | Meaning |
|---|---|---|
| `update_interval_sec` | 300 | Threat database update interval |
| `auto_log` | true | Record suspicious scans in the report database |
| `auto_log_threshold` | 35 | Minimum score to auto-log |
| `store_message_text` | false | Store full message text (default false = fingerprint only, for privacy) |
| `auto_report` | true | Back-end reporting to Netcraft / URLhaus |
| `auto_report_threshold` | 60 | Risk needed for automatic reporting |
| `reporter_email` | "" | **Required** for Netcraft auto-reporting |
| `admin_token` | generated | Secret for the `/admin` back office |
| `check_emails_stopforumspam` | false | E-mail reputation lookup (sends addresses to StopForumSpam) |
| `api_keys.google_safe_browsing` / `virustotal` / `urlhaus` | "" | Optional online checks / URLhaus reporting |

## API
| Method | Path | |
|---|---|---|
| GET | `/api/status` | Protection stats (aggregate only) |
| POST | `/api/scan` `{text, online}` | Scan, auto-log and queue reporting |
| GET | `/admin?token=` | Back-office page |
| GET | `/api/admin/items?status=&kind=` | Items + counts + reporting log (header `X-Admin-Token`) |
| POST | `/api/admin/status` `{id, status}` | Confirm / dismiss (header `X-Admin-Token`) |
| GET | `/api/admin/export?token=` | JSON export |

## Limits
New scam sites often appear hours before any blocklist lists them; the heuristics cover that gap. A "safe" result means "no known red flags", not a guarantee. Hiding the `.data` folder keeps the lists out of the UI and API, but anyone with access to this computer's files can still read them.
