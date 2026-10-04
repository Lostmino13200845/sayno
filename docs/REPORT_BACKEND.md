# Report relay: sending scam reports from the SAYNO team address

The website's **Report a scam** page (`/report-scam/`) lets a visitor pick an incident type, fill in blanks
(link, number, message text, a multiple-choice list of what the scammer asked for) and send it. A static website cannot
send email, so the page posts the fields to a tiny relay that runs **as the SAYNO team Google account**
(`sayoshield@gmail.com`). The email therefore always comes from the team address, and the reporter's name,
email address and IP address are never part of it.

```
visitor's browser  --(JSON fields, only after they press Send)-->  Apps Script web app (runs as sayoshield@gmail.com)
                                                                      |-- checks and rebuilds the email itself
                                                                      |-- MailApp.sendEmail  ->  team mailbox (copy)
                                                                      '-- ... and, for links / scam emails ->  reportphishing@apwg.org
```

Until the relay is switched on, the page shows **Copy report** and **Open in my email app** only, and the
Send button is disabled with an explanation.

## One-time setup (about 5 minutes, signed in as sayoshield@gmail.com)

1. Go to <https://script.google.com> and choose **New project**. Name it `SAYNO report relay`.
2. Delete the sample code and paste in the whole of `backend/report-relay.gs`.
3. Check `CONFIG` at the top (team address, recipients, the site address). Save.
4. **Deploy -> New deployment -> type: Web app**.
   - Execute as: **Me (sayoshield@gmail.com)**
   - Who has access: **Anyone**
5. Authorise when Google asks (it needs to send mail as you). "Advanced -> Go to SAYNO report relay (unsafe)" is
   normal for your own script.
6. Copy the **Web app URL** (it ends in `/exec`).
7. In this repo, open `static/assets/report-scam.js` and put the URL in the first line:
   `const REPORT_ENDPOINT = "https://script.google.com/macros/s/XXXX/exec";`
   then commit and push. (Or ask Claude to do steps 7 and the checks below.)
8. Test: open the live `/report-scam/` page, fill in a test link such as `https://example.com/test`, tick the consent
   box and press **Send report**. A copy arrives in the team mailbox within a minute. *Delete test reports so they are
   not forwarded in real life: a test with a link also goes to APWG, so use a clearly fake address such as
   `https://sayno-test.invalid/` while testing, or temporarily set `EXTERNAL_RECIPIENTS` to `[]`.*

## What the relay does and does not do

| It does | It does not |
|---|---|
| Send from the team address with `MailApp` | Receive the reporter's name, email address or IP address (Apps Script does not expose them) |
| Validate every field and cap its length; remove control characters (stops header injection) | Trust the browser's preview text: it rebuilds the email itself |
| Choose recipients itself. Nothing in the request can add a recipient | Accept free-form recipients, attachments or HTML |
| Send links and scam emails to the anti-phishing organisations; keep texts and calls without a link with the team | Forward phone-number-only reports to web block lists (they cannot be listed) |
| Ignore requests that fill the hidden honeypot field | Show a robot check (see "Hardening" below) |
| Cap total volume (`MAX_PER_HOUR`) and drop repeats of the same link or number for 6 hours | |

## Limits and housekeeping

- A consumer Gmail account can send roughly **100 recipients per day** with `MailApp`. The hourly cap protects this.
- Every report is also in the team mailbox. Delete reports on request (the privacy page promises this).
- To change recipients, edit `EXTERNAL_RECIPIENTS` and re-deploy (**Deploy -> Manage deployments -> edit -> New version**).
  The URL stays the same.
- To switch the feature off, set `REPORT_ENDPOINT` back to `""` and push, or disable the deployment.
- Netcraft also takes email reports, but we have not confirmed a current address; add it to `EXTERNAL_RECIPIENTS`
  only after checking their site. Google Safe Browsing and the Canadian Anti-Fraud Centre have web forms only, which is why
  the result pages and the report page link to them.

## Hardening you can add later

- A bot check such as Cloudflare Turnstile needs a server that can verify the token; Apps Script can do this with
  `UrlFetchApp`, but it needs a Cloudflare account and a secret.
- Only accept reports for links that SAYNO itself rated as risky (the page would send the rating, which the browser could fake, so this
  reduces accidents rather than stopping a determined abuser).

## Tests

`node tests/report_relay.test.mjs` runs the relay's validation and email-building code without any Google services.
CI runs it on every push.
