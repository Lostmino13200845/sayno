# Chrome Web Store listing text (copy into the developer dashboard)

## Name
SAYNO – Card Guard

## Short description (max 132 characters)
Blocks fake bank pages before you type your card, and checks suspicious messages. Everything stays on your device.

## Detailed description
SAYNO protects new bank customers and anyone who gets "your card is locked" messages from the scams that target them.

WHAT IT DOES
• Card Guard: if a page asks for your card number, CVV or PIN and it is not your bank or a known payment provider, SAYNO stops you before you type, and tells you why in plain words.
• Site check: every page is rated on the toolbar icon (safe, caution, danger) using warning signs in the link and a list of hundreds of thousands of known phishing and malware addresses that is refreshed every few hours.
• Message check: select any text or link, right-click, and choose "Check this text with SAYNO" to get a danger score and the reasons. Or paste it into the popup.
• New-account mode: extra warnings for people who just opened a bank account, when scammers strike most ("activate your new card", "pending e-Transfer", "tax refund").

PRIVATE BY DESIGN
SAYNO checks everything on your device. The pages you visit, the text you check and the card numbers you type are never sent anywhere. The extension only downloads public block-list files; when a page matches the list it fetches one small file named by a single hash byte, which does not reveal the page. No accounts, no ads, no tracking, no server that receives your data.

Block lists: URLhaus, ThreatFox, OpenPhish, Phishing Army, CERT Polska, Phishing.Database.

## Category
Privacy & Security (or Productivity if that is not offered).

## Single purpose (required)
Protect users from phishing and card-theft scams by rating web pages and blocking fake pages that ask for card details.

## Permission justifications
- **Host permission: all websites (content script)** – Needed to see whether any page the user opens asks for card details and to show the warning on that page. Page content is analysed on the device and is not sent anywhere.
- **Host permission: the SAYNO block-list host (GitHub Pages)** – Downloads the static block-list files (meta.json, prefixes.bin and small shard files). Nothing about the user or their browsing is uploaded.
- **tabs** – Shows each tab's rating on the toolbar icon and re-checks a tab after in-page navigation.
- **storage** – Saves the user's settings (chosen bank, switches) and the block-list fingerprints used for local checks.
- **alarms** – Checks for a new block list every 30 minutes.
- **contextMenus** – Adds "Check this text / link with SAYNO" to the right-click menu.
- **notifications (optional)** – Only after the user switches it on: warns about unencrypted pages.
- **Optional host permissions** – Only if the user enters their own block-list address in Advanced settings.
- **Remote code** – None. All code ships in the package.

## Data usage disclosures (Privacy tab)
Answer the questionnaire like this (it matches `static/site/privacy.html`):
- *Web history, website content, personally identifiable information, health, financial and payment information, authentication information, personal communications, location, user activity*: **Not collected.** Everything is processed on the device.
Then certify the three statements: data is not sold to third parties, not used or transferred for purposes unrelated to the single purpose, and not used for creditworthiness or lending.
Privacy policy URL: `https://<user>.github.io/<repo>/privacy/`

## Screenshots (1280×800)
`python tools/store_screenshots.py` writes them to `dist/screenshots/`: the card-guard block, the message result, and the popup.
