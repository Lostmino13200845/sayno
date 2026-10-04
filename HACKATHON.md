# SAYNO · Presenter notes (StormHacks)

The text for the submission form is in `docs/SUBMISSION.md`. This file is for presenting and the live demo.

## One-line pitch
> **SAYNO stops new bank customers from handing their card details to scammers. It explains why a message or page is risky and what to do next, and it checks everything on your own device.**

## The persona and the story
Maya, 24, is new to Canada. She gets an SMS: "Your new debit card is locked. Verify within 24 hours." It looks real and she is not sure. The story the product tells, in the same order as the demo:
1. She **checks the message** and learns it is HIGH RISK, and why.
2. She **checks the link** without opening it and learns the website is HIGH RISK.
3. Later she lands on that website by accident. **Card Guard** sees the card fields, stops her, and blocks the page.
4. She never types her card.

Every result answers three questions: what happened, why SAYNO did this, what to do now.

## Live demo script (about 3 minutes)
Before you start: install the extension (download it from the website, unzip, `chrome://extensions` → Developer mode → Load unpacked). Open these tabs: the home page, the message check (`/message-check/`), and `/demo/fake-bank.html` and `/demo/shop.html` on https://lostmino13200845.github.io/sayno/. Use the live site so nothing runs locally.

1. **(0:00) Hook:** show the fake SMS on the home page. "Would you click?"
2. **(0:20) Message check:** open the web scanner and paste the RBC text. It rates HIGH or CRITICAL and lists the reasons: urgency, a locked-card threat, new-card activation, a link imitating RBC. Point at "Do not click the link".
3. **(0:50) False alarms matter:** paste "Hi sweetie, dinner on Sunday at 6?". It comes back SAFE, and the page says safe does not guarantee trustworthy.
4. **(1:10) The trap:** open the fake-bank demo page. **Card Guard blocks it:** "It asks for your PIN… bank-style pressure… not your bank's website." Pause here, this is the wow moment.
5. **(1:50) No false alarm:** open the shop demo page, a normal checkout, and click the card field. No block, only a gentle reminder.
6. **(2:10) The privacy proof:** open the browser's developer tools, Network tab, and reload. "Look: the only requests are downloads of the public block list. Nothing about what I checked or visited is sent." (Be accurate: you will see `meta.json`, `prefixes.bin`, and rarely one small shard file.)
7. **(2:40) Close:** "600,000 known threats, refreshed every 15 minutes, free to host, and all of it checked on your device. Built for the people scammers target first."

**Backup plan:** record this the night before. The block lists are cached on the device after the first download, so the demo still works if the Wi-Fi fails.

## Judge Q&A
| Question | Answer |
|---|---|
| *How is this different from Google Safe Browsing?* | Safe Browsing knows a page only once it is listed. Card Guard reacts to behaviour: a page asking for your PIN is stopped even if it was created five minutes ago. We also check message text, handle Canada-specific scams, and explain why in plain language. |
| *Do you see my browsing history?* | No. Pages are hashed and checked on your device against a downloaded list. There is no server that receives your data. When a page matches the list, one small file named by a single hash byte is fetched, which does not reveal the page. |
| *Where is the data stored?* | On your device: your settings and the downloaded fingerprints. SAYNO stores nothing about what you check. |
| *False positives?* | We tested 246 popular addresses (banks, shops, Google, GitHub) with none flagged. The trusted list covers official bank domains and payment processors, every block says why, and "continue" is always available. |
| *How do you know the JavaScript and Python versions agree?* | One generator produces the shared word and brand lists, and 68 test cases run on every build in Ubuntu, macOS and Windows. A mismatch fails the build. |
| *Why an extension?* | Card Guard has to act on the page at the moment a card is asked for. Messages are checked in the extension popup, with right-click, or on the website. |
| *Business model?* | Free for individuals. Banks, credit unions and universities could offer it to new customers and international students. |
| *What would you do with more time?* | A usability study with international students, warnings in newcomers' languages, a domain-age signal, and a phone version for SMS. |

## Honest limitations
- Rules can miss cleverly worded scams. SAFE never means guaranteed.
- Lists refresh every 15 minutes, so very new scam sites are caught by behaviour and look-alike rules, not by a list.
- Card Guard stops the page by covering it; it does not cancel a form that was already submitted.
- The Chrome Web Store listing may still be in review. Until then the extension installs from a download.

## Day-of checklist
- [ ] The extension is loaded, and the toolbar icon is pinned.
- [ ] The four demo tabs are open and the live site loads on the venue Wi-Fi (test it on your phone's hotspot too).
- [ ] Browser zoom at 125%, notifications off, bookmarks bar hidden.
- [ ] A backup demo video on a USB stick and in the cloud.
- [ ] One teammate presents, one drives the demo, one handles Q&A.
