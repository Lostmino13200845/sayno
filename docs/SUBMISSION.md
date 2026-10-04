# SAYNO · Hackathon submission text (copy each block into the form)

Fill the `[brackets]` before you submit. Everything else matches what the product does today.

## Project name
SAYNO – Card Guard

## Tagline (about 60 characters)
Stop card scams before you type. All checked on your device.

## Elevator pitch (about 200 characters)
SAYNO is a browser extension and website that stops new bank customers from handing their card details to scammers. It explains why a message or page is risky and what to do next, and checks it all on your device.

## Try it out (links)
- Live website and web scanner: https://lostmino13200845.github.io/sayno/
- Practice tutorial: https://lostmino13200845.github.io/sayno/tutorial/
- Extension download (unzip, then Load unpacked): https://lostmino13200845.github.io/sayno/download/sayno-extension.zip
- Privacy policy: https://lostmino13200845.github.io/sayno/privacy/
- Source code: https://github.com/Lostmino13200845/sayno
- Chrome Web Store: [add the link once Google approves it]
- Demo video: [add the link]

---

## About the project

### Inspiration
Every September thousands of international students and newcomers open their first Canadian bank account. They do not yet know what their bank's real messages look like, and they are expecting messages like "activate your new card". Scammers know this. A text saying "your new debit card is locked, verify within 24 hours" leads to a fake bank page that asks for the card number, CVV, expiry and PIN. Our persona, Maya, is 24 and new to Canada. She thinks: "It looks real. I just don't know if I should trust it." SAYNO answers that question in plain language, before she gives anything away. [Add one verified statistic from the Canadian Anti-Fraud Centre.]

### What it does
SAYNO is one protection layer with three checks, built around CHECK, UNDERSTAND, ACT.
- **Message check:** paste or right-click a suspicious text or email. SAYNO looks for pressure, threats, requests for card details, government and bank impersonation and look-alike links, then says what it found, why, and what to do now.
- **Website check:** the extension rates each page you open. It spots look-alike and disguised addresses, risky endings and known dangerous sites from public threat lists, and shows the result on its icon.
- **Card Guard:** if a page asks for a card number, CVV or PIN and it is not one of your banks or a known payment provider, SAYNO stops you before you type, explains why, and makes "leave this page" the biggest button.

Every result is written in plain words. HIGH RISK and SAFE never rely on colour alone, and SAFE always says it does not guarantee trustworthy.

### Privacy by design
Everything is checked on the device. The pages you visit, the text you check and the card numbers you type are never uploaded. There is no server that receives your data and no account. The extension downloads public block lists as hashed files and compares them locally. When a page matches the local list, it fetches one small file named by a single hash byte, which does not reveal the page. The website scanner works the same way, and the password check sends only the first 5 characters of a hash to Have I Been Pwned.

### How we built it
- **Detection engine:** a rule-based scorer (14 scam-language rule groups, 53 brand names and aliases, including the major Canadian banks, 34 risky endings, link forensics for look-alike letters, disguised IP addresses and free-hosting fakes). It is written once in Python and again in JavaScript for the device, and 68 test cases check that both give identical answers on every build.
- **Block lists:** 600,000+ entries from 7 public feeds (URLhaus, ThreatFox, OpenPhish, Phishing Army, CERT Polska, Phishing.Database and a disposable-email list). A GitHub Actions workflow refreshes them every 3 hours, hashes them and publishes 256 small files plus a 2.4 MB prefix list on GitHub Pages. The extension never sends a page to a server: it hashes on the device (the same idea as Google Safe Browsing).
- **Extension:** Manifest V3, plain JavaScript, no dependencies.
- **Website:** static HTML, CSS and JavaScript (also on GitHub Pages) with a practice tutorial and the web scanner. A Python standard-library server is included for local use.
- **Quality:** 27 automated tests, a smoke test of the real server, and continuous checks on Ubuntu, macOS and Windows. An accessibility scan (axe, WCAG AA) reports zero violations on every page, in light and dark mode.
- **Design:** grayscale wireframes for the full website and the product journey, with a clickable prototype.

### Challenges we ran into
- Keeping real protection and real privacy together: a hosted checker would have seen everyone's browsing, so we rebuilt it so the server learns nothing.
- False alarms. Our first version rated github.com and Google Docs as dangerous because malware feeds list single files hosted there. We fixed it by matching only exact bad links on big shared platforms, and checked 246 popular addresses with no false alarms.
- Look-alike tricks: Cyrillic letters, a capital "I" posing as "l", numeric IP addresses and scam pages hosted on cloud storage.
- Making a SAFE result honest, and writing risk messages that reassure instead of frighten.

### Accomplishments that we're proud of
- It works end to end: from a scam text to a blocked fake bank page, without sending anything off the device.
- The device and the website run the same tested engine.
- It is free to host: no servers to run or pay for.
- Zero accessibility violations in an automated WCAG AA scan.

### What we learned
Security tools earn trust by collecting less, not more. Explaining why matters as much as the verdict. Small details, such as making the safest action the largest button, change what people do.

### What's next
- Publish on the Chrome Web Store and Edge Add-ons.
- A usability study with international students, and warnings in the languages newcomers speak.
- A domain-age signal (most phishing sites are days old) and early warning from certificate logs.
- A phone version for SMS, where most of these scams arrive.
- A pilot with a university or credit union as part of new-customer onboarding.

## Built with
JavaScript, Python, HTML, CSS, Chrome Extension Manifest V3, GitHub Actions, GitHub Pages, SHA-256 hash-prefix lookups, Playwright (testing), URLhaus, ThreatFox, OpenPhish, Phishing Army, CERT Polska, Phishing.Database, Have I Been Pwned (k-anonymity)

## Team
[Names, roles and links]

---

## Honest limitations (say them before a judge does)
- Rules can miss cleverly worded scams, and a brand-new site that asks for nothing sensitive may pass. SAFE is never a guarantee.
- The block lists refresh every 3 hours, so a site that went live minutes ago is judged by its look and behaviour, not by a list.
- Card Guard blocks a page that asks for card details by covering it and moving focus; it does not cancel a form that was already submitted.
- The Chrome Web Store version is [pending review / live]. Until then the extension installs from a download.

## Upload checklist
- [ ] Cover image: `sayno-hackathon-submission/cover-1500x1000.png`
- [ ] Gallery: the three extension screenshots, then the wireframe pages from `wireframes/`
- [ ] Demo video (2 to 3 minutes, script in `HACKATHON.md`) uploaded to YouTube or Vimeo, link added above
- [ ] GitHub repo link works while logged out (the repo is public)
- [ ] Live site opens on a phone and in a private window
- [ ] Team members added to the submission and all agree to submit
- [ ] Check the hackathon's rules on AI-assisted work and disclose it if required: SAYNO was built with the help of Claude Code
