# Scam Shield · Design handoff (for UI/UX)

Everything visual in Scam Shield (website, tutorial, web scanner and browser extension) is built from **one design system**. You can restyle the whole product by editing CSS in `design/`, without touching any logic.

## 1. See it live
Start the server (`start.bat`), then open:

| Page | URL | What it is |
|---|---|---|
| Website + tutorial | http://127.0.0.1:8765/ | Landing page, interactive tutorial, options, install |
| Tutorial only | http://127.0.0.1:8765/tutorial | Full-screen tutorial, good for the pitch or usability tests |
| Jump to a step | http://127.0.0.1:8765/tutorial#tutorial-9 | Opens step 9 directly (1–12) |
| **Design system** | http://127.0.0.1:8765/design | Every colour, type size, component and extension screen in all states, plus a dark-mode toggle |
| Web scanner | http://127.0.0.1:8765/app | Paste-and-scan app, password check, safety checklist |
| Card Guard demo | http://127.0.0.1:8765/demo/fake-bank.html | Real block screen (needs the extension loaded) |

## 2. Where to edit
| I want to change… | Edit | Notes |
|---|---|---|
| Colours, fonts, spacing, radius, shadows, motion | `design/tokens.css` | Light theme on `:root`, dark theme below it; change a token once and it applies everywhere |
| Buttons, level chips, badges, toggles, inputs, cards, findings list | `design/components.css` | Classes start with `ss-` |
| Extension popup layout | `design/popup.css` + `extension/popup.html` | Classes start with `pp-` |
| Card Guard block screen, toast, right-click result panel | `design/overlay.css` + markup in `extension/content.js` (search `ov-`) | Rendered in a closed shadow DOM, so web pages can't restyle it |
| Website & tutorial layout | `design/site.css` + `static/site/index.html` | Tutorial wording lives in `static/assets/tutorial.js` → `STEPS` |
| Icons | `extension/icons/*.png` (16/48/128 px) | Also copy into `static/assets/shield-48.png` / `shield-128.png` |

**After every CSS change:** run `py tools/sync_design.py`. It copies `design/*.css` into the website (`static/assets/`) and the extension (`extension/ui/`). Never edit those copies; they get overwritten.
- Website: just refresh the browser.
- Extension: open `edge://extensions` and press ↻ (reload) on Scam Shield.

## 3. Screens & states to design
**Extension popup:** safe site · risky site (medium / high / critical) · "not rated" / server offline · message pasted → result · My bank(s) expanded · toggles on/off.

**Card Guard (in-page):**
1. **Block screen:** 1 to 4 reasons, primary "Get me out of here", secondary "continue anyway"
2. **Toast:** gentle reminder when typing a card on a normal shop
3. **Result panel:** after right-click → "Check with Scam Shield"

**On-screen notification** (Windows/macOS system notification, styled by the OS, so we only control the icon, title, text and 2 buttons): not secure (http) · risky / known scam (stays until dismissed) · "don't type your password/card here" · test notification. Plus the **permission card** on the welcome page (before allow / allowed / declined) and the popup switch with its "not allowed" hint.

**Toolbar badge:** none (safe) · `!` medium · `!!` high · `✖` critical · `off` offline. Chrome/Edge badges only allow ~4 characters and a background colour.

**Website:** hero · how it works · tutorial (12 steps) · options · install · safety tips · footer.

## 4. Constraints to keep in mind
- **Colour is never the only signal.** Every risk level also has a word or symbol (SAFE, !, !!, ✖), because users may be colour-blind.
- **Contrast:** keep text at WCAG AA (4.5:1) or better in both themes. The `/design` page has a dark/light toggle for checking.
- **Popup width** is fixed by the browser at up to 800 × 600 px. We use 360 px wide.
- **The block screen must stay alarming** but calm: one clear safe action, no dark patterns on "continue anyway".
- **Audience:** newcomers and international students, often reading in a second language. Short sentences, no jargon ("phishing" → "fake bank page").
- **Motion:** respect `prefers-reduced-motion` (already wired in; keep it).
- **Fake bank / shop pages in the tutorial** are deliberately *not* themed, because they imitate third-party sites.

## 5. Ideas worth exploring
- A friendlier illustration or mascot for the hero instead of the phone mockup.
- A Figma library that mirrors the tokens (same names: `ss-brand-600`, `ss-critical`, …) so design ↔ code stays 1:1.
- Translate the block screen (Mandarin, Punjabi, Farsi, Hindi, Korean, Tagalog, Spanish) and test the layout with longer strings.
- A quick usability test with 3–5 international students on `/tutorial`: can they find the shield, paste a message and leave the fake page without help?
