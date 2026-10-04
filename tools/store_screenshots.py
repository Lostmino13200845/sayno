"""Takes the 1280x800 screenshots the Chrome Web Store asks for, using the real extension on the demo pages.

Needs the local SAYNO server running (start.bat / start.sh) and Playwright:
    pip install playwright && python -m playwright install chromium
    python tools/store_screenshots.py            ->  dist/screenshots/*.png
"""
import os
import sys
import tempfile
import time

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sys.exit("Playwright is not installed: pip install playwright && python -m playwright install chromium")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXT = os.path.join(ROOT, "extension")
OUT = os.path.join(ROOT, "dist", "screenshots")
BASE = "http://127.0.0.1:8765"
SMS = ("RBC: Your new debit card is not yet activated and has been temporarily locked. Activate your card within "
       "24 hours at https://rbc-card-activation.help/secure to avoid suspension.")


def main():
    os.makedirs(OUT, exist_ok=True)
    with sync_playwright() as p:
        ctx = p.chromium.launch_persistent_context(
            tempfile.mkdtemp(prefix="sayno-shots-"), headless=False, viewport={"width": 1280, "height": 800},
            args=[f"--disable-extensions-except={EXT}", f"--load-extension={EXT}"])
        time.sleep(5)
        sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker")
        ext_id = sw.url.split("/")[2]

        # 1. Card Guard stopping a fake bank page
        # Served under a believable fake address so the warning reads like the real thing (not "127.0.0.1").
        with open(os.path.join(ROOT, "static", "demo", "fake-bank.html"), "rb") as f:
            fake_bank = f.read()
        ctx.route("https://northpeak-card-verify.example/**",
                  lambda r: r.fulfill(status=200, content_type="text/html", body=fake_bank))
        page = ctx.new_page()
        page.goto("https://northpeak-card-verify.example/verify")
        time.sleep(3)
        page.screenshot(path=os.path.join(OUT, "1-card-guard.png"))

        # 2. "Check this text with SAYNO" result on the message demo
        inbox = ctx.new_page()
        inbox.goto(BASE + "/demo/inbox.html")
        time.sleep(1)
        inbox.evaluate("""(text) => { const el = [...document.querySelectorAll('body *')]
            .filter(e => e.textContent.includes(text.slice(0, 30)) && ![...e.children].some(c => c.textContent.includes(text.slice(0, 30)))).pop();
            const r = document.createRange(); r.selectNodeContents(el); const s = getSelection(); s.removeAllRanges(); s.addRange(r); }""", SMS)
        helper = ctx.new_page()  # an extension page can message tabs, like the context-menu handler does
        helper.goto(f"chrome-extension://{ext_id}/popup.html")
        time.sleep(1)
        helper.evaluate("""async (text) => {
            const res = await new Promise(r => chrome.runtime.sendMessage({ type: 'scan', text }, r));
            res.result.reported = 0;  // the public server never files reports, so the screenshot must not claim it
            const [tab] = await chrome.tabs.query({ url: '*://127.0.0.1/demo/inbox.html' });
            await chrome.tabs.sendMessage(tab.id, { type: 'scanResult', result: res.result, text });
        }""", SMS)
        inbox.bring_to_front()
        time.sleep(1.2)
        inbox.screenshot(path=os.path.join(OUT, "2-message-check.png"))

        # 3. The popup, as shown in the website's practice browser
        tour = ctx.new_page()
        tour.goto(BASE + "/tutorial")
        time.sleep(1.5)
        tour.click("#mExt", force=True)
        tour.click("#pTxt", force=True)
        time.sleep(2)
        tour.screenshot(path=os.path.join(OUT, "3-popup.png"))
        ctx.close()
    for name in sorted(os.listdir(OUT)):
        print("wrote", os.path.join("dist", "screenshots", name))


if __name__ == "__main__":
    main()
