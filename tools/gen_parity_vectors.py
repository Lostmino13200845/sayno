"""Writes tests/parity_vectors.json: what the Python engine says about a spread of links and messages. The
extension's on-device rules (extension/heuristics.js, extension/engine.js) must give identical answers;
tests/parity.test.mjs checks that. CI regenerates this file first, so a change to engine.py that is not
mirrored in the JavaScript fails the build.
Run:  python tools/gen_parity_vectors.py
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))
from shieldlib.engine import analyze, analyze_url  # noqa: E402

URLS = """https://github.com/torvalds/linux
https://docs.google.com/document/d/abc
https://www.rbcroyalbank.com/personal.html
https://www.amazon.ca/gp/css/order-history
https://www.paypal.com/signin
https://accounts.google.com/signin/v2/identifier
https://rbc-card-activation.help/secure
https://rbc-secure-verify.help/login
http://interac-deposit.top/claim
http://cra-refund-canada.xyz
https://paypa1-secure.com/login
https://paypaI.com/signin
https://amazon-login.s3.amazonaws.com/verify/account
https://paypal-secure.googleusercontent.com/login
https://раураl.com/login
http://3232235777/login
http://0xC0A80101/bank
http://192.168.1.5/login
http://1.2.3.4:8080/x
http://[::1]:8080/login
http://user@evil.example.com/
https://xn--80ak6aa92e.com/
bit.ly/3xYz
https://tinyurl.com/abc
https://a.b.c.d.e.example.com/
https://my-bank-secure-login-verify.example.com/
https://www.rbcroyalbank.com.verify-login.net/
https://rbcroyalbank.com.verify-login.net/login
https://paypal.com-login.net/signin
https://login.microsoftonline.com.evil.io/
https://www.google.com.au/
https://www.amazon.com.au/
https://my-office.com/
https://signin.paypal.com/
http://example.com:99999/x
http://example.com:abc/x
http://[bad/x
https://example.com/files/setup.exe
https://rnicrosoft-support.com
https://microsoft-support.online/verify
https://applesauce-recipes.com/
https://www.visa-info.org/canada-travel
https://td-tutoring.ca/
https://amazon-reviews-blog.com/best
http://sub.domain.co.uk/login
https://login.paypal.com.evil.top/x
example.com
www.example.org/path?x=1
http://...
http://.com
https://very-long-example-domain.com/""" + "a" * 130

TEXTS = [
    "RBC: Your new debit card is not yet activated and has been temporarily locked. Activate your card within 24 hours at https://rbc-card-activation.help/secure to avoid suspension.",
    "RBC: Your debit card has been temporarily locked. Verify your card within 24 hours at https://rbc-secure-verify.help/login",
    "INTERAC e-Transfer: You have received $1,250.00 CAD. Your e-transfer is pending - deposit your funds here: http://interac-deposit.top/claim?id=88213. Enter your card number and PIN to accept the payment.",
    "Canada Revenue Agency: you are eligible for a tax refund of $468.20. Confirm your SIN and banking details at http://cra-refund-canada.xyz within 48 hours.",
    "URGENT: your PayPal account is suspended. Verify now https://paypa1-secure.com/login",
    "From notify@interac-etransfer.online: your e-transfer is pending, act within 24 hours",
    "Hi sweetie, dinner on Sunday at 6? Dad is making lasagna",
    "Your Microsoft order has shipped. View at https://account.microsoft.com/orders",
    "Urgent: please review the doc before 5pm https://applesauce-recipes.com/",
    "RBC: your statement is ready, please review within 3 days at https://www.rbcroyalbank.com/statements",
    "Hi mum, this is my new number, I lost my phone. Please send $500 by e-transfer, don't tell dad",
    "Congratulations! You have won the lottery jackpot. Claim your prize now: bit.ly/3xYz",
    "Your parcel is on hold. Pay the customs fee at https://dhl-delivery-track.xyz/pay",
    "Please install AnyDesk so our support agent can fix your account. Keep this confidential.",
    "Dear customer, unauthorized login detected. Sign in at https://micros0ft-account.com/login to confirm your password.",
    "Verify your account at rbc-secure[.]com/login now, urgent",
    "hxxps://paypal-help.top/login and also contact support@paypal-help.top",
    "Lunch at noon? My email is sara@outlook.com and the menu is at https://www.amazon.com/dp/B08N5WRWNW",
    "Reminder: your password policy changes next week.",
    "Gift cards or bitcoin only. Wire transfer via Western Union. Processing fee required immediately.",
    "John from payroll@amaz0n-hr.club needs your SSN and card number within 24 hours or the account will be closed",
    "",
    "a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a." * 5,
    "Check https://github.com/torvalds/linux and docs.google.com/document/d/abc",
    "Your Interac e-Transfer is awaiting deposit at https://interac.ca/etransfer and from interac@mail.example.com",
]


class NoIntel:
    """No block lists: the on-device rules are compared without them (lists are tested separately)."""
    def lookup_url(self, url):
        return []

    def lookup_email_domain(self, domain):
        return {"disposable": False, "blocklisted": None}


def brief(r):
    return {"score": r["score"], "level": r["level"], "findings": [[f["weight"], f["message"]] for f in r["findings"]]}


def main():
    urls = []
    for u in URLS.split("\n"):
        r = analyze_url(u, NoIntel())
        urls.append({"url": u, **brief(r)})
    texts = []
    for t in TEXTS:
        r = analyze(t, NoIntel())
        texts.append({
            "text": t, "score": r["score"], "level": r["level"],
            "textScore": r["text"]["score"],
            "textFindings": [[f["weight"], f["message"]] for f in r["text"]["findings"]],
            "urls": [brief(u) | {"url": u["url"]} for u in r["urls"]],
            "emails": [brief(e) | {"email": e["email"]} for e in r["emails"]],
            "advice": r["advice"],
        })
    out = os.path.join(ROOT, "tests", "parity_vectors.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"urls": urls, "texts": texts}, f, ensure_ascii=False, indent=1)
    print(len(urls), "link vectors and", len(texts), "message vectors written")


if __name__ == "__main__":
    main()
