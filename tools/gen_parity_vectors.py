"""Writes tests/parity_vectors.json: what the Python engine says about a spread of links. The extension's
on-device rules (extension/heuristics.js) must give identical answers; tests/parity.test.mjs checks that.
CI regenerates this file first, so a change to engine.py that is not mirrored in the JS fails the build.
Run:  python tools/gen_parity_vectors.py
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))
from shieldlib.engine import analyze_url  # noqa: E402

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


class NoIntel:
    def lookup_url(self, url):
        return []


def main():
    vectors = []
    for u in URLS.split("\n"):
        r = analyze_url(u, NoIntel())
        vectors.append({"url": u, "score": r["score"], "level": r["level"],
                        "findings": [[f["weight"], f["message"]] for f in r["findings"]]})
    with open(os.path.join(ROOT, "tests", "parity_vectors.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(vectors, f, ensure_ascii=False, indent=1)
    print(len(vectors), "vectors written")


if __name__ == "__main__":
    main()
