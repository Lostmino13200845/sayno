"""Offline unit tests for the scoring engine and the block-list lookups.
Run:  python -m unittest discover -s tests -v     (from the project root; needs no network)"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))

from shieldlib import analyze, is_reportable  # noqa: E402
from shieldlib.intel import ThreatIntel, is_shared_host  # noqa: E402


class NoIntel:
    """An empty threat database, so these tests exercise only the heuristics."""
    def lookup_url(self, url):
        return []

    def lookup_email_domain(self, domain):
        return {"disposable": False, "blocklisted": None}


def score(text):
    return analyze(text, NoIntel())["score"]


class ScamsAreHigh(unittest.TestCase):
    def test_rbc_card_locked_sms(self):
        self.assertGreaterEqual(score(
            "RBC: Your new debit card is not yet activated and has been temporarily locked. Activate your card "
            "within 24 hours at https://rbc-card-activation.help/secure to avoid suspension."), 70)

    def test_rbc_variant_not_left_at_medium(self):
        self.assertGreaterEqual(score(
            "RBC: Your debit card has been temporarily locked. Verify your card within 24 hours at "
            "https://rbc-secure-verify.help/login"), 70)

    def test_interac_etransfer(self):
        self.assertGreaterEqual(score(
            "INTERAC e-Transfer: You have received $1,250.00 CAD. Your e-transfer is pending - deposit your funds "
            "here: http://interac-deposit.top/claim?id=88213. Enter your card number and PIN to accept the payment."), 70)

    def test_cra_refund(self):
        self.assertGreaterEqual(score(
            "Canada Revenue Agency: you are eligible for a tax refund of $468.20. Confirm your SIN and banking "
            "details at http://cra-refund-canada.xyz within 48 hours."), 70)

    def test_lookalike_sender(self):
        self.assertGreaterEqual(score("From notify@interac-etransfer.online: your e-transfer is pending, act within 24 hours"), 70)


class DisguisedLinks(unittest.TestCase):
    def test_free_hosting_with_brand_name(self):
        self.assertGreaterEqual(score("https://amazon-login.s3.amazonaws.com/verify/account"), 35)

    def test_cyrillic_lookalike(self):
        self.assertGreaterEqual(score("https://раураl.com/login"), 35)

    def test_capital_i_lookalike(self):
        self.assertGreaterEqual(score("https://paypaI.com/signin"), 35)

    def test_decimal_and_hex_ip(self):
        self.assertGreaterEqual(score("http://3232235777/login"), 35)
        self.assertGreaterEqual(score("http://0xC0A80101/bank"), 35)


class LegitStaysLow(unittest.TestCase):
    def test_real_sites(self):
        for url in ["https://www.rbcroyalbank.com/personal.html", "https://www.amazon.ca/gp/css/order-history",
                    "https://www.paypal.com/signin", "https://github.com/torvalds/linux",
                    "https://docs.google.com/document/d/abc", "https://www.youtube.com/watch?v=abc"]:
            with self.subTest(url=url):
                self.assertLess(score(url), 35)

    def test_ordinary_messages(self):
        self.assertLess(score("Hi sweetie, dinner on Sunday at 6? Dad is making lasagna"), 15)
        self.assertLess(score("Your Microsoft order has shipped. View at https://account.microsoft.com/orders"), 35)

    def test_urgent_message_with_unrelated_link_is_not_high(self):
        self.assertLess(score("Urgent: please review the doc before 5pm https://applesauce-recipes.com/"), 70)

    def test_real_bank_notice_is_not_high(self):
        self.assertLess(score("RBC: your statement is ready, please review within 3 days at "
                              "https://www.rbcroyalbank.com/statements"), 70)


class BlockListLookups(unittest.TestCase):
    def make_intel(self):
        intel = ThreatIntel()
        intel._data = {"urlhaus": {"urls": {"github.com/evil/malware.exe", "badsite.example/x"},
                                   "hosts": {"github.com": 878, "badsite.example": 1},
                                   "domains": set()}}
        return intel

    def test_shared_host_helper(self):
        self.assertTrue(is_shared_host("raw.githubusercontent.com"))
        self.assertTrue(is_shared_host("docs.google.com"))
        self.assertFalse(is_shared_host("badsite.example"))

    def test_shared_host_not_condemned_for_other_pages(self):
        intel = self.make_intel()
        self.assertEqual(intel.lookup_url("https://github.com/torvalds/linux"), [])

    def test_shared_host_exact_bad_link_still_caught(self):
        intel = self.make_intel()
        self.assertTrue(intel.lookup_url("https://github.com/evil/malware.exe"))

    def test_small_site_with_a_bad_link_is_still_flagged_as_a_whole(self):
        intel = self.make_intel()
        self.assertTrue(intel.lookup_url("https://badsite.example/other/page"))


class HostileInput(unittest.TestCase):
    """Inputs that once kept the server busy for minutes (regex backtracking) must stay fast."""

    def assert_fast(self, text, limit=3.0):
        start = time.time()
        analyze(text, NoIntel())
        self.assertLess(time.time() - start, limit)

    def test_dotted_labels(self):
        self.assert_fast("a." * 20000)

    def test_email_like_runs(self):
        self.assert_fast("a" * 100000)
        self.assert_fast("@" * 50000)
        self.assert_fast("a.b@" * 20000)

    def test_odd_hosts_do_not_crash(self):
        for text in ["http://[bad/x", "http://... http://.com", "http://a.com:99999/x", "\x00\x00 pin", ""]:
            with self.subTest(text=text):
                analyze(text, NoIntel())


class Reporting(unittest.TestCase):
    def test_private_addresses_never_reportable(self):
        r = analyze("urgent: verify your card http://192.168.1.5/login", NoIntel())
        self.assertFalse(any(is_reportable(u, r, 0) for u in r["urls"]))



class EmbeddedOfficialAddress(unittest.TestCase):
    """A real brand address used inside someone else's domain is a classic phishing disguise."""

    class _NoThreats:
        def lookup_url(self, url):
            return []

    def level(self, url):
        from shieldlib.engine import analyze_url
        return analyze_url(url, self._NoThreats())["level"]

    def test_brand_address_inside_another_domain_is_high_or_worse(self):
        for url in ("https://www.rbcroyalbank.com.verify-login.net/", "https://paypal.com-login.net/signin",
                    "https://login.microsoftonline.com.evil.io/"):
            self.assertIn(self.level(url), ("high", "critical"), url)

    def test_real_and_unrelated_domains_are_not_flagged_by_this_rule(self):
        from shieldlib.engine import analyze_url
        for url in ("https://www.rbcroyalbank.com/personal.html", "https://signin.paypal.com/", "https://my-office.com/",
                    "https://www.amazon.com.au/", "https://www.google.com.au/", "https://example.com/"):
            findings = analyze_url(url, self._NoThreats())["findings"]
            self.assertFalse([f for f in findings if "inside a different website" in f["message"]], url)


if __name__ == "__main__":
    unittest.main()
