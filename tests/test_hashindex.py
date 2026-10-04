"""Tests for the privacy-preserving block-list index (server/shieldlib/hashindex.py)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))

from shieldlib.hashindex import HashIndex, sha  # noqa: E402


class FakeIntel:
    def snapshot(self):
        return [
            ("urls", "phishing", {"urls": {"evil.example/login", "github.com/evil/mal.exe"},
                                  "hosts": {"evil.example": 1, "github.com": 500}, "domains": set()}),
            ("domains", "malware", {"urls": set(), "hosts": {}, "domains": {"bad-domain.test", "worse.test"}}),
        ]


class HashIndexTests(unittest.TestCase):
    def setUp(self):
        self.index = HashIndex()
        self.index.rebuild(FakeIntel())

    def lookup(self, text):
        h = sha(text)
        return [(x, c) for x, c in self.index.lookup([h[:4]]) if x == h.hex()]

    def test_exact_link_host_and_domain_are_found_with_their_category(self):
        self.assertEqual(self.lookup("u:evil.example/login")[0][1], "phishing")
        self.assertEqual(self.lookup("h:evil.example")[0][1], "phishing")
        self.assertEqual(self.lookup("d:bad-domain.test")[0][1], "malware")

    def test_shared_platform_host_is_never_listed_but_its_exact_bad_link_is(self):
        self.assertEqual(self.lookup("h:github.com"), [])
        self.assertTrue(self.lookup("u:github.com/evil/mal.exe"))

    def test_unlisted_things_are_not_found(self):
        self.assertEqual(self.lookup("u:example.com/"), [])
        self.assertEqual(self.lookup("d:example.com"), [])

    def test_prefix_list_is_sorted_unique_four_byte_records(self):
        version, blob = self.index.prefix_list()
        self.assertEqual(len(blob) % 4, 0)
        prefixes = [blob[i:i + 4] for i in range(0, len(blob), 4)]
        self.assertEqual(prefixes, sorted(set(prefixes)))
        self.assertTrue(version and version != "0")
        self.assertEqual(self.index.count, 5)  # 2 exact links + 1 host (github.com is shared) + 2 domains

    def test_lookup_returns_nothing_for_unknown_prefix_and_caps_the_batch(self):
        self.assertEqual(self.index.lookup([b"\x00\x00\x00\x00"]), [])
        self.assertLessEqual(len(self.index.lookup([sha("u:evil.example/login")[:4]] * 200)), 500)


if __name__ == "__main__":
    unittest.main()
