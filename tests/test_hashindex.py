"""Tests for the privacy-preserving block-list index (server/shieldlib/hashindex.py)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))

from shieldlib.hashindex import CATEGORIES, HashIndex, sha  # noqa: E402


class FakeIntel:
    def snapshot(self):
        return [
            ("urls", "phishing", {"urls": {"evil.example/login", "github.com/evil/mal.exe"},
                                  "hosts": {"evil.example": 1, "github.com": 500}, "domains": set()}),
            ("domains", "malware", {"urls": set(), "hosts": {}, "domains": {"bad-domain.test", "worse.test"}}),
            ("email_domains", "disposable", {"urls": set(), "hosts": {}, "domains": {"throwaway.test"}}),
        ]


class HashIndexTests(unittest.TestCase):
    def setUp(self):
        self.index = HashIndex()
        self.index.rebuild(FakeIntel())

    def lookup(self, text):
        """What the extension does: find the full hash inside the shard for its first byte."""
        h = sha(text)
        shard = self.index.shard(h[0])
        cat = shard.get(h[1:].hex())
        return None if cat is None else CATEGORIES[cat]

    def test_exact_link_host_domain_and_disposable_are_found_with_their_category(self):
        self.assertEqual(self.lookup("u:evil.example/login"), "phishing")
        self.assertEqual(self.lookup("h:evil.example"), "phishing")
        self.assertEqual(self.lookup("d:bad-domain.test"), "malware")
        self.assertEqual(self.lookup("x:throwaway.test"), "disposable")

    def test_shared_platform_host_is_never_listed_but_its_exact_bad_link_is(self):
        self.assertIsNone(self.lookup("h:github.com"))
        self.assertEqual(self.lookup("u:github.com/evil/mal.exe"), "phishing")

    def test_unlisted_things_are_not_found(self):
        self.assertIsNone(self.lookup("u:example.com/"))
        self.assertIsNone(self.lookup("d:example.com"))

    def test_prefix_list_is_sorted_unique_four_byte_records_covering_every_entry(self):
        version, blob = self.index.prefix_list()
        self.assertEqual(len(blob) % 4, 0)
        prefixes = [blob[i:i + 4] for i in range(0, len(blob), 4)]
        self.assertEqual(prefixes, sorted(set(prefixes)))
        self.assertTrue(version and version != "0")
        self.assertEqual(self.index.count, 6)  # 2 exact links + 1 host (github.com is shared) + 2 domains + 1 disposable
        for text in ("u:evil.example/login", "d:worse.test", "x:throwaway.test"):
            self.assertIn(sha(text)[:4], prefixes)

    def test_shards_partition_all_entries(self):
        total = sum(len(self.index.shard(b)) for b in range(256))
        self.assertEqual(total, self.index.count)

    def test_static_files_are_written(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as out:
            self.index.write_static(out)
            self.assertTrue(os.path.getsize(os.path.join(out, "v1", "prefixes.bin")) > 0)
            self.assertEqual(len(os.listdir(os.path.join(out, "v1", "shards"))), 256)
            meta = json.load(open(os.path.join(out, "v1", "meta.json"), encoding="utf-8"))
            self.assertEqual((meta["entries"], meta["version"]), (6, self.index.version))
            b = sha("d:bad-domain.test")[0]
            shard = json.load(open(os.path.join(out, "v1", "shards", f"{b:02x}.json"), encoding="utf-8"))
            self.assertEqual(shard["c"][shard["h"][sha("d:bad-domain.test")[1:].hex()]], "malware")


if __name__ == "__main__":
    unittest.main()
