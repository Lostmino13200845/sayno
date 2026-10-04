import importlib.util
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class SitePagesTable(unittest.TestCase):
    def test_app_and_build_site_agree(self):
        def table(path):
            src = open(os.path.join(ROOT, path), encoding="utf-8").read()
            m = re.search(r"SITE_PAGES = (\{.*?\})\n", src, re.S)
            return eval(m.group(1))
        self.assertEqual(table("server/app.py"), table("tools/build_site.py"))

    def test_every_page_exists(self):
        src = open(os.path.join(ROOT, "tools/build_site.py"), encoding="utf-8").read()
        for name in re.findall(r'"([a-z-]+)"', re.search(r"SITE_PAGES = (\{.*?\})\n", src, re.S).group(1)):
            if name:
                self.assertTrue(os.path.exists(os.path.join(ROOT, "static/pages", name + ".html")))


if __name__ == "__main__":
    unittest.main()
