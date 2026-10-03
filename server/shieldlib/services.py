"""Optional online reputation lookups, and the back-end job that reports
high-risk links to external takedown services automatically."""
import base64
import json
import urllib.error
import urllib.parse
import urllib.request

from ._store import USER_AGENT
from .engine import is_private_host
from .intel import host_of


def _http(method, url, body=None, headers=None, timeout=20):
    h = {"User-Agent": USER_AGENT, **(headers or {})}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            return r.status, raw
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


# ------------------------------------------------------------------ lookups
class OnlineChecker:
    """Reputation APIs. Each is used only if configured."""

    def __init__(self, cfg):
        self.cfg = cfg

    def enrich(self, url_results, email_results):
        keys = self.cfg.get("api_keys", {})
        if keys.get("google_safe_browsing") and url_results:
            self._safe_browsing(keys["google_safe_browsing"], url_results)
        if keys.get("virustotal"):
            for r in url_results[:4]:  # free tier: 4 requests / minute
                self._virustotal(keys["virustotal"], r)
        if self.cfg.get("check_emails_stopforumspam"):
            for r in email_results:
                self._stopforumspam(r)
        for r in url_results + email_results:
            r["score"] = min(100, sum(f["weight"] for f in r["findings"]))

    @staticmethod
    def _add(result, weight, msg, sev="danger"):
        result["findings"].append({"weight": weight, "message": msg, "severity": sev})

    def _safe_browsing(self, key, url_results):
        body = {
            "client": {"clientId": "sayno", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": r["url"]} for r in url_results],
            },
        }
        try:
            status, raw = _http("POST", "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="
                                + urllib.parse.quote(key), body)
            if status == 200:
                for m in json.loads(raw or "{}").get("matches", []):
                    for r in url_results:
                        if r["url"] == m["threat"]["url"]:
                            self._add(r, 95, f"Google Safe Browsing: {m['threatType']}")
        except Exception as e:
            for r in url_results:
                self._add(r, 0, f"Google Safe Browsing lookup failed: {e}", "info")

    def _virustotal(self, key, r):
        uid = base64.urlsafe_b64encode(r["url"].encode()).decode().strip("=")
        try:
            status, raw = _http("GET", f"https://www.virustotal.com/api/v3/urls/{uid}",
                                headers={"x-apikey": key})
            if status == 200:
                stats = json.loads(raw)["data"]["attributes"]["last_analysis_stats"]
                bad = stats.get("malicious", 0) + stats.get("suspicious", 0)
                if bad >= 3:
                    self._add(r, 90, f"VirusTotal: {bad} security vendors flag this URL")
                elif bad:
                    self._add(r, 30, f"VirusTotal: {bad} vendor(s) flag this URL", "warn")
        except Exception as e:
            self._add(r, 0, f"VirusTotal lookup failed: {e}", "info")

    def _stopforumspam(self, r):
        try:
            status, raw = _http("GET", "https://api.stopforumspam.org/api?json&email="
                                + urllib.parse.quote(r["email"]))
            if status == 200:
                d = json.loads(raw).get("email", {})
                if d.get("appears"):
                    self._add(r, 30, f"Reported {d.get('frequency', '?')} time(s) to StopForumSpam", "warn")
        except Exception as e:
            self._add(r, 0, f"StopForumSpam lookup failed: {e}", "info")


def pwned_range(prefix):
    """Have I Been Pwned - Pwned Passwords k-anonymity range query.
    Only the first 5 hex chars of the SHA-1 hash are sent."""
    status, raw = _http("GET", f"https://api.pwnedpasswords.com/range/{prefix.upper()}",
                        headers={"Add-Padding": "true"})
    return raw if status == 200 else ""


# ------------------------------------------------------------------ automatic reporting
NETCRAFT_URL = "https://report.netcraft.com/api/v3/report/urls"
BATCH = 25


def _netcraft(email, urls):
    body = {"email": email, "reason": "Phishing / scam link detected by SAYNO",
            "urls": [{"url": u} for u in urls]}
    status, raw = _http("POST", NETCRAFT_URL, body, timeout=30)
    ok = 200 <= status < 300
    try:
        uuid = json.loads(raw).get("uuid")
        detail = f"uuid {uuid}" if uuid else raw[:200]
    except ValueError:
        detail = raw[:200]
    return ok, f"HTTP {status}: {detail}"


def _urlhaus(key, urls):
    body = {"anonymous": "0", "submission": [{"url": u, "threat": "malware_download"} for u in urls]}
    status, raw = _http("POST", "https://urlhaus.abuse.ch/api/", body, {"Auth-Key": key}, timeout=30)
    return 200 <= status < 300, f"HTTP {status}: {raw[:200]}"


def auto_report(store, intel, cfg, log=print):
    """Back-end job: send every new high-risk link from the report database to
    external takedown services. Each link is sent once per service.

    Skips links that are already in the global threat database (the services
    know them already) and anything an admin dismissed.
    """
    if not cfg.get("auto_report", True):
        return
    email = (cfg.get("reporter_email") or "").strip()
    urlhaus_key = cfg.get("api_keys", {}).get("urlhaus")

    jobs = [("netcraft", email, _netcraft, lambda i: True)]
    if urlhaus_key:  # URLhaus only accepts malware-download links
        jobs.append(("urlhaus", urlhaus_key, _urlhaus,
                     lambda i: any("executable" in r for r in i["reasons"])))

    for service, cred, send, wanted in jobs:
        items = [i for i in store.pending_reports(service)
                 if wanted(i) and not intel.lookup_url(i["display"])
                 and not is_private_host(host_of(i["display"]))]
        if not items:
            continue
        if not cred:
            log(f"[auto-report] {len(items)} link(s) waiting - set reporter_email in config.json to enable Netcraft")
            continue
        for n in range(0, len(items), BATCH):
            chunk = items[n:n + BATCH]
            try:
                ok, detail = send(cred, [i["display"] for i in chunk])
            except Exception as e:
                ok, detail = False, str(e)[:200]
            for i in chunk:
                store.log_report(i["id"], service, ok, detail)
            log(f"[auto-report] {service}: {len(chunk)} link(s) -> {'OK' if ok else 'FAILED'} ({detail})")


def manual_links(urls):
    """Places that accept reports through a web form or e-mail (no API)."""
    links = [
        {"name": "Google Safe Browsing - report phishing page",
         "url": "https://safebrowsing.google.com/safebrowsing/report_phish/"
                + (("?url=" + urllib.parse.quote(urls[0], safe="")) if urls else "")},
        {"name": "Microsoft - report unsafe site", "url": "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site"},
        {"name": "PhishTank (free account)", "url": "https://phishtank.org/add_web_phish.php"},
        {"name": "APWG - forward phishing e-mails to reportphishing@apwg.org", "url": "https://apwg.org/reportphishing/"},
        {"name": "USA - FTC fraud report", "url": "https://reportfraud.ftc.gov/"},
        {"name": "USA - FBI IC3 (if you lost money)", "url": "https://www.ic3.gov/"},
        {"name": "UK - forward e-mails to report@phishing.gov.uk, texts to 7726",
         "url": "https://www.ncsc.gov.uk/collection/phishing-scams"},
        {"name": "EU / other - find your national CERT", "url": "https://www.first.org/members/teams/"},
    ]
    return links
