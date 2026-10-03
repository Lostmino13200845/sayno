"""Scam-detection engine: extracts links / e-mail addresses from text,
applies heuristics, checks blocklists and produces a 0-100 danger score."""
import hashlib
import ipaddress
import re
from urllib.parse import urlsplit

from .intel import host_of

# ------------------------------------------------------------------ patterns
URL_RE = re.compile(
    r"""(?:(?:https?|hxxps?)://|www\.)[^\s<>"'`]+"""
    r"""|\b(?:[a-z0-9-]+\.)+(?:com|net|org|info|biz|xyz|top|club|online|site|shop|live|"""
    r"""click|link|icu|buzz|zip|mov|ru|cn|tk|ml|ga|cf|gq|io|co|me|app|ly|gl)(?:/[^\s<>"'`]*)?""",
    re.I,
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")

# (category, weight, message, regex)
TEXT_RULES = [
    ("urgency", 12, "Creates urgency / time pressure",
     r"\b(urgent(ly)?|immediately|right away|act now|within \d+ ?(hours?|hrs?|minutes?|days?)|"
     r"final (notice|warning|reminder)|expires? (today|soon)|last chance|limited time)\b"),
    ("credentials", 22, "Asks for passwords, codes or identity data",
     r"\b(verify your (account|identity|details)|confirm your (password|account|details|identity)|"
     r"(banking|bank|card|account|payment) (details|information|info|credentials)|"
     r"(login|log-in|sign.?in) details|password|passcode|one.?time (code|password)|\botp\b|"
     r"verification code|security code|\bpin\b|cvv|card number|social security|\bssn\b|"
     r"update your (billing|payment) (info|information|details))\b"),
    ("payment", 18, "Requests unusual payment (gift cards, crypto, wire)",
     r"\b(gift ?cards?|itunes card|google play card|steam card|wire transfer|western union|"
     r"moneygram|bitcoin|btc|usdt|crypto(currency)?|wallet address|bank transfer|"
     r"processing fee|release fee|customs fee|pay (a|the) (small )?fee)\b"),
    ("prize", 16, "Promises prizes, winnings or free money",
     r"\b(you('ve| have)? won|winner|congratulations|claim your (prize|reward|refund|gift)|"
     r"lottery|jackpot|inheritance|unclaimed (funds|money)|free (iphone|money|gift)|"
     r"guaranteed (profit|returns?)|double your (money|investment))\b"),
    ("threat", 12, "Threatens account closure, arrest or legal action",
     r"\b((account|card|debit card|credit card) (has been |will be |is |was )?(temporarily |permanently )?"
     r"(suspended|locked|blocked|frozen|disabled|closed|limited|terminated|deactivated)|"
     r"to avoid (suspension|closure|deactivation|cancellation)|"
     r"legal action|arrest(ed)?|warrant|police|lawsuit|penalt(y|ies)|unauthori[sz]ed (login|access|activity)|"
     r"suspicious (activity|login|sign.?in))\b"),
    ("secrecy", 12, "Asks you to keep it secret",
     r"\b(don'?t tell (anyone|anybody)|keep (this|it) (confidential|secret|between us)|"
     r"do not share this with)\b"),
    ("remote_access", 20, "Asks you to install remote-access software",
     r"\b(anydesk|teamviewer|ultraviewer|rustdesk|quick ?support|remote (access|desktop|control))\b"),
    ("delivery", 8, "Fake delivery / parcel notification pattern",
     r"\b(parcel|package|delivery|shipment) (is )?(on hold|could not be delivered|pending|failed|held)\b"),
    ("generic_greeting", 5, "Generic greeting (not addressed to you by name)",
     r"\b(dear (customer|user|client|member|account holder|sir/madam|valued customer))\b"),
    ("card_request", 24, "Asks for full card details (number, CVV, expiry or PIN)",
     r"\b(card ?number|cvv2?|cvc|security code on the back|expiry date|expiration date|card ?pin|"
     r"debit ?pin|full card details|re-?enter your card|confirm your card|card (has been|was) (locked|blocked|frozen))\b"),
    ("etransfer", 16, "Fake Interac e-Transfer / bank deposit notice",
     r"\b(e-?transfer (is )?(pending|on hold|expir\w*|awaiting|declined)|deposit (your|the) (funds|money|e-?transfer)|"
     r"accept (the|your) (payment|e-?transfer)|funds (are )?(on hold|pending)|interac.{0,20}(pending|deposit|refund))\b"),
    ("gov_impersonation", 14, "Government / tax-agency impersonation (CRA, IRS, Service Canada)",
     r"\b(cra|canada revenue agency|service canada|irs|sin number|social insurance number|"
     r"tax (refund|rebate|return) (is )?(pending|available|approved)|gst (credit|refund))\b"),
    ("new_account", 12, "Targets new accounts ('welcome', 'activate your new account/card')",
     r"\b(activate your (new )?(account|card|debit card|credit card)|new (account|card) (verification|activation)|"
     r"complete your (account )?(setup|registration) to avoid|welcome bonus.{0,30}(verify|confirm))\b"),
    ("family_emergency", 16, "'Hi mum/dad, new number' family-emergency scam pattern",
     r"\b(hi (mum|mom|dad)|this is my new number|lost my phone|new phone number)\b"),
]
TEXT_RULES = [(c, w, m, re.compile(p, re.I)) for c, w, m, p in TEXT_RULES]

BRANDS = {
    "paypal": ["paypal.com", "paypal.me"],
    "apple": ["apple.com", "icloud.com", "me.com"],
    "icloud": ["icloud.com", "apple.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "office365.com"],
    "office365": ["office.com", "microsoft.com", "office365.com"],
    "outlook": ["outlook.com", "live.com", "microsoft.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.ca", "amazon.in", "amazon.it",
               "amazon.es", "amazon.co.jp", "amazon.com.au", "amazonaws.com", "amazon.jobs"],
    "google": ["google.com", "gmail.com", "youtube.com", "googleusercontent.com", "goo.gl"],
    "gmail": ["gmail.com", "google.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com", "facebookmail.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net", "wa.me"],
    "telegram": ["telegram.org", "t.me"],
    "dhl": ["dhl.com", "dhl.de", "dhl.co.uk"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"],
    "ups": ["ups.com"],
    "irs": ["irs.gov"],
    "hmrc": ["gov.uk"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "metamask": ["metamask.io"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dropbox": ["dropbox.com"],
    "linkedin": ["linkedin.com"],
    # Canadian banks, payment networks and agencies (most impersonated in Canada)
    "rbc": ["rbc.com", "rbcroyalbank.com", "royalbank.com"],
    "royalbank": ["rbc.com", "rbcroyalbank.com", "royalbank.com"],
    "td": ["td.com", "tdcanadatrust.com", "tdbank.com"],
    "tdcanadatrust": ["td.com", "tdcanadatrust.com"],
    "bmo": ["bmo.com"],
    "scotiabank": ["scotiabank.com", "scotiaonline.scotiabank.com"],
    "scotia": ["scotiabank.com"],
    "cibc": ["cibc.com"],
    "desjardins": ["desjardins.com"],
    "tangerine": ["tangerine.ca"],
    "simplii": ["simplii.com"],
    "eqbank": ["eqbank.ca"],
    "vancity": ["vancity.com"],
    "coastcapital": ["coastcapitalsavings.com"],
    "nationalbank": ["nbc.ca"],
    "interac": ["interac.ca"],
    "etransfer": ["interac.ca"],
    "wealthsimple": ["wealthsimple.com"],
    "koho": ["koho.ca"],
    "cra": ["canada.ca", "gc.ca"],
    "canadapost": ["canadapost.ca", "canadapost-postescanada.ca"],
    "visa": ["visa.com", "visa.ca"],
    "mastercard": ["mastercard.com", "mastercard.ca"],
}
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "aol.com", "icloud.com",
             "mail.ru", "yandex.com", "yandex.ru", "gmx.com", "proton.me", "protonmail.com", "zoho.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly",
              "shorturl.at", "rb.gy", "tiny.cc", "s.id", "t.ly", "v.gd", "qrco.de", "bit.do", "shorte.st"}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "work", "rest", "help",
              "icu", "cam", "buzz", "sbs", "cfd", "monster", "quest", "lol", "bond", "cyou", "support", "live",
              "shop", "online", "site", "fun", "win", "loan", "download", "review"}
SUSPICIOUS_WORDS = re.compile(r"(login|log-in|signin|sign-in|verify|verification|secure|account|update|"
                              r"confirm|wallet|unlock|recover|billing|webscr|password|auth)", re.I)
TWO_LEVEL_SUFFIXES = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.jp", "co.in", "com.br",
                      "co.za", "com.mx", "com.tr", "co.nz", "com.cn", "com.sg", "co.kr", "com.ar"}
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a",
                            "$": "s", "!": "i"})

LEVELS = [(85, "critical"), (60, "high"), (35, "medium"), (15, "low"), (0, "safe")]


def registered_domain(host):
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_official(host, brand):
    reg = registered_domain(host)
    return any(reg == d or host == d or host.endswith("." + d) for d in BRANDS[brand])


def brand_tokens(text):
    """Brands whose name appears as a token (split on . - _) in text; also after homoglyph folding."""
    raw = re.split(r"[.\-_+]", text.lower())
    folded = [t.translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w") for t in raw]
    found = {}

    def hit(tokens, brand):
        # Short names (ups, irs, dhl) must match a whole token; longer ones may carry a suffix
        # like "paypalsecure" or "amazon2fa".
        if brand in tokens:
            return True
        return len(brand) >= 5 and any(t.startswith(brand) and len(t) - len(brand) <= 8 for t in tokens)

    for brand in BRANDS:
        if hit(raw, brand):
            found[brand] = "exact"
        elif hit(folded, brand):
            found[brand] = "lookalike"
    return found


def extract(text):
    urls, seen = [], set()
    for m in URL_RE.finditer(text):
        u = m.group(0).rstrip(".,;:!?)]}>'\"")
        if "@" in u.split("/")[0] and "://" not in u:
            continue  # that's an e-mail address, handled separately
        u = re.sub(r"^hxxp", "http", u, flags=re.I).replace("[.]", ".")
        if u.lower() not in seen:
            seen.add(u.lower())
            urls.append(u)
    emails = sorted({m.group(0).lower() for m in EMAIL_RE.finditer(text)})
    # drop "urls" that are just the domain part of an extracted e-mail
    email_domains = {e.split("@", 1)[1] for e in emails}
    urls = [u for u in urls if u.lower() not in email_domains]
    return urls, emails


def level_for(score):
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "safe"


def text_fingerprint(text):
    norm = re.sub(r"\s+", " ", re.sub(r"[^\w\s]", "", text.lower())).strip()
    return hashlib.sha256(norm.encode()).hexdigest()


# ------------------------------------------------------------------ analyzers
def _history(store, kind, value, add):
    """Findings from our own report database."""
    row = store.get(kind, value) if store else None
    if not row or row["status"] == "dismissed":
        return
    if row["status"] == "confirmed":
        add(95, "Confirmed scam in the SAYNO report database", "danger")
    elif row["times_seen"] >= 2:
        add(0, f"Flagged as suspicious {row['times_seen']} times before", "info")


def analyze_url(url, intel, store=None):
    findings = []

    def add(weight, msg, sev="warn", **extra):
        findings.append({"weight": weight, "message": msg, "severity": sev, **extra})

    full = url if re.match(r"^[a-z]+://", url, re.I) else "http://" + url
    try:
        parts = urlsplit(full)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        add(20, "Malformed URL", "danger")
        return {"url": url, "host": "", "score": 20, "level": level_for(20), "findings": findings}

    for category, match in intel.lookup_url(url):
        add(95, f"Known {category} threat in the global threat database ({match})", "danger")
    _history(store, "url", url, add)

    try:
        ipaddress.ip_address(host)
        add(22, "Uses a raw IP address instead of a domain name", "danger")
    except ValueError:
        pass
    if "xn--" in host:
        add(22, "Punycode / internationalized domain (possible look-alike characters)", "danger")
    if "@" in parts.netloc:
        add(22, "Contains '@' before the host - the real destination is hidden", "danger")
    if host in SHORTENERS or registered_domain(host) in SHORTENERS:
        add(10, "Link shortener hides the real destination")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in RISKY_TLDS:
        add(10, f"Top-level domain '.{tld}' is heavily abused by scammers")
    if full.lower().startswith("http://"):
        add(6, "Not encrypted (http, not https)")
    if host.count(".") >= 4:
        add(8, "Unusually many sub-domains")
    if host.count("-") >= 3:
        add(6, "Many hyphens in the domain name")
    if port and port not in (80, 443):
        add(8, f"Non-standard port {port}")
    if len(url) > 120:
        add(4, "Very long URL")
    official = any(is_official(host, b) for b in BRANDS)
    if not official:
        if SUSPICIOUS_WORDS.search(host):
            add(8, "Domain contains words like login / verify / secure / account")
        elif SUSPICIOUS_WORDS.search(parts.path or ""):
            add(4, "Path contains words like login / verify / account")
    if re.search(r"\.(exe|scr|apk|msi|bat|cmd|ps1|sh|dll|js|vbs|jar|iso|img|lnk|hta)(\?|$)", parts.path or "", re.I):
        add(25, "Link points directly to an executable / installer file", "danger")

    for brand, kind in brand_tokens(host).items():
        if not is_official(host, brand):
            if kind == "lookalike":
                add(30, f"Look-alike of '{brand}' (character substitution) on a non-{brand} domain", "danger",
                    brand=brand, lookalike=True)
            else:
                add(24, f"Mentions '{brand}' but is not an official {brand} domain", "danger", brand=brand)

    score = min(100, sum(f["weight"] for f in findings))
    return {"url": url, "host": host, "score": score, "level": level_for(score), "findings": findings}


def analyze_email(addr, intel, store=None):
    findings = []

    def add(weight, msg, sev="warn", **extra):
        findings.append({"weight": weight, "message": msg, "severity": sev, **extra})

    local, domain = addr.split("@", 1)
    info = intel.lookup_email_domain(domain)
    _history(store, "email", addr, add)
    if info["blocklisted"]:
        category, match = info["blocklisted"]
        add(80, f"Sender domain is a known {category} threat ({match})", "danger")
    if info["disposable"]:
        add(18, "Disposable / throwaway e-mail provider")
    for brand, kind in {**brand_tokens(local), **brand_tokens(domain)}.items():
        if is_official(domain, brand):
            continue
        if domain in FREE_MAIL:
            add(22, f"Claims to be '{brand}' but uses free webmail ({domain})", "danger")
        elif kind == "lookalike":
            add(30, f"Look-alike of '{brand}' in the address", "danger", brand=brand, lookalike=True)
        else:
            add(20, f"Mentions '{brand}' but domain is not official", "danger", brand=brand)
    tld = domain.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        add(8, f"Top-level domain '.{tld}' is heavily abused")
    if re.search(r"\d{4,}", local):
        add(4, "Address contains a long random-looking number")

    score = min(100, sum(f["weight"] for f in findings))
    return {"email": addr, "score": score, "level": level_for(score), "findings": findings}


def analyze(text, intel, store=None, online=None):
    """Full scan. `store` is the ReportStore, `online` an optional OnlineChecker."""
    urls, emails = extract(text)
    text_findings = []
    matched = set()
    for cat, weight, msg, rx in TEXT_RULES:
        m = rx.search(text)
        if m:
            matched.add(cat)
            text_findings.append({"weight": weight, "message": msg, "severity": "warn",
                                  "evidence": m.group(0)})
    fp = text_fingerprint(text)
    _history(store, "text", fp, lambda w, m, s="warn": text_findings.append(
        {"weight": w, "message": m, "severity": s}))
    # Combination bonus: pressure + request for data / money is the classic scam shape.
    if matched & {"urgency", "threat"} and matched & {"credentials", "payment", "remote_access", "card_request",
                                                     "etransfer", "gov_impersonation", "new_account"}:
        text_findings.append({"weight": 15, "severity": "danger",
                              "message": "Pressure combined with a request for data or money (classic scam pattern)"})

    url_results = [analyze_url(u, intel, store) for u in urls]
    email_results = [analyze_email(e, intel, store) for e in emails]

    # Bank-phishing shape: a link or sender that imitates a brand, in a message that pressures you
    # (urgency / threats / requests for data) and names that brand or uses a look-alike spelling.
    impersonated = None
    if matched & {"urgency", "threat", "credentials", "card_request", "etransfer", "new_account", "payment"}:
        for r in url_results + email_results:
            for f in r["findings"]:
                b = f.get("brand")
                if b and (f.get("lookalike") or re.search(r"\b" + re.escape(b) + r"\b", text, re.I)):
                    impersonated = b
                    break
            if impersonated:
                break
    if impersonated:
        text_findings.append({"weight": 20, "severity": "danger",
                              "message": f"A link or sender imitates '{impersonated}' while the message pushes you to act "
                                         "(typical bank-phishing pattern)"})

    if online:
        online.enrich(url_results, email_results)

    text_score = min(100, sum(f["weight"] for f in text_findings))
    if urls and matched & {"credentials", "payment", "threat", "urgency"}:
        text_score = min(100, text_score + 8)  # a link to click raises the stakes

    worst_item = max([r["score"] for r in url_results + email_results] or [0])
    # Overall: the worst single indicator dominates, others add on with diminishing weight.
    parts = sorted([text_score, worst_item], reverse=True)
    overall = min(100, round(parts[0] + 0.35 * parts[1]))
    if impersonated:
        overall = max(overall, 70)  # never leave this pattern at "medium"

    return {
        "score": overall,
        "level": level_for(overall),
        "text": {"score": text_score, "findings": text_findings},
        "urls": url_results,
        "emails": email_results,
        "fingerprint": fp,
        "advice": advice_for(level_for(overall), matched, url_results, email_results),
    }


def is_reportable(url_result, scan_result, threshold=60):
    """A link qualifies for automatic external reporting when it is dangerous on its own,
    or suspicious and sitting inside a dangerous message. Local / private-network
    addresses are never reported - they mean nothing outside this network."""
    if is_private_host(url_result.get("host", "")):
        return False
    s = url_result["score"]
    return s >= threshold or (s >= 35 and scan_result["score"] >= threshold)


def is_private_host(host):
    if host in ("", "localhost") or host.endswith((".local", ".localhost", ".internal", ".lan")):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


def record_scan(result, text, store, threshold=35, store_text=True, report_threshold=60):
    """Automatically log everything suspicious from a scan into the server database."""
    reasons = lambda fs: [f["message"] for f in fs if f["weight"]]
    for u in result["urls"]:
        if u["score"] >= threshold:
            store.record("url", u["url"], u["url"], u["score"], u["level"], reasons(u["findings"]),
                         reportable=is_reportable(u, result, report_threshold))
    for e in result["emails"]:
        if e["score"] >= threshold:
            store.record("email", e["email"], e["email"], e["score"], e["level"], reasons(e["findings"]))
    if result["score"] >= threshold:
        display = text if store_text else f"[message text not stored, {len(text)} chars]"
        store.record("text", result["fingerprint"], display, result["score"], result["level"],
                     reasons(result["text"]["findings"]))


def advice_for(level, matched, urls, emails):
    tips = []
    if level in ("critical", "high"):
        tips.append("Do NOT click any link, open attachments, reply, or call numbers in this message.")
        tips.append("Delete it after reporting. If you already clicked or entered data, see 'If you were hit' in the guide.")
    elif level == "medium":
        tips.append("Treat with caution: contact the organization through its official app or website you type yourself.")
    else:
        tips.append("No strong scam signals found - but a clean result is not a guarantee. Stay alert.")
    if "credentials" in matched:
        tips.append("Legitimate companies never ask for passwords, PINs or one-time codes by message.")
    if "payment" in matched:
        tips.append("Gift cards, crypto and wire transfers are the scammer's favourite - they can't be reversed.")
    if "remote_access" in matched:
        tips.append("Never install AnyDesk / TeamViewer for someone who contacted you first.")
    if "family_emergency" in matched:
        tips.append("Call your family member on their OLD, known number before sending anything.")
    if any(u["host"] in SHORTENERS for u in urls):
        tips.append("Expand short links with a preview service (e.g. unshorten.it) before trusting them.")
    return tips
