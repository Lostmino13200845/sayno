"""Scam Shield core library.

    intel    - private, self-updating global threat database (hidden storage)
    engine   - message / link / e-mail analysis and danger scoring
    reports  - server-side database of suspicious and confirmed scams
    services - optional online reputation APIs and external abuse reporting
"""
from .engine import analyze, is_reportable, record_scan
from .intel import ThreatIntel
from .reports import ReportStore
from .services import OnlineChecker, auto_report, manual_links, pwned_range

__all__ = ["analyze", "is_reportable", "record_scan", "ThreatIntel", "ReportStore", "OnlineChecker", "auto_report", "manual_links", "pwned_range"]
