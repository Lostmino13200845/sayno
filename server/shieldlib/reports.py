"""Server-side database of suspicious items (SQLite, in the hidden data folder).

Every scan that looks suspicious is logged automatically ("auto"); items a user
confirms as a scam are marked "confirmed" and are then treated as blocklisted
by future scans. The table is the base for future steps: sharing, exporting,
bulk-reporting to external services, training, dashboards...
"""
import json
import os
import sqlite3
import threading
import time

from ._store import DATA_DIR
from .intel import normalize_url

DB_PATH = os.path.join(DATA_DIR, "reports.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    id          INTEGER PRIMARY KEY,
    kind        TEXT NOT NULL,           -- url | email | text
    value       TEXT NOT NULL,           -- normalized url / email / text fingerprint
    display     TEXT,                    -- original url / email / message excerpt
    max_score   INTEGER NOT NULL,
    level       TEXT NOT NULL,
    reasons     TEXT,                    -- JSON list of finding messages
    status      TEXT NOT NULL DEFAULT 'auto',  -- auto | confirmed | dismissed
    times_seen  INTEGER NOT NULL DEFAULT 1,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    reported_to TEXT,                    -- JSON list of external services it was sent to
    reportable  INTEGER NOT NULL DEFAULT 0,  -- 1 = qualifies for automatic external reporting
    note        TEXT,
    UNIQUE(kind, value)
);
CREATE INDEX IF NOT EXISTS idx_status ON items(status);
CREATE INDEX IF NOT EXISTS idx_last   ON items(last_seen);
CREATE TABLE IF NOT EXISTS report_log (  -- audit trail of automatic submissions
    id       INTEGER PRIMARY KEY,
    item_id  INTEGER NOT NULL REFERENCES items(id),
    service  TEXT NOT NULL,
    sent_at  REAL NOT NULL,
    ok       INTEGER NOT NULL,
    detail   TEXT
);
CREATE INDEX IF NOT EXISTS idx_log_item ON report_log(item_id, service);
"""
MAX_ATTEMPTS = 3


class ReportStore:
    def __init__(self, path=DB_PATH):
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)
        cols = {r[1] for r in self._db.execute("PRAGMA table_info(items)")}
        if "reportable" not in cols:  # upgrade databases created by older versions
            self._db.execute("ALTER TABLE items ADD COLUMN reportable INTEGER NOT NULL DEFAULT 0")
        self._db.commit()

    @staticmethod
    def key(kind, value):
        if kind == "url":
            return normalize_url(value)
        if kind == "email":
            return value.lower()
        return value  # text: already a fingerprint

    def record(self, kind, value, display, score, level, reasons, status="auto", note=None,
               reportable=False):
        now = time.time()
        k = self.key(kind, value)
        with self._lock:
            self._db.execute(
                """INSERT INTO items(kind,value,display,max_score,level,reasons,status,first_seen,last_seen,note,reportable)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(kind,value) DO UPDATE SET
                     times_seen = times_seen + 1,
                     last_seen  = excluded.last_seen,
                     max_score  = MAX(max_score, excluded.max_score),
                     level      = CASE WHEN excluded.max_score >= max_score THEN excluded.level ELSE level END,
                     reasons    = excluded.reasons,
                     status     = CASE WHEN excluded.status='confirmed' THEN 'confirmed' ELSE status END,
                     note       = COALESCE(excluded.note, note),
                     reportable = MAX(reportable, excluded.reportable)""",
                (kind, k, display[:2000], score, level, json.dumps(reasons), status, now, now, note, int(reportable)))
            self._db.commit()

    def pending_reports(self, service):
        """Links not yet successfully sent to `service` (and not failed too often)."""
        with self._lock:
            rows = self._db.execute(
                """SELECT * FROM items i
                   WHERE kind='url' AND (reportable=1 OR status='confirmed') AND status!='dismissed'
                     AND COALESCE(reported_to,'[]') NOT LIKE ?
                     AND (SELECT COUNT(*) FROM report_log l
                          WHERE l.item_id=i.id AND l.service=? AND l.ok=0) < ?
                   ORDER BY first_seen LIMIT 200""",
                (f'%"{service}"%', service, MAX_ATTEMPTS)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["reasons"] = json.loads(d["reasons"] or "[]")
            out.append(d)
        return out

    def log_report(self, item_id, service, ok, detail):
        with self._lock:
            self._db.execute("INSERT INTO report_log(item_id,service,sent_at,ok,detail) VALUES(?,?,?,?,?)",
                             (item_id, service, time.time(), int(ok), detail[:500]))
            if ok:
                row = self._db.execute("SELECT reported_to FROM items WHERE id=?", (item_id,)).fetchone()
                prev = set(json.loads(row["reported_to"] or "[]"))
                self._db.execute("UPDATE items SET reported_to=? WHERE id=?",
                                 (json.dumps(sorted(prev | {service})), item_id))
            self._db.commit()

    def report_history(self, limit=200):
        with self._lock:
            rows = self._db.execute(
                """SELECT l.*, i.display FROM report_log l JOIN items i ON i.id=l.item_id
                   ORDER BY l.sent_at DESC LIMIT ?""", (int(limit),)).fetchall()
        return [dict(r) for r in rows]

    def set_status(self, item_id, status):
        with self._lock:
            self._db.execute("UPDATE items SET status=? WHERE id=?", (status, item_id))
            self._db.commit()

    def get(self, kind, value):
        with self._lock:
            row = self._db.execute("SELECT * FROM items WHERE kind=? AND value=?",
                                   (kind, self.key(kind, value))).fetchone()
        return dict(row) if row else None

    def list(self, status=None, kind=None, limit=200):
        q, args = "SELECT * FROM items WHERE 1=1", []
        if status:
            q += " AND status=?"
            args.append(status)
        if kind:
            q += " AND kind=?"
            args.append(kind)
        q += " ORDER BY last_seen DESC LIMIT ?"
        args.append(int(limit))
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["reasons"] = json.loads(d["reasons"] or "[]")
            d["reported_to"] = json.loads(d["reported_to"] or "[]")
            out.append(d)
        return out

    def counts(self):
        with self._lock:
            rows = self._db.execute("SELECT status, COUNT(*) n FROM items GROUP BY status").fetchall()
        return {r["status"]: r["n"] for r in rows}
