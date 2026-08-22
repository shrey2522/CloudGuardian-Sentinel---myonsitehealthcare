"""Centralized audit trail.

Dual write for durability (PRD: 24h+ retention, no data loss):
  - append-only JSONL, flushed+fsynced on every event (crash-safe)
  - SQLite index for querying
Every event carries a UTC timestamp and actor (user context).
"""
import json
import os
import sqlite3
import threading

from sentinel.models import utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    message TEXT NOT NULL,
    details TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_ts ON audit_events(ts);
"""


class AuditLog:
    def __init__(self, audit_dir, actor):
        self.actor = actor
        audit_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl_path = audit_dir / "audit.jsonl"
        self.db_path = audit_dir / "audit.db"
        self._lock = threading.Lock()
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(SCHEMA)

    def record(self, event_type, message, **details):
        event = {
            "ts": utcnow(),
            "event_type": event_type,
            "actor": self.actor,
            "message": message,
            "details": details,
        }
        with self._lock:
            with open(self.jsonl_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, default=str) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO audit_events (ts, event_type, actor, message, details) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (event["ts"], event_type, self.actor, message,
                     json.dumps(details, default=str)),
        )
        return event

    def recent(self, limit=50, event_type=None):
        query = "SELECT ts, event_type, actor, message, details FROM audit_events"
        params = []
        if event_type:
            query += " WHERE event_type = ?"
            params.append(event_type)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {"ts": r[0], "event_type": r[1], "actor": r[2], "message": r[3],
             "details": json.loads(r[4] or "{}")}
            for r in rows
        ]
