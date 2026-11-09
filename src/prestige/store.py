"""Canonical SQLite state; transactions serialize writers, never model-written Markdown."""

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from prestige.types import PrestigeError


def encoded(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class Store:
    def __init__(self, home: Path):
        home.mkdir(parents=True, exist_ok=True)
        self.home = home
        self.lock = threading.RLock()
        self.db = sqlite3.connect(home / "state.sqlite3", timeout=15, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA busy_timeout=15000")
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1):
            raise PrestigeError("Unsupported database schema; upgrade PRESTIGE")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY, created REAL NOT NULL, status TEXT NOT NULL,
                mode TEXT NOT NULL, lane TEXT NOT NULL, backend TEXT NOT NULL,
                settings TEXT NOT NULL, turns INTEGER NOT NULL DEFAULT 0,
                tokens INTEGER NOT NULL DEFAULT 0, unknown_usage INTEGER NOT NULL DEFAULT 0,
                elapsed REAL NOT NULL DEFAULT 0, session TEXT, attempts INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
                event_key TEXT NOT NULL, kind TEXT NOT NULL, at REAL NOT NULL,
                data TEXT NOT NULL, UNIQUE(run_id,event_key));
            CREATE TABLE IF NOT EXISTS artifacts (
                run_id TEXT NOT NULL REFERENCES runs(id), id TEXT NOT NULL,
                label TEXT NOT NULL, size INTEGER NOT NULL, parent TEXT,
                transform TEXT, PRIMARY KEY(run_id,id));
            CREATE TABLE IF NOT EXISTS candidates (
                run_id TEXT NOT NULL REFERENCES runs(id), digest TEXT NOT NULL,
                artifact TEXT NOT NULL, value BLOB NOT NULL, verified INTEGER NOT NULL,
                PRIMARY KEY(run_id,digest));
            CREATE TABLE IF NOT EXISTS leases (
                run_id TEXT PRIMARY KEY REFERENCES runs(id), owner TEXT NOT NULL, until REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS knowledge (
                id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
                record TEXT NOT NULL, status TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS models (id TEXT PRIMARY KEY, manifest TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS competitions (name TEXT PRIMARY KEY, data TEXT NOT NULL);
            PRAGMA user_version=1;
        """)
        # Migration: add attempts column to runs created before this increment.
        try:
            self.db.execute("ALTER TABLE runs ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield self.db
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise

    def rows(self, sql: str, args=()) -> list[dict]:
        with self.lock:
            return [dict(row) for row in self.db.execute(sql, args).fetchall()]

    def create_run(self, mode: str, backend: str, settings: dict) -> str:
        run_id = uuid.uuid4().hex[:16]
        with self.transaction() as db:
            db.execute(
                "INSERT INTO runs(id,created,status,mode,lane,backend,settings) VALUES(?,?,?,?,?,?,?)",
                (
                    run_id,
                    time.time(),
                    "ready",
                    mode,
                    "expert" if mode == "expert" else "fast",
                    backend,
                    encoded(settings),
                ),
            )
        return run_id

    def run(self, run_id: str) -> dict:
        rows = self.rows("SELECT * FROM runs WHERE id=?", (run_id,))
        if not rows:
            raise PrestigeError("Unknown run ID")
        result = rows[0]
        result["settings"] = json.loads(result["settings"])
        return result

    def update(self, run_id: str, **fields):
        if not fields or set(fields) - {
            "status",
            "lane",
            "turns",
            "tokens",
            "unknown_usage",
            "elapsed",
            "session",
            "attempts",
        }:
            raise ValueError("Invalid run update")
        with self.transaction() as db:
            db.execute(
                f"UPDATE runs SET {','.join(k + '=?' for k in fields)} WHERE id=?",
                (*fields.values(), run_id),
            )

    def event(self, run_id: str, kind: str, data: dict, key: str | None = None):
        with self.transaction() as db:
            db.execute(
                "INSERT OR IGNORE INTO events(run_id,event_key,kind,at,data) VALUES(?,?,?,?,?)",
                (run_id, key or uuid.uuid4().hex, kind, time.time(), encoded(data)),
            )

    def events(self, run_id: str) -> list[dict]:
        self.run(run_id)
        rows = self.rows(
            "SELECT seq,kind,at,data FROM events WHERE run_id=? ORDER BY seq", (run_id,)
        )
        return [{**row, "data": json.loads(row["data"])} for row in rows]

    def acquire(self, run_id: str, owner: str, duration: float = 120):
        with self.transaction() as db:
            row = db.execute("SELECT * FROM leases WHERE run_id=?", (run_id,)).fetchone()
            if row and row["owner"] != owner and row["until"] > time.time():
                raise PrestigeError("Run already has an active worker")
            db.execute(
                "INSERT OR REPLACE INTO leases VALUES(?,?,?)",
                (run_id, owner, time.time() + duration),
            )

    def release(self, run_id: str, owner: str):
        with self.transaction() as db:
            db.execute("DELETE FROM leases WHERE run_id=? AND owner=?", (run_id, owner))

    def candidate(self, run_id: str, artifact: str, value: bytes, verified: bool):
        digest = hashlib.sha256(value).hexdigest()
        with self.transaction() as db:
            db.execute(
                "INSERT INTO candidates VALUES(?,?,?,?,?) ON CONFLICT(run_id,digest) "
                "DO UPDATE SET verified=MAX(verified,excluded.verified)",
                (run_id, digest, artifact, value, int(verified)),
            )

    def close(self):
        self.db.close()
