"""Histórico de eventos (varreduras, detecções, ações) em SQLite."""
from __future__ import annotations

import datetime
import sqlite3
import threading

from . import paths

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None
_listeners: list = []


def _db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        from .db import open_db
        _conn = open_db(paths.data_dir() / "history.db",
                        ["CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, "
                         "kind TEXT, message TEXT, path TEXT)",
                         "CREATE INDEX IF NOT EXISTS events_kind ON events(kind)",
                         "PRAGMA synchronous=NORMAL"])
    return _conn


def log(kind: str, message: str, path: str = "") -> None:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        c = _db()
        c.execute("INSERT INTO events (ts, kind, message, path) VALUES (?,?,?,?)", (ts, kind, message, path))
        c.commit()
    for cb in list(_listeners):
        try:
            cb(ts, kind, message, path)
        except Exception:
            pass


def recent(limit: int = 500, kind: str | None = None) -> list[tuple]:
    with _lock:
        c = _db()
        if kind:
            return c.execute("SELECT ts, kind, message, path FROM events WHERE kind=? ORDER BY id DESC LIMIT ?",
                             (kind, limit)).fetchall()
        return c.execute("SELECT ts, kind, message, path FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def count(kind: str) -> int:
    with _lock:
        return _db().execute("SELECT COUNT(*) FROM events WHERE kind=?", (kind,)).fetchone()[0]


def clear() -> None:
    with _lock:
        c = _db()
        c.execute("DELETE FROM events")
        c.commit()


def add_listener(cb) -> None:
    _listeners.append(cb)


def reset_for_tests() -> None:
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
        _conn = None
