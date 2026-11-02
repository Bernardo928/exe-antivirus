"""Histórico de eventos (varreduras, detecções, ações) em SQLite."""
from __future__ import annotations

import datetime
import hashlib
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
        try:   # versões antigas não tinham o encadeamento por hash
            _conn.execute("ALTER TABLE events ADD COLUMN chain TEXT")
            _conn.commit()
        except sqlite3.OperationalError:
            pass
    return _conn


def _link(prev: str, ts: str, kind: str, message: str, path: str) -> str:
    """Cada evento guarda o hash do anterior: alterar ou apagar um evento do meio quebra a corrente."""
    return hashlib.sha256("\x1f".join((prev, ts, kind, message, path)).encode("utf-8", "replace")).hexdigest()


def _head_file():
    return paths.data_dir() / "history.head"


def _last_chain(c) -> str:
    row = c.execute("SELECT chain FROM events WHERE chain IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
    return row[0] if row else ""


def verify() -> dict:
    """Confere a integridade do histórico. {'ok', 'eventos', 'problema'}"""
    with _lock:
        c = _db()
        rows = c.execute("SELECT id, ts, kind, message, path, chain FROM events WHERE chain IS NOT NULL "
                         "ORDER BY id").fetchall()
        try:
            head = _head_file().read_text("utf-8").strip()
        except OSError:
            head = ""
    prev, last_id = "", None
    for rid, ts, kind, msg, path, chain in rows:
        if kind == "auditoria" and msg.startswith("Histórico limpo"):
            prev = ""          # limpeza legítima feita pelo usuário reinicia a corrente
        elif last_id is not None and rid != last_id + 1:
            return {"ok": False, "eventos": len(rows), "problema": f"eventos apagados antes do #{rid}"}
        if _link(prev, ts, kind, msg, path or "") != chain:
            return {"ok": False, "eventos": len(rows), "problema": f"evento #{rid} foi alterado"}
        prev, last_id = chain, rid
    if rows and head and head != prev:
        return {"ok": False, "eventos": len(rows), "problema": "eventos mais recentes foram apagados"}
    return {"ok": True, "eventos": len(rows), "problema": ""}


def log(kind: str, message: str, path: str = "") -> None:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        c = _db()
        if c.in_transaction:
            c.commit()
        c.execute("BEGIN IMMEDIATE")    # serializa com outras instâncias (GUI + linha de comando)
        try:
            chain = _link(_last_chain(c), ts, kind, message, path or "")
            c.execute("INSERT INTO events (ts, kind, message, path, chain) VALUES (?,?,?,?,?)",
                      (ts, kind, message, path, chain))
            c.commit()
        except Exception:
            c.rollback()
            raise
        try:
            _head_file().write_text(chain, "utf-8")
        except OSError:
            pass
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
    log("auditoria", "Histórico limpo pelo usuário")


def add_listener(cb) -> None:
    _listeners.append(cb)


def reset_for_tests() -> None:
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
        _conn = None
