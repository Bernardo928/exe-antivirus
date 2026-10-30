"""Abertura resiliente dos bancos SQLite: um arquivo corrompido nunca impede o programa de abrir."""
from __future__ import annotations

import datetime
import os
import sqlite3
from pathlib import Path


def open_db(path: Path | str, init_sql: list[str], wal: bool = False) -> sqlite3.Connection:
    """Abre (ou recria) o banco. Se estiver corrompido, guarda uma cópia '.corrompido-*' e cria um novo."""
    path = Path(path)
    for attempt in range(2):
        conn = None
        try:
            conn = sqlite3.connect(str(path), timeout=30, check_same_thread=False)
            if wal:
                conn.execute("PRAGMA journal_mode=WAL")
            for sql in init_sql:
                conn.execute(sql)
            conn.execute("SELECT 1").fetchone()
            conn.commit()
            return conn
        except sqlite3.DatabaseError:
            if conn is not None:
                conn.close()
            if attempt:
                raise
            stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            for suffix in ("", "-wal", "-shm", "-journal"):
                p = Path(str(path) + suffix)
                if p.exists():
                    try:
                        os.replace(p, Path(f"{path}.corrompido-{stamp}{suffix}"))
                    except OSError:
                        p.unlink(missing_ok=True)
    raise sqlite3.DatabaseError(f"não foi possível abrir {path}")
