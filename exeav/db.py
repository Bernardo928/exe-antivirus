"""Abertura resiliente dos bancos SQLite: um arquivo corrompido nunca impede o programa de abrir."""
from __future__ import annotations

import datetime
import os
import sqlite3
from pathlib import Path


def _is_corruption(e: Exception) -> bool:
    msg = str(e).lower()
    return isinstance(e, sqlite3.DatabaseError) and not isinstance(e, sqlite3.OperationalError) or any(
        k in msg for k in ("not a database", "malformed", "disk image", "file is encrypted", "corrupt"))


def open_db(path: Path | str, init_sql: list[str], wal: bool = False) -> sqlite3.Connection:
    """Abre (ou recria) o banco. Se estiver corrompido, guarda uma cópia '.corrompido-*' e cria um novo."""
    path = Path(path)
    import time
    for attempt in range(2):
        conn = None
        try:
            conn = sqlite3.connect(str(path), timeout=30, check_same_thread=False)
            if wal:
                conn.execute("PRAGMA journal_mode=WAL")
            for retry in range(20):
                try:
                    for sql in init_sql:
                        conn.execute(sql)
                    conn.execute("SELECT 1").fetchone()
                    conn.commit()
                    break
                except sqlite3.OperationalError as e:
                    # banco em uso por outro processo NÃO é banco corrompido: espera e tenta de novo
                    if "locked" not in str(e).lower() and "busy" not in str(e).lower() or retry == 19:
                        raise
                    conn.rollback()
                    time.sleep(0.05 * (retry + 1))
            return conn
        except sqlite3.DatabaseError as e:
            if conn is not None:
                conn.close()
            if attempt or not _is_corruption(e):
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
