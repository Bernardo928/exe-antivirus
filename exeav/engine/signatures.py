"""Banco de assinaturas por hash (SHA-256 / SHA-1 / MD5) em SQLite."""
from __future__ import annotations

import hashlib
import re
import sqlite3
import threading
import urllib.request
from pathlib import Path

from .. import paths

_HEX_RE = re.compile(r"\b([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b")


class SignatureDB:
    def __init__(self, path: Path | None = None):
        self.path = path or (paths.data_dir() / "signatures.db")
        self._lock = threading.Lock()
        self._local = threading.local()
        from ..db import open_db
        self._local.conn = open_db(self.path, [
            "CREATE TABLE IF NOT EXISTS hashes (hash TEXT PRIMARY KEY, name TEXT, source TEXT)",
            "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)"])
        self._seed()
        self._refresh_stats()

    def _conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
            self._local.conn = c
        return c

    def _seed(self) -> None:
        # Hash do arquivo de teste EICAR (montado a partir da regra ofuscada, nunca em texto puro)
        from .rules import load_builtin_dicts
        for d in load_builtin_dicts():
            if d["id"] == "test.eicar":
                eicar = bytes.fromhex(d["all"][0][4:])
                for variant in (eicar, eicar + b"\r\n", eicar + b"\n"):
                    self.add(hashlib.sha256(variant).hexdigest(), "EICAR-Test-File", "interno")
                break

    def _refresh_stats(self) -> None:
        c = self._conn()
        self.count = c.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
        kinds = {r[0] for r in c.execute("SELECT DISTINCT length(hash) FROM hashes")}
        self.has_md5 = 32 in kinds
        self.has_sha1 = 40 in kinds
        row = c.execute("SELECT v FROM meta WHERE k='updated'").fetchone()
        self.updated = row[0] if row else ""

    @property
    def version(self) -> str:
        return f"{self.count}-{self.updated}"

    def add(self, h: str, name: str, source: str) -> None:
        with self._lock:
            c = self._conn()
            c.execute("INSERT OR IGNORE INTO hashes VALUES (?,?,?)", (h.lower(), name, source))
            c.commit()

    def lookup(self, sha256: str, md5: str = "", sha1: str = "") -> tuple[str, str] | None:
        c = self._conn()
        for h in (sha256, sha1, md5):
            if h:
                row = c.execute("SELECT name, source FROM hashes WHERE hash=?", (h.lower(),)).fetchone()
                if row:
                    return row
        return None

    def import_text(self, text: str, source: str, default_name: str = "Malware.Known") -> int:
        """Importa listas de hashes (um por linha, CSV do MalwareBazaar, 'hash;nome', etc.)."""
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "//")):
                continue
            m = _HEX_RE.search(line)
            if not m:
                continue
            name = default_name
            rest = line[m.end():].strip(" ,;\t\"")
            parts = [p.strip(" \"") for p in re.split(r"[;,\t]", rest) if p.strip(" \"")]
            for p in parts:
                if 2 < len(p) < 80 and not _HEX_RE.fullmatch(p) and not p.replace(" ", "").replace(":", "").replace("-", "").isdigit():
                    name = p
                    break
            rows.append((m.group(1).lower(), name, source))
        with self._lock:
            c = self._conn()
            before = c.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
            c.executemany("INSERT OR IGNORE INTO hashes VALUES (?,?,?)", rows)
            import datetime
            c.execute("INSERT OR REPLACE INTO meta VALUES ('updated', ?)",
                      (datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),))
            c.commit()
            added = c.execute("SELECT COUNT(*) FROM hashes").fetchone()[0] - before
        self._refresh_stats()
        return max(0, added)

    def import_file(self, path: str) -> int:
        raw = Path(path).read_bytes()
        if raw[:2] == b"PK":
            import io
            import zipfile
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                text = "\n".join(z.read(n).decode("utf-8", "replace") for n in z.namelist()[:20])
        else:
            text = raw.decode("utf-8", "replace")
        return self.import_text(text, Path(path).name)

    def update_from_url(self, url: str, timeout: int = 60) -> int:
        req = urllib.request.Request(url, headers={"User-Agent": "EXE-Antivirus/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(256 * 1024 * 1024)
        if raw[:2] == b"PK":
            import io
            import zipfile
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                text = "\n".join(z.read(n).decode("utf-8", "replace") for n in z.namelist()[:20])
        else:
            text = raw.decode("utf-8", "replace")
        return self.import_text(text, url.split("/")[2] if "//" in url else url)
