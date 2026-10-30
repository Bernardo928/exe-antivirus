"""Cofre de amostras: armazena arquivos perigosos de forma neutralizada.

O conteúdo é cifrado com XOR de chave aleatória por arquivo (o suficiente para
que o arquivo nunca possa ser executado nem reconhecido por acidente) e gravado
sem permissão de execução, com metadados em JSON ao lado.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
import uuid
from pathlib import Path

MAGIC = b"EXEAVQ01"
CHUNK = 1 << 20


def _xor_chunk(chunk: bytes, key: bytes, pos: int) -> bytes:
    klen = len(key)
    shift = pos % klen
    k = key[shift:] + key[:shift]
    reps = len(chunk) // klen + 1
    ks = (k * reps)[:len(chunk)]
    return (int.from_bytes(chunk, "little") ^ int.from_bytes(ks, "little")).to_bytes(len(chunk), "little")


class Vault:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _paths(self, item_id: str) -> tuple[Path, Path]:
        return self.root / f"{item_id}.bin", self.root / f"{item_id}.json"

    def store_bytes(self, data: bytes, meta: dict) -> str:
        item_id = uuid.uuid4().hex
        key = secrets.token_bytes(64)
        blob, mpath = self._paths(item_id)
        with open(blob, "wb") as f:
            f.write(MAGIC + key)
            for i in range(0, len(data), CHUNK):
                f.write(_xor_chunk(data[i:i + CHUNK], key, i))
        self._lock_down(blob)
        meta = dict(meta, id=item_id)
        mpath.write_text(json.dumps(meta, ensure_ascii=False, indent=1), "utf-8")
        return item_id

    def store_file(self, path: str, meta: dict) -> str:
        item_id = uuid.uuid4().hex
        key = secrets.token_bytes(64)
        blob, mpath = self._paths(item_id)
        with open(path, "rb") as src, open(blob, "wb") as f:
            f.write(MAGIC + key)
            pos = 0
            while True:
                c = src.read(CHUNK)
                if not c:
                    break
                f.write(_xor_chunk(c, key, pos))
                pos += len(c)
        self._lock_down(blob)
        meta = dict(meta, id=item_id)
        mpath.write_text(json.dumps(meta, ensure_ascii=False, indent=1), "utf-8")
        return item_id

    @staticmethod
    def _lock_down(p: Path) -> None:
        try:
            os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    def read(self, item_id: str) -> bytes:
        blob, _ = self._paths(item_id)
        raw = blob.read_bytes()
        if raw[:8] != MAGIC:
            raise ValueError("item do cofre corrompido")
        key, body = raw[8:72], raw[72:]
        return b"".join(_xor_chunk(body[i:i + CHUNK], key, i) for i in range(0, len(body), CHUNK))

    def extract_to(self, item_id: str, dest: str) -> None:
        blob, _ = self._paths(item_id)
        with open(blob, "rb") as f, open(dest, "wb") as out:
            head = f.read(72)
            if head[:8] != MAGIC:
                raise ValueError("item do cofre corrompido")
            key = head[8:]
            pos = 0
            while True:
                c = f.read(CHUNK)
                if not c:
                    break
                out.write(_xor_chunk(c, key, pos))
                pos += len(c)

    def meta(self, item_id: str) -> dict:
        _, mpath = self._paths(item_id)
        return json.loads(mpath.read_text("utf-8"))

    def update_meta(self, item_id: str, meta: dict) -> None:
        _, mpath = self._paths(item_id)
        mpath.write_text(json.dumps(meta, ensure_ascii=False, indent=1), "utf-8")

    def delete(self, item_id: str) -> None:
        for p in self._paths(item_id):
            try:
                p.unlink()
            except FileNotFoundError:
                pass

    def items(self) -> list[dict]:
        out = []
        for m in self.root.glob("*.json"):
            try:
                d = json.loads(m.read_text("utf-8"))
                if (self.root / f"{d['id']}.bin").exists():
                    out.append(d)
            except (OSError, ValueError, KeyError):
                continue
        out.sort(key=lambda d: d.get("date", ""), reverse=True)
        return out
