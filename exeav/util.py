"""Funções utilitárias: entropia, hashes, extração de strings, formatação."""
from __future__ import annotations

import hashlib
import math
import os
import re
from collections import Counter

_ASCII_RE = re.compile(rb"[\x20-\x7e\t]{5,}")
_WIDE_RE = re.compile(rb"(?:[\x20-\x7e\t]\x00){5,}")


def entropy(data: bytes) -> float:
    """Entropia de Shannon (0..8 bits por byte). Amostra blocos grandes para ser rápida."""
    if not data:
        return 0.0
    if len(data) > 262_144:
        step = len(data) // 8
        data = b"".join(data[i * step: i * step + 32768] for i in range(8))
    n = len(data)
    counts = Counter(data).values()
    return -sum((c / n) * math.log2(c / n) for c in counts)


def entropy_profile(data: bytes, blocks: int = 128) -> list[float]:
    """Entropia por bloco, usada no gráfico da Sala de Análise."""
    if not data:
        return []
    size = max(256, len(data) // blocks)
    return [entropy(data[i:i + size]) for i in range(0, len(data), size)][:blocks * 2]


def hashes_of_bytes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def extract_strings(data: bytes, min_len: int = 5, limit: int = 20000) -> list[str]:
    """Strings ASCII e UTF-16LE presentes no binário."""
    out: list[str] = []
    rx_a = _ASCII_RE if min_len == 5 else re.compile(rb"[\x20-\x7e\t]{%d,}" % min_len)
    rx_w = _WIDE_RE if min_len == 5 else re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}" % min_len)
    for m in rx_a.finditer(data):
        out.append(m.group().decode("ascii", "replace"))
        if len(out) >= limit:
            return out
    for m in rx_w.finditer(data):
        out.append(m.group().decode("utf-16le", "replace"))
        if len(out) >= limit:
            break
    return out


def wide_strings_blob(data: bytes, limit_bytes: int = 4_000_000) -> bytes:
    """Converte as strings UTF-16LE em ASCII para que as regras textuais as enxerguem."""
    parts = []
    total = 0
    for m in _WIDE_RE.finditer(data):
        s = m.group().replace(b"\x00", b"")
        parts.append(s)
        total += len(s)
        if total > limit_bytes:
            break
    return b"\n".join(parts)


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def hexdump(data: bytes, offset: int = 0, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join(f"{b:02X}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset + i:08X}  {hx:<{width * 3}} {asc}")
    return "\n".join(lines)


def safe_stat(path: str):
    try:
        return os.stat(path, follow_symlinks=False)
    except OSError:
        return None


URL_RE = re.compile(r"(?:https?|ftp|wss?|stratum\+tcp)://[^\s\"'<>()\\]{4,200}", re.I)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{2,5})?\b")
EMAIL_RE = re.compile(r"\b[\w.+-]{2,40}@[\w-]{2,40}\.[a-z]{2,10}\b", re.I)
REG_RE = re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|SOFTWARE\\|SYSTEM\\CurrentControlSet)[\\A-Za-z0-9 _.{}-]*", re.I)
WINPATH_RE = re.compile(r"\b[A-Za-z]:\\[^\s\"'<>|*?]{3,200}|%[A-Za-z]+%\\[^\s\"'<>|*?]{2,200}")
NIXPATH_RE = re.compile(r"(?<![\w.])/(?:etc|bin|sbin|usr|tmp|var|dev|proc|root|home|lib|opt|boot)/[\w./-]{2,200}")
BTC_RE = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ONION_RE = re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.I)


def classify_strings(strings: list[str]) -> dict[str, list[str]]:
    """Separa strings interessantes por categoria (URLs, IPs, caminhos, registro...)."""
    cats: dict[str, set[str]] = {k: set() for k in
                                 ("urls", "ips", "emails", "registro", "caminhos", "bitcoin", "onion")}
    for s in strings:
        if len(s) > 4000:
            s = s[:4000]
        for m in URL_RE.findall(s):
            cats["urls"].add(m)
        for m in IPV4_RE.findall(s):
            if not m.startswith(("0.", "255.")) and m.count(".") == 3:
                cats["ips"].add(m)
        for m in EMAIL_RE.findall(s):
            cats["emails"].add(m)
        for m in REG_RE.findall(s):
            if len(m) > 6:
                cats["registro"].add(m)
        for m in WINPATH_RE.findall(s):
            cats["caminhos"].add(m)
        for m in NIXPATH_RE.findall(s):
            cats["caminhos"].add(m)
        for m in ONION_RE.findall(s):
            cats["onion"].add(m)
        if 25 <= len(s) <= 90:
            for m in BTC_RE.findall(s):
                if any(c.isdigit() for c in m) and any(c.isupper() for c in m) or m.startswith("bc1"):
                    cats["bitcoin"].add(m)
    return {k: sorted(v)[:500] for k, v in cats.items()}
