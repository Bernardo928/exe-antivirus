"""Desofuscação de scripts (CMD, PowerShell, VBScript, JavaScript, PHP, shell).

Reconstrói o texto "real" que o interpretador executaria, desfazendo truques comuns:
circunflexos e aspas no CMD, variáveis do SET, crases do PowerShell, concatenação de
strings, operador -f, [char]/Chr()/fromCharCode, strings invertidas, .Replace() e
Base64 curtos passados direto para funções de decodificação.

O resultado é usado APENAS para análise (é anexado ao conteúdo original).
"""
from __future__ import annotations

import base64
import binascii
import re

MAX_CHARS = 2 * 1024 * 1024


def _c(pattern: str, flags: int = 0) -> re.Pattern:
    from .rules import harden
    return re.compile(harden(pattern), flags)

_CARET = _c(r"\^(?=[\w\"%\\/.\-&|<>(),:=])")
_BACKTICK = _c(r"`(?=[A-Za-z0-9\-_.:\\/'\"])")
_CMD_QUOTES = _c(r"(?<=[\w.%\\])\"+(?=[\w.%\\])|(?<=\s)\"\"(?=\w)")
_SET = _c(r"^[ \t]*+@?[ \t]*+set[ \t]++(?:/a[ \t]++)?\"?([A-Za-z_][\w.#$-]{0,40})=([^\r\n\"]{0,400})\"?[ \t]*+$|"
                  r"(?<![\w])set[ \t]++\"?([A-Za-z_][\w.#$-]{0,40})=([^\r\n&\"]{0,400})", re.I | re.M)
_CONCAT_SAME = _c(r"(['\"])([^'\"\r\n]{0,400})\1\s*(?:\+|&|\.(?!\w))\s*\1([^'\"\r\n]{0,400})\1")
_CONCAT_MIXED = _c(r"(['\"])([^'\"\r\n]{0,400})\1\s*(?:\+|&|\.(?!\w))\s*(['\"])([^'\"\r\n]{0,400})\3")
_FORMAT = _c(r"\(\s*(['\"])((?:\{\d{1,2}\}|[^'\"{}\r\n]){1,300}?)\1\s*-f\s*((?:(['\"])[^'\"\r\n]{0,200}\4\s*,\s*){0,30}"
                     r"(['\"])[^'\"\r\n]{0,200}\5)\s*\)", re.I)
_FMT_ARG = _c(r"(['\"])([^'\"\r\n]{0,200})\1")
_PS_CHAR = _c(r"\[char\]\s*\(?\s*(0x[0-9a-f]{1,4}|\d{1,5})\s*\)?", re.I)
_VB_CHR = _c(r"\bchr[wb]?\$?\s*\(\s*(\d{1,5})\s*\)", re.I)
_NUM_LIST = _c(r"(?:\[char\[\]\]|\[char\]\s*\[\s*\]|fromcharcode|\bchr\b|\[byte\[\]\])\s*\(?\s*\(?\s*"
                       r"((?:(?:0x[0-9a-f]{1,4}|\d{1,5})\s*,\s*){3,4000}(?:0x[0-9a-f]{1,4}|\d{1,5}))", re.I)
_REVERSED = _c(r"(['\"])([^'\"\r\n]{4,400})\1\s*\[\s*-1\s*\.\.\s*-?\(?[\w.$ +-]{1,40}\)?\s*\]")
_STRREVERSE = _c(r"strreverse\s*\(\s*(['\"])([^'\"\r\n]{4,400})\1\s*\)", re.I)
_REPLACE = _c(r"(['\"])([^'\"\r\n]{1,400})\1\s*(?:\.replace\s*\(|-replace\s*)\s*(['\"])([^'\"\r\n]{1,30})\3"
                      r"\s*,\s*(['\"])([^'\"\r\n]{0,30})\5\s*\)?", re.I)
_B64_CALL = _c(r"(?:frombase64string|b64decode|atob|base64_decode|decodestring|base64\s+(?:-d|--decode|-D))"
                       r"\s*\(?\s*\(?\s*['\"]?([A-Za-z0-9+/=_-]{8,})['\"]?", re.I)
_B64_ECHO = _c(r"(?:echo|printf)\s+(?:-[ne]+\s+)?['\"]?([A-Za-z0-9+/=]{12,})['\"]?\s*\|\s*base64\s+(?:-d|--decode|-D)")


def _quote_char(code: int) -> str | None:
    try:
        c = chr(code)
    except (ValueError, OverflowError):
        return None
    if c in "'\"\r\n\x00" or not (c.isprintable() or c in "\t"):
        return None
    return c


def _num(tok: str) -> int:
    return int(tok, 16) if tok.lower().startswith("0x") else int(tok)


def _cmd_vars(s: str) -> str:
    env: dict[str, str] = {}
    for m in _SET.finditer(s):
        name = m.group(1) or m.group(3)
        val = m.group(2) if m.group(1) else m.group(4)
        if name and val is not None:
            env[name.lower()] = val.strip()
        if len(env) > 500:
            break
    if not env:
        return s

    def sub_slice(m):
        v = env.get(m.group(1).lower())
        if v is None:
            return m.group(0)
        a = int(m.group(2))
        b = m.group(3)
        if b is None:
            return v[a:]
        b = int(b)
        start = a if a >= 0 else len(v) + a
        return v[start:start + b] if b >= 0 else v[start:len(v) + b]
    s = re.sub(r"%([\w.#$-]{1,40}):~(-?\d{1,4})(?:,(-?\d{1,4}))?%", sub_slice, s)
    return re.sub(r"[%!]([\w.#$-]{1,40})[%!]", lambda m: env.get(m.group(1).lower(), m.group(0)), s)


def _join_concat(s: str) -> str:
    for _ in range(40):
        n = _CONCAT_SAME.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{m.group(1)}", s)
        n = _CONCAT_MIXED.sub(lambda m: f"'{m.group(2)}{m.group(4)}'", n)
        if n == s:
            break
        s = n
    return s


def _format(m: re.Match) -> str:
    fmt = m.group(2)
    args = [a[1] for a in _FMT_ARG.findall(m.group(3))]
    try:
        out = re.sub(r"\{(\d{1,2})\}", lambda k: args[int(k.group(1))], fmt)
    except IndexError:
        return m.group(0)
    return f"('{out}')"


def _num_list(m: re.Match) -> str:
    chars = []
    for tok in re.findall(r"0x[0-9a-f]{1,4}|\d{1,5}", m.group(1), re.I):
        try:
            c = chr(_num(tok))
        except (ValueError, OverflowError):
            return m.group(0)
        if not (c.isprintable() or c in "\r\n\t"):
            return m.group(0)
        chars.append(c)
    # o texto decodificado vai em uma linha própria (pode conter aspas)
    return m.group(0) + "\n" + "".join(chars) + "\n"


def _replace(m: re.Match) -> str:
    return f"{m.group(1)}{m.group(2).replace(m.group(4), m.group(6))}{m.group(1)}"


def normalize(text: str) -> str:
    """Retorna a versão desofuscada do script (pode ser igual à original)."""
    s = text[:MAX_CHARS]
    for _ in range(3):
        before = s
        s = _CARET.sub("", s)
        s = _CMD_QUOTES.sub("", s)
        s = _cmd_vars(s)
        s = _BACKTICK.sub("", s)
        s = _PS_CHAR.sub(lambda m: (f"'{c}'" if (c := _quote_char(_num(m.group(1)))) else m.group(0)), s)
        s = _VB_CHR.sub(lambda m: (f"\"{c}\"" if (c := _quote_char(int(m.group(1)))) else m.group(0)), s)
        s = _NUM_LIST.sub(_num_list, s)
        s = _join_concat(s)
        s = _FORMAT.sub(_format, s)
        s = _REVERSED.sub(lambda m: f"{m.group(1)}{m.group(2)[::-1]}{m.group(1)}", s)
        s = _STRREVERSE.sub(lambda m: f"\"{m.group(2)[::-1]}\"", s)
        s = _REPLACE.sub(_replace, s)
        s = _join_concat(s)
        if s == before:
            break
    return s


def _try_b64(tok: str) -> str | None:
    tok = tok.replace("-", "+").replace("_", "/")
    try:
        raw = base64.b64decode(tok + "=" * (-len(tok) % 4))
    except (binascii.Error, ValueError):
        return None
    for cand in (raw.decode("utf-16le", "ignore") if raw[1:2] == b"\x00" else None, raw.decode("utf-8", "ignore")):
        if cand and len(cand) >= 4 and sum(ch.isprintable() or ch in "\r\n\t" for ch in cand) / len(cand) > 0.9:
            return cand
    return None


def short_base64_layers(text: str, limit: int = 40) -> list[str]:
    """Decodifica Base64 passado diretamente a funções de decodificação (mesmo quando curto)."""
    out = []
    for rx in (_B64_CALL, _B64_ECHO):
        for m in rx.finditer(text[:MAX_CHARS]):
            dec = _try_b64(m.group(1))
            if dec:
                out.append(dec)
            if len(out) >= limit:
                return out
    return out


_MD_LINE = re.compile(r"^\s{0,3}(?:#{1,6}\s+\S|[-*+]\s+\S|\d{1,3}[.)]\s+\S|>\s|```|~~~|\|.*\|\s*$)")
_MD_LINK = re.compile(r"\[[^\]\n]{1,120}\]\((?:https?://|#|\.{0,2}/)[^)\s]{1,300}\)")
_WORD = re.compile(r"[A-Za-zÀ-ÿ]{2,}")


def looks_like_documentation(text: str) -> bool:
    """Documentação (Markdown, METADATA do PyPI, manuais): muitos marcadores de Markdown e prosa.

    Decidido pelo CONTEÚDO, nunca pela extensão do arquivo."""
    sample = text[:200_000]
    lines = [ln for ln in sample.splitlines() if ln.strip()][:4000]
    if len(lines) < 8:
        return False
    md = sum(1 for ln in lines if _MD_LINE.match(ln))
    links = len(_MD_LINK.findall(sample))
    fences = sample.count("```") + sample.count("~~~")
    prose = 0
    for ln in lines:
        words = _WORD.findall(ln)
        if len(words) >= 7 and sum(ln.count(c) for c in ";{}$=<>|&") <= 2:
            prose += 1
    if fences < 2 and md + links < 6:
        return False
    return prose / len(lines) >= 0.2 and (md + links) >= 4
