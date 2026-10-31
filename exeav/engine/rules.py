"""Carregamento e execução das regras de conteúdo.

As regras são distribuídas em exeav/data/rules.bin (JSON compactado e ofuscado
por XOR) para que o executável não contenha padrões maliciosos em texto puro.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from .models import Indicator

try:
    import ahocorasick  # pré-filtro em C, opcional
except ImportError:  # pragma: no cover
    ahocorasick = None

_KEY = b"EXEAV::rules::v1::\x13\x37\xc0\xde"
RULES_BIN = Path(__file__).resolve().parent.parent / "data" / "rules.bin"
USER_RULES_NAME = "user_rules.json"


def _xor(data: bytes) -> bytes:
    k = (_KEY * (len(data) // len(_KEY) + 1))[:len(data)]
    return (int.from_bytes(data, "little") ^ int.from_bytes(k, "little")).to_bytes(len(data), "little")


def encode_rules(rules: list[dict]) -> bytes:
    raw = json.dumps(rules, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return b"EXR1" + _xor(zlib.compress(raw, 9))


def decode_rules(blob: bytes) -> list[dict]:
    if blob[:4] != b"EXR1":
        raise ValueError("arquivo de regras inválido")
    return json.loads(zlib.decompress(_xor(blob[4:])).decode("utf-8"))


try:  # Python 3.11+
    from re import _constants as _sc
    from re import _parser as _sp
except ImportError:  # pragma: no cover
    import sre_constants as _sc  # type: ignore
    import sre_parse as _sp  # type: ignore

_REPEATS = {_sc.MAX_REPEAT, _sc.MIN_REPEAT} | ({_sc.POSSESSIVE_REPEAT} if hasattr(_sc, "POSSESSIVE_REPEAT") else set())


def _best(cands: list[frozenset]) -> frozenset | None:
    good = [c for c in cands if c and min(len(x) for x in c) >= 3]
    if not good:
        return None
    return max(good, key=lambda c: (min(len(x) for x in c), -len(c)))


def _required(seq) -> frozenset | None:
    """Conjunto de literais dos quais ao menos um precisa aparecer em qualquer casamento."""
    cands: list[frozenset] = []
    run = bytearray()
    for op, av in seq:
        if op is _sc.LITERAL:
            run.append(av)
            continue
        if run:
            cands.append(frozenset([bytes(run).lower()]))
            run = bytearray()
        if op is _sc.SUBPATTERN:
            r = _required(av[-1])
            if r:
                cands.append(r)
        elif op in _REPEATS:
            lo, _hi, item = av
            if lo >= 1:
                r = _required(item)
                if r:
                    cands.append(r)
        elif op is _sc.BRANCH:
            alts = [_required(b) for b in av[1]]
            if alts and all(alts):
                cands.append(frozenset().union(*alts))
    if run:
        cands.append(frozenset([bytes(run).lower()]))
    return _best(cands)


_POSSESSIVE_OK = sys.version_info >= (3, 11)
_WS_RE = re.compile(r"(?<!\\)((?:\\\\)*)(\\s[*+])(?![*+?])")


def harden(pattern: str) -> str:
    """Torna possessivos os '\\s*' e '\\s+' (nunca voltam atrás), eliminando ReDoS por espaços em branco.

    Ex.: '(?:\\s*\\(?\\s*x)' com 200 mil espaços passaria de tempo quadrático para linear."""
    if not _POSSESSIVE_OK or pattern.startswith("hex:"):
        return pattern
    return _WS_RE.sub(lambda m: m.group(1) + m.group(2) + "+", pattern)


_WINDOW = 2048
_WINDOW_MIN = 256 * 1024


class _Pat:
    """Expressão regular com pré-filtro literal (teste rápido 'in' antes da regex)."""
    __slots__ = ("rx", "anchors", "raw")

    def __init__(self, pattern: str):
        self.raw = None
        if pattern.startswith("hex:"):
            self.raw = bytes.fromhex(pattern[4:])
            self.rx = re.compile(re.escape(self.raw))
            self.anchors = None
            return
        b = harden(pattern).encode("utf-8")
        self.rx = re.compile(b, re.IGNORECASE)
        try:
            self.anchors = _required(_sp.parse(b, re.IGNORECASE))
        except Exception:
            self.anchors = None

    def search(self, buf: bytes, low: bytes, present: set | None = None):
        if self.raw is not None:
            i = buf.find(self.raw)
            return _Hit(self.raw) if i >= 0 else None
        if self.anchors is None:
            return self.rx.search(buf)
        if present is not None:
            found = self.anchors & present
        else:
            found = [a for a in self.anchors if a in low]
        if not found:
            return None
        if len(buf) <= _WINDOW_MIN:
            return self.rx.search(buf)
        # Buffer grande: roda a regex apenas em janelas ao redor de cada ocorrência da âncora.
        for a in found:
            pos, n = low.find(a), 0
            while pos >= 0 and n < 200:
                m = self.rx.search(buf[max(0, pos - _WINDOW): pos + len(a) + _WINDOW])
                if m:
                    return m
                pos = low.find(a, pos + len(a) + _WINDOW)
                n += 1
        return None


class _Hit:
    __slots__ = ("_g",)

    def __init__(self, g: bytes):
        self._g = g

    def group(self) -> bytes:
        return self._g


def _compile(pattern: str) -> _Pat:
    return _Pat(pattern)


@dataclass
class Rule:
    id: str
    name: str
    category: str
    family: str
    severity: str
    weight: int
    targets: frozenset
    description: str
    all: list = field(default_factory=list)
    any: list = field(default_factory=list)
    min: int = 1
    source: str = "builtin"
    bonus: bool = False

    def __post_init__(self):
        # Pré-condição barata: conjuntos de âncoras que precisam estar presentes no conteúdo.
        self.need: list[frozenset] = [p.anchors for p in self.all if p.anchors]
        if self.any and all(p.anchors for p in self.any):
            self.need.append(frozenset().union(*(p.anchors for p in self.any)))

    def possible(self, present: set) -> bool:
        for n in self.need:
            if n.isdisjoint(present):
                return False
        return True

    def applies(self, target: str) -> bool:
        return "any" in self.targets or target in self.targets

    def match(self, buf: bytes, low: bytes, present: set | None = None) -> list[str] | None:
        evidence: list[str] = []
        # 1) padrões obrigatórios com pré-filtro literal (baratos)
        slow_all = []
        for rx in self.all:
            if rx.raw is None and rx.anchors is None:
                slow_all.append(rx)
                continue
            m = rx.search(buf, low, present)
            if not m:
                return None
            evidence.append(_ev(m.group()))
        # 2) padrões alternativos
        hits = 0
        if self.any:
            for rx in self.any:
                m = rx.search(buf, low, present)
                if m:
                    hits += 1
                    evidence.append(_ev(m.group()))
            if hits < self.min:
                return None
        # 3) padrões obrigatórios sem pré-filtro (regex completa)
        for rx in slow_all:
            m = rx.search(buf, low, present)
            if not m:
                return None
            evidence.append(_ev(m.group()))
        self._last_extra = max(0, hits - max(self.min, 1)) if self.any else 0
        return evidence


def _ev(b: bytes) -> str:
    s = b[:160].decode("latin-1")
    s = "".join(c if 32 <= ord(c) < 127 else "." for c in s)
    return s + ("…" if len(b) > 160 else "")


def _build(d: dict, source: str) -> Rule:
    return Rule(
        id=d["id"], name=d["name"], category=d.get("category", "Genérico"),
        family=d.get("family", "Heur.Generic"), severity=d.get("severity", "media"),
        weight=int(d.get("weight", 20)), targets=frozenset(d.get("targets", ["any"])),
        description=d.get("description", ""),
        all=[_compile(p) for p in d.get("all", [])], any=[_compile(p) for p in d.get("any", [])],
        min=int(d.get("min", 1)), source=source, bonus=bool(d.get("bonus", False)),
    )


def load_builtin_dicts() -> list[dict]:
    if RULES_BIN.exists():
        return decode_rules(RULES_BIN.read_bytes())
    # Ambiente de desenvolvimento: lê a fonte legível
    src = Path(__file__).resolve().parents[2] / "rules"
    sys.path.insert(0, str(src))
    try:
        import rules_src  # type: ignore
        return list(rules_src.RULES)
    finally:
        sys.path.remove(str(src))


def validate_user_rules(text: str) -> list[dict]:
    """Valida o JSON de regras personalizadas. Lança ValueError com mensagem amigável."""
    try:
        data = json.loads(text or "[]")
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON inválido: {e}") from e
    if not isinstance(data, list):
        raise ValueError("O arquivo deve conter uma lista de regras.")
    for i, d in enumerate(data):
        if not isinstance(d, dict) or "id" not in d or "name" not in d:
            raise ValueError(f"Regra #{i + 1}: campos obrigatórios 'id' e 'name'.")
        if not d.get("all") and not d.get("any"):
            raise ValueError(f"Regra '{d['id']}': informe padrões em 'all' ou 'any'.")
        try:
            _build(d, "user")
        except re.error as e:
            raise ValueError(f"Regra '{d['id']}': expressão regular inválida ({e}).") from e
        except ValueError as e:
            raise ValueError(f"Regra '{d['id']}': {e}") from e
    return data


class RuleSet:
    def __init__(self, user_rules_path: Path | None = None):
        dicts = load_builtin_dicts()
        self.rules = [_build(d, "builtin") for d in dicts]
        self.user_rules_path = user_rules_path
        if user_rules_path and user_rules_path.exists():
            try:
                for d in validate_user_rules(user_rules_path.read_text("utf-8")):
                    self.rules.append(_build(d, "user"))
            except (OSError, ValueError):
                pass
        h = hashlib.sha256()
        for d in dicts:
            h.update(json.dumps(d, sort_keys=True).encode())
        if user_rules_path and user_rules_path.exists():
            h.update(user_rules_path.read_bytes())
        self.version = h.hexdigest()[:12]
        self._by_target: dict[str, list[Rule]] = {}
        self._automata: dict[str, object] = {}

    def for_target(self, target: str) -> list[Rule]:
        lst = self._by_target.get(target)
        if lst is None:
            lst = [r for r in self.rules if r.applies(target)]
            self._by_target[target] = lst
        return lst

    def _automaton(self, target: str):
        """Autômato Aho-Corasick com todos os literais-âncora das regras do alvo (uma única passada)."""
        if ahocorasick is None:
            return None
        if target not in self._automata:
            words = set()
            for r in self.for_target(target):
                for p in r.all + r.any:
                    if p.anchors:
                        words |= p.anchors
            a = ahocorasick.Automaton()
            for w in words:
                a.add_word(w.decode("latin-1"), w)
            a.make_automaton()
            self._automata[target] = a if words else None
        return self._automata[target]

    def run(self, buf: bytes, target: str) -> list[Indicator]:
        out = []
        low = buf.lower()
        present = None
        ac = self._automaton(target)
        if ac is not None:
            present = {w for _end, w in ac.iter(low.decode("latin-1"))}
        for r in self.for_target(target):
            if present is not None and not r.possible(present):
                continue
            ev = r.match(buf, low, present)
            if ev is not None:
                weight = r.weight
                if r.bonus and r.weight > 0:
                    # várias técnicas diferentes da mesma família = evidência mais forte (até +20)
                    weight += min(getattr(r, "_last_extra", 0), 2) * 10
                out.append(Indicator(id=r.id, name=r.name, category=r.category, description=r.description,
                                     weight=weight, severity=r.severity, evidence=ev, family=r.family))
        return out
