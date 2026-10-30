"""Gera exeav/data/rules.bin a partir de rules/rules_src.py.

Uso: python tools/build_rules.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "rules"))

import rules_src  # noqa: E402
from exeav.engine.rules import RULES_BIN, _build, encode_rules  # noqa: E402


def main() -> None:
    ids = set()
    for d in rules_src.RULES:
        if d["id"] in ids:
            raise SystemExit(f"id duplicado: {d['id']}")
        ids.add(d["id"])
        _build(d, "builtin")  # valida as expressões regulares
    RULES_BIN.parent.mkdir(parents=True, exist_ok=True)
    RULES_BIN.write_bytes(encode_rules(list(rules_src.RULES)))
    print(f"{len(rules_src.RULES)} regras gravadas em {RULES_BIN}")


if __name__ == "__main__":
    main()
