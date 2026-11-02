"""Motor de eliminação de falsos positivos.

Exclusões ESPECÍFICAS, AUDITÁVEIS e REVERSÍVEIS:

- A exclusão vale para o conteúdo exato do arquivo (SHA-256), nunca para um caminho ou pasta inteira:
  se o arquivo mudar (por exemplo, um vírus infectar o programa liberado), a exclusão deixa de valer.
- Escopo "arquivo": o arquivo inteiro é considerado legítimo.
  Escopo "regras": só as regras que geraram o alarme deixam de valer PARA AQUELE ARQUIVO; qualquer outra
  evidência continua sendo avaliada normalmente.
- Toda decisão guarda justificativa, data, caminho, regras responsáveis, pontuação e veredito no momento,
  e entra no histórico. Revogar desfaz a exclusão (o registro fica, marcado como revogado).
- Assinatura de malware conhecido (hash) e EICAR nunca podem ser liberados por aqui.
"""
from __future__ import annotations

import datetime
import json
import sqlite3
import threading

from . import history, paths

HARD_IDS = {"sig.hash", "test.eicar"}
_lock = threading.RLock()
_conn: sqlite3.Connection | None = None
_cache: dict[str, dict] | None = None


def _db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        from .db import open_db
        _conn = open_db(paths.data_dir() / "false_positives.db", [
            "CREATE TABLE IF NOT EXISTS fp (id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT NOT NULL, "
            "scope TEXT NOT NULL, rules TEXT, justification TEXT, path TEXT, threat TEXT, score INTEGER, "
            "verdict TEXT, created TEXT, active INTEGER DEFAULT 1, revoked TEXT, revoke_reason TEXT)",
            "CREATE INDEX IF NOT EXISTS fp_sha ON fp(sha256)"])
    return _conn


def reset_for_tests() -> None:
    global _conn, _cache
    with _lock:
        if _conn is not None:
            _conn.close()
        _conn, _cache = None, None


def _load() -> dict[str, dict]:
    global _cache
    with _lock:
        if _cache is None:
            c = _db()
            out: dict[str, dict] = {}
            for sha, scope, rules in c.execute("SELECT sha256, scope, rules FROM fp WHERE active=1"):
                d = out.setdefault(sha, {"file": False, "rules": set()})
                if scope == "arquivo":
                    d["file"] = True
                else:
                    d["rules"] |= set(json.loads(rules or "[]"))
            _cache = out
        return _cache


def lookup(sha256: str) -> dict | None:
    """{'file': bool, 'rules': set} se houver exclusão ativa para este conteúdo."""
    if not sha256:
        return None
    return _load().get(sha256)


def mark(result, justification: str, scope: str = "arquivo") -> int:
    """Marca um resultado (ScanResult) como falso positivo. Retorna o id da decisão."""
    if scope not in ("arquivo", "regras"):
        raise ValueError("escopo inválido")
    if not result.sha256:
        raise ValueError("resultado sem SHA-256: não dá para criar uma exclusão específica")
    if not (justification or "").strip():
        raise ValueError("informe o motivo (a decisão precisa ser auditável)")
    ids = sorted({i.id for i in result.indicators if i.weight > 0})
    if HARD_IDS & set(ids):
        raise PermissionError("Arquivo idêntico a malware conhecido (ou EICAR) não pode ser marcado como falso positivo.")
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        c = _db()
        cur = c.execute("INSERT INTO fp (sha256, scope, rules, justification, path, threat, score, verdict, created) "
                        "VALUES (?,?,?,?,?,?,?,?,?)",
                        (result.sha256, scope, json.dumps(ids), justification.strip()[:2000], result.path,
                         result.threat_name, result.score, result.verdict, now))
        c.commit()
        global _cache
        _cache = None
        fid = cur.lastrowid
    history.log("falso positivo", f"Marcado como falso positivo ({scope}): {result.threat_name} — "
                                  f"regras {', '.join(ids) or '—'} — motivo: {justification.strip()[:200]}",
                result.path)
    return fid


def revoke(fp_id: int, reason: str = "") -> None:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        c = _db()
        row = c.execute("SELECT sha256, path FROM fp WHERE id=?", (fp_id,)).fetchone()
        if not row:
            raise KeyError(fp_id)
        c.execute("UPDATE fp SET active=0, revoked=?, revoke_reason=? WHERE id=?", (now, reason[:500], fp_id))
        c.commit()
        global _cache
        _cache = None
    history.log("falso positivo", f"Exclusão #{fp_id} revogada{': ' + reason[:200] if reason else ''}", row[1] or "")


def decisions(include_revoked: bool = True) -> list[dict]:
    q = "SELECT id, sha256, scope, rules, justification, path, threat, score, verdict, created, active, revoked, " \
        "revoke_reason FROM fp" + ("" if include_revoked else " WHERE active=1") + " ORDER BY id DESC"
    with _lock:
        rows = _db().execute(q).fetchall()
    keys = ("id", "sha256", "scope", "rules", "justification", "path", "threat", "score", "verdict", "created",
            "active", "revoked", "revoke_reason")
    out = []
    for r in rows:
        d = dict(zip(keys, r))
        d["rules"] = json.loads(d["rules"] or "[]")
        d["active"] = bool(d["active"])
        out.append(d)
    return out


def rule_stats() -> list[tuple[str, int]]:
    """Regras que mais geraram falsos positivos confirmados — onde o motor precisa ser ajustado."""
    from collections import Counter
    cnt = Counter()
    for d in decisions(include_revoked=False):
        cnt.update(d["rules"])
    return cnt.most_common()


def apply(indicators: list, sha256: str):
    """Usado pelo motor: devolve (indicadores filtrados, indicador informativo ou None)."""
    fp = lookup(sha256)
    if not fp or any(i.id in HARD_IDS for i in indicators):
        return indicators, None
    from .engine.models import Indicator
    if fp["file"]:
        kept = [i for i in indicators if i.weight <= 0]
        note = "o arquivo inteiro"
    else:
        kept = [i for i in indicators if i.id not in fp["rules"]]
        note = "as regras " + ", ".join(sorted(fp["rules"]))
    info = Indicator(id="fp.user", name="Marcado como falso positivo por você", category="Confiança",
                     description=f"Você marcou este conteúdo exato (SHA-256) como falso positivo para {note}. "
                                 "Se o arquivo mudar, a exclusão deixa de valer. Revogue em Zero-Day → Falsos positivos.",
                     weight=0, severity="info", evidence=[sha256])
    return kept, info
