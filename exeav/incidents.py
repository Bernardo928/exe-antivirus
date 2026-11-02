"""Centro de relatórios de ameaças (Zero-Day & Threat Intelligence Center).

Cada detecção relevante vira um INCIDENTE com evidências:
identificador, data, sistema, hashes (SHA-256, SHA-512, SHA3-256), tipo, origem conhecida (marca da
internet do Windows / atributo de origem do Linux), assinatura digital, comportamentos, indicadores,
regras acionadas, processo e cadeia de processos, conexões, nível de confiança, ações e resultado.

"Ameaça desconhecida" = detectada por COMPORTAMENTO ou HEURÍSTICA, sem assinatura de malware catalogado.
O EXE Antivirus nunca chama isso de "zero-day confirmado": o status começa como "em investigação" e só
muda por decisão do usuário (ameaça confirmada / falso positivo) ou por assinatura conhecida.

Privacidade: nada é enviado para fora. As evidências ficam neste computador.
Ocorrências repetidas do mesmo conteúdo NÃO geram alertas novos: somam ao incidente existente.
"""
from __future__ import annotations

import datetime
import hashlib
import html
import json
import os
import platform
import sqlite3
import threading
import uuid

from . import history, paths

CLASSES = ("informativo", "suspeito", "alto risco", "crítico")
STATUSES = ("em investigação", "ameaça confirmada", "falso positivo", "resolvido")
_lock = threading.RLock()
_conn: sqlite3.Connection | None = None
_listeners: list = []
MAX_EVIDENCE = 64 * 1024 * 1024


def _db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        from .db import open_db
        _conn = open_db(paths.data_dir() / "incidents.db", [
            "CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, created TEXT, updated TEXT, dedup TEXT, "
            "classification TEXT, status TEXT, confidence TEXT, unknown INTEGER, score INTEGER, sha256 TEXT, "
            "path TEXT, threat TEXT, source TEXT, occurrences INTEGER, data TEXT)",
            "CREATE INDEX IF NOT EXISTS inc_dedup ON incidents(dedup)",
            "CREATE INDEX IF NOT EXISTS inc_created ON incidents(created)"])
    return _conn


def reset_for_tests() -> None:
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
        _conn = None


def add_listener(cb) -> None:
    """cb(incidente: dict, novo: bool) — chamado a cada registro."""
    _listeners.append(cb)


def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- coleta de evidências
def file_hashes(path: str = "", data: bytes | None = None) -> dict:
    h = {"sha256": hashlib.sha256(), "sha512": hashlib.sha512(), "sha3_256": hashlib.sha3_256()}
    if data is not None:
        for x in h.values():
            x.update(data)
    else:
        with open(path, "rb") as f:
            while True:
                b = f.read(1 << 20)
                if not b:
                    break
                for x in h.values():
                    x.update(b)
    return {k: v.hexdigest() for k, v in h.items()}


def file_origin(path: str) -> dict:
    """De onde o arquivo veio, quando o sistema registra isso (nunca consulta a internet)."""
    out = {}
    try:
        if paths.IS_WINDOWS:
            with open(path + ":Zone.Identifier", "r", encoding="utf-8", errors="replace") as f:
                for line in f.read().splitlines():
                    if "=" in line:
                        k, v = line.split("=", 1)
                        if k in ("ZoneId", "HostUrl", "ReferrerUrl"):
                            out[k] = v.strip()
            zone = {"3": "internet", "4": "site não confiável", "2": "sites confiáveis", "1": "intranet",
                    "0": "este computador"}.get(out.get("ZoneId", ""), "")
            if zone:
                out["zona"] = zone
        else:
            for attr in ("user.xdg.origin.url", "user.xdg.referrer.url"):
                try:
                    out[attr.split(".")[-2]] = os.getxattr(path, attr).decode("utf-8", "replace")
                except (OSError, AttributeError):
                    pass
    except OSError:
        pass
    return out


def signature_info(path: str) -> dict:
    try:
        from .engine import trust
        ok, desc = trust.check(path)
    except Exception:
        ok, desc = False, ""
    if ok:
        return {"status": "assinado/confiável", "detalhe": desc}
    if desc.startswith("ATENÇÃO"):
        return {"status": "ALTERADO depois de instalado", "detalhe": desc}
    return {"status": "sem assinatura verificável",
            "detalhe": "Não assinado não significa malicioso: só que a origem não pôde ser comprovada."}


def process_info(pid: int | None) -> dict:
    if not pid:
        return {}
    try:
        import psutil
        p = psutil.Process(pid)
        info = {"pid": pid, "nome": p.name(), "executavel": p.exe() or "", "linha_de_comando": " ".join(p.cmdline())[:1000],
                "inicio": datetime.datetime.fromtimestamp(p.create_time()).strftime("%Y-%m-%d %H:%M:%S")}
        try:
            info["usuario"] = p.username()
        except psutil.Error:
            pass
        chain = []
        for a in p.parents()[:8]:
            try:
                chain.append({"pid": a.pid, "nome": a.name(), "executavel": a.exe() or ""})
            except psutil.Error:
                chain.append({"pid": a.pid})
        info["cadeia_de_processos"] = chain
        try:
            conns = p.net_connections(kind="inet") if hasattr(p, "net_connections") else p.connections(kind="inet")
            info["conexoes"] = [f"{c.raddr.ip}:{c.raddr.port} ({c.status})" for c in conns if c.raddr][:40]
        except (psutil.Error, OSError):
            pass
        return info
    except Exception:
        return {"pid": pid, "observacao": "processo já tinha terminado quando as evidências foram coletadas"}


def classify(verdict: str, confidence: str, behavioral_critical: bool = False) -> str:
    if verdict == "malicioso":
        return "crítico" if confidence in ("confirmada", "alta") or behavioral_critical else "alto risco"
    if verdict == "suspeito":
        return "suspeito"
    return "informativo"


# --------------------------------------------------------------------------- registro
def collect(path: str) -> dict:
    """Evidências que se perdem quando o arquivo vai para a quarentena (chamar ANTES de isolar)."""
    pre = {}
    try:
        if path and os.path.isfile(path):
            pre = {"hashes": file_hashes(path), "origem": file_origin(path), "assinatura_digital": signature_info(path),
                   "tamanho": os.path.getsize(path)}
    except OSError:
        pass
    return pre


def report(result=None, source: str = "", pid: int | None = None, action: str = "", events: list | None = None,
           behavior: dict | None = None, data: bytes | None = None, quarantine_id: str = "",
           pre: dict | None = None, process: dict | None = None) -> tuple[str, bool]:
    """Registra (ou atualiza) um incidente. Retorna (id, novo?).

    result: ScanResult da detecção (arquivo/script) ou None para detecções só comportamentais.
    behavior: {'title', 'verdict', 'score', 'indicators': [{'name','weight','description','evidence'}],
               'critical': bool} para detecções de comportamento (botnet, ransomware...).
    data: conteúdo analisado quando não há arquivo (script capturado da memória)."""
    try:
        return _report(result, source, pid, action, events, behavior, data, quarantine_id, pre or {}, process)
    except Exception as e:  # noqa: BLE001 — registrar evidências nunca pode impedir a proteção
        history.log("erro", f"Falha ao registrar incidente: {type(e).__name__}: {e}")
        return "", False


def _report(result, source, pid, action, events, behavior, data, quarantine_id, pre, process=None):
    path = result.path if result is not None else (behavior or {}).get("path", "")
    real_path = path if path and os.path.isfile(path) else ""
    hashes = {}
    if real_path:
        try:
            hashes = file_hashes(real_path)
        except OSError:
            hashes = {}
    elif data is not None:
        hashes = file_hashes(data=data)
    if not hashes and pre.get("hashes"):
        hashes = pre["hashes"]
    if not hashes and result is not None and result.sha256:
        hashes = {"sha256": result.sha256}
    if result is not None:
        inds = [i.to_dict() for i in result.indicators]
        verdict, score, threat = result.verdict, result.score, result.threat_name
        confidence = result.confidence
        rules = sorted({i.id for i in result.indicators if i.weight > 0})
        groups = result.evidence_groups
        known = any(i.id in ("sig.hash", "test.eicar") for i in result.indicators)
        ftype = result.file_type
    else:
        b = behavior or {}
        inds = b.get("indicators", [])
        verdict, score, threat = b.get("verdict", "suspeito"), int(b.get("score", 0)), b.get("title", "Comportamento")
        groups = sorted({i.get("category", "Comportamento") for i in inds if i.get("weight", 0) > 0})
        rules = sorted({i.get("id", "") for i in inds if i.get("id")})
        confidence = "alta" if verdict == "malicioso" and len(inds) >= 3 else "média" if len(inds) >= 2 else "baixa"
        known = bool(b.get("known"))
        ftype = "comportamento"
    classification = classify(verdict, confidence, bool((behavior or {}).get("critical")))
    unknown = not known
    dedup = hashes.get("sha256") or f"{source}|{threat}|{path or (behavior or {}).get('key', '')}"
    now = _now()
    event = {"quando": now, "fonte": source, "acao": action, "pid": pid}
    with _lock:
        c = _db()
        row = c.execute("SELECT id, data, occurrences, status FROM incidents WHERE dedup=? AND status IN "
                        "('em investigação','ameaça confirmada') ORDER BY created DESC LIMIT 1", (dedup,)).fetchone()
        if row:
            inc = json.loads(row[1])
            inc["ocorrencias"] = row[2] + 1
            inc["atualizado"] = now
            inc["cadeia_de_eventos"] = (inc.get("cadeia_de_eventos", []) + [event] + (events or []))[-200:]
            if action:
                inc["acoes"] = (inc.get("acoes", []) + [f"{now}: {action}"])[-100:]
            c.execute("UPDATE incidents SET updated=?, occurrences=?, data=? WHERE id=?",
                      (now, inc["ocorrencias"], json.dumps(inc, ensure_ascii=False), row[0]))
            c.commit()
            new = False
        else:
            inc_id = time_id()
            evidence = _preserve(real_path, data, quarantine_id)
            inc = {
                "id": inc_id, "criado": now, "atualizado": now,
                "sistema": f"{platform.system()} {platform.release()} ({platform.machine()})",
                "computador": platform.node(), "fonte": source, "arquivo": path,
                "hashes": hashes, "tipo": ftype,
                "tamanho": os.path.getsize(real_path) if real_path else pre.get("tamanho", len(data) if data is not None else None),
                "origem": file_origin(real_path) if real_path else pre.get("origem", {}),
                "assinatura_digital": signature_info(real_path) if real_path else pre.get("assinatura_digital", {}),
                "ameaca": threat, "veredito": verdict, "pontuacao": score, "confianca": confidence,
                "tipos_de_evidencia": groups, "regras_acionadas": rules, "indicadores": inds,
                "classificacao": classification, "desconhecida": unknown,
                "status": "em investigação" if unknown else "ameaça confirmada",
                "processo": process if process is not None else process_info(pid), "acoes": [f"{now}: {action}"] if action else [],
                "cadeia_de_eventos": [event] + (events or []), "evidencia": evidence,
                "ocorrencias": 1,
                "resultado_da_analise": _summary(verdict, confidence, unknown, groups),
            }
            c.execute("INSERT INTO incidents (id, created, updated, dedup, classification, status, confidence, unknown, "
                      "score, sha256, path, threat, source, occurrences, data) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (inc_id, now, now, dedup, classification, inc["status"], confidence, int(unknown), score,
                       hashes.get("sha256", ""), path, threat, source, 1, json.dumps(inc, ensure_ascii=False)))
            c.commit()
            new = True
    if new:
        history.log("incidente", f"[{classification}] {threat} — confiança {confidence or '—'}"
                                 + (" — ameaça desconhecida em investigação" if unknown else ""), path)
    for cb in list(_listeners):
        try:
            cb(inc, new)
        except Exception:
            pass
    return inc["id"], new


def time_id() -> str:
    return datetime.datetime.now().strftime("INC-%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6].upper()


def _summary(verdict: str, confidence: str, unknown: bool, groups: list[str]) -> str:
    base = {"malicioso": "Comportamento/conteúdo malicioso", "suspeito": "Comportamento/conteúdo suspeito"}.get(
        verdict, "Evento informativo")
    s = f"{base}; confiança {confidence or 'baixa'}; {len(groups)} tipo(s) independente(s) de evidência"
    s += f" ({', '.join(groups)})." if groups else "."
    if unknown:
        s += (" Não corresponde a nenhum malware catalogado: ameaça DESCONHECIDA em investigação. Isto não confirma "
              "um zero-day — confirme ou marque como falso positivo depois de revisar as evidências.")
    return s


def _preserve(path: str, data: bytes | None, quarantine_id: str) -> dict:
    """Guarda uma cópia neutralizada (cifrada, não executável) para análise posterior."""
    if quarantine_id:
        return {"onde": "quarentena", "id": quarantine_id}
    try:
        from .vault import Vault
        v = Vault(paths.sub_dir("evidence"))
        if path and os.path.getsize(path) <= MAX_EVIDENCE:
            return {"onde": "evidências", "id": v.store_file(path, {"original_path": path, "date": _now()})}
        if data is not None and len(data) <= MAX_EVIDENCE:
            return {"onde": "evidências", "id": v.store_bytes(data, {"original_path": "(memória)", "date": _now()})}
    except Exception as e:  # noqa: BLE001
        return {"onde": "não preservada", "motivo": str(e)[:200]}
    return {"onde": "não preservada", "motivo": "arquivo indisponível ou maior que 64 MB"}


# --------------------------------------------------------------------------- consulta
def get(inc_id: str) -> dict | None:
    with _lock:
        row = _db().execute("SELECT data FROM incidents WHERE id=?", (inc_id,)).fetchone()
    return json.loads(row[0]) if row else None


def search(text: str = "", classification: str = "", status: str = "", unknown_only: bool = False,
           limit: int = 500) -> list[dict]:
    q, args = "SELECT data FROM incidents WHERE 1=1", []
    if text:
        q += " AND (path LIKE ? OR threat LIKE ? OR sha256 LIKE ? OR id LIKE ? OR data LIKE ?)"
        like = f"%{text}%"
        args += [like] * 5
    if classification:
        q += " AND classification=?"
        args.append(classification)
    if status:
        q += " AND status=?"
        args.append(status)
    if unknown_only:
        q += " AND unknown=1"
    q += " ORDER BY created DESC LIMIT ?"
    args.append(limit)
    with _lock:
        rows = _db().execute(q, args).fetchall()
    return [json.loads(r[0]) for r in rows]


def counts() -> dict:
    with _lock:
        c = _db()
        total = c.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        inv = c.execute("SELECT COUNT(*) FROM incidents WHERE unknown=1 AND status='em investigação'").fetchone()[0]
        crit = c.execute("SELECT COUNT(*) FROM incidents WHERE classification IN ('crítico','alto risco') AND "
                         "status IN ('em investigação','ameaça confirmada')").fetchone()[0]
        fp = c.execute("SELECT COUNT(*) FROM incidents WHERE status='falso positivo'").fetchone()[0]
    return {"total": total, "em_investigacao": inv, "alto_risco_abertos": crit, "falsos_positivos": fp}


def set_status(inc_id: str, status: str, note: str = "") -> dict:
    if status not in STATUSES:
        raise ValueError("status inválido")
    with _lock:
        inc = get(inc_id)
        if not inc:
            raise KeyError(inc_id)
        inc["status"] = status
        inc["atualizado"] = _now()
        inc.setdefault("revisao", []).append({"quando": inc["atualizado"], "status": status, "nota": note[:2000]})
        c = _db()
        c.execute("UPDATE incidents SET status=?, updated=?, data=? WHERE id=?",
                  (status, inc["atualizado"], json.dumps(inc, ensure_ascii=False), inc_id))
        c.commit()
    history.log("incidente", f"{inc_id}: {status}" + (f" — {note[:200]}" if note else ""), inc.get("arquivo", ""))
    return inc


def mark_false_positive(inc_id: str, justification: str, scope: str = "arquivo") -> dict:
    """Revisão do usuário: registra a exclusão ESPECÍFICA (SHA-256) e fecha o incidente como falso positivo."""
    from . import fpengine
    from .engine.models import Indicator, ScanResult
    inc = get(inc_id)
    if not inc:
        raise KeyError(inc_id)
    sha = (inc.get("hashes") or {}).get("sha256", "")
    if inc.get("tipo") != "comportamento":
        r = ScanResult(path=inc.get("arquivo", ""), verdict=inc.get("veredito", ""), score=inc.get("pontuacao", 0),
                       threat_name=inc.get("ameaca", ""), sha256=sha)
        r.indicators = [Indicator.from_dict(i) for i in inc.get("indicadores", [])]
        fpengine.mark(r, justification, scope)
    return set_status(inc_id, "falso positivo", justification)


def export_json(inc: dict) -> str:
    return json.dumps(inc, ensure_ascii=False, indent=1)


def export_html(incs: list[dict]) -> str:
    e = html.escape

    def kv(d: dict) -> str:
        return "".join(f"<tr><th>{e(str(k))}</th><td>{e(json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else str(v))}</td></tr>"
                       for k, v in d.items() if v not in (None, "", [], {}))
    blocks = []
    for inc in incs:
        inds = "".join(f"<tr><td>{e(str(i.get('weight', '')))}</td><td>{e(i.get('name', ''))}</td>"
                       f"<td>{e(i.get('category', ''))}</td><td>{e(i.get('description', ''))}</td>"
                       f"<td>{e('; '.join(map(str, i.get('evidence', [])))[:400])}</td></tr>" for i in inc.get("indicadores", []))
        head = {k: inc.get(k) for k in ("id", "criado", "atualizado", "classificacao", "status", "confianca", "ameaca",
                                         "veredito", "pontuacao", "fonte", "arquivo", "tipo", "tamanho", "sistema",
                                         "ocorrencias", "resultado_da_analise")}
        blocks.append(f"""<section><h2>{e(inc['id'])} — {e(inc.get('ameaca', ''))}</h2>
<p class="tag">{e(inc.get('classificacao', ''))} · {e(inc.get('status', ''))}{' · ameaça desconhecida' if inc.get('desconhecida') else ''}</p>
<table>{kv(head)}{kv({'hashes': inc.get('hashes'), 'origem': inc.get('origem'), 'assinatura digital': inc.get('assinatura_digital'),
'regras acionadas': inc.get('regras_acionadas'), 'tipos de evidência': inc.get('tipos_de_evidencia'),
'processo': inc.get('processo'), 'ações': inc.get('acoes'), 'evidência preservada': inc.get('evidencia'),
'revisão': inc.get('revisao')})}</table>
<h3>Indicadores</h3><table><tr><th>Peso</th><th>Indicador</th><th>Categoria</th><th>Descrição</th><th>Evidência</th></tr>{inds}</table>
<h3>Cadeia de eventos</h3><table>{''.join(f"<tr><td>{e(json.dumps(x, ensure_ascii=False))}</td></tr>" for x in inc.get('cadeia_de_eventos', []))}</table>
</section>""")
    return f"""<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>Relatório de incidentes — EXE Antivirus</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#1d2733}}
table{{border-collapse:collapse;width:100%;margin:6px 0 16px}}th,td{{border:1px solid #d6dde6;padding:5px 8px;font-size:13px;
text-align:left;vertical-align:top;word-break:break-word}}th{{background:#f2f5f9;width:22%}}section{{border-bottom:2px solid #e3e8ee;
padding-bottom:10px}}.tag{{font-weight:600;color:#9a3412}}</style>
<h1>Relatório de incidentes — EXE Antivirus</h1><p>Gerado em {e(_now())}. Nenhuma informação foi enviada para fora
deste computador. "Ameaça desconhecida" significa que não há assinatura de malware catalogado; não é confirmação de zero-day.</p>
{''.join(blocks) or '<p>Nenhum incidente.</p>'}</html>"""
