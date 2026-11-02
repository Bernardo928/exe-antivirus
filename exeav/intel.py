"""Motor de inteligência de ameaças (Threat Intelligence).

Fontes públicas (respeitando as condições de uso de cada uma; nenhuma exige envio de dados do usuário):

    feodo        Feodo Tracker (abuse.ch)   IPs de servidores de comando de botnets bancárias
    urlhaus      URLhaus (abuse.ch)         domínios que distribuem malware
    threatfox    ThreatFox (abuse.ch)       IOCs recentes: IP:porta, domínios, URLs e hashes SHA-256
    cisa_kev     CISA KEV                   vulnerabilidades sendo exploradas ativamente (informativo)

As assinaturas por hash do MalwareBazaar continuam no banco de assinaturas (Configurações).

Nada é aceito às cegas:
- download por HTTPS com limite de tamanho; o SHA-256 do que foi baixado fica registrado (procedência);
- cada linha é validada; o feed é RECUSADO se tiver poucos indicadores válidos ou muitas linhas inválidas
  (arquivo corrompido, página de erro, formato mudado) — a versão anterior continua valendo;
- endereços que nunca podem ser bloqueados são descartados (rede local, loopback, domínios essenciais
  como os de atualização do Windows) — protege contra feed adulterado que tente "derrubar" o computador;
- deduplicação, versão incremental, histórico de atualizações, cópia da versão anterior;
- cada indicador guarda quando foi visto pela última vez e EXPIRA depois de `ttl_dias` sem aparecer
  nos feeds (indicadores velhos geram falso positivo: o IP muda de dono);
- o arquivo local tem uma soma de verificação: se for corrompido/adulterado, é ignorado.

Limitação honesta: estes feeds não são assinados digitalmente pelos publicadores; a verificação possível
é TLS + validação de conteúdo + registro do hash.
"""
from __future__ import annotations

import csv
import datetime
import hashlib
import io
import ipaddress
import json
import re
import threading
import time
import urllib.request
from pathlib import Path

from . import history, paths

FEEDS: dict[str, dict] = {
    "feodo": {"name": "Feodo Tracker (abuse.ch)", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
              "kind": "ip", "ttl": 30, "min": 1, "desc": "Servidores de comando de botnets (IPs)"},
    "urlhaus": {"name": "URLhaus (abuse.ch)", "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
                "kind": "domain", "ttl": 30, "min": 20, "desc": "Domínios que distribuem malware"},
    "threatfox": {"name": "ThreatFox (abuse.ch)", "url": "https://threatfox.abuse.ch/export/csv/recent/",
                  "kind": "mixed", "ttl": 30, "min": 5, "desc": "IOCs recentes: IPs, domínios, URLs e hashes"},
    "cisa_kev": {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                 "kind": "cve", "ttl": 3650, "min": 100, "desc": "Vulnerabilidades exploradas ativamente (informativo)"},
}
MAX_DOWNLOAD = 64 * 1024 * 1024
MAX_INVALID_RATIO = 0.30
# nunca bloquear (um feed adulterado poderia tentar cortar atualizações, DNS ou o próprio antivírus)
NEVER_BLOCK_DOMAINS = {
    "microsoft.com", "windowsupdate.com", "windows.com", "windows.net", "msftncsi.com", "live.com", "office.com",
    "google.com", "googleapis.com", "gstatic.com", "apple.com", "icloud.com", "cloudflare.com", "akamai.net",
    "akamaiedge.net", "amazonaws.com", "github.com", "githubusercontent.com", "ubuntu.com", "debian.org",
    "mozilla.org", "mullvad.net", "abuse.ch", "cisa.gov", "localhost", "digicert.com", "letsencrypt.org",
}
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_lock = threading.RLock()


def _dir() -> Path:
    return paths.sub_dir("intel")


# --------------------------------------------------------------------------- validação
def valid_ip(text: str) -> str | None:
    try:
        a = ipaddress.ip_address(text.strip().strip("[]"))
    except ValueError:
        return None
    if a.is_private or a.is_loopback or a.is_multicast or a.is_unspecified or a.is_reserved or a.is_link_local:
        return None
    return str(a)


def valid_domain(text: str) -> str | None:
    d = text.strip().lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    if not _DOMAIN.match(d) or valid_ip(d) or re.match(r"^\d+(\.\d+){3}$", d):
        return None
    parts = d.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in NEVER_BLOCK_DOMAINS:
            return None
    return d


def _never_blocked(d: str) -> bool:
    parts = d.lower().split(".")
    return any(".".join(parts[i:]) in NEVER_BLOCK_DOMAINS for i in range(len(parts) - 1))


def parse(feed: str, raw: bytes) -> tuple[dict[str, set[str]], int, int]:
    """Converte o conteúdo bruto do feed em indicadores. Retorna ({tipo: valores}, válidos, inválidos)."""
    text = raw.decode("utf-8", "replace")
    out: dict[str, set[str]] = {"ip": set(), "domain": set(), "url": set(), "sha256": set(), "cve": set()}
    good = bad = 0
    if feed == "cisa_kev":
        try:
            data = json.loads(text)
            vulns = data.get("vulnerabilities") or []
        except (ValueError, AttributeError):
            return out, 0, 1
        for v in vulns:
            cve = str(v.get("cveID", ""))
            if _CVE.match(cve):
                out["cve"].add(cve)
                good += 1
            else:
                bad += 1
        return out, good, bad
    if feed == "threatfox":
        lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
        for row in csv.reader(lines, skipinitialspace=True):
            if len(row) < 4:
                bad += 1
                continue
            value, kind = row[2].strip().strip('"'), row[3].strip().strip('"').lower()
            ok, ignore = None, False
            if kind == "ip:port":
                ok = valid_ip(value.rsplit(":", 1)[0])
                if ok:
                    out["ip"].add(ok)
            elif kind == "domain":
                ok = valid_domain(value)
                if ok:
                    out["domain"].add(ok)
                ignore = _never_blocked(value)
            elif kind == "url":
                m = re.match(r"^(?:https?|ftp)://([^/:?#\s]+)", value, re.I)
                if m and (valid_domain(m.group(1)) or valid_ip(m.group(1))):
                    ok = value[:500]
                    out["url"].add(ok)
            elif kind == "sha256_hash":
                if _SHA256.match(value.lower()):
                    ok = value.lower()
                    out["sha256"].add(ok)
            else:
                ok = "outro"        # md5/sha1 e outros tipos: válidos, mas não usados
            if ok:
                good += 1
            elif not ignore:
                bad += 1
        return out, good, bad
    for line in text.splitlines():
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        if feed == "urlhaus":
            parts = s.split()
            host = parts[1] if len(parts) >= 2 else parts[0]
            d = valid_domain(host)
            if d:
                out["domain"].add(d)
                good += 1
            elif not _never_blocked(host):
                bad += 1
        else:  # lista de IPs (feodo e importações)
            ip = valid_ip(s.split(",")[0].split()[0].rsplit(":", 1)[0] if s.count(":") == 1 else s.split(",")[0].split()[0])
            if ip:
                out["ip"].add(ip)
                good += 1
            else:
                bad += 1
    return out, good, bad


# --------------------------------------------------------------------------- armazenamento
def _checksum(entries: dict) -> str:
    h = hashlib.sha256()
    for kind in sorted(entries):
        for v in sorted(entries[kind]):
            h.update(f"{kind}\0{v}\0{entries[kind][v]}\n".encode())
    return h.hexdigest()


def _feed_file(feed: str) -> Path:
    return _dir() / f"{feed}.json"


def load_feed(feed: str) -> dict:
    """{'version','updated','sha256_download','count','entries':{tipo:{valor: ultima_vez}},'corrompido'}"""
    p = _feed_file(feed)
    try:
        d = json.loads(p.read_text("utf-8"))
        if d.get("checksum") != _checksum(d.get("entries", {})):
            history.log("inteligência", f"Feed {feed}: arquivo local corrompido ou adulterado — ignorado", str(p))
            return {"corrompido": True, "entries": {}}
        return d
    except FileNotFoundError:
        return {"entries": {}}
    except (OSError, ValueError):
        return {"corrompido": True, "entries": {}}


def _save_feed(feed: str, d: dict) -> None:
    p = _feed_file(feed)
    d["checksum"] = _checksum(d["entries"])
    if p.exists():
        try:
            p.replace(p.with_suffix(".anterior.json"))
        except OSError:
            pass
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False), "utf-8")
    tmp.replace(p)


def _log_update(rec: dict) -> None:
    hp = _dir() / "historico.json"
    try:
        hist = json.loads(hp.read_text("utf-8"))
    except (OSError, ValueError):
        hist = []
    hist.append(rec)
    hp.write_text(json.dumps(hist[-500:], ensure_ascii=False, indent=1), "utf-8")


def update_history() -> list[dict]:
    try:
        return json.loads((_dir() / "historico.json").read_text("utf-8"))[::-1]
    except (OSError, ValueError):
        return []


def ingest(feed: str, raw: bytes, source: str) -> dict:
    """Valida e incorpora um conteúdo baixado/importado. Levanta ValueError se o feed for recusado."""
    cfg = FEEDS[feed]
    parsed, good, bad = parse(feed, raw)
    total = good + bad
    if good < cfg["min"]:
        raise ValueError(f"feed recusado: só {good} indicador(es) válido(s) (mínimo {cfg['min']}) — "
                         "arquivo vazio, corrompido, página de erro ou formato desconhecido")
    if total and bad / total > MAX_INVALID_RATIO:
        raise ValueError(f"feed recusado: {bad} de {total} linhas inválidas ({bad * 100 // total}%)")
    now = time.time()
    with _lock:
        cur = load_feed(feed)
        entries: dict[str, dict[str, float]] = {k: dict(v) for k, v in cur.get("entries", {}).items()}
        before = {k: set(v) for k, v in entries.items()}
        for kind, values in parsed.items():
            if not values:
                continue
            bucket = entries.setdefault(kind, {})
            for v in values:
                bucket[v] = now
        ttl = cfg["ttl"] * 86400
        expired = 0
        for kind, bucket in entries.items():
            for v in [v for v, t in bucket.items() if now - t > ttl]:
                del bucket[v]
                expired += 1
        added = sum(len(set(entries.get(k, {})) - before.get(k, set())) for k in entries)
        count = sum(len(b) for b in entries.values())
        d = {"feed": feed, "version": int(cur.get("version", 0)) + 1,
             "updated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "source": source,
             "sha256_download": hashlib.sha256(raw).hexdigest(), "valid_lines": good, "invalid_lines": bad,
             "count": count, "entries": entries}
        _save_feed(feed, d)
        _invalidate()
    rec = {"data": d["updated"], "feed": feed, "resultado": "ok", "versao": d["version"], "novos": added,
           "expirados": expired, "total": count, "sha256": d["sha256_download"], "origem": source,
           "invalidas": bad}
    _log_update(rec)
    history.log("inteligência", f"Feed {cfg['name']} v{d['version']}: {count} indicador(es), {added} novo(s), "
                                f"{expired} expirado(s)", source)
    return rec


def update(feed: str, timeout: int = 60) -> dict:
    cfg = FEEDS[feed]
    try:
        req = urllib.request.Request(cfg["url"], headers={"User-Agent": "EXE-Antivirus (threat-intel)"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(MAX_DOWNLOAD + 1)
        if len(raw) > MAX_DOWNLOAD:
            raise ValueError("feed maior que o limite de segurança")
        return ingest(feed, raw, cfg["url"])
    except Exception as e:
        rec = {"data": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "feed": feed,
               "resultado": f"falhou: {type(e).__name__}: {str(e)[:200]}", "origem": cfg["url"]}
        _log_update(rec)
        history.log("inteligência", f"Feed {cfg['name']}: atualização falhou ({str(e)[:120]}) — versão anterior mantida")
        raise


def update_all() -> list[dict]:
    out = []
    for f in FEEDS:
        try:
            out.append(update(f))
        except Exception as e:  # noqa: BLE001 — um feed fora do ar não pode impedir os outros
            out.append({"feed": f, "resultado": f"falhou: {e}"})
    return out


def import_file(feed: str, path: str) -> dict:
    with open(path, "rb") as f:
        return ingest(feed, f.read(MAX_DOWNLOAD), f"arquivo: {path}")


# --------------------------------------------------------------------------- consulta (cache em memória)
_index: dict[str, set[str]] | None = None


def _invalidate() -> None:
    global _index
    _index = None


def index() -> dict[str, set[str]]:
    global _index
    with _lock:
        if _index is None:
            idx: dict[str, set[str]] = {"ip": set(), "domain": set(), "url": set(), "sha256": set(), "cve": set()}
            for f in FEEDS:
                for kind, bucket in load_feed(f).get("entries", {}).items():
                    idx.setdefault(kind, set()).update(bucket)
            _index = idx
        return _index


def ips() -> set[str]:
    return index()["ip"]


def domains() -> set[str]:
    return index()["domain"]


def is_malicious_domain(name: str) -> bool:
    doms = index()["domain"]
    if not doms:
        return False
    q = name.lower().rstrip(".")
    while "." in q:
        if q in doms:
            return True
        q = q.split(".", 1)[1]
    return False


def hash_known(sha256: str) -> bool:
    return bool(sha256) and sha256 in index()["sha256"]


def status() -> list[dict]:
    """Situação de cada feed para a interface (dados reais, nada estimado)."""
    out = []
    now = time.time()
    for f, cfg in FEEDS.items():
        d = load_feed(f)
        upd = d.get("updated", "")
        age_days = None
        if upd:
            try:
                age_days = (now - time.mktime(time.strptime(upd, "%Y-%m-%d %H:%M:%S"))) / 86400
            except ValueError:
                pass
        out.append({"id": f, "nome": cfg["name"], "descricao": cfg["desc"], "versao": d.get("version", 0),
                    "atualizado": upd or "nunca", "indicadores": d.get("count", 0), "corrompido": bool(d.get("corrompido")),
                    "desatualizado": age_days is None or age_days > 7, "idade_dias": round(age_days, 1) if age_days is not None else None,
                    "sha256_download": d.get("sha256_download", "")})
    return out


_URL_RE = re.compile(rb"(?:https?|ftp)://([a-z0-9.-]{4,253})", re.I)


def content_hits(data: bytes, limit: int = 4 * 1024 * 1024) -> list[str]:
    """Domínios de infraestrutura maliciosa conhecida citados no conteúdo (para o motor)."""
    doms = index()["domain"]
    if not doms:
        return []
    hits = set()
    for m in _URL_RE.finditer(data[:limit]):
        host = m.group(1).decode("ascii", "replace").lower()
        if is_malicious_domain(host):
            hits.add(host)
            if len(hits) >= 10:
                break
    return sorted(hits)
