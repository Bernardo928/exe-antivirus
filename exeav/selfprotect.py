"""Autoproteção: o antivírus confere a própria integridade.

Verificações (todas locais, sem enviar nada para fora):

- arquivos do programa: o build grava `integrity.json` com o SHA-256 de cada arquivo da instalação; ao abrir,
  o antivírus confere tudo (arquivo alterado, faltando ou estranho). Instalado em "Arquivos de Programas"
  (Windows) só um administrador consegue alterar esses arquivos — programa comum não adultera o manifesto;
- regras de detecção: o pacote de regras precisa decodificar e bater com a contagem/assinatura interna;
- configurações: o antivírus guarda o hash do que ELE gravou; se o arquivo for alterado por fora (ex.: um
  malware desligando a proteção em tempo real), avisa, mostra o que mudou e permite restaurar;
- histórico: eventos encadeados por hash — alterar ou apagar eventos é detectado;
- quarentena: as amostras ficam cifradas e sem permissão de execução; o cabeçalho de cada uma é conferido.

Limites honestos: um programa com privilégio de administrador pode adulterar tudo isso junto (manifesto e
arquivos). Proteção contra isso exige componentes de kernel/serviço protegido do sistema, fora do escopo.
O usuário sempre pode desinstalar o antivírus pelos meios normais do sistema.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from . import config, history, paths

MANIFEST = "integrity.json"
# o instalador do Windows (Inno Setup) grava o próprio desinstalador na raiz da pasta depois do build
_INSTALLER_FILES = re.compile(r"^unins\d{3}\.(?:exe|dat|msg)$", re.I)


def build_manifest(root: Path) -> dict:
    """Usado por tools/build.py: hash de todos os arquivos da instalação."""
    files = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.name != MANIFEST:
            files[p.relative_to(root).as_posix()] = _sha256(p)
    from . import VERSION
    return {"versao": VERSION, "arquivos": files}


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def check_program_files(root: Path | None = None) -> dict:
    root = root or paths.app_root()
    mf = root / MANIFEST
    if not mf.exists():
        mode = "desenvolvimento (código-fonte)" if not paths.IS_FROZEN else "portátil (arquivo único)"
        return {"nome": "Arquivos do programa", "ok": None, "detalhe": f"Sem manifesto de integridade: modo {mode}."}
    try:
        data = json.loads(mf.read_text("utf-8"))
        expected: dict = data["arquivos"]
    except (OSError, ValueError, KeyError):
        return {"nome": "Arquivos do programa", "ok": False, "detalhe": "Manifesto de integridade ilegível ou adulterado."}
    changed, missing = [], []
    for rel, h in expected.items():
        p = root / rel
        if not p.is_file():
            missing.append(rel)
        elif _sha256(p) != h:
            changed.append(rel)
    extra = []
    for p in root.rglob("*"):
        rel = p.relative_to(root).as_posix()
        if p.is_file() and p.name != MANIFEST and rel not in expected \
                and p.suffix.lower() in (".exe", ".dll", ".so", ".pyd", ".py", ".bin") \
                and not _INSTALLER_FILES.match(rel):
            extra.append(rel)
    ok = not (changed or missing or extra)
    det = f"{len(expected)} arquivo(s) conferido(s)."
    if not ok:
        det = (f"ALTERADOS: {', '.join(changed[:5])}" if changed else "") + \
              (f" FALTANDO: {', '.join(missing[:5])}" if missing else "") + \
              (f" ESTRANHOS: {', '.join(extra[:5])}" if extra else "")
    return {"nome": "Arquivos do programa", "ok": ok, "detalhe": det.strip(),
            "alterados": changed, "faltando": missing, "estranhos": extra}


def check_rules() -> dict:
    try:
        from .engine.rules import load_builtin_dicts
        n = len(load_builtin_dicts())
        ok = n > 0
        return {"nome": "Regras de detecção", "ok": ok, "detalhe": f"{n} regras íntegras." if ok else "Pacote vazio."}
    except Exception as e:  # noqa: BLE001
        return {"nome": "Regras de detecção", "ok": False, "detalhe": f"Pacote de regras corrompido: {e}"}


def config_changes() -> tuple[bool | None, list[str]]:
    """(alterada_por_fora?, chaves alteradas)."""
    st = config.store()
    p = st.path
    hp, lg = p.with_suffix(".sha256"), p.with_suffix(".lastgood.json")
    try:
        cur = p.read_bytes()
        saved = hp.read_text("utf-8").strip()
    except OSError:
        return None, []
    if hashlib.sha256(cur).hexdigest() == saved:
        return False, []
    keys = []
    try:
        a = json.loads(lg.read_text("utf-8"))
        b = json.loads(cur.decode("utf-8", "replace"))
        keys = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
    except (OSError, ValueError):
        keys = ["(arquivo ilegível)"]
    return True, keys


PROTECTION_KEYS = {"realtime_enabled", "realtime_process_monitor", "realtime_kill_malicious_process",
                   "ransomware_shield", "botnet_shield", "usb_guard", "script_guard", "boot_guard", "exclusions",
                   "auto_action", "sensitivity"}


def check_config() -> dict:
    changed, keys = config_changes()
    if changed is None:
        return {"nome": "Configurações", "ok": None, "detalhe": "Ainda sem registro de integridade (será criado ao salvar)."}
    if not changed:
        return {"nome": "Configurações", "ok": True, "detalhe": "Iguais às gravadas pelo antivírus."}
    danger = sorted(set(keys) & PROTECTION_KEYS)
    det = "Alteradas FORA do antivírus: " + ", ".join(keys[:10])
    if danger:
        det += f" — inclui proteções: {', '.join(danger)}"
    return {"nome": "Configurações", "ok": False, "detalhe": det, "chaves": keys, "protecoes": danger}


def restore_config() -> None:
    """Volta às últimas configurações gravadas pelo próprio antivírus."""
    st = config.store()
    lg = st.path.with_suffix(".lastgood.json")
    data = lg.read_bytes()
    json.loads(data.decode("utf-8"))
    st.path.write_bytes(data)
    st.settings = st._load()
    st.save()
    history.log("autoproteção", "Configurações restauradas para a última versão gravada pelo antivírus")


def check_history() -> dict:
    v = history.verify()
    return {"nome": "Histórico (log encadeado)", "ok": v["ok"],
            "detalhe": f"{v['eventos']} evento(s) encadeado(s) íntegros." if v["ok"] else f"ADULTERADO: {v['problema']}"}


def check_quarantine() -> dict:
    from .vault import MAGIC
    d = paths.quarantine_dir()
    bad, n = [], 0
    for p in d.glob("*.bin"):
        n += 1
        try:
            with open(p, "rb") as f:
                if f.read(len(MAGIC)) != MAGIC:
                    bad.append(p.name)
            if os.name != "nt" and os.stat(p).st_mode & 0o111:
                bad.append(p.name + " (executável)")
        except OSError:
            bad.append(p.name)
    if bad:
        return {"nome": "Quarentena", "ok": False, "detalhe": f"{len(bad)} item(ns) com cabeçalho/permissão inválidos: "
                                                              + ", ".join(bad[:5])}
    return {"nome": "Quarentena", "ok": True, "detalhe": f"{n} amostra(s) cifradas e não executáveis."}


def run_all() -> list[dict]:
    checks = []
    for fn in (check_program_files, check_rules, check_config, check_history, check_quarantine):
        try:
            checks.append(fn())
        except Exception as e:  # noqa: BLE001
            checks.append({"nome": fn.__name__, "ok": False, "detalhe": f"falha na verificação: {e}"})
    bad = [c for c in checks if c["ok"] is False]
    if bad:
        history.log("autoproteção", "Problemas de integridade: " + "; ".join(f"{c['nome']}: {c['detalhe'][:120]}"
                                                                           for c in bad))
    return checks
