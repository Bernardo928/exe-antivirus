"""Arquivos-isca (canários) contra ransomware.

Arquivos com nomes que aparecem primeiro na listagem ("!EXE-Antivirus-...") são colocados nas pastas de
documentos protegidas. Nenhum programa legítimo tem motivo para alterá-los: se o CONTEÚDO de uma isca mudar
ou ela for RENOMEADA (o que o ransomware faz ao cifrar), o escudo anti-ransomware reage na hora, antes de
esperar dezenas de arquivos cifrados. Apagar uma isca sozinho não dispara bloqueio (o usuário pode apagar):
só é registrado e a isca é recriada.

Os arquivos são documentos válidos que explicam o que são, caso o usuário os abra.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import zipfile
from pathlib import Path

from . import paths

NAMES = ("!EXE-Antivirus-protecao.docx", "!EXE-Antivirus-protecao.txt")
TEXT = ("Este arquivo protege seus documentos contra ransomware (EXE Antivirus).\n"
        "Ele serve de isca: se algum programa tentar cifrá-lo, o antivírus bloqueia o ataque.\n"
        "Não altere este arquivo. Para removê-lo, desative 'Arquivos-isca' nas configurações do Tempo Real.\n")


def _docx() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/'
                   'content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.'
                   'relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName='
                   '"/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.'
                   'document.main+xml"/></Types>')
        z.writestr("_rels/.rels",
                   '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/'
                   'package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
                   'officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        paras = "".join(f"<w:p><w:r><w:t>{line}</w:t></w:r></w:p>" for line in TEXT.strip().splitlines())
        z.writestr("word/document.xml",
                   '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/'
                   f'wordprocessingml/2006/main"><w:body>{paras}</w:body></w:document>')
    return buf.getvalue()


def _content(name: str) -> bytes:
    return _docx() if name.endswith(".docx") else TEXT.encode("utf-8")


def _manifest_path() -> Path:
    return paths.data_dir() / "canaries.json"


def manifest() -> dict[str, str]:
    try:
        d = json.loads(_manifest_path().read_text("utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(d: dict) -> None:
    _manifest_path().write_text(json.dumps(d, ensure_ascii=False, indent=1), "utf-8")


def default_dirs(watched: list[str]) -> list[str]:
    """Pastas de documentos do usuário que estão sendo monitoradas (nunca /tmp ou pastas de sistema)."""
    home = paths.norm(Path.home())
    out = []
    for d in watched:
        n = paths.norm(d)
        base = os.path.basename(n).lower()
        if n.startswith(home + os.sep) and base not in ("tmp", "temp", "startup", "autostart", "bin") \
                and os.path.isdir(d) and os.access(d, os.W_OK):
            out.append(d)
    return out


def ensure(dirs: list[str]) -> list[str]:
    """Cria (ou repõe) as iscas. Retorna os caminhos ativos."""
    d = manifest()
    active = []
    for folder in dirs:
        for name in NAMES:
            p = os.path.join(folder, name)
            data = _content(name)
            h = hashlib.sha256(data).hexdigest()
            try:
                if os.path.isfile(p) and _hash(p) == h:
                    d[p] = h
                    active.append(p)
                    continue
                d[p] = h                       # registra ANTES de gravar: o evento do arquivo já encontra o hash
                tmp = os.path.join(folder, f".{name}.exeav-tmp")
                with open(tmp, "wb") as f:
                    f.write(data)
                if paths.IS_WINDOWS and os.path.exists(p):
                    import ctypes
                    ctypes.windll.kernel32.SetFileAttributesW(p, 0x80)   # o Windows não substitui arquivo oculto
                os.replace(tmp, p)             # gravação atômica: nunca existe isca pela metade
                if paths.IS_WINDOWS:
                    import ctypes
                    ctypes.windll.kernel32.SetFileAttributesW(p, 0x2)   # oculto
                active.append(p)
            except OSError:
                d.pop(p, None)
    _save(d)
    return active


def remove_all() -> int:
    d = manifest()
    n = 0
    for p, h in d.items():
        try:
            if os.path.isfile(p) and _hash(p) == h:
                if paths.IS_WINDOWS:
                    import ctypes
                    ctypes.windll.kernel32.SetFileAttributesW(p, 0x80)
                os.remove(p)
                n += 1
        except OSError:
            continue
    _save({})
    return n


def _hash(p: str) -> str:
    with open(p, "rb") as f:
        return hashlib.sha256(f.read(4 * 1024 * 1024)).hexdigest()


def is_canary(path: str) -> bool:
    return os.path.basename(path) in NAMES and path in manifest()


def tripped(path: str, event: str) -> bool:
    """event: 'modificado' | 'renomeado' | 'apagado'. True = sinal forte de ransomware."""
    expected = manifest().get(path)
    if expected is None:
        return False
    if event == "renomeado":
        return True
    if event == "apagado":
        return False
    try:
        return _hash(path) != expected
    except OSError:
        return False
