"""Caminhos da aplicação e regras de autoexclusão.

O antivírus nunca deve analisar a si mesmo: a pasta de instalação, a pasta
temporária de extração do PyInstaller, a pasta de dados (quarentena, sala de
análise, backups, banco de assinaturas) e o próprio executável ficam sempre
fora de qualquer varredura.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from . import APP_ID

IS_WINDOWS = os.name == "nt"
IS_FROZEN = bool(getattr(sys, "frozen", False))


def _norm(p: str | os.PathLike) -> str:
    """Normaliza um caminho para comparação (absoluto, sem links, case-insensitive no Windows)."""
    try:
        s = os.path.realpath(os.fspath(p))
    except (OSError, ValueError):
        s = os.path.abspath(os.fspath(p))
    s = os.path.normpath(s)
    return os.path.normcase(s)


def _variants(p: str | os.PathLike) -> set[str]:
    """Forma real e forma absoluta (sem resolver links) de um caminho."""
    out = {_norm(p)}
    try:
        out.add(os.path.normcase(os.path.normpath(os.path.abspath(os.fspath(p)))))
    except (OSError, ValueError):
        pass
    return out


def data_dir() -> Path:
    override = os.environ.get("EXEAV_DATA_DIR")
    if override:
        base = Path(override)
    elif IS_WINDOWS:
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "ExeAntivirus"
    else:
        xdg = os.environ.get("XDG_DATA_HOME")
        base = (Path(xdg) if xdg else Path.home() / ".local" / "share") / APP_ID
    base.mkdir(parents=True, exist_ok=True)
    return base


def sub_dir(name: str) -> Path:
    d = data_dir() / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def quarantine_dir() -> Path:
    return sub_dir("quarantine")


def lab_dir() -> Path:
    return sub_dir("analysis_lab")


def backup_dir() -> Path:
    return sub_dir("backups")


def reports_dir() -> Path:
    return sub_dir("reports")


def app_root() -> Path:
    """Pasta onde o programa está instalado (ou o código-fonte, em desenvolvimento)."""
    if IS_FROZEN:
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def resource_path(rel: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base / rel


def self_excluded_roots() -> list[str]:
    roots = _variants(data_dir()) | _variants(Path(__file__).resolve().parent) | _variants(app_root())
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        roots |= _variants(meipass)
    return sorted(roots)


def self_executables() -> set[str]:
    exes = _variants(sys.executable)
    if IS_FROZEN and sys.argv and sys.argv[0]:
        exes |= _variants(sys.argv[0])
    return exes


class Exclusions:
    """Testa rapidamente se um caminho deve ser ignorado (autoproteção + exclusões do usuário)."""

    def __init__(self, user_paths: list[str] | None = None):
        self.roots = list(self_excluded_roots())
        self.files = set(self_executables())
        for p in user_paths or []:
            if p and p.strip():
                vs = _variants(p.strip())
                if os.path.isfile(p.strip()):
                    self.files |= vs
                else:
                    self.roots.extend(vs)
        self._prefixes = tuple(r.rstrip(os.sep) + os.sep for r in self.roots)
        self._exact = set(self.roots) | self.files

    def is_excluded(self, path: str | os.PathLike) -> bool:
        n = _norm(path)
        if n in self._exact:
            return True
        if n.startswith(self._prefixes):
            return True
        a = os.path.normcase(os.path.normpath(os.path.abspath(os.fspath(path))))
        return a in self._exact or a.startswith(self._prefixes)

    def is_excluded_fast(self, normalized_path: str) -> bool:
        """Versão para caminhos já normalizados por os.path.normcase(os.path.abspath())."""
        if normalized_path in self._exact:
            return True
        return normalized_path.startswith(self._prefixes)


norm = _norm


def launcher() -> list[str]:
    """Comando para abrir o antivírus de fora (atalhos, inicialização automática, tarefas agendadas).
    No AppImage o executável fica num ponto de montagem temporário: o caminho estável é $APPIMAGE."""
    appimage = os.environ.get("APPIMAGE")
    if appimage and os.path.isfile(appimage):
        return [appimage]
    if IS_FROZEN:
        return [sys.executable]
    main = Path(__file__).resolve().parent.parent / "main.py"
    exe = sys.executable
    if IS_WINDOWS and exe.lower().endswith("python.exe"):
        cand = exe[:-10] + "pythonw.exe"
        if os.path.isfile(cand):
            exe = cand
    return [exe, str(main)]
