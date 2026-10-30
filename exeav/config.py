"""Configurações persistentes (JSON na pasta de dados)."""
from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import paths


def _default_watch_dirs() -> list[str]:
    home = Path.home()
    cands = [home / "Downloads", home / "Desktop", home / "Documents",
             home / "Transferências", home / "Área de Trabalho", home / "Documentos"]
    if paths.IS_WINDOWS:
        appdata = os.environ.get("APPDATA")
        if appdata:
            cands.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
        tmp = os.environ.get("TEMP")
        if tmp:
            cands.append(Path(tmp))
    else:
        cands += [Path("/tmp"), home / ".config" / "autostart", home / ".local" / "bin"]
    out, seen = [], set()
    for c in cands:
        try:
            if c.is_dir():
                k = paths.norm(c)
                if k not in seen:
                    seen.add(k)
                    out.append(str(c))
        except OSError:
            pass
    return out


SETTINGS_VERSION = 2


@dataclass
class Settings:
    realtime_enabled: bool = True
    realtime_dirs: list[str] = field(default_factory=_default_watch_dirs)
    realtime_process_monitor: bool = True
    realtime_kill_malicious_process: bool = True
    ransomware_shield: bool = True
    auto_action: str = "quarantine"          # quarantine | notify
    sensitivity: str = "media"               # baixa | media | alta
    scan_archives: bool = True
    archive_max_depth: int = 5
    max_file_size_mb: int = 128
    exclusions: list[str] = field(default_factory=list)
    scan_threads: int = 0                    # 0 = automático
    scan_processes: bool = True              # usa vários núcleos da CPU (processos paralelos)
    use_cache: bool = True
    scheduled_scan_enabled: bool = False
    scheduled_scan_time: str = "12:00"
    scheduled_scan_type: str = "quick"       # quick | full
    last_scheduled_run: str = ""
    start_minimized: bool = False
    minimize_to_tray: bool = True
    notifications: bool = True
    signature_update_url: str = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
    last_scan: str = ""
    last_scan_type: str = ""
    last_full_scan: str = ""
    language: str = "pt-BR"
    settings_version: int = SETTINGS_VERSION

    def sanitize(self) -> None:
        """Corrige valores inválidos (arquivo editado à mão, corrompido ou de versão antiga)."""
        def clamp(name, lo, hi):
            setattr(self, name, max(lo, min(hi, getattr(self, name))))
        clamp("max_file_size_mb", 1, 4096)
        clamp("archive_max_depth", 1, 10)
        clamp("scan_threads", 0, 64)
        if self.sensitivity not in ("baixa", "media", "alta"):
            self.sensitivity = "media"
        if self.auto_action not in ("quarantine", "notify"):
            self.auto_action = "quarantine"
        if self.scheduled_scan_type not in ("quick", "full"):
            self.scheduled_scan_type = "quick"
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", self.scheduled_scan_time or ""):
            self.scheduled_scan_time = "12:00"
        self.realtime_dirs = [d for d in self.realtime_dirs if isinstance(d, str) and d.strip()]
        self.exclusions = [d for d in self.exclusions if isinstance(d, str) and d.strip()]

    def thresholds(self) -> tuple[int, int]:
        """(limite suspeito, limite malicioso) conforme a sensibilidade."""
        return {"baixa": (50, 85), "alta": (25, 55)}.get(self.sensitivity, (35, 70))


class SettingsStore:
    _lock = threading.RLock()

    def __init__(self, path: Path | None = None):
        self.path = path or (paths.data_dir() / "settings.json")
        self.settings = self._load()

    def _load(self) -> Settings:
        s = Settings()
        try:
            raw = json.loads(self.path.read_text("utf-8"))
        except (OSError, ValueError):
            raw = None
        if isinstance(raw, dict):
            for k, v in raw.items():
                if hasattr(s, k) and type(v) is type(getattr(s, k)):
                    setattr(s, k, v)
            if raw.get("settings_version", 1) < 2:
                # versão 1 usava profundidade 2 em compactados: ZIPs aninhados escapavam
                if s.archive_max_depth == 2:
                    s.archive_max_depth = 5
                s.settings_version = SETTINGS_VERSION
        s.sanitize()
        return s

    def save(self) -> None:
        with self._lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(asdict(self.settings), indent=2, ensure_ascii=False), "utf-8")
            os.replace(tmp, self.path)


_store: SettingsStore | None = None


def store() -> SettingsStore:
    global _store
    if _store is None:
        _store = SettingsStore()
    return _store


def get() -> Settings:
    return store().settings


def save() -> None:
    store().save()
