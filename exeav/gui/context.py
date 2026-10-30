"""Serviços compartilhados entre as abas e a ponte de sinais thread → interface."""
from __future__ import annotations

import threading

from PySide6.QtCore import QObject, Signal

from .. import config, history
from ..engine.engine import Engine
from ..engine.signatures import SignatureDB
from ..lab import AnalysisLab
from ..quarantine import Quarantine
from ..realtime import RealtimeProtection
from ..scanner import ScanCache, Scanner


class Bridge(QObject):
    scan_started = Signal(str)
    scan_progress = Signal(object)
    scan_threat = Signal(object)
    scan_finished = Signal(object)
    rt_event = Signal(str, object)
    history_event = Signal(str, str, str, str)
    quarantine_changed = Signal()
    lab_changed = Signal(str)
    open_in_lab = Signal(str)
    navigate = Signal(str)
    settings_changed = Signal()


class AppContext:
    def __init__(self):
        self.settings = config.get()
        self.bridge = Bridge()
        self.sigdb = SignatureDB()
        self.engine = Engine(self.settings, self.sigdb)
        self.cache = ScanCache()
        self.quarantine = Quarantine()
        self.lab = AnalysisLab(self.engine)
        self.realtime = RealtimeProtection(self.engine, self.quarantine, self._rt_cb, self.cache)
        self.scanner: Scanner | None = None
        self._scan_thread: threading.Thread | None = None
        history.add_listener(lambda *a: self.bridge.history_event.emit(*a))

    def _rt_cb(self, kind: str, data) -> None:
        self.bridge.rt_event.emit(kind, data)
        if kind == "threat":
            self.bridge.quarantine_changed.emit()

    # ------------------------------------------------------------------ varreduras
    @property
    def scanning(self) -> bool:
        return self._scan_thread is not None and self._scan_thread.is_alive()

    def start_scan(self, kind: str, targets: list[str]) -> bool:
        if self.scanning:
            return False
        sc = Scanner(self.engine, kind, targets,
                     on_threat=lambda r: self.bridge.scan_threat.emit(r),
                     on_progress=lambda s: self.bridge.scan_progress.emit(s),
                     cache=self.cache)
        self.scanner = sc

        def run():
            stats = sc.run()
            self.bridge.scan_finished.emit(stats)

        self._scan_thread = threading.Thread(target=run, daemon=True, name="scan-main")
        self._scan_thread.start()
        self.bridge.scan_started.emit(kind)
        return True

    def stop_scan(self) -> None:
        if self.scanner:
            self.scanner.stop()

    def apply_settings(self) -> None:
        config.save()
        self.engine.reload()
        self.bridge.settings_changed.emit()

    def shutdown(self) -> None:
        self.stop_scan()
        try:
            if self.realtime.running:
                self.realtime.stop()
        except Exception:
            pass
        try:
            self.cache.flush()
        except Exception:
            pass
