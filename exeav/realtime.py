"""Proteção em tempo real.

- Monitor de arquivos (watchdog / inotify / ReadDirectoryChangesW): todo arquivo criado,
  modificado ou movido nas pastas protegidas é analisado assim que termina de ser gravado.
- Monitor de processos: todo processo novo tem seu executável analisado; processos
  maliciosos podem ser encerrados automaticamente.
- Escudo anti-ransomware: detecta reescrita em massa de arquivos com conteúdo cifrado.
"""
from __future__ import annotations

import os
import threading
import time
from collections import deque

import psutil

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # pragma: no cover
    Observer = None
    FileSystemEventHandler = object

from . import history, paths, util
from .engine.engine import Engine
from .engine.models import MALICIOUS, ScanResult
from .quarantine import Quarantine
from .scanner import ScanCache

DOC_EXT = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".jpg", ".jpeg", ".png", ".csv",
           ".odt", ".ods", ".rtf", ".psd", ".mp3", ".zip", ".sql", ".md", ".json", ".xml", ".html", ".bmp"}


class _Handler(FileSystemEventHandler):
    def __init__(self, rt: "RealtimeProtection"):
        self.rt = rt

    def on_created(self, event):
        if not event.is_directory:
            self.rt.enqueue(event.src_path, modified=True)

    def on_modified(self, event):
        if not event.is_directory:
            self.rt.enqueue(event.src_path, modified=True)

    def on_moved(self, event):
        if not event.is_directory:
            self.rt.enqueue(event.dest_path, modified=True)

    def on_closed(self, event):
        if not event.is_directory:
            self.rt.enqueue(event.src_path)


class RealtimeProtection:
    """callback(evento, dados): 'threat' (ScanResult), 'action' (str), 'ransomware' (dict), 'status' (str)."""

    def __init__(self, engine: Engine, quarantine: Quarantine, callback=None, cache: ScanCache | None = None):
        self.engine = engine
        self.settings = engine.settings
        self.quarantine = quarantine
        self.callback = callback or (lambda *a: None)
        self.cache = cache
        self._observer = None
        self._pending: dict[str, float] = {}
        self._plock = threading.Lock()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._known_pids: set[int] = set()
        self._scanned_exes: dict[tuple, str] = {}
        self._mods: deque = deque()
        self._last_ransom_alert = 0.0
        self.files_scanned = 0
        self.threats_blocked = 0
        self.processes_checked = 0
        self.watched: list[str] = []
        self.errors: list[str] = []

    @property
    def running(self) -> bool:
        return bool(self._threads) and not self._stop.is_set()

    # ------------------------------------------------------------------ ciclo de vida
    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self.errors.clear()
        self.watched.clear()
        if Observer is not None:
            self._observer = Observer()
            for d in self.settings.realtime_dirs:
                if not os.path.isdir(d) or self.engine.exclusions.is_excluded(d):
                    continue
                try:
                    self._observer.schedule(_Handler(self), d, recursive=True)
                    self.watched.append(d)
                except Exception as e:  # limite de inotify, permissão etc.
                    self.errors.append(f"{d}: {e}")
            self._observer.daemon = True
            self._observer.start()
        t = threading.Thread(target=self._file_loop, daemon=True, name="rt-files")
        t.start()
        self._threads = [t]
        if self.settings.realtime_process_monitor:
            p = threading.Thread(target=self._process_loop, daemon=True, name="rt-procs")
            p.start()
            self._threads.append(p)
        history.log("tempo real", f"Proteção em tempo real ativada ({len(self.watched)} pasta(s))")
        self.callback("status", "on")

    def stop(self) -> None:
        self._stop.set()
        if self._observer is not None:
            try:
                self._observer.stop()
                self._observer.join(timeout=3)
            except Exception:
                pass
            self._observer = None
        for t in self._threads:
            t.join(timeout=3)
        self._threads = []
        history.log("tempo real", "Proteção em tempo real desativada")
        self.callback("status", "off")

    def restart(self) -> None:
        self.stop()
        self.start()

    # ------------------------------------------------------------------ arquivos
    def enqueue(self, path: str, modified: bool = False) -> None:
        if self._stop.is_set():
            return
        try:
            if self.engine.exclusions.is_excluded(path):
                return
        except (OSError, ValueError):
            return
        with self._plock:
            self._pending[path] = time.time()
        if modified and self.settings.ransomware_shield:
            self._mods.append((time.time(), path))

    def _file_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(0.25)
            now = time.time()
            ready = []
            with self._plock:
                for p, t in list(self._pending.items()):
                    if now - t >= 0.8:  # aguarda o arquivo terminar de ser gravado
                        ready.append(p)
                        del self._pending[p]
            for p in ready:
                if self._stop.is_set():
                    return
                self._scan_path(p)
            if self.settings.ransomware_shield:
                self._ransomware_check()

    def _scan_path(self, path: str) -> None:
        try:
            st = os.stat(path)
        except OSError:
            return
        if not os.path.isfile(path):
            return
        version = self.engine.version
        if self.cache and self.cache.is_clean(path, st.st_size, st.st_mtime_ns, version):
            return
        try:
            res = self.engine.scan_file(path).result
        except Exception:
            return
        self.files_scanned += 1
        if res.is_threat:
            self._handle_threat(res)
        elif self.cache and not res.skipped:
            self.cache.mark_clean(path, st.st_size, st.st_mtime_ns, version)

    def _handle_threat(self, res: ScanResult, pids: list[int] | None = None) -> None:
        history.log("detecção", f"[Tempo real] {res.threat_name} ({res.verdict}, {res.score} pts)", res.path)
        action = "notificado"
        if res.verdict == MALICIOUS:
            if self.settings.realtime_kill_malicious_process:
                from .system import processes
                for pid in pids or processes.processes_using(res.path):
                    try:
                        processes.kill(pid)
                        action = "processo encerrado"
                        history.log("bloqueio", f"Processo {pid} encerrado ({res.threat_name})", res.path)
                    except Exception:
                        pass
            if self.settings.auto_action == "quarantine":
                try:
                    self.quarantine.isolate(res)
                    action = "colocado em quarentena" + (" e processo encerrado" if action == "processo encerrado" else "")
                    self.threats_blocked += 1
                except Exception as e:
                    action = f"falha ao isolar: {e}"
        res.action = action
        self.callback("threat", res)

    def _ransomware_check(self) -> None:
        now = time.time()
        while self._mods and now - self._mods[0][0] > 15:
            self._mods.popleft()
        if len(self._mods) < 15 or now - self._last_ransom_alert < 60:
            return
        candidates = {p for _t, p in self._mods if os.path.splitext(p)[1].lower() in DOC_EXT
                      or "." in os.path.basename(p)}
        encrypted = []
        for p in list(candidates)[:40]:
            try:
                with open(p, "rb") as f:
                    head = f.read(65536)
            except OSError:
                continue
            if len(head) >= 512 and util.entropy(head) > 7.85:
                from .engine import filetype
                t = filetype.detect(head)
                if t in ("binary",):  # documento virou ruído aleatório (sem formato reconhecível)
                    encrypted.append(p)
        if len(encrypted) >= 10:
            self._last_ransom_alert = now
            top = self._top_writer()
            info = {"files": encrypted[:20], "count": len(encrypted), "process": top}
            history.log("ransomware", f"Atividade de ransomware: {len(encrypted)} arquivos cifrados em 15s"
                        + (f" — processo suspeito: {top['name']} (PID {top['pid']})" if top else ""))
            if top and self.settings.realtime_kill_malicious_process and not top.get("self"):
                try:
                    from .system import processes
                    processes.suspend(top["pid"])
                    info["suspended"] = True
                    history.log("bloqueio", f"Processo {top['name']} (PID {top['pid']}) SUSPENSO pelo escudo anti-ransomware")
                except Exception:
                    pass
            self.callback("ransomware", info)

    @staticmethod
    def _top_writer() -> dict | None:
        best, best_w = None, 0
        me = os.getpid()
        for p in psutil.process_iter(["pid", "name", "exe"]):
            try:
                if p.info["pid"] == me:
                    continue
                io = p.io_counters()
                if io.write_bytes > best_w and time.time() - p.create_time() < 3600:
                    best_w = io.write_bytes
                    best = {"pid": p.info["pid"], "name": p.info["name"], "exe": p.info["exe"] or "",
                            "written": util.human_size(io.write_bytes)}
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError, NotImplementedError):
                continue
        return best

    # ------------------------------------------------------------------ processos
    def _process_loop(self) -> None:
        self._known_pids = set(psutil.pids())
        first = True
        while not self._stop.is_set():
            try:
                current = set(psutil.pids())
            except Exception:
                current = set()
            new = current - self._known_pids if not first else current
            self._known_pids = current
            first = False
            for pid in new:
                if self._stop.is_set():
                    return
                self._check_process(pid)
            self._stop.wait(1.5)

    def _check_process(self, pid: int) -> None:
        if pid == os.getpid():
            return
        try:
            p = psutil.Process(pid)
            exe = p.exe()
            cmdline = p.cmdline()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            return
        if not exe or self.engine.exclusions.is_excluded(exe):
            return
        if os.path.isfile(exe):
            self._check_exe(p, pid, exe)
        if _is_interpreter(exe) and len(cmdline) > 1:
            self._check_cmdline(p, pid, exe, cmdline)

    def _check_exe(self, p, pid: int, exe: str) -> None:
        try:
            st = os.stat(exe)
        except OSError:
            return
        key = (exe, st.st_size, st.st_mtime_ns)
        verdict = self._scanned_exes.get(key)
        if verdict is None:
            if self.cache and self.cache.is_clean(exe, st.st_size, st.st_mtime_ns, self.engine.version):
                self._scanned_exes[key] = "limpo"
                return
            try:
                res = self.engine.scan_file(exe).result
            except Exception:
                return
            self.processes_checked += 1
            self._scanned_exes[key] = res.verdict
            if res.is_threat:
                self._handle_threat(res, pids=[pid])
            elif self.cache and not res.skipped:
                self.cache.mark_clean(exe, st.st_size, st.st_mtime_ns, self.engine.version)
        elif verdict == MALICIOUS and self.settings.realtime_kill_malicious_process:
            self._kill(pid, p, exe)

    def _kill(self, pid: int, p, what: str) -> bool:
        try:
            from .system import processes
            name = p.name()
            processes.kill(pid)
            history.log("bloqueio", f"Processo malicioso {name} (PID {pid}) encerrado", what)
            return True
        except Exception:
            return False

    def _check_cmdline(self, p, pid: int, exe: str, cmdline: list[str]) -> None:
        """Interpretadores (bash, python, powershell, wscript...): verifica o script executado e o código
        passado direto na linha de comando (ataques "sem arquivo")."""
        try:
            cwd = p.cwd()
        except (psutil.Error, OSError):
            cwd = ""
        for arg in cmdline[1:8]:
            if not arg or arg.startswith(("-", "/")) and not os.path.isabs(arg):
                continue
            path = arg if os.path.isabs(arg) else os.path.join(cwd, arg) if cwd else ""
            try:
                if not path or not os.path.isfile(path) or self.engine.exclusions.is_excluded(path):
                    continue
                st = os.stat(path)
            except (OSError, ValueError):
                continue
            key = (path, st.st_size, st.st_mtime_ns)
            if key in self._scanned_exes:
                verdict = self._scanned_exes[key]
                if verdict == MALICIOUS and self.settings.realtime_kill_malicious_process:
                    self._kill(pid, p, path)
                continue
            try:
                res = self.engine.scan_file(path).result
            except Exception:
                continue
            self.processes_checked += 1
            self._scanned_exes[key] = res.verdict
            if res.is_threat:
                self._handle_threat(res, pids=[pid])
                return
        text = " ".join(cmdline)
        if len(text) < 24:
            return
        key = ("cmd", hash(text))
        if key in self._scanned_exes:
            return
        try:
            res = self.engine.analyze(text.encode("utf-8", "replace"), ftype="script").result
        except Exception:
            return
        self._scanned_exes[key] = res.verdict
        if res.verdict == MALICIOUS:
            res.path = f"[linha de comando do PID {pid}] {text[:300]}"
            history.log("detecção", f"[Tempo real] {res.threat_name} na linha de comando ({res.score} pts)", res.path)
            killed = self.settings.realtime_kill_malicious_process and self._kill(pid, p, exe)
            res.action = "processo encerrado" if killed else "notificado"
            if killed:
                self.threats_blocked += 1
            self.callback("threat", res)


_INTERPRETERS = {"bash", "sh", "dash", "zsh", "ksh", "fish", "python", "python2", "python3", "perl", "ruby", "node",
                 "nodejs", "php", "lua", "pwsh", "powershell", "powershell_ise", "wscript", "cscript", "mshta",
                 "cmd", "java", "javaw", "osascript", "rundll32", "regsvr32", "msiexec"}


def _is_interpreter(exe: str) -> bool:
    name = os.path.basename(exe).lower()
    if name.endswith(".exe"):
        name = name[:-4]
    name = name.rstrip("0123456789.")
    return name in _INTERPRETERS
