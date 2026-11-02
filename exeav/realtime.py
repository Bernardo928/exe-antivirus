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
            self.rt.canary_event(event.src_path, "modificado")
            self.rt.enqueue(event.src_path, modified=True)

    def on_moved(self, event):
        if not event.is_directory:
            self.rt.canary_event(event.src_path, "renomeado")
            self.rt.enqueue(event.dest_path, modified=True)

    def on_deleted(self, event):
        if not event.is_directory:
            self.rt.canary_event(event.src_path, "apagado")

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
        self._io_samples: deque = deque()
        self._last_io_sample = 0.0
        self.files_scanned = 0
        self.threats_blocked = 0
        self.processes_checked = 0
        self.watched: list[str] = []
        self.errors: list[str] = []
        self.canaries: set[str] = set()
        self._canary_names: set[str] = set()
        self._canary_redo = 0.0
        self._last_canary_alert = 0.0

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
        self._setup_canaries()
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
            if self._canary_redo and now >= self._canary_redo:
                self._canary_redo = 0.0
                self._setup_canaries()

    # ------------------------------------------------------------------ arquivos-isca
    def _setup_canaries(self) -> None:
        from . import canary
        if not (self.settings.ransomware_shield and self.settings.ransomware_canaries):
            self.canaries = set()
            return
        try:
            self.canaries = set(canary.ensure(canary.default_dirs(self.watched)))
            self._canary_names = {os.path.basename(p) for p in self.canaries}
        except Exception as e:  # noqa: BLE001
            self.errors.append(f"arquivos-isca: {e}")

    def canary_event(self, path: str, event: str) -> None:
        if not self.canaries or os.path.basename(path) not in self._canary_names or path not in self.canaries:
            return
        from . import canary
        if not canary.tripped(path, event):
            if event == "apagado":
                history.log("ransomware", "Arquivo-isca apagado (recriado em seguida)", path)
                self._canary_redo = time.time() + 5
            return
        now = time.time()
        if now - self._last_canary_alert < 30:
            return
        self._last_canary_alert = now
        # quem está escrevendo AGORA (janela curta medida na hora: o ataque continua cifrando)
        base = _io_snapshot()
        time.sleep(0.8)
        top = self._culprit(0, base=base, min_bytes=1024)
        info = {"files": [path], "count": 1, "process": top, "canary": path, "event": event}
        history.log("ransomware", f"ARQUIVO-ISCA {event.upper()}: ataque de ransomware em andamento"
                    + (f" — processo suspeito: {top['name']} (PID {top['pid']})" if top else ""), path)
        if top and top.get("can_suspend") and self.settings.realtime_kill_malicious_process:
            try:
                from .system import processes
                processes.suspend(top["pid"])
                info["suspended"] = True
                history.log("bloqueio", f"Processo {top['name']} (PID {top['pid']}) SUSPENSO: mexeu no arquivo-isca")
            except Exception:
                pass
        from . import incidents
        incidents.report(None, "anti-ransomware (isca)", pid=(top or {}).get("pid"),
                         action="processo suspenso" if info.get("suspended") else "alerta",
                         behavior={"title": "Ransomware: arquivo-isca atacado", "verdict": "malicioso", "score": 100,
                                   "critical": True, "key": f"canary-{(top or {}).get('exe', '')}",
                                   "path": (top or {}).get("exe", ""),
                                   "indicators": [{"id": "ransom.canary", "name": f"Arquivo-isca {event}",
                                                   "category": "Ransomware", "weight": 100, "evidence": [path],
                                                   "description": "Um programa alterou/renomeou um arquivo-isca que "
                                                                  "nenhum programa legítimo tem motivo para tocar."}]})
        self._canary_redo = now + 5
        self.callback("ransomware", info)

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
        from . import incidents
        pre = incidents.collect(res.path)
        qid = ""
        action = "notificado"
        if res.verdict == MALICIOUS:
            if self.settings.realtime_kill_malicious_process:
                from .system import processes
                protected = _self_and_ancestors()
                for pid in pids or processes.processes_using(res.path):
                    if pid in protected:
                        continue
                    try:
                        processes.kill(pid)
                        action = "processo encerrado"
                        history.log("bloqueio", f"Processo {pid} encerrado ({res.threat_name})", res.path)
                    except Exception:
                        pass
            if self.settings.auto_action == "quarantine":
                try:
                    qid = self.quarantine.isolate(res)
                    action = "colocado em quarentena" + (" e processo encerrado" if action == "processo encerrado" else "")
                    self.threats_blocked += 1
                except Exception as e:
                    action = f"falha ao isolar: {e}"
        res.action = action
        incidents.report(res, "tempo real", pid=(pids or [None])[0], action=action, quarantine_id=qid, pre=pre)
        self.callback("threat", res)

    def _ransomware_check(self) -> None:
        now = time.time()
        while self._mods and now - self._mods[0][0] > 15:
            self._mods.popleft()
        if self._mods and now - self._last_io_sample >= 2.0:
            # amostras de E/S por processo durante a atividade, para saber QUEM escreveu na janela do ataque
            self._last_io_sample = now
            self._io_samples.append((now, _io_snapshot()))
            while self._io_samples and now - self._io_samples[0][0] > 30:
                self._io_samples.popleft()
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
            enc_bytes = 0
            for f in encrypted:
                try:
                    enc_bytes += os.path.getsize(f)
                except OSError:
                    pass
            top = self._culprit(enc_bytes)
            info = {"files": encrypted[:20], "count": len(encrypted), "process": top}
            history.log("ransomware", f"Atividade de ransomware: {len(encrypted)} arquivos cifrados em 15s"
                        + (f" — processo suspeito: {top['name']} (PID {top['pid']})" if top else ""))
            if top and top.get("can_suspend") and self.settings.realtime_kill_malicious_process:
                try:
                    from .system import processes
                    processes.suspend(top["pid"])
                    info["suspended"] = True
                    history.log("bloqueio", f"Processo {top['name']} (PID {top['pid']}) SUSPENSO pelo escudo anti-ransomware")
                except Exception:
                    pass
            from . import incidents
            incidents.report(None, "anti-ransomware", pid=(top or {}).get("pid"),
                             action="processo suspenso" if info.get("suspended") else "alerta",
                             behavior={"title": "Atividade de ransomware", "verdict": "malicioso", "score": 100,
                                       "critical": True, "key": f"ransom-{(top or {}).get('pid')}",
                                       "path": (top or {}).get("exe", ""),
                                       "indicators": [{"id": "ransom.mass_encrypt", "name": "Arquivos cifrados em massa",
                                                       "category": "Ransomware", "weight": 100,
                                                       "description": f"{len(encrypted)} arquivos viraram dados "
                                                                      "aleatórios (cifrados) em 15 segundos.",
                                                       "evidence": encrypted[:20]}]})
            self.callback("ransomware", info)

    def _culprit(self, enc_bytes: int, base: dict | None = None, min_bytes: int = 16 * 1024) -> dict | None:
        """Processo que mais escreveu DURANTE a janela do ataque (não o total acumulado desde que abriu).

        Nunca aponta para suspensão: o próprio antivírus, quem o iniciou (terminal, sessão), processos
        críticos ou programas íntegros do sistema/assinados — esses apenas aparecem no alerta."""
        now_snap = _io_snapshot()
        if base is None:
            base = self._io_samples[0][1] if self._io_samples else {}
            t0 = self._io_samples[0][0] if self._io_samples else 0
        else:
            t0 = time.time() - 1
        protected = _self_and_ancestors()
        best, best_delta = None, 0
        for pid, (ctime, wb, wc, name, exe) in now_snap.items():
            if pid in protected:
                continue
            old = base.get(pid)
            if old and old[0] == ctime:
                delta = max(wb - old[1], wc - old[2])
            elif not base or ctime >= t0 - 1:
                delta = max(wb, wc)  # processo nasceu durante o ataque
            else:
                continue
            if delta > best_delta:
                best_delta, best = delta, (pid, name, exe)
        if best is None or best_delta < max(min_bytes, enc_bytes // 4):
            return None
        pid, name, exe = best
        can = True
        from .system import processes
        if processes.critical_reason(pid):
            can = False
        elif exe and not _is_interpreter(exe):
            # programa íntegro do sistema / assinado: só alerta. Interpretadores (python, powershell, wscript...)
            # são legítimos mas executam ransomware em script, então podem ser suspensos.
            from .engine import trust
            from .quarantine import protection_reason
            ok, _desc = trust.check(exe)
            can = not (ok or protection_reason(exe))
        return {"pid": pid, "name": name, "exe": exe, "written": util.human_size(best_delta), "can_suspend": can}

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
        if (_is_interpreter(exe) or _is_lolbin(exe)) and len(cmdline) > 1:
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
        if pid in _self_and_ancestors():
            return False
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
        parent = self._untrusted_parent(p) if res.is_threat else None
        if parent:
            # segundo sinal independente: o comando perigoso foi disparado por um programa sem origem verificável
            from .engine.models import Indicator
            res.indicators.append(Indicator(
                id="chain.untrusted_parent", name="Disparado por programa desconhecido", category="Cadeia de execução",
                description="Quem executou este comando foi um programa sem assinatura digital/pacote verificado — "
                            "cadeia típica de malware usando ferramentas do sistema.",
                weight=25, severity="alta", evidence=[f"{parent['name']} (PID {parent['pid']}) {parent['exe']}"]))
            res.score += 25
            lo, hi = self.settings.thresholds()
            res.verdict = MALICIOUS if res.score >= hi else res.verdict
            res.threat_name = self.engine._threat_name(res)
        self._scanned_exes[key] = res.verdict
        if res.is_threat:
            res.path = f"[linha de comando do PID {pid}] {text[:300]}"
            history.log("detecção", f"[Tempo real] {res.threat_name} na linha de comando ({res.verdict}, "
                                    f"{res.score} pts)", res.path)
            action = "notificado"
            if res.verdict == MALICIOUS and self.settings.realtime_kill_malicious_process:
                if self._kill(pid, p, exe):
                    action = "processo encerrado"
                    self.threats_blocked += 1
                if parent and parent.get("can_suspend"):
                    try:
                        from .system import processes
                        processes.suspend(parent["pid"])
                        action += f" • programa que disparou ({parent['name']}) suspenso"
                        history.log("bloqueio", f"{parent['name']} (PID {parent['pid']}) suspenso: disparou "
                                                f"{res.threat_name}", parent["exe"])
                    except Exception:
                        pass
            res.action = action
            from . import incidents
            incidents.report(res, "tempo real: linha de comando", pid=pid, action=res.action,
                             data=text.encode("utf-8", "replace"),
                             events=[{"processo_pai": parent}] if parent else None)
            self.callback("threat", res)

    def _untrusted_parent(self, p) -> dict | None:
        """Processo-pai sem origem verificável (nem o antivírus, nem do sistema, nem assinado)."""
        try:
            par = p.parent()
            if par is None:
                return None
            exe = par.exe()
            name = par.name()
        except (psutil.Error, OSError):
            return None
        if not exe or not os.path.isfile(exe) or self.engine.exclusions.is_excluded(exe) or _is_interpreter(exe):
            return None
        from .engine import trust
        from .quarantine import protection_reason
        from .system import processes
        if trust.check(exe)[0] or protection_reason(exe):
            return None
        return {"pid": par.pid, "name": name, "exe": exe,
                "can_suspend": par.pid not in _self_and_ancestors() and not processes.critical_reason(par.pid)}


def _io_snapshot() -> dict:
    out = {}
    for p in psutil.process_iter(["pid", "name", "exe", "create_time"]):
        try:
            io = p.io_counters()
            wc = getattr(io, "write_chars", 0) or 0
            out[p.info["pid"]] = (p.info["create_time"] or 0, io.write_bytes, wc, p.info["name"] or "",
                                  p.info["exe"] or "")
        except (psutil.Error, AttributeError, NotImplementedError, OSError):
            continue
    return out


def _self_and_ancestors() -> set[int]:
    pids = {os.getpid()}
    try:
        p = psutil.Process(os.getpid())
        for a in p.parents():
            pids.add(a.pid)
        for c in p.children(recursive=True):  # processos de varredura do próprio antivírus
            try:
                if any("multiprocessing" in a for a in c.cmdline()):
                    pids.add(c.pid)
            except psutil.Error:
                continue
    except psutil.Error:
        pass
    return pids


_INTERPRETERS = {"bash", "sh", "dash", "zsh", "ksh", "fish", "python", "python2", "python3", "perl", "ruby", "node",
                 "nodejs", "php", "lua", "pwsh", "powershell", "powershell_ise", "wscript", "cscript", "mshta",
                 "cmd", "java", "javaw", "osascript", "rundll32", "regsvr32", "msiexec"}


# Ferramentas legítimas do sistema que o ransomware/malware usa direto (sem interpretador) para apagar backups,
# desligar a recuperação, derrubar o firewall ou baixar arquivos. A linha de comando delas é analisada pelas
# mesmas regras dos scripts (só alarma se o comando for de fato destrutivo).
_LOLBINS = {"vssadmin", "wmic", "wbadmin", "bcdedit", "netsh", "reg", "schtasks", "certutil", "bitsadmin",
            "wevtutil", "fsutil", "cipher", "sc", "icacls", "takeown", "attrib",
            "crontab", "chattr", "iptables", "nft", "ufw", "systemctl", "setenforce", "shred", "curl", "wget"}


def _is_lolbin(exe: str) -> bool:
    name = os.path.basename(exe).lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name in _LOLBINS


def _is_interpreter(exe: str) -> bool:
    name = os.path.basename(exe).lower()
    if name.endswith(".exe"):
        name = name[:-4]
    name = name.rstrip("0123456789.")
    return name in _INTERPRETERS
