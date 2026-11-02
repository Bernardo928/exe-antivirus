"""Análise de scripts por dentro.

Vírus modernos raramente deixam um arquivo .exe: eles rodam scripts ofuscados, baixados na hora e
executados direto na memória. Este módulo olha o código que REALMENTE está sendo executado:

- Windows — PowerShell: com o registro de blocos de script (Script Block Logging) ligado, o próprio
  PowerShell entrega o código já decodificado (depois de -EncodedCommand, IEX, FromBase64String,
  concatenações...). Cada bloco é analisado pelo motor; se for malicioso o processo é encerrado e o
  código vai para a Sala de Análise. Funciona com o Windows PowerShell 5 e o PowerShell 7.
- Linux e Windows — interpretadores (bash, sh, python, perl, node...): o script aberto pelo processo é
  lido pelo descritor de arquivo, inclusive quando o vírus já apagou o arquivo do disco para se esconder.
- Linux — "curl | sh": detecta script baixado da internet e executado direto pelo shell.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

import psutil

from . import history, paths
from .engine.models import MALICIOUS, SUSPICIOUS, Indicator, ScanResult

PS_CHANNELS = ("Microsoft-Windows-PowerShell/Operational", "PowerShellCore/Operational")
_POLICY_KEYS = (r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                r"SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging")
_SHELLS = {"bash", "sh", "dash", "zsh", "ksh", "fish", "busybox"}
_INTERP = _SHELLS | {"python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php", "lua", "pwsh",
                     "powershell", "wscript", "cscript", "mshta", "osascript"}
_DOWNLOADERS = {"curl", "wget", "fetch", "aria2c"}
MAX_SCRIPT = 4 * 1024 * 1024


def _base(name: str) -> str:
    n = os.path.basename(name or "").lower()
    if n.endswith(".exe"):
        n = n[:-4]
    return n.rstrip("0123456789.")


# --------------------------------------------------------------------------- PowerShell (Windows)
def logging_enabled() -> bool:
    if not paths.IS_WINDOWS:
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _POLICY_KEYS[0]) as k:
            return winreg.QueryValueEx(k, "EnableScriptBlockLogging")[0] == 1
    except OSError:
        return False


def enable_logging(enabled: bool = True) -> None:
    """Liga o registro de blocos de script do PowerShell (exige administrador)."""
    import winreg
    for key in _POLICY_KEYS:
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "EnableScriptBlockLogging", 0, winreg.REG_DWORD, 1 if enabled else 0)


def _wevtutil(args: list[str]) -> str:
    r = subprocess.run(["wevtutil"] + args, capture_output=True, timeout=30, creationflags=0x08000000)
    return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else ""


def last_record_id(channel: str) -> int:
    out = _wevtutil(["qe", channel, "/c:1", "/rd:true", "/f:xml"])
    m = re.search(r"<EventRecordID>(\d+)</EventRecordID>", out)
    return int(m.group(1)) if m else 0


def parse_events(xml_text: str) -> list[dict]:
    """Lê eventos 4104 (XML do wevtutil) → [{record, pid, block_id, number, total, text, path}]."""
    out = []
    if not xml_text.strip():
        return out
    if not xml_text.lstrip().startswith("<Events"):
        xml_text = f"<Events>{xml_text}</Events>"
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    for ev in root.iter():
        if not ev.tag.endswith("Event") or ev.tag.endswith("Events"):
            continue
        d = {"record": 0, "pid": 0, "block_id": "", "number": 1, "total": 1, "text": "", "path": "", "event_id": 0}
        for el in ev.iter():
            tag = el.tag.rsplit("}", 1)[-1]
            if tag == "EventRecordID":
                d["record"] = int(el.text or 0)
            elif tag == "EventID":
                d["event_id"] = int(el.text or 0)
            elif tag == "Execution":
                d["pid"] = int(el.get("ProcessID") or 0)
            elif tag == "Data":
                name = el.get("Name")
                if name == "ScriptBlockText":
                    d["text"] = el.text or ""
                elif name == "ScriptBlockId":
                    d["block_id"] = el.text or ""
                elif name == "MessageNumber":
                    d["number"] = int(el.text or 1)
                elif name == "MessageTotal":
                    d["total"] = int(el.text or 1)
                elif name == "Path":
                    d["path"] = el.text or ""
        if d["event_id"] == 4104 and d["text"]:
            out.append(d)
    return out


def read_new_events(channel: str, after: int) -> list[dict]:
    q = f"*[System[(EventID=4104) and (EventRecordID>{after})]]"
    return parse_events(_wevtutil(["qe", channel, f"/q:{q}", "/f:xml", "/e:Events", "/c:500"]))


# --------------------------------------------------------------------------- serviço
class ScriptGuard:
    """callback(evento, dados): 'threat' (ScanResult), 'suspeito' (ScanResult), 'status' (str)."""

    def __init__(self, engine, quarantine=None, callback=None, lab=None, interval: float = 1.5):
        self.engine = engine
        self.settings = engine.settings
        self.quarantine = quarantine
        self.lab = lab
        self.callback = callback or (lambda *a: None)
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen: dict[str, str] = {}          # hash do código → veredito
        self._known_pids: set[int] = set()
        self._checked_fds: set[tuple] = set()
        self._records: dict[str, int] = {}
        self._parts: dict[str, dict] = {}        # blocos grandes chegam em vários eventos
        self.blocks_analyzed = 0
        self.scripts_analyzed = 0
        self.threats_blocked = 0

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop.is_set()

    @property
    def powershell_ready(self) -> bool:
        return paths.IS_WINDOWS and logging_enabled()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        if paths.IS_WINDOWS:
            for ch in PS_CHANNELS:
                try:
                    self._records[ch] = last_record_id(ch)
                except Exception:
                    self._records[ch] = 0
        self._known_pids = set(psutil.pids())
        self._thread = threading.Thread(target=self._loop, daemon=True, name="script-guard")
        self._thread.start()
        history.log("scripts", "Análise de scripts por dentro ativada")
        self.callback("status", "on")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._thread = None
        history.log("scripts", "Análise de scripts por dentro desativada")
        self.callback("status", "off")

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.tick()
            except Exception:
                continue

    def tick(self) -> None:
        if paths.IS_WINDOWS:
            self.poll_powershell()
        self.poll_processes()

    # ------------------------------------------------------------------ PowerShell
    def poll_powershell(self) -> int:
        n = 0
        for ch in PS_CHANNELS:
            try:
                events = read_new_events(ch, self._records.get(ch, 0))
            except Exception:
                continue
            for ev in sorted(events, key=lambda e: e["record"]):
                self._records[ch] = max(self._records.get(ch, 0), ev["record"])
                text = self._join_parts(ev)
                if text is None:
                    continue
                n += 1
                self.analyze_code(text, ev["pid"], "PowerShell", ev.get("path") or "", runtime=True)
        return n

    def _join_parts(self, ev: dict) -> str | None:
        if ev["total"] <= 1:
            return ev["text"]
        st = self._parts.setdefault(ev["block_id"], {"parts": {}, "t": time.time()})
        st["parts"][ev["number"]] = ev["text"]
        for k in [k for k, v in self._parts.items() if time.time() - v["t"] > 300]:
            self._parts.pop(k, None)
        if len(st["parts"]) < ev["total"]:
            return None
        self._parts.pop(ev["block_id"], None)
        return "".join(st["parts"][i] for i in sorted(st["parts"]))

    # ------------------------------------------------------------------ interpretadores
    def poll_processes(self) -> None:
        try:
            current = set(psutil.pids())
        except Exception:
            return
        new = current - self._known_pids
        self._known_pids = current
        self._checked_fds = {k for k in self._checked_fds if k[0] in current}
        me = os.getpid()
        for pid in new:
            if pid == me:
                continue
            try:
                p = psutil.Process(pid)
                name = _base(p.name())
                if name not in _INTERP:
                    continue
                exe = p.exe()
            except (psutil.Error, OSError):
                continue
            self.check_interpreter(p, name, exe)

    def check_interpreter(self, p: psutil.Process, name: str, exe: str = "") -> None:
        if not paths.IS_WINDOWS:
            if name in _SHELLS:
                self._scan_fds(p)
                self._pipe_from_downloader(p)
        else:
            try:
                files = [f.path for f in p.open_files()]
            except (psutil.Error, OSError):
                files = []
            for f in files:
                if os.path.splitext(f)[1].lower() in (".ps1", ".vbs", ".js", ".jse", ".vbe", ".wsf", ".hta",
                                                       ".bat", ".cmd", ".py"):
                    self._scan_script_file(p, f, f)

    def _scan_fds(self, p: psutil.Process) -> None:
        """Lê os scripts abertos pelo interpretador direto de /proc/PID/fd (funciona com arquivo apagado)."""
        fd_dir = f"/proc/{p.pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            return
        for fd in fds:
            # shells guardam o script num descritor alto (bash: 255, dash/zsh: 10+); descritores baixos são
            # redirecionamentos de saída e arquivos de dados, que não são código
            if not fd.isdigit() or int(fd) < 10:
                continue
            link = os.path.join(fd_dir, fd)
            try:
                target = os.readlink(link)
            except OSError:
                continue
            if not target.startswith("/") or target.startswith(("/dev/", "/proc/", "/sys/")):
                continue
            deleted = target.endswith(" (deleted)")
            real = target[:-10] if deleted else target
            low = real.lower()
            if low.endswith((".so", ".pyc", ".mo", ".cache", ".db", ".sqlite", ".log")) or "/lib/" in low and not deleted:
                continue
            key = (p.pid, fd, target)
            if key in self._checked_fds:
                continue
            self._checked_fds.add(key)
            if not deleted and self.engine.exclusions.is_excluded(real):
                continue
            self._scan_script_file(p, link, real + (" (apagado do disco)" if deleted else ""), deleted=deleted)

    def _scan_script_file(self, p: psutil.Process, read_path: str, shown: str, deleted: bool = False) -> None:
        try:
            with open(read_path, "rb") as f:
                data = f.read(MAX_SCRIPT)
        except OSError:
            return
        if not data or b"\x00" in data[:4096]:
            return  # binário: o tempo real já analisa executáveis
        self.scripts_analyzed += 1
        extra = []
        if deleted:
            extra.append(Indicator(id="script.deleted", name="Script apagado do disco enquanto roda",
                                   category="Comportamento", weight=25, severity="media",
                                   description="O arquivo do script foi apagado logo depois de começar a rodar — "
                                               "técnica usada para não deixar rastros."))
        self.analyze_code(data.decode("utf-8", "replace"), p.pid, _base(p.name()), shown, extra)

    def _pipe_from_downloader(self, p: psutil.Process) -> None:
        """'curl URL | sh': shell lendo da saída de um programa de download."""
        try:
            stdin = os.readlink(f"/proc/{p.pid}/fd/0")
        except OSError:
            return
        if not stdin.startswith("pipe:"):
            return
        cands = []
        try:
            cands = [p.parent()] + p.parent().children() if p.parent() else []
        except psutil.Error:
            pass
        for q in cands:
            try:
                if q is None or q.pid == p.pid or _base(q.name()) not in _DOWNLOADERS:
                    continue
                if os.readlink(f"/proc/{q.pid}/fd/1") != stdin:
                    continue
                url = next((a for a in q.cmdline()[1:] if re.match(r"(?i)(?:https?|ftp)://", a)), "")
            except (psutil.Error, OSError):
                continue
            res = ScanResult(path=f"[{p.name()} PID {p.pid}] script baixado de {url or 'internet'}",
                             verdict=SUSPICIOUS, score=40, threat_name="Script.PipeToShell", file_type="script")
            res.indicators = [Indicator(id="script.pipe_shell", name="Script baixado e executado direto (curl | sh)",
                                        category="Comportamento", weight=40, severity="media",
                                        evidence=[url] if url else [],
                                        description=f"O shell (PID {p.pid}) está executando o que o {q.name()} "
                                                    "baixa da internet, sem salvar nem conferir o arquivo. "
                                                    "Instaladores legítimos às vezes fazem isso; vírus também.")]
            res.action = "notificado"
            history.log("detecção", f"[Scripts] {res.indicators[0].name}: {url}", res.path)
            self.callback("suspeito", res)
            return

    # ------------------------------------------------------------------ análise
    def analyze_code(self, text: str, pid: int, source: str, where: str = "",
                     extra: list[Indicator] | None = None, runtime: bool = False) -> ScanResult | None:
        """runtime=True: o código foi entregue pelo próprio PowerShell no momento em que ia ser executado."""
        if not text or len(text.strip()) < 16:
            return None
        data = text.encode("utf-8", "replace")[:MAX_SCRIPT]
        h = hashlib.sha256(data).hexdigest()
        if h in self._seen and not extra:
            verdict = self._seen[h]
            if verdict == MALICIOUS:
                self._kill(pid)
            return None
        self.blocks_analyzed += 1
        try:
            res = self.engine.analyze(data, ftype="script").result
        except Exception:
            return None
        if runtime and any(i.id.startswith("ps.download_exec") for i in res.indicators):
            extra = (extra or []) + [Indicator(
                id="script.runtime_cradle", name="Código baixado da internet executado na memória",
                category="Comportamento", weight=20, severity="alta",
                description="O PowerShell está executando agora um código que baixa e roda outro código direto na "
                            "memória, sem salvar arquivo (técnica \"fileless\" de vírus).")]
        if extra and res.indicators:
            res.indicators += extra
            res.score += sum(i.weight for i in extra)
            lo, hi = self.settings.thresholds()
            res.verdict = MALICIOUS if res.score >= hi else SUSPICIOUS if res.score >= lo else res.verdict
        self._seen[h] = res.verdict
        if len(self._seen) > 20000:
            self._seen.clear()
        if not res.is_threat:
            return res
        first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")[:160]
        res.path = f"[{source} PID {pid}] {where or first}"
        saved = self._save_capture(data, source, h)
        if res.verdict == MALICIOUS:
            killed = self._kill(pid)
            res.action = "processo encerrado" if killed else "detectado"
            if killed:
                self.threats_blocked += 1
            if saved and self.lab is not None:
                try:
                    self.lab.add_file(saved, f"script capturado ({source})")
                    res.action += " • código enviado à Sala de Análise"
                except Exception:
                    pass
            history.log("detecção", f"[Scripts] {res.threat_name} ({res.score} pts) — {res.action}", res.path)
            self.callback("threat", res)
        else:
            res.action = "notificado"
            history.log("detecção", f"[Scripts] suspeito: {res.threat_name} ({res.score} pts)", res.path)
            self.callback("suspeito", res)
        return res

    def _save_capture(self, data: bytes, source: str, h: str) -> str:
        try:
            d = paths.sub_dir("captured_scripts")
            ext = ".ps1.txt" if "powershell" in source.lower() or "pwsh" in source.lower() else ".txt"
            p = d / f"{time.strftime('%Y%m%d-%H%M%S')}-{h[:12]}{ext}"
            p.write_bytes(data)
            return str(p)
        except OSError:
            return ""

    def _kill(self, pid: int) -> bool:
        if not pid or not self.settings.realtime_kill_malicious_process:
            return False
        from .realtime import _self_and_ancestors
        from .system import processes
        if pid in _self_and_ancestors() or processes.critical_reason(pid):
            return False
        try:
            name = psutil.Process(pid).name()
            processes.kill(pid)
            history.log("bloqueio", f"Processo {name} (PID {pid}) encerrado: script malicioso", str(pid))
            return True
        except (psutil.Error, OSError):
            return False
