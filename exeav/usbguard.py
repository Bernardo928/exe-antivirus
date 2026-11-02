"""Proteção de pen drives e discos externos.

Assim que um dispositivo removível (pen drive, cartão de memória, HD/SSD externo USB) é conectado:

1. a raiz é inspecionada à procura dos truques clássicos de vírus de pen drive:
   - autorun.inf que executa um programa ao abrir o dispositivo;
   - "vírus de atalho": as pastas do usuário são escondidas e no lugar aparecem atalhos (.lnk) com o
     mesmo nome que, ao serem abertos, executam o vírus;
   - programas e scripts escondidos na raiz;
2. todos os arquivos do dispositivo são verificados (em segundo plano, com prioridade baixa);
3. ameaças vão para a quarentena e, no caso do vírus de atalho, as pastas escondidas voltam a aparecer.
"""
from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass, field

import psutil

from . import history, paths
from .engine.models import MALICIOUS, SUSPICIOUS, Indicator, ScanResult

EXEC_EXT = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
            ".ps1", ".lnk", ".dll", ".cpl", ".msi", ".jar", ".sh", ".elf", ".appimage", ".desktop"}
_SCRIPT_RUNNERS = re.compile(rb"(?:cmd(?:\.exe)?\s*/[ck]|wscript|cscript|mshta|rundll32|powershell|regsvr32|"
                             rb"\.vbs|\.vbe|\.js\b|\.jse|\.hta|start\s+/b|explorer(?:\.exe)?\s)", re.I)


@dataclass
class Drive:
    mountpoint: str
    device: str
    fstype: str
    label: str = ""
    total: int = 0
    connected: float = field(default_factory=time.time)

    @property
    def key(self) -> str:
        return f"{self.device}|{self.mountpoint}"

    def title(self) -> str:
        name = self.label or os.path.basename(self.mountpoint.rstrip("\\/")) or self.mountpoint
        return f"{name} ({self.mountpoint})" if name != self.mountpoint else self.mountpoint


@dataclass
class Finding:
    kind: str           # autorun | atalho | oculto
    path: str
    description: str
    hidden_target: str = ""     # pasta escondida pelo vírus de atalho (para reexibir)


# --------------------------------------------------------------------------- detecção de dispositivos
def _win_is_usb(letter: str) -> bool:
    """Disco na porta USB (HDs/SSDs externos aparecem como 'fixos' para o Windows)."""
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    h = k32.CreateFileW(f"\\\\.\\{letter}:", 0, 3, None, 3, 0, None)
    if h in (None, wintypes.HANDLE(-1).value):
        return False
    try:
        query = (ctypes.c_ulong * 3)(0, 0, 0)            # StorageDeviceProperty, PropertyStandardQuery
        buf = ctypes.create_string_buffer(1024)
        ret = wintypes.DWORD()
        ok = k32.DeviceIoControl(h, 0x002D1400, query, ctypes.sizeof(query), buf, 1024, ctypes.byref(ret), None)
        if not ok or ret.value < 32:
            return False
        bus_type = int.from_bytes(buf.raw[28:32], "little")   # STORAGE_DEVICE_DESCRIPTOR.BusType
        return bus_type in (7, 12, 13)                       # USB, SD, MMC
    finally:
        k32.CloseHandle(h)


def _win_label(mount: str) -> str:
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(261)
        if ctypes.windll.kernel32.GetVolumeInformationW(mount, buf, 261, None, None, None, None, 0):
            return buf.value
    except Exception:
        pass
    return ""


def _linux_block_parent(device: str) -> str:
    name = os.path.basename(os.path.realpath(device))
    sysp = f"/sys/class/block/{name}"
    if os.path.exists(os.path.join(sysp, "partition")):
        return os.path.basename(os.path.dirname(os.path.realpath(sysp)))
    return name


def _linux_is_removable(device: str, mount: str) -> bool:
    if not device.startswith("/dev/"):
        return False
    parent = _linux_block_parent(device)
    try:
        with open(f"/sys/block/{parent}/removable") as f:
            if f.read().strip() == "1":
                return True
    except OSError:
        pass
    try:
        if "/usb" in os.path.realpath(f"/sys/block/{parent}"):
            return True
    except OSError:
        pass
    return mount.startswith(("/media/", "/run/media/")) and not parent.startswith(("loop", "dm-", "sr"))


def list_removable() -> list[Drive]:
    out = []
    try:
        parts = psutil.disk_partitions(all=False)
    except Exception:
        return out
    for p in parts:
        try:
            if paths.IS_WINDOWS:
                if "cdrom" in p.opts or not p.mountpoint:
                    continue
                letter = p.mountpoint[0]
                if letter.upper() in "AB":
                    continue
                if "removable" not in p.opts and not _win_is_usb(letter):
                    continue
                label = _win_label(p.mountpoint)
            else:
                if not _linux_is_removable(p.device, p.mountpoint):
                    continue
                label = os.path.basename(p.mountpoint)
            try:
                total = psutil.disk_usage(p.mountpoint).total
            except OSError:
                total = 0
            out.append(Drive(p.mountpoint, p.device, p.fstype, label, total))
        except Exception:
            continue
    return out


# --------------------------------------------------------------------------- truques de vírus de pen drive
def _is_hidden(path: str) -> bool:
    name = os.path.basename(path.rstrip("\\/"))
    if paths.IS_WINDOWS:
        try:
            attrs = os.stat(path).st_file_attributes
            return bool(attrs & 0x2)    # FILE_ATTRIBUTE_HIDDEN
        except (OSError, AttributeError):
            return False
    return name.startswith(".")


def _unhide(path: str) -> None:
    if paths.IS_WINDOWS:
        import ctypes
        attrs = ctypes.windll.kernel32.GetFileAttributesW(path)
        if attrs != 0xFFFFFFFF:
            ctypes.windll.kernel32.SetFileAttributesW(path, attrs & ~0x2 & ~0x4)   # tira oculto e sistema
    else:
        base = os.path.basename(path.rstrip("/"))
        if base.startswith("."):
            dst = os.path.join(os.path.dirname(path.rstrip("/")), base.lstrip("."))
            if not os.path.exists(dst):
                os.rename(path, dst)


def inspect_root(root: str) -> list[Finding]:
    """Procura autorun.inf, vírus de atalho e executáveis escondidos na raiz do dispositivo."""
    found: list[Finding] = []
    try:
        entries = list(os.scandir(root))
    except OSError:
        return found
    by_name = {e.name.lower(): e for e in entries}
    for e in entries:
        low = e.name.lower()
        try:
            is_file = e.is_file(follow_symlinks=False)
        except OSError:
            continue
        if low == "autorun.inf" and is_file:
            try:
                txt = open(e.path, "rb").read(65536).decode("latin-1", "replace")
            except OSError:
                continue
            m = re.search(r"^\s*(?:open|shellexecute|shell\\[^\\]+\\command)\s*=\s*(.+)$", txt, re.I | re.M)
            if m:
                found.append(Finding("autorun", e.path, f"autorun.inf manda executar \"{m.group(1).strip()[:120]}\" "
                                                        "quando o dispositivo é aberto — técnica de vírus de pen drive."))
        elif low.endswith(".lnk") and is_file:
            stem = low[:-4]
            twin = by_name.get(stem)
            try:
                data = open(e.path, "rb").read(65536)
            except OSError:
                continue
            runs_script = bool(_SCRIPT_RUNNERS.search(data) or _SCRIPT_RUNNERS.search(data.replace(b"\x00", b"")))
            if twin is not None and twin.is_dir(follow_symlinks=False) and (_is_hidden(twin.path) or runs_script):
                found.append(Finding("atalho", e.path,
                                     f"Atalho \"{e.name}\" imita a pasta \"{twin.name}\", que foi escondida — "
                                     "sinal do vírus de atalho.", hidden_target=twin.path))
            elif runs_script:
                hidden_dot = by_name.get("." + stem)
                found.append(Finding("atalho", e.path, f"Atalho \"{e.name}\" na raiz do dispositivo executa um "
                                                       "comando/script em vez de abrir um arquivo.",
                                     hidden_target=hidden_dot.path if hidden_dot else ""))
        elif is_file and _is_hidden(e.path) and os.path.splitext(low)[1] in EXEC_EXT and low != "autorun.inf":
            found.append(Finding("oculto", e.path, f"Programa/script escondido na raiz: \"{e.name}\"."))
    return found


def finding_result(f: Finding) -> ScanResult:
    """Transforma um achado da raiz em resultado de detecção (para a quarentena e o histórico)."""
    names = {"autorun": ("USB.Autorun", "Autorun de pen drive", 45),
             "atalho": ("USB.ShortcutWorm", "Vírus de atalho (pen drive)", 75),
             "oculto": ("USB.HiddenExecutable", "Executável escondido no pen drive", 40)}
    threat, title, weight = names[f.kind]
    try:
        size = os.path.getsize(f.path)
    except OSError:
        size = 0
    r = ScanResult(path=f.path, size=size, file_type="usb", threat_name=threat, score=weight,
                   verdict=MALICIOUS if weight >= 70 else SUSPICIOUS)
    r.indicators = [Indicator(id=f"usb.{f.kind}", name=title, category="Pen drive", description=f.description,
                              weight=weight, severity="alta" if weight >= 70 else "media", family=threat)]
    return r


# --------------------------------------------------------------------------- serviço
class UsbGuard:
    """callback(evento, dados): 'inserted' (Drive), 'removed' (Drive), 'finding' ((Drive, Finding, ScanResult)),
    'threat' (ScanResult), 'progress' ((Drive, ScanStats)), 'done' ((Drive, ScanStats)), 'status' (str)."""

    def __init__(self, engine, quarantine, callback=None, cache=None, interval: float = 2.0, lister=None):
        self.engine = engine
        self.settings = engine.settings
        self.quarantine = quarantine
        self.callback = callback or (lambda *a: None)
        self.cache = cache
        self.interval = interval
        self.lister = lister or list_removable
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._known: dict[str, Drive] = {}
        self._scanning: dict[str, object] = {}
        self._lock = threading.Lock()
        self.drives_scanned = 0
        self.threats_found = 0
        self.last: dict[str, dict] = {}     # resumo da última verificação de cada dispositivo

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop.is_set()

    def connected(self) -> list[Drive]:
        with self._lock:
            return list(self._known.values())

    def is_scanning(self, drive: Drive) -> bool:
        return drive.key in self._scanning

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        with self._lock:
            # dispositivos já conectados ao ligar o antivírus ficam visíveis; a verificação é manual
            self._known = {d.key: d for d in self.lister()}
        self._thread = threading.Thread(target=self._loop, daemon=True, name="usb-guard")
        self._thread.start()
        history.log("pen drive", "Proteção de pen drives ativada")
        self.callback("status", "on")

    def stop(self) -> None:
        self._stop.set()
        for sc in list(self._scanning.values()):
            try:
                sc.stop()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)
        self._thread = None
        history.log("pen drive", "Proteção de pen drives desativada")
        self.callback("status", "off")

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            self.poll()

    def poll(self) -> list[Drive]:
        """Compara os dispositivos conectados com a última leitura; retorna os novos."""
        current = {d.key: d for d in self.lister()}
        with self._lock:
            new = [d for k, d in current.items() if k not in self._known]
            gone = [d for k, d in self._known.items() if k not in current]
            self._known = current
        for d in gone:
            history.log("pen drive", f"Dispositivo removido: {d.title()}")
            self.callback("removed", d)
        for d in new:
            history.log("pen drive", f"Dispositivo conectado: {d.title()}", d.device)
            self.callback("inserted", d)
            if self.settings.usb_auto_scan:
                self.scan_drive(d, background=True)
        return new

    # ------------------------------------------------------------------ verificação
    def scan_drive(self, drive: Drive, background: bool = True):
        if drive.key in self._scanning:
            return None
        if background:
            t = threading.Thread(target=self._scan, args=(drive,), daemon=True, name="usb-scan")
            t.start()
            return t
        return self._scan(drive)

    def _isolate(self, res: ScanResult) -> str:
        if res.verdict != MALICIOUS or self.settings.auto_action != "quarantine":
            res.action = "notificado"
            return ""
        try:
            qid = self.quarantine.isolate(res)
            res.action = "quarentena"
            return qid
        except Exception as e:
            res.action = f"falha ao isolar: {e}"
            return ""

    def _scan(self, drive: Drive):
        from .scanner import USB, Scanner
        root = drive.mountpoint
        summary = {"drive": drive.title(), "files": 0, "threats": 0, "fixed": 0, "date": time.strftime("%H:%M:%S")}
        # 1) truques na raiz
        from . import incidents
        for f in inspect_root(root):
            res = finding_result(f)
            pre = incidents.collect(f.path)
            qid = self._isolate(res)
            if (f.hidden_target and os.path.exists(f.hidden_target) and _is_hidden(f.hidden_target)
                    and self.settings.usb_fix_shortcut_virus and res.verdict == MALICIOUS):
                try:
                    _unhide(f.hidden_target)
                    res.action += " • pasta escondida voltou a aparecer"
                    summary["fixed"] += 1
                except OSError:
                    pass
            summary["threats"] += 1
            self.threats_found += 1
            history.log("detecção", f"[Pen drive] {res.threat_name}: {f.description}", f.path)
            incidents.report(res, f"pen drive: {drive.title()}", action=res.action, pre=pre, quarantine_id=qid,
                             events=[{"dispositivo": drive.title(), "device": drive.device, "fs": drive.fstype}])
            self.callback("finding", (drive, f, res))

        # 2) todos os arquivos
        def on_threat(r):
            pre = incidents.collect(r.path)
            qid = self._isolate(r)
            summary["threats"] += 1
            self.threats_found += 1
            history.log("detecção", f"[Pen drive] {r.threat_name} ({r.score} pts) — {r.action}", r.path)
            incidents.report(r, f"pen drive: {drive.title()}", action=r.action, pre=pre, quarantine_id=qid,
                             events=[{"dispositivo": drive.title(), "device": drive.device, "fs": drive.fstype}])
            self.callback("threat", r)
        sc = Scanner(self.engine, USB, [root], on_threat=on_threat, cache=self.cache, low_priority=True,
                     on_progress=lambda st: self.callback("progress", (drive, st)))
        self._scanning[drive.key] = sc
        try:
            st = sc.run()
        finally:
            self._scanning.pop(drive.key, None)
        summary["files"] = st.files
        self.drives_scanned += 1
        self.last[drive.key] = summary
        self.callback("done", (drive, st))
        return st
