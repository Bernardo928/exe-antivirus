"""Varreduras: rápida, completa e personalizada (multithread, com cache incremental)."""
from __future__ import annotations

import multiprocessing
import os
import queue
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import config, history, paths
from .engine.engine import Engine
from .engine.models import CLEAN, ScanResult

QUICK, FULL, CUSTOM, USB, BOOT = "quick", "full", "custom", "usb", "boot"
BIG_FILE = 32 * 1024 * 1024
KIND_NAMES = {QUICK: "Scan rápido", FULL: "Scan completo", CUSTOM: "Scan personalizado", USB: "Scan de pen drive",
              BOOT: "Scan de inicialização"}

PSEUDO_FS = {"proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "securityfs", "pstore", "bpf",
             "tracefs", "debugfs", "mqueue", "hugetlbfs", "fusectl", "configfs", "autofs", "binfmt_misc",
             "nsfs", "squashfs", "nfs", "nfs4", "cifs", "smbfs", "smb3", "fuse.sshfs", "fuse.gvfsd-fuse",
             "efivarfs", "rpc_pipefs", "fuse.portal", "fuse.snapfuse", "ramfs", "selinuxfs"}
LINUX_SKIP = ("/proc", "/sys", "/dev", "/run/user", "/run/lock", "/snap", "/var/lib/docker/overlay2",
              "/var/lib/containers/storage/overlay", "/var/snap/lxd")


# --------------------------------------------------------------------------- processos paralelos
_child_engine = None


def lower_priority(pid: int | None = None) -> None:
    """Prioridade baixa de CPU e disco (varredura em segundo plano não pode deixar o PC lento)."""
    try:
        import psutil
        p = psutil.Process(pid or os.getpid())
        if paths.IS_WINDOWS:
            p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
            try:
                p.ionice(psutil.IOPRIO_LOW)
            except Exception:
                pass
        else:
            p.nice(max(p.nice(), 10))
            try:
                p.ionice(psutil.IOPRIO_CLASS_IDLE)
            except Exception:
                pass
    except Exception:
        pass


def _child_init(settings_dict: dict, low_priority: bool = False) -> None:
    global _child_engine
    if low_priority:
        lower_priority()
    from .engine.engine import Engine as _E
    s = config.Settings()
    for k, v in settings_dict.items():
        if hasattr(s, k):
            setattr(s, k, v)
    _child_engine = _E(s)


def _child_scan(path: str) -> ScanResult:
    try:
        return _child_engine.scan_file(path).result
    except MemoryError:
        return ScanResult(path=path, skipped=True, error="Memória insuficiente")
    except Exception as e:  # noqa: BLE001
        return ScanResult(path=path, skipped=True, error=f"Erro interno: {e}")


class ScanCache:
    """Lembra arquivos limpos já analisados (tamanho + data de modificação + versão do motor)."""

    def __init__(self, path: Path | None = None):
        self.path = path or (paths.data_dir() / "scan_cache.db")
        self._lock = threading.Lock()
        from .db import open_db
        self._conn = open_db(self.path, ["CREATE TABLE IF NOT EXISTS cache (path TEXT PRIMARY KEY, size INTEGER, "
                                         "mtime INTEGER, version TEXT)"], wal=True)
        self._pending: list[tuple] = []

    def is_clean(self, path: str, size: int, mtime: int, version: str) -> bool:
        with self._lock:
            row = self._conn.execute("SELECT size, mtime, version FROM cache WHERE path=?", (path,)).fetchone()
        return bool(row) and row[0] == size and row[1] == mtime and row[2] == version

    def mark_clean(self, path: str, size: int, mtime: int, version: str) -> None:
        with self._lock:
            self._pending.append((path, size, mtime, version))
            if len(self._pending) >= 500:
                self._flush_locked()

    def forget(self, path: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM cache WHERE path=?", (path,))
            self._conn.commit()

    def _flush_locked(self) -> None:
        if self._pending:
            self._conn.executemany("INSERT OR REPLACE INTO cache VALUES (?,?,?,?)", self._pending)
            self._conn.commit()
            self._pending.clear()

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def clear(self) -> None:
        with self._lock:
            self._pending.clear()
            self._conn.execute("DELETE FROM cache")
            self._conn.commit()

    def size(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]


@dataclass
class ScanStats:
    kind: str = CUSTOM
    started: float = field(default_factory=time.time)
    finished: float = 0.0
    files: int = 0
    from_cache: int = 0
    skipped: int = 0
    bytes: int = 0
    threats: list[ScanResult] = field(default_factory=list)
    current: str = ""
    discovered: int = 0
    walking_done: bool = False
    cancelled: bool = False
    errors: int = 0

    @property
    def elapsed(self) -> float:
        return (self.finished or time.time()) - self.started


def _home_dirs() -> list[Path]:
    home = Path.home()
    names = ["Downloads", "Desktop", "Documents", "Transferências", "Área de Trabalho", "Documentos",
             "Music", "Pictures", "Videos", "Público", "Public"]
    out = [home / n for n in names[:6]]
    try:
        import subprocess
        if not paths.IS_WINDOWS:
            for key in ("DOWNLOAD", "DESKTOP", "DOCUMENTS"):
                r = subprocess.run(["xdg-user-dir", key], capture_output=True, text=True, timeout=3)
                if r.returncode == 0 and r.stdout.strip():
                    out.append(Path(r.stdout.strip()))
    except Exception:
        pass
    return out


def quick_targets() -> list[str]:
    """Locais onde malware costuma ficar: downloads, área de trabalho, temporários, inicialização,
    e os executáveis de todos os processos em execução."""
    cands: list[Path] = _home_dirs()
    env = os.environ
    if paths.IS_WINDOWS:
        for v in ("TEMP", "TMP"):
            if env.get(v):
                cands.append(Path(env[v]))
        if env.get("APPDATA"):
            ap = Path(env["APPDATA"])
            cands += [ap / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup", ap]
        if env.get("LOCALAPPDATA"):
            cands.append(Path(env["LOCALAPPDATA"]) / "Temp")
        if env.get("PROGRAMDATA"):
            pd = Path(env["PROGRAMDATA"])
            cands += [pd / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp"]
        if env.get("PUBLIC"):
            cands.append(Path(env["PUBLIC"]))
        cands.append(Path(env.get("WINDIR", r"C:\Windows")) / "Temp")
    else:
        home = Path.home()
        cands += [Path("/tmp"), Path("/var/tmp"), Path("/dev/shm"), home / ".config" / "autostart",
                  home / ".local" / "bin", home / ".config" / "systemd" / "user", Path("/etc/cron.d"),
                  Path("/etc/systemd/system"), Path("/etc/init.d"), Path("/usr/local/bin")]
    seen, out = set(), []
    for c in cands:
        try:
            if c.exists():
                k = paths.norm(c)
                if k not in seen:
                    seen.add(k)
                    out.append(str(c))
        except OSError:
            pass
    # processos em execução e itens de inicialização
    try:
        from .system import processes, startup
        for exe in processes.running_executables():
            k = paths.norm(exe)
            if k not in seen:
                seen.add(k)
                out.append(exe)
        for item in startup.list_items():
            t = item.get("target")
            if t and os.path.isfile(t):
                k = paths.norm(t)
                if k not in seen:
                    seen.add(k)
                    out.append(t)
    except Exception:
        pass
    return out


def full_targets() -> list[str]:
    try:
        import psutil
        parts = psutil.disk_partitions(all=False)
    except Exception:
        parts = []
    if paths.IS_WINDOWS:
        roots = [p.mountpoint for p in parts if "cdrom" not in p.opts and p.fstype]
        return roots or ["C:\\"]
    return ["/"]


def _skip_mounts() -> set[str]:
    if paths.IS_WINDOWS:
        return set()
    out = set()
    try:
        import psutil
        for p in psutil.disk_partitions(all=True):
            if p.mountpoint != "/" and p.fstype in PSEUDO_FS:
                out.add(p.mountpoint)
    except Exception:
        pass
    return out


class Scanner:
    """Executa uma varredura em threads. Callbacks são chamados das threads de trabalho."""

    def __init__(self, engine: Engine, kind: str, targets: list[str], on_threat=None, on_progress=None,
                 cache: ScanCache | None = None, max_depth: int | None = None, low_priority: bool = False):
        self.engine = engine
        self.low_priority = low_priority
        self.settings = engine.settings
        self.kind = kind
        self.targets = targets
        self.on_threat = on_threat
        self.on_progress = on_progress
        self.cache = cache if (cache and self.settings.use_cache) else None
        self.max_depth = max_depth if max_depth is not None else (6 if kind == QUICK else 10_000)
        self.stats = ScanStats(kind=kind)
        self._stop = threading.Event()
        self._pause = threading.Event()
        self._pause.set()
        self._q: queue.Queue = queue.Queue(maxsize=4096)
        self._lock = threading.Lock()
        self._skip_dirs = set(_skip_mounts())
        if not paths.IS_WINDOWS:
            self._skip_dirs |= set(LINUX_SKIP)
        self._version = engine.version
        self._pool = None
        self._pool_n = 0
        self._big_sem = threading.BoundedSemaphore(1)

    def _make_pool(self, n: int):
        if not self.settings.scan_processes or (os.cpu_count() or 1) < 2 or len(self.targets) == 0:
            return None
        if self.kind == CUSTOM and len(self.targets) <= 3 and all(os.path.isfile(t) for t in self.targets):
            return None  # poucos arquivos: não compensa iniciar processos
        try:
            from concurrent.futures import ProcessPoolExecutor
            from dataclasses import asdict
            ctx = multiprocessing.get_context("spawn")
            return ProcessPoolExecutor(max_workers=n, mp_context=ctx, initializer=_child_init,
                                       initargs=(asdict(self.settings), self.low_priority))
        except Exception:
            return None

    def _scan_in_pool(self, path: str) -> ScanResult:
        """Analisa em um processo separado. Se o processo morrer (arquivo que derruba o analisador) ou
        travar, o grupo de processos é recriado — a análise NUNCA é refeita no processo principal,
        que é o da interface."""
        from concurrent.futures import TimeoutError as FutureTimeout
        from concurrent.futures.process import BrokenProcessPool
        pool = self._pool
        if pool is not None:
            try:
                return pool.submit(_child_scan, path).result(timeout=300)
            except BrokenProcessPool:
                # o grupo caiu por causa de ALGUM arquivo em análise — não necessariamente este.
                # Reanalisa este sozinho num processo próprio: só o culpado de verdade é ignorado.
                self._replace_pool(pool)
            except FutureTimeout:
                self._replace_pool(pool)
                return ScanResult(path=path, skipped=True,
                                  error="Tempo de análise esgotado (arquivo gigantesco ou malformado)")
            except RuntimeError:  # grupo encerrado no meio (parada da varredura)
                pass
        if self._stop.is_set():
            return ScanResult(path=path, skipped=True, error="Varredura interrompida")
        return self._scan_isolated(path)

    def _scan_isolated(self, path: str) -> ScanResult:
        from concurrent.futures import ProcessPoolExecutor
        from concurrent.futures import TimeoutError as FutureTimeout
        from concurrent.futures.process import BrokenProcessPool
        from dataclasses import asdict
        ex = ProcessPoolExecutor(max_workers=1, mp_context=multiprocessing.get_context("spawn"),
                                 initializer=_child_init, initargs=(asdict(self.settings), self.low_priority))
        try:
            return ex.submit(_child_scan, path).result(timeout=300)
        except BrokenProcessPool:
            history.log("análise", "Arquivo derrubou o processo de análise e foi ignorado (estrutura malformada)", path)
            return ScanResult(path=path, skipped=True,
                              error="O arquivo derrubou o processo de análise (estrutura malformada)")
        except FutureTimeout:
            return ScanResult(path=path, skipped=True, error="Tempo de análise esgotado (arquivo gigantesco ou malformado)")
        finally:
            procs = list(getattr(ex, "_processes", {}).values() or [])
            ex.shutdown(wait=False, cancel_futures=True)
            for p in procs:
                try:
                    p.kill()
                except Exception:
                    pass

    def _replace_pool(self, broken) -> None:
        with self._lock:
            if self._pool is not broken or self._stop.is_set():
                return
            try:
                broken.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
            for p in list(getattr(broken, "_processes", {}).values() or []):
                try:
                    p.kill()  # processo travado continuaria consumindo CPU/memória
                except Exception:
                    pass
            self._pool = self._make_pool(self._pool_n)

    # ------------------------------------------------------------------ controle
    def stop(self) -> None:
        self._stop.set()
        self._pause.set()

    def pause(self) -> None:
        self._pause.clear()

    def resume(self) -> None:
        self._pause.set()

    @property
    def paused(self) -> bool:
        return not self._pause.is_set()

    # ------------------------------------------------------------------ execução
    def run(self) -> ScanStats:
        history.log("scan", f"{KIND_NAMES.get(self.kind, 'Scan')} iniciado", "; ".join(self.targets[:5]))
        n = self.settings.scan_threads or min(8, max(2, (os.cpu_count() or 2)))
        if self.low_priority:
            n = max(1, n // 2)  # segundo plano: metade dos núcleos
        self._pool_n = n
        self._pool = self._make_pool(n)
        # com processos, mais threads mantêm todos os núcleos ocupados enquanto outras esperam E/S
        workers = [threading.Thread(target=self._worker, daemon=True, name=f"scan-{i}")
                   for i in range(n * 2 if self._pool else n)]
        for w in workers:
            w.start()
        try:
            self._walk()
        finally:
            self.stats.walking_done = True
            for _ in workers:
                self._q.put(None)
            for w in workers:
                w.join()
            if self._pool is not None:
                self._pool.shutdown(wait=False, cancel_futures=True)
                self._pool = None
            if self.cache:
                self.cache.flush()
            self.stats.finished = time.time()
            self.stats.cancelled = self._stop.is_set()
        s = self.stats
        msg = (f"{KIND_NAMES.get(self.kind, 'Scan')} {'cancelado' if s.cancelled else 'concluído'}: "
               f"{s.files} arquivos, {len(s.threats)} ameaça(s), {s.elapsed:.0f}s")
        history.log("scan", msg)
        st = config.get()
        st.last_scan = time.strftime("%Y-%m-%d %H:%M")
        st.last_scan_type = self.kind
        if self.kind == FULL and not s.cancelled:
            st.last_full_scan = st.last_scan
        try:
            config.save()
        except OSError:
            pass
        return s

    def _emit_progress(self) -> None:
        if self.on_progress:
            try:
                self.on_progress(self.stats)
            except Exception:
                pass

    def _put(self, path: str) -> bool:
        while not self._stop.is_set():
            try:
                self._q.put(path, timeout=0.2)
                self.stats.discovered += 1
                return True
            except queue.Full:
                continue
        return False

    def _walk(self) -> None:
        excl = self.engine.exclusions
        for t in self.targets:
            if self._stop.is_set():
                return
            try:
                st = os.stat(t, follow_symlinks=False)
            except OSError:
                continue
            if excl.is_excluded(t):
                continue
            if stat.S_ISREG(st.st_mode):
                self._put(t)
                continue
            if not stat.S_ISDIR(st.st_mode):
                continue
            stack = [(t, 0)]
            while stack and not self._stop.is_set():
                d, depth = stack.pop()
                self._pause.wait()
                try:
                    it = os.scandir(d)
                except OSError:
                    continue
                with it:
                    for e in it:
                        if self._stop.is_set():
                            return
                        try:
                            if e.is_symlink():
                                continue
                            p = e.path
                            if e.is_dir(follow_symlinks=False):
                                if depth + 1 <= self.max_depth and p not in self._skip_dirs \
                                        and not excl.is_excluded(p):
                                    stack.append((p, depth + 1))
                            elif e.is_file(follow_symlinks=False):
                                if not excl.is_excluded(p):
                                    self._put(p)
                        except OSError:
                            continue

    def _worker(self) -> None:
        last_emit = 0.0
        while True:
            item = self._q.get()
            if item is None:
                return
            if self._stop.is_set():
                continue
            self._pause.wait()
            self.stats.current = item
            res = self.scan_one(item)
            with self._lock:
                self.stats.files += 1
                self.stats.bytes += res.size
                if res.from_cache:
                    self.stats.from_cache += 1
                elif res.skipped:
                    self.stats.skipped += 1
                if res.is_threat:
                    self.stats.threats.append(res)
            if res.is_threat:
                history.log("detecção", f"{res.threat_name} ({res.verdict}, {res.score} pts)", res.path)
                if self.on_threat:
                    try:
                        self.on_threat(res)
                    except Exception:
                        pass
            now = time.time()
            if now - last_emit > 0.15:
                last_emit = now
                self._emit_progress()

    def scan_one(self, path: str) -> ScanResult:
        try:
            st = os.stat(path)
        except OSError:
            st = None
        if self.cache and st is not None and self.cache.is_clean(path, st.st_size, st.st_mtime_ns, self._version):
            return ScanResult(path=path, size=st.st_size, from_cache=True)
        big = st is not None and st.st_size > BIG_FILE
        if big:
            self._big_sem.acquire()  # arquivos grandes um de cada vez: limita o pico de memória
        try:
            if self._pool is not None:
                res = self._scan_in_pool(path)
            else:
                res = self.engine.scan_file(path).result
        except MemoryError:
            res = ScanResult(path=path, skipped=True, error="Memória insuficiente")
        except Exception as e:  # nunca derrubar a varredura por um arquivo problemático
            res = ScanResult(path=path, skipped=True, error=f"Erro interno: {e}")
        finally:
            if big:
                self._big_sem.release()
        if self.cache and st is not None and res.verdict == CLEAN and not res.skipped:
            self.cache.mark_clean(path, st.st_size, st.st_mtime_ns, self._version)
        return res
