"""Processos em execução."""
from __future__ import annotations

import os

import psutil

from .. import paths


def list_processes() -> list[dict]:
    out = []
    me = os.getpid()
    for p in psutil.process_iter(["pid", "name", "exe", "username", "memory_info", "cmdline", "create_time"]):
        try:
            i = p.info
            out.append({
                "pid": i["pid"], "name": i["name"] or "", "exe": i["exe"] or "",
                "user": i["username"] or "", "mem": (i["memory_info"].rss if i["memory_info"] else 0),
                "cmdline": " ".join(i["cmdline"] or [])[:500], "self": i["pid"] == me,
                "created": i["create_time"] or 0,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return out


def running_executables() -> list[str]:
    excl = paths.Exclusions()
    seen = set()
    out = []
    for p in psutil.process_iter(["exe"]):
        try:
            exe = p.info["exe"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if exe and exe not in seen and os.path.isfile(exe) and not excl.is_excluded(exe):
            seen.add(exe)
            out.append(exe)
    return out


def kill(pid: int) -> None:
    if pid == os.getpid():
        raise PermissionError("O antivírus não pode encerrar a si mesmo.")
    p = psutil.Process(pid)
    p.kill()
    p.wait(timeout=5)


def suspend(pid: int) -> None:
    if pid == os.getpid():
        raise PermissionError("O antivírus não pode suspender a si mesmo.")
    psutil.Process(pid).suspend()


def resume(pid: int) -> None:
    psutil.Process(pid).resume()


def processes_using(path: str) -> list[int]:
    """PIDs cujo executável é o arquivo informado."""
    target = paths.norm(path)
    pids = []
    for p in psutil.process_iter(["pid", "exe"]):
        try:
            if p.info["exe"] and paths.norm(p.info["exe"]) == target and p.info["pid"] != os.getpid():
                pids.append(p.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return pids
