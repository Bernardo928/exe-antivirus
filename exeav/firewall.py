"""Bloqueio de endereços IP no firewall do sistema (Windows Firewall, nftables ou iptables).

Os bloqueios ficam registrados em JSON na pasta de dados para poder listar, desfazer e reaplicar
(regras do nftables/iptables não sobrevivem a uma reinicialização).
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import shutil
import subprocess
import threading

from . import history, paths

_TABLE = "exeav"
_RULE_PREFIX = "EXE Antivirus - bloqueio "
_lock = threading.Lock()


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    kw = {"creationflags": 0x08000000} if paths.IS_WINDOWS else {}
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=20, **kw)
    if check and r.returncode != 0:
        raise OSError((r.stderr or r.stdout or "falha").strip()[:300])
    return r


def _valid_ip(ip: str) -> str:
    addr = ipaddress.ip_address(ip.strip())
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        raise ValueError(f"Endereço {ip} não pode ser bloqueado.")
    return str(addr)


def backend() -> str | None:
    """Mecanismo de firewall disponível ('windows', 'nft', 'iptables') ou None."""
    if paths.IS_WINDOWS:
        return "windows" if shutil.which("netsh") else None
    if shutil.which("nft"):
        return "nft"
    if shutil.which("iptables"):
        return "iptables"
    return None


def _store_path():
    return paths.data_dir() / "firewall_blocks.json"


def blocked() -> dict[str, dict]:
    try:
        data = json.loads(_store_path().read_text("utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data: dict) -> None:
    tmp = _store_path().with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), "utf-8")
    tmp.replace(_store_path())


# --------------------------------------------------------------------------- mecanismos
def _nft_ensure() -> None:
    _run(["nft", "add", "table", "inet", _TABLE])
    _run(["nft", "add", "chain", "inet", _TABLE, "saida",
          "{ type filter hook output priority 0 ; policy accept ; }"])
    _run(["nft", "add", "chain", "inet", _TABLE, "entrada",
          "{ type filter hook input priority 0 ; policy accept ; }"])


def _apply(ip: str) -> None:
    kind = backend()
    fam = "ip6" if ":" in ip else "ip"
    if kind == "windows":
        for direction in ("out", "in"):
            _run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={_RULE_PREFIX}{ip}",
                  f"dir={direction}", "action=block", f"remoteip={ip}", "enable=yes"])
    elif kind == "nft":
        _nft_ensure()
        # 'reject' na saída: o programa recebe erro imediato (em vez de esperar o tempo limite)
        _run(["nft", "add", "rule", "inet", _TABLE, "saida", fam, "daddr", ip, "reject"])
        _run(["nft", "add", "rule", "inet", _TABLE, "entrada", fam, "saddr", ip, "drop"])
    elif kind == "iptables":
        tool = "ip6tables" if fam == "ip6" else "iptables"
        _run([tool, "-I", "OUTPUT", "-d", ip, "-j", "REJECT"])
        _run([tool, "-I", "INPUT", "-s", ip, "-j", "DROP"])
    else:
        raise OSError("Nenhum firewall disponível neste sistema.")


def _remove(ip: str) -> None:
    kind = backend()
    fam = "ip6" if ":" in ip else "ip"
    if kind == "windows":
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={_RULE_PREFIX}{ip}"], check=False)
    elif kind == "nft":
        r = _run(["nft", "-a", "list", "table", "inet", _TABLE], check=False)
        chain = None
        for line in r.stdout.splitlines():
            s = line.strip()
            if s.startswith("chain "):
                chain = s.split()[1]
            elif f"{fam} {'daddr' if chain == 'saida' else 'saddr'} {ip} " in s + " " and "# handle" in s:
                handle = s.rsplit("# handle", 1)[1].strip()
                _run(["nft", "delete", "rule", "inet", _TABLE, chain, "handle", handle], check=False)
    elif kind == "iptables":
        tool = "ip6tables" if fam == "ip6" else "iptables"
        _run([tool, "-D", "OUTPUT", "-d", ip, "-j", "REJECT"], check=False)
        _run([tool, "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False)


# --------------------------------------------------------------------------- API
def block(ip: str, reason: str, process: str = "") -> bool:
    """Bloqueia o IP (entrada e saída). Retorna False se já estava bloqueado."""
    ip = _valid_ip(ip)
    with _lock:
        data = blocked()
        if ip in data:
            return False
        _apply(ip)
        data[ip] = {"reason": reason, "process": process, "backend": backend(),
                    "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        _save(data)
    history.log("firewall", f"IP {ip} bloqueado no firewall ({reason})", process)
    return True


def unblock(ip: str) -> None:
    ip = _valid_ip(ip)
    with _lock:
        _remove(ip)
        data = blocked()
        data.pop(ip, None)
        _save(data)
    history.log("firewall", f"IP {ip} desbloqueado")


def reapply() -> int:
    """Reaplica os bloqueios registrados (após reiniciar o computador). Retorna quantos foram aplicados."""
    n = 0
    for ip in list(blocked()):
        try:
            _remove(ip)
            _apply(ip)
            n += 1
        except (OSError, ValueError, subprocess.SubprocessError):
            continue
    return n
