"""Integração com o firewall do sistema.

Mecanismos suportados (detectados automaticamente, na ordem de preferência):

- Windows: Windows Firewall (netsh advfirewall) — regras permanentes.
- Linux, firewalls de código aberto:
    * ufw (Uncomplicated Firewall) quando ativo — regras permanentes;
    * firewalld quando em execução — regras permanentes (policies);
    * nftables / iptables — regras em memória, reaplicadas pelo antivírus a cada inicialização;
    * OpenSnitch (firewall de aplicativos) — usado para bloquear um programa específico.

Os bloqueios ficam registrados em JSON na pasta de dados para listar, desfazer e reaplicar.
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

from . import history, paths

_TABLE = "exeav"
_RULE_PREFIX = "EXE Antivirus - bloqueio "
_APP_PREFIX = "EXE Antivirus - app "
_FWD_POLICY_OUT = "exeav-saida"
_FWD_POLICY_IN = "exeav-entrada"
OPENSNITCH_RULES = Path("/etc/opensnitchd/rules")
PERSISTENT = {"windows", "ufw", "firewalld"}
NAMES = {"windows": "Windows Firewall", "ufw": "ufw", "firewalld": "firewalld", "nft": "nftables",
         "iptables": "iptables", "opensnitch": "OpenSnitch"}
_lock = threading.RLock()


def _run(cmd: list[str], check: bool = True, timeout: int = 30) -> subprocess.CompletedProcess:
    kw = {"creationflags": 0x08000000} if paths.IS_WINDOWS else {}
    env = None
    if not paths.IS_WINDOWS:
        # ferramentas do sistema escritas em Python (ufw, firewall-cmd) não podem herdar o Python do antivírus
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV")}
        env["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin:" + env.get("PATH", "")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, **kw)
    if check and r.returncode != 0:
        raise OSError((r.stderr or r.stdout or "falha").strip()[:300])
    return r


def _which(name: str) -> str | None:
    return shutil.which(name) or next((p for p in (f"/usr/sbin/{name}", f"/sbin/{name}", f"/usr/bin/{name}")
                                       if os.path.isfile(p)), None)


def _valid_ip(ip: str) -> str:
    addr = ipaddress.ip_address(ip.strip())
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        raise ValueError(f"Endereço {ip} não pode ser bloqueado.")
    return str(addr)


# --------------------------------------------------------------------------- detecção
def _ufw_active() -> bool:
    if not _which("ufw"):
        return False
    try:
        conf = Path("/etc/ufw/ufw.conf").read_text("utf-8", "replace")
        if "ENABLED=yes" not in conf.replace(" ", ""):
            return False
    except OSError:
        return False
    try:
        return "Status: active" in _run(["ufw", "status"], check=False, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return False


def _firewalld_running() -> bool:
    if not _which("firewall-cmd") or not os.path.exists("/run/firewalld"):
        return False
    try:
        return _run(["firewall-cmd", "--state"], check=False, timeout=10).stdout.strip() == "running"
    except (OSError, subprocess.SubprocessError):
        return False


def opensnitch_available() -> bool:
    if paths.IS_WINDOWS or not _which("opensnitchd"):
        return False
    return OPENSNITCH_RULES.is_dir() or Path("/etc/opensnitchd").is_dir()


_backend_cache: tuple[float, str | None] | None = None


def backend(refresh: bool = False) -> str | None:
    """Mecanismo de firewall usado para bloquear IPs ('windows', 'ufw', 'firewalld', 'nft', 'iptables') ou None."""
    global _backend_cache
    import time
    if not refresh and _backend_cache and time.time() - _backend_cache[0] < 30:
        return _backend_cache[1]
    if paths.IS_WINDOWS:
        kind = "windows" if shutil.which("netsh") else None
    elif _ufw_active():
        kind = "ufw"
    elif _firewalld_running():
        kind = "firewalld"
    elif _which("nft"):
        kind = "nft"
    elif _which("iptables"):
        kind = "iptables"
    else:
        kind = None
    _backend_cache = (time.time(), kind)
    return kind


def detect() -> list[dict]:
    """Firewalls encontrados no sistema, para exibir na interface."""
    if paths.IS_WINDOWS:
        return [{"id": "windows", "name": NAMES["windows"], "installed": bool(shutil.which("netsh")),
                 "active": bool(shutil.which("netsh")), "open_source": False,
                 "use": "bloqueio de IPs e de programas"}]
    cur = backend(refresh=True)
    out = []
    for k, use in (("ufw", "bloqueio de IPs (regras permanentes)"), ("firewalld", "bloqueio de IPs (regras permanentes)"),
                   ("nft", "bloqueio de IPs"), ("iptables", "bloqueio de IPs"),
                   ("opensnitch", "bloqueio de programas específicos")):
        binary = {"nft": "nft", "opensnitch": "opensnitchd", "firewalld": "firewall-cmd"}.get(k, k)
        installed = bool(_which(binary))
        if k == "ufw":
            active = _ufw_active()
        elif k == "firewalld":
            active = _firewalld_running()
        elif k == "opensnitch":
            active = installed and _service_active("opensnitch")
        else:
            active = installed
        out.append({"id": k, "name": NAMES[k], "installed": installed, "active": active, "open_source": True,
                    "use": use, "in_use": k == cur or (k == "opensnitch" and opensnitch_available())})
    return out


def _service_active(name: str) -> bool:
    if not _which("systemctl"):
        return False
    try:
        return _run(["systemctl", "is-active", name], check=False, timeout=5).stdout.strip() == "active"
    except (OSError, subprocess.SubprocessError):
        return False


def is_admin() -> bool:
    if paths.IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


# --------------------------------------------------------------------------- armazenamento
def _store(name: str) -> Path:
    return paths.data_dir() / name


def _load(name: str) -> dict:
    try:
        data = json.loads(_store(name).read_text("utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_to(name: str, data: dict) -> None:
    tmp = _store(name).with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), "utf-8")
    tmp.replace(_store(name))


def blocked() -> dict[str, dict]:
    return _load("firewall_blocks.json")


def blocked_apps() -> dict[str, dict]:
    return _load("firewall_apps.json")


def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- IPs: mecanismos
def _nft_ensure() -> None:
    _run(["nft", "add", "table", "inet", _TABLE])
    _run(["nft", "add", "chain", "inet", _TABLE, "saida",
          "{ type filter hook output priority 0 ; policy accept ; }"])
    _run(["nft", "add", "chain", "inet", _TABLE, "entrada",
          "{ type filter hook input priority 0 ; policy accept ; }"])


def _fwd_ensure() -> None:
    """Cria (uma vez) as policies do firewalld usadas pelo antivírus: tráfego do computador → qualquer zona
    e de qualquer zona → computador."""
    r = _run(["firewall-cmd", "--permanent", "--get-policies"], check=False)
    have = set(r.stdout.split())
    for name, ingress, egress in ((_FWD_POLICY_OUT, "HOST", "ANY"), (_FWD_POLICY_IN, "ANY", "HOST")):
        if name in have:
            continue
        _run(["firewall-cmd", "--permanent", "--new-policy", name])
        _run(["firewall-cmd", "--permanent", "--policy", name, "--add-ingress-zone", ingress])
        _run(["firewall-cmd", "--permanent", "--policy", name, "--add-egress-zone", egress])
        _run(["firewall-cmd", "--permanent", "--policy", name, "--set-priority", "-100"])


def _fwd_rules(ip: str) -> list[tuple[str, str]]:
    fam = "ipv6" if ":" in ip else "ipv4"
    return [(_FWD_POLICY_OUT, f'rule family="{fam}" destination address="{ip}" reject'),
            (_FWD_POLICY_IN, f'rule family="{fam}" source address="{ip}" drop')]


def _apply(ip: str, kind: str | None = None) -> None:
    kind = kind or backend()
    fam = "ip6" if ":" in ip else "ip"
    if kind == "windows":
        for direction in ("out", "in"):
            _run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={_RULE_PREFIX}{ip}",
                  f"dir={direction}", "action=block", f"remoteip={ip}", "enable=yes"])
    elif kind == "ufw":
        _run(["ufw", "prepend", "reject", "out", "to", ip, "comment", "EXE Antivirus"])
        _run(["ufw", "prepend", "deny", "from", ip, "comment", "EXE Antivirus"])
    elif kind == "firewalld":
        _fwd_ensure()
        for pol, rule in _fwd_rules(ip):
            r = _run(["firewall-cmd", "--permanent", "--policy", pol, "--add-rich-rule", rule], check=False)
            if r.returncode != 0 and "ALREADY_ENABLED" not in (r.stderr + r.stdout):
                raise OSError((r.stderr or r.stdout).strip()[:300])
        _run(["firewall-cmd", "--reload"])
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


def _remove(ip: str, kind: str | None = None) -> None:
    kind = kind or backend()
    fam = "ip6" if ":" in ip else "ip"
    if kind == "windows":
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={_RULE_PREFIX}{ip}"], check=False)
    elif kind == "ufw":
        _run(["ufw", "delete", "reject", "out", "to", ip], check=False)
        _run(["ufw", "delete", "deny", "from", ip], check=False)
    elif kind == "firewalld":
        for pol, rule in _fwd_rules(ip):
            _run(["firewall-cmd", "--permanent", "--policy", pol, "--remove-rich-rule", rule], check=False)
        _run(["firewall-cmd", "--reload"], check=False)
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


# --------------------------------------------------------------------------- IPs: API
def _apply_best(ip: str) -> str:
    """Aplica o bloqueio no firewall em uso; retorna o mecanismo usado."""
    kind = backend()
    try:
        _apply(ip, kind)
    except OSError as e:
        if kind != "ufw" or ":" not in ip:
            raise
        # ufw com IPv6 desligado (IPV6=no): o endereço IPv6 é bloqueado direto no nftables/iptables
        kind = "nft" if _which("nft") else "iptables"
        if not _which(kind):
            raise e
        _apply(ip, kind)
    return kind


def block(ip: str, reason: str, process: str = "") -> bool:
    """Bloqueia o IP (entrada e saída). Retorna False se já estava bloqueado."""
    ip = _valid_ip(ip)
    with _lock:
        data = blocked()
        if ip in data:
            return False
        kind = _apply_best(ip)
        data[ip] = {"reason": reason, "process": process, "backend": kind, "date": _now()}
        _save_to("firewall_blocks.json", data)
    history.log("firewall", f"IP {ip} bloqueado no firewall ({NAMES.get(kind, kind)}: {reason})", process)
    return True


def unblock(ip: str) -> None:
    ip = _valid_ip(ip)
    with _lock:
        data = blocked()
        kind = (data.get(ip) or {}).get("backend") or backend()
        _remove(ip, kind)
        if kind != backend():
            _remove(ip)
        data.pop(ip, None)
        _save_to("firewall_blocks.json", data)
    history.log("firewall", f"IP {ip} desbloqueado")


def reapply() -> int:
    """Garante que os bloqueios registrados estão ativos (regras do nftables/iptables somem ao reiniciar o
    computador; se o firewall em uso mudou, por exemplo o ufw foi ativado, os bloqueios migram para ele).
    Retorna quantos bloqueios foram (re)aplicados."""
    n = 0
    cur = backend(refresh=True)
    if cur is None:
        return 0
    with _lock:
        data = blocked()
        changed = False
        for ip, d in list(data.items()):
            old = d.get("backend")
            if old in PERSISTENT and old == cur:
                continue
            try:
                if old and old not in PERSISTENT:
                    _remove(ip, old)          # evita regra duplicada se ainda existir
                try:
                    used = _apply_best(ip)
                except (OSError, subprocess.SubprocessError):
                    if not old or old in PERSISTENT or not _which(old):
                        raise
                    _apply(ip, old)
                    used = old
                if used != old:
                    d["backend"] = used
                    changed = True
                n += 1
            except (OSError, ValueError, subprocess.SubprocessError):
                continue
        if changed:
            _save_to("firewall_blocks.json", data)
        for path, d in list(blocked_apps().items()):
            try:
                if d.get("backend") in ("windows", "opensnitch") and _app_rule_present(path, d["backend"]):
                    continue
                _apply_app(path, d.get("backend") or app_backend())
                n += 1
            except (OSError, ValueError, subprocess.SubprocessError, KeyError):
                continue
    return n


# --------------------------------------------------------------------------- programas
def app_backend() -> str | None:
    """Mecanismo capaz de bloquear a rede de um programa específico."""
    if paths.IS_WINDOWS:
        return "windows" if shutil.which("netsh") else None
    return "opensnitch" if opensnitch_available() else None


def _app_id(path: str) -> str:
    return hashlib.sha1(paths.norm(path).encode("utf-8", "replace")).hexdigest()[:16]


def opensnitch_rule(path: str) -> dict:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    return {"created": now, "updated": now, "name": f"exeav-bloqueio-{_app_id(path)}",
            "description": f"EXE Antivirus: bloqueio de rede de {path}", "enabled": True, "precedence": True,
            "nolog": False, "action": "deny", "duration": "always",
            "operator": {"type": "simple", "operand": "process.path", "sensitive": False, "data": path, "list": []}}


def _opensnitch_file(path: str) -> Path:
    return OPENSNITCH_RULES / f"exeav-bloqueio-{_app_id(path)}.json"


def _app_rule_present(path: str, kind: str) -> bool:
    if kind == "opensnitch":
        return _opensnitch_file(path).exists()
    if kind == "windows":
        r = _run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={_APP_PREFIX}{_app_id(path)}"],
                 check=False)
        return r.returncode == 0
    return False


def _apply_app(path: str, kind: str | None) -> None:
    if kind == "windows":
        for direction in ("out", "in"):
            _run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={_APP_PREFIX}{_app_id(path)}",
                  f"dir={direction}", "action=block", f"program={path}", "enable=yes"])
    elif kind == "opensnitch":
        OPENSNITCH_RULES.mkdir(parents=True, exist_ok=True)
        f = _opensnitch_file(path)
        tmp = f.with_suffix(".tmp")
        tmp.write_text(json.dumps(opensnitch_rule(path), indent=2), "utf-8")
        os.replace(tmp, f)   # o OpenSnitch recarrega as regras da pasta sozinho
    else:
        raise OSError("Bloquear a rede de um programa específico no Linux exige o OpenSnitch (firewall de "
                      "aplicativos de código aberto). Instale com: sudo apt install opensnitch")


def block_app(path: str, reason: str) -> bool:
    """Impede um programa de usar a rede. Retorna False se já estava bloqueado."""
    path = os.path.abspath(path)
    if paths.Exclusions().is_excluded(path):
        raise ValueError("O próprio antivírus não pode ser bloqueado.")
    from .quarantine import protection_reason
    why = protection_reason(path)
    if why:
        raise ValueError(f"Arquivo do sistema protegido: {why}")
    with _lock:
        data = blocked_apps()
        if path in data:
            return False
        kind = app_backend()
        _apply_app(path, kind)
        data[path] = {"reason": reason, "backend": kind, "date": _now()}
        _save_to("firewall_apps.json", data)
    history.log("firewall", f"Programa bloqueado na rede ({NAMES.get(kind, kind)}): {os.path.basename(path)} "
                            f"— {reason}", path)
    return True


def unblock_app(path: str) -> None:
    with _lock:
        data = blocked_apps()
        d = data.pop(path, None) or {}
        kind = d.get("backend") or app_backend()
        if kind == "windows":
            _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={_APP_PREFIX}{_app_id(path)}"],
                 check=False)
        elif kind == "opensnitch":
            try:
                _opensnitch_file(path).unlink()
            except FileNotFoundError:
                pass
        _save_to("firewall_apps.json", data)
    history.log("firewall", f"Programa liberado na rede: {os.path.basename(path)}", path)


def remove_all() -> None:
    """Remove todas as regras criadas pelo antivírus (usado na desinstalação)."""
    for ip in list(blocked()):
        try:
            unblock(ip)
        except Exception:
            pass
    for p in list(blocked_apps()):
        try:
            unblock_app(p)
        except Exception:
            pass
    kind = backend(refresh=True)
    try:
        if kind == "nft":
            _run(["nft", "delete", "table", "inet", _TABLE], check=False)
        elif kind == "firewalld":
            for pol in (_FWD_POLICY_OUT, _FWD_POLICY_IN):
                _run(["firewall-cmd", "--permanent", "--delete-policy", pol], check=False)
            _run(["firewall-cmd", "--reload"], check=False)
    except Exception:
        pass
