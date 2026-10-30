"""Conexões de rede ativas e verificação do arquivo hosts."""
from __future__ import annotations

import os
import re

import psutil

from .. import paths

SUSPICIOUS_PORTS = {
    4444: "Metasploit / shell reverso", 1337: "Backdoor comum", 31337: "Back Orifice / backdoor",
    6666: "IRC (botnets)", 6667: "IRC (botnets)", 6697: "IRC (botnets)", 3333: "Pool de mineração (stratum)",
    5555: "Pool de mineração / ADB", 7777: "Pool de mineração", 14444: "Pool de mineração (Monero)",
    14433: "Pool de mineração (Monero)", 45700: "Pool de mineração", 9050: "Tor", 9150: "Tor",
    5900: "VNC (acesso remoto)", 12345: "NetBus / backdoor", 54321: "Backdoor", 1604: "DarkComet RAT",
    5552: "njRAT", 2404: "Remcos RAT", 8808: "AsyncRAT", 6606: "AsyncRAT", 7707: "AsyncRAT",
}

PROTECTED_DOMAINS = ["google.com", "www.google.com", "microsoft.com", "update.microsoft.com",
                     "windowsupdate.com", "download.windowsupdate.com", "facebook.com", "www.facebook.com",
                     "paypal.com", "www.paypal.com", "bancodobrasil.com.br", "itau.com.br", "bradesco.com.br",
                     "caixa.gov.br", "nubank.com.br", "santander.com.br", "mercadopago.com.br", "gmail.com",
                     "accounts.google.com", "outlook.com", "live.com", "login.live.com", "apple.com",
                     "avast.com", "kaspersky.com", "eset.com", "malwarebytes.com", "virustotal.com",
                     "bitdefender.com", "mcafee.com", "symantec.com", "norton.com", "github.com"]


def connections() -> list[dict]:
    out = []
    names: dict[int, tuple[str, str]] = {}
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        conns = []
    for c in conns:
        if not c.raddr and c.status != psutil.CONN_LISTEN:
            continue
        pid = c.pid or 0
        if pid and pid not in names:
            try:
                p = psutil.Process(pid)
                names[pid] = (p.name(), p.exe() or "")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                names[pid] = ("?", "")
        lport = c.laddr.port if c.laddr else 0
        rport = c.raddr.port if c.raddr else 0
        flag = SUSPICIOUS_PORTS.get(rport) or (SUSPICIOUS_PORTS.get(lport) if c.status == psutil.CONN_LISTEN else None)
        out.append({
            "pid": pid, "process": names.get(pid, ("", ""))[0], "exe": names.get(pid, ("", ""))[1],
            "proto": "TCP" if c.type == 1 else "UDP", "local": f"{c.laddr.ip}:{lport}" if c.laddr else "",
            "remote": f"{c.raddr.ip}:{rport}" if c.raddr else "", "status": c.status, "flag": flag or "",
        })
    out.sort(key=lambda d: (not d["flag"], d["process"].lower()))
    return out


def hosts_path() -> str:
    if paths.IS_WINDOWS:
        return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
    return "/etc/hosts"


def check_hosts() -> list[dict]:
    """Encontra redirecionamentos de domínios importantes no arquivo hosts (pharming)."""
    issues = []
    try:
        with open(hosts_path(), "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return issues
    for i, line in enumerate(lines):
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        parts = s.split()
        if len(parts) < 2:
            continue
        ip, hosts = parts[0], [h.lower() for h in parts[1:]]
        for h in hosts:
            if any(h == d or h.endswith("." + d) for d in PROTECTED_DOMAINS):
                blocked = ip in ("0.0.0.0", "127.0.0.1", "::1", "::")
                issues.append({
                    "line": i + 1, "ip": ip, "host": h,
                    "problem": ("Site de segurança/serviço BLOQUEADO (malware costuma impedir acesso a antivírus)"
                                if blocked else f"Domínio REDIRECIONADO para {ip} (possível phishing/pharming)"),
                })
    return issues


def is_private(ip: str) -> bool:
    return bool(re.match(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fe80:|0\.0\.0\.0)", ip))
