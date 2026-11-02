"""Proteção Web: DNS da Mullvad (criptografado, com filtros) e bloqueio de sites.

Perfis do DNS público da Mullvad (gratuito, sem registro, só funciona criptografado — DoH/DoT):

    sem-filtro  dns.mullvad.net            194.242.2.2  só privacidade
    anuncios    adblock.dns.mullvad.net    194.242.2.3  anúncios e rastreadores
    base        base.dns.mullvad.net       194.242.2.4  anúncios, rastreadores e sites maliciosos (recomendado)
    estendido   extended.dns.mullvad.net   194.242.2.5  base + redes sociais
    familia     family.dns.mullvad.net     194.242.2.6  base + conteúdo adulto e apostas
    tudo        all.dns.mullvad.net        194.242.2.9  todos os filtros

Como o DNS é aplicado (o mais nativo possível):

- Windows 11: DNS-over-HTTPS do próprio Windows (Add-DnsClientDohServerAddress) em todas as placas de rede.
- Linux com systemd-resolved: DNS-over-TLS do resolved (arquivo em /etc/systemd/resolved.conf.d).
- Windows 10 e Linux sem resolved: o antivírus roda um servidor DNS local (127.0.0.1:53) que repassa as
  consultas para a Mullvad por HTTPS. Se o antivírus for fechado, o DNS original é restaurado na hora
  para a internet nunca ficar sem funcionar.

Sites bloqueados pelo usuário vão para o arquivo hosts (vale com qualquer DNS) e, no modo servidor local,
também bloqueiam todos os subdomínios.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import socket
import socketserver
import ssl
import struct
import subprocess
import threading
import time
from pathlib import Path

from . import history, paths

PROFILES: dict[str, dict] = {
    "sem-filtro": {"host": "dns.mullvad.net", "ip4": "194.242.2.2", "ip6": "2a07:e340::2",
                   "title": "Sem filtro", "desc": "Só privacidade, não bloqueia nada."},
    "anuncios": {"host": "adblock.dns.mullvad.net", "ip4": "194.242.2.3", "ip6": "2a07:e340::3",
                 "title": "Anúncios", "desc": "Anúncios e rastreadores."},
    "base": {"host": "base.dns.mullvad.net", "ip4": "194.242.2.4", "ip6": "2a07:e340::4",
             "title": "Base (recomendado)", "desc": "Anúncios, rastreadores e malware."},
    "estendido": {"host": "extended.dns.mullvad.net", "ip4": "194.242.2.5", "ip6": "2a07:e340::5",
                  "title": "Estendido", "desc": "Base + redes sociais."},
    "familia": {"host": "family.dns.mullvad.net", "ip4": "194.242.2.6", "ip6": "2a07:e340::6",
                "title": "Família", "desc": "Base + adulto e apostas."},
    "tudo": {"host": "all.dns.mullvad.net", "ip4": "194.242.2.9", "ip6": "2a07:e340::9",
             "title": "Tudo", "desc": "Todos os filtros juntos."},
}
HOSTS_BEGIN = "# >>> EXE Antivirus - sites bloqueados >>>"
HOSTS_END = "# <<< EXE Antivirus - sites bloqueados <<<"
RESOLVED_CONF = Path("/etc/systemd/resolved.conf.d/90-exe-antivirus-mullvad.conf")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
_lock = threading.RLock()


def doh_url(profile: str) -> str:
    return f"https://{PROFILES[profile]['host']}/dns-query"


def _run(cmd: list[str], check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess:
    kw = {"creationflags": 0x08000000} if paths.IS_WINDOWS else {}
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)
    if check and r.returncode != 0:
        raise OSError((r.stderr or r.stdout or "falha").strip()[:400])
    return r


def _ps(script: str, check: bool = True) -> str:
    return _run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                 script], check=check).stdout


def hosts_path() -> Path:
    if paths.IS_WINDOWS:
        return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


# --------------------------------------------------------------------------- estado
def _state_file() -> Path:
    return paths.data_dir() / "dns_state.json"


def state() -> dict:
    try:
        d = json.loads(_state_file().read_text("utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(d: dict) -> None:
    tmp = _state_file().with_suffix(".tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=1), "utf-8")
    tmp.replace(_state_file())


# --------------------------------------------------------------------------- domínios
def normalize_domain(text: str) -> str:
    """'https://www.Exemplo.com/caminho' → 'exemplo.com'. Levanta ValueError se não for um domínio."""
    s = (text or "").strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].split("@")[-1]
    s = s.rsplit(":", 1)[0] if s.count(":") == 1 else s
    s = s.strip(".")
    if s.startswith("*."):
        s = s[2:]
    if s.startswith("www."):
        s = s[4:]
    try:
        s = s.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(f"Endereço inválido: {text}") from None
    if not _DOMAIN.match(s):
        raise ValueError(f"Endereço inválido: {text}")
    if s in ("localhost", "local") or s.endswith((".local", ".localhost")):
        raise ValueError("Endereços locais não podem ser bloqueados.")
    return s


def is_blocked_name(qname: str, blocked: set[str]) -> bool:
    """Domínio bloqueado ou subdomínio de um bloqueado."""
    q = qname.lower().rstrip(".")
    while q:
        if q in blocked:
            return True
        if "." not in q:
            return False
        q = q.split(".", 1)[1]
    return False


def render_hosts(original: str, sites: list[str]) -> str:
    """Conteúdo novo do arquivo hosts com a seção do antivírus atualizada (o resto fica intacto)."""
    text = original.replace("\r\n", "\n")
    text = re.sub(rf"\n?{re.escape(HOSTS_BEGIN)}.*?{re.escape(HOSTS_END)}\n?", "\n", text, flags=re.S)
    text = text.rstrip("\n") + "\n"
    if sites:
        lines = [HOSTS_BEGIN]
        for d in sorted(set(sites)):
            for name in (d, f"www.{d}"):
                lines.append(f"0.0.0.0 {name}")
                lines.append(f":: {name}")
        lines.append(HOSTS_END)
        text += "\n".join(lines) + "\n"
    if paths.IS_WINDOWS:
        text = text.replace("\n", "\r\n")
    return text


def apply_sites(sites: list[str]) -> None:
    """Grava os sites bloqueados no arquivo hosts (exige administrador)."""
    with _lock:
        hp = hosts_path()
        try:
            original = hp.read_bytes().decode("utf-8", "replace")
        except FileNotFoundError:
            original = ""
        new = render_hosts(original, sites)
        if new != original:
            backup = paths.sub_dir("backups") / "hosts.original"
            if not backup.exists():
                backup.write_text(original, "utf-8")
            hp.write_bytes(new.encode("utf-8"))
        flush_cache()
        if _proxy is not None:
            _proxy.blocked = set(sites)


def flush_cache() -> None:
    try:
        if paths.IS_WINDOWS:
            _run(["ipconfig", "/flushdns"], check=False, timeout=20)
        elif _which("resolvectl"):
            _run(["resolvectl", "flush-caches"], check=False, timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass


def _which(name: str) -> str | None:
    import shutil
    return shutil.which(name) or next((p for p in (f"/usr/bin/{name}", f"/bin/{name}") if os.path.isfile(p)), None)


# --------------------------------------------------------------------------- detecção do modo
def windows_has_doh() -> bool:
    try:
        return "True" in _ps("[bool](Get-Command Add-DnsClientDohServerAddress -ErrorAction SilentlyContinue)",
                             check=False)
    except (OSError, subprocess.SubprocessError):
        return False


def resolved_active() -> bool:
    if paths.IS_WINDOWS or not _which("systemctl") or not os.path.isdir("/run/systemd/resolve"):
        return False
    try:
        return _run(["systemctl", "is-active", "systemd-resolved"], check=False).stdout.strip() == "active"
    except (OSError, subprocess.SubprocessError):
        return False


def best_mode() -> str:
    if paths.IS_WINDOWS:
        return "windows-doh" if windows_has_doh() else "proxy"
    return "resolved" if resolved_active() else "proxy"


MODE_NAMES = {"windows-doh": "DNS-over-HTTPS do Windows", "resolved": "DNS-over-TLS do systemd-resolved",
              "proxy": "servidor DNS local do antivírus (DNS-over-HTTPS)"}


# --------------------------------------------------------------------------- Windows
_WIN_SNAPSHOT = r"""
Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
  $g = $_.InterfaceGuid
  $v4 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$g" -EA SilentlyContinue).NameServer
  $v6 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$g" -EA SilentlyContinue).NameServer
  [pscustomobject]@{ idx = $_.ifIndex; name = $_.Name; v4 = "$v4"; v6 = "$v6" }
} | ConvertTo-Json -Compress
"""


def _win_snapshot() -> list[dict]:
    out = _ps(_WIN_SNAPSHOT).strip()
    if not out:
        return []
    data = json.loads(out)
    return data if isinstance(data, list) else [data]


def _win_set_servers(servers: list[str], snapshot: list[dict]) -> None:
    lst = ",".join(f"'{s}'" for s in servers)
    for a in snapshot:
        _ps(f"Set-DnsClientServerAddress -InterfaceIndex {int(a['idx'])} -ServerAddresses @({lst})")


def _win_apply(profile: str, snapshot: list[dict]) -> None:
    p = PROFILES[profile]
    t = doh_url(profile)
    for ip in (p["ip4"], p["ip6"]):
        _ps(f"if (Get-DnsClientDohServerAddress -ServerAddress '{ip}' -EA SilentlyContinue) "
            f"{{ Set-DnsClientDohServerAddress -ServerAddress '{ip}' -DohTemplate '{t}' -AllowFallbackToUdp $false "
            f"-AutoUpgrade $true }} else {{ Add-DnsClientDohServerAddress -ServerAddress '{ip}' -DohTemplate '{t}' "
            f"-AllowFallbackToUdp $false -AutoUpgrade $true }}")
    _win_set_servers([p["ip4"], p["ip6"]], snapshot)


def _win_restore(snapshot: list[dict]) -> None:
    for a in snapshot:
        servers = [s for s in re.split(r"[,\s]+", f"{a.get('v4', '')} {a.get('v6', '')}") if s]
        try:
            if servers:
                lst = ",".join(f"'{s}'" for s in servers)
                _ps(f"Set-DnsClientServerAddress -InterfaceIndex {int(a['idx'])} -ServerAddresses @({lst})")
            else:   # DNS vinha do roteador (DHCP)
                _ps(f"Set-DnsClientServerAddress -InterfaceIndex {int(a['idx'])} -ResetServerAddresses")
        except OSError:
            continue


# --------------------------------------------------------------------------- Linux
def resolved_conf(profile: str) -> str:
    p = PROFILES[profile]
    return ("# Criado pelo EXE Antivirus: DNS da Mullvad criptografado (DNS-over-TLS)\n[Resolve]\n"
            f"DNS={p['ip4']}#{p['host']} {p['ip6']}#{p['host']}\nDNSOverTLS=yes\nDomains=~.\nFallbackDNS=\n")


def _resolved_apply(profile: str) -> None:
    RESOLVED_CONF.parent.mkdir(parents=True, exist_ok=True)
    RESOLVED_CONF.write_text(resolved_conf(profile), "utf-8")
    _run(["systemctl", "restart", "systemd-resolved"])


def _resolved_restore() -> None:
    try:
        RESOLVED_CONF.unlink()
    except FileNotFoundError:
        pass
    _run(["systemctl", "restart", "systemd-resolved"], check=False)


def _resolv_conf_point_local() -> str:
    """Aponta /etc/resolv.conf para o servidor local; retorna o conteúdo original."""
    rc = Path("/etc/resolv.conf")
    if rc.is_symlink():
        original = "@link:" + os.readlink(rc)     # ex.: NetworkManager ou resolvconf gerenciam o arquivo
        rc.unlink()
    else:
        try:
            original = rc.read_text("utf-8")
        except OSError:
            original = ""
    rc.write_text("# EXE Antivirus: DNS da Mullvad via servidor local\nnameserver 127.0.0.1\noptions edns0 trust-ad\n",
                  "utf-8")
    return original


def _restore_resolv(prev: str) -> None:
    rc = Path("/etc/resolv.conf")
    if prev.startswith("@link:"):
        if rc.exists() or rc.is_symlink():
            rc.unlink()
        os.symlink(prev[6:], rc)
    else:
        if rc.is_symlink():
            rc.unlink()
        rc.write_text(prev, "utf-8")


# --------------------------------------------------------------------------- servidor DNS local (DoH)
def _qname(packet: bytes) -> str:
    i, labels = 12, []
    while i < len(packet):
        n = packet[i]
        if n == 0:
            break
        labels.append(packet[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    return ".".join(labels)


def _intel_blocked(name: str) -> bool:
    try:
        from . import intel
        return intel.is_malicious_domain(name)
    except Exception:
        return False


def blocked_answer(query: bytes) -> bytes:
    """Resposta NXDOMAIN para um site bloqueado."""
    if len(query) < 12:
        return b""
    qid, flags = struct.unpack(">HH", query[:4])
    rd = flags & 0x0100
    end = 12
    while end < len(query) and query[end] != 0:
        end += 1 + query[end]
    end += 5   # zero final + QTYPE + QCLASS
    return struct.pack(">HHHHHH", qid, 0x8000 | 0x0400 | rd | 0x0080 | 0x0003, 1, 0, 0, 0) + query[12:end]


def servfail(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
    qid, flags = struct.unpack(">HH", query[:4])
    return struct.pack(">HHHHHH", qid, 0x8000 | (flags & 0x0100) | 0x0080 | 0x0002, 0, 0, 0, 0)


class DohProxy:
    """Servidor DNS local que repassa as consultas para a Mullvad por DNS-over-HTTPS."""

    def __init__(self, profile: str = "base", blocked: set[str] | None = None, listen: str = "127.0.0.1",
                 port: int = 53, upstream: tuple[str, str, int, bool] | None = None):
        p = PROFILES.get(profile, PROFILES["base"])
        # (endereço para conectar, nome do servidor para o certificado, porta, usar TLS)
        self.upstream = upstream or (p["ip4"], p["host"], 443, True)
        self.blocked = set(blocked or ())
        self.use_intel = True       # também bloqueia domínios maliciosos dos feeds de inteligência
        self.listen, self.port = listen, port
        self.queries = 0
        self.blocked_count = 0
        self.errors = 0
        self._local = threading.local()
        self._servers: list[socketserver.BaseServer] = []
        self._ctx = ssl.create_default_context()

    def _conn(self) -> http.client.HTTPConnection:
        c = getattr(self._local, "conn", None)
        if c is None:
            addr, host, port, use_tls = self.upstream
            if use_tls:
                ctx = self._ctx

                class _C(http.client.HTTPSConnection):
                    def connect(self_inner):
                        sock = socket.create_connection((addr, port), self_inner.timeout)
                        self_inner.sock = ctx.wrap_socket(sock, server_hostname=host)
                c = _C(host, port, timeout=3, context=ctx)
            else:
                c = http.client.HTTPConnection(addr, port, timeout=3)
            self._local.conn = c
        return c

    def resolve(self, query: bytes) -> bytes:
        self.queries += 1
        name = _qname(query)
        if is_blocked_name(name, self.blocked) or (self.use_intel and _intel_blocked(name)):
            self.blocked_count += 1
            return blocked_answer(query)
        addr, host, port, _tls = self.upstream
        for _attempt in range(2):
            reused = getattr(self._local, "conn", None) is not None
            try:
                c = self._conn()
                c.request("POST", "/dns-query", body=query,
                          headers={"Host": host, "Content-Type": "application/dns-message",
                                   "Accept": "application/dns-message"})
                r = c.getresponse()
                body = r.read()
                if r.status == 200 and len(body) >= 12:
                    return query[:2] + body[2:]
                raise OSError(f"HTTP {r.status}")
            except (OSError, http.client.HTTPException):
                try:
                    self._local.conn.close()
                except Exception:
                    pass
                self._local.conn = None
                if not reused:      # só tenta de novo quando a conexão reaproveitada tinha caído
                    break
        self.errors += 1
        return servfail(query)

    def start(self) -> None:
        proxy = self

        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                ans = proxy.resolve(data)
                if ans:
                    sock.sendto(ans, self.client_address)

        class TCP(socketserver.StreamRequestHandler):
            def handle(self):
                while True:
                    hdr = self.rfile.read(2)
                    if len(hdr) < 2:
                        return
                    q = self.rfile.read(struct.unpack(">H", hdr)[0])
                    ans = proxy.resolve(q)
                    self.wfile.write(struct.pack(">H", len(ans)) + ans)

        class U(socketserver.ThreadingUDPServer):
            allow_reuse_address = True
            daemon_threads = True

        class T(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
        self._servers = [U((self.listen, self.port), UDP), T((self.listen, self.port), TCP)]
        if self.port == 0:   # testes: TCP na mesma porta sorteada para o UDP
            self._servers[1].server_close()
            self._servers[1] = T((self.listen, self._servers[0].server_address[1]), TCP)
            self.port = self._servers[0].server_address[1]
        for s in self._servers:
            threading.Thread(target=s.serve_forever, daemon=True, name="dns-local").start()

    def stop(self) -> None:
        for s in self._servers:
            try:
                s.shutdown()
                s.server_close()
            except Exception:
                pass
        self._servers = []


_proxy: DohProxy | None = None


def proxy() -> DohProxy | None:
    return _proxy


# --------------------------------------------------------------------------- API
def current() -> dict:
    """{'profile', 'mode', 'active'} do DNS aplicado pelo antivírus."""
    st = state()
    active = bool(st.get("profile"))
    if st.get("mode") == "proxy":
        active = active and _proxy is not None
    return {"profile": st.get("profile", ""), "mode": st.get("mode", ""), "active": active}


def apply(profile: str, sites: list[str] | None = None) -> str:
    """Passa a usar o DNS da Mullvad com o perfil escolhido. Retorna o modo usado. Exige administrador."""
    global _proxy
    if profile not in PROFILES:
        raise ValueError("Perfil de DNS desconhecido.")
    with _lock:
        st = state()
        if st.get("profile"):
            revert(keep_state=False)
            st = state()
        mode = best_mode()
        new = {"profile": profile, "mode": mode, "date": time.strftime("%Y-%m-%d %H:%M:%S")}
        if mode == "windows-doh":
            snap = _win_snapshot()
            new["previous"] = snap
            _save_state(new)          # salvo antes de mexer: se algo falhar, ainda dá para desfazer
            _win_apply(profile, snap)
        elif mode == "resolved":
            _save_state(new)
            _resolved_apply(profile)
        else:
            _proxy = DohProxy(profile, set(sites or []))
            _proxy.start()            # falha aqui (sem permissão para a porta 53) não altera nada no sistema
            try:
                if paths.IS_WINDOWS:
                    snap = _win_snapshot()
                    new["previous"] = snap
                    _save_state(new)
                    _win_set_servers(["127.0.0.1", "::1"], snap)
                else:
                    _save_state(new)
                    new["previous_resolv"] = _resolv_conf_point_local()
                    _save_state(new)
            except Exception:
                _proxy.stop()
                _proxy = None
                raise
        flush_cache()
    history.log("proteção web", f"DNS da Mullvad ativado: {PROFILES[profile]['title']} ({MODE_NAMES[mode]})")
    return mode


def revert(keep_state: bool = False) -> None:
    """Volta ao DNS original do computador."""
    global _proxy
    with _lock:
        st = state()
        mode = st.get("mode")
        if mode == "windows-doh":
            _win_restore(st.get("previous") or [])
        elif mode == "resolved":
            _resolved_restore()
        elif mode == "proxy":
            if paths.IS_WINDOWS:
                _win_restore(st.get("previous") or [])
            elif st.get("previous_resolv") is not None:
                _restore_resolv(st["previous_resolv"])
            if _proxy is not None:
                _proxy.stop()
                _proxy = None
        if not keep_state:
            _save_state({})
        flush_cache()
    if mode and not keep_state:
        history.log("proteção web", "DNS original do computador restaurado")


def on_app_start(sites: list[str]) -> str:
    """Ao abrir o antivírus: o modo servidor local precisa do antivírus rodando. Retorna mensagem de erro ou ''."""
    global _proxy
    st = state()
    if st.get("mode") != "proxy" or not st.get("profile"):
        return ""
    try:
        if _proxy is None:
            _proxy = DohProxy(st["profile"], set(sites))
            _proxy.start()
        if paths.IS_WINDOWS:
            _win_set_servers(["127.0.0.1", "::1"], st.get("previous") or [])
        else:
            cur = Path("/etc/resolv.conf").read_text("utf-8") if Path("/etc/resolv.conf").exists() else ""
            if "127.0.0.1" not in cur:
                st["previous_resolv"] = _resolv_conf_point_local()
                _save_state(st)
        return ""
    except Exception as e:
        # sem o servidor local o computador ficaria sem internet: volta ao DNS original
        try:
            revert(keep_state=True)
        except Exception:
            pass
        return f"DNS da Mullvad pausado (precisa de administrador): {e}"


def on_app_exit() -> None:
    """Ao fechar o antivírus no modo servidor local: devolve o DNS original (o perfil continua salvo e é
    reativado na próxima abertura)."""
    if state().get("mode") == "proxy":
        try:
            revert(keep_state=True)
        except Exception:
            pass
