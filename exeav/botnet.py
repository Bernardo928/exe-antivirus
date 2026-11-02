"""Escudo anti-botnet: impede que o computador seja controlado remotamente e usado em ataques.

Uma botnet é uma rede de computadores infectados que recebem ordens de um servidor de comando
(C2) e são usados para ataques DDoS, envio de spam, mineração e para infectar outras máquinas.
O escudo observa o comportamento de REDE de cada processo e pontua sinais típicos de um "bot":

  * conexão com servidor de comando (C2) conhecido (lista do abuse.ch / importada);
  * varredura de outras máquinas em portas usadas para se espalhar (Telnet, SSH, SMB, RDP, ADB...);
  * tentativas de conexão em massa (varredura / DDoS) e inundação de um único alvo;
  * contato periódico e regular com o mesmo servidor ("beaconing");
  * portas de IRC, trojans de acesso remoto, Tor e pools de mineração;
  * porta de entrada (backdoor) aberta para a rede;
  * executável rodando de pasta temporária, apagado do disco enquanto roda, ou com nome de
    processo do sistema fora do lugar (ex.: "kworker" em /tmp);
  * veredito do motor de análise sobre o próprio executável.

Ações (configuráveis): encerrar o processo, isolar o executável na quarentena e bloquear no
firewall os IPs usados. Processos do sistema, programas íntegros/assinados, o próprio antivírus e
quem o iniciou nunca são encerrados — nesses casos o escudo apenas alerta.
"""
from __future__ import annotations

import ipaddress
import os
import statistics
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

import psutil

from . import firewall, history, paths
from .engine.models import MALICIOUS, SUSPICIOUS, ScanResult

WINDOW = 60.0           # segundos de histórico considerados
BOTNET_SCORE = 70       # a partir daqui: bot (ação automática)
SUSPICIOUS_SCORE = 40   # a partir daqui: alerta

WORM_PORTS = {23: "Telnet", 2323: "Telnet", 22: "SSH", 445: "SMB", 139: "NetBIOS", 3389: "RDP",
              5555: "ADB (Android)", 7547: "TR-069 (roteadores)", 37215: "roteadores Huawei",
              52869: "UPnP", 5900: "VNC", 1433: "MS-SQL", 3306: "MySQL", 6379: "Redis",
              2375: "API do Docker", 8291: "MikroTik", 81: "câmeras IP", 9527: "câmeras IP"}
C2_PORTS = {6667: "IRC", 6668: "IRC", 6669: "IRC", 6697: "IRC", 7000: "IRC", 1337: "backdoor",
            31337: "Back Orifice", 4444: "Metasploit", 12345: "NetBus", 54321: "backdoor",
            1604: "DarkComet", 5552: "njRAT", 2404: "Remcos", 8808: "AsyncRAT", 6606: "AsyncRAT",
            7707: "AsyncRAT", 9050: "Tor", 9150: "Tor", 9001: "Tor"}
MINING_PORTS = {3333, 3334, 4443, 5556, 7777, 8888, 9999, 14433, 14444, 45560, 45700}
BACKDOOR_LISTEN = {4444, 1337, 31337, 12345, 54321, 6666, 6667, 5552, 1604, 2404}
SYSTEM_NAMES = {"kworker", "kthreadd", "ksoftirqd", "kswapd0", "migration", "rcu_sched", "watchdog",
                "systemd", "systemd-journald", "systemd-logind", "sshd", "crond", "cron", "init", "dbus-daemon",
                "rsyslogd", "udevd", "svchost.exe", "csrss.exe", "lsass.exe", "services.exe", "winlogon.exe",
                "explorer.exe", "dllhost.exe", "smss.exe", "spoolsv.exe", "taskhostw.exe", "conhost.exe",
                "rundll32.exe", "wininit.exe", "dwm.exe"}
_LINUX_TEMP = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")
_LINUX_SYSTEM = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/")


_FINDING_GROUP = {"botnet.c2_known": "Inteligência de ameaças", "botnet.deleted_exe": "Processo",
                  "botnet.temp_exe": "Processo", "botnet.masquerade": "Processo", "botnet.exe_malicious": "Arquivo",
                  "botnet.exe_suspicious": "Arquivo", "botnet.trusted": "Confiança"}


@dataclass
class Finding:
    id: str
    name: str
    description: str
    weight: int
    evidence: list[str] = field(default_factory=list)


@dataclass
class ProcessReport:
    pid: int
    name: str
    exe: str
    cmdline: str
    score: int = 0
    verdict: str = "limpo"
    findings: list[Finding] = field(default_factory=list)
    remote_ips: list[str] = field(default_factory=list)
    trusted: bool = False
    protected: bool = False
    action: str = ""
    family: str = ""

    def reasons(self) -> list[str]:
        return [f"{f.name} ({f.weight:+d})" for f in sorted(self.findings, key=lambda f: -f.weight)]


def _is_public_or_lan(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return not (a.is_loopback or a.is_unspecified or a.is_multicast or a.is_link_local)


def _is_temp_path(exe: str) -> bool:
    n = os.path.normcase(exe)
    if paths.IS_WINDOWS:
        for v in ("TEMP", "TMP"):
            t = os.environ.get(v)
            if t and n.startswith(os.path.normcase(os.path.abspath(t)) + "\\"):
                return True
        return "\\appdata\\local\\temp\\" in n or "\\windows\\temp\\" in n or "\\$recycle.bin\\" in n
    return n.startswith(_LINUX_TEMP)


def _is_system_location(exe: str) -> bool:
    n = os.path.normcase(exe)
    if paths.IS_WINDOWS:
        root = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows")) + "\\"
        return n.startswith(root)
    return n.startswith(_LINUX_SYSTEM)


def _exe_deleted(pid: int, exe: str) -> bool:
    if not exe:
        return False
    if not paths.IS_WINDOWS:
        try:
            if os.readlink(f"/proc/{pid}/exe").endswith(" (deleted)"):
                return True
        except OSError:
            pass
    return not os.path.exists(exe)


def _parse_ip(line: str) -> str | None:
    """Extrai o IP de uma linha de lista (IPv4, IPv6, 'ip:porta', '[ipv6]:porta', CSV, comentários)."""
    tok = line.split("#", 1)[0].strip().split(",")[0].strip().strip('"').strip("'")
    if not tok:
        return None
    cands = [tok]
    if tok.startswith("[") and "]" in tok:
        cands.append(tok[1:tok.index("]")])
    elif tok.count(":") == 1:
        cands.append(tok.split(":")[0])
    for c in cands:
        try:
            return str(ipaddress.ip_address(c))
        except ValueError:
            continue
    return None


class C2Blocklist:
    """Lista de IPs de servidores de comando conhecidos (ex.: Feodo Tracker do abuse.ch)."""

    DEFAULT_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

    def __init__(self):
        self.path = paths.data_dir() / "c2_blocklist.txt"
        self.ips: set[str] = set()
        self.load()

    def load(self) -> None:
        ips = set()
        try:
            for line in self.path.read_text("utf-8", "replace").splitlines():
                ip = _parse_ip(line)
                if ip:
                    ips.add(ip)
        except OSError:
            pass
        self.ips = ips

    def add_text(self, text: str, source: str) -> int:
        before = len(self.ips)
        new = set(self.ips)
        for line in text.splitlines():
            ip = _parse_ip(line)
            if ip:
                new.add(ip)
        self.ips = new
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text("# servidores de comando (C2) — atualizado de " + source + "\n" + "\n".join(sorted(new)) + "\n",
                       "utf-8")
        tmp.replace(self.path)
        added = len(new) - before
        history.log("assinaturas", f"Lista de servidores C2: {added} novo(s) IP(s) de {source}")
        return added

    def update(self, url: str | None = None, timeout: int = 30) -> int:
        import urllib.request
        url = url or self.DEFAULT_URL
        req = urllib.request.Request(url, headers={"User-Agent": "EXE-Antivirus/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            text = r.read(16 * 1024 * 1024).decode("utf-8", "replace")
        return self.add_text(text, url.split("/")[2] if "//" in url else url)

    def import_file(self, path: str) -> int:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return self.add_text(f.read(), os.path.basename(path))


class BotnetShield:
    """callback(evento, dados): 'botnet' / 'suspeito' (ProcessReport), 'status' (str)."""

    def __init__(self, engine, quarantine, callback=None, interval: float = 2.0,
                 watch_pids: set[int] | None = None, dry_run: bool = False):
        self.engine = engine
        self.settings = engine.settings
        self.quarantine = quarantine
        self.callback = callback or (lambda *a: None)
        self.interval = interval
        self.watch_pids = watch_pids      # testes: limita o escudo a estes processos
        self.dry_run = dry_run            # só observa, nunca age
        self.c2 = C2Blocklist()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        # pid -> deque[(ts, ip, porta, status, porta_local)]
        self._conns: dict[int, deque] = defaultdict(lambda: deque(maxlen=20000))
        # (pid, ip, porta) -> deque[ts em que surgiu uma conexão NOVA (porta local nova)]
        self._new_conn_times: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=64))
        self._seen_local: dict[tuple, float] = {}
        self._listen: dict[int, set] = defaultdict(set)
        self._proc_cache: dict[int, tuple] = {}
        self._exe_verdicts: dict[tuple, str] = {}
        self._handled: dict[int, str] = {}
        self.reports: dict[int, ProcessReport] = {}
        self.connections_seen = 0
        self.blocked_count = 0
        self.processes_watched = 0

    # ------------------------------------------------------------------ ciclo de vida
    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop.is_set()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="anti-botnet")
        self._thread.start()
        history.log("anti-botnet", "Escudo anti-botnet ativado")
        self.callback("status", "on")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._thread = None
        history.log("anti-botnet", "Escudo anti-botnet desativado")
        self.callback("status", "off")

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.sample()
                for rep in self.evaluate():
                    self._act(rep)
            except Exception:
                pass
            self._stop.wait(self.interval)

    # ------------------------------------------------------------------ coleta
    def sample(self) -> None:
        now = time.time()
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            conns = []
            for p in psutil.process_iter(["pid"]):  # sem privilégio: coleta por processo
                try:
                    for c in p.net_connections(kind="inet"):
                        conns.append(psutil._common.sconn(c.fd, c.family, c.type, c.laddr, c.raddr,
                                                          c.status, p.info["pid"]))
                except (psutil.Error, OSError):
                    continue
        with self._lock:
            for c in conns:
                pid = c.pid or 0
                if not pid or (self.watch_pids is not None and pid not in self.watch_pids):
                    continue
                if c.status == psutil.CONN_LISTEN:
                    if c.laddr and _is_public_or_lan(c.laddr.ip) or (c.laddr and c.laddr.ip in ("0.0.0.0", "::")):
                        self._listen[pid].add(c.laddr.port)
                    continue
                if not c.raddr or not _is_public_or_lan(c.raddr.ip):
                    continue
                ip, port = c.raddr.ip, c.raddr.port
                lport = c.laddr.port if c.laddr else 0
                self._conns[pid].append((now, ip, port, c.status, lport))
                self.connections_seen += 1
                key = (pid, ip, port, lport)
                if key not in self._seen_local:
                    self._seen_local[key] = now
                    self._new_conn_times[(pid, ip, port)].append(now)
            # descarta o que saiu da janela / processos que terminaram
            for pid in list(self._conns):
                dq = self._conns[pid]
                while dq and now - dq[0][0] > WINDOW:
                    dq.popleft()
                if not dq and not psutil.pid_exists(pid):
                    del self._conns[pid]
                    self._listen.pop(pid, None)
            if len(self._seen_local) > 200_000:
                self._seen_local = {k: t for k, t in self._seen_local.items() if now - t < WINDOW * 5}

    # ------------------------------------------------------------------ análise
    def _proc(self, pid: int):
        try:
            p = psutil.Process(pid)
            key = (pid, p.create_time())
            cached = self._proc_cache.get(pid)
            if cached and cached[0] == key:
                return cached[1]
            info = {"name": p.name() or "", "exe": p.exe() or "", "cmdline": " ".join(p.cmdline() or [])[:500],
                    "cpu": 0.0, "proc": p}
            self._proc_cache[pid] = (key, info)
            return info
        except (psutil.Error, OSError):
            return None

    def evaluate(self) -> list[ProcessReport]:
        from .realtime import _self_and_ancestors
        protected_pids = _self_and_ancestors()
        with self._lock:
            pids = set(self._conns) | set(self._listen)
            snapshot = {pid: list(self._conns.get(pid, ())) for pid in pids}
            listens = {pid: set(self._listen.get(pid, ())) for pid in pids}
            beacons = {k: list(v) for k, v in self._new_conn_times.items() if k[0] in pids}
        self.processes_watched = len(pids)
        out = []
        for pid in pids:
            info = self._proc(pid)
            if info is None:
                continue
            rep = self._score(pid, info, snapshot[pid], listens[pid],
                              {k[1:]: v for k, v in beacons.items() if k[0] == pid})
            rep.protected = pid in protected_pids or pid <= 4
            self.reports[pid] = rep
            if rep.verdict != "limpo":
                out.append(rep)
        return out

    def _score(self, pid, info, conns, listens, beacons) -> ProcessReport:
        exe, name = info["exe"], info["name"]
        rep = ProcessReport(pid=pid, name=name, exe=exe, cmdline=info["cmdline"])
        F = rep.findings
        ips = {c[1] for c in conns}
        rep.remote_ips = sorted(ips)[:200]
        families = []

        # 1. servidor de comando conhecido
        c2_hits = sorted(ips & self._c2_ips())
        if c2_hits:
            F.append(Finding("botnet.c2_known", "Conexão com servidor de comando (C2) conhecido",
                             "O processo se comunica com um endereço catalogado como servidor de controle de "
                             "botnets.", 100, c2_hits[:10]))
            families.append("C2")
        # 2. propagação (worm)
        worm = defaultdict(set)
        for _t, ip, port, _st, _lp in conns:
            if port in WORM_PORTS:
                worm[port].add(ip)
        worm_ips = set().union(*worm.values()) if worm else set()
        if len(worm_ips) >= 8:
            ports = ", ".join(f"{p} ({WORM_PORTS[p]})" for p in sorted(worm, key=lambda p: -len(worm[p]))[:4])
            F.append(Finding("botnet.worm_scan", "Varredura para infectar outras máquinas",
                             f"Tenta acessar {len(worm_ips)} computadores diferentes em portas usadas por worms e "
                             "bots para se espalhar (senhas fracas de Telnet/SSH, falhas de SMB/RDP...).",
                             60 if len(worm_ips) >= 20 else 50, [ports] + sorted(worm_ips)[:8]))
            families.append("Worm")
        # 3. varredura / DDoS
        syn = {c[1] for c in conns if c[3] == psutil.CONN_SYN_SENT}
        if len(syn) >= 25:
            F.append(Finding("botnet.mass_connect", "Tentativas de conexão em massa",
                             f"Tentou se conectar a {len(syn)} endereços diferentes em pouco tempo (a maioria sem "
                             "resposta): comportamento de varredura de rede ou ataque DDoS.", 40,
                             sorted(syn)[:8]))
            families.append("Scanner")
        per_target = defaultdict(set)
        for _t, ip, port, _st, lport in conns:
            per_target[(ip, port)].add(lport)
        flood = [(k, len(v)) for k, v in per_target.items() if len(v) >= 150]
        if flood:
            (ip, port), n = max(flood, key=lambda x: x[1])
            F.append(Finding("botnet.flood", "Inundação de um único alvo (DDoS)",
                             f"Abriu {n} conexões para o mesmo destino em pouco tempo: típico de ataque de "
                             "negação de serviço comandado por uma botnet.", 45, [f"{ip}:{port} ({n} conexões)"]))
            families.append("DDoS")
        # 4. beaconing
        for (ip, port), times in beacons.items():
            ts = sorted(times)
            if len(ts) < 4:
                continue
            gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0.2]
            if len(gaps) >= 3:
                mean = statistics.mean(gaps)
                # tolerância: 25% do intervalo + erro de amostragem (o escudo só vê a rede a cada 'interval' s)
                if 1.5 <= mean <= 900 and statistics.pstdev(gaps) <= 0.25 * mean + 0.6 * self.interval:
                    irc = port in C2_PORTS  # reconexão periódica em porta de IRC/RAT: canal de comando típico
                    F.append(Finding("botnet.beacon", "Contato periódico com servidor (beaconing)",
                                     f"Conecta-se a {ip}:{port} em intervalos regulares de ~{mean:.0f}s — bots "
                                     "\"batem ponto\" no servidor de comando para receber ordens"
                                     + (f" (porta {port}, {C2_PORTS[port]})." if irc else "."), 50 if irc else 30,
                                     [f"{ip}:{port}", f"{len(ts)} conexões, intervalo {mean:.1f}s"]))
                    families.append("C2")
                    break
        # 5. portas suspeitas
        c2p = {f"{port} ({C2_PORTS[port]})" for _t, _ip, port, _s, _l in conns if port in C2_PORTS}
        if c2p:
            F.append(Finding("botnet.c2_port", "Porta de IRC / acesso remoto / Tor",
                             "Conecta-se a portas usadas por canais de comando de botnets (IRC), trojans de "
                             "acesso remoto ou pela rede Tor.", 25, sorted(c2p)[:6]))
        mining = {port for _t, _ip, port, _s, _l in conns if port in MINING_PORTS}
        if mining:
            try:
                cpu = info["proc"].cpu_percent(interval=0.2)
            except (psutil.Error, OSError):
                cpu = 0.0
            if cpu >= 50:
                F.append(Finding("botnet.miner", "Mineração de criptomoedas",
                                 f"Usa {cpu:.0f}% da CPU e se conecta a portas de pools de mineração.", 40,
                                 [str(p) for p in sorted(mining)]))
                families.append("Miner")
        # 6. porta de entrada aberta
        if listens:
            bad = sorted(listens & BACKDOOR_LISTEN)
            odd = _is_temp_path(exe) or _exe_deleted(pid, exe)
            if bad or odd:
                F.append(Finding("botnet.backdoor_listen", "Porta de entrada aberta para a rede (backdoor)",
                                 "Aguarda conexões vindas da rede" + (" em porta típica de backdoor" if bad else
                                 " a partir de um programa em pasta temporária") +
                                 ": permite que o computador seja controlado remotamente.",
                                 55 if (bad and odd) else 40 if bad else 35, [str(p) for p in sorted(listens)[:6]]))
                families.append("Backdoor")
        # 7. executável
        if exe:
            if _exe_deleted(pid, exe):
                F.append(Finding("botnet.deleted_exe", "Executável apagado enquanto roda",
                                 "O programa apagou o próprio arquivo depois de iniciar para não ser encontrado — "
                                 "técnica clássica de bots Linux (Mirai e derivados).", 40, [exe]))
            elif _is_temp_path(exe):
                F.append(Finding("botnet.temp_exe", "Executa de pasta temporária",
                                 "Programas legítimos raramente rodam de pastas temporárias; malware baixado "
                                 "costuma rodar dali.", 20, [exe]))
            base = os.path.basename(exe).lower()
            nm = name.lower()
            if (nm in SYSTEM_NAMES or nm.split("/")[0] in SYSTEM_NAMES or base in SYSTEM_NAMES) \
                    and not _is_system_location(exe):
                F.append(Finding("botnet.masquerade", "Disfarçado de processo do sistema",
                                 f"Usa o nome '{name}', de um processo do sistema, mas roda de outro lugar.", 35,
                                 [exe]))
            if os.path.isfile(exe) and not self.engine.exclusions.is_excluded(exe):
                try:
                    st = os.stat(exe)
                    key = (exe, st.st_size, st.st_mtime_ns)
                    v = self._exe_verdicts.get(key)
                    if v is None:
                        r = self.engine.scan_file(exe).result
                        v = r.verdict
                        self._exe_verdicts[key] = v
                    if v == MALICIOUS:
                        F.append(Finding("botnet.exe_malicious", "Executável malicioso",
                                         "O motor de análise condenou o próprio arquivo do programa.", 50, [exe]))
                    elif v == SUSPICIOUS:
                        F.append(Finding("botnet.exe_suspicious", "Executável suspeito",
                                         "O motor de análise considerou o arquivo do programa suspeito.", 20, [exe]))
                except OSError:
                    pass
        # 8. confiança (interpretadores não: executam qualquer script, inclusive bots em Python/PowerShell)
        from .realtime import _is_interpreter
        if exe and os.path.isfile(exe) and F and not _is_interpreter(exe):
            from .engine import trust
            from .quarantine import protection_reason
            ok, desc = trust.check(exe)
            if ok or protection_reason(exe):
                rep.trusted = True
                F.append(Finding("botnet.trusted", "Programa íntegro do sistema / assinado",
                                 desc or "Arquivo original do sistema.", -40, [exe]))
        rep.score = max(0, sum(f.weight for f in F))
        if rep.score >= BOTNET_SCORE:
            rep.verdict = MALICIOUS
        elif rep.score >= SUSPICIOUS_SCORE:
            rep.verdict = SUSPICIOUS
        rep.family = "Botnet." + (families[0] if families else "Generic")
        return rep

    # ------------------------------------------------------------------ ações
    def _act(self, rep: ProcessReport) -> None:
        if self._handled.get(rep.pid) == rep.verdict or (self._handled.get(rep.pid) == MALICIOUS):
            return
        self._handled[rep.pid] = rep.verdict
        from . import incidents
        proc_info = incidents.process_info(rep.pid) if not self.dry_run else {}
        if rep.verdict == SUSPICIOUS or self.dry_run:
            rep.action = "alerta" if not self.dry_run else "apenas observado"
            history.log("anti-botnet", f"Comportamento suspeito de bot: {rep.name} (PID {rep.pid}, {rep.score} pts)",
                        rep.exe)
            if not self.dry_run:
                self._report(rep, proc_info)
            self.callback("suspeito", rep)
            return
        actions = []
        can_act = not rep.protected and not rep.trusted
        from .system import processes
        if can_act and processes.critical_reason(rep.pid):
            can_act = False
        if can_act and self.settings.botnet_auto_kill:
            try:
                processes.kill(rep.pid)
                actions.append("processo encerrado")
            except Exception as e:
                actions.append(f"falha ao encerrar ({e})")
        target = self._file_to_isolate(rep)
        pre = incidents.collect(target) if target else {}
        if can_act and target and self.settings.auto_action == "quarantine":
            try:
                self.quarantine.isolate(ScanResult(path=target, verdict=MALICIOUS, score=rep.score,
                                                   threat_name=rep.family, file_type="", indicators=[]))
                actions.append(("script" if target != rep.exe else "executável") + " em quarentena")
            except Exception as e:
                actions.append(f"quarentena falhou ({str(e)[:60]})")
        if self.settings.botnet_firewall_block and (can_act or any(f.id == "botnet.c2_known" for f in rep.findings)):
            known = self._c2_ips()
            c2_ips = [ip for ip in rep.remote_ips if ip in known]
            targets = c2_ips or [ip for ip in rep.remote_ips if self._is_c2_candidate(rep, ip)]
            n = 0
            for ip in targets[:20]:
                try:
                    if firewall.block(ip, rep.family, rep.exe or rep.name):
                        n += 1
                except Exception:
                    break
            if n:
                actions.append(f"{n} IP(s) bloqueado(s) no firewall")
                self.blocked_count += n
        if not can_act:
            actions.append("apenas alerta (programa do sistema/assinado ou protegido)")
        rep.action = "; ".join(actions) or "alerta"
        history.log("bloqueio" if can_act else "anti-botnet",
                    f"BOTNET: {rep.family} — {rep.name} (PID {rep.pid}, {rep.score} pts): {rep.action}", rep.exe)
        self._report(rep, proc_info, pre, target or "")
        self.callback("botnet", rep)

    def _c2_ips(self) -> set[str]:
        """Lista própria de C2 + IPs de servidores de comando dos feeds de inteligência (Feodo/ThreatFox)."""
        from . import intel
        try:
            extra = intel.ips()
        except Exception:
            extra = set()
        return self.c2.ips | extra if extra else self.c2.ips

    def _report(self, rep: ProcessReport, proc_info: dict, pre: dict | None = None, target: str = "") -> None:
        from . import incidents
        incidents.report(None, "anti-botnet", pid=rep.pid, action=rep.action, pre=pre, process=proc_info, behavior={
            "title": f"Botnet: {rep.family}" if rep.verdict == MALICIOUS else "Comportamento de bot",
            "verdict": rep.verdict, "score": rep.score, "critical": rep.verdict == MALICIOUS and rep.score >= 100,
            "known": any(f.id == "botnet.c2_known" for f in rep.findings), "path": target or rep.exe,
            "key": f"{rep.exe}|{rep.family}",
            "indicators": [{"id": f.id, "name": f.name, "category": _FINDING_GROUP.get(f.id, "Rede"),
                            "weight": f.weight, "description": f.description, "evidence": f.evidence}
                           for f in rep.findings]})

    def _file_to_isolate(self, rep: ProcessReport) -> str | None:
        """Arquivo a isolar: o executável do bot ou, se for um interpretador, o script que ele executa."""
        from .realtime import _is_interpreter
        cand = None
        if rep.exe and _is_interpreter(rep.exe):
            for arg in rep.cmdline.split()[1:6]:
                if not arg.startswith("-") and os.path.isabs(arg) and os.path.isfile(arg):
                    cand = arg
                    break
        elif rep.exe and os.path.isfile(rep.exe):
            cand = rep.exe
        if cand and self.engine.exclusions.is_excluded(cand):
            return None  # nunca isola arquivos do próprio antivírus
        return cand

    def _is_c2_candidate(self, rep: ProcessReport, ip: str) -> bool:
        """Bloqueia apenas servidores de controle (beacon / portas de C2), nunca as vítimas de uma varredura."""
        for f in rep.findings:
            if f.id in ("botnet.beacon", "botnet.c2_port") and any(ip in e for e in f.evidence):
                return True
        if any(f.id == "botnet.c2_port" for f in rep.findings):
            with self._lock:
                return any(c[1] == ip and c[2] in C2_PORTS for c in self._conns.get(rep.pid, ()))
        return False

    def check_now(self) -> list[ProcessReport]:
        """Análise imediata (botão 'Analisar agora' e linha de comando)."""
        self.sample()
        time.sleep(0.3)
        self.sample()
        reps = self.evaluate()
        for r in reps:
            self._act(r)
        return reps
