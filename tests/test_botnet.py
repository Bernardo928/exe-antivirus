"""Escudo anti-botnet: simula comportamentos de bot com o simulador inofensivo (tests/botsim.py).

O simulador só usa endereços reservados para documentação (RFC 5737), que nunca chegam a uma máquina real.
"""
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import pytest

from exeav import config, firewall
from exeav.botnet import BotnetShield, C2Blocklist
from exeav.engine.engine import Engine
from exeav.engine.models import MALICIOUS, SUSPICIOUS
from exeav.quarantine import Quarantine

HERE = os.path.dirname(os.path.abspath(__file__))


def _sim_copy(tmp_path):
    """Cópia do simulador fora da pasta do projeto (o antivírus nunca isola os próprios arquivos)."""
    dst = tmp_path / "botsim.py"
    shutil.copy(os.path.join(HERE, "botsim.py"), dst)
    return str(dst)


def _shield(pids, tmp_path, firewall_block=False):
    s = config.Settings()
    s.botnet_firewall_block = firewall_block
    events = []
    sh = BotnetShield(Engine(s), Quarantine(tmp_path / "q"), lambda k, d: events.append((k, d)),
                      interval=0.4, watch_pids=set(pids))
    return sh, events


def _wait(cond, timeout=15.0):
    t = time.time()
    while time.time() - t < timeout:
        if cond():
            return True
        time.sleep(0.2)
    return False


def _bot_event(events, pid):
    return next((d for k, d in events if k == "botnet" and d.pid == pid), None)


def test_worm_scanner_is_killed_and_script_isolated(tmp_path):
    sim = _sim_copy(tmp_path)
    p = subprocess.Popen([sys.executable, sim, "worm", "40"], stdout=subprocess.DEVNULL)
    sh, events = _shield([p.pid], tmp_path)
    sh.start()
    try:
        assert _wait(lambda: p.poll() is not None), "o bot não foi encerrado"
    finally:
        sh.stop()
        if p.poll() is None:
            p.kill()
    rep = _bot_event(events, p.pid)
    assert rep and rep.verdict == MALICIOUS
    assert "botnet.worm_scan" in {f.id for f in rep.findings}
    assert not os.path.exists(sim), "o script do bot devia estar na quarentena"


def test_beacon_to_irc_is_blocked(tmp_path):
    sim = _sim_copy(tmp_path)
    p = subprocess.Popen([sys.executable, sim, "beacon", "70", "1.5"], stdout=subprocess.DEVNULL)
    sh, events = _shield([p.pid], tmp_path)
    sh.start()
    try:
        assert _wait(lambda: p.poll() is not None, 60), "o bot não foi encerrado"
    finally:
        sh.stop()
        if p.poll() is None:
            p.kill()
    rep = _bot_event(events, p.pid)
    assert rep and {"botnet.beacon", "botnet.c2_port"} <= {f.id for f in rep.findings}


def test_known_c2_server(tmp_path):
    sim = _sim_copy(tmp_path)
    p = subprocess.Popen([sys.executable, sim, "c2", "40", "203.0.113.200"], stdout=subprocess.DEVNULL)
    sh, events = _shield([p.pid], tmp_path)
    sh.c2.add_text("203.0.113.200\n", "teste")
    sh.start()
    try:
        assert _wait(lambda: p.poll() is not None), "o bot não foi encerrado"
    finally:
        sh.stop()
        if p.poll() is None:
            p.kill()
    rep = _bot_event(events, p.pid)
    assert rep and rep.findings[0].id == "botnet.c2_known" and "203.0.113.200" in rep.remote_ips


def test_backdoor_port_raises_alert(tmp_path):
    sim = _sim_copy(tmp_path)
    p = subprocess.Popen([sys.executable, sim, "listen", "40", "31337"], stdout=subprocess.PIPE)
    p.stdout.readline()
    sh, events = _shield([p.pid], tmp_path)
    try:
        sh.check_now()
        rep = sh.reports.get(p.pid)
        assert rep and rep.verdict in (SUSPICIOUS, MALICIOUS)
        assert "botnet.backdoor_listen" in {f.id for f in rep.findings}
    finally:
        p.kill()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="cópia do interpretador só funciona assim no Linux")
def test_disguised_bot_in_temp_folder(tmp_path):
    """Bot disfarçado de 'kworker', rodando de pasta temporária e abrindo backdoor: encerrado e isolado."""
    d = tempfile.mkdtemp(prefix="bot-")
    fake = os.path.join(d, "kworker")
    shutil.copy(os.path.realpath(sys.executable), fake)
    sim = _sim_copy(tmp_path)
    p = subprocess.Popen([fake, sim, "listen", "40", "4444"], stdout=subprocess.DEVNULL)
    sh, events = _shield([p.pid], tmp_path)
    sh.start()
    try:
        assert _wait(lambda: p.poll() is not None), "o bot não foi encerrado"
    finally:
        sh.stop()
        if p.poll() is None:
            p.kill()
    rep = _bot_event(events, p.pid)
    ids = {f.id for f in rep.findings}
    assert {"botnet.backdoor_listen", "botnet.masquerade", "botnet.temp_exe"} <= ids
    assert not os.path.exists(fake), "o executável do bot devia estar na quarentena"


def test_quiet_program_untouched(tmp_path):
    sim = _sim_copy(tmp_path)
    p = subprocess.Popen([sys.executable, sim, "quiet", "20"], stdout=subprocess.DEVNULL)
    sh, events = _shield([p.pid], tmp_path)
    sh.start()
    time.sleep(3)
    sh.stop()
    alive = p.poll() is None
    p.kill()
    assert alive and not events or all(k == "status" for k, _ in events)


def test_never_kills_itself(tmp_path):
    """Mesmo se o próprio processo do antivírus 'parecer' um bot, ele nunca é encerrado."""
    socks = []
    for i in range(30):
        s = socket.socket()
        s.setblocking(False)
        try:
            s.connect((f"198.51.100.{i + 1}", 23))
        except OSError:
            pass
        socks.append(s)
    sh, events = _shield([os.getpid()], tmp_path)
    reps = sh.check_now()
    for s in socks:
        s.close()
    rep = next(r for r in reps if r.pid == os.getpid())
    assert rep.verdict == MALICIOUS and rep.protected
    assert "processo encerrado" not in rep.action


def test_c2_list_formats(tmp_path):
    c = C2Blocklist()
    n = c.add_text("# Feodo Tracker\n# comentário\n203.0.113.5\n198.51.100.9:443\n\"192.0.2.7\",80\nlixo\n"
                   "2001:db8::1\n", "teste")
    assert n == 4 and {"203.0.113.5", "198.51.100.9", "192.0.2.7", "2001:db8::1"} <= c.ips
    assert C2Blocklist().ips >= {"203.0.113.5"}  # persistido em disco


def test_firewall_refuses_dangerous_targets():
    for bad in ("127.0.0.1", "0.0.0.0", "::1", "não-é-ip"):
        with pytest.raises(ValueError):
            firewall.block(bad, "teste")


@pytest.mark.skipif(not (sys.platform.startswith("linux") and os.geteuid() == 0 and firewall.backend()),
                    reason="requer Linux com firewall e root")
def test_firewall_block_linux_real():
    ip = "203.0.113.77"

    def connect_fast_fails():
        s = socket.socket()
        s.settimeout(2)
        t = time.time()
        try:
            s.connect((ip, 443))
            return False
        except OSError:
            return time.time() - t < 1.5  # recusado na hora pelo firewall (sem bloqueio: espera o tempo limite)
        finally:
            s.close()
    if firewall.backend() == "nft" and subprocess.run(["nft", "list", "tables"], capture_output=True).returncode:
        pytest.skip("nftables sem permissão")
    assert firewall.block(ip, "teste")
    try:
        assert ip in firewall.blocked()
        assert connect_fast_fails()
    finally:
        firewall.unblock(ip)
    assert ip not in firewall.blocked()
    assert not connect_fast_fails()


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="somente Windows")
def test_firewall_block_windows_real():
    ip = "203.0.113.78"
    name = f"name=EXE Antivirus - bloqueio {ip}"
    assert firewall.block(ip, "teste")
    try:
        r = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", name], capture_output=True, text=True)
        assert r.returncode == 0 and ip in r.stdout
    finally:
        firewall.unblock(ip)
    r = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", name], capture_output=True, text=True)
    assert r.returncode != 0
