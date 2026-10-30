"""Sala de Análise: guarda amostras de forma neutralizada e produz um relatório completo."""
from __future__ import annotations

import datetime
import hashlib
import html
import json
import os
from pathlib import Path

from . import VERSION, history, paths, util
from .engine import filetype, trust
from .engine.engine import STRUCTURAL, Engine
from .engine.models import MALICIOUS, SEVERITY_ORDER, SUSPICIOUS
from .vault import Vault

# Mapeamento de indicadores para técnicas MITRE ATT&CK
MITRE = [
    ("ransom.shadow_delete", "T1490", "Inibir recuperação do sistema"),
    ("ransom.recovery_off", "T1490", "Inibir recuperação do sistema"),
    ("ransom.", "T1486", "Dados criptografados para impacto"),
    ("pe.ransom_combo", "T1486", "Dados criptografados para impacto"),
    ("miner.", "T1496", "Sequestro de recursos (mineração)"),
    ("nix.kill_competitors", "T1496", "Sequestro de recursos (mineração)"),
    ("cred.", "T1003", "Despejo de credenciais do SO"),
    ("steal.browser", "T1555.003", "Credenciais de navegadores"),
    ("steal.wallets", "T1005", "Dados do sistema local"),
    ("exfil.", "T1567", "Exfiltração por serviço web"),
    ("evasion.defender", "T1562.001", "Desativar ferramentas de segurança"),
    ("evasion.uac_bypass", "T1548.002", "Contornar o UAC"),
    ("evasion.log_clear", "T1070.001", "Limpar logs de eventos"),
    ("evasion.antivm", "T1497", "Evasão de virtualização/sandbox"),
    ("persist.run_key", "T1547.001", "Chaves Run / pasta Inicializar"),
    ("persist.startup_folder", "T1547.001", "Chaves Run / pasta Inicializar"),
    ("persist.winlogon", "T1547.004", "Winlogon helper"),
    ("persist.schtask", "T1053.005", "Tarefa agendada"),
    ("spy.keylog", "T1056.001", "Captura de teclado"),
    ("script.keylog", "T1056.001", "Captura de teclado"),
    ("pe.api_keylogger", "T1056.001", "Captura de teclado"),
    ("spy.screen", "T1113", "Captura de tela"),
    ("pe.self_delete", "T1070.004", "Exclusão de arquivos (indicadores)"),
    ("lolbin.certutil", "T1105", "Transferência de ferramentas"),
    ("lolbin.proxyexec", "T1218", "Execução por binário do sistema"),
    ("cmd.add_admin", "T1136.001", "Criar conta local"),
    ("cmd.firewall_off", "T1562.004", "Desativar firewall"),
    ("ps.", "T1059.001", "PowerShell"),
    ("script.char", "T1027", "Arquivos/informações ofuscados"),
    ("deobf.", "T1027", "Arquivos/informações ofuscados"),
    ("vbs.", "T1059.005", "Visual Basic"),
    ("js.", "T1059.007", "JavaScript"),
    ("html.smuggling", "T1027.006", "HTML smuggling"),
    ("php.webshell", "T1505.003", "Web shell"),
    ("nix.reverse_shell", "T1059.004", "Unix shell"),
    ("elf.bindshell", "T1059.004", "Unix shell"),
    ("nix.dropper_tmp", "T1105", "Transferência de ferramentas"),
    ("nix.pipe_shell", "T1105", "Transferência de ferramentas"),
    ("nix.b64_exec", "T1140", "Decodificar arquivos/informações"),
    ("nix.history_wipe", "T1070.003", "Limpar histórico de comandos"),
    ("nix.ssh_implant", "T1098.004", "Chaves SSH autorizadas"),
    ("nix.cron_persist", "T1053.003", "Cron"),
    ("nix.preload_rootkit", "T1574.006", "Sequestro do carregador dinâmico"),
    ("elf.preload_hooks", "T1574.006", "Sequestro do carregador dinâmico"),
    ("nix.immutable", "T1222.002", "Modificar permissões de arquivos"),
    ("nix.botnet", "T1498", "Negação de serviço de rede"),
    ("nix.rm_root", "T1485", "Destruição de dados"),
    ("win.wiper", "T1561", "Limpeza de disco"),
    ("win.raw_disk", "T1561", "Limpeza de disco"),
    ("py.exec", "T1027", "Arquivos/informações ofuscados"),
    ("macro.", "T1204.002", "Execução pelo usuário: arquivo malicioso"),
    ("pdf.", "T1204.002", "Execução pelo usuário: arquivo malicioso"),
    ("rtf.exploit", "T1203", "Exploração para execução"),
    ("ooxml.follina", "T1203", "Exploração para execução"),
    ("ooxml.remote_template", "T1221", "Injeção de modelo"),
    ("lnk.malicious", "T1204.002", "Execução pelo usuário: arquivo malicioso"),
    ("pe.api_injection", "T1055", "Injeção em processos"),
    ("pe.api_hollowing", "T1055.012", "Process hollowing"),
    ("elf.ptrace_inject", "T1055.008", "Injeção via ptrace"),
    ("ps.reflective_load", "T1620", "Carregamento reflexivo de código"),
    ("ps.amsi_bypass", "T1562.001", "Desativar ferramentas de segurança"),
    ("pe.av_killer", "T1562.001", "Desativar ferramentas de segurança"),
    ("pe.packer", "T1027.002", "Empacotamento de software"),
    ("pe.protector", "T1027.002", "Empacotamento de software"),
    ("elf.upx", "T1027.002", "Empacotamento de software"),
    ("pe.high_entropy_code", "T1027.002", "Empacotamento de software"),
    ("pe.fake_ms", "T1036", "Disfarce (masquerading)"),
    ("pe.api_downloader", "T1105", "Transferência de ferramentas"),
    ("pe.embedded_pe", "T1027.009", "Payloads embutidos"),
    ("gen.embedded_pe", "T1027.009", "Payloads embutidos"),
    ("pe.sedebug", "T1134", "Manipulação de token de acesso"),
    ("pe.clipper", "T1115", "Dados da área de transferência"),
    ("pe.api_antidebug", "T1622", "Evasão de depurador"),
]

VERDICT_TEXT = {MALICIOUS: "MALICIOSO", SUSPICIOUS: "SUSPEITO"}


def mitre_for(indicators: list[dict]) -> list[dict]:
    out, seen = [], set()
    for ind in indicators:
        if ind.get("weight", 0) <= 0:
            continue
        for prefix, tid, name in MITRE:
            if ind["id"].startswith(prefix):
                if tid not in seen:
                    seen.add(tid)
                    out.append({"id": tid, "name": name, "por": ind["name"]})
                break
    return out


def explain(rep: dict) -> str:
    """Texto em linguagem simples explicando o porquê do veredito."""
    v = rep["verdict"]
    inds = [i for i in rep["indicators"] if i["weight"] > 0]
    inds.sort(key=lambda i: (-SEVERITY_ORDER.get(i["severity"], 0), -i["weight"]))
    if v == MALICIOUS:
        head = (f"Este arquivo foi classificado como MALICIOSO com {rep['score']} pontos de risco "
                f"(identificado como {rep['threat_name']}).")
    elif v == SUSPICIOUS:
        head = (f"Este arquivo é SUSPEITO ({rep['score']} pontos). Ele apresenta comportamentos usados por "
                f"malware, mas não o suficiente para uma condenação certa.")
    else:
        head = f"Nenhum comportamento perigoso relevante foi encontrado ({rep['score']} pontos)."
    lines = [head]
    if inds:
        lines.append("")
        lines.append("O que o arquivo faz / contém:")
        for i in inds[:10]:
            lines.append(f"• {i['name']}: {i['description']}")
    behaviors = sorted({i["category"] for i in inds if i["id"] not in STRUCTURAL})
    if behaviors:
        lines.append("")
        lines.append("Categorias de comportamento: " + ", ".join(behaviors) + ".")
    neg = [i for i in rep["indicators"] if i["weight"] < 0]
    for i in neg:
        lines.append("")
        lines.append(f"Fator atenuante: {i['description']} ({i['weight']} pontos).")
    lines.append("")
    lines.append("A detecção é feita pelo CONTEÚDO do arquivo (código, estrutura e comportamento), nunca pelo nome.")
    return "\n".join(lines)


def build_report(engine: Engine, data: bytes, name: str, original_path: str = "") -> dict:
    an = engine.analyze(data, path="", deep=True)
    res = an.result
    if original_path and os.path.isfile(original_path) and res.score > 0:
        try:
            with open(original_path, "rb") as f:
                same = hashlib.sha256(f.read()).hexdigest() == res.sha256
        except OSError:
            same = False
        if same:
            ok, desc = trust.check(original_path)
            if ok:
                from .engine.models import Indicator
                res.indicators.append(Indicator(id="trust.verified", name="Origem verificada", category="Confiança",
                                                description=desc, weight=-40, severity="info", evidence=[desc]))
                res.score = max(0, res.score - 40)
                susp, mal = engine.settings.thresholds()
                hard = any(i.id in ("sig.hash", "test.eicar") for i in res.indicators)
                res.verdict = MALICIOUS if hard or res.score >= mal else SUSPICIOUS if res.score >= susp else "limpo"
                res.threat_name = engine._threat_name(res) if res.verdict != "limpo" else ""
    hashes = util.hashes_of_bytes(data)
    hashes["sha512"] = hashlib.sha512(data).hexdigest()
    strings = util.extract_strings(data[:32 * 1024 * 1024], min_len=5, limit=8000)
    info = {k: v for k, v in an.info.items() if not k.startswith("_")}
    st = None
    if original_path:
        try:
            st = os.stat(original_path)
        except OSError:
            st = None
    rep = {
        "name": name,
        "original_path": original_path,
        "analyzed_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "engine": engine.version,
        "size": len(data),
        "file_type": res.file_type,
        "type_description": filetype.DESCRIPTIONS.get(res.file_type, res.file_type),
        "magic": data[:16].hex(" ").upper(),
        "hashes": hashes,
        "entropy": round(util.entropy(data), 4),
        "entropy_profile": [round(x, 3) for x in util.entropy_profile(data, 160)],
        "verdict": res.verdict,
        "score": res.score,
        "threat_name": res.threat_name,
        "indicators": sorted([i.to_dict() for i in res.indicators], key=lambda d: -d["weight"]),
        "info": info,
        "sections": an.info.get("_sections", []),
        "imports": an.info.get("_imports", {}),
        "exports": an.info.get("_exports", [])[:3000],
        "resources": an.info.get("_resources", []),
        "version_info": an.info.get("_version", {}),
        "suspicious_apis": an.info.get("_suspicious_apis", {}),
        "signers": an.info.get("_signers", []),
        "strings": strings[:8000],
        "string_classes": util.classify_strings(strings),
        "macro": an.macro[:200000],
        "decoded": an.decoded[:20],
        "members": [m.to_dict() for m in an.members[:50]],
        "hexdump": util.hexdump(data[:2048]),
        "timestamps": {
            "modificado": datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "acessado": datetime.datetime.fromtimestamp(st.st_atime).strftime("%Y-%m-%d %H:%M:%S"),
            "criado/alterado": datetime.datetime.fromtimestamp(st.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
        } if st else {},
    }
    if res.file_type in ("script", "html"):
        rep["script_preview"] = (filetype.decode_text(data[:200000]) or data[:200000].decode("latin-1"))
    rep["mitre"] = mitre_for(rep["indicators"])
    rep["explanation"] = explain(rep)
    return rep


class AnalysisLab:
    def __init__(self, engine: Engine, root: Path | None = None):
        self.engine = engine
        self.vault = Vault(root or paths.lab_dir())

    def add_file(self, path: str, source: str = "manual") -> str:
        with open(path, "rb") as f:
            data = f.read(512 * 1024 * 1024)
        return self.add_bytes(data, os.path.basename(path), os.path.abspath(path), source)

    def add_bytes(self, data: bytes, name: str, original_path: str = "", source: str = "manual") -> str:
        existing = self.find_by_hash(hashlib.sha256(data).hexdigest())
        if existing:  # a mesma amostra já está na Sala de Análise: reaproveita
            return existing
        rep = build_report(self.engine, data, name, original_path)
        meta = {"name": name, "original_path": original_path, "source": source,
                "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "size": len(data),
                "verdict": rep["verdict"], "score": rep["score"], "threat_name": rep["threat_name"],
                "sha256": rep["hashes"]["sha256"], "file_type": rep["file_type"]}
        item_id = self.vault.store_bytes(data, meta)
        self._save_report(item_id, rep)
        history.log("análise", f"Amostra '{name}' enviada para a Sala de Análise ({rep['verdict']})", original_path)
        return item_id

    def _report_path(self, item_id: str) -> Path:
        return self.vault.root / f"{item_id}.report.json"

    def _save_report(self, item_id: str, rep: dict) -> None:
        self._report_path(item_id).write_text(json.dumps(rep, ensure_ascii=False), "utf-8")

    def report(self, item_id: str) -> dict:
        p = self._report_path(item_id)
        if p.exists():
            try:
                return json.loads(p.read_text("utf-8"))
            except ValueError:
                pass
        return self.reanalyze(item_id)

    def reanalyze(self, item_id: str) -> dict:
        meta = self.vault.meta(item_id)
        rep = build_report(self.engine, self.vault.read(item_id), meta.get("name", "amostra"),
                           meta.get("original_path", ""))
        self._save_report(item_id, rep)
        meta.update(verdict=rep["verdict"], score=rep["score"], threat_name=rep["threat_name"])
        self.vault.update_meta(item_id, meta)
        return rep

    def items(self) -> list[dict]:
        return self.vault.items()

    def remove(self, item_id: str) -> None:
        self.vault.delete(item_id)
        try:
            self._report_path(item_id).unlink()
        except FileNotFoundError:
            pass

    def find_by_hash(self, sha256: str) -> str | None:
        for it in self.items():
            if it.get("sha256") == sha256:
                return it["id"]
        return None

    def export_json(self, item_id: str, dest: str) -> None:
        Path(dest).write_text(json.dumps(self.report(item_id), ensure_ascii=False, indent=2), "utf-8")

    def export_html(self, item_id: str, dest: str) -> None:
        Path(dest).write_text(render_html(self.report(item_id)), "utf-8")


def _e(x) -> str:
    return html.escape(str(x))


def render_html(rep: dict) -> str:
    color = {"malicioso": "#e5484d", "suspeito": "#f5a524"}.get(rep["verdict"], "#30a46c")
    rows = "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in rep["info"].items())
    hashes = "".join(f"<tr><th>{k.upper()}</th><td class=mono>{v}</td></tr>" for k, v in rep["hashes"].items())
    inds = "".join(
        f"<tr><td><span class='sev {i['severity']}'>{_e(i['severity'])}</span></td><td><b>{_e(i['name'])}</b>"
        f"<div class=muted>{_e(i['description'])}</div>"
        + (f"<div class=mono>{_e(' | '.join(i['evidence'][:4]))}</div>" if i["evidence"] else "")
        + f"</td><td>{_e(i['category'])}</td><td style='text-align:right'>{i['weight']:+d}</td></tr>"
        for i in rep["indicators"])
    mitre = "".join(f"<li><b>{_e(m['id'])}</b> {_e(m['name'])} <span class=muted>({_e(m['por'])})</span></li>"
                    for m in rep["mitre"]) or "<li class=muted>Nenhuma</li>"
    secs = "".join("<tr>" + "".join(f"<td>{_e(v)}</td>" for v in s.values()) + "</tr>" for s in rep["sections"])
    sec_head = "".join(f"<th>{_e(k)}</th>" for k in (rep["sections"][0].keys() if rep["sections"] else []))
    imps = "".join(f"<details><summary>{_e(dll)} ({len(f)})</summary><div class=mono>{_e(', '.join(f))}</div></details>"
                   for dll, f in rep["imports"].items())
    sc = rep["string_classes"]
    strs = "".join(f"<h4>{_e(k.capitalize())} ({len(v)})</h4><div class=mono>{'<br>'.join(_e(x) for x in v[:200])}</div>"
                   for k, v in sc.items() if v)
    return f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>Relatório - {_e(rep['name'])}</title>
<style>
body{{font-family:Segoe UI,Roboto,Arial,sans-serif;background:#0f1419;color:#e6e9ef;margin:0;padding:32px;}}
h1{{margin:0 0 4px}} h2{{border-bottom:1px solid #2a3340;padding-bottom:6px;margin-top:32px}}
.card{{background:#171d25;border:1px solid #2a3340;border-radius:12px;padding:20px;margin:12px 0}}
.verdict{{display:inline-block;padding:6px 14px;border-radius:999px;background:{color};color:#fff;font-weight:700}}
table{{width:100%;border-collapse:collapse}} th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid #222b36;vertical-align:top}}
th{{color:#9aa4b2;font-weight:600;width:220px}} .mono{{font-family:Consolas,monospace;font-size:12px;word-break:break-all;color:#b8c1cc}}
.muted{{color:#8b95a3;font-size:13px}} .sev{{padding:2px 8px;border-radius:6px;font-size:12px;background:#2a3340}}
.sev.critica,.sev.alta{{background:#5c1f22;color:#ffb4b6}} .sev.media{{background:#5a3e10;color:#ffd38a}}
.sev.info{{background:#163b29;color:#9be3bf}} pre{{white-space:pre-wrap;background:#0b0f14;padding:12px;border-radius:8px}}
</style></head><body>
<h1>Relatório da Sala de Análise</h1><div class=muted>EXE Antivirus {VERSION} · motor {_e(rep['engine'])} · {_e(rep['analyzed_at'])}</div>
<div class=card><h2 style="margin-top:0">{_e(rep['name'])}</h2>
<span class=verdict>{_e(rep['verdict'].upper())} · {rep['score']} pts</span> <b style="margin-left:12px">{_e(rep['threat_name'])}</b>
<pre>{_e(rep['explanation'])}</pre></div>
<h2>Arquivo</h2><div class=card><table>
<tr><th>Caminho original</th><td>{_e(rep['original_path'])}</td></tr>
<tr><th>Tipo real (pelo conteúdo)</th><td>{_e(rep['type_description'])}</td></tr>
<tr><th>Tamanho</th><td>{util.human_size(rep['size'])} ({rep['size']} bytes)</td></tr>
<tr><th>Entropia</th><td>{rep['entropy']}</td></tr><tr><th>Assinatura mágica</th><td class=mono>{_e(rep['magic'])}</td></tr>
{hashes}{rows}</table></div>
<h2>Indicadores ({len(rep['indicators'])})</h2><div class=card><table><tr><th>Severidade</th><th>Indicador</th><th>Categoria</th><th>Pontos</th></tr>{inds}</table></div>
<h2>Técnicas MITRE ATT&amp;CK</h2><div class=card><ul>{mitre}</ul></div>
{'<h2>Seções</h2><div class=card><table><tr>' + sec_head + '</tr>' + secs + '</table></div>' if secs else ''}
{'<h2>Importações</h2><div class=card>' + imps + '</div>' if imps else ''}
{'<h2>Macros VBA</h2><div class=card><pre>' + _e(rep['macro'][:50000]) + '</pre></div>' if rep['macro'] else ''}
{'<h2>Conteúdo decodificado</h2><div class=card><pre>' + _e(chr(10).join(rep['decoded'])[:50000]) + '</pre></div>' if rep['decoded'] else ''}
<h2>Strings relevantes</h2><div class=card>{strs or '<span class=muted>Nenhuma</span>'}</div>
<h2>Início do arquivo (hex)</h2><div class=card><pre class=mono>{_e(rep['hexdump'][:6000])}</pre></div>
</body></html>"""
