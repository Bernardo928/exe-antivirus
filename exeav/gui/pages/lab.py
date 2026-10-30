"""Sala de Análise: mostra por que um arquivo é vírus e todas as informações sobre ele."""
from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QComboBox, QFileDialog, QHBoxLayout, QLineEdit, QListWidget, QListWidgetItem,
                               QMessageBox, QPlainTextEdit, QSplitter, QStackedWidget, QTabWidget, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from ... import util
from ...engine.models import SEVERITY_ORDER
from ...engine.pe_analyzer import API_GROUPS
from .. import icons, theme
from ..widgets import (Badge, Card, DataTable, EmptyState, EntropyChart, PageHeader, ScoreGauge, button, confirm,
                       label, run_bg)

SUSPICIOUS_API_NAMES = set().union(*(API_GROUPS[k] for k in ("injection", "hollowing", "keylog", "download",
                                                             "privilege", "crypto", "clipboard")))
SEV_LABEL = {"critica": "CRÍTICA", "alta": "ALTA", "media": "MÉDIA", "baixa": "BAIXA", "info": "INFO"}


def _text_view() -> QPlainTextEdit:
    t = QPlainTextEdit()
    t.setReadOnly(True)
    t.setObjectName("mono")
    t.setLineWrapMode(QPlainTextEdit.NoWrap)
    return t


class LabPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.rep: dict | None = None
        self.current_id: str | None = None
        self.setAcceptDrops(True)
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        hdr = PageHeader("Sala de Análise", "Coloque um arquivo aqui para ver exatamente POR QUE ele é (ou não) um "
                                            "vírus e todas as informações técnicas. As amostras ficam neutralizadas.",
                         "flask")
        add = button("Adicionar arquivo", "plus", "primary")
        add.clicked.connect(self.add_file)
        hdr.right.addWidget(add)
        root.addWidget(hdr)

        split = QSplitter(Qt.Horizontal)
        split.setChildrenCollapsible(False)
        # ---------------- lista de amostras
        left = Card()
        left.setMinimumWidth(250)
        left.setMaximumWidth(310)
        left.lay.addWidget(label("Amostras", "sectionTitle"))
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filtrar amostras…")
        self.search.textChanged.connect(self.refresh_list)
        left.lay.addWidget(self.search)
        self.list = QListWidget()
        self.list.currentItemChanged.connect(self._on_select)
        left.lay.addWidget(self.list, 1)
        lb = QHBoxLayout()
        self.b_reanalyze = button("", "refresh", tip="Reanalisar com o motor atual")
        self.b_remove = button("", "trash", "danger", tip="Remover amostra da Sala de Análise")
        self.b_html = button("", "download", tip="Exportar relatório em HTML")
        self.b_json = button("", "code", tip="Exportar relatório em JSON")
        self.b_quar = button("", "lock", tip="Isolar o arquivo original na quarentena")
        for b in (self.b_reanalyze, self.b_html, self.b_json, self.b_quar, self.b_remove):
            lb.addWidget(b)
        left.lay.addLayout(lb)
        drop = label("Dica: arraste e solte arquivos nesta tela.", "small")
        drop.setAlignment(Qt.AlignCenter)
        left.lay.addWidget(drop)
        split.addWidget(left)

        # ---------------- detalhes
        self.detail_stack = QStackedWidget()
        self.detail_stack.addWidget(EmptyState("flask", "Nenhuma amostra selecionada",
                                               "Adicione um arquivo, envie um item da quarentena ou um resultado de "
                                               "verificação para ver a análise completa."))
        detail = QWidget()
        dv = QVBoxLayout(detail)
        dv.setContentsMargins(0, 0, 0, 0)
        dv.setSpacing(12)
        head = Card()
        hh = QHBoxLayout()
        self.gauge = ScoreGauge(118)
        hh.addWidget(self.gauge)
        hv = QVBoxLayout()
        hv.setSpacing(4)
        self.d_name = label("", "pageTitle")
        self.d_name.setWordWrap(True)
        hv.addWidget(self.d_name)
        br = QHBoxLayout()
        self.d_badge = Badge("")
        self.d_threat = label("", "sectionTitle")
        br.addWidget(self.d_badge)
        br.addWidget(self.d_threat, 1)
        hv.addLayout(br)
        self.d_meta = label("", "muted", wrap=True)
        self.d_meta.setTextInteractionFlags(Qt.TextSelectableByMouse)
        hv.addWidget(self.d_meta)
        hh.addLayout(hv, 1)
        head.lay.addLayout(hh)
        dv.addWidget(head)

        self.tabs = QTabWidget()
        # Por que é vírus
        why = QWidget()
        wv = QVBoxLayout(why)
        wv.setContentsMargins(12, 12, 12, 12)
        self.explain = QPlainTextEdit()
        self.explain.setReadOnly(True)
        self.explain.setMinimumHeight(150)
        self.explain.setMaximumHeight(230)
        wv.addWidget(self.explain)
        wv.addWidget(label("Evidências encontradas no conteúdo do arquivo", "sectionTitle"))
        self.ind_table = DataTable(["Severidade", "Indicador", "Categoria", "Pontos", "Evidência"], stretch_col=4)
        for i, w in enumerate((85, 270, 135, 60)):
            self.ind_table.setColumnWidth(i, w)
        self.ind_table.itemSelectionChanged.connect(self._on_indicator)
        wv.addWidget(self.ind_table, 1)
        self.ind_desc = label("", "muted", wrap=True)
        self.ind_desc.setTextInteractionFlags(Qt.TextSelectableByMouse)
        wv.addWidget(self.ind_desc)
        self.tabs.addTab(why, icons.icon("alert", theme.WARNING, 16), "Por que é vírus")
        # Informações
        self.info_table = DataTable(["Propriedade", "Valor"], stretch_col=1)
        self.info_table.setColumnWidth(0, 230)
        self.info_table.setWordWrap(True)
        self.tabs.addTab(self.info_table, icons.icon("info", theme.TEXT, 16), "Informações")
        # Estrutura
        st = QWidget()
        sv = QVBoxLayout(st)
        sv.setContentsMargins(12, 12, 12, 12)
        sv.addWidget(label("Entropia ao longo do arquivo (vermelho = cifrado/compactado)", "sectionTitle"))
        self.entropy = EntropyChart()
        sv.addWidget(self.entropy)
        sv.addWidget(label("Seções", "sectionTitle"))
        self.sections = DataTable(["Nome", "Endereço", "Tam. virtual / tipo", "Tam. bruto", "Entropia", "Permissões"], stretch_col=0)
        sv.addWidget(self.sections, 1)
        self.tabs.addTab(st, icons.icon("archive", theme.TEXT, 16), "Estrutura")
        # Importações
        self.imports = QTreeWidget()
        self.imports.setHeaderLabels(["Biblioteca / função", "Observação"])
        self.imports.setColumnWidth(0, 420)
        self.tabs.addTab(self.imports, icons.icon("cpu", theme.TEXT, 16), "Importações")
        # Strings
        sw = QWidget()
        swv = QVBoxLayout(sw)
        swv.setContentsMargins(12, 12, 12, 12)
        sh = QHBoxLayout()
        self.str_kind = QComboBox()
        self.str_kind.addItems(["Todas", "URLs", "IPs", "E-mails", "Registro", "Caminhos", "Bitcoin", "Onion"])
        self.str_kind.currentIndexChanged.connect(self._fill_strings)
        self.str_filter = QLineEdit()
        self.str_filter.setPlaceholderText("Buscar nas strings…")
        self.str_filter.textChanged.connect(self._fill_strings)
        sh.addWidget(self.str_kind)
        sh.addWidget(self.str_filter, 1)
        swv.addLayout(sh)
        self.strings = _text_view()
        swv.addWidget(self.strings, 1)
        self.tabs.addTab(sw, icons.icon("search", theme.TEXT, 16), "Strings")
        # Código
        self.code = _text_view()
        self.tabs.addTab(self.code, icons.icon("code", theme.TEXT, 16), "Código")
        # Hex
        self.hex = _text_view()
        self.tabs.addTab(self.hex, icons.icon("file", theme.TEXT, 16), "Hex")
        # MITRE
        self.mitre = DataTable(["Técnica", "Nome", "Evidência"], stretch_col=2)
        self.mitre.setColumnWidth(0, 110)
        self.mitre.setColumnWidth(1, 300)
        self.tabs.addTab(self.mitre, icons.icon("bug", theme.TEXT, 16), "MITRE")
        # Conteúdo interno
        self.members = DataTable(["Item interno", "Veredito", "Pontos", "Ameaça", "Motivos"], stretch_col=4)
        self.members.setColumnWidth(0, 260)
        self.tabs.addTab(self.members, icons.icon("archive", theme.TEXT, 16), "Conteúdo")
        dv.addWidget(self.tabs, 1)
        self.detail_stack.addWidget(detail)
        split.addWidget(self.detail_stack)
        split.setStretchFactor(1, 1)
        root.addWidget(split, 1)

        self.b_reanalyze.clicked.connect(self.reanalyze)
        self.b_remove.clicked.connect(self.remove)
        self.b_html.clicked.connect(lambda: self.export("html"))
        self.b_json.clicked.connect(lambda: self.export("json"))
        self.b_quar.clicked.connect(self.quarantine_original)
        ctx.bridge.open_in_lab.connect(self.open_item)
        ctx.bridge.lab_changed.connect(lambda *_: self.refresh_list())
        self._set_buttons(False)
        self.refresh_list()

    # ------------------------------------------------------------------ arrastar e soltar
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        files = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        files = [f for f in files if os.path.isfile(f)]
        if files:
            self._add_paths(files)

    # ------------------------------------------------------------------ ações
    def add_file(self):
        fs, _ = QFileDialog.getOpenFileNames(self, "Arquivos para analisar")
        if fs:
            self._add_paths(fs)

    def _add_paths(self, files):
        def work():
            ids = []
            for f in files:
                if self.ctx.engine.exclusions.is_excluded(f):
                    continue
                ids.append(self.ctx.lab.add_file(f, "manual"))
            return ids

        def done(ids):
            if not ids:
                QMessageBox.information(self, "Sala de Análise", "Os arquivos escolhidos pertencem ao próprio "
                                        "antivírus e não são analisados.")
                return
            self.open_item(ids[-1])
        self.d_meta.setText("Analisando…")
        run_bg(work, done)

    def open_item(self, item_id: str):
        self.refresh_list(select=item_id)
        self.ctx.bridge.navigate.emit("lab")

    def reanalyze(self):
        if not self.current_id:
            return
        item_id = self.current_id
        run_bg(lambda: self.ctx.lab.reanalyze(item_id), lambda rep: self.refresh_list(select=item_id))

    def remove(self):
        if self.current_id and confirm(self, "Remover", "Remover esta amostra da Sala de Análise?"):
            self.ctx.lab.remove(self.current_id)
            self.current_id = None
            self.refresh_list()

    def export(self, kind: str):
        if not self.current_id or not self.rep:
            return
        base = os.path.splitext(self.rep["name"])[0] + f"-relatorio.{kind}"
        dest, _ = QFileDialog.getSaveFileName(self, "Exportar relatório", base)
        if dest:
            (self.ctx.lab.export_html if kind == "html" else self.ctx.lab.export_json)(self.current_id, dest)

    def quarantine_original(self):
        if not self.rep:
            return
        p = self.rep.get("original_path")
        if not p or not os.path.isfile(p):
            QMessageBox.information(self, "Quarentena", "O arquivo original não existe mais no local de origem.")
            return
        if not confirm(self, "Quarentena", f"Isolar o arquivo original?\n\n{p}"):
            return
        from ...engine.models import ScanResult
        r = ScanResult(path=p, verdict=self.rep["verdict"], score=self.rep["score"],
                       threat_name=self.rep["threat_name"] or "Manual", file_type=self.rep["file_type"],
                       sha256=self.rep["hashes"]["sha256"])
        try:
            self.ctx.quarantine.isolate(r)
            self.ctx.bridge.quarantine_changed.emit()
            QMessageBox.information(self, "Quarentena", "Arquivo isolado com sucesso.")
        except Exception as e:
            QMessageBox.warning(self, "Quarentena", str(e))

    # ------------------------------------------------------------------ exibição
    def _set_buttons(self, on: bool):
        for b in (self.b_reanalyze, self.b_remove, self.b_html, self.b_json, self.b_quar):
            b.setEnabled(on)

    def refresh_list(self, *_, select: str | None = None):
        keep = select or self.current_id
        flt = self.search.text().lower().strip()
        self.list.blockSignals(True)
        self.list.clear()
        target = None
        for it in self.ctx.lab.items():
            if flt and flt not in (it.get("name", "") + it.get("threat_name", "") + it.get("sha256", "")).lower():
                continue
            v = it.get("verdict", "limpo")
            li = QListWidgetItem(icons.icon("shield" if v == "limpo" else "alert",
                                            theme.VERDICT_COLORS.get(v, theme.MUTED), 18),
                                 f"{it.get('name', '')}\n{(it.get('threat_name') or v).upper()} · {it.get('score', 0)} pts")
            li.setData(Qt.UserRole, it["id"])
            li.setToolTip(it.get("original_path", ""))
            self.list.addItem(li)
            if it["id"] == keep:
                target = li
        self.list.blockSignals(False)
        if target is not None:
            self.list.setCurrentItem(target)
            self._load(target.data(Qt.UserRole))
        elif self.list.count() == 0:
            self.detail_stack.setCurrentIndex(0)
            self._set_buttons(False)

    def _on_select(self, cur, _prev):
        if cur is not None:
            self._load(cur.data(Qt.UserRole))

    def _load(self, item_id: str):
        self.current_id = item_id
        try:
            rep = self.ctx.lab.report(item_id)
        except Exception as e:
            QMessageBox.warning(self, "Sala de Análise", f"Não foi possível abrir a amostra: {e}")
            return
        self.rep = rep
        self._set_buttons(True)
        self.detail_stack.setCurrentIndex(1)
        v = rep["verdict"]
        color = theme.VERDICT_COLORS.get(v, theme.MUTED)
        self.gauge.set(rep["score"], v)
        self.d_name.setText(rep["name"])
        self.d_badge.set(v.upper(), color)
        self.d_threat.setText(rep["threat_name"] or "Nenhuma ameaça identificada")
        self.d_threat.setStyleSheet(f"color: {color};")
        self.d_meta.setText(f"{rep['type_description']} · {util.human_size(rep['size'])} · SHA-256 "
                            f"{rep['hashes']['sha256']}\nOrigem: {rep.get('original_path') or '—'} · analisado em "
                            f"{rep['analyzed_at']}")
        self.explain.setPlainText(rep["explanation"])
        self.explain.moveCursor(self.explain.textCursor().MoveOperation.Start)

        self.ind_table.clear_rows()
        inds = sorted(rep["indicators"], key=lambda i: (-SEVERITY_ORDER.get(i["severity"], 0), -i["weight"]))
        for i in inds:
            c = theme.SEVERITY_COLORS.get(i["severity"], theme.MUTED)
            self.ind_table.add_row([SEV_LABEL.get(i["severity"], i["severity"]), i["name"], i["category"],
                                    f"{i['weight']:+d}", " | ".join(i["evidence"][:5])], data=i,
                                   colors={0: c, 3: theme.SUCCESS if i["weight"] < 0 else c})
        if inds:
            self.ind_table.selectRow(0)
        else:
            self.ind_desc.setText("Nenhum indicador de risco encontrado.")

        self.info_table.clear_rows()
        rows = [("Nome", rep["name"]), ("Caminho original", rep.get("original_path") or "—"),
                ("Tipo real (pelo conteúdo)", rep["type_description"]), ("Assinatura mágica (bytes iniciais)", rep["magic"]),
                ("Tamanho", f"{util.human_size(rep['size'])} ({rep['size']:,} bytes)".replace(",", ".")),
                ("Entropia geral", f"{rep['entropy']} de 8.0"), ("MD5", rep["hashes"]["md5"]),
                ("SHA-1", rep["hashes"]["sha1"]), ("SHA-256", rep["hashes"]["sha256"]),
                ("SHA-512", rep["hashes"]["sha512"])]
        rows += [(k.capitalize(), v) for k, v in rep.get("timestamps", {}).items()]
        rows += [(str(k).capitalize(), v) for k, v in rep["info"].items()]
        rows += [(f"Versão: {k}", v) for k, v in rep.get("version_info", {}).items()]
        if rep.get("signers"):
            rows.append(("Certificados da assinatura", ", ".join(rep["signers"])))
        if rep.get("resources"):
            rows.append(("Recursos embutidos", ", ".join(f"{t} ({util.human_size(s)})" for t, s in rep["resources"][:30])))
        if rep.get("exports"):
            rows.append(("Funções exportadas", ", ".join(rep["exports"][:200])))
        rows.append(("Motor de análise", rep["engine"]))
        for k, val in rows:
            self.info_table.add_row([k, val])
        self.info_table.resizeRowsToContents()

        self.entropy.set(rep.get("entropy_profile", []))
        self.sections.clear_rows()
        for s in rep.get("sections", []):
            ent = s.get("entropia", 0)
            c = theme.DANGER if ent > 7.2 else theme.WARNING if ent > 6.5 else None
            self.sections.add_row([s.get("nome"), s.get("endereço virtual", ""), s.get("tamanho virtual", s.get("tipo", "")),
                                   s.get("tamanho bruto", ""), ent, s.get("permissões", "")],
                                  colors={4: c} if c else None)

        self.imports.clear()
        susp = rep.get("suspicious_apis", {})
        flagged = {f.lower() for v in susp.values() for f in v}
        for dll, funcs in rep.get("imports", {}).items():
            top = QTreeWidgetItem([f"{dll}  ({len(funcs)})", ""])
            bad = 0
            for f in funcs:
                n = f.lower().rstrip("aw") if f.lower().endswith(("a", "w")) else f.lower()
                is_bad = f.lower() in flagged or n in flagged or f.lower() in SUSPICIOUS_API_NAMES or n in SUSPICIOUS_API_NAMES
                ch = QTreeWidgetItem([f, "⚠ usada por malware" if is_bad else ""])
                if is_bad:
                    bad += 1
                    ch.setForeground(0, QColor(theme.DANGER))
                    ch.setForeground(1, QColor(theme.DANGER))
                top.addChild(ch)
            if bad:
                top.setText(1, f"{bad} função(ões) suspeita(s)")
                top.setForeground(1, QColor(theme.WARNING))
            self.imports.addTopLevelItem(top)
        if susp:
            grp = QTreeWidgetItem(["Comportamentos inferidos pelas importações", ""])
            for k, v in susp.items():
                grp.addChild(QTreeWidgetItem([k, ", ".join(v)]))
            grp.setForeground(0, QColor(theme.DANGER))
            self.imports.insertTopLevelItem(0, grp)
            grp.setExpanded(True)
        if not rep.get("imports"):
            self.imports.addTopLevelItem(QTreeWidgetItem(["(sem tabela de importações para este tipo de arquivo)", ""]))

        self._fill_strings()
        code_parts = []
        if rep.get("macro"):
            code_parts.append("' ================= MACROS VBA EXTRAÍDAS =================\n" + rep["macro"])
        if rep.get("decoded"):
            code_parts.append("# ================= CONTEÚDO OFUSCADO DECODIFICADO =================\n" +
                              "\n\n# -----\n".join(rep["decoded"]))
        if rep.get("script_preview"):
            code_parts.append("# ================= CONTEÚDO DO SCRIPT =================\n" + rep["script_preview"])
        self.code.setPlainText("\n\n".join(code_parts) or "Nenhum código-fonte, macro ou conteúdo decodificado para exibir.")
        self.hex.setPlainText(rep.get("hexdump", ""))
        self.mitre.clear_rows()
        for m in rep.get("mitre", []):
            self.mitre.add_row([m["id"], m["name"], m["por"]], colors={0: theme.ACCENT})
        self.members.clear_rows()
        for m in rep.get("members", []):
            c = theme.VERDICT_COLORS.get(m["verdict"], theme.MUTED)
            self.members.add_row([m["path"], m["verdict"], m["score"], m["threat_name"],
                                  "; ".join(i["name"] for i in m["indicators"][:6])], colors={0: c, 1: c})

    def _on_indicator(self):
        sel = self.ind_table.selected_data()
        if sel and sel[0]:
            i = sel[0]
            ev = "\n".join(f"   • {e}" for e in i["evidence"][:8])
            self.ind_desc.setText(f"<b>{i['name']}</b> — {i['description']}" +
                                  (f"<br><span style='color:{theme.MUTED}'>Evidências:</span><pre>{_esc(ev)}</pre>" if ev else ""))

    def _fill_strings(self, *_):
        if not self.rep:
            return
        kind = self.str_kind.currentIndex()
        keys = [None, "urls", "ips", "emails", "registro", "caminhos", "bitcoin", "onion"]
        data = self.rep["strings"] if kind == 0 else self.rep["string_classes"].get(keys[kind], [])
        flt = self.str_filter.text().lower()
        if flt:
            data = [s for s in data if flt in s.lower()]
        self.strings.setPlainText("\n".join(data[:8000]) or "(nenhuma)")


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
