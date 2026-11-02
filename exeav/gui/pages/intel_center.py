"""ZERO-DAY & THREAT INTELLIGENCE CENTER: incidentes, evidências, inteligência, falsos positivos e autoproteção."""
from __future__ import annotations

import html
import json
import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QInputDialog, QLineEdit, QMessageBox,
                               QSplitter, QTabWidget, QTextBrowser, QVBoxLayout, QWidget)

from ... import fpengine, incidents, intel, selfprotect
from .. import theme
from ..widgets import Card, DataTable, Debouncer, PageHeader, StatCard, button, confirm, label, run_bg

CLASS_COLORS = {"crítico": theme.DANGER, "alto risco": "#f97316", "suspeito": theme.WARNING, "informativo": theme.INFO}
STATUS_COLORS = {"em investigação": theme.WARNING, "ameaça confirmada": theme.DANGER,
                 "falso positivo": theme.SUCCESS, "resolvido": theme.MUTED}


class IntelCenterPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.current: dict | None = None
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(14)
        hdr = PageHeader("Zero-Day & Threat Intelligence Center",
                         "Ameaças desconhecidas em investigação, com evidências, nível de confiança, histórico e "
                         "relatórios. Nada sai deste computador.", "bug")
        b_html = button("Exportar HTML", "download")
        b_json = button("Exportar JSON", "code")
        b_html.clicked.connect(lambda: self.export("html"))
        b_json.clicked.connect(lambda: self.export("json"))
        hdr.right.addWidget(b_html)
        hdr.right.addWidget(b_json)
        root.addWidget(hdr)

        stats = QHBoxLayout()
        stats.setSpacing(12)
        self.s_inv = StatCard("Desconhecidas em investigação", "0", "search", theme.WARNING)
        self.s_high = StatCard("Alto risco / críticos abertos", "0", "alert", theme.DANGER)
        self.s_total = StatCard("Incidentes registrados", "0", "database", theme.INFO)
        self.s_fp = StatCard("Falsos positivos revisados", "0", "check-circle", theme.SUCCESS)
        for w in (self.s_inv, self.s_high, self.s_total, self.s_fp):
            stats.addWidget(w)
        root.addLayout(stats)

        tabs = QTabWidget()
        root.addWidget(tabs, 1)
        tabs.addTab(self._incidents_tab(), "Incidentes")
        tabs.addTab(self._intel_tab(), "Inteligência de ameaças")
        tabs.addTab(self._fp_tab(), "Falsos positivos")
        tabs.addTab(self._self_tab(), "Autoproteção")
        tabs.currentChanged.connect(lambda i: [self.refresh_incidents, self.refresh_intel, self.refresh_fp,
                                               self.refresh_self][i]())

        self._debounce = Debouncer(lambda: self.refresh_incidents() if self.isVisible() else None, 600, self)
        ctx.bridge.incident_event.connect(lambda inc, new: self._debounce.trigger())

    # ------------------------------------------------------------------ incidentes
    def _incidents_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 10, 0, 0)
        f = QHBoxLayout()
        self.q = QLineEdit()
        self.q.setPlaceholderText("Buscar por arquivo, ameaça, SHA-256 ou identificador…")
        self.cls = QComboBox()
        self.cls.addItems(["Todas as classificações"] + list(incidents.CLASSES))
        self.st = QComboBox()
        self.st.addItems(["Todos os status"] + list(incidents.STATUSES))
        self.unk = QCheckBox("Só ameaças desconhecidas")
        for x in (self.q, self.cls, self.st, self.unk):
            f.addWidget(x, 2 if x is self.q else 0)
        self.q.textChanged.connect(lambda *_: self._debounce.trigger())
        self.cls.currentIndexChanged.connect(lambda *_: self.refresh_incidents())
        self.st.currentIndexChanged.connect(lambda *_: self.refresh_incidents())
        self.unk.toggled.connect(lambda *_: self.refresh_incidents())
        v.addLayout(f)
        split = QSplitter(Qt.Horizontal)
        left = Card()
        self.table = DataTable(["Data", "Classificação", "Ameaça", "Status"], stretch_col=2)
        for i, wd in enumerate((112, 96, 200)):
            self.table.setColumnWidth(i, wd)
        self.table.itemSelectionChanged.connect(self.show_selected)
        left.lay.addWidget(self.table)
        split.addWidget(left)
        right = Card()
        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(False)
        self.detail.setStyleSheet(f"background:{theme.SURFACE}; border:none;")
        right.lay.addWidget(self.detail, 1)
        acts = QHBoxLayout()
        self.b_confirm = button("Confirmar ameaça", "alert", "danger")
        self.b_fp = button("Falso positivo…", "check", "success")
        self.b_resolve = button("Resolvido", "check-circle")
        self.b_lab = button("Sala de Análise", "flask")
        self.b_confirm.clicked.connect(lambda: self.set_status("ameaça confirmada"))
        self.b_resolve.clicked.connect(lambda: self.set_status("resolvido"))
        self.b_fp.clicked.connect(self.mark_fp)
        self.b_lab.clicked.connect(self.to_lab)
        for b in (self.b_confirm, self.b_fp, self.b_resolve, self.b_lab):
            acts.addWidget(b)
        right.lay.addLayout(acts)
        split.addWidget(right)
        split.setSizes([560, 560])
        v.addWidget(split, 1)
        return w

    def refresh_incidents(self):
        self._refresh_counts()
        cls = self.cls.currentText() if self.cls.currentIndex() > 0 else ""
        st = self.st.currentText() if self.st.currentIndex() > 0 else ""
        rows = incidents.search(self.q.text().strip(), cls, st, self.unk.isChecked())
        sel = self.current["id"] if self.current else None
        self.table.clear_rows()
        with self.table.bulk():
            for inc in rows:
                n = inc.get("ocorrencias", 1)
                self.table.add_row([inc["criado"][5:16], inc["classificacao"],
                                    inc["ameaca"] + (f"  ×{n}" if n > 1 else ""), inc["status"]], data=inc["id"],
                                   colors={1: CLASS_COLORS.get(inc["classificacao"], theme.MUTED),
                                           3: STATUS_COLORS.get(inc["status"], theme.MUTED)})
        if sel:
            for r in range(self.table.rowCount()):
                if self.table.row_data(r) == sel:
                    self.table.selectRow(r)
                    break
        if not rows:
            self.current = None
            self.detail.setHtml(f"<p style='color:{theme.MUTED}'>Nenhum incidente com esses filtros. Detecções de "
                                "todas as proteções (tempo real, verificações, scripts, pen drives, anti-botnet, "
                                "anti-ransomware e inicialização) aparecem aqui com as evidências.</p>")
        self._buttons()

    def _refresh_counts(self):
        c = incidents.counts()
        self.s_inv.set(c["em_investigacao"])
        self.s_high.set(c["alto_risco_abertos"])
        self.s_total.set(c["total"])
        self.s_fp.set(c["falsos_positivos"])

    def show_selected(self):
        ids = [x for x in self.table.selected_data() if x]
        self.current = incidents.get(ids[0]) if ids else None
        self._buttons()
        if not self.current:
            return
        self.detail.setHtml(render_detail(self.current))

    def _buttons(self):
        on = self.current is not None
        for b in (self.b_confirm, self.b_fp, self.b_resolve):
            b.setEnabled(on)
        self.b_lab.setEnabled(on and bool(self.current and os.path.isfile(self.current.get("arquivo") or "")))

    def set_status(self, status: str):
        if not self.current:
            return
        note, ok = QInputDialog.getText(self, status.capitalize(), "Observação da revisão (opcional):")
        if ok:
            incidents.set_status(self.current["id"], status, note)
            self.refresh_incidents()
            self.show_selected()

    def mark_fp(self):
        if not self.current:
            return
        inc = self.current
        just, ok = QInputDialog.getMultiLineText(
            self, "Marcar como falso positivo",
            "Por que esta detecção está errada? (obrigatório — a decisão fica registrada e pode ser desfeita)\n"
            "A exclusão vale só para este conteúdo exato (SHA-256), não para a pasta nem para outros arquivos.")
        if not ok or not just.strip():
            return
        scope = "arquivo"
        if inc.get("regras_acionadas") and inc.get("tipo") != "comportamento":
            choice, ok2 = QInputDialog.getItem(self, "Escopo da exclusão", "O que deixa de valer para este arquivo?",
                                               ["Só as regras que dispararam (recomendado)", "O arquivo inteiro"], 0,
                                               False)
            if not ok2:
                return
            scope = "regras" if choice.startswith("Só") else "arquivo"
        try:
            incidents.mark_false_positive(inc["id"], just, scope)
        except (PermissionError, ValueError) as e:
            QMessageBox.warning(self, "Falso positivo", str(e))
            return
        ev = inc.get("evidencia") or {}
        if ev.get("onde") == "quarentena" and confirm(self, "Restaurar", "O arquivo está na quarentena. "
                                                                          "Restaurar para o local original?"):
            try:
                self.ctx.quarantine.restore(ev["id"])
                self.ctx.bridge.quarantine_changed.emit()
            except Exception as e:
                QMessageBox.warning(self, "Restaurar", str(e))
        self.refresh_incidents()
        self.show_selected()

    def to_lab(self):
        p = (self.current or {}).get("arquivo") or ""
        if os.path.isfile(p):
            run_bg(lambda: self.ctx.lab.add_file(p, "zero-day center"),
                   lambda item_id: self.ctx.bridge.open_in_lab.emit(item_id))

    def export(self, kind: str):
        sel = [x for x in self.table.selected_data() if x]
        incs = [incidents.get(i) for i in sel] if len(sel) > 1 else \
            ([self.current] if self.current else incidents.search(limit=5000))
        if not incs:
            QMessageBox.information(self, "Exportar", "Nenhum incidente para exportar.")
            return
        ext = ".html" if kind == "html" else ".json"
        p, _ = QFileDialog.getSaveFileName(self, "Exportar relatório", f"incidentes-exeav{ext}",
                                           "HTML (*.html)" if kind == "html" else "JSON (*.json)")
        if not p:
            return
        text = incidents.export_html(incs) if kind == "html" else json.dumps(incs, ensure_ascii=False, indent=1)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        QMessageBox.information(self, "Exportar", f"{len(incs)} incidente(s) exportado(s) para {p}")

    # ------------------------------------------------------------------ inteligência
    def _intel_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 10, 0, 0)
        h = QHBoxLayout()
        h.addWidget(label("Fontes públicas validadas (TLS + validação de conteúdo + hash registrado). Indicadores "
                          "expiram se deixarem de aparecer nos feeds.", "muted", wrap=True), 1)
        self.b_upd = button("Atualizar todos", "refresh", "primary")
        b_imp = button("Importar arquivo…", "upload")
        self.b_upd.clicked.connect(self.update_feeds)
        b_imp.clicked.connect(self.import_feed)
        h.addWidget(self.b_upd)
        h.addWidget(b_imp)
        v.addLayout(h)
        self.feeds = DataTable(["Fonte", "Uso", "Indicadores", "Versão", "Atualizado", "Situação"], stretch_col=1)
        for i, wd in enumerate((190, 300, 100, 70, 150)):
            self.feeds.setColumnWidth(i, wd)
        self.feeds.setMaximumHeight(190)
        v.addWidget(self.feeds)
        v.addWidget(label("Histórico de atualizações", "sectionTitle"))
        self.feed_hist = DataTable(["Data", "Fonte", "Resultado", "Novos", "Expirados", "Total", "SHA-256 do download"],
                                   stretch_col=6)
        for i, wd in enumerate((140, 90, 240, 60, 75, 70)):
            self.feed_hist.setColumnWidth(i, wd)
        v.addWidget(self.feed_hist, 1)
        return w

    def refresh_intel(self):
        self.feeds.clear_rows()
        for f in intel.status():
            if f["corrompido"]:
                st, col = "ARQUIVO LOCAL ADULTERADO — ignorado", theme.DANGER
            elif f["atualizado"] == "nunca":
                st, col = "nunca atualizado", theme.MUTED
            elif f["desatualizado"]:
                st, col = f"desatualizado ({f['idade_dias']:.0f} dias)", theme.WARNING
            else:
                st, col = "em dia", theme.SUCCESS
            self.feeds.add_row([f["nome"], f["descricao"], f"{f['indicadores']:,}".replace(",", "."), f["versao"],
                                f["atualizado"], st], data=f["id"], colors={5: col})
        self.feed_hist.clear_rows()
        for r in intel.update_history()[:200]:
            ok = r.get("resultado") == "ok"
            self.feed_hist.add_row([r.get("data", ""), r.get("feed", ""), r.get("resultado", ""), r.get("novos", ""),
                                    r.get("expirados", ""), r.get("total", ""), r.get("sha256", "")],
                                   colors={2: theme.SUCCESS if ok else theme.DANGER})

    def update_feeds(self):
        self.b_upd.setEnabled(False)
        self.b_upd.setText("Atualizando…")

        def done(results):
            self.b_upd.setEnabled(True)
            self.b_upd.setText("Atualizar todos")
            ok = sum(1 for r in results if r.get("resultado") == "ok")
            QMessageBox.information(self, "Inteligência de ameaças", f"{ok} de {len(results)} fonte(s) atualizada(s)."
                                    + ("" if ok == len(results) else " As que falharam mantêm a versão anterior "
                                                                    "(veja o histórico)."))
            self.refresh_intel()
        run_bg(intel.update_all, done, lambda e: (self.b_upd.setEnabled(True), self.b_upd.setText("Atualizar todos")))

    def import_feed(self):
        feed, ok = QInputDialog.getItem(self, "Importar", "Para qual fonte é este arquivo?", list(intel.FEEDS), 0, False)
        if not ok:
            return
        p, _ = QFileDialog.getOpenFileName(self, "Arquivo do feed", "", "Todos (*)")
        if p:
            try:
                r = intel.import_file(feed, p)
                QMessageBox.information(self, "Importar", f"{r['total']} indicador(es); {r['novos']} novo(s).")
            except ValueError as e:
                QMessageBox.warning(self, "Importar", str(e))
            self.refresh_intel()

    # ------------------------------------------------------------------ falsos positivos
    def _fp_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 10, 0, 0)
        h = QHBoxLayout()
        h.addWidget(label("Exclusões específicas por conteúdo (SHA-256). Revogar desfaz a exclusão; o registro "
                          "da decisão é mantido para auditoria.", "muted", wrap=True), 1)
        b_rev = button("Revogar", "restore", "danger")
        b_rev.clicked.connect(self.revoke_fp)
        h.addWidget(b_rev)
        v.addLayout(h)
        self.fp_table = DataTable(["#", "Data", "Escopo", "Ameaça", "Regras", "Motivo", "Situação", "Arquivo"], stretch_col=5)
        for i, wd in enumerate((40, 140, 70, 170, 170)):
            self.fp_table.setColumnWidth(i, wd)
        v.addWidget(self.fp_table, 2)
        v.addWidget(label("Regras com mais falsos positivos confirmados (onde o motor precisa de ajuste)", "sectionTitle"))
        self.rule_table = DataTable(["Regra", "Falsos positivos"], stretch_col=0)
        self.rule_table.setMaximumHeight(160)
        v.addWidget(self.rule_table)
        return w

    def refresh_fp(self):
        self.fp_table.clear_rows()
        for d in fpengine.decisions():
            sit = "ativa" if d["active"] else f"revogada {d['revoked'] or ''}"
            self.fp_table.add_row([d["id"], d["created"], d["scope"], d["threat"], ", ".join(d["rules"]),
                                   d["justification"], sit, d["path"]], data=d["id"],
                                  colors={6: theme.SUCCESS if d["active"] else theme.MUTED})
        self.rule_table.clear_rows()
        for rule, n in fpengine.rule_stats():
            self.rule_table.add_row([rule, n])

    def revoke_fp(self):
        sel = [x for x in self.fp_table.selected_data() if x]
        if sel and confirm(self, "Revogar", f"Revogar a exclusão #{sel[0]}? O arquivo volta a ser avaliado normalmente."):
            fpengine.revoke(sel[0], "revogada pelo usuário")
            self.refresh_fp()

    # ------------------------------------------------------------------ autoproteção
    def _self_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 10, 0, 0)
        h = QHBoxLayout()
        h.addWidget(label("O antivírus confere a integridade dos próprios arquivos, regras, configurações, histórico "
                          "e quarentena.", "muted", wrap=True), 1)
        b_run = button("Verificar agora", "shield", "primary")
        self.b_restore_cfg = button("Restaurar configurações", "restore")
        b_run.clicked.connect(self.refresh_self)
        self.b_restore_cfg.clicked.connect(self.restore_cfg)
        h.addWidget(b_run)
        h.addWidget(self.b_restore_cfg)
        v.addLayout(h)
        self.self_table = DataTable(["Verificação", "Resultado", "Detalhe"], stretch_col=2)
        self.self_table.setColumnWidth(0, 220)
        self.self_table.setColumnWidth(1, 120)
        v.addWidget(self.self_table, 1)
        v.addWidget(label("Limite: um programa com privilégio de administrador pode adulterar arquivos e manifesto "
                          "juntos. Instale em 'Arquivos de Programas' (o instalador faz isso) para que programas comuns "
                          "não consigam alterar o antivírus.", "small", wrap=True))
        return w

    def refresh_self(self):
        run_bg(selfprotect.run_all, self._show_self)

    def _show_self(self, checks):
        self.self_table.clear_rows()
        bad_cfg = False
        for c in checks:
            res = {True: "íntegro", False: "PROBLEMA", None: "não verificável"}[c["ok"]]
            col = {True: theme.SUCCESS, False: theme.DANGER, None: theme.MUTED}[c["ok"]]
            self.self_table.add_row([c["nome"], res, c["detalhe"]], colors={1: col})
            bad_cfg |= c["nome"] == "Configurações" and c["ok"] is False
        self.b_restore_cfg.setEnabled(bad_cfg)

    def restore_cfg(self):
        if confirm(self, "Restaurar", "Voltar às últimas configurações gravadas pelo próprio antivírus?"):
            try:
                selfprotect.restore_config()
                self.ctx.settings = selfprotect.config.get()
                self.ctx.engine.settings = self.ctx.settings
                self.ctx.apply_settings()
            except Exception as e:
                QMessageBox.warning(self, "Restaurar", str(e))
            self.refresh_self()

    def showEvent(self, e):
        super().showEvent(e)
        self.refresh_incidents()


def render_detail(inc: dict) -> str:
    e = html.escape
    col = CLASS_COLORS.get(inc.get("classificacao"), theme.MUTED)
    hs = inc.get("hashes") or {}
    proc = inc.get("processo") or {}
    sig = inc.get("assinatura_digital") or {}
    origin = inc.get("origem") or {}
    rows = [("Identificador", inc["id"]), ("Criado / atualizado", f"{inc['criado']} / {inc.get('atualizado', '')}"),
            ("Status", inc["status"]), ("Confiança", inc.get("confianca") or "—"),
            ("Pontuação", inc.get("pontuacao")), ("Fonte", inc.get("fonte")), ("Arquivo", inc.get("arquivo") or "—"),
            ("Tipo / tamanho", f"{inc.get('tipo', '')} / {inc.get('tamanho') or '—'}"),
            ("SHA-256", hs.get("sha256", "—")), ("SHA-512", hs.get("sha512", "—")), ("SHA3-256", hs.get("sha3_256", "—")),
            ("Assinatura digital", f"{sig.get('status', '—')} {sig.get('detalhe', '')}"),
            ("Origem", ", ".join(f"{k}: {v}" for k, v in origin.items()) or "não registrada pelo sistema"),
            ("Processo", f"{proc.get('nome', '—')} (PID {proc.get('pid', '—')}) {proc.get('linha_de_comando', '')}"),
            ("Cadeia de processos", " ← ".join(f"{p.get('nome', '?')} ({p.get('pid')})" for p in proc.get("cadeia_de_processos", []))
             or "—"),
            ("Conexões", ", ".join(proc.get("conexoes", [])) or "—"),
            ("Regras acionadas", ", ".join(inc.get("regras_acionadas", [])) or "—"),
            ("Tipos de evidência", ", ".join(inc.get("tipos_de_evidencia", [])) or "—"),
            ("Evidência preservada", json.dumps(inc.get("evidencia", {}), ensure_ascii=False)),
            ("Ocorrências", inc.get("ocorrencias", 1)), ("Sistema", inc.get("sistema"))]
    table = "".join(f"<tr><td style='color:{theme.MUTED};padding:2px 10px 2px 0;vertical-align:top'>{e(str(k))}</td>"
                    f"<td style='padding:2px 0'>{e(str(v))}</td></tr>" for k, v in rows)
    inds = "".join(f"<li><b>{e(i.get('name', ''))}</b> <span style='color:{theme.MUTED}'>({e(i.get('category', ''))}, "
                   f"{i.get('weight', '')})</span><br>{e(i.get('description', ''))}</li>" for i in inc.get("indicadores", [])
                   if i.get("weight", 0) != 0 or i.get("id") == "fp.user")
    acts = "".join(f"<li>{e(a)}</li>" for a in inc.get("acoes", []))
    rev = "".join(f"<li>{e(r['quando'])}: {e(r['status'])} — {e(r.get('nota', ''))}</li>" for r in inc.get("revisao", []))
    tag = " · AMEAÇA DESCONHECIDA EM INVESTIGAÇÃO" if inc.get("desconhecida") and inc["status"] == "em investigação" else ""
    return (f"<h3 style='margin:0'>{e(inc.get('ameaca', ''))}</h3>"
            f"<p style='color:{col};font-weight:700;margin:4px 0'>{e(inc.get('classificacao', '').upper())}{tag}</p>"
            f"<p>{e(inc.get('resultado_da_analise', ''))}</p><table>{table}</table>"
            f"<h4>Indicadores</h4><ul>{inds or '<li>—</li>'}</ul><h4>Ações executadas</h4><ul>{acts or '<li>—</li>'}</ul>"
            + (f"<h4>Revisão</h4><ul>{rev}</ul>" if rev else ""))
