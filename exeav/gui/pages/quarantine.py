"""Aba Quarentena."""
from __future__ import annotations

from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QMessageBox, QStackedWidget, QVBoxLayout, QWidget

from ... import util
from .. import theme
from ..widgets import Card, DataTable, EmptyState, PageHeader, button, confirm, label, run_bg


class QuarantinePage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        root.addWidget(PageHeader("Quarentena", "Arquivos perigosos isolados e cifrados: não podem ser executados "
                                                "nem afetar o sistema. Você pode restaurá-los ou excluí-los.", "lock"))
        card = Card()
        h = QHBoxLayout()
        self.count = label("", "sectionTitle")
        h.addWidget(self.count)
        h.addStretch(1)
        self.b_lab = button("Analisar", "flask", "primary", "Enviar uma cópia para a Sala de Análise")
        self.b_restore = button("Restaurar", "restore")
        self.b_restore_to = button("Restaurar em…", "folder")
        self.b_delete = button("Excluir", "trash", "danger")
        self.b_delete_all = button("Esvaziar quarentena", "trash", "danger")
        for b in (self.b_lab, self.b_restore, self.b_restore_to, self.b_delete, self.b_delete_all):
            h.addWidget(b)
        card.lay.addLayout(h)
        self.stack = QStackedWidget()
        self.table = DataTable(["Ameaça", "Veredito", "Pontos", "Data", "Tamanho", "Local original"], stretch_col=5)
        for i, w in enumerate((240, 90, 70, 165, 90)):
            self.table.setColumnWidth(i, w)
        self.table.setSortingEnabled(True)
        self.table.doubleClicked.connect(lambda *_: self.analyze())
        self.stack.addWidget(self.table)
        self.stack.addWidget(EmptyState("shield-check", "Quarentena vazia",
                                        "Nenhuma ameaça isolada. Quando algo perigoso for encontrado, ficará aqui."))
        card.lay.addWidget(self.stack)
        root.addWidget(card, 1)
        info = label("Como funciona: o arquivo é removido do local original e guardado cifrado na pasta de dados do "
                     "antivírus, sem permissão de execução. Restaurar devolve o arquivo exatamente como era.", "small",
                     wrap=True)
        root.addWidget(info)

        self.b_lab.clicked.connect(self.analyze)
        self.b_restore.clicked.connect(lambda: self.restore(False))
        self.b_restore_to.clicked.connect(lambda: self.restore(True))
        self.b_delete.clicked.connect(self.delete)
        self.b_delete_all.clicked.connect(self.delete_all)
        ctx.bridge.quarantine_changed.connect(self.refresh)
        self.refresh()

    def refresh(self):
        items = self.ctx.quarantine.items()
        self.table.clear_rows()
        for it in items:
            c = theme.VERDICT_COLORS.get(it.get("verdict"), theme.WARNING)
            self.table.add_row([it.get("threat_name", ""), it.get("verdict", ""), it.get("score", 0),
                                it.get("date", ""), util.human_size(it.get("size", 0)), it.get("original_path", "")],
                               data=it["id"], colors={0: c, 1: c})
        self.count.setText(f"{len(items)} item(ns) isolado(s)")
        self.stack.setCurrentIndex(0 if items else 1)
        for b in (self.b_lab, self.b_restore, self.b_restore_to, self.b_delete, self.b_delete_all):
            b.setEnabled(bool(items))

    def _selected(self):
        return [x for x in self.table.selected_data() if x]

    def analyze(self):
        sel = self._selected()
        if not sel:
            return
        item_id = sel[0]
        q = self.ctx.quarantine

        def work():
            meta = q.meta(item_id)
            existing = self.ctx.lab.find_by_hash(meta.get("sha256", ""))
            if existing:
                return existing
            data = q.read(item_id)
            import os
            return self.ctx.lab.add_bytes(data, os.path.basename(meta.get("original_path", "amostra")),
                                          meta.get("original_path", ""), "quarentena")
        run_bg(work, lambda lab_id: self.ctx.bridge.open_in_lab.emit(lab_id))

    def restore(self, choose: bool):
        sel = self._selected()
        if not sel:
            return
        if not confirm(self, "Restaurar", "Restaurar arquivo(s) da quarentena? Só faça isso se tiver certeza de que "
                                          "é um falso positivo. Considere adicioná-lo às exclusões."):
            return
        done = []
        for item_id in sel:
            dest = None
            if choose:
                meta = self.ctx.quarantine.meta(item_id)
                import os
                dest, _ = QFileDialog.getSaveFileName(self, "Restaurar como", os.path.basename(meta["original_path"]))
                if not dest:
                    continue
            try:
                done.append(self.ctx.quarantine.restore(item_id, dest))
            except Exception as e:
                QMessageBox.warning(self, "Restaurar", f"Falha ao restaurar: {e}")
        if done:
            add = QMessageBox.question(self, "Restaurado", "Arquivo(s) restaurado(s):\n" + "\n".join(done) +
                                       "\n\nAdicionar às exclusões para não ser detectado novamente?")
            if add == QMessageBox.Yes:
                for p in done:
                    if p not in self.ctx.settings.exclusions:
                        self.ctx.settings.exclusions.append(p)
                self.ctx.apply_settings()
        self.refresh()

    def delete(self):
        sel = self._selected()
        if sel and confirm(self, "Excluir", f"Excluir definitivamente {len(sel)} item(ns)?"):
            for item_id in sel:
                self.ctx.quarantine.delete(item_id)
            self.refresh()

    def delete_all(self):
        items = self.ctx.quarantine.items()
        if items and confirm(self, "Esvaziar", f"Excluir definitivamente TODOS os {len(items)} itens da quarentena?"):
            for it in items:
                self.ctx.quarantine.delete(it["id"])
            self.refresh()
