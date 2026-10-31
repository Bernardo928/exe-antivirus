"""Aba Histórico."""
from __future__ import annotations

import csv

from PySide6.QtWidgets import QComboBox, QFileDialog, QHBoxLayout, QLineEdit, QVBoxLayout, QWidget

from ... import history
from .. import theme
from ..widgets import Card, DataTable, Debouncer, PageHeader, button, confirm

KINDS = ["Todos", "detecção", "quarentena", "bloqueio", "ransomware", "scan", "tempo real", "análise", "restauração",
         "exclusão", "recuperação", "backup", "inicialização", "assinaturas", "anti-botnet", "firewall"]
COLORS = {"detecção": theme.DANGER, "bloqueio": theme.DANGER, "ransomware": theme.DANGER,
          "quarentena": theme.WARNING, "scan": theme.ACCENT, "tempo real": theme.SUCCESS, "análise": theme.INFO}


class HistoryPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        root.addWidget(PageHeader("Histórico", "Registro de tudo o que o antivírus fez: verificações, detecções, "
                                               "bloqueios e ações.", "clock"))
        card = Card()
        h = QHBoxLayout()
        self.kind = QComboBox()
        self.kind.addItems(KINDS)
        self.kind.currentIndexChanged.connect(self.refresh)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Buscar…")
        self.search.textChanged.connect(self.refresh)
        h.addWidget(self.kind)
        h.addWidget(self.search, 1)
        exp = button("Exportar CSV", "download")
        clr = button("Limpar", "trash", "danger")
        exp.clicked.connect(self.export)
        clr.clicked.connect(self.clear)
        h.addWidget(exp)
        h.addWidget(clr)
        card.lay.addLayout(h)
        self.table = DataTable(["Data/hora", "Tipo", "Evento", "Caminho"], stretch_col=3)
        for i, w in enumerate((165, 120, 420)):
            self.table.setColumnWidth(i, w)
        card.lay.addWidget(self.table)
        root.addWidget(card, 1)
        self._debounce = Debouncer(lambda: self.refresh() if self.isVisible() else None, 500, self)
        ctx.bridge.history_event.connect(self._debounce.trigger)
        self.search.textChanged.disconnect()
        self._search_debounce = Debouncer(self.refresh, 250, self)
        self.search.textChanged.connect(self._search_debounce.trigger)

    def _rows(self):
        k = self.kind.currentText()
        rows = history.recent(5000, None if k == "Todos" else k)
        q = self.search.text().lower()
        return [r for r in rows if not q or q in " ".join(r).lower()]

    def refresh(self, *_):
        self.table.clear_rows()
        rows = self._rows()
        with self.table.bulk():
            for ts, kind, msg, path in rows[:1500]:
                self.table.add_row([ts, kind, msg, path], colors={1: COLORS.get(kind, theme.MUTED)})

    def export(self):
        dest, _ = QFileDialog.getSaveFileName(self, "Exportar histórico", "historico-exe-antivirus.csv")
        if dest:
            with open(dest, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f, delimiter=";")
                w.writerow(["data", "tipo", "evento", "caminho"])
                w.writerows(self._rows())

    def clear(self):
        if confirm(self, "Limpar", "Apagar todo o histórico?"):
            history.clear()
            self.refresh()

    def showEvent(self, e):
        super().showEvent(e)
        self.refresh()
