"""Aba Pen drives: proteção de dispositivos removíveis."""
from __future__ import annotations

import datetime

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QCheckBox, QHBoxLayout, QVBoxLayout, QWidget

from ... import util
from .. import theme
from ..widgets import Badge, Card, DataTable, PageHeader, StatCard, button, label


class UsbPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        s = ctx.settings
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        hdr = PageHeader("Pen drives", "Verifica pen drives, cartões de memória e HDs externos assim que são "
                                       "conectados e desfaz o vírus de atalho.", "usb")
        self.badge = Badge("Desligada", theme.DANGER)
        self.toggle = button("Ativar", "power", "success")
        self.toggle.clicked.connect(self.toggle_guard)
        hdr.right.addWidget(self.badge)
        hdr.right.addWidget(self.toggle)
        root.addWidget(hdr)

        stats = QHBoxLayout()
        stats.setSpacing(12)
        self.s_conn = StatCard("Conectados agora", "0", "usb", theme.INFO)
        self.s_scanned = StatCard("Dispositivos verificados", "0", "check-circle", theme.SUCCESS)
        self.s_threats = StatCard("Ameaças encontradas", "0", "shield", theme.DANGER)
        for w in (self.s_conn, self.s_scanned, self.s_threats):
            stats.addWidget(w)
        root.addLayout(stats)

        dev = Card()
        dh = QHBoxLayout()
        dh.addWidget(label("Dispositivos conectados", "sectionTitle"))
        dh.addStretch(1)
        self.b_scan = button("Verificar agora", "search", "primary")
        self.b_scan.clicked.connect(self.scan_selected)
        dh.addWidget(self.b_scan)
        dev.lay.addLayout(dh)
        self.devs = DataTable(["Dispositivo", "Sistema de arquivos", "Tamanho", "Situação"], stretch_col=3)
        for i, w in enumerate((280, 150, 110)):
            self.devs.setColumnWidth(i, w)
        self.devs.setMaximumHeight(170)
        dev.lay.addWidget(self.devs)
        self.c_auto = QCheckBox("Verificar automaticamente todo dispositivo conectado")
        self.c_fix = QCheckBox("Desfazer o vírus de atalho (mostrar de novo as pastas escondidas)")
        self.c_auto.setChecked(s.usb_auto_scan)
        self.c_fix.setChecked(s.usb_fix_shortcut_virus)
        for c in (self.c_auto, self.c_fix):
            c.toggled.connect(self.save_opts)
            dev.lay.addWidget(c)
        dev.lay.addWidget(label("A verificação roda em segundo plano com prioridade baixa. Arquivos que já foram "
                                "verificados e não mudaram são pulados (cache).", "small", wrap=True))
        root.addWidget(dev)

        ev = Card()
        ev.lay.addWidget(label("Detecções em pen drives", "sectionTitle"))
        self.table = DataTable(["Hora", "Ameaça", "Veredito", "Ação", "Arquivo"], stretch_col=4)
        for i, w in enumerate((80, 220, 90, 260)):
            self.table.setColumnWidth(i, w)
        ev.lay.addWidget(self.table)
        root.addWidget(ev, 1)

        self._progress: dict[str, str] = {}
        ctx.bridge.usb_event.connect(self.on_event)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh_stats)
        self._timer.start(2000)
        self.refresh()

    def save_opts(self, *_):
        s = self.ctx.settings
        s.usb_auto_scan = self.c_auto.isChecked()
        s.usb_fix_shortcut_virus = self.c_fix.isChecked()
        self.ctx.apply_settings()

    def toggle_guard(self):
        g = self.ctx.usb
        if g.running:
            g.stop()
        else:
            g.start()
        self.ctx.settings.usb_guard = g.running
        self.ctx.apply_settings()
        self.refresh()

    def scan_selected(self):
        sel = [d for d in self.devs.selected_data() if d] or self.ctx.usb.connected()[:1]
        for d in sel:
            self.ctx.usb.scan_drive(d)
            self._progress[d.key] = "verificando…"
        self.refresh_devices()

    def on_event(self, kind, data):
        if kind == "progress":
            d, st = data
            self._progress[d.key] = f"verificando… {st.files} arquivo(s)"
            self.refresh_devices()
            return
        if kind == "done":
            d, st = data
            n = len(st.threats)
            self._progress[d.key] = f"verificado: {st.files} arquivo(s), " + (f"{n} ameaça(s)" if n else "limpo")
        elif kind in ("threat", "finding"):
            r = data[2] if kind == "finding" else data
            now = datetime.datetime.now().strftime("%H:%M:%S")
            c = theme.VERDICT_COLORS.get(r.verdict, theme.WARNING)
            row = self.table.add_row([now, r.threat_name, r.verdict, r.action, r.path], data=r, colors={1: c, 2: c})
            self.table.scrollToItem(self.table.item(row, 0))
        elif kind == "inserted":
            self._progress[data.key] = "conectado"
        elif kind == "removed":
            self._progress.pop(data.key, None)
        self.refresh()

    def refresh_devices(self):
        self.devs.clear_rows()
        for d in self.ctx.usb.connected():
            st = self._progress.get(d.key) or ("verificando…" if self.ctx.usb.is_scanning(d) else "não verificado")
            col = theme.DANGER if "ameaça" in st else theme.SUCCESS if "limpo" in st else theme.MUTED
            self.devs.add_row([d.title(), d.fstype, util.human_size(d.total) if d.total else "—", st], data=d,
                              colors={3: col})

    def refresh_stats(self):
        g = self.ctx.usb
        self.s_conn.set(len(g.connected()))
        self.s_scanned.set(g.drives_scanned)
        self.s_threats.set(g.threats_found)

    def refresh(self):
        on = self.ctx.usb.running
        self.badge.set("Ativa" if on else "Desligada", theme.SUCCESS if on else theme.DANGER)
        self.toggle.setText("Desativar" if on else "Ativar")
        self.toggle.setObjectName("danger" if on else "success")
        self.toggle.style().unpolish(self.toggle)
        self.toggle.style().polish(self.toggle)
        self.refresh_devices()
        self.refresh_stats()
