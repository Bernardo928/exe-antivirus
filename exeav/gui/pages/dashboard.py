"""Painel principal."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QScrollArea, QVBoxLayout, QWidget

from ... import VERSION, history
from .. import theme
from ..widgets import Card, DataTable, Debouncer, PageHeader, ShieldStatus, StatCard, button, label


class DashboardPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        body = QWidget()
        scroll.setWidget(body)
        outer.addWidget(scroll)
        root = QVBoxLayout(body)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(18)
        root.addWidget(PageHeader("Painel", "Visão geral da proteção do seu computador.", "home"))

        # Banner de status
        banner = Card()
        bl = QHBoxLayout()
        bl.setSpacing(24)
        self.shield = ShieldStatus()
        bl.addWidget(self.shield)
        info = QVBoxLayout()
        info.setSpacing(6)
        self.status_title = label("Você está protegido", "pageTitle")
        self.status_text = label("", "muted", wrap=True)
        info.addStretch(1)
        info.addWidget(self.status_title)
        info.addWidget(self.status_text)
        btns = QHBoxLayout()
        btns.setSpacing(10)
        self.quick_btn = button("Scan rápido", "zap", "primary")
        self.full_btn = button("Scan completo", "drive")
        self.rt_btn = button("Ativar tempo real", "activity", "success")
        self.quick_btn.clicked.connect(lambda: self._scan("quick"))
        self.full_btn.clicked.connect(lambda: self._scan("full"))
        self.rt_btn.clicked.connect(self._toggle_rt)
        btns.addWidget(self.quick_btn)
        btns.addWidget(self.full_btn)
        btns.addWidget(self.rt_btn)
        btns.addStretch(1)
        info.addSpacing(8)
        info.addLayout(btns)
        info.addStretch(1)
        bl.addLayout(info, 1)
        banner.lay.addLayout(bl)
        root.addWidget(banner)

        grid = QGridLayout()
        grid.setSpacing(14)
        self.s_rt = StatCard("Proteção em tempo real", "—", "activity", theme.SUCCESS)
        self.s_quar = StatCard("Itens em quarentena", "0", "lock", theme.WARNING)
        self.s_det = StatCard("Ameaças detectadas (total)", "0", "alert", theme.DANGER)
        self.s_lab = StatCard("Amostras na Sala de Análise", "0", "flask", theme.INFO)
        self.s_last = StatCard("Última verificação", "Nunca", "clock", theme.ACCENT)
        self.s_sig = StatCard("Regras + assinaturas", "—", "database", "#a78bfa")
        for i, w in enumerate((self.s_rt, self.s_quar, self.s_det, self.s_lab, self.s_last, self.s_sig)):
            grid.addWidget(w, i // 3, i % 3)
        root.addLayout(grid)

        ev = Card()
        hl = QHBoxLayout()
        hl.addWidget(label("Atividade recente", "sectionTitle"))
        hl.addStretch(1)
        more = button("Ver histórico", "clock")
        more.clicked.connect(lambda: ctx.bridge.navigate.emit("history"))
        hl.addWidget(more)
        ev.lay.addLayout(hl)
        self.events = DataTable(["Quando", "Tipo", "Evento"], stretch_col=2)
        self.events.setMinimumHeight(260)
        self.events.setColumnWidth(0, 165)
        self.events.setColumnWidth(1, 120)
        ev.lay.addWidget(self.events)
        root.addWidget(ev)
        foot = label(f"EXE Antivirus {VERSION} · detecção por conteúdo, comportamento e estrutura — nunca pelo nome do arquivo.", "small")
        foot.setAlignment(Qt.AlignCenter)
        root.addWidget(foot)

        self._debounce = Debouncer(lambda: self.refresh() if self.isVisible() else None, 500, self)
        ctx.bridge.history_event.connect(self._debounce.trigger)
        ctx.bridge.rt_event.connect(self._debounce.trigger)
        ctx.bridge.scan_finished.connect(self._debounce.trigger)

    def _scan(self, kind: str):
        self.ctx.bridge.navigate.emit("scan")
        self.ctx.bridge.navigate.emit(f"scan:{kind}")

    def _toggle_rt(self):
        rt = self.ctx.realtime
        if rt.running:
            rt.stop()
            self.ctx.settings.realtime_enabled = False
        else:
            rt.start()
            self.ctx.settings.realtime_enabled = True
        self.ctx.apply_settings()
        self.refresh()

    def refresh(self):
        ctx = self.ctx
        rt_on = ctx.realtime.running
        quar = len(ctx.quarantine.items())
        recent_threats = history.count("detecção")
        s = ctx.settings
        if not rt_on:
            self.shield.set_state("danger")
            self.status_title.setText("Proteção em tempo real desligada")
            self.status_text.setText("Seu computador não está sendo monitorado continuamente. Ative a proteção em "
                                     "tempo real para bloquear ameaças assim que aparecerem.")
        elif not s.last_scan:
            self.shield.set_state("warn")
            self.status_title.setText("Protegido — faça a primeira verificação")
            self.status_text.setText("A proteção em tempo real está ativa. Recomendamos um scan rápido agora para "
                                     "verificar o que já está no computador.")
        else:
            self.shield.set_state("ok")
            self.status_title.setText("Você está protegido")
            self.status_text.setText(f"Proteção em tempo real ativa em {len(ctx.realtime.watched)} pasta(s) e "
                                     f"monitorando processos. Última verificação: {s.last_scan}.")
        self.rt_btn.setText("Desativar tempo real" if rt_on else "Ativar tempo real")
        self.rt_btn.setObjectName("danger" if rt_on else "success")
        self.rt_btn.style().unpolish(self.rt_btn)
        self.rt_btn.style().polish(self.rt_btn)
        self.s_rt.set("Ativa" if rt_on else "Desligada")
        self.s_quar.set(quar)
        self.s_det.set(recent_threats)
        self.s_lab.set(len(ctx.lab.items()))
        self.s_last.set(s.last_scan or "Nunca")
        self.s_sig.set(f"{len(ctx.engine.rules.rules)} + {ctx.sigdb.count:,}".replace(",", "."))
        self.events.clear_rows()
        colors = {"detecção": theme.DANGER, "quarentena": theme.WARNING, "bloqueio": theme.DANGER,
                  "ransomware": theme.DANGER, "scan": theme.ACCENT, "tempo real": theme.SUCCESS}
        with self.events.bulk():
            for ts, kind, msg, path in history.recent(40):
                self.events.add_row([ts, kind, msg + (f" — {path}" if path else "")],
                                    colors={1: colors.get(kind, theme.MUTED)})
