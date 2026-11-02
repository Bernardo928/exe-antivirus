"""Aba de proteção em tempo real."""
from __future__ import annotations

import datetime

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QGridLayout, QHBoxLayout, QListWidget,
                               QVBoxLayout, QWidget)

from ... import paths
from .. import theme
from ..widgets import Badge, Card, DataTable, PageHeader, StatCard, button, label


class RealtimePage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        s = ctx.settings
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        hdr = PageHeader("Proteção em tempo real", "Monitora arquivos novos/alterados e processos iniciados, "
                                                    "bloqueando ameaças no momento em que aparecem.", "activity")
        self.badge = Badge("Desligada", theme.DANGER)
        self.toggle = button("Ativar", "power", "success")
        self.toggle.clicked.connect(self.toggle_rt)
        hdr.right.addWidget(self.badge)
        hdr.right.addWidget(self.toggle)
        root.addWidget(hdr)

        stats = QHBoxLayout()
        stats.setSpacing(12)
        self.s_files = StatCard("Arquivos analisados", "0", "file", theme.ACCENT)
        self.s_procs = StatCard("Processos verificados", "0", "cpu", theme.INFO)
        self.s_block = StatCard("Ameaças bloqueadas", "0", "shield", theme.DANGER)
        self.s_dirs = StatCard("Pastas monitoradas", "0", "folder", theme.SUCCESS)
        for w in (self.s_files, self.s_procs, self.s_block, self.s_dirs):
            stats.addWidget(w)
        root.addLayout(stats)

        mid = QGridLayout()
        mid.setSpacing(14)
        opts = Card()
        opts.lay.addWidget(label("Escudos", "sectionTitle"))
        self.c_proc = QCheckBox("Monitor de processos — analisa todo programa que for executado")
        self.c_kill = QCheckBox("Encerrar automaticamente processos maliciosos")
        self.c_ransom = QCheckBox("Escudo anti-ransomware — detecta criptografia em massa de arquivos")
        self.c_proc.setChecked(s.realtime_process_monitor)
        self.c_kill.setChecked(s.realtime_kill_malicious_process)
        self.c_ransom.setChecked(s.ransomware_shield)
        for c in (self.c_proc, self.c_kill, self.c_ransom):
            opts.lay.addWidget(c)
            c.toggled.connect(self.save_opts)
        row = QHBoxLayout()
        row.addWidget(label("Ao detectar ameaça maliciosa:", "muted"))
        self.action = QComboBox()
        self.action.addItems(["Colocar em quarentena automaticamente", "Apenas notificar"])
        self.action.setCurrentIndex(0 if s.auto_action == "quarantine" else 1)
        self.action.currentIndexChanged.connect(self.save_opts)
        row.addWidget(self.action, 1)
        opts.lay.addLayout(row)
        opts.lay.addWidget(label("Arquivos apenas suspeitos geram um alerta e podem ser enviados à quarentena ou "
                                 "à Sala de Análise manualmente.", "small", wrap=True))
        opts.lay.addStretch(1)
        mid.addWidget(opts, 0, 0)

        dirs = Card()
        dh = QHBoxLayout()
        dh.addWidget(label("Pastas monitoradas", "sectionTitle"))
        dh.addStretch(1)
        add = button("Adicionar", "plus")
        rem = button("Remover", "minus")
        add.clicked.connect(self.add_dir)
        rem.clicked.connect(self.remove_dir)
        dh.addWidget(add)
        dh.addWidget(rem)
        dirs.lay.addLayout(dh)
        self.dirs = QListWidget()
        self.dirs.setMinimumHeight(150)
        dirs.lay.addWidget(self.dirs)
        mid.addWidget(dirs, 0, 1)

        sc = Card()
        sh = QHBoxLayout()
        sh.addWidget(label("Análise de scripts por dentro", "sectionTitle"))
        self.sc_badge = Badge("", theme.MUTED)
        sh.addWidget(self.sc_badge)
        sh.addStretch(1)
        self.c_scripts = QCheckBox("Ativada")
        self.c_scripts.setChecked(s.script_guard)
        self.c_scripts.toggled.connect(self.toggle_scripts)
        sh.addWidget(self.c_scripts)
        self.b_pslog = button("Ligar registro do PowerShell", "terminal", "primary")
        self.b_pslog.clicked.connect(self.enable_pslog)
        self.b_pslog.setVisible(paths.IS_WINDOWS)
        sh.addWidget(self.b_pslog)
        sc.lay.addLayout(sh)
        self.sc_info = label("", "small", wrap=True)
        sc.lay.addWidget(self.sc_info)
        mid.addWidget(sc, 1, 0, 1, 2)
        root.addLayout(mid)

        feed = Card()
        feed.lay.addWidget(label("Eventos em tempo real", "sectionTitle"))
        self.feed = DataTable(["Hora", "Ameaça", "Veredito", "Ação", "Arquivo"], stretch_col=4)
        for i, w in enumerate((90, 230, 90, 200)):
            self.feed.setColumnWidth(i, w)
        feed.lay.addWidget(self.feed)
        root.addWidget(feed, 1)

        ctx.bridge.rt_event.connect(self.on_event)
        ctx.bridge.script_event.connect(lambda k, d: self.on_event("threat", d) if k in ("threat", "suspeito")
                                        else self.refresh_scripts())
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh_stats)
        self._timer.start(1500)
        self.refresh()

    def save_opts(self, *_):
        s = self.ctx.settings
        s.realtime_process_monitor = self.c_proc.isChecked()
        s.realtime_kill_malicious_process = self.c_kill.isChecked()
        s.ransomware_shield = self.c_ransom.isChecked()
        s.auto_action = "quarantine" if self.action.currentIndex() == 0 else "notify"
        self.ctx.apply_settings()

    def toggle_rt(self):
        rt = self.ctx.realtime
        if rt.running:
            rt.stop()
            self.ctx.settings.realtime_enabled = False
        else:
            rt.start()
            self.ctx.settings.realtime_enabled = True
        self.ctx.apply_settings()
        self.refresh()

    def toggle_scripts(self, on: bool):
        g = self.ctx.scripts
        if on and not g.running:
            g.start()
        elif not on and g.running:
            g.stop()
        self.ctx.settings.script_guard = on
        self.ctx.apply_settings()
        self.refresh_scripts()

    def enable_pslog(self):
        from PySide6.QtWidgets import QMessageBox

        from ... import scriptguard
        try:
            scriptguard.enable_logging(True)
            QMessageBox.information(self, "PowerShell", "Registro de blocos de script ligado. A partir de agora o "
                                    "antivírus vê o código do PowerShell já decodificado, mesmo quando o vírus "
                                    "tenta escondê-lo.")
        except OSError as e:
            QMessageBox.warning(self, "PowerShell", f"É preciso executar o antivírus como administrador.\n\n{e}")
        self.refresh_scripts()

    def refresh_scripts(self):
        g = self.ctx.scripts
        on = g.running
        self.sc_badge.set("Ativa" if on else "Desligada", theme.SUCCESS if on else theme.DANGER)
        txt = (f"{g.blocks_analyzed} trecho(s) de código analisado(s), {g.threats_blocked} bloqueado(s). "
               "Olha o código que realmente está rodando: ")
        if paths.IS_WINDOWS:
            ready = g.powershell_ready
            self.b_pslog.setVisible(not ready)
            txt += ("PowerShell decodificado pelo próprio Windows (registro de blocos de script "
                    + ("ligado" if ready else "DESLIGADO — clique em ligar; sem ele só os blocos que o Windows "
                       "já considera suspeitos são vistos") + ") e scripts abertos por wscript/cscript/mshta.")
        else:
            txt += ("scripts que o shell está executando — inclusive os que o vírus apagou do disco para se "
                    "esconder — e downloads executados direto (curl | sh).")
        self.sc_info.setText(txt)

    def _restart_if_running(self):
        if self.ctx.realtime.running:
            self.ctx.realtime.restart()

    def add_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Pasta para monitorar")
        if d and d not in self.ctx.settings.realtime_dirs:
            self.ctx.settings.realtime_dirs.append(d)
            self.ctx.apply_settings()
            self._restart_if_running()
            self.refresh()

    def remove_dir(self):
        it = self.dirs.currentItem()
        if it and it.text() in self.ctx.settings.realtime_dirs:
            self.ctx.settings.realtime_dirs.remove(it.text())
            self.ctx.apply_settings()
            self._restart_if_running()
            self.refresh()

    def on_event(self, kind, data):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        if kind == "threat":
            c = theme.VERDICT_COLORS.get(data.verdict, theme.WARNING)
            r = self.feed.add_row([now, data.threat_name, data.verdict, data.action, data.path], data=data,
                                  colors={1: c, 2: c})
            self.feed.scrollToItem(self.feed.item(r, 0))
        elif kind == "ransomware":
            proc = data.get("process") or {}
            self.feed.add_row([now, "ATIVIDADE DE RANSOMWARE", "malicioso",
                               "processo suspenso" if data.get("suspended") else "alerta",
                               f"{data['count']} arquivos cifrados · processo: {proc.get('name', '?')} "
                               f"(PID {proc.get('pid', '?')})"], colors={1: theme.DANGER, 2: theme.DANGER})
        self.refresh()

    def refresh_stats(self):
        if not self.isVisible():
            return
        rt = self.ctx.realtime
        self.s_files.set(rt.files_scanned)
        self.s_procs.set(rt.processes_checked)
        self.s_block.set(rt.threats_blocked)
        self.s_dirs.set(len(rt.watched) if rt.running else 0)
        self.refresh_scripts()

    def refresh(self):
        rt = self.ctx.realtime
        on = rt.running
        self.badge.set("Ativa" if on else "Desligada", theme.SUCCESS if on else theme.DANGER)
        self.toggle.setText("Desativar" if on else "Ativar")
        self.toggle.setObjectName("danger" if on else "success")
        self.toggle.style().unpolish(self.toggle)
        self.toggle.style().polish(self.toggle)
        self.dirs.clear()
        self.dirs.addItems(self.ctx.settings.realtime_dirs)
        self.refresh_stats()
