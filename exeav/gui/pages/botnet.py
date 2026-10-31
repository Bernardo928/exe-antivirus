"""Aba Anti-Botnet."""
from __future__ import annotations

import datetime

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (QCheckBox, QFileDialog, QGridLayout, QHBoxLayout, QInputDialog, QMessageBox,
                               QVBoxLayout, QWidget)

from ... import firewall
from ...engine.models import MALICIOUS
from .. import theme
from ..widgets import Badge, Card, DataTable, PageHeader, StatCard, button, confirm, label, run_bg


class BotnetPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        s = ctx.settings
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        hdr = PageHeader("Anti-Botnet", "Impede que o computador seja controlado à distância e usado em ataques: "
                                        "vigia a rede de cada programa e bloqueia comportamento de bot.", "network")
        self.badge = Badge("Desligado", theme.DANGER)
        self.b_check = button("Analisar agora", "search")
        self.toggle = button("Ativar", "power", "success")
        self.b_check.clicked.connect(self.check_now)
        self.toggle.clicked.connect(self.toggle_shield)
        hdr.right.addWidget(self.badge)
        hdr.right.addWidget(self.b_check)
        hdr.right.addWidget(self.toggle)
        root.addWidget(hdr)

        stats = QHBoxLayout()
        stats.setSpacing(12)
        self.s_procs = StatCard("Programas na rede", "0", "cpu", theme.INFO)
        self.s_conns = StatCard("Conexões analisadas", "0", "globe", theme.ACCENT)
        self.s_bots = StatCard("Bots bloqueados", "0", "shield", theme.DANGER)
        self.s_ips = StatCard("IPs bloqueados", "0", "ban", theme.WARNING)
        self.s_c2 = StatCard("Servidores C2", "0", "database", "#a78bfa")
        for w in (self.s_procs, self.s_conns, self.s_bots, self.s_ips, self.s_c2):
            stats.addWidget(w)
        root.addLayout(stats)

        mid = QGridLayout()
        mid.setSpacing(14)
        opts = Card()
        opts.lay.addWidget(label("O que o escudo vigia", "sectionTitle"))
        opts.lay.addWidget(label(
            "Conexões com servidores de comando (C2) • varredura de outros computadores para se espalhar • ataques "
            "DDoS • contato periódico com servidor (beaconing) • portas de IRC/trojans/Tor/mineração • backdoor "
            "aberto para a rede • programa rodando de pasta temporária, apagado do disco ou disfarçado de processo "
            "do sistema.", "muted", wrap=True))
        self.c_kill = QCheckBox("Encerrar e isolar automaticamente os bots")
        self.c_fw = QCheckBox("Bloquear no firewall os servidores de comando usados pelo bot")
        self.c_kill.setChecked(s.botnet_auto_kill)
        self.c_fw.setChecked(s.botnet_firewall_block)
        for c in (self.c_kill, self.c_fw):
            c.toggled.connect(self.save_opts)
            opts.lay.addWidget(c)
        kind = firewall.backend()
        opts.lay.addWidget(label(f"Firewall: {({'windows': 'Windows Firewall', 'nft': 'nftables', 'iptables': 'iptables'}).get(kind, 'indisponível')}"
                                 " — bloquear IPs exige executar como administrador.", "small", wrap=True))
        opts.lay.addWidget(label("Programas do sistema, programas assinados e o próprio antivírus nunca são "
                                 "encerrados: nesses casos o escudo apenas alerta.", "small", wrap=True))
        opts.lay.addStretch(1)
        mid.addWidget(opts, 0, 0)

        c2 = Card()
        c2.lay.addWidget(label("Lista de servidores de comando (C2)", "sectionTitle"))
        c2.lay.addWidget(label("Endereços de servidores que controlam botnets conhecidas (Emotet, QakBot, "
                               "Dridex...). Qualquer programa que fale com eles é bloqueado na hora.", "muted",
                               wrap=True))
        h = QHBoxLayout()
        self.b_update = button("Atualizar lista online", "download", "primary")
        b_import = button("Importar arquivo…", "upload")
        b_manual = button("Bloquear IP…", "ban")
        self.b_update.clicked.connect(self.update_c2)
        b_import.clicked.connect(self.import_c2)
        b_manual.clicked.connect(self.block_manual)
        for b in (self.b_update, b_import, b_manual):
            h.addWidget(b)
        h.addStretch(1)
        c2.lay.addLayout(h)
        c2.lay.addWidget(label("Fonte: Feodo Tracker (abuse.ch). Também aceita listas de IPs em texto.", "small"))
        c2.lay.addStretch(1)
        mid.addWidget(c2, 0, 1)
        root.addLayout(mid)

        det = Card()
        det.lay.addWidget(label("Detecções", "sectionTitle"))
        self.table = DataTable(["Hora", "Programa", "PID", "Pontos", "Veredito", "Ação", "Por quê"], stretch_col=6)
        for i, w in enumerate((80, 170, 70, 70, 90, 260)):
            self.table.setColumnWidth(i, w)
        det.lay.addWidget(self.table)
        root.addWidget(det, 2)

        fw = Card()
        fh = QHBoxLayout()
        fh.addWidget(label("IPs bloqueados no firewall", "sectionTitle"))
        fh.addStretch(1)
        b_unblock = button("Desbloquear", "restore")
        b_unblock.clicked.connect(self.unblock)
        fh.addWidget(b_unblock)
        fw.lay.addLayout(fh)
        self.fw_table = DataTable(["IP", "Motivo", "Programa", "Data"], stretch_col=2)
        self.fw_table.setColumnWidth(0, 160)
        self.fw_table.setColumnWidth(1, 200)
        self.fw_table.setMaximumHeight(170)
        fw.lay.addWidget(self.fw_table)
        root.addWidget(fw, 1)

        ctx.bridge.botnet_event.connect(self.on_event)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh_stats)
        self._timer.start(2000)
        self.refresh()

    # ------------------------------------------------------------------ ações
    def save_opts(self, *_):
        s = self.ctx.settings
        s.botnet_auto_kill = self.c_kill.isChecked()
        s.botnet_firewall_block = self.c_fw.isChecked()
        self.ctx.apply_settings()

    def toggle_shield(self):
        sh = self.ctx.botnet
        if sh.running:
            sh.stop()
        else:
            sh.start()
        self.ctx.settings.botnet_shield = sh.running
        self.ctx.apply_settings()
        self.refresh()

    def check_now(self):
        self.b_check.setEnabled(False)

        def done(reps):
            self.b_check.setEnabled(True)
            if not reps:
                QMessageBox.information(self, "Anti-Botnet", "Nenhum comportamento de botnet encontrado agora.")
            self.refresh()
        run_bg(self.ctx.botnet.check_now, done, lambda e: (self.b_check.setEnabled(True),
                                                           QMessageBox.warning(self, "Anti-Botnet", str(e))))

    def update_c2(self):
        self.b_update.setEnabled(False)
        self.b_update.setText("Baixando…")

        def finish(msg, ok=True):
            self.b_update.setEnabled(True)
            self.b_update.setText("Atualizar lista online")
            (QMessageBox.information if ok else QMessageBox.warning)(self, "Servidores C2", msg)
            self.refresh_stats()
        run_bg(lambda: self.ctx.botnet.c2.update(self.ctx.settings.botnet_c2_url),
               lambda n: finish(f"{n} novo(s) servidor(es) de comando adicionado(s)."),
               lambda e: finish(f"Não foi possível atualizar: {e}", False))

    def import_c2(self):
        p, _ = QFileDialog.getOpenFileName(self, "Lista de IPs de servidores C2", "", "Texto (*.txt *.csv);;Todos (*)")
        if p:
            n = self.ctx.botnet.c2.import_file(p)
            QMessageBox.information(self, "Servidores C2", f"{n} novo(s) IP(s) importado(s).")
            self.refresh_stats()

    def block_manual(self):
        ip, ok = QInputDialog.getText(self, "Bloquear IP", "Endereço IP a bloquear (entrada e saída):")
        if ok and ip.strip():
            try:
                firewall.block(ip.strip(), "bloqueio manual")
            except Exception as e:
                QMessageBox.warning(self, "Firewall", f"Não foi possível bloquear: {e}")
            self.refresh()

    def unblock(self):
        sel = [x for x in self.fw_table.selected_data() if x]
        if sel and confirm(self, "Desbloquear", f"Desbloquear {sel[0]} no firewall?"):
            try:
                firewall.unblock(sel[0])
            except Exception as e:
                QMessageBox.warning(self, "Firewall", str(e))
            self.refresh()

    # ------------------------------------------------------------------ exibição
    def on_event(self, kind, rep):
        if kind not in ("botnet", "suspeito"):
            self.refresh()
            return
        now = datetime.datetime.now().strftime("%H:%M:%S")
        c = theme.DANGER if rep.verdict == MALICIOUS else theme.WARNING
        r = self.table.add_row([now, rep.name, rep.pid, rep.score, "BOT" if rep.verdict == MALICIOUS else "suspeito",
                                rep.action, " • ".join(rep.reasons())], data=rep, colors={1: c, 4: c})
        self.table.scrollToItem(self.table.item(r, 0))
        self.refresh()

    def refresh_stats(self):
        sh = self.ctx.botnet
        self.s_procs.set(sh.processes_watched)
        self.s_conns.set(f"{sh.connections_seen:,}".replace(",", "."))
        self.s_bots.set(sum(1 for v in sh._handled.values() if v == MALICIOUS))
        self.s_ips.set(len(firewall.blocked()))
        self.s_c2.set(f"{len(sh.c2.ips):,}".replace(",", "."))

    def refresh(self):
        on = self.ctx.botnet.running
        self.badge.set("Ativo" if on else "Desligado", theme.SUCCESS if on else theme.DANGER)
        self.toggle.setText("Desativar" if on else "Ativar")
        self.toggle.setObjectName("danger" if on else "success")
        self.toggle.style().unpolish(self.toggle)
        self.toggle.style().polish(self.toggle)
        self.fw_table.clear_rows()
        with self.fw_table.bulk():
            for ip, d in sorted(firewall.blocked().items(), key=lambda kv: kv[1].get("date", ""), reverse=True):
                self.fw_table.add_row([ip, d.get("reason", ""), d.get("process", ""), d.get("date", "")], data=ip)
        self.refresh_stats()
