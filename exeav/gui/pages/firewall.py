"""Aba Firewall: integração com o firewall do sistema (ufw, firewalld, nftables, OpenSnitch, Windows Firewall)."""
from __future__ import annotations

from PySide6.QtWidgets import QFileDialog, QGridLayout, QHBoxLayout, QInputDialog, QMessageBox, QVBoxLayout, QWidget

from ... import firewall, paths
from .. import theme
from ..widgets import Badge, Card, DataTable, PageHeader, button, confirm, label, run_bg


class FirewallPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        hdr = PageHeader("Firewall", "O antivírus comanda o firewall do sistema: bloqueia endereços de servidores "
                                     "maliciosos e corta a internet de programas suspeitos.", "wall")
        self.badge = Badge("", theme.MUTED)
        b_refresh = button("Atualizar", "refresh")
        b_refresh.clicked.connect(self.refresh)
        hdr.right.addWidget(self.badge)
        hdr.right.addWidget(b_refresh)
        root.addWidget(hdr)

        fw = Card()
        fw.lay.addWidget(label("Firewalls encontrados", "sectionTitle"))
        self.fw_table = DataTable(["Firewall", "Código aberto", "Situação", "Usado para"], stretch_col=3)
        for i, w in enumerate((180, 120, 190)):
            self.fw_table.setColumnWidth(i, w)
        self.fw_table.setFixedHeight(232)
        fw.lay.addWidget(self.fw_table)
        self.note = label("", "small", wrap=True)
        fw.lay.addWidget(self.note)
        root.addWidget(fw)

        grid = QGridLayout()
        grid.setSpacing(14)
        ips = Card()
        ih = QHBoxLayout()
        ih.addWidget(label("Endereços IP bloqueados", "sectionTitle"))
        ih.addStretch(1)
        b_ip = button("Bloquear IP…", "ban", "danger")
        b_unip = button("Desbloquear", "restore")
        b_ip.clicked.connect(self.block_ip)
        b_unip.clicked.connect(self.unblock_ip)
        ih.addWidget(b_ip)
        ih.addWidget(b_unip)
        ips.lay.addLayout(ih)
        self.ip_table = DataTable(["IP", "Motivo", "Firewall", "Data"], stretch_col=1)
        self.ip_table.setColumnWidth(0, 150)
        ips.lay.addWidget(self.ip_table)
        grid.addWidget(ips, 0, 0)

        apps = Card()
        ah = QHBoxLayout()
        ah.addWidget(label("Programas sem internet", "sectionTitle"))
        ah.addStretch(1)
        b_app = button("Bloquear programa…", "ban", "danger")
        b_unapp = button("Liberar", "restore")
        b_app.clicked.connect(self.block_app)
        b_unapp.clicked.connect(self.unblock_app)
        ah.addWidget(b_app)
        ah.addWidget(b_unapp)
        apps.lay.addLayout(ah)
        self.app_table = DataTable(["Programa", "Motivo", "Firewall", "Data"], stretch_col=0)
        apps.lay.addWidget(self.app_table)
        grid.addWidget(apps, 0, 1)
        root.addLayout(grid, 1)
        self.refresh()

    def _admin_hint(self) -> str:
        return "" if firewall.is_admin() else "\n\nExecute o antivírus como administrador para mexer no firewall."

    def block_ip(self):
        ip, ok = QInputDialog.getText(self, "Bloquear IP", "Endereço IP a bloquear (entrada e saída):")
        if ok and ip.strip():
            run_bg(lambda: firewall.block(ip.strip(), "bloqueio manual"), lambda _: self.refresh(),
                   lambda e: (QMessageBox.warning(self, "Firewall", f"Não foi possível bloquear: {e}"
                                                  + self._admin_hint()), self.refresh()))

    def unblock_ip(self):
        sel = [x for x in self.ip_table.selected_data() if x]
        if sel and confirm(self, "Desbloquear", f"Desbloquear {sel[0]} no firewall?"):
            run_bg(lambda: firewall.unblock(sel[0]), lambda _: self.refresh(),
                   lambda e: (QMessageBox.warning(self, "Firewall", str(e)), self.refresh()))

    def block_app(self):
        flt = "Programas (*.exe);;Todos (*)" if paths.IS_WINDOWS else "Todos (*)"
        p, _ = QFileDialog.getOpenFileName(self, "Programa que não pode acessar a internet", "", flt)
        if p:
            run_bg(lambda: firewall.block_app(p, "bloqueio manual"), lambda _: self.refresh(),
                   lambda e: (QMessageBox.warning(self, "Firewall", f"Não foi possível bloquear: {e}"
                                                  + self._admin_hint()), self.refresh()))

    def unblock_app(self):
        sel = [x for x in self.app_table.selected_data() if x]
        if sel and confirm(self, "Liberar", f"Liberar a internet para {sel[0]}?"):
            run_bg(lambda: firewall.unblock_app(sel[0]), lambda _: self.refresh(),
                   lambda e: (QMessageBox.warning(self, "Firewall", str(e)), self.refresh()))

    def refresh(self):
        run_bg(lambda: (firewall.detect(), firewall.backend(), firewall.app_backend(), firewall.is_admin()),
               self._show)

    def _show(self, info):
        found, ip_kind, app_kind, admin = info
        self.badge.set(f"IPs: {firewall.NAMES.get(ip_kind, 'indisponível')}",
                       theme.SUCCESS if ip_kind else theme.DANGER)
        self.fw_table.clear_rows()
        for f in found:
            if not f["installed"]:
                st, col = "não instalado", theme.MUTED
            elif f.get("in_use"):
                st, col = "em uso pelo antivírus", theme.SUCCESS
            elif f["active"]:
                st, col = "instalado e ativo", theme.INFO
            else:
                st, col = "instalado, desligado", theme.MUTED
            self.fw_table.add_row([f["name"], "sim" if f["open_source"] else "não", st, f["use"]], colors={2: col})
        notes = []
        if not paths.IS_WINDOWS:
            notes.append("Ordem de preferência para bloquear IPs: ufw (se ativo) → firewalld (se ativo) → nftables → "
                         "iptables. Com ufw/firewalld os bloqueios ficam salvos no próprio firewall; com nftables/"
                         "iptables o antivírus os reaplica toda vez que o computador liga.")
            if not app_kind:
                notes.append("Para cortar a internet de um programa específico, instale o OpenSnitch (firewall de "
                             "aplicativos de código aberto): sudo apt install opensnitch")
        else:
            notes.append("No Windows o antivírus usa o Windows Firewall (regras permanentes, por IP e por programa).")
        if not admin:
            notes.append("Sem permissão de administrador: os bloqueios não podem ser criados agora.")
        self.note.setText(" ".join(notes))
        self.ip_table.clear_rows()
        for ip, d in sorted(firewall.blocked().items(), key=lambda kv: kv[1].get("date", ""), reverse=True):
            self.ip_table.add_row([ip, d.get("reason", ""), firewall.NAMES.get(d.get("backend"), d.get("backend") or ""),
                                   d.get("date", "")], data=ip)
        self.app_table.clear_rows()
        for p, d in sorted(firewall.blocked_apps().items(), key=lambda kv: kv[1].get("date", ""), reverse=True):
            self.app_table.add_row([p, d.get("reason", ""), firewall.NAMES.get(d.get("backend"), d.get("backend") or ""),
                                    d.get("date", "")], data=p)

    def showEvent(self, e):
        super().showEvent(e)
        self.refresh()
