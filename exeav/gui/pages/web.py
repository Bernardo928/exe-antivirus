"""Aba Proteção Web: DNS da Mullvad e bloqueio de sites."""
from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (QButtonGroup, QGridLayout, QHBoxLayout, QInputDialog, QMessageBox, QPushButton,
                               QVBoxLayout, QWidget)

from ... import dnsguard, firewall, history
from .. import theme
from ..widgets import Badge, Card, DataTable, PageHeader, StatCard, button, confirm, label, run_bg


class WebPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        hdr = PageHeader("Proteção Web", "DNS da Mullvad criptografado: bloqueia sites de golpe e malware, "
                                         "anúncios e rastreadores antes de o navegador abrir a página.", "web")
        self.badge = Badge("DNS original", theme.MUTED)
        self.b_apply = button("Ativar DNS da Mullvad", "shield", "primary")
        self.b_off = button("Voltar ao DNS original", "restore")
        self.b_apply.clicked.connect(self.apply)
        self.b_off.clicked.connect(self.revert)
        hdr.right.addWidget(self.badge)
        hdr.right.addWidget(self.b_off)
        hdr.right.addWidget(self.b_apply)
        root.addWidget(hdr)

        stats = QHBoxLayout()
        stats.setSpacing(12)
        self.s_mode = StatCard("Modo", "—", "web", theme.ACCENT)
        self.s_sites = StatCard("Sites bloqueados por você", "0", "ban", theme.DANGER)
        self.s_queries = StatCard("Consultas (servidor local)", "—", "activity", theme.INFO)
        for w in (self.s_mode, self.s_sites, self.s_queries):
            stats.addWidget(w)
        root.addLayout(stats)

        prof = Card()
        prof.lay.addWidget(label("Filtro do DNS da Mullvad", "sectionTitle"))
        prof.lay.addWidget(label("Gratuito, sem cadastro e sem guardar registros. As consultas vão criptografadas "
                                 "(ninguém na rede vê nem altera os sites que você acessa).", "muted", wrap=True))
        grid = QGridLayout()
        grid.setSpacing(10)
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        self.choices: dict[str, QPushButton] = {}
        for i, (key, p) in enumerate(dnsguard.PROFILES.items()):
            b = QPushButton(f"{p['title']}\n{p['desc']}")
            b.setObjectName("choice")
            b.setCheckable(True)
            b.setMinimumHeight(64)
            b.setToolTip(f"{p['host']} — {p['ip4']} / {p['ip6']}")
            self.group.addButton(b)
            self.choices[key] = b
            grid.addWidget(b, i // 3, i % 3)
        prof.lay.addLayout(grid)
        cur = dnsguard.state().get("profile") or ctx.settings.dns_profile or "base"
        self.choices.get(cur, self.choices["base"]).setChecked(True)
        self.mode_lbl = label("", "small", wrap=True)
        prof.lay.addWidget(self.mode_lbl)
        root.addWidget(prof)

        sites = Card()
        sh = QHBoxLayout()
        sh.addWidget(label("Sites bloqueados por você", "sectionTitle"))
        sh.addStretch(1)
        b_add = button("Bloquear site…", "plus", "danger")
        b_rem = button("Desbloquear", "minus")
        b_add.clicked.connect(self.add_site)
        b_rem.clicked.connect(self.remove_site)
        sh.addWidget(b_add)
        sh.addWidget(b_rem)
        sites.lay.addLayout(sh)
        self.table = DataTable(["Site", "Também bloqueia"], stretch_col=1)
        self.table.setColumnWidth(0, 280)
        sites.lay.addWidget(self.table)
        sites.lay.addWidget(label(
            "Funciona com qualquer DNS (arquivo hosts do sistema). Importante: se o navegador estiver com "
            "\"DNS seguro\" próprio ligado (Chrome/Edge: Privacidade → Usar DNS seguro; Firefox: DNS via HTTPS), "
            "ele ignora o DNS do sistema — desligue essa opção para a proteção valer no navegador.",
            "small", wrap=True))
        root.addWidget(sites, 1)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh_stats)
        self._timer.start(3000)
        self.refresh()

    # ------------------------------------------------------------------ ações
    def _selected(self) -> str:
        return next((k for k, b in self.choices.items() if b.isChecked()), "base")

    def apply(self):
        prof = self._selected()
        self.b_apply.setEnabled(False)

        def done(mode):
            self.ctx.settings.dns_profile = prof
            self.ctx.apply_settings()
            self.b_apply.setEnabled(True)
            QMessageBox.information(self, "Proteção Web", f"DNS da Mullvad ativado ({dnsguard.PROFILES[prof]['title']})."
                                    f"\nModo: {dnsguard.MODE_NAMES[mode]}.")
            self.refresh()

        def fail(e):
            self.b_apply.setEnabled(True)
            QMessageBox.warning(self, "Proteção Web", "Não foi possível trocar o DNS"
                                + ("" if firewall.is_admin() else " — execute o antivírus como administrador") + f".\n\n{e}")
            self.refresh()
        run_bg(lambda: dnsguard.apply(prof, self.ctx.settings.dns_blocked_sites), done, fail)

    def revert(self):
        def done(_):
            self.ctx.settings.dns_profile = ""
            self.ctx.apply_settings()
            self.refresh()
        run_bg(dnsguard.revert, done, lambda e: (QMessageBox.warning(self, "Proteção Web", str(e)), self.refresh()))

    def _save_sites(self, sites: list[str]) -> bool:
        try:
            dnsguard.apply_sites(sites)
        except PermissionError:
            QMessageBox.warning(self, "Bloquear site", "É preciso executar o antivírus como administrador para "
                                                       "alterar o arquivo hosts do sistema.")
            return False
        except OSError as e:
            QMessageBox.warning(self, "Bloquear site", str(e))
            return False
        self.ctx.settings.dns_blocked_sites = sites
        self.ctx.apply_settings()
        return True

    def add_site(self):
        text, ok = QInputDialog.getText(self, "Bloquear site", "Endereço do site (ex.: exemplo.com):")
        if not ok or not text.strip():
            return
        try:
            dom = dnsguard.normalize_domain(text)
        except ValueError as e:
            QMessageBox.warning(self, "Bloquear site", str(e))
            return
        sites = list(self.ctx.settings.dns_blocked_sites)
        if dom not in sites and self._save_sites(sites + [dom]):
            history.log("proteção web", f"Site bloqueado: {dom}")
        self.refresh()

    def remove_site(self):
        sel = [d for d in self.table.selected_data() if d]
        if sel and confirm(self, "Desbloquear", f"Desbloquear {sel[0]}?"):
            sites = [s for s in self.ctx.settings.dns_blocked_sites if s != sel[0]]
            if self._save_sites(sites):
                history.log("proteção web", f"Site desbloqueado: {sel[0]}")
            self.refresh()

    # ------------------------------------------------------------------ exibição
    def refresh_stats(self):
        px = dnsguard.proxy()
        self.s_queries.set(f"{px.queries} • {px.blocked_count} bloq." if px else "—")
        self.s_sites.set(len(self.ctx.settings.dns_blocked_sites))

    def refresh(self):
        cur = dnsguard.current()
        if cur["active"]:
            title = dnsguard.PROFILES.get(cur["profile"], {}).get("title", cur["profile"])
            self.badge.set(f"Mullvad: {title}", theme.SUCCESS)
            self.s_mode.set({"windows-doh": "DoH (Windows)", "resolved": "DoT (resolved)",
                             "proxy": "Servidor local"}.get(cur["mode"], cur["mode"]))
            self.mode_lbl.setText(f"Ativo via {dnsguard.MODE_NAMES.get(cur['mode'], cur['mode'])}. Para trocar o "
                                  "filtro, escolha outro e clique em Ativar.")
        elif cur["profile"]:
            self.badge.set("Pausado", theme.WARNING)
            self.s_mode.set("Pausado")
            self.mode_lbl.setText("O DNS da Mullvad está configurado, mas pausado (o servidor local precisa do "
                                  "antivírus aberto como administrador).")
        else:
            self.badge.set("DNS original", theme.MUTED)
            self.s_mode.set("—")
            self.mode_lbl.setText("Ao ativar, o antivírus usa o método mais seguro disponível: DNS-over-HTTPS nativo "
                                  "do Windows 11, DNS-over-TLS do systemd-resolved no Linux ou, se o sistema não "
                                  "tiver suporte, um servidor DNS local que conversa com a Mullvad por HTTPS. "
                                  "Exige executar como administrador.")
        self.b_off.setEnabled(bool(cur["profile"]))
        self.table.clear_rows()
        for d in sorted(self.ctx.settings.dns_blocked_sites):
            self.table.add_row([d, f"www.{d}" + (" e todos os subdomínios (servidor local)"
                                                  if cur["mode"] == "proxy" and cur["active"] else "")], data=d)
        self.refresh_stats()
