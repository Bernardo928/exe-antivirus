"""Abas Processos, Inicialização e Rede."""
from __future__ import annotations

import os

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (QCheckBox, QComboBox, QHBoxLayout, QLineEdit, QMessageBox, QSpinBox, QVBoxLayout,
                               QWidget)

from ... import util
from ...system import network, processes, startup
from .. import theme
from ..widgets import Badge, Card, DataTable, PageHeader, button, confirm, label, open_location, run_bg


def _send_to_lab(ctx, path: str):
    if not path or not os.path.isfile(path):
        QMessageBox.information(None, "Sala de Análise", "Arquivo não encontrado ou inacessível.")
        return

    def work():
        return ctx.lab.add_file(path, "sistema")
    run_bg(work, lambda item_id: ctx.bridge.open_in_lab.emit(item_id))


# --------------------------------------------------------------------------- processos
class ProcessesPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.verdicts: dict[str, object] = {}
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        root.addWidget(PageHeader("Processos", "Programas em execução agora. Verifique os executáveis, encerre "
                                               "processos perigosos ou envie-os para a Sala de Análise.", "cpu"))
        card = Card()
        h = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filtrar por nome, PID ou caminho…")
        self.filter.textChanged.connect(self.populate)
        h.addWidget(self.filter, 1)
        self.b_refresh = button("Atualizar", "refresh")
        self.b_scan = button("Verificar todos", "shield", "primary")
        self.b_lab = button("Analisar", "flask")
        self.b_kill = button("Encerrar", "x-circle", "danger")
        self.b_open = button("", "external", tip="Abrir local do executável")
        for b in (self.b_refresh, self.b_scan, self.b_lab, self.b_kill, self.b_open):
            h.addWidget(b)
        card.lay.addLayout(h)
        self.table = DataTable(["Processo", "PID", "Usuário", "Memória", "Verificação", "Executável"], stretch_col=5)
        for i, w in enumerate((200, 70, 140, 90, 200)):
            self.table.setColumnWidth(i, w)
        self.table.setSortingEnabled(True)
        card.lay.addWidget(self.table)
        self.status = label("", "small")
        card.lay.addWidget(self.status)
        root.addWidget(card, 1)
        self.procs: list[dict] = []
        self.b_refresh.clicked.connect(self.refresh)
        self.b_scan.clicked.connect(self.scan_all)
        self.b_lab.clicked.connect(lambda: [_send_to_lab(ctx, p["exe"]) for p in self.table.selected_data()[:1] if p])
        self.b_kill.clicked.connect(self.kill)
        self.b_open.clicked.connect(lambda: [open_location(p["exe"]) for p in self.table.selected_data()[:1] if p and p["exe"]])

    def refresh(self):
        run_bg(processes.list_processes, self._set)

    def _set(self, procs):
        self.procs = procs
        self.populate()

    def populate(self, *_):
        flt = self.filter.text().lower()
        self.table.clear_rows()
        self.table.setSortingEnabled(False)
        for p in self.procs:
            if flt and flt not in f"{p['name']} {p['pid']} {p['exe']}".lower():
                continue
            v = self.verdicts.get(p["exe"])
            if p["self"]:
                vt, col = "EXE Antivirus (protegido)", theme.ACCENT
            elif v is None:
                vt, col = ("não verificado" if p["exe"] else "— (sem executável acessível)"), theme.MUTED
            elif v.is_threat:
                vt, col = f"{v.verdict.upper()}: {v.threat_name}", theme.VERDICT_COLORS[v.verdict]
            else:
                vt, col = "limpo", theme.SUCCESS
            colors = {4: col}
            if v is not None and v.is_threat:
                colors[0] = col
            self.table.add_row([p["name"], p["pid"], p["user"], util.human_size(p["mem"]), vt, p["exe"]], data=p,
                               colors=colors)
        self.table.setSortingEnabled(True)
        n = sum(1 for v in self.verdicts.values() if v.is_threat)
        self.status.setText(f"{len(self.procs)} processos · {len(self.verdicts)} executáveis verificados · {n} ameaça(s)")

    def scan_all(self):
        exes = sorted({p["exe"] for p in self.procs if p["exe"] and not p["self"]})
        self.b_scan.setEnabled(False)
        self.b_scan.setText("Verificando…")

        def work():
            out = {}
            for e in exes:
                if self.ctx.engine.exclusions.is_excluded(e):
                    continue
                try:
                    out[e] = self.ctx.engine.scan_file(e).result
                except Exception:
                    continue
            return out

        def done(res):
            self.verdicts.update(res)
            self.b_scan.setEnabled(True)
            self.b_scan.setText("Verificar todos")
            self.populate()
            threats = [r for r in res.values() if r.is_threat]
            if threats:
                QMessageBox.warning(self, "Processos", f"{len(threats)} processo(s) perigoso(s) encontrado(s):\n\n" +
                                    "\n".join(f"{r.threat_name} — {r.path}" for r in threats[:10]))
        run_bg(work, done)

    def kill(self):
        sel = [p for p in self.table.selected_data() if p]
        if not sel or not confirm(self, "Encerrar", f"Encerrar {sel[0]['name']} (PID {sel[0]['pid']})?"):
            return
        try:
            processes.kill(sel[0]["pid"])
        except Exception as e:
            QMessageBox.warning(self, "Encerrar", f"Não foi possível encerrar: {e}")
        QTimer.singleShot(300, self.refresh)

    def showEvent(self, e):
        super().showEvent(e)
        if not self.procs:
            self.refresh()


# --------------------------------------------------------------------------- inicialização
class StartupPage(QWidget):
    """Programas que iniciam com o sistema + proteção ao ligar o computador."""
    MODES = [("desconhecidos", "Bloquear programas desconhecidos (sem assinatura digital)"),
             ("todos", "Bloquear tudo o que não for do sistema e não for liberado por mim"),
             ("avisar", "Só avisar, não bloquear nada")]

    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        s = ctx.settings
        self.decisions: list = []
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        hdr = PageHeader("Inicialização", "Toda vez que o computador liga, o antivírus decide o que pode abrir junto "
                                          "com o sistema, bloqueia o resto e faz um scan em segundo plano.", "power")
        self.badge = Badge("", theme.MUTED)
        self.toggle = button("Ativar", "power", "success")
        self.toggle.clicked.connect(self.toggle_guard)
        hdr.right.addWidget(self.badge)
        hdr.right.addWidget(self.toggle)
        root.addWidget(hdr)

        opts = Card()
        opts.lay.addWidget(label("Ao ligar o computador", "sectionTitle"))
        row = QHBoxLayout()
        row.addWidget(label("Programas que iniciam junto:", "muted"))
        self.mode = QComboBox()
        for _k, t in self.MODES:
            self.mode.addItem(t)
        self.mode.setCurrentIndex(next((i for i, (k, _t) in enumerate(self.MODES) if k == s.boot_block_mode), 0))
        self.mode.currentIndexChanged.connect(self.save_opts)
        row.addWidget(self.mode, 1)
        opts.lay.addLayout(row)
        row2 = QHBoxLayout()
        self.c_scan = QCheckBox("Fazer um scan rápido em segundo plano")
        self.c_scan.setChecked(s.boot_scan)
        self.c_scan.toggled.connect(self.save_opts)
        row2.addWidget(self.c_scan)
        row2.addWidget(label("começando", "muted"))
        self.delay = QSpinBox()
        self.delay.setRange(0, 3600)
        self.delay.setSuffix(" s depois de ligar")
        self.delay.setValue(s.boot_scan_delay)
        self.delay.valueChanged.connect(self.save_opts)
        row2.addWidget(self.delay)
        row2.addStretch(1)
        opts.lay.addLayout(row2)
        self.info = label("", "small", wrap=True)
        opts.lay.addWidget(self.info)
        root.addWidget(opts)

        card = Card()
        h = QHBoxLayout()
        h.addWidget(label("Programas que iniciam com o sistema", "sectionTitle"))
        h.addStretch(1)
        self.b_refresh = button("Atualizar", "refresh")
        self.b_lab = button("Analisar", "flask")
        self.b_allow = button("Liberar", "check", "success")
        self.b_block = button("Bloquear", "ban", "danger")
        self.b_now = button("Aplicar agora", "shield", "primary")
        for b in (self.b_refresh, self.b_lab, self.b_allow, self.b_block, self.b_now):
            h.addWidget(b)
        card.lay.addLayout(h)
        self.table = DataTable(["Nome", "Origem", "Decisão", "Motivo", "Comando"], stretch_col=4)
        for i, w in enumerate((190, 150, 100, 300)):
            self.table.setColumnWidth(i, w)
        card.lay.addWidget(self.table)
        root.addWidget(card, 2)

        dis = Card()
        dh = QHBoxLayout()
        dh.addWidget(label("Bloqueados pelo antivírus", "sectionTitle"))
        dh.addStretch(1)
        self.b_restore = button("Liberar e devolver à inicialização", "restore")
        dh.addWidget(self.b_restore)
        dis.lay.addLayout(dh)
        self.dis_table = DataTable(["Nome", "Origem", "Quando", "Comando"], stretch_col=3)
        for i, w in enumerate((190, 150, 150)):
            self.dis_table.setColumnWidth(i, w)
        self.dis_table.setMaximumHeight(180)
        dis.lay.addWidget(self.dis_table)
        root.addWidget(dis, 1)

        self.b_refresh.clicked.connect(self.refresh)
        self.b_lab.clicked.connect(lambda: [_send_to_lab(ctx, d["item"]["target"])
                                            for d in self.table.selected_data()[:1] if d])
        self.b_allow.clicked.connect(self.allow_selected)
        self.b_block.clicked.connect(self.block_selected)
        self.b_now.clicked.connect(self.apply_now)
        self.b_restore.clicked.connect(self.restore_selected)
        ctx.bridge.boot_event.connect(self.on_event)
        self._loaded = False
        self.show_state()

    # ------------------------------------------------------------------ opções
    def save_opts(self, *_):
        s = self.ctx.settings
        s.boot_block_mode = self.MODES[self.mode.currentIndex()][0]
        s.boot_scan = self.c_scan.isChecked()
        s.boot_scan_delay = self.delay.value()
        self.ctx.apply_settings()
        self.show_state()

    def toggle_guard(self):
        g = self.ctx.boot
        if g.running:
            g.stop()
        else:
            g.start()
        self.ctx.settings.boot_guard = g.running
        self.ctx.apply_settings()
        self.show_state()

    def show_state(self):
        g = self.ctx.boot
        on = g.running
        self.badge.set("Ativa" if on else "Desligada", theme.SUCCESS if on else theme.DANGER)
        self.toggle.setText("Desativar" if on else "Ativar")
        self.toggle.setObjectName("danger" if on else "success")
        self.toggle.style().unpolish(self.toggle)
        self.toggle.style().polish(self.toggle)
        parts = []
        if g.blocked_this_boot:
            parts.append(f"{g.blocked_this_boot} programa(s) bloqueado(s) desde que o computador ligou.")
        if g.boot_scan_state:
            parts.append(f"Scan em segundo plano: {g.boot_scan_state}.")
        parts.append("Bloquear = encerrar o programa, cortar a internet dele no firewall e tirá-lo da inicialização "
                     "(com cópia de segurança). Itens novos que aparecem com o computador ligado também são avaliados.")
        self.info.setText(" ".join(parts))

    # ------------------------------------------------------------------ listas
    def refresh(self):
        self.b_refresh.setEnabled(False)
        run_bg(lambda: (self.ctx.boot.classify(startup.list_items()), startup.list_disabled()), self._set,
               lambda e: self.b_refresh.setEnabled(True))

    def _set(self, data):
        decisions, disabled = data
        self.b_refresh.setEnabled(True)
        self._loaded = True
        self.decisions = decisions
        colors = {"liberado": theme.SUCCESS, "bloqueado": theme.DANGER, "aviso": theme.WARNING}
        self.table.clear_rows()
        with self.table.bulk():
            for d in decisions:
                it = d["item"]
                self.table.add_row([it["name"], it["source"], d["decision"], d["reason"], it["command"]], data=d,
                                   colors={2: colors.get(d["decision"], theme.MUTED)})
        self.dis_table.clear_rows()
        for r in disabled:
            it = r["item"]
            when = r.get("date", "")
            when = f"{when[6:8]}/{when[4:6]} {when[9:11]}:{when[11:13]}" if len(when) >= 13 else when
            self.dis_table.add_row([it["name"], it["source"], when, it["command"]], data=r)
        self.show_state()

    # ------------------------------------------------------------------ ações
    def allow_selected(self):
        sel = [d for d in self.table.selected_data() if d]
        if not sel:
            return
        d = sel[0]
        self.ctx.boot.allow(d["key"], target=d["item"].get("target") or "")
        self.refresh()

    def block_selected(self):
        sel = [d for d in self.table.selected_data() if d]
        if not sel:
            return
        d = sel[0]
        if not d["item"].get("removable", True):
            QMessageBox.information(self, "Inicialização", "Este item é do sistema ou exige edição manual "
                                    f"(local: {d['item']['location']}).")
            return
        if confirm(self, "Bloquear", f"Bloquear '{d['item']['name']}'? Ele será encerrado, perderá a internet e "
                                     "não vai mais abrir junto com o computador."):
            d["reason"] = "bloqueado por você"
            run_bg(lambda: self.ctx.boot.block(d, remember=True), lambda _: self.refresh(),
                   lambda e: (QMessageBox.warning(self, "Bloquear", f"Falhou (talvez precise de administrador): {e}"),
                              self.refresh()))

    def restore_selected(self):
        sel = [r for r in self.dis_table.selected_data() if r]
        if not sel:
            return
        r = sel[0]
        it = r["item"]
        from ...bootguard import item_key
        try:
            self.ctx.boot.allow(item_key(it), r["id"], it.get("target") or "")
        except Exception as e:
            QMessageBox.warning(self, "Liberar", f"Não foi possível restaurar (talvez precise de administrador): {e}")
        self.refresh()

    def apply_now(self):
        self.b_now.setEnabled(False)
        run_bg(self.ctx.boot.check_now, lambda _: (self.b_now.setEnabled(True), self.refresh()),
               lambda e: (self.b_now.setEnabled(True), QMessageBox.warning(self, "Inicialização", str(e))))

    def on_event(self, kind, data):
        if kind in ("blocked", "boot_scan", "status"):
            self.show_state()
            if kind == "blocked" and self.isVisible():
                self.refresh()

    def showEvent(self, e):
        super().showEvent(e)
        if not self._loaded:
            self.refresh()


# --------------------------------------------------------------------------- rede
class NetworkPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.conns: list[dict] = []
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        root.addWidget(PageHeader("Rede", "Conexões abertas por cada programa e verificação do arquivo hosts contra "
                                          "redirecionamentos maliciosos.", "globe"))
        card = Card()
        h = QHBoxLayout()
        self.c_listen = QCheckBox("Mostrar portas em escuta")
        self.c_listen.setChecked(True)
        self.c_listen.toggled.connect(self.populate)
        h.addWidget(self.c_listen)
        h.addStretch(1)
        self.b_refresh = button("Atualizar", "refresh", "primary")
        self.b_lab = button("Analisar programa", "flask")
        self.b_kill = button("Encerrar programa", "x-circle", "danger")
        for b in (self.b_refresh, self.b_lab, self.b_kill):
            h.addWidget(b)
        card.lay.addLayout(h)
        self.table = DataTable(["Programa", "PID", "Protocolo", "Local", "Remoto", "Estado", "Alerta"], stretch_col=6)
        for i, w in enumerate((180, 70, 80, 180, 200, 110)):
            self.table.setColumnWidth(i, w)
        self.table.setSortingEnabled(True)
        card.lay.addWidget(self.table, 1)
        root.addWidget(card, 2)
        hc = Card()
        hh = QHBoxLayout()
        hh.addWidget(label("Arquivo hosts", "sectionTitle"))
        self.hosts_status = label("", "muted")
        hh.addWidget(self.hosts_status, 1)
        self.b_hosts = button("Abrir pasta", "external")
        self.b_hosts.clicked.connect(lambda: open_location(network.hosts_path()))
        hh.addWidget(self.b_hosts)
        hc.lay.addLayout(hh)
        self.hosts = DataTable(["Linha", "Domínio", "Aponta para", "Problema"], stretch_col=3)
        self.hosts.setMaximumHeight(170)
        hc.lay.addWidget(self.hosts)
        root.addWidget(hc, 1)
        self.b_refresh.clicked.connect(self.refresh)
        self.b_lab.clicked.connect(lambda: [_send_to_lab(ctx, c["exe"]) for c in self.table.selected_data()[:1] if c])
        self.b_kill.clicked.connect(self.kill)

    def refresh(self):
        run_bg(lambda: (network.connections(), network.check_hosts()), self._set)

    def _set(self, res):
        self.conns, issues = res
        self.populate()
        self.hosts.clear_rows()
        for i in issues:
            self.hosts.add_row([i["line"], i["host"], i["ip"], i["problem"]], colors={3: theme.DANGER})
        self.hosts_status.setText(f"{len(issues)} problema(s) encontrado(s)" if issues else "Nenhum redirecionamento suspeito")
        self.hosts_status.setStyleSheet(f"color: {theme.DANGER if issues else theme.SUCCESS};")

    def populate(self, *_):
        self.table.clear_rows()
        self.table.setSortingEnabled(False)
        for c in self.conns:
            if not self.c_listen.isChecked() and c["status"] == "LISTEN":
                continue
            col = theme.DANGER if c["flag"] else None
            self.table.add_row([c["process"] or "?", c["pid"], c["proto"], c["local"], c["remote"] or "—", c["status"],
                                c["flag"]], data=c, colors={0: col, 6: col} if col else None)
        self.table.setSortingEnabled(True)

    def kill(self):
        sel = [c for c in self.table.selected_data() if c and c["pid"]]
        if sel and confirm(self, "Encerrar", f"Encerrar {sel[0]['process']} (PID {sel[0]['pid']})?"):
            try:
                processes.kill(sel[0]["pid"])
            except Exception as e:
                QMessageBox.warning(self, "Encerrar", str(e))
            QTimer.singleShot(300, self.refresh)

    def showEvent(self, e):
        super().showEvent(e)
        if not self.conns:
            self.refresh()
