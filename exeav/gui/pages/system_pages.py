"""Abas Processos, Inicialização e Rede."""
from __future__ import annotations

import os

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QCheckBox, QHBoxLayout, QLineEdit, QMessageBox, QVBoxLayout, QWidget

from ... import util
from ...system import network, processes, startup
from .. import theme
from ..widgets import Card, DataTable, PageHeader, button, confirm, label, open_location, run_bg


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
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.items: list[dict] = []
        self.verdicts: dict[str, object] = {}
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        root.addWidget(PageHeader("Inicialização", "Tudo o que roda automaticamente quando o computador liga: é onde "
                                                   "malware se esconde para sobreviver a reinicializações.", "power"))
        card = Card()
        h = QHBoxLayout()
        self.b_refresh = button("Atualizar", "refresh")
        self.b_scan = button("Verificar alvos", "shield", "primary")
        self.b_lab = button("Analisar", "flask")
        self.b_disable = button("Desativar", "ban", "danger")
        h.addStretch(1)
        for b in (self.b_refresh, self.b_scan, self.b_lab, self.b_disable):
            h.addWidget(b)
        card.lay.addLayout(h)
        self.table = DataTable(["Nome", "Origem", "Situação", "Comando", "Arquivo alvo"], stretch_col=3)
        for i, w in enumerate((200, 160, 210, 300)):
            self.table.setColumnWidth(i, w)
        card.lay.addWidget(self.table)
        card.lay.addWidget(label("Itens marcados como suspeitos usam comandos ocultos, codificados ou executam a partir "
                                 "de pastas temporárias. Desativar guarda uma cópia para desfazer depois.", "small", wrap=True))
        root.addWidget(card, 1)
        self.b_refresh.clicked.connect(self.refresh)
        self.b_scan.clicked.connect(self.scan)
        self.b_lab.clicked.connect(lambda: [_send_to_lab(ctx, i["target"]) for i in self.table.selected_data()[:1] if i])
        self.b_disable.clicked.connect(self.disable)

    def refresh(self):
        run_bg(startup.list_items, self._set)

    def _set(self, items):
        self.items = items
        self.table.clear_rows()
        for it in items:
            v = self.verdicts.get(it["target"])
            if v is not None and v.is_threat:
                st, col = f"{v.verdict.upper()}: {v.threat_name}", theme.VERDICT_COLORS[v.verdict]
            elif it["suspicious"]:
                st, col = "Comando suspeito", theme.WARNING
            elif v is not None:
                st, col = "Verificado: limpo", theme.SUCCESS
            else:
                st, col = "Não verificado", theme.MUTED
            self.table.add_row([it["name"], it["source"], st, it["command"], it["target"] or "—"], data=it,
                               colors={2: col})

    def scan(self):
        targets = sorted({i["target"] for i in self.items if i["target"]})

        def work():
            return {t: self.ctx.engine.scan_file(t).result for t in targets
                    if not self.ctx.engine.exclusions.is_excluded(t)}

        def done(res):
            self.verdicts.update(res)
            self._set(self.items)
        run_bg(work, done)

    def disable(self):
        sel = [i for i in self.table.selected_data() if i]
        if not sel:
            return
        it = sel[0]
        if not it["removable"]:
            QMessageBox.information(self, "Inicialização", "Este item é do sistema ou exige edição manual "
                                    f"(local: {it['location']}).")
            return
        if confirm(self, "Desativar", f"Desativar '{it['name']}' da inicialização?"):
            try:
                startup.disable_item(it)
            except Exception as e:
                QMessageBox.warning(self, "Desativar", f"Falhou (talvez precise de administrador): {e}")
            self.refresh()

    def showEvent(self, e):
        super().showEvent(e)
        if not self.items:
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
