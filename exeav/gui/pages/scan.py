"""Aba de verificação: scan rápido, completo e personalizado."""
from __future__ import annotations

import os
import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QFileDialog, QGridLayout, QHBoxLayout, QLabel, QMessageBox, QProgressBar,
                               QVBoxLayout, QWidget)

from ... import scanner as sc
from ... import util
from .. import icons, theme
from ..widgets import Card, DataTable, PageHeader, StatCard, button, confirm, label, open_location, run_bg


class ScanOption(Card):
    def __init__(self, icon_name: str, title: str, text: str, color: str, on_click):
        super().__init__(hover=True)
        self.setCursor(Qt.PointingHandCursor)
        self._cb = on_click
        h = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(icons.pixmap(icon_name, color, 26))
        ic.setFixedSize(48, 48)
        ic.setAlignment(Qt.AlignCenter)
        ic.setStyleSheet(f"background:{theme.SURFACE2}; border-radius: 12px;")
        h.addWidget(ic)
        v = QVBoxLayout()
        v.setSpacing(2)
        v.addWidget(label(title, "sectionTitle"))
        v.addWidget(label(text, "muted", wrap=True))
        h.addLayout(v, 1)
        self.lay.addLayout(h)

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.LeftButton and self.isEnabled():
            self._cb()


class ScanPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.results = []
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        root.addWidget(PageHeader("Verificação", "Escolha o tipo de varredura. A análise é feita pelo conteúdo e "
                                                 "comportamento dos arquivos, nunca pelo nome.", "search"))

        opts = QGridLayout()
        opts.setSpacing(14)
        self.opt_quick = ScanOption("zap", "Scan rápido", "Downloads, área de trabalho, temporários, inicialização "
                                    "e todos os processos em execução.", theme.WARNING, lambda: self.start("quick"))
        self.opt_full = ScanOption("drive", "Scan completo", "Todos os discos e pastas do computador.",
                                   theme.ACCENT, lambda: self.start("full"))
        self.opt_folder = ScanOption("folder", "Scan de pasta", "Escolha uma pasta ou unidade (ex.: pen drive).",
                                     theme.SUCCESS, self.pick_folder)
        self.opt_file = ScanOption("file", "Scan de arquivo", "Verifique arquivos específicos.", "#a78bfa",
                                   self.pick_files)
        opts.addWidget(self.opt_quick, 0, 0)
        opts.addWidget(self.opt_full, 0, 1)
        opts.addWidget(self.opt_folder, 1, 0)
        opts.addWidget(self.opt_file, 1, 1)
        root.addLayout(opts)

        prog = Card()
        top = QHBoxLayout()
        self.title = label("Nenhuma verificação em andamento", "sectionTitle")
        top.addWidget(self.title, 1)
        self.pause_btn = button("Pausar", "pause")
        self.stop_btn = button("Parar", "stop", "danger")
        self.pause_btn.clicked.connect(self.toggle_pause)
        self.stop_btn.clicked.connect(self.ctx.stop_scan)
        top.addWidget(self.pause_btn)
        top.addWidget(self.stop_btn)
        prog.lay.addLayout(top)
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        prog.lay.addWidget(self.bar)
        self.current = label("", "small")
        self.current.setMinimumWidth(100)
        prog.lay.addWidget(self.current)
        stats = QHBoxLayout()
        stats.setSpacing(12)
        self.st_files = StatCard("Arquivos verificados", "0", "file", theme.ACCENT)
        self.st_threats = StatCard("Ameaças encontradas", "0", "alert", theme.DANGER)
        self.st_speed = StatCard("Velocidade", "—", "zap", theme.WARNING)
        self.st_time = StatCard("Tempo decorrido", "0s", "clock", theme.SUCCESS)
        for w in (self.st_files, self.st_threats, self.st_speed, self.st_time):
            stats.addWidget(w)
        prog.lay.addLayout(stats)
        root.addWidget(prog)

        res = Card()
        rh = QHBoxLayout()
        rh.addWidget(label("Ameaças encontradas", "sectionTitle"))
        rh.addStretch(1)
        self.b_quar = button("Quarentena", "lock", "primary", "Isolar os itens selecionados")
        self.b_quar_all = button("Isolar todas", "shield")
        self.b_lab = button("Sala de Análise", "flask", tip="Ver por que o arquivo é perigoso")
        self.b_ignore = button("Ignorar", "ban", tip="Adicionar às exclusões")
        self.b_del = button("Excluir", "trash", "danger")
        self.b_open = button("", "external", tip="Abrir local do arquivo")
        for b in (self.b_quar, self.b_quar_all, self.b_lab, self.b_ignore, self.b_del, self.b_open):
            rh.addWidget(b)
        res.lay.addLayout(rh)
        self.table = DataTable(["Ameaça", "Veredito", "Pontos", "Tipo", "Arquivo", "Principal motivo", "Situação"],
                               stretch_col=4)
        for i, w in enumerate((220, 90, 70, 110, 300, 280, 140)):
            self.table.setColumnWidth(i, w)
        self.table.setSortingEnabled(True)
        self.table.doubleClicked.connect(lambda *_: self.send_to_lab())
        res.lay.addWidget(self.table)
        root.addWidget(res, 1)

        self.b_quar.clicked.connect(lambda: self.quarantine(self.table.selected_data()))
        self.b_quar_all.clicked.connect(lambda: self.quarantine([r for r in self.results if not r.action]))
        self.b_lab.clicked.connect(self.send_to_lab)
        self.b_ignore.clicked.connect(self.ignore)
        self.b_del.clicked.connect(self.delete)
        self.b_open.clicked.connect(lambda: [open_location(r.path) for r in self.table.selected_data()[:1]])

        b = ctx.bridge
        b.scan_started.connect(self.on_started)
        b.scan_progress.connect(self.on_progress)
        b.scan_threat.connect(self.on_threat)
        b.scan_finished.connect(self.on_finished)
        self._set_running(False)

    # ------------------------------------------------------------------ ações
    def pick_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Escolha a pasta para verificar")
        if d:
            self.start("custom", [d])

    def pick_files(self):
        fs, _ = QFileDialog.getOpenFileNames(self, "Escolha os arquivos para verificar")
        if fs:
            self.start("custom", fs)

    def start(self, kind: str, targets: list[str] | None = None):
        if self.ctx.scanning:
            QMessageBox.information(self, "Verificação", "Já existe uma verificação em andamento.")
            return
        if kind == "quick":
            self.title.setText("Preparando scan rápido…")
            run_bg(sc.quick_targets, lambda t: self._go("quick", t))
            return
        if kind == "full":
            targets = sc.full_targets()
        self._go(kind, targets or [])

    def _go(self, kind, targets):
        self.results.clear()
        self.table.clear_rows()
        self.ctx.start_scan(kind, targets)

    def toggle_pause(self):
        s = self.ctx.scanner
        if not s:
            return
        if s.paused:
            s.resume()
            self.pause_btn.setText("Pausar")
            self.pause_btn.setIcon(icons.icon("pause", theme.TEXT, 16))
        else:
            s.pause()
            self.pause_btn.setText("Continuar")
            self.pause_btn.setIcon(icons.icon("play", theme.TEXT, 16))

    def _set_running(self, running: bool):
        for o in (self.opt_quick, self.opt_full, self.opt_folder, self.opt_file):
            o.setEnabled(not running)
        self.pause_btn.setEnabled(running)
        self.stop_btn.setEnabled(running)

    # ------------------------------------------------------------------ sinais
    def on_started(self, kind):
        self._set_running(True)
        self.title.setText(f"{sc.KIND_NAMES.get(kind, 'Verificação')} em andamento…")
        self.bar.setRange(0, 0)
        self.st_threats.set(0)

    def on_progress(self, s):
        if s.walking_done and s.discovered:
            self.bar.setRange(0, s.discovered)
            self.bar.setValue(s.files)
        self.st_files.set(f"{s.files:,}".replace(",", "."))
        self.st_threats.set(len(s.threats))
        el = max(0.1, s.elapsed)
        self.st_speed.set(f"{s.files / el:.0f} arq/s · {util.human_size(s.bytes / el)}/s")
        self.st_time.set(_fmt_time(el))
        cur = s.current
        fm = self.current.fontMetrics()
        self.current.setText(fm.elidedText(cur, Qt.ElideMiddle, max(200, self.current.width() - 10)))

    def on_threat(self, r):
        self.results.append(r)
        color = theme.VERDICT_COLORS.get(r.verdict, theme.WARNING)
        reason = r.reasons()[0] if r.reasons() else ""
        self.table.add_row([r.threat_name, r.verdict, r.score, r.file_type, r.path, reason, r.action or "Pendente"],
                           data=r, colors={0: color, 1: color})

    def on_finished(self, s):
        self._set_running(False)
        self.bar.setRange(0, 100)
        self.bar.setValue(100)
        self.on_progress(s)
        self.current.setText(f"Itens lidos do cache (sem mudanças desde a última verificação): {s.from_cache:,} · "
                             f"ignorados: {s.skipped:,}".replace(",", "."))
        n = len(s.threats)
        st = "cancelada" if s.cancelled else "concluída"
        self.title.setText(f"Verificação {st}: {n} ameaça(s) encontrada(s)" if n else f"Verificação {st}: nenhuma ameaça encontrada")
        self.pause_btn.setText("Pausar")

    def _refresh_row(self, r):
        for row in range(self.table.rowCount()):
            if self.table.row_data(row) is r:
                self.table.item(row, 6).setText(r.action)

    def quarantine(self, items):
        items = [r for r in items if r and not r.action]
        if not items:
            return
        errors = []
        for r in items:
            try:
                self.ctx.quarantine.isolate(r)
                r.action = "Em quarentena"
                self.ctx.cache.forget(r.path)
            except Exception as e:
                r.action = "Falha"
                errors.append(f"{r.path}: {e}")
            self._refresh_row(r)
        self.ctx.bridge.quarantine_changed.emit()
        if errors:
            QMessageBox.warning(self, "Quarentena", "Alguns itens não puderam ser isolados (execute como "
                                "administrador ou feche o programa que os usa):\n\n" + "\n".join(errors[:10]))

    def send_to_lab(self):
        sel = self.table.selected_data()
        if not sel:
            return
        r = sel[0]
        if r.action == "Em quarentena":
            QMessageBox.information(self, "Sala de Análise", "O arquivo já está em quarentena. Envie-o para a Sala "
                                    "de Análise pela aba Quarentena.")
            return

        def work():
            existing = self.ctx.lab.find_by_hash(r.sha256) if r.sha256 else None
            return existing or self.ctx.lab.add_file(r.path, "scan")
        run_bg(work, lambda item_id: self.ctx.bridge.open_in_lab.emit(item_id))

    def ignore(self):
        sel = [r for r in self.table.selected_data() if r]
        if not sel or not confirm(self, "Ignorar", f"Adicionar {len(sel)} arquivo(s) às exclusões? Eles não serão "
                                                   "mais verificados."):
            return
        for r in sel:
            if r.path not in self.ctx.settings.exclusions:
                self.ctx.settings.exclusions.append(r.path)
            r.action = "Ignorado"
            self._refresh_row(r)
        self.ctx.apply_settings()

    def delete(self):
        sel = [r for r in self.table.selected_data() if r and not r.action]
        if not sel or not confirm(self, "Excluir", f"Excluir DEFINITIVAMENTE {len(sel)} arquivo(s)? Esta ação não "
                                                   "pode ser desfeita (a quarentena é mais segura)."):
            return
        for r in sel:
            try:
                os.remove(r.path)
                r.action = "Excluído"
            except OSError as e:
                r.action = f"Falha: {e.strerror}"
            self._refresh_row(r)


def _fmt_time(sec: float) -> str:
    sec = int(sec)
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m {sec % 60:02d}s"
    return time.strftime("%Hh %Mm", time.gmtime(sec))
