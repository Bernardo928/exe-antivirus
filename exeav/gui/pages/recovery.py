"""Aba Recuperação: reparo de arquivos corrompidos e backups protegidos."""
from __future__ import annotations

import os

from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QMessageBox, QTabWidget, QVBoxLayout, QWidget

from ... import recovery, util
from .. import icons, theme
from ..widgets import Card, DataTable, PageHeader, button, confirm, label, open_location, run_bg


class RecoveryPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.findings: list[recovery.Finding] = []
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        root.addWidget(PageHeader("Recuperação de arquivos", "Encontre e repare arquivos corrompidos (ZIP/Office, "
                                                              "PDF, PNG, JPEG, GIF, JSON, textos) e proteja suas pastas "
                                                              "com backups contra ransomware.", "lifebuoy"))
        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        # ------------------------------------------------ reparo
        rep = QWidget()
        rv = QVBoxLayout(rep)
        rv.setContentsMargins(14, 14, 14, 14)
        h = QHBoxLayout()
        self.b_scan = button("Verificar pasta", "search", "primary")
        self.b_file = button("Verificar arquivo", "file")
        self.b_fix = button("Reparar selecionados", "tool", "success")
        self.b_fix_all = button("Reparar todos", "tool")
        self.b_open = button("", "external", tip="Abrir local")
        for b in (self.b_scan, self.b_file):
            h.addWidget(b)
        h.addStretch(1)
        for b in (self.b_fix, self.b_fix_all, self.b_open):
            h.addWidget(b)
        rv.addLayout(h)
        self.status = label("Escolha uma pasta para procurar arquivos danificados. O original nunca é alterado: a "
                            "versão reparada é salva ao lado com o nome '.recuperado'.", "muted", wrap=True)
        rv.addWidget(self.status)
        self.table = DataTable(["Arquivo", "Tipo", "Problema", "Reparável", "Resultado"], stretch_col=2)
        for i, w in enumerate((330, 70, 380, 90)):
            self.table.setColumnWidth(i, w)
        rv.addWidget(self.table, 1)
        tabs.addTab(rep, icons.icon("tool", theme.TEXT, 16), "Reparar arquivos corrompidos")

        # ------------------------------------------------ backups
        bk = QWidget()
        bv = QVBoxLayout(bk)
        bv.setContentsMargins(14, 14, 14, 14)
        bh = QHBoxLayout()
        self.b_backup = button("Criar backup de uma pasta", "archive", "primary")
        self.b_restore = button("Restaurar backup", "restore")
        self.b_del_backup = button("Excluir backup", "trash", "danger")
        bh.addWidget(self.b_backup)
        bh.addStretch(1)
        bh.addWidget(self.b_restore)
        bh.addWidget(self.b_del_backup)
        bv.addLayout(bh)
        bv.addWidget(label("Os backups ficam na pasta protegida do antivírus (que nunca é verificada nem alterada por ele). "
                           "Se um ransomware criptografar seus arquivos, restaure a partir daqui.", "muted", wrap=True))
        self.backups = DataTable(["Backup", "Pasta de origem", "Data", "Arquivos", "Tamanho"], stretch_col=1)
        self.backups.setColumnWidth(0, 260)
        bv.addWidget(self.backups, 1)
        tabs.addTab(bk, icons.icon("archive", theme.TEXT, 16), "Backups protegidos")

        self.b_scan.clicked.connect(self.scan_folder)
        self.b_file.clicked.connect(self.scan_file)
        self.b_fix.clicked.connect(lambda: self.repair(self.table.selected_data()))
        self.b_fix_all.clicked.connect(lambda: self.repair([f for f in self.findings if f.repairable]))
        self.b_open.clicked.connect(lambda: [open_location(f.path) for f in self.table.selected_data()[:1] if f])
        self.b_backup.clicked.connect(self.create_backup)
        self.b_restore.clicked.connect(self.restore_backup)
        self.b_del_backup.clicked.connect(self.delete_backup)
        self.refresh_backups()

    def _show(self, findings):
        self.findings = findings
        self.table.clear_rows()
        for f in findings:
            c = {"alta": theme.DANGER, "media": theme.WARNING}.get(f.severity, theme.INFO)
            self.table.add_row([f.path, f.kind, f.problem, "Sim" if f.repairable else "Não", ""], data=f,
                               colors={2: c, 3: theme.SUCCESS if f.repairable else theme.MUTED})
        self.status.setText(f"{len(findings)} arquivo(s) com problema encontrado(s)." if findings
                            else "Nenhum arquivo corrompido encontrado.")

    def scan_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Pasta para verificar")
        if not d:
            return
        self.status.setText("Verificando… (pode demorar em pastas grandes)")
        self.b_scan.setEnabled(False)

        def done(res):
            self.b_scan.setEnabled(True)
            self._show(res)
        run_bg(lambda: recovery.scan_folder(d), done, lambda e: (self.b_scan.setEnabled(True), self.status.setText(str(e))))

    def scan_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "Arquivo para verificar")
        if f:
            r = recovery.check_file(f)
            if r is None:
                ext = os.path.splitext(f)[1].lower()
                msg = "O arquivo está íntegro." if ext in recovery.SUPPORTED else \
                    "Formato não suportado pela verificação de integridade."
                QMessageBox.information(self, "Recuperação", msg)
            self._show([r] if r else [])

    def repair(self, items):
        items = [f for f in items if f and f.repairable]
        if not items:
            return
        ok = 0
        for f in items:
            row = next((r for r in range(self.table.rowCount()) if self.table.row_data(r) is f), None)
            try:
                out, desc = recovery.repair(f.path)
                ok += 1
                txt, col = f"OK: {desc} → {os.path.basename(out)}", theme.SUCCESS
            except Exception as e:
                txt, col = f"Falhou: {e}", theme.DANGER
            if row is not None:
                it = self.table.item(row, 4)
                it.setText(txt)
                it.setToolTip(txt)
                from PySide6.QtGui import QColor
                it.setForeground(QColor(col))
        self.status.setText(f"{ok} de {len(items)} arquivo(s) reparado(s). As cópias reparadas têm '.recuperado' no nome.")

    # ------------------------------------------------ backups
    def refresh_backups(self):
        self.backups.clear_rows()
        for b in recovery.list_backups():
            d = b.get("date", "")
            if len(d) == 15:
                d = f"{d[6:8]}/{d[4:6]}/{d[:4]} {d[9:11]}:{d[11:13]}"
            self.backups.add_row([b["name"], b.get("source", "?"), d, b.get("files", "?"), util.human_size(b["size"])],
                                 data=b)

    def create_backup(self):
        d = QFileDialog.getExistingDirectory(self, "Pasta para proteger com backup")
        if not d:
            return
        self.b_backup.setEnabled(False)
        self.b_backup.setText("Criando backup…")

        def done(r):
            self.b_backup.setEnabled(True)
            self.b_backup.setText("Criar backup de uma pasta")
            self.refresh_backups()
            QMessageBox.information(self, "Backup", f"Backup criado com {r['files']} arquivo(s) "
                                                    f"({util.human_size(r['bytes'])}).")

        def fail(e):
            self.b_backup.setEnabled(True)
            self.b_backup.setText("Criar backup de uma pasta")
            QMessageBox.warning(self, "Backup", str(e))
        run_bg(lambda: recovery.create_backup(d), done, fail)

    def restore_backup(self):
        sel = [b for b in self.backups.selected_data() if b]
        if not sel:
            return
        b = sel[0]
        dest = QFileDialog.getExistingDirectory(self, "Restaurar para qual pasta?", b.get("source", ""))
        if not dest or not confirm(self, "Restaurar", f"Restaurar o backup em:\n{dest}\n\nArquivos com o mesmo nome "
                                                      "serão substituídos."):
            return
        run_bg(lambda: recovery.restore_backup(b["file"], dest),
               lambda n: QMessageBox.information(self, "Backup", f"{n} arquivo(s) restaurado(s)."))

    def delete_backup(self):
        sel = [b for b in self.backups.selected_data() if b]
        if sel and confirm(self, "Excluir", "Excluir o backup selecionado?"):
            try:
                os.remove(sel[0]["file"])
            except OSError as e:
                QMessageBox.warning(self, "Backup", str(e))
            self.refresh_backups()
