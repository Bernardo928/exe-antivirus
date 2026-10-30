"""Aba Configurações."""
from __future__ import annotations

import os
import sys

from PySide6.QtCore import QTime
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QFileDialog, QFormLayout, QGridLayout, QHBoxLayout,
                               QLineEdit, QListWidget, QMessageBox, QPlainTextEdit, QScrollArea, QSpinBox, QTimeEdit,
                               QVBoxLayout, QWidget)

from ... import APP_NAME, VERSION, history, paths
from ...engine.rules import USER_RULES_NAME, validate_user_rules
from ...system import autostart
from ..widgets import Card, PageHeader, button, confirm, label, open_location, run_bg

RULES_EXAMPLE = """[
  {
    "id": "minha.regra.exemplo",
    "name": "Exemplo: script que baixa de um domínio específico",
    "category": "Personalizada",
    "family": "Custom.Exemplo",
    "severity": "alta",
    "weight": 50,
    "targets": ["script", "pe"],
    "description": "Explique aqui por que este conteúdo é perigoso.",
    "all": ["dominio-malicioso\\\\.exemplo"],
    "any": ["invoke-webrequest", "curl\\\\s"],
    "min": 1
  }
]
"""


class RulesDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Regras personalizadas")
        self.resize(820, 560)
        v = QVBoxLayout(self)
        v.addWidget(label("Crie suas próprias regras de detecção por conteúdo (expressões regulares sobre os bytes do "
                          "arquivo, sem diferenciar maiúsculas). 'all' = todos os padrões precisam aparecer; 'any' = "
                          "pelo menos 'min' deles. Alvos: pe, elf, script, html, macro, pdf, rtf, lnk, any.", "muted",
                          wrap=True))
        self.edit = QPlainTextEdit()
        self.edit.setObjectName("mono")
        self.path = paths.data_dir() / USER_RULES_NAME
        self.edit.setPlainText(self.path.read_text("utf-8") if self.path.exists() else RULES_EXAMPLE)
        v.addWidget(self.edit, 1)
        h = QHBoxLayout()
        self.msg = label("", "muted")
        h.addWidget(self.msg, 1)
        val = button("Validar", "check-circle")
        save = button("Salvar", "download", "primary")
        val.clicked.connect(self.validate)
        save.clicked.connect(self.save)
        h.addWidget(val)
        h.addWidget(save)
        v.addLayout(h)

    def validate(self) -> bool:
        try:
            rules = validate_user_rules(self.edit.toPlainText())
        except ValueError as e:
            self.msg.setText(f"❌ {e}")
            return False
        self.msg.setText(f"✔ {len(rules)} regra(s) válida(s).")
        return True

    def save(self):
        if self.validate():
            self.path.write_text(self.edit.toPlainText(), "utf-8")
            self.accept()


class SettingsPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        s = ctx.settings
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
        root.setSpacing(16)
        root.addWidget(PageHeader("Configurações", "Ajuste a detecção, exclusões, agendamento, assinaturas e o "
                                                   "comportamento do programa.", "sliders"))
        grid = QGridLayout()
        grid.setSpacing(14)

        # ---------------- detecção
        det = Card()
        det.lay.addWidget(label("Detecção", "sectionTitle"))
        f = QFormLayout()
        f.setSpacing(10)
        self.sens = QComboBox()
        self.sens.addItems(["Baixa (menos alertas)", "Média (recomendada)", "Alta (mais rigorosa)"])
        self.sens.setCurrentIndex({"baixa": 0, "media": 1, "alta": 2}.get(s.sensitivity, 1))
        f.addRow("Sensibilidade heurística", self.sens)
        self.maxsize = QSpinBox()
        self.maxsize.setRange(8, 4096)
        self.maxsize.setSuffix(" MB")
        self.maxsize.setValue(s.max_file_size_mb)
        f.addRow("Tamanho máximo por arquivo", self.maxsize)
        self.threads = QSpinBox()
        self.threads.setRange(0, 64)
        self.threads.setSpecialValueText("Automático")
        self.threads.setValue(s.scan_threads)
        f.addRow("Threads de verificação", self.threads)
        self.procs = QCheckBox("Usar todos os núcleos da CPU (processos paralelos — muito mais rápido)")
        self.procs.setChecked(s.scan_processes)
        f.addRow(self.procs)
        self.archives = QCheckBox("Verificar dentro de arquivos compactados (ZIP, JAR, GZ, Office)")
        self.archives.setChecked(s.scan_archives)
        f.addRow(self.archives)
        self.depth = QSpinBox()
        self.depth.setRange(1, 5)
        self.depth.setValue(s.archive_max_depth)
        f.addRow("Profundidade em compactados", self.depth)
        self.cache = QCheckBox("Cache inteligente: pula arquivos que não mudaram desde a última verificação")
        self.cache.setChecked(s.use_cache)
        f.addRow(self.cache)
        det.lay.addLayout(f)
        hc = QHBoxLayout()
        self.cache_lbl = label("", "small")
        hc.addWidget(self.cache_lbl, 1)
        clr = button("Limpar cache", "trash")
        clr.clicked.connect(self.clear_cache)
        hc.addWidget(clr)
        det.lay.addLayout(hc)
        rules = button("Regras personalizadas…", "code")
        rules.clicked.connect(self.edit_rules)
        det.lay.addWidget(rules)
        grid.addWidget(det, 0, 0)

        # ---------------- exclusões
        exc = Card()
        eh = QHBoxLayout()
        eh.addWidget(label("Exclusões", "sectionTitle"))
        eh.addStretch(1)
        af = button("Arquivo", "plus")
        ad = button("Pasta", "plus")
        rm = button("Remover", "minus")
        af.clicked.connect(lambda: self.add_exclusion(False))
        ad.clicked.connect(lambda: self.add_exclusion(True))
        rm.clicked.connect(self.remove_exclusion)
        for b in (af, ad, rm):
            eh.addWidget(b)
        exc.lay.addLayout(eh)
        self.excl = QListWidget()
        self.excl.addItems(s.exclusions)
        exc.lay.addWidget(self.excl, 1)
        exc.lay.addWidget(label("O próprio antivírus (programa, quarentena, Sala de Análise e backups) é sempre "
                                "excluído automaticamente — ele nunca escaneia a si mesmo.", "small", wrap=True))
        grid.addWidget(exc, 0, 1)

        # ---------------- agendamento
        sch = Card()
        sch.lay.addWidget(label("Verificação agendada", "sectionTitle"))
        self.sch_on = QCheckBox("Executar verificação automática todos os dias")
        self.sch_on.setChecked(s.scheduled_scan_enabled)
        sch.lay.addWidget(self.sch_on)
        sf = QFormLayout()
        self.sch_time = QTimeEdit()
        self.sch_time.setDisplayFormat("HH:mm")
        hh, mm = (s.scheduled_scan_time.split(":") + ["0"])[:2]
        self.sch_time.setTime(QTime(int(hh), int(mm)))
        sf.addRow("Horário", self.sch_time)
        self.sch_type = QComboBox()
        self.sch_type.addItems(["Scan rápido", "Scan completo"])
        self.sch_type.setCurrentIndex(0 if s.scheduled_scan_type == "quick" else 1)
        sf.addRow("Tipo", self.sch_type)
        sch.lay.addLayout(sf)
        sch.lay.addStretch(1)
        grid.addWidget(sch, 1, 0)

        # ---------------- assinaturas
        sig = Card()
        sig.lay.addWidget(label("Banco de assinaturas (hashes)", "sectionTitle"))
        self.sig_lbl = label("", "muted", wrap=True)
        sig.lay.addWidget(self.sig_lbl)
        self.url = QLineEdit(s.signature_update_url)
        sig.lay.addWidget(label("Fonte de atualização (lista de SHA-256/MD5, texto ou ZIP):", "small"))
        sig.lay.addWidget(self.url)
        sh = QHBoxLayout()
        self.b_update = button("Atualizar agora", "download", "primary")
        imp = button("Importar arquivo…", "upload")
        self.b_update.clicked.connect(self.update_sigs)
        imp.clicked.connect(self.import_sigs)
        sh.addWidget(self.b_update)
        sh.addWidget(imp)
        sh.addStretch(1)
        sig.lay.addLayout(sh)
        sig.lay.addWidget(label("As assinaturas complementam a detecção heurística: amostras conhecidas são condenadas "
                                "instantaneamente pelo hash.", "small", wrap=True))
        grid.addWidget(sig, 1, 1)

        # ---------------- sistema
        sysc = Card()
        sysc.lay.addWidget(label("Programa", "sectionTitle"))
        self.autostart = QCheckBox("Iniciar com o sistema (minimizado na bandeja)")
        try:
            self.autostart.setChecked(autostart.is_enabled())
        except Exception:
            self.autostart.setEnabled(False)
        self.tray = QCheckBox("Ao fechar a janela, continuar protegendo na bandeja do sistema")
        self.tray.setChecked(s.minimize_to_tray)
        self.notif = QCheckBox("Mostrar notificações de ameaças")
        self.notif.setChecked(s.notifications)
        for c in (self.autostart, self.tray, self.notif):
            sysc.lay.addWidget(c)
        bh = QHBoxLayout()
        data = button("Abrir pasta de dados", "folder")
        data.clicked.connect(lambda: open_location(str(paths.data_dir()) + os.sep))
        bh.addWidget(data)
        if paths.IS_WINDOWS:
            adm = button("Reiniciar como administrador", "shield")
            adm.clicked.connect(self.elevate)
            bh.addWidget(adm)
        bh.addStretch(1)
        sysc.lay.addLayout(bh)
        grid.addWidget(sysc, 2, 0)

        about = Card()
        about.lay.addWidget(label(f"{APP_NAME} {VERSION}", "sectionTitle"))
        about.lay.addWidget(label(
            "Antivírus multiplataforma (Windows e Linux) com detecção por conteúdo: análise estrutural de executáveis "
            "PE/ELF, desofuscação de scripts, extração de macros do Office, análise de PDF/RTF/LNK, varredura dentro de "
            "compactados, regras comportamentais, assinaturas por hash e verificação de assinatura digital / pacotes do "
            "sistema para evitar falsos positivos.", "muted", wrap=True))
        about.lay.addWidget(label(f"Pasta de dados: {paths.data_dir()}", "small", wrap=True))
        grid.addWidget(about, 2, 1)
        root.addLayout(grid)

        sb = QHBoxLayout()
        sb.addStretch(1)
        save = button("Salvar configurações", "check-circle", "primary")
        save.clicked.connect(self.save)
        sb.addWidget(save)
        root.addLayout(sb)
        self.refresh()

    def refresh(self):
        db = self.ctx.sigdb
        self.sig_lbl.setText(f"{db.count:,} assinatura(s) de hash".replace(",", ".") +
                             (f" · atualizado em {db.updated}" if db.updated else "") +
                             f" · {len(self.ctx.engine.rules.rules)} regras comportamentais (versão {self.ctx.engine.rules.version})")
        try:
            self.cache_lbl.setText(f"{self.ctx.cache.size():,} arquivo(s) no cache".replace(",", "."))
        except Exception:
            pass

    def save(self):
        s = self.ctx.settings
        s.sensitivity = ["baixa", "media", "alta"][self.sens.currentIndex()]
        s.max_file_size_mb = self.maxsize.value()
        s.scan_threads = self.threads.value()
        s.scan_processes = self.procs.isChecked()
        s.scan_archives = self.archives.isChecked()
        s.archive_max_depth = self.depth.value()
        s.use_cache = self.cache.isChecked()
        s.exclusions = [self.excl.item(i).text() for i in range(self.excl.count())]
        s.scheduled_scan_enabled = self.sch_on.isChecked()
        s.scheduled_scan_time = self.sch_time.time().toString("HH:mm")
        s.scheduled_scan_type = "quick" if self.sch_type.currentIndex() == 0 else "full"
        s.signature_update_url = self.url.text().strip()
        s.minimize_to_tray = self.tray.isChecked()
        s.notifications = self.notif.isChecked()
        try:
            if self.autostart.isEnabled() and self.autostart.isChecked() != autostart.is_enabled():
                autostart.set_enabled(self.autostart.isChecked())
        except Exception as e:
            QMessageBox.warning(self, "Inicialização", f"Não foi possível alterar a inicialização automática: {e}")
        self.ctx.apply_settings()
        self.refresh()
        QMessageBox.information(self, "Configurações", "Configurações salvas.")

    def add_exclusion(self, folder: bool):
        p = QFileDialog.getExistingDirectory(self, "Pasta a excluir") if folder else \
            QFileDialog.getOpenFileName(self, "Arquivo a excluir")[0]
        if p:
            self.excl.addItem(p)

    def remove_exclusion(self):
        for it in self.excl.selectedItems():
            self.excl.takeItem(self.excl.row(it))

    def clear_cache(self):
        if confirm(self, "Cache", "Limpar o cache? A próxima verificação analisará todos os arquivos novamente."):
            self.ctx.cache.clear()
            self.refresh()

    def edit_rules(self):
        if RulesDialog(self).exec():
            self.ctx.engine.reload()
            self.refresh()
            QMessageBox.information(self, "Regras", "Regras personalizadas carregadas.")

    def _after_sig(self, n):
        self.b_update.setEnabled(True)
        self.b_update.setText("Atualizar agora")
        history.log("assinaturas", f"{n} nova(s) assinatura(s) adicionada(s)")
        self.refresh()
        QMessageBox.information(self, "Assinaturas", f"{n} nova(s) assinatura(s) adicionada(s).")

    def update_sigs(self):
        url = self.url.text().strip()
        if not url:
            return
        self.b_update.setEnabled(False)
        self.b_update.setText("Baixando…")

        def fail(e):
            self.b_update.setEnabled(True)
            self.b_update.setText("Atualizar agora")
            QMessageBox.warning(self, "Assinaturas", f"Não foi possível atualizar: {e}")
        run_bg(lambda: self.ctx.sigdb.update_from_url(url), self._after_sig, fail)

    def import_sigs(self):
        p, _ = QFileDialog.getOpenFileName(self, "Lista de hashes", "", "Listas (*.txt *.csv *.zip *.lst);;Todos (*)")
        if p:
            run_bg(lambda: self.ctx.sigdb.import_file(p), self._after_sig)

    def elevate(self):
        import ctypes
        args = " ".join(f'"{a}"' for a in sys.argv[1:])
        if paths.IS_FROZEN:
            exe, params = sys.executable, args
        else:
            exe, params = sys.executable, f'"{os.path.abspath(sys.argv[0])}" {args}'
        r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        if r > 32:
            from PySide6.QtWidgets import QApplication
            self.ctx.shutdown()
            QApplication.instance().exit(0)
