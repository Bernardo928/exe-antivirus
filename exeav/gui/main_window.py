"""Janela principal: barra lateral com uma aba para cada função."""
from __future__ import annotations

import datetime

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (QApplication, QButtonGroup, QFrame, QHBoxLayout, QLabel, QMainWindow, QMenu,
                               QMessageBox, QPushButton, QScrollArea, QStackedWidget, QSystemTrayIcon, QVBoxLayout,
                               QWidget)

from .. import APP_NAME, VERSION, config, scanner
from . import icons, theme
from .pages.botnet import BotnetPage
from .pages.dashboard import DashboardPage
from .pages.firewall import FirewallPage
from .pages.history import HistoryPage
from .pages.intel_center import IntelCenterPage
from .pages.lab import LabPage
from .pages.quarantine import QuarantinePage
from .pages.realtime import RealtimePage
from .pages.recovery import RecoveryPage
from .pages.scan import ScanPage
from .pages.settings import SettingsPage
from .pages.system_pages import NetworkPage, ProcessesPage, StartupPage
from .pages.usb import UsbPage
from .pages.web import WebPage

NAV = [
    ("dashboard", "Painel", "home"),
    ("scan", "Verificação", "search"),
    ("realtime", "Tempo Real", "activity"),
    ("botnet", "Anti-Botnet", "network"),
    ("usb", "Pen drives", "usb"),
    ("web", "Proteção Web", "web"),
    ("firewall", "Firewall", "wall"),
    ("intel", "Zero-Day && Intel", "bug"),
    ("quarantine", "Quarentena", "lock"),
    ("lab", "Sala de Análise", "flask"),
    ("recovery", "Recuperação", "lifebuoy"),
    ("processes", "Processos", "cpu"),
    ("startup", "Inicialização", "power"),
    ("network", "Rede", "globe"),
    ("history", "Histórico", "clock"),
    ("settings", "Configurações", "sliders"),
]


class MainWindow(QMainWindow):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self._really_quit = False
        self.setWindowTitle(f"{APP_NAME}")
        self.setWindowIcon(icons.app_icon())
        self.resize(1360, 860)
        self.setMinimumSize(1080, 700)

        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)

        side = QWidget()
        side.setObjectName("sidebar")
        side.setFixedWidth(232)
        sv = QVBoxLayout(side)
        sv.setContentsMargins(14, 18, 14, 14)
        sv.setSpacing(4)
        brand = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(icons.app_icon_pixmap(64).scaled(36, 36, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        brand.addWidget(logo)
        bt = QVBoxLayout()
        bt.setSpacing(0)
        t = QLabel("EXE Antivirus")
        t.setObjectName("brand")
        st = QLabel(f"versão {VERSION}")
        st.setObjectName("brandSub")
        bt.addWidget(t)
        bt.addWidget(st)
        brand.addLayout(bt, 1)
        sv.addLayout(brand)
        sv.addSpacing(18)

        self.stack = QStackedWidget()
        self.pages: dict[str, QWidget] = {}
        self.nav_buttons: dict[str, QPushButton] = {}
        group = QButtonGroup(self)
        group.setExclusive(True)
        factories = {"dashboard": DashboardPage, "scan": ScanPage, "realtime": RealtimePage, "botnet": BotnetPage,
                     "usb": UsbPage, "web": WebPage, "firewall": FirewallPage, "intel": IntelCenterPage,
                     "quarantine": QuarantinePage, "lab": LabPage, "recovery": RecoveryPage,
                     "processes": ProcessesPage, "startup": StartupPage, "network": NetworkPage,
                     "history": HistoryPage, "settings": SettingsPage}
        nav_box = QWidget()
        nav_lay = QVBoxLayout(nav_box)
        nav_lay.setContentsMargins(0, 0, 0, 0)
        nav_lay.setSpacing(2)
        nav_scroll = QScrollArea()
        nav_scroll.setObjectName("navScroll")
        nav_scroll.setWidgetResizable(True)
        nav_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        nav_scroll.setFrameShape(QFrame.NoFrame)
        nav_scroll.setWidget(nav_box)
        for key, title, ic in NAV:
            b = QPushButton(f"  {title}")
            b.setObjectName("nav")
            b.setCheckable(True)
            b.setIcon(icons.icon(ic, theme.MUTED, 18))
            b.setIconSize(QSize(18, 18))
            b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(lambda _=False, k=key: self.go(k))
            group.addButton(b)
            nav_lay.addWidget(b)
            self.nav_buttons[key] = b
            page = factories[key](ctx)
            self.pages[key] = page
            self.stack.addWidget(page)
        nav_lay.addStretch(1)
        sv.addWidget(nav_scroll, 1)
        self.rt_label = QLabel()
        self.rt_label.setObjectName("small")
        self.rt_label.setWordWrap(True)
        sv.addWidget(self.rt_label)
        h.addWidget(side)
        h.addWidget(self.stack, 1)
        self.statusBar().showMessage("Pronto")

        ctx.bridge.navigate.connect(self._on_navigate)
        ctx.bridge.rt_event.connect(self._on_rt_event)
        ctx.bridge.botnet_event.connect(self._on_botnet_event)
        ctx.bridge.usb_event.connect(self._on_usb_event)
        ctx.bridge.script_event.connect(self._on_script_event)
        ctx.bridge.boot_event.connect(self._on_boot_event)
        ctx.bridge.incident_event.connect(self._on_incident)
        ctx.bridge.scan_finished.connect(self._on_scan_finished)
        ctx.bridge.scan_threat.connect(lambda r: self.statusBar().showMessage(f"Ameaça encontrada: {r.threat_name} — {r.path}", 8000))
        self._setup_tray()
        self._sched = QTimer(self)
        self._sched.timeout.connect(self._check_schedule)
        self._sched.start(30_000)
        self.go("dashboard")
        self._update_rt_label()

    # ------------------------------------------------------------------ navegação
    def go(self, key: str):
        page = self.pages[key]
        self.stack.setCurrentWidget(page)
        for k, b in self.nav_buttons.items():
            ic = next(i for kk, _t, i in NAV if kk == k)
            b.setChecked(k == key)
            b.setIcon(icons.icon(ic, theme.ACCENT if k == key else theme.MUTED, 18))
        if hasattr(page, "refresh") and key in ("dashboard", "quarantine", "settings", "realtime", "usb", "web"):
            page.refresh()

    def _on_navigate(self, key: str):
        if key.startswith("scan:"):
            self.pages["scan"].start(key.split(":", 1)[1])
            return
        if key in self.pages:
            self.go(key)
            self.show_normal()

    # ------------------------------------------------------------------ bandeja
    def _setup_tray(self):
        self.tray = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(icons.status_icon(True), self)
        self.tray.setToolTip(APP_NAME)
        m = QMenu()
        a_open = QAction("Abrir EXE Antivirus", self)
        a_open.triggered.connect(self.show_normal)
        a_quick = QAction("Scan rápido", self)
        a_quick.triggered.connect(lambda: (self.show_normal(), self.go("scan"), self.pages["scan"].start("quick")))
        self.a_rt = QAction("Proteção em tempo real", self)
        self.a_rt.setCheckable(True)
        self.a_rt.triggered.connect(self._tray_toggle_rt)
        a_quit = QAction("Sair", self)
        a_quit.triggered.connect(self.quit_app)
        for a in (a_open, a_quick, self.a_rt):
            m.addAction(a)
        m.addSeparator()
        m.addAction(a_quit)
        self.tray.setContextMenu(m)
        self.tray.activated.connect(lambda r: self.show_normal() if r in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick) else None)
        self.tray.show()
        self._tray_menu = m

    def _tray_toggle_rt(self, on: bool):
        rt = self.ctx.realtime
        if on and not rt.running:
            rt.start()
        elif not on and rt.running:
            rt.stop()
        self.ctx.settings.realtime_enabled = rt.running
        self.ctx.apply_settings()

    def show_normal(self):
        self.show()
        self.setWindowState((self.windowState() & ~Qt.WindowMinimized) | Qt.WindowActive)
        self.raise_()
        self.activateWindow()

    def notify(self, title: str, text: str, critical: bool = True):
        if self.tray and self.ctx.settings.notifications:
            self.tray.showMessage(title, text, QSystemTrayIcon.Critical if critical else QSystemTrayIcon.Information, 8000)

    def _update_rt_label(self):
        on = self.ctx.realtime.running
        color = theme.SUCCESS if on else theme.DANGER
        self.rt_label.setText(f"<span style='color:{color}'>●</span> Tempo real {'ativo' if on else 'desligado'}")
        if self.tray:
            self.tray.setIcon(icons.status_icon(on))
            self.a_rt.setChecked(on)
            self.tray.setToolTip(f"{APP_NAME} — proteção {'ativa' if on else 'DESLIGADA'}")

    def _on_botnet_event(self, kind, rep):
        if kind == "botnet":
            self.notify(f"BOTNET BLOQUEADA: {rep.family}",
                        f"{rep.name} (PID {rep.pid}) — {rep.action}\n" + "; ".join(rep.reasons()[:3]))
            self.statusBar().showMessage(f"[Anti-Botnet] {rep.name}: {rep.action}", 12000)
        elif kind == "suspeito":
            self.notify("Comportamento suspeito de bot", f"{rep.name} (PID {rep.pid}): " + "; ".join(rep.reasons()[:2]),
                        critical=False)

    def _on_incident(self, inc, new):
        # um alerta por incidente novo e relevante; repetições do mesmo evento só somam ocorrências
        if new and inc.get("desconhecida") and inc.get("classificacao") in ("alto risco", "crítico"):
            self.notify("Ameaça desconhecida em investigação",
                        f"{inc.get('ameaca')} — confiança {inc.get('confianca') or 'baixa'}\n"
                        f"{(inc.get('arquivo') or '')[:120]}\nVeja as evidências em Zero-Day & Intel.")

    def _on_usb_event(self, kind, data):
        if kind == "inserted":
            self.statusBar().showMessage(f"[Pen drive] {data.title()} conectado"
                                         + (" — verificando…" if self.ctx.settings.usb_auto_scan else ""), 8000)
        elif kind in ("threat", "finding"):
            r = data[2] if kind == "finding" else data
            self.notify(f"Pen drive: {r.threat_name}", f"{r.path}\nAção: {r.action}", critical=r.verdict == "malicioso")
        elif kind == "done":
            d, st = data
            n = len(st.threats)
            msg = f"{d.title()}: {st.files} arquivo(s) verificado(s), " + (f"{n} ameaça(s)" if n else "nenhuma ameaça")
            self.statusBar().showMessage(f"[Pen drive] {msg}", 15000)
            self.notify("Pen drive verificado", msg, critical=bool(n))

    def _on_script_event(self, kind, r):
        if kind == "threat":
            self.notify(f"Script malicioso bloqueado: {r.threat_name}", f"{r.path[:160]}\nAção: {r.action}")
            self.statusBar().showMessage(f"[Scripts] {r.threat_name} — {r.action}", 12000)
        elif kind == "suspeito":
            self.notify("Script suspeito", r.path[:200], critical=False)

    def _on_boot_event(self, kind, data):
        if kind == "blocked":
            self.statusBar().showMessage(f"[Inicialização] {data['item'].get('name')} bloqueado — {data['reason']}",
                                         12000)
            self.notify("Programa bloqueado ao ligar", f"{data['item'].get('name')}: {data['reason']}",
                        critical=data.get("verdict") == "malicioso")
        elif kind == "boot_scan" and data == "done":
            st = self.ctx.boot.boot_scan_state
            self.statusBar().showMessage(f"[Inicialização] scan em segundo plano {st}", 15000)
            if "0 ameaça" not in st:
                self.notify("Scan de inicialização", st)
        elif kind == "threat":
            self.notify(f"Ameaça {data.verdict}: {data.threat_name}", f"{data.path}\nAção: {data.action}")
        elif kind == "status" and isinstance(data, str) and data not in ("on", "off"):
            self.statusBar().showMessage(data, 20000)

    def _on_rt_event(self, kind, data):
        if kind == "status":
            self._update_rt_label()
        elif kind == "threat":
            self.notify(f"Ameaça {data.verdict}: {data.threat_name}", f"{data.path}\nAção: {data.action}")
            self.statusBar().showMessage(f"[Tempo real] {data.threat_name} — {data.action}", 10000)
        elif kind == "ransomware":
            p = data.get("process") or {}
            self.notify("ATIVIDADE DE RANSOMWARE DETECTADA",
                        f"{data['count']} arquivos cifrados em segundos. Processo suspeito: {p.get('name', '?')}"
                        + (" (suspenso)" if data.get("suspended") else ""))
            QMessageBox.critical(self, "Ransomware detectado",
                                 f"{data['count']} arquivos foram cifrados em poucos segundos.\n\nProcesso mais "
                                 f"suspeito: {p.get('name', '?')} (PID {p.get('pid', '?')})\n{p.get('exe', '')}\n\n"
                                 + ("O processo foi SUSPENSO. " if data.get("suspended") else "")
                                 + "Verifique a aba Processos e restaure seus arquivos a partir dos backups.")

    def _on_scan_finished(self, stats):
        n = len(stats.threats)
        msg = f"{scanner.KIND_NAMES.get(stats.kind, 'Verificação')} concluída: {stats.files} arquivos, {n} ameaça(s)."
        self.statusBar().showMessage(msg, 15000)
        if not self.isVisible() or self.isMinimized():
            self.notify("Verificação concluída", msg, critical=bool(n))

    def _check_schedule(self):
        s = self.ctx.settings
        if not s.scheduled_scan_enabled or self.ctx.scanning:
            return
        now = datetime.datetime.now()
        today = now.strftime("%Y-%m-%d")
        if s.last_scheduled_run == today:
            return
        hh, mm = (s.scheduled_scan_time.split(":") + ["0"])[:2]
        if (now.hour, now.minute) >= (int(hh), int(mm)):
            s.last_scheduled_run = today
            config.save()
            self.pages["scan"].start(s.scheduled_scan_type)
            self.notify("Verificação agendada", "Iniciando verificação agendada.", critical=False)

    # ------------------------------------------------------------------ fechar
    def closeEvent(self, e):
        if not self._really_quit and self.tray and self.ctx.settings.minimize_to_tray:
            e.ignore()
            self.hide()
            if not getattr(self, "_told", False):
                self._told = True
                self.notify(APP_NAME, "O antivírus continua protegendo em segundo plano. Use o ícone da bandeja para "
                                      "abrir ou sair.", critical=False)
            return
        self.ctx.shutdown()
        e.accept()
        QApplication.instance().quit()

    def quit_app(self):
        self._really_quit = True
        self.close()
