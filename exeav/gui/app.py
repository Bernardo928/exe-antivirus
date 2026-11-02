"""Inicialização da interface gráfica."""
from __future__ import annotations

import os
import sys

from PySide6.QtCore import QLockFile, Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication, QMessageBox

from .. import APP_NAME, paths


def run(argv: list[str]) -> int:
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("ExeAntivirus.App")
        except Exception:
            pass
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("EXE")
    app.setQuitOnLastWindowClosed(False)
    f = QFont("Segoe UI" if sys.platform.startswith("win") else "Inter")
    f.setStyleHint(QFont.SansSerif)
    f.setPointSizeF(10)
    app.setFont(f)

    from . import icons, theme
    app.setWindowIcon(icons.app_icon())
    app.setStyleSheet(theme.QSS + check_indicator_qss())

    lock = QLockFile(str(paths.data_dir() / "instance.lock"))
    lock.setStaleLockTime(0)
    if not lock.tryLock(4000):
        QMessageBox.information(None, APP_NAME, "O EXE Antivirus já está em execução (veja o ícone na bandeja do sistema).")
        return 0

    from .context import AppContext
    from .main_window import MainWindow
    ctx = AppContext()
    win = MainWindow(ctx)
    minimized = "--minimized" in argv or ctx.settings.start_minimized
    if not (minimized and win.tray):
        win.show()
    if ctx.settings.realtime_enabled and os.environ.get("EXEAV_NO_REALTIME") != "1":
        try:
            ctx.realtime.start()
        except Exception as e:  # nunca impedir a abertura do programa
            win.statusBar().showMessage(f"Falha ao iniciar a proteção em tempo real: {e}")
    if os.environ.get("EXEAV_NO_REALTIME") != "1":
        start_services(ctx, win)
    win.pages["dashboard"].refresh()
    code = app.exec()
    ctx.shutdown()
    lock.unlock()
    return code


def start_services(ctx, win) -> None:
    """Liga os escudos configurados. Uma falha em um deles nunca impede os outros nem a abertura do programa."""
    import threading

    from .. import dnsguard, firewall
    s = ctx.settings
    for enabled, svc, name in ((s.botnet_shield, ctx.botnet, "escudo anti-botnet"),
                               (s.usb_guard, ctx.usb, "proteção de pen drives"),
                               (s.script_guard and s.realtime_enabled, ctx.scripts, "análise de scripts"),
                               (s.boot_guard, ctx.boot, "proteção ao ligar")):
        if not enabled:
            continue
        try:
            svc.start()
        except Exception as e:
            win.statusBar().showMessage(f"Falha ao iniciar {name}: {e}")

    def background():
        try:
            from ..system import install
            if install.appimage_first_run():
                ctx.bridge.boot_event.emit("status", "EXE Antivirus adicionado ao menu de aplicativos e à "
                                                     "inicialização automática.")
        except Exception:
            pass
        # regras do nftables/iptables somem ao reiniciar; a proteção ao ligar reaplica no boot, e aqui
        # garantimos o mesmo para quem abre o antivírus depois (independente do escudo anti-botnet)
        if not s.boot_guard:
            try:
                firewall.reapply()
            except Exception:
                pass
        try:
            from .. import selfprotect
            bad = [c for c in selfprotect.run_all() if c["ok"] is False]
            if bad:
                ctx.bridge.boot_event.emit("status", "AUTOPROTEÇÃO: " + "; ".join(f"{c['nome']}: {c['detalhe'][:80]}"
                                                                                   for c in bad))
        except Exception:
            pass
        msg = dnsguard.on_app_start(s.dns_blocked_sites)
        if msg:
            ctx.bridge.boot_event.emit("status", msg)
    threading.Thread(target=background, daemon=True, name="startup-tasks").start()


def check_indicator_qss() -> str:
    """Desenha a marca de seleção das caixas de seleção (QSS só aceita imagens em arquivo)."""
    from . import icons
    try:
        p = paths.data_dir() / "ui-check.png"
        icons.pixmap("check", "#ffffff", 14, 3.0).save(str(p), "PNG")
        return "QCheckBox::indicator:checked { image: url(%s); }" % p.as_posix()
    except Exception:
        return ""


def smoke_test(png_path: str) -> int:
    """Abre a interface, percorre todas as abas, salva uma captura e sai (usado no CI)."""
    from PySide6.QtCore import QEventLoop, QTimer
    os.environ.setdefault("EXEAV_NO_REALTIME", "1")
    app = QApplication([sys.argv[0]])
    from . import icons, theme
    app.setStyleSheet(theme.QSS + check_indicator_qss())
    app.setWindowIcon(icons.app_icon())
    from .context import AppContext
    from .main_window import NAV, MainWindow
    ctx = AppContext()
    win = MainWindow(ctx)
    win.resize(1360, 860)
    win.show()

    def pump(ms):
        loop = QEventLoop()
        QTimer.singleShot(ms, loop.quit)
        loop.exec()
    for key, _t, _i in NAV:
        win.go(key)
        pump(150)
    win.go("dashboard")
    pump(300)
    ok = win.grab().save(png_path)
    ctx.shutdown()
    win._really_quit = True
    win.close()
    print("SMOKE-TEST:", "OK" if ok else "FALHOU", png_path)
    return 0 if ok else 1
