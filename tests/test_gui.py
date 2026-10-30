"""Teste de fumaça da interface gráfica (modo offscreen)."""
import os

import pytest

import samples

pytest.importorskip("PySide6")


@pytest.fixture(scope="module")
def app():
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from PySide6.QtWidgets import QApplication
    from exeav.gui import theme
    a = QApplication.instance() or QApplication([])
    a.setStyleSheet(theme.QSS)
    return a


def _pump(ms=200):
    from PySide6.QtCore import QEventLoop, QTimer
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def test_all_tabs_open(app, tmp_path):
    from exeav.gui.context import AppContext
    from exeav.gui.main_window import NAV, MainWindow
    ctx = AppContext()
    win = MainWindow(ctx)
    win.show()
    for key, title, _ in NAV:
        win.go(key)
        _pump(100)
        assert win.stack.currentWidget() is win.pages[key]
    # Sala de Análise recebe um arquivo e mostra o motivo
    p = tmp_path / "suspeito.bat"
    p.write_bytes(b"vssadmin delete shadows /all /quiet\r\nbcdedit /set {default} recoveryenabled no\r\n")
    lid = ctx.lab.add_file(str(p))
    ctx.bridge.open_in_lab.emit(lid)
    _pump(300)
    lab = win.pages["lab"]
    assert lab.rep and lab.rep["verdict"] == "malicioso"
    assert lab.ind_table.rowCount() >= 1
    assert "MALICIOSO" in lab.explain.toPlainText()
    # varredura personalizada pela interface
    d = tmp_path / "pasta"
    d.mkdir()
    (d / "x.dat").write_bytes(samples.eicar())
    win.pages["scan"].start("custom", [str(d)])
    for _ in range(50):
        _pump(100)
        if not ctx.scanning:
            break
    _pump(300)
    assert win.pages["scan"].table.rowCount() == 1
    win.pages["scan"].quarantine(win.pages["scan"].results)
    assert len(ctx.quarantine.items()) == 1
    ctx.shutdown()
    win._really_quit = True
    win.close()
