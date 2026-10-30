"""Componentes visuais reutilizáveis."""
from __future__ import annotations

import math
import os
import subprocess
import sys
import threading

from PySide6.QtCore import QObject, QPointF, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (QAbstractItemView, QFrame, QHBoxLayout, QHeaderView, QLabel, QMessageBox,
                               QPushButton, QSizePolicy, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from . import icons, theme


# --------------------------------------------------------------------------- execução em segundo plano
class _Runner(QObject):
    done = Signal(object)
    failed = Signal(object)


_runners: set = set()


def run_bg(fn, on_done=None, on_error=None) -> None:
    """Executa fn() em uma thread e entrega o resultado na thread da interface."""
    r = _Runner()
    _runners.add(r)

    def finish_ok(v):
        _runners.discard(r)
        if on_done:
            on_done(v)

    def finish_err(e):
        _runners.discard(r)
        if on_error:
            on_error(e)
        else:
            QMessageBox.warning(None, "Erro", str(e))

    r.done.connect(finish_ok, Qt.QueuedConnection)
    r.failed.connect(finish_err, Qt.QueuedConnection)

    def work():
        try:
            v = fn()
        except Exception as e:  # noqa: BLE001
            r.failed.emit(e)
        else:
            r.done.emit(v)

    threading.Thread(target=work, daemon=True).start()


class Debouncer(QObject):
    """Agrupa muitos pedidos de atualização em uma só execução (evita travar a interface com rajadas de eventos)."""

    def __init__(self, fn, delay_ms: int = 400, parent=None):
        super().__init__(parent)
        self._fn = fn
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(delay_ms)
        self._timer.timeout.connect(fn)

    def trigger(self, *_):
        if not self._timer.isActive():
            self._timer.start()


# --------------------------------------------------------------------------- utilitários
def open_location(path: str) -> None:
    folder = path if os.path.isdir(path) else os.path.dirname(path)
    try:
        if sys.platform.startswith("win"):
            if os.path.isfile(path):
                subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
            else:
                os.startfile(folder)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", folder])
        else:
            subprocess.Popen(["xdg-open", folder], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def confirm(parent, title: str, text: str) -> bool:
    return QMessageBox.question(parent, title, text, QMessageBox.Yes | QMessageBox.No,
                                QMessageBox.No) == QMessageBox.Yes


def label(text: str = "", obj: str = "", wrap: bool = False) -> QLabel:
    lb = QLabel(text)
    if obj:
        lb.setObjectName(obj)
    lb.setWordWrap(wrap)
    return lb


def button(text: str, icon_name: str = "", kind: str = "", tip: str = "") -> QPushButton:
    b = QPushButton(text)
    if icon_name:
        color = "#ffffff" if kind == "primary" else {"danger": "#ffb3b6", "success": "#9ff0bf"}.get(kind, theme.TEXT)
        b.setIcon(icons.icon(icon_name, color, 16))
        b.setIconSize(QSize(16, 16))
    if kind:
        b.setObjectName(kind)
    if tip:
        b.setToolTip(tip)
    b.setCursor(Qt.PointingHandCursor)
    return b


class Card(QFrame):
    def __init__(self, hover: bool = False, parent=None):
        super().__init__(parent)
        self.setObjectName("cardHover" if hover else "card")
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(18, 16, 18, 16)
        self.lay.setSpacing(10)


class PageHeader(QWidget):
    def __init__(self, title: str, subtitle: str, icon_name: str):
        super().__init__()
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(14)
        ic = QLabel()
        ic.setPixmap(icons.pixmap(icon_name, theme.ACCENT, 30))
        ic.setFixedSize(46, 46)
        ic.setAlignment(Qt.AlignCenter)
        ic.setStyleSheet(f"background:{theme.SURFACE2}; border:1px solid {theme.BORDER}; border-radius:12px;")
        h.addWidget(ic)
        v = QVBoxLayout()
        v.setSpacing(2)
        v.addWidget(label(title, "pageTitle"))
        v.addWidget(label(subtitle, "pageSub", wrap=True))
        h.addLayout(v, 1)
        self.right = QHBoxLayout()
        self.right.setSpacing(8)
        h.addLayout(self.right)


class StatCard(QFrame):
    def __init__(self, title: str, value: str, icon_name: str, color: str = theme.ACCENT):
        super().__init__()
        self.setObjectName("card")
        h = QHBoxLayout(self)
        h.setContentsMargins(16, 14, 16, 14)
        h.setSpacing(12)
        ic = QLabel()
        ic.setPixmap(icons.pixmap(icon_name, color, 22))
        ic.setFixedSize(42, 42)
        ic.setAlignment(Qt.AlignCenter)
        c = QColor(color)
        ic.setStyleSheet(f"background: rgba({c.red()},{c.green()},{c.blue()},38); border-radius: 11px;")
        h.addWidget(ic)
        v = QVBoxLayout()
        v.setSpacing(0)
        self.value = label(value)
        self.value.setStyleSheet("font-size: 20px; font-weight: 700;")
        v.addWidget(self.value)
        v.addWidget(label(title, "muted"))
        h.addLayout(v, 1)

    def set(self, value) -> None:
        self.value.setText(str(value))


class Badge(QLabel):
    def __init__(self, text: str = "", color: str = theme.SUCCESS):
        super().__init__(text)
        self.set(text, color)

    def set(self, text: str, color: str) -> None:
        c = QColor(color)
        self.setText(text)
        self.setStyleSheet(f"background: rgba({c.red()},{c.green()},{c.blue()},45); color: {color}; "
                           f"border: 1px solid rgba({c.red()},{c.green()},{c.blue()},110); border-radius: 9px; "
                           f"padding: 3px 10px; font-weight: 700; font-size: 12px;")


class ShieldStatus(QWidget):
    """Grande escudo animado que mostra o estado de proteção."""

    def __init__(self):
        super().__init__()
        self.state = "ok"
        self.setFixedSize(150, 160)
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(50)

    def _tick(self):
        if self.isVisible():
            self._phase = (self._phase + 0.06) % (2 * math.pi)
            self.update()

    def set_state(self, state: str) -> None:
        self.state = state
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        col = {"ok": theme.SUCCESS, "warn": theme.WARNING, "danger": theme.DANGER}[self.state]
        c = QColor(col)
        w, h = self.width(), self.height()
        glow = 0.5 + 0.5 * math.sin(self._phase)
        for i in range(4, 0, -1):
            cc = QColor(c)
            cc.setAlpha(int(14 * i * (0.6 + 0.4 * glow)))
            p.setPen(Qt.NoPen)
            p.setBrush(cc)
            r = 52 + i * 7
            p.drawEllipse(QPointF(w / 2, h / 2), r, r)
        s = 4.6
        ox, oy = w / 2 - 12 * s, h / 2 - 12 * s
        path = QPainterPath()
        path.moveTo(ox + 12 * s, oy + 22.5 * s)
        path.cubicTo(ox + 12 * s, oy + 22.5 * s, ox + 20.5 * s, oy + 18.5 * s, ox + 20.5 * s, oy + 12 * s)
        path.lineTo(ox + 20.5 * s, oy + 4.6 * s)
        path.lineTo(ox + 12 * s, oy + 1.5 * s)
        path.lineTo(ox + 3.5 * s, oy + 4.6 * s)
        path.lineTo(ox + 3.5 * s, oy + 12 * s)
        path.cubicTo(ox + 3.5 * s, oy + 18.5 * s, ox + 12 * s, oy + 22.5 * s, ox + 12 * s, oy + 22.5 * s)
        g = QLinearGradient(0, oy, 0, oy + 24 * s)
        g.setColorAt(0, c.lighter(130))
        g.setColorAt(1, c.darker(150))
        p.fillPath(path, g)
        pen = QPen(QColor("white"), 2.4 * s, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
        p.setPen(pen)
        if self.state == "ok":
            m = QPainterPath()
            m.moveTo(ox + 8.2 * s, oy + 12.2 * s)
            m.lineTo(ox + 11 * s, oy + 15 * s)
            m.lineTo(ox + 16 * s, oy + 9.3 * s)
            p.drawPath(m)
        else:
            p.drawLine(QPointF(ox + 12 * s, oy + 7.5 * s), QPointF(ox + 12 * s, oy + 13 * s))
            p.drawPoint(QPointF(ox + 12 * s, oy + 16.6 * s))
        p.end()


class ScoreGauge(QWidget):
    """Medidor circular da pontuação de risco."""

    def __init__(self, size: int = 120):
        super().__init__()
        self.score = 0
        self.color = theme.SUCCESS
        self.setFixedSize(size, size)

    def set(self, score: int, verdict: str) -> None:
        self.score = score
        self.color = theme.VERDICT_COLORS.get(verdict, theme.SUCCESS)
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(10, 10, self.width() - 20, self.height() - 20)
        pen = QPen(QColor(theme.SURFACE3), 10, Qt.SolidLine, Qt.RoundCap)
        p.setPen(pen)
        p.drawArc(r, 225 * 16, -270 * 16)
        pen.setColor(QColor(self.color))
        p.setPen(pen)
        frac = min(self.score, 100) / 100.0
        p.drawArc(r, 225 * 16, int(-270 * 16 * frac))
        p.setPen(QColor(theme.TEXT))
        f = QFont(self.font())
        f.setPointSize(20)
        f.setBold(True)
        p.setFont(f)
        p.drawText(QRectF(0, 0, self.width(), self.height() - 8), Qt.AlignCenter, str(self.score))
        f.setPointSize(7)
        f.setBold(False)
        p.setFont(f)
        p.setPen(QColor(theme.MUTED))
        w = self.width()
        p.drawText(QRectF(w * 0.2, self.height() * 0.80, w * 0.6, 16), Qt.AlignCenter, "pontos")
        p.end()


class EntropyChart(QWidget):
    """Gráfico da entropia ao longo do arquivo (dados cifrados/compactados aparecem em vermelho)."""

    def __init__(self):
        super().__init__()
        self.values: list[float] = []
        self.setMinimumHeight(170)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set(self, values: list[float]) -> None:
        self.values = values or []
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(self.rect(), QColor(theme.SURFACE))
        left, bottom, top = 34, h - 22, 10
        ch = bottom - top
        p.setPen(QPen(QColor(theme.BORDER), 1, Qt.DashLine))
        f = QFont(self.font())
        f.setPointSize(8)
        p.setFont(f)
        for v in (0, 2, 4, 6, 8):
            y = bottom - ch * v / 8
            p.drawLine(left, int(y), w - 8, int(y))
            p.setPen(QColor(theme.MUTED))
            p.drawText(4, int(y) + 4, str(v))
            p.setPen(QPen(QColor(theme.BORDER), 1, Qt.DashLine))
        p.setPen(QColor(theme.MUTED))
        p.drawText(left, h - 4, "início do arquivo")
        p.drawText(w - 90, h - 4, "fim do arquivo")
        if not self.values:
            p.end()
            return
        n = len(self.values)
        bw = (w - 8 - left) / n
        for i, v in enumerate(self.values):
            col = QColor(theme.DANGER if v > 7.2 else theme.WARNING if v > 6.0 else theme.ACCENT)
            col.setAlpha(210)
            bh = ch * v / 8
            p.fillRect(QRectF(left + i * bw, bottom - bh, max(1.0, bw - 0.6), bh), QBrush(col))
        p.end()


class DataTable(QTableWidget):
    """Tabela padronizada (somente leitura, seleção por linha, ordenável)."""

    def __init__(self, headers: list[str], stretch_col: int = -1):
        super().__init__(0, len(headers))
        self.setHorizontalHeaderLabels(headers)
        self.verticalHeader().setVisible(False)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setAlternatingRowColors(True)
        self.setShowGrid(False)
        self.setWordWrap(False)
        self.verticalHeader().setDefaultSectionSize(34)
        hh = self.horizontalHeader()
        hh.setHighlightSections(False)
        hh.setSectionResizeMode(QHeaderView.Interactive)
        hh.setStretchLastSection(stretch_col == -1)
        if stretch_col >= 0:
            hh.setSectionResizeMode(stretch_col, QHeaderView.Stretch)

    def add_row(self, values: list, color: str | None = None, data=None, colors: dict | None = None) -> int:
        sorting = self.isSortingEnabled()
        self.setSortingEnabled(False)
        r = self.rowCount()
        self.insertRow(r)
        for c, v in enumerate(values):
            it = QTableWidgetItem()
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                it.setData(Qt.DisplayRole, v)
            else:
                it.setText("" if v is None else str(v))
                it.setToolTip("" if v is None else str(v)[:2000])
            if colors and colors.get(c):
                it.setForeground(QColor(colors[c]))
            elif color and c == 0:
                it.setForeground(QColor(color))
            if c == 0 and data is not None:
                it.setData(Qt.UserRole, data)
            self.setItem(r, c, it)
        self.setSortingEnabled(sorting)
        return r

    def row_data(self, row: int):
        it = self.item(row, 0)
        return it.data(Qt.UserRole) if it else None

    def selected_data(self) -> list:
        rows = sorted({i.row() for i in self.selectedIndexes()})
        return [self.row_data(r) for r in rows]

    def clear_rows(self) -> None:
        self.setRowCount(0)


class EmptyState(QWidget):
    def __init__(self, icon_name: str, title: str, text: str):
        super().__init__()
        v = QVBoxLayout(self)
        v.setAlignment(Qt.AlignCenter)
        ic = QLabel()
        ic.setPixmap(icons.pixmap(icon_name, theme.MUTED, 42))
        ic.setAlignment(Qt.AlignCenter)
        v.addWidget(ic)
        t = label(title, "sectionTitle")
        t.setAlignment(Qt.AlignCenter)
        v.addWidget(t)
        s = label(text, "muted", wrap=True)
        s.setAlignment(Qt.AlignCenter)
        v.addWidget(s)
