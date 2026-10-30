"""Tema visual escuro da aplicação."""

BG = "#0b1016"
SURFACE = "#121922"
SURFACE2 = "#18212c"
SURFACE3 = "#1f2a37"
BORDER = "#253242"
TEXT = "#e6edf3"
MUTED = "#8b98a9"
ACCENT = "#3b8cff"
ACCENT_HOVER = "#5aa0ff"
SUCCESS = "#22c55e"
WARNING = "#f5a524"
DANGER = "#ef4444"
INFO = "#38bdf8"

VERDICT_COLORS = {"malicioso": DANGER, "suspeito": WARNING, "limpo": SUCCESS}
SEVERITY_COLORS = {"critica": "#ff5c63", "alta": DANGER, "media": WARNING, "baixa": INFO, "info": SUCCESS}

QSS = f"""
* {{ font-size: 13px; color: {TEXT}; }}
QMainWindow, QWidget#root {{ background: {BG}; }}
QWidget {{ background: transparent; }}
QToolTip {{ background: {SURFACE3}; color: {TEXT}; border: 1px solid {BORDER}; padding: 6px; border-radius: 6px; }}

#sidebar {{ background: {SURFACE}; border-right: 1px solid {BORDER}; }}
#brand {{ font-size: 17px; font-weight: 700; }}
#brandSub {{ color: {MUTED}; font-size: 11px; }}
QPushButton#nav {{
    text-align: left; padding: 10px 14px; border: none; border-radius: 10px; color: {MUTED};
    font-size: 13px; font-weight: 500; background: transparent;
}}
QPushButton#nav:hover {{ background: {SURFACE2}; color: {TEXT}; }}
QPushButton#nav:checked {{ background: {SURFACE3}; color: {TEXT}; font-weight: 600; }}

#pageTitle {{ font-size: 22px; font-weight: 700; }}
#pageSub {{ color: {MUTED}; font-size: 13px; }}
#sectionTitle {{ font-size: 15px; font-weight: 650; }}
#muted {{ color: {MUTED}; }}
#small {{ color: {MUTED}; font-size: 11px; }}
#mono {{ font-family: "Cascadia Mono", "Consolas", "DejaVu Sans Mono", monospace; font-size: 12px; }}

QFrame#card {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 14px; }}
QFrame#cardHover {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 14px; }}
QFrame#cardHover:hover {{ border: 1px solid {ACCENT}; background: {SURFACE2}; }}
QFrame#banner {{ border-radius: 14px; }}

QPushButton {{
    background: {SURFACE3}; border: 1px solid {BORDER}; border-radius: 9px; padding: 8px 14px; font-weight: 500;
}}
QPushButton:hover {{ background: #263345; border-color: #33465c; }}
QPushButton:pressed {{ background: {SURFACE2}; }}
QPushButton:disabled {{ color: #5b6878; background: {SURFACE2}; border-color: {SURFACE3}; }}
QPushButton#primary {{ background: {ACCENT}; border: 1px solid {ACCENT}; color: white; font-weight: 600; }}
QPushButton#primary:hover {{ background: {ACCENT_HOVER}; }}
QPushButton#primary:disabled {{ background: #2a4a73; border-color: #2a4a73; color: #9fb4cc; }}
QPushButton#danger {{ background: #3a1518; border: 1px solid #6b2328; color: #ffb3b6; }}
QPushButton#danger:hover {{ background: #4c1b1f; }}
QPushButton#success {{ background: #133222; border: 1px solid #1f5c3a; color: #9ff0bf; }}
QPushButton#success:hover {{ background: #18402b; }}

QLineEdit, QSpinBox, QComboBox, QTimeEdit, QPlainTextEdit, QTextEdit {{
    background: {SURFACE2}; border: 1px solid {BORDER}; border-radius: 8px; padding: 6px 8px;
    selection-background-color: {ACCENT};
}}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{ border-color: {ACCENT}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QAbstractSpinBox::up-button, QAbstractSpinBox::down-button {{ width: 0px; border: none; }}
QComboBox QAbstractItemView {{ background: {SURFACE2}; border: 1px solid {BORDER}; selection-background-color: {SURFACE3}; }}

QTableWidget, QTreeWidget, QListWidget, QTableView {{
    background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 10px; gridline-color: {SURFACE2};
    alternate-background-color: #141c26; selection-background-color: #23344a; selection-color: {TEXT};
}}
QTableWidget::item, QTreeWidget::item, QListWidget::item {{ padding: 4px 6px; }}
QListWidget::item {{ border-radius: 8px; margin: 2px 4px; padding: 8px; }}
QListWidget::item:selected {{ background: {SURFACE3}; }}
QListWidget::item:hover {{ background: {SURFACE2}; }}
QHeaderView::section {{
    background: {SURFACE2}; color: {MUTED}; border: none; border-bottom: 1px solid {BORDER};
    padding: 7px 8px; font-weight: 600; font-size: 12px;
}}
QTableCornerButton::section {{ background: {SURFACE2}; border: none; }}

QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 12px; top: -1px; background: {SURFACE}; }}
QTabBar::tab {{
    background: transparent; color: {MUTED}; padding: 8px 10px; margin-right: 1px; border: none;
    border-bottom: 2px solid transparent; font-weight: 500;
}}
QTabBar::tab:selected {{ color: {TEXT}; border-bottom: 2px solid {ACCENT}; }}
QTabBar::tab:hover {{ color: {TEXT}; }}

QProgressBar {{ background: {SURFACE2}; border: none; border-radius: 6px; height: 12px; text-align: center; color: transparent; }}
QProgressBar::chunk {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {ACCENT}, stop:1 #6fb6ff); border-radius: 6px; }}

QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{ width: 18px; height: 18px; border-radius: 5px; border: 1px solid {BORDER}; background: {SURFACE2}; }}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; image: none; }}

QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: #2b3a4d; border-radius: 4px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: #3a4d66; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: #2b3a4d; border-radius: 4px; min-width: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}
QSplitter::handle {{ background: {BG}; }}
QMenu {{ background: {SURFACE2}; border: 1px solid {BORDER}; padding: 6px; border-radius: 8px; }}
QMenu::item {{ padding: 6px 18px; border-radius: 6px; }}
QMenu::item:selected {{ background: {SURFACE3}; }}
QStatusBar {{ background: {SURFACE}; color: {MUTED}; border-top: 1px solid {BORDER}; }}
QMessageBox {{ background: {SURFACE}; }}
QDialog {{ background: {SURFACE}; }}
QGroupBox {{ border: 1px solid {BORDER}; border-radius: 12px; margin-top: 14px; padding: 14px 12px 12px 12px; background: {SURFACE}; font-weight: 600; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 14px; padding: 0 6px; color: {TEXT}; }}
"""
