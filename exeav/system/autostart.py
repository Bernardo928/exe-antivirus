"""Faz o próprio antivírus iniciar junto com o sistema."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from .. import APP_NAME, paths

_WIN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_WIN_NAME = "EXEAntivirus"


def _command() -> str:
    if paths.IS_FROZEN:
        return f'"{sys.executable}" --minimized'
    main = Path(__file__).resolve().parents[2] / "main.py"
    return f'"{sys.executable}" "{main}" --minimized'


def _desktop_file() -> Path:
    return Path.home() / ".config" / "autostart" / "exe-antivirus.desktop"


def is_enabled() -> bool:
    if paths.IS_WINDOWS:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WIN_KEY) as k:
                winreg.QueryValueEx(k, _WIN_NAME)
                return True
        except OSError:
            return False
    return _desktop_file().exists()


def set_enabled(enabled: bool) -> None:
    if paths.IS_WINDOWS:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WIN_KEY, 0, winreg.KEY_SET_VALUE) as k:
            if enabled:
                winreg.SetValueEx(k, _WIN_NAME, 0, winreg.REG_SZ, _command())
            else:
                try:
                    winreg.DeleteValue(k, _WIN_NAME)
                except OSError:
                    pass
        return
    f = _desktop_file()
    if enabled:
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(f"[Desktop Entry]\nType=Application\nName={APP_NAME}\nExec={_command()}\n"
                     "X-GNOME-Autostart-enabled=true\nTerminal=false\n", "utf-8")
    elif f.exists():
        os.remove(f)
