"""Faz o próprio antivírus iniciar junto com o sistema.

- Windows: tarefa agendada "EXE Antivirus" no logon, com privilégios elevados (sem pedir UAC a cada
  inicialização — firewall, DNS e proteção de inicialização precisam de administrador). Sem permissão de
  administrador, usa a chave Run do usuário.
- Linux: arquivo .desktop em ~/.config/autostart (abre no login da sessão gráfica).
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .. import APP_NAME, paths

_WIN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_WIN_NAME = "EXEAntivirus"
TASK_NAME = "EXE Antivirus"
BOOT_ARGS = ["--minimized", "--boot"]


def _quote(parts: list[str]) -> str:
    return " ".join(f'"{p}"' if (" " in p or not p) else p for p in parts)


def _command() -> str:
    return _quote(paths.launcher() + BOOT_ARGS)


def _desktop_file() -> Path:
    return Path.home() / ".config" / "autostart" / "exe-antivirus.desktop"


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, creationflags=0x08000000)


# --------------------------------------------------------------------------- Windows: tarefa agendada
def task_exists() -> bool:
    if not paths.IS_WINDOWS:
        return False
    try:
        return _run(["schtasks", "/Query", "/TN", TASK_NAME]).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def create_task() -> None:
    """Tarefa no logon de qualquer usuário, com o nível mais alto de privilégio disponível para ele."""
    launch = paths.launcher()
    exe, args = launch[0], _quote(launch[1:] + BOOT_ARGS)
    ps = (f"$a = New-ScheduledTaskAction -Execute '{exe}' -Argument '{args}'; "
          "$t = New-ScheduledTaskTrigger -AtLogOn; "
          "$p = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Highest; "
          "$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries "
          "-ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew; "
          f"Register-ScheduledTask -TaskName '{TASK_NAME}' -Action $a -Trigger $t -Principal $p -Settings $s "
          "-Description 'Protege o computador desde a inicialização' -Force | Out-Null")
    r = _run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps])
    if r.returncode != 0:
        raise OSError((r.stderr or r.stdout).strip()[:400] or "falha ao criar a tarefa agendada")


def delete_task() -> None:
    if paths.IS_WINDOWS:
        _run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])


def _run_key(enabled: bool) -> None:
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WIN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if enabled:
            winreg.SetValueEx(k, _WIN_NAME, 0, winreg.REG_SZ, _command())
        else:
            try:
                winreg.DeleteValue(k, _WIN_NAME)
            except OSError:
                pass


def _run_key_exists() -> bool:
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WIN_KEY) as k:
            winreg.QueryValueEx(k, _WIN_NAME)
            return True
    except OSError:
        return False


# --------------------------------------------------------------------------- API
def is_enabled() -> bool:
    if paths.IS_WINDOWS:
        return task_exists() or _run_key_exists()
    return _desktop_file().exists()


def set_enabled(enabled: bool) -> None:
    if paths.IS_WINDOWS:
        from ..firewall import is_admin
        if enabled:
            if is_admin():
                create_task()
                _run_key(False)        # evita abrir duas vezes
            else:
                _run_key(True)
        else:
            if task_exists():
                delete_task()
            _run_key(False)
        return
    f = _desktop_file()
    if enabled:
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(f"[Desktop Entry]\nType=Application\nName={APP_NAME}\nExec={_command()}\n"
                     f"Icon=exe-antivirus\nX-GNOME-Autostart-enabled=true\nX-GNOME-Autostart-Delay=2\n"
                     "Terminal=false\nNoDisplay=true\n", "utf-8")
    elif f.exists():
        os.remove(f)
