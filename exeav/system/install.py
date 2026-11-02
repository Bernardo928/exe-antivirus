"""Instalação no sistema (chamada pelo instalador do Windows e pelo AppImage no Linux).

    ExeAntivirus --install-system [--autostart] [--pslog] [--boot-service]
    ExeAntivirus --uninstall-system

Instalar:
- Windows: tarefa agendada no logon (proteção desde a inicialização) e, opcionalmente, o registro de
  blocos de script do PowerShell (análise de scripts por dentro). Os atalhos e arquivos ficam por conta do
  instalador (Inno Setup).
- Linux (AppImage): atalho no menu de aplicativos, ícone, inicialização automática e, se executado como
  administrador, o serviço "exe-antivirus-boot" que reaplica os bloqueios do firewall a cada boot,
  antes mesmo do login.

Desinstalar desfaz tudo o que o antivírus mudou no sistema: tarefa/inicialização, DNS, sites bloqueados no
arquivo hosts, regras de firewall e o registro do PowerShell (se foi ligado pelo instalador).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from .. import APP_NAME, history, paths
from . import autostart

BOOT_UNIT = Path("/etc/systemd/system/exe-antivirus-boot.service")


def _marker() -> Path:
    return paths.data_dir() / "install.json"


def _load_marker() -> dict:
    try:
        return json.loads(_marker().read_text("utf-8"))
    except (OSError, ValueError):
        return {}


def _save_marker(d: dict) -> None:
    _marker().write_text(json.dumps(d, ensure_ascii=False, indent=1), "utf-8")


def _icon_source() -> Path | None:
    for c in (paths.resource_path("assets/icon.png"), paths.app_root() / "icon.png",
              paths.app_root() / "assets" / "icon.png"):
        if c.is_file():
            return c
    return None


# --------------------------------------------------------------------------- Linux
def _linux_menu_entry() -> Path:
    return Path.home() / ".local" / "share" / "applications" / "exe-antivirus.desktop"


def _linux_icon() -> Path:
    return Path.home() / ".local" / "share" / "icons" / "hicolor" / "256x256" / "apps" / "exe-antivirus.png"


def linux_installed() -> bool:
    return _linux_menu_entry().exists()


def _linux_install_user() -> list[str]:
    done = []
    launch = " ".join(f'"{p}"' if " " in p else p for p in paths.launcher())
    ico = _icon_source()
    if ico:
        _linux_icon().parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ico, _linux_icon())
    e = _linux_menu_entry()
    e.parent.mkdir(parents=True, exist_ok=True)
    e.write_text(f"[Desktop Entry]\nType=Application\nName={APP_NAME}\nGenericName=Antivírus\n"
                 "Comment=Proteção contra vírus, botnets, ransomware e sites maliciosos\n"
                 f"Exec={launch}\nIcon=exe-antivirus\nTerminal=false\nCategories=System;Security;Utility;\n"
                 "Keywords=antivirus;virus;malware;firewall;segurança;\nStartupWMClass=ExeAntivirus\n", "utf-8")
    os.chmod(e, 0o755)
    done.append(f"atalho no menu ({e})")
    for cmd in (["update-desktop-database", str(e.parent)], ["gtk-update-icon-cache", "-q", "-t",
                                                              str(_linux_icon().parents[2])]):
        if shutil.which(cmd[0]):
            subprocess.run(cmd, capture_output=True, timeout=30)
    return done


def _real_user_home() -> tuple[str, Path]:
    """Usuário que chamou sudo/pkexec (o serviço de boot usa os dados dele)."""
    import pwd
    uid = os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID")
    if uid:
        pw = pwd.getpwuid(int(uid))
    else:
        pw = pwd.getpwuid(os.getuid())
    return pw.pw_name, Path(pw.pw_dir)


def _linux_install_boot_service() -> str:
    if os.geteuid() != 0:
        raise PermissionError("o serviço de boot precisa ser instalado como administrador (sudo/pkexec)")
    user, home = _real_user_home()
    data = paths.data_dir() if not os.environ.get("PKEXEC_UID") and not os.environ.get("SUDO_UID") \
        else home / ".local" / "share" / "exe-antivirus"
    launch = " ".join(f'"{p}"' if " " in p else p for p in paths.launcher())
    BOOT_UNIT.write_text(f"""[Unit]
Description=EXE Antivirus - reaplica os bloqueios do firewall ao ligar
After=network-pre.target nftables.service ufw.service firewalld.service
Wants=network-pre.target

[Service]
Type=oneshot
Environment=EXEAV_DATA_DIR={data}
ExecStart={launch} --boot-tasks
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
""", "utf-8")
    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=60)
        subprocess.run(["systemctl", "enable", BOOT_UNIT.name], capture_output=True, timeout=60)
    return f"serviço de boot {BOOT_UNIT.name} (dados de {user})"


# --------------------------------------------------------------------------- API
def install(autostart_on: bool = True, pslog: bool = False, boot_service: bool = False) -> list[str]:
    done: list[str] = []
    marker = _load_marker()
    if paths.IS_WINDOWS:
        if autostart_on:
            autostart.set_enabled(True)
            done.append("tarefa agendada no logon" if autostart.task_exists() else "inicialização automática")
        if pslog:
            from .. import scriptguard
            if not scriptguard.logging_enabled():
                scriptguard.enable_logging(True)
                marker["pslog_by_installer"] = True
            done.append("registro de scripts do PowerShell")
    else:
        done += _linux_install_user()
        if autostart_on:
            autostart.set_enabled(True)
            done.append("inicialização automática")
        if boot_service:
            done.append(_linux_install_boot_service())
    marker["installed"] = True
    marker["launcher"] = paths.launcher()
    _save_marker(marker)
    history.log("instalação", "Instalado no sistema: " + ", ".join(done))
    return done


def uninstall() -> list[str]:
    """Remove tudo o que o antivírus mudou no sistema (os arquivos do programa ficam por conta do instalador)."""
    done: list[str] = []
    marker = _load_marker()

    def step(name, fn):
        try:
            fn()
            done.append(name)
        except Exception as e:  # noqa: BLE001 — desinstalar nunca pode parar no meio
            done.append(f"{name}: falhou ({e})")
    step("inicialização automática removida", lambda: autostart.set_enabled(False))
    from .. import dnsguard, firewall
    step("DNS original restaurado", dnsguard.revert)
    step("sites bloqueados removidos do hosts", lambda: dnsguard.apply_sites([]))
    step("regras de firewall removidas", firewall.remove_all)
    if paths.IS_WINDOWS and marker.get("pslog_by_installer"):
        from .. import scriptguard
        step("registro do PowerShell desligado", lambda: scriptguard.enable_logging(False))
    if not paths.IS_WINDOWS:
        def rm_linux():
            for p in (_linux_menu_entry(), _linux_icon()):
                if p.exists():
                    p.unlink()
            if os.geteuid() == 0 and BOOT_UNIT.exists():
                if shutil.which("systemctl"):
                    subprocess.run(["systemctl", "disable", BOOT_UNIT.name], capture_output=True, timeout=60)
                BOOT_UNIT.unlink()
        step("atalhos removidos", rm_linux)
    marker.update({"installed": False})
    _save_marker(marker)
    history.log("instalação", "Removido do sistema: " + "; ".join(done))
    return done


def kill_other_instances() -> None:
    """Fecha outras cópias abertas do antivírus (o desinstalador precisa apagar os arquivos)."""
    import psutil
    me = os.getpid()
    mine = {paths.norm(p) for p in paths.self_executables()}
    for p in psutil.process_iter(["pid", "exe"]):
        try:
            if p.pid != me and p.info["exe"] and paths.norm(p.info["exe"]) in mine:
                p.kill()
        except (psutil.Error, OSError):
            continue


def boot_tasks() -> int:
    """Executado pelo serviço de boot (Linux, como root): reaplica os bloqueios do firewall."""
    from .. import firewall
    n = firewall.reapply()
    history.log("firewall", f"Serviço de boot: {n} bloqueio(s) reaplicado(s)")
    print(f"{n} bloqueio(s) reaplicado(s)")
    return 0


def appimage_first_run() -> bool:
    """No primeiro uso do AppImage: cria o atalho no menu e a inicialização automática (uma vez só)."""
    if paths.IS_WINDOWS or not os.environ.get("APPIMAGE"):
        return False
    m = _load_marker()
    if m.get("installed") is not None and m.get("launcher") == paths.launcher():
        return False
    try:
        install(autostart_on=True)
        return True
    except Exception:
        return False
