"""Programas que iniciam com o sistema (pontos de persistência)."""
from __future__ import annotations

import datetime
import glob
import json
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

from .. import history, paths

SUSPICIOUS_CMD = re.compile(
    r"(?:-enc(?:odedcommand)?\s|downloadstring|invoke-expression|\biex\b|frombase64string|-w(?:indowstyle)?\s+hidden|"
    r"mshta\s|regsvr32[^\n]*/i:|rundll32[^\n]*javascript:|certutil[^\n]*-urlcache|/dev/tcp/|\bnc\s+-e|"
    r"curl[^|\n]*\|\s*(?:ba)?sh|wget[^|\n]*\|\s*(?:ba)?sh|base64\s+-d|/tmp/|/dev/shm/|\\temp\\|\\appdata\\local\\temp)",
    re.I)


_SHELL_WORDS = {"env", "sh", "bash", "dash", "zsh", "-c", "nohup", "exec", "test", "[", "[[", "if", "then", "cd",
                "true", "false", "sudo", "nice", "ionice", "run-parts", "flock", "timeout", "command"}


def _target_from_command(cmd: str) -> str:
    cmd = os.path.expandvars(cmd.strip())
    if not cmd:
        return ""
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        cand = cmd[1:end] if end > 0 else cmd[1:]
        return cand if os.path.isfile(cand) else ""
    if paths.IS_WINDOWS:
        m = re.match(r"(.+?\.(?:exe|bat|cmd|com|scr|ps1|vbs|js|dll|hta|lnk))\b", cmd, re.I)
        if m and os.path.isfile(m.group(1)):
            return m.group(1)
    try:
        parts = shlex.split(cmd)
    except ValueError:
        parts = cmd.split()
    # primeiro caminho absoluto de arquivo que não seja um utilitário de shell
    for p in parts:
        p = p.strip(";&|()")
        if os.path.isabs(p) and os.path.isfile(p) and os.path.basename(p) not in _SHELL_WORDS:
            return p
    for p in parts[:3]:
        if p in _SHELL_WORDS or p.startswith("-") or "=" in p:
            continue
        w = shutil.which(p)
        if w:
            return w
        break
    return ""


def _item(source: str, name: str, command: str, location: str, kind: str, removable: bool = True,
          target: str | None = None) -> dict:
    t = target if target is not None else _target_from_command(command)
    return {"source": source, "name": name, "command": command, "location": location, "kind": kind,
            "target": t, "removable": removable, "suspicious": bool(SUSPICIOUS_CMD.search(command or ""))}


# --------------------------------------------------------------------------- Windows
def _windows_items() -> list[dict]:
    import winreg
    out = []
    keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (32 bits)"),
    ]
    for hive, sub, label in keys:
        try:
            with winreg.OpenKey(hive, sub) as k:
                i = 0
                while True:
                    try:
                        name, val, _t = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    out.append(_item(label, name, str(val), f"{label}\\{name}", "registro"))
        except OSError:
            continue
    # Winlogon
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon") as k:
            for v in ("Shell", "Userinit"):
                try:
                    val = winreg.QueryValueEx(k, v)[0]
                    normal = {"shell": "explorer.exe", "userinit": "c:\\windows\\system32\\userinit.exe,"}
                    it = _item("Winlogon", v, str(val), f"HKLM Winlogon\\{v}", "registro", removable=False)
                    if str(val).strip().lower() != normal[v.lower()]:
                        it["suspicious"] = True
                    out.append(it)
                except OSError:
                    pass
    except OSError:
        pass
    folders = []
    if os.environ.get("APPDATA"):
        folders.append(Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    if os.environ.get("PROGRAMDATA"):
        folders.append(Path(os.environ["PROGRAMDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp")
    for f in folders:
        for p in f.glob("*") if f.exists() else []:
            if p.name.lower() == "desktop.ini":
                continue
            out.append(_item("Pasta Inicializar", p.name, str(p), str(p), "arquivo", target=str(p)))
    # Tarefas agendadas
    try:
        r = subprocess.run(["schtasks", "/query", "/fo", "csv", "/v"], capture_output=True, text=True, timeout=30,
                           creationflags=0x08000000)
        import csv
        rows = list(csv.reader(r.stdout.splitlines()))
        if rows:
            hdr = rows[0]
            idx_name = 1
            idx_run = next((i for i, h in enumerate(hdr) if "Run" in h or "Executar" in h or "Tarefa a" in h), None)
            seen = set()
            for row in rows[1:]:
                if len(row) <= max(idx_name, idx_run or 0) or row[0] == hdr[0]:
                    continue
                name = row[idx_name]
                if name.startswith("\\Microsoft\\") or name in seen:
                    continue
                seen.add(name)
                cmd = row[idx_run] if idx_run is not None else ""
                out.append(_item("Tarefa agendada", name, cmd, name, "tarefa", removable=True))
    except Exception:
        pass
    return out


# --------------------------------------------------------------------------- Linux
def _desktop_exec(p: Path) -> str:
    try:
        for line in p.read_text("utf-8", "replace").splitlines():
            if line.startswith("Exec="):
                return re.sub(r"%[a-zA-Z]", "", line[5:]).strip()
    except OSError:
        pass
    return ""


def _linux_items() -> list[dict]:
    out = []
    home = Path.home()
    for d, label in ((home / ".config" / "autostart", "Autostart (usuário)"), (Path("/etc/xdg/autostart"), "Autostart (sistema)")):
        for p in sorted(d.glob("*.desktop")) if d.exists() else []:
            out.append(_item(label, p.stem, _desktop_exec(p), str(p), "desktop",
                             removable=os.access(p, os.W_OK)))
    for d, label in ((home / ".config" / "systemd" / "user", "systemd (usuário)"), (Path("/etc/systemd/system"), "systemd (sistema)")):
        for p in sorted(d.glob("*.service")) if d.exists() else []:
            if p.is_symlink() and str(os.readlink(p)).startswith("/dev/null"):
                continue
            cmd = ""
            try:
                for line in p.read_text("utf-8", "replace").splitlines():
                    if line.strip().startswith("ExecStart="):
                        cmd = line.split("=", 1)[1].lstrip("-@+!:").strip()
                        break
            except OSError:
                continue
            out.append(_item(label, p.stem, cmd, str(p), "systemd", removable=os.access(p.parent, os.W_OK)))
    # cron
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
        for i, line in enumerate(r.stdout.splitlines()):
            s = line.strip()
            if s and not s.startswith("#") and not re.match(r"^\w+=", s):
                cmd = s if s.startswith("@") else " ".join(s.split()[5:])
                if s.startswith("@"):
                    cmd = " ".join(s.split()[1:])
                out.append(_item("crontab (usuário)", f"linha {i + 1}", cmd, f"crontab:{i}", "cron"))
    except Exception:
        pass
    for f in ["/etc/crontab"] + glob.glob("/etc/cron.d/*"):
        try:
            for i, line in enumerate(Path(f).read_text("utf-8", "replace").splitlines()):
                s = line.strip()
                if s and not s.startswith("#") and not re.match(r"^\w+=", s):
                    parts = s.split()
                    cmd = " ".join(parts[2:]) if s.startswith("@") else " ".join(parts[6:])
                    out.append(_item("cron (sistema)", f"{Path(f).name}:{i + 1}", cmd, f, "cron",
                                     removable=False))
        except OSError:
            continue
    # arquivos de shell executados no login
    for rc in (".bashrc", ".profile", ".bash_profile", ".zshrc"):
        p = home / rc
        try:
            for i, line in enumerate(p.read_text("utf-8", "replace").splitlines()):
                if SUSPICIOUS_CMD.search(line) and not line.strip().startswith("#"):
                    out.append(_item(f"~/{rc}", f"linha {i + 1}", line.strip(), str(p), "shellrc", removable=False))
        except OSError:
            continue
    pre = Path("/etc/ld.so.preload")
    try:
        content = pre.read_text().strip()
        if content:
            it = _item("ld.so.preload", "pré-carregamento global", content, str(pre), "preload", removable=False,
                       target=content.split()[0] if content.split() else "")
            it["suspicious"] = True
            out.append(it)
    except OSError:
        pass
    return out


def list_items() -> list[dict]:
    try:
        return _windows_items() if paths.IS_WINDOWS else _linux_items()
    except Exception:
        return []


def disable_item(item: dict) -> str:
    """Desativa um item de inicialização, guardando uma cópia de segurança para desfazer."""
    bdir = paths.sub_dir("startup_backup")
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    record = {"item": item, "date": ts}
    kind = item["kind"]
    if kind == "registro" and paths.IS_WINDOWS:
        import winreg
        label, name = item["source"], item["name"]
        mapping = {"HKCU Run": (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                   "HKCU RunOnce": (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                   "HKLM Run": (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                   "HKLM RunOnce": (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                   "HKLM Run (32 bits)": (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")}
        hive, sub = mapping[label]
        with winreg.OpenKey(hive, sub, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, name)
    elif kind == "tarefa" and paths.IS_WINDOWS:
        r = subprocess.run(["schtasks", "/change", "/tn", item["name"], "/disable"], capture_output=True, text=True,
                           creationflags=0x08000000)
        if r.returncode != 0:
            raise OSError(r.stderr.strip() or "falha ao desativar a tarefa")
    elif kind in ("arquivo", "desktop", "systemd"):
        src = item["location"]
        dst = bdir / f"{ts}-{Path(src).name}"
        shutil.move(src, dst)
        record["backup"] = str(dst)
    elif kind == "cron":
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
        lines = r.stdout.splitlines()
        idx = int(item["location"].split(":")[1])
        record["crontab"] = r.stdout
        lines[idx] = "# desativado pelo EXE Antivirus: " + lines[idx]
        subprocess.run(["crontab", "-"], input="\n".join(lines) + "\n", text=True, check=True, timeout=5)
    else:
        raise OSError("Este item não pode ser desativado automaticamente.")
    (bdir / f"{ts}.json").write_text(json.dumps(record, ensure_ascii=False, indent=1), "utf-8")
    history.log("inicialização", f"Item de inicialização desativado: {item['name']}", item["location"])
    return ts
