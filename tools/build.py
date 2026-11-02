"""Compila o EXE Antivirus com PyInstaller (Windows ou Linux).

Uso:  python tools/build.py              -> pasta dist/ExeAntivirus (recomendado) + pacote compactado
      python tools/build.py --onefile    -> também gera um executável único (portátil)
      python tools/build.py --installer  -> Windows: também gera o instalador .exe (Inno Setup)
      python tools/build.py --appimage   -> Linux: também gera o .AppImage
"""
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
IS_WIN = os.name == "nt"
SEP = ";" if IS_WIN else ":"


def run(cmd):
    print("+", " ".join(str(c) for c in cmd))
    subprocess.check_call([str(c) for c in cmd], cwd=ROOT)


def pyinstaller_args(onefile: bool) -> list:
    from exeav import VERSION  # noqa: F401
    args = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--name", "ExeAntivirus",
            "--windowed", "--icon", str(ROOT / "assets" / ("icon.ico" if IS_WIN else "icon.png")),
            "--add-data", f"{ROOT / 'exeav' / 'data' / 'rules.bin'}{SEP}exeav/data",
            "--hidden-import", "ahocorasick",
            "--exclude-module", "tkinter", "--exclude-module", "PySide6.QtNetwork",
            "--exclude-module", "PySide6.QtQml", "--exclude-module", "PySide6.QtQuick",
            "--exclude-module", "PySide6.QtWebEngineCore", "--exclude-module", "PySide6.QtMultimedia",
            "--exclude-module", "PySide6.QtPdf", "--exclude-module", "PySide6.Qt3DCore",
            "--exclude-module", "rules_src", "--exclude-module", "pytest",
            "--distpath", str(ROOT / "dist" / ("onefile" if onefile else "")), "--workpath", str(ROOT / "build"),
            "--specpath", str(ROOT / "build")]
    if IS_WIN:
        args += ["--hidden-import", "watchdog.observers.read_directory_changes",
                 "--version-file", str(ROOT / "build" / "version.txt")]
    else:
        args += ["--hidden-import", "watchdog.observers.inotify", "--hidden-import", "watchdog.observers.inotify_buffer"]
    args.append("--onefile" if onefile else "--onedir")
    args.append(str(ROOT / "main.py"))
    return args


def write_version_file():
    from exeav import VERSION
    v = tuple(int(x) for x in VERSION.split(".")) + (0,)
    (ROOT / "build").mkdir(exist_ok=True)
    (ROOT / "build" / "version.txt").write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={v}, prodvers={v}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[StringFileInfo([StringTable('041604B0', [
    StringStruct('CompanyName', 'EXE Antivirus'),
    StringStruct('FileDescription', 'EXE Antivirus - proteção contra malware'),
    StringStruct('FileVersion', '{VERSION}'),
    StringStruct('InternalName', 'ExeAntivirus'),
    StringStruct('OriginalFilename', 'ExeAntivirus.exe'),
    StringStruct('ProductName', 'EXE Antivirus'),
    StringStruct('ProductVersion', '{VERSION}')])]),
  VarFileInfo([VarStruct('Translation', [0x0416, 1200])])]
)
""", "utf-8")


APPIMAGETOOL_URL = "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"


def build_appimage(version: str, arch: str) -> Path:
    """AppImage: um único arquivo que roda em qualquer distribuição Linux; no primeiro uso ele se adiciona
    ao menu de aplicativos e à inicialização automática."""
    import urllib.request
    appdir = ROOT / "build" / "AppDir"
    shutil.rmtree(appdir, ignore_errors=True)
    (appdir / "usr" / "lib").mkdir(parents=True)
    shutil.copytree(ROOT / "dist" / "ExeAntivirus", appdir / "usr" / "lib" / "ExeAntivirus", symlinks=True)
    apprun = appdir / "AppRun"
    apprun.write_text('#!/bin/sh\nHERE="$(dirname "$(readlink -f "$0")")"\n'
                      'exec "$HERE/usr/lib/ExeAntivirus/ExeAntivirus" "$@"\n', "utf-8")
    os.chmod(apprun, 0o755)
    (appdir / "exe-antivirus.desktop").write_text(
        "[Desktop Entry]\nType=Application\nName=EXE Antivirus\nGenericName=Antivirus\n"
        "Comment=Protecao contra virus, botnets, ransomware e sites maliciosos\nExec=ExeAntivirus\n"
        "Icon=exe-antivirus\nTerminal=false\nCategories=System;Security;\n", "utf-8")
    shutil.copy(ROOT / "assets" / "icon.png", appdir / "exe-antivirus.png")
    shutil.copy(ROOT / "assets" / "icon.png", appdir / ".DirIcon")
    tool = ROOT / "build" / "appimagetool.AppImage"
    if not tool.exists():
        print("baixando appimagetool…")
        urllib.request.urlretrieve(APPIMAGETOOL_URL, tool)
        os.chmod(tool, 0o755)
    out = ROOT / "dist" / f"ExeAntivirus-{version}-linux-{arch}.AppImage"
    env = dict(os.environ, ARCH="x86_64" if arch == "x64" else arch, APPIMAGE_EXTRACT_AND_RUN="1")
    print("+ appimagetool", appdir, out)
    subprocess.check_call([str(tool), "--no-appstream", str(appdir), str(out)], cwd=ROOT, env=env)
    return out


def find_iscc() -> str | None:
    cands = [shutil.which("iscc"), shutil.which("ISCC")]
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"), os.environ.get("LOCALAPPDATA")):
        if base:
            cands.append(str(Path(base) / "Inno Setup 6" / "ISCC.exe"))
            cands.append(str(Path(base) / "Programs" / "Inno Setup 6" / "ISCC.exe"))
    return next((c for c in cands if c and os.path.isfile(c)), None)


def build_installer(version: str) -> Path:
    """Instalador do Windows (Inno Setup): Arquivos de Programas, menu Iniciar, atalho, proteção desde a
    inicialização e desinstalador que desfaz tudo."""
    iscc = find_iscc()
    if not iscc:
        raise SystemExit("Inno Setup não encontrado (instale com: choco install innosetup)")
    run([iscc, f"/DAppVersion={version}", str(ROOT / "packaging" / "windows" / "ExeAntivirus.iss")])
    out = ROOT / "dist" / f"ExeAntivirus-{version}-windows-x64-instalador.exe"
    if not out.exists():
        raise SystemExit("o instalador não foi gerado")
    return out


def write_integrity_manifest(pkg_dir: Path) -> None:
    """SHA-256 de todos os arquivos da instalação: o antivírus confere a própria integridade ao abrir."""
    import json

    from exeav.selfprotect import MANIFEST, build_manifest
    m = build_manifest(pkg_dir)
    (pkg_dir / MANIFEST).write_text(json.dumps(m, indent=0), "utf-8")
    print(f"manifesto de integridade: {len(m['arquivos'])} arquivos")


def main():
    onefile = "--onefile" in sys.argv
    run([sys.executable, ROOT / "tools" / "build_rules.py"])
    run([sys.executable, ROOT / "tools" / "make_icon.py"])
    if IS_WIN:
        write_version_file()
    run(pyinstaller_args(False))
    from exeav import VERSION
    plat = "windows" if IS_WIN else "linux"
    arch = platform.machine().lower().replace("amd64", "x64").replace("x86_64", "x64")
    pkg_dir = ROOT / "dist" / "ExeAntivirus"
    if not IS_WIN:
        shutil.copy(ROOT / "packaging" / "install-linux.sh", pkg_dir / "install-linux.sh")
        os.chmod(pkg_dir / "install-linux.sh", 0o755)
        shutil.copy(ROOT / "assets" / "icon.png", pkg_dir / "icon.png")
    write_integrity_manifest(pkg_dir)
    if not IS_WIN:
        out = ROOT / "dist" / f"ExeAntivirus-{VERSION}-{plat}-{arch}.tar.gz"
        with tarfile.open(out, "w:gz") as t:
            t.add(pkg_dir, arcname="ExeAntivirus")
    else:
        out = ROOT / "dist" / f"ExeAntivirus-{VERSION}-{plat}-{arch}.zip"
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for p in pkg_dir.rglob("*"):
                z.write(p, Path("ExeAntivirus") / p.relative_to(pkg_dir))
    print("pacote:", out)
    if "--installer" in sys.argv and IS_WIN:
        print("instalador:", build_installer(VERSION))
    if "--appimage" in sys.argv and not IS_WIN:
        print("AppImage:", build_appimage(VERSION, arch))
    if onefile:
        run(pyinstaller_args(True))
        single = ROOT / "dist" / "onefile" / ("ExeAntivirus.exe" if IS_WIN else "ExeAntivirus")
        final = ROOT / "dist" / (f"ExeAntivirus-{VERSION}-{plat}-{arch}-portatil" + (".exe" if IS_WIN else ""))
        if single.exists():
            shutil.move(single, final)
            shutil.rmtree(ROOT / "dist" / "onefile", ignore_errors=True)
            print("executável único:", final)


if __name__ == "__main__":
    main()
