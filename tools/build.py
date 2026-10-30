"""Compila o EXE Antivirus com PyInstaller (Windows ou Linux).

Uso:  python tools/build.py            -> pasta dist/ExeAntivirus (recomendado) + pacote compactado
      python tools/build.py --onefile  -> também gera um executável único
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
        out = ROOT / "dist" / f"ExeAntivirus-{VERSION}-{plat}-{arch}.tar.gz"
        with tarfile.open(out, "w:gz") as t:
            t.add(pkg_dir, arcname="ExeAntivirus")
    else:
        out = ROOT / "dist" / f"ExeAntivirus-{VERSION}-{plat}-{arch}.zip"
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for p in pkg_dir.rglob("*"):
                z.write(p, Path("ExeAntivirus") / p.relative_to(pkg_dir))
    print("pacote:", out)
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
