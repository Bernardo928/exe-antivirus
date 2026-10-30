"""Zona de quarentena: isola ameaças de forma segura e reversível."""
from __future__ import annotations

import datetime
import os
import stat
from pathlib import Path

from . import history, paths
from .engine.models import ScanResult
from .vault import Vault


_LINUX_SYSTEM_DIRS = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib64/", "/usr/lib32/",
                      "/lib/", "/lib64/", "/lib32/", "/usr/libexec/", "/boot/", "/etc/", "/usr/share/")


def _system_dirs() -> tuple[str, ...]:
    if paths.IS_WINDOWS:
        root = os.environ.get("SystemRoot", r"C:\Windows")
        dirs = [root]
        for v in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles"):
            if os.environ.get(v):
                dirs.append(os.environ[v])
        return tuple(os.path.normcase(os.path.abspath(d)).rstrip("\\") + "\\" for d in dirs)
    return _LINUX_SYSTEM_DIRS


def protection_reason(path: str) -> str | None:
    """Motivo para RECUSAR mexer em um arquivo essencial e íntegro do sistema (None = pode isolar).

    Um arquivo de sistema adulterado (hash diferente do pacote / sem assinatura válida) continua
    podendo ser isolado — é exatamente assim que uma infecção real se parece."""
    from .engine import trust
    for cand in {os.path.abspath(path), os.path.realpath(path)}:
        n = os.path.normcase(cand)
        if n.startswith(_system_dirs()):
            ok, desc = trust.check(cand)
            if ok:
                return (f"Arquivo essencial do sistema e íntegro ({desc}). Ele não será isolado nem excluído para "
                        "não danificar o sistema operacional.")
    return None


class Quarantine:
    def __init__(self, root: Path | None = None):
        self.vault = Vault(root or paths.quarantine_dir())

    def isolate(self, result: ScanResult) -> str:
        """Move o arquivo para a quarentena (cifrado) e remove o original."""
        path = result.path
        lst = os.lstat(path)
        if not (stat.S_ISREG(lst.st_mode) or stat.S_ISLNK(lst.st_mode)):
            raise OSError("Apenas arquivos comuns podem ser isolados.")
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            raise OSError("Apenas arquivos comuns podem ser isolados.")
        reason = protection_reason(path)
        if reason:
            raise PermissionError(reason)
        meta = {
            "original_path": os.path.abspath(path),
            "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "size": st.st_size,
            "mode": stat.S_IMODE(st.st_mode),
            "threat_name": result.threat_name,
            "verdict": result.verdict,
            "score": result.score,
            "sha256": result.sha256,
            "file_type": result.file_type,
            "result": result.to_dict(),
        }
        item_id = self.vault.store_file(path, meta)
        try:
            _force_remove(path)
        except OSError as e:
            self.vault.delete(item_id)
            raise OSError(f"Não foi possível remover o original: {e.strerror or e}") from e
        history.log("quarentena", f"{result.threat_name} isolado", path)
        return item_id

    def items(self) -> list[dict]:
        return self.vault.items()

    def restore(self, item_id: str, dest: str | None = None) -> str:
        meta = self.vault.meta(item_id)
        target = dest or meta["original_path"]
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        if os.path.exists(target):
            base, ext = os.path.splitext(target)
            target = f"{base} (restaurado){ext}"
        self.vault.extract_to(item_id, target)
        try:
            os.chmod(target, meta.get("mode", 0o644))
        except OSError:
            pass
        self.vault.delete(item_id)
        history.log("restauração", f"{meta.get('threat_name', '')} restaurado da quarentena", target)
        return target

    def delete(self, item_id: str) -> None:
        meta = self.vault.meta(item_id)
        self.vault.delete(item_id)
        history.log("exclusão", f"{meta.get('threat_name', '')} excluído definitivamente", meta.get("original_path", ""))

    def read(self, item_id: str) -> bytes:
        return self.vault.read(item_id)

    def meta(self, item_id: str) -> dict:
        return self.vault.meta(item_id)


def _force_remove(path: str) -> None:
    try:
        os.remove(path)
    except PermissionError:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        os.remove(path)
