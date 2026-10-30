"""Zona de quarentena: isola ameaças de forma segura e reversível."""
from __future__ import annotations

import datetime
import os
import stat
from pathlib import Path

from . import history, paths
from .engine.models import ScanResult
from .vault import Vault


class Quarantine:
    def __init__(self, root: Path | None = None):
        self.vault = Vault(root or paths.quarantine_dir())

    def isolate(self, result: ScanResult) -> str:
        """Move o arquivo para a quarentena (cifrado) e remove o original."""
        path = result.path
        st = os.stat(path)
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
