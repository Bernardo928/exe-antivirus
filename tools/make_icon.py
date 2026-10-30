"""Gera assets/icon.png e assets/icon.ico a partir do ícone vetorial do aplicativo."""
import os
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QBuffer, QIODevice  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from exeav.gui.icons import app_icon_pixmap  # noqa: E402


def png_bytes(size: int) -> bytes:
    buf = QBuffer()
    buf.open(QIODevice.WriteOnly)
    app_icon_pixmap(size).save(buf, "PNG")
    return bytes(buf.data())


def main() -> None:
    QApplication([])
    out = ROOT / "assets"
    out.mkdir(exist_ok=True)
    (out / "icon.png").write_bytes(png_bytes(256))
    sizes = [16, 24, 32, 48, 64, 128, 256]
    images = [png_bytes(s) for s in sizes]
    # ICO com imagens PNG embutidas (suportado desde o Windows Vista)
    header = struct.pack("<HHH", 0, 1, len(sizes))
    offset = 6 + 16 * len(sizes)
    entries = b""
    for s, img in zip(sizes, images):
        entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(img), offset)
        offset += len(img)
    (out / "icon.ico").write_bytes(header + entries + b"".join(images))
    print("ícones gerados em", out)


if __name__ == "__main__":
    main()
