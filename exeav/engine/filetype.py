"""Identificação do tipo REAL do arquivo pelos bytes (assinaturas mágicas), nunca pelo nome."""
from __future__ import annotations

import struct

# Tipos "inertes": mídia e formatos de dados sem código executável.
MEDIA_TYPES = {"png", "jpeg", "gif", "bmp", "webp", "tiff", "ico", "mp3", "mp4", "wav", "avi",
               "ogg", "flac", "mkv", "psd", "font", "sqlite", "iso"}
ARCHIVE_TYPES = {"zip", "7z", "rar", "gzip", "bzip2", "xz", "cab"}

DESCRIPTIONS = {
    "pe": "Executável Windows (PE)", "pe-dll": "Biblioteca Windows (DLL)", "pe-dotnet": "Executável .NET",
    "elf": "Executável Linux (ELF)", "elf-so": "Biblioteca compartilhada Linux (ELF .so)",
    "macho": "Executável macOS (Mach-O)", "ole": "Documento OLE (Office 97-2003 / MSI)",
    "zip": "Arquivo ZIP", "ooxml": "Documento Office (OOXML)", "jar": "Pacote Java (JAR)",
    "apk": "Aplicativo Android (APK)", "pdf": "Documento PDF", "rtf": "Documento RTF",
    "lnk": "Atalho do Windows (LNK)", "7z": "Arquivo 7-Zip", "rar": "Arquivo RAR",
    "gzip": "Arquivo GZip", "bzip2": "Arquivo BZip2", "xz": "Arquivo XZ", "cab": "Arquivo CAB",
    "script": "Script / texto", "html": "Documento HTML/HTA", "text": "Texto",
    "png": "Imagem PNG", "jpeg": "Imagem JPEG", "gif": "Imagem GIF", "bmp": "Imagem BMP",
    "webp": "Imagem WebP", "tiff": "Imagem TIFF", "ico": "Ícone", "mp3": "Áudio MP3",
    "mp4": "Vídeo MP4/MOV", "wav": "Áudio WAV", "avi": "Vídeo AVI", "ogg": "Áudio/Vídeo OGG",
    "flac": "Áudio FLAC", "mkv": "Vídeo Matroska", "psd": "Imagem Photoshop", "font": "Fonte",
    "sqlite": "Banco SQLite", "iso": "Imagem de disco ISO", "java-class": "Classe Java",
    "wasm": "WebAssembly", "binary": "Binário desconhecido", "empty": "Vazio",
}


def _is_pe(head: bytes) -> bool:
    if len(head) < 64 or head[:2] != b"MZ":
        return False
    off = struct.unpack_from("<I", head, 0x3C)[0]
    return 0 < off < len(head) - 4 and head[off:off + 4] == b"PE\x00\x00"


def _pe_kind(head: bytes) -> str:
    try:
        off = struct.unpack_from("<I", head, 0x3C)[0]
        chars = struct.unpack_from("<H", head, off + 22)[0]
        magic = struct.unpack_from("<H", head, off + 24)[0]
        dd_off = off + 24 + (112 if magic == 0x20B else 96)
        clr_rva = struct.unpack_from("<I", head, dd_off + 14 * 8)[0] if dd_off + 14 * 8 + 4 <= len(head) else 0
        if clr_rva:
            return "pe-dotnet"
        if chars & 0x2000:
            return "pe-dll"
    except struct.error:
        pass
    return "pe"


_NON_TEXT = bytes(b for b in range(256) if not (32 <= b < 127 or b in (9, 10, 12, 13, 27) or b >= 0x80))


def _elf_kind(h: bytes) -> str:
    """'elf' para executáveis (inclusive PIE, que têm interpretador) e 'elf-so' para bibliotecas."""
    try:
        e = "<" if h[5] == 1 else ">"
        e_type = struct.unpack_from(e + "H", h, 16)[0]
        if e_type != 3:
            return "elf"
        if h[4] == 2:
            phoff = struct.unpack_from(e + "Q", h, 32)[0]
            phentsize, phnum = struct.unpack_from(e + "HH", h, 54)
        else:
            phoff = struct.unpack_from(e + "I", h, 28)[0]
            phentsize, phnum = struct.unpack_from(e + "HH", h, 42)
        for i in range(min(phnum, 64)):
            off = phoff + i * phentsize
            if off + 4 > len(h):
                break
            if struct.unpack_from(e + "I", h, off)[0] == 3:  # PT_INTERP
                return "elf"
        return "elf-so"
    except struct.error:
        return "elf"


def _text_ratio(sample: bytes) -> float:
    if not sample:
        return 0.0
    return len(sample.translate(None, _NON_TEXT)) / len(sample)


def decode_text(data: bytes) -> str | None:
    """Decodifica conteúdo textual (UTF-8/UTF-16 com BOM) ou None se for binário."""
    if data[:3] == b"\xef\xbb\xbf":
        return data[3:].decode("utf-8", "replace")
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    sample = data[:8192]
    if b"\x00" in sample:
        # UTF-16LE sem BOM (comum em scripts PowerShell gerados por malware)
        if len(sample) > 16 and sample[1::2].count(0) > len(sample) // 2 * 0.9:
            return data.decode("utf-16le", "replace")
        return None
    if _text_ratio(sample) < 0.95:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def detect(head: bytes) -> str:
    """Retorna o tipo do arquivo a partir dos primeiros bytes (idealmente >= 4 KB)."""
    if not head:
        return "empty"
    h = head
    if h[:2] == b"MZ":
        return _pe_kind(h) if _is_pe(h) else "binary"
    if h[:4] == b"\x7fELF":
        return _elf_kind(h)
    if h[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if h[:4] == b"\xca\xfe\xba\xbe":
        # Mach-O universal ou classe Java
        n = struct.unpack_from(">I", h, 4)[0] if len(h) >= 8 else 0
        return "macho" if 0 < n < 20 else "java-class"
    if h[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if h[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        if b"[Content_Types].xml" in h or b"word/" in h or b"xl/" in h or b"ppt/" in h:
            return "ooxml"
        if b"AndroidManifest.xml" in h or b"classes.dex" in h:
            return "apk"
        if b"META-INF/MANIFEST.MF" in h or b"META-INF/" in h[:200]:
            return "jar"
        return "zip"
    if b"%PDF-" in h[:1024]:
        return "pdf"
    if h[:5] == b"{\\rtf":
        return "rtf"
    if h[:8] == b"L\x00\x00\x00\x01\x14\x02\x00":
        return "lnk"
    if h[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if h[:6] == b"Rar!\x1a\x07":
        return "rar"
    if h[:2] == b"\x1f\x8b":
        return "gzip"
    if h[:3] == b"BZh" and h[3:4].isdigit():
        return "bzip2"
    if h[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if h[:4] == b"MSCF":
        return "cab"
    if h[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if h[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if h[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if h[:4] == b"RIFF" and len(h) >= 12:
        return {b"WAVE": "wav", b"AVI ": "avi", b"WEBP": "webp"}.get(h[8:12], "binary")
    if h[4:8] == b"ftyp":
        return "mp4"
    if h[:3] == b"ID3" or (len(h) > 1 and h[0] == 0xFF and (h[1] & 0xE0) == 0xE0 and h[1] != 0xFF):
        return "mp3"
    if h[:4] == b"OggS":
        return "ogg"
    if h[:4] == b"fLaC":
        return "flac"
    if h[:4] == b"\x1a\x45\xdf\xa3":
        return "mkv"
    if h[:4] == b"8BPS":
        return "psd"
    if h[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if h[:4] in (b"\x00\x01\x00\x00", b"OTTO", b"wOFF", b"wOF2", b"true", b"ttcf"):
        return "font"
    if h[:16] == b"SQLite format 3\x00":
        return "sqlite"
    if h[:4] == b"\x00asm":
        return "wasm"
    if h[:4] == b"\x00\x00\x01\x00" and len(h) > 6 and 0 < h[4] < 64:
        return "ico"
    if h[:2] == b"BM" and len(h) > 14 and struct.unpack_from("<I", h, 2)[0] > 26 and h[6:10] == b"\x00\x00\x00\x00":
        return "bmp"
    txt = decode_text(h)
    if txt is not None:
        low = txt[:4096].lower()
        if "<html" in low or "<script" in low or "<hta:" in low or "<!doctype html" in low or "<svg" in low:
            return "html"
        return "script"
    return "binary"


def script_language(text: str) -> str:
    """Estimativa da linguagem do script pelo conteúdo (somente para exibição)."""
    t = text[:20000]
    low = t.lower()
    first = t.lstrip()[:200].lower()
    if first.startswith("#!"):
        line = first.splitlines()[0]
        for key, name in (("python", "Python"), ("bash", "Bash"), ("/sh", "Shell"), ("zsh", "Zsh"),
                          ("perl", "Perl"), ("node", "JavaScript (Node)"), ("ruby", "Ruby"),
                          ("php", "PHP"), ("pwsh", "PowerShell")):
            if key in line:
                return name
    if "<hta:" in low:
        return "HTA"
    if "<html" in low or "<script" in low:
        return "HTML"
    scores = {
        "PowerShell": sum(low.count(k) for k in ("$env:", "invoke-", "new-object", "get-", "set-", "-scope ", "write-host", "[system.")),
        "Batch (CMD)": sum(low.count(k) for k in ("@echo off", "%~dp0", "goto ", "setlocal", "\nrem ", "errorlevel")),
        "VBScript": sum(low.count(k) for k in ("dim ", "createobject(", "wscript.", "end sub", "end function", "msgbox")),
        "JavaScript": sum(low.count(k) for k in ("function(", "function ", "var ", "const ", "let ", "=>", "document.")),
        "Python": sum(low.count(k) for k in ("import ", "def ", "self.", "__name__", "elif ", "print(")),
        "Shell": sum(low.count(k) for k in ("fi\n", "then\n", "esac", "echo ", "export ", "$(")),
        "PHP": low.count("<?php") * 5 + low.count("$_get") + low.count("$_post"),
    }
    best = max(scores, key=scores.get)
    return best if scores[best] >= 2 else "Texto"


def is_executable_type(ftype: str) -> bool:
    return ftype.startswith(("pe", "elf")) or ftype in ("macho", "java-class", "wasm")
