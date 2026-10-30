"""Recuperação de arquivos corrompidos e backups protegidos.

O original NUNCA é alterado: a versão reparada é gravada ao lado, com o sufixo
".recuperado".
"""
from __future__ import annotations

import datetime
import io
import json
import os
import re
import struct
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

from . import history, paths, util

ZIP_EXT = {".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".odt", ".ods", ".odp", ".epub",
           ".jar", ".apk", ".cbz", ".kmz", ".xpi", ".vsix", ".3mf"}
TEXT_EXT = {".txt", ".csv", ".log", ".md", ".ini", ".cfg", ".conf", ".xml", ".html", ".htm", ".css", ".js",
            ".py", ".c", ".h", ".cpp", ".java", ".sql", ".yaml", ".yml", ".srt", ".tsv", ".json"}
EXPECTED_MAGIC = {
    ".pdf": [b"%PDF"], ".png": [b"\x89PNG"], ".jpg": [b"\xff\xd8\xff"], ".jpeg": [b"\xff\xd8\xff"],
    ".gif": [b"GIF8"], ".doc": [b"\xd0\xcf\x11\xe0"], ".xls": [b"\xd0\xcf\x11\xe0"], ".ppt": [b"\xd0\xcf\x11\xe0"],
    ".mp3": [b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"], ".bmp": [b"BM"], ".rar": [b"Rar!"],
    ".7z": [b"7z\xbc\xaf"], ".gz": [b"\x1f\x8b"], ".psd": [b"8BPS"], ".rtf": [b"{\\rtf"],
}
for _e in ZIP_EXT:
    EXPECTED_MAGIC[_e] = [b"PK\x03\x04", b"PK\x05\x06"]
SUPPORTED = set(EXPECTED_MAGIC) | TEXT_EXT


@dataclass
class Finding:
    path: str
    kind: str
    problem: str
    repairable: bool
    severity: str = "media"   # baixa | media | alta


def check_file(path: str) -> Finding | None:
    """Verifica a integridade de um arquivo conhecido. Retorna None se estiver íntegro."""
    ext = os.path.splitext(path)[1].lower()
    if ext not in SUPPORTED:
        return None
    try:
        size = os.path.getsize(path)
        if size > 512 * 1024 * 1024:
            return None
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return Finding(path, ext, f"Não foi possível ler o arquivo: {e.strerror or e}", False, "alta")
    if not data:
        return Finding(path, ext, "Arquivo vazio (0 bytes) — o conteúdo foi perdido.", False, "alta")
    if data.count(0) == len(data):
        return Finding(path, ext, "Conteúdo totalmente zerado — os dados foram sobrescritos.", False, "alta")
    magics = EXPECTED_MAGIC.get(ext)
    if magics and not any(data.startswith(m) or (ext == ".pdf" and m in data[:1024]) for m in magics):
        ent = util.entropy(data[:1 << 20])
        if ent > 7.6:
            return Finding(path, ext, "Cabeçalho ausente e conteúdo totalmente aleatório: o arquivo parece ter sido "
                                      "CRIPTOGRAFADO por ransomware. Restaure a partir de um backup.", False, "alta")
        if ext in ZIP_EXT and b"PK\x03\x04" in data:
            return Finding(path, ext, "Lixo antes do início do arquivo ZIP/Office.", True)
        if ext == ".pdf" and b"%PDF" in data:
            return Finding(path, ext, "Lixo antes do cabeçalho do PDF.", True)
        if ext in (".jpg", ".jpeg") and b"\xff\xd8\xff" in data[:65536]:
            return Finding(path, ext, "Lixo antes do início da imagem JPEG.", True)
        return Finding(path, ext, "Cabeçalho do formato ausente ou danificado.", False, "alta")
    try:
        if ext in ZIP_EXT:
            return _check_zip(path, ext, data)
        if ext == ".png":
            return _check_png(path, data)
        if ext in (".jpg", ".jpeg"):
            if data.rstrip(b"\x00")[-2:] != b"\xff\xd9":
                return Finding(path, ext, "Imagem JPEG truncada (sem marcador de fim).", True, "baixa")
        if ext == ".gif":
            if not data.rstrip(b"\x00").endswith(b";"):
                return Finding(path, ext, "GIF truncado (sem terminador).", True, "baixa")
        if ext == ".pdf":
            return _check_pdf(path, data)
        if ext == ".json":
            try:
                json.loads(data.decode("utf-8-sig"))
            except (ValueError, UnicodeDecodeError) as e:
                return Finding(path, ext, f"JSON inválido: {str(e)[:80]}", _json_fixable(data))
            return None
        if ext in TEXT_EXT:
            nul = data.count(0)
            if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
                return None
            if nul and nul < len(data) // 4:
                return Finding(path, ext, f"Texto com {nul} bytes nulos (setores danificados).", True, "baixa")
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    data.decode("cp1252")
                except UnicodeDecodeError:
                    return Finding(path, ext, "Texto com caracteres inválidos.", True, "baixa")
    except Exception as e:  # formato muito danificado
        return Finding(path, ext, f"Estrutura danificada: {str(e)[:100]}", ext in ZIP_EXT or ext == ".pdf")
    return None


def _check_zip(path: str, ext: str, data: bytes) -> Finding | None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            bad = z.testzip()
            if bad:
                return Finding(path, ext, f"Item interno corrompido: {bad}", True)
    except zipfile.BadZipFile as e:
        return Finding(path, ext, f"Estrutura do arquivo danificada ({e}).", True)
    except (zlib.error, EOFError, OSError, ValueError, NotImplementedError) as e:
        return Finding(path, ext, f"Dados internos danificados ({str(e)[:60]}).", True)
    return None


def _check_png(path: str, data: bytes) -> Finding | None:
    pos, bad_crc = 8, 0
    while pos + 12 <= len(data):
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        if pos + 12 + ln > len(data):
            return Finding(path, ".png", "Imagem PNG truncada.", True)
        crc = struct.unpack(">I", data[pos + 8 + ln:pos + 12 + ln])[0]
        if zlib.crc32(typ + data[pos + 8:pos + 8 + ln]) & 0xFFFFFFFF != crc:
            bad_crc += 1
        if typ == b"IEND":
            break
        pos += 12 + ln
    else:
        return Finding(path, ".png", "Imagem PNG sem bloco final (IEND).", True)
    if bad_crc:
        return Finding(path, ".png", f"{bad_crc} bloco(s) com CRC inválido.", True, "baixa")
    return None


def _check_pdf(path: str, data: bytes) -> Finding | None:
    tail = data[-2048:]
    if b"%%EOF" not in tail:
        return Finding(path, ".pdf", "PDF truncado (sem marcador %%EOF).", True)
    ms = list(re.finditer(rb"startxref\s+(\d+)", tail))
    m = ms[-1] if ms else None
    if not m:
        return Finding(path, ".pdf", "PDF sem referência à tabela xref.", True)
    off = int(m.group(1))
    if off >= len(data) or not (data[off:off + 4] == b"xref" or re.match(rb"\d+\s+\d+\s+obj", data[off:off + 30])):
        return Finding(path, ".pdf", "Tabela de referências (xref) aponta para posição inválida.", True)
    return None


def _json_fixable(data: bytes) -> bool:
    return True


# --------------------------------------------------------------------------- reparo
def output_path(path: str) -> str:
    base, ext = os.path.splitext(path)
    out = f"{base}.recuperado{ext}"
    i = 2
    while os.path.exists(out):
        out = f"{base}.recuperado{i}{ext}"
        i += 1
    return out


def repair(path: str) -> tuple[str, str]:
    """Tenta reparar. Retorna (caminho_reparado, descrição). Lança ValueError se impossível."""
    ext = os.path.splitext(path)[1].lower()
    with open(path, "rb") as f:
        data = f.read()
    if ext in ZIP_EXT:
        fixed, desc = _repair_zip(data)
    elif ext == ".png":
        fixed, desc = _repair_png(data)
    elif ext in (".jpg", ".jpeg"):
        fixed, desc = _repair_jpeg(data)
    elif ext == ".gif":
        fixed, desc = data.rstrip(b"\x00") + (b"" if data.rstrip(b"\x00").endswith(b";") else b";"), "Terminador do GIF adicionado."
    elif ext == ".pdf":
        fixed, desc = _repair_pdf(data)
    elif ext == ".json":
        fixed, desc = _repair_json(data)
    elif ext in TEXT_EXT:
        fixed, desc = _repair_text(data)
    else:
        raise ValueError("Formato não suportado para reparo.")
    out = output_path(path)
    with open(out, "wb") as f:
        f.write(fixed)
    history.log("recuperação", f"Arquivo reparado: {desc}", out)
    return out, desc


def _repair_zip(data: bytes) -> tuple[bytes, str]:
    """Reconstrói o ZIP lendo os cabeçalhos locais de cada item (ignora diretório central danificado)."""
    out = io.BytesIO()
    saved, lost = 0, 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for m in re.finditer(rb"PK\x03\x04", data):
            p = m.start()
            try:
                (_ver, flags, method, mtime, mdate, crc, csize, usize, nlen, xlen) = struct.unpack_from(
                    "<HHHHHIIIHH", data, p + 4)
            except struct.error:
                break
            name = data[p + 30:p + 30 + nlen].decode("utf-8" if flags & 0x800 else "cp437", "replace")
            start = p + 30 + nlen + xlen
            if not name or name.endswith("/"):
                continue
            try:
                if method == 0:
                    if flags & 8 and csize == 0:
                        nxt = data.find(b"PK\x07\x08", start)
                        csize = (nxt if nxt > 0 else len(data)) - start
                    content = data[start:start + csize]
                elif method == 8:
                    d = zlib.decompressobj(-15)
                    chunk = data[start:start + csize] if (csize and not flags & 8) else data[start:]
                    content = d.decompress(chunk)
                    content += d.flush()
                else:
                    lost += 1
                    continue
                if flags & 8 == 0 and usize and len(content) != usize:
                    content = content[:usize]
                zi = zipfile.ZipInfo(name)
                try:
                    zi.date_time = (((mdate >> 9) & 0x7F) + 1980, max(1, (mdate >> 5) & 0xF), max(1, mdate & 0x1F),
                                    (mtime >> 11) & 0x1F, (mtime >> 5) & 0x3F, (mtime & 0x1F) * 2)
                except ValueError:
                    pass
                zi.compress_type = zipfile.ZIP_DEFLATED
                zout.writestr(zi, content)
                saved += 1
            except (zlib.error, ValueError):
                lost += 1
    if not saved:
        raise ValueError("Nenhum item recuperável foi encontrado.")
    return out.getvalue(), f"{saved} item(ns) recuperado(s)" + (f", {lost} perdido(s)" if lost else "") + "."


def _repair_png(data: bytes) -> tuple[bytes, str]:
    start = data.find(b"\x89PNG\r\n\x1a\n")
    if start < 0:
        raise ValueError("Assinatura PNG não encontrada.")
    data = data[start:]
    out = bytearray(data[:8])
    pos, fixed_crc = 8, 0
    while pos + 12 <= len(data):
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        if pos + 12 + ln > len(data) or not typ.isalpha():
            break
        body = data[pos + 8:pos + 8 + ln]
        crc = zlib.crc32(typ + body) & 0xFFFFFFFF
        if struct.unpack(">I", data[pos + 8 + ln:pos + 12 + ln])[0] != crc:
            fixed_crc += 1
        out += struct.pack(">I", ln) + typ + body + struct.pack(">I", crc)
        pos += 12 + ln
        if typ == b"IEND":
            return bytes(out), f"{fixed_crc} CRC(s) corrigido(s); dados após o fim removidos."
    out += struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
    return bytes(out), f"Imagem truncada finalizada (bloco IEND adicionado); {fixed_crc} CRC(s) corrigido(s)."


def _repair_jpeg(data: bytes) -> tuple[bytes, str]:
    s = data.find(b"\xff\xd8\xff")
    if s < 0:
        raise ValueError("Início do JPEG não encontrado.")
    data = data[s:].rstrip(b"\x00")
    e = data.rfind(b"\xff\xd9")
    if e > 0 and e >= len(data) - 4096:
        return data[:e + 2], "Lixo removido do início/fim da imagem."
    return data + b"\xff\xd9", "Marcador de fim (EOI) adicionado à imagem truncada."


def _repair_pdf(data: bytes) -> tuple[bytes, str]:
    s = data.find(b"%PDF")
    if s < 0:
        raise ValueError("Cabeçalho PDF não encontrado.")
    data = data[s:]
    end = data.rfind(b"%%EOF")
    body = data[:end] if end > 0 else data
    # remove xref/trailer antigos e reconstrói a tabela com as posições reais dos objetos
    objs: dict[int, int] = {}
    for m in re.finditer(rb"(?<![0-9])(\d{1,7})\s+(\d{1,5})\s+obj\b", body):
        objs[int(m.group(1))] = m.start()
    if not objs:
        raise ValueError("Nenhum objeto PDF encontrado.")
    root = None
    for m in re.finditer(rb"/Root\s+(\d+)\s+(\d+)\s+R", body):
        root = m.group(1) + b" " + m.group(2) + b" R"
    if root is None:
        for num, off in objs.items():
            if re.search(rb"/Type\s*/Catalog", body[off:off + 2000]):
                root = str(num).encode() + b" 0 R"
                break
    if root is None:
        raise ValueError("Catálogo (raiz) do PDF não encontrado.")
    info = re.search(rb"/Info\s+(\d+\s+\d+\s+R)", body)
    last_obj = body.rfind(b"endobj")
    if last_obj > 0:
        body = body[:last_obj + 6]  # descarta xref/trailer antigos e danificados
    body = body.rstrip() + b"\n"
    size = max(objs) + 1
    xref = [b"xref", b"0 %d" % size, b"0000000000 65535 f "]
    for i in range(1, size):
        xref.append(b"%010d 00000 n " % objs[i] if i in objs else b"0000000000 65535 f ")
    trailer = b"trailer\n<< /Size %d /Root %s%s >>\n" % (size, root, b" /Info " + info.group(1) if info else b"")
    out = body + b"\n".join(xref) + b"\n" + trailer + b"startxref\n%d\n%%%%EOF\n" % len(body)
    return out, f"Tabela xref reconstruída com {len(objs)} objeto(s)."


def _repair_text(data: bytes) -> tuple[bytes, str]:
    n = data.count(0)
    data = data.replace(b"\x00", b"")
    try:
        txt = data.decode("utf-8")
        return txt.encode("utf-8"), f"{n} byte(s) nulo(s) removido(s)."
    except UnicodeDecodeError:
        txt = data.decode("utf-8", "replace")
        return txt.encode("utf-8"), f"{n} byte(s) nulo(s) removido(s); caracteres inválidos substituídos."


def _repair_json(data: bytes) -> tuple[bytes, str]:
    txt = data.replace(b"\x00", b"").decode("utf-8-sig", "replace").rstrip()
    try:
        json.loads(txt)
        return txt.encode("utf-8"), "Bytes nulos removidos."
    except ValueError:
        pass
    # fecha estruturas abertas de um JSON truncado
    stack, in_str, esc = [], False, False
    for ch in txt:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "{[":
            stack.append("}" if ch == "{" else "]")
        elif ch in "}]" and stack:
            stack.pop()
    fixed = txt + ('"' if in_str else "")
    fixed = re.sub(r"[,:]\s*$", "", fixed)
    fixed += "".join(reversed(stack))
    try:
        json.loads(fixed)
    except ValueError as e:
        raise ValueError(f"Não foi possível reconstruir o JSON ({e}).") from e
    return fixed.encode("utf-8"), "Estrutura JSON truncada foi fechada."


def scan_folder(folder: str, progress=None, stop=None) -> list[Finding]:
    found: list[Finding] = []
    excl = paths.Exclusions()
    n = 0
    for root, dirs, files in os.walk(folder):
        if stop and stop():
            break
        dirs[:] = [d for d in dirs if not excl.is_excluded(os.path.join(root, d))]
        for fn in files:
            p = os.path.join(root, fn)
            if os.path.splitext(fn)[1].lower() not in SUPPORTED or ".recuperado" in fn:
                continue
            n += 1
            if progress and n % 20 == 0:
                progress(n, p)
            f = check_file(p)
            if f:
                found.append(f)
    return found


# --------------------------------------------------------------------------- backups protegidos
def create_backup(folder: str, progress=None) -> dict:
    folder = os.path.abspath(folder)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    name = f"{Path(folder).name or 'raiz'}-{ts}.zip"
    dest = paths.backup_dir() / name
    count, total = 0, 0
    excl = paths.Exclusions()
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as z:
        for root, dirs, files in os.walk(folder):
            dirs[:] = [d for d in dirs if not excl.is_excluded(os.path.join(root, d))]
            for fn in files:
                p = os.path.join(root, fn)
                try:
                    z.write(p, os.path.relpath(p, folder))
                    count += 1
                    total += os.path.getsize(p)
                except OSError:
                    continue
                if progress and count % 25 == 0:
                    progress(count, p)
        z.writestr("__exeav_backup__.json", json.dumps({"source": folder, "date": ts, "files": count,
                                                        "bytes": total}))
    history.log("backup", f"Backup criado: {count} arquivo(s)", str(dest))
    return {"file": str(dest), "files": count, "bytes": total}


def list_backups() -> list[dict]:
    out = []
    for p in sorted(paths.backup_dir().glob("*.zip"), reverse=True):
        meta = {"file": str(p), "name": p.name, "size": p.stat().st_size}
        try:
            with zipfile.ZipFile(p) as z:
                meta.update(json.loads(z.read("__exeav_backup__.json")))
        except (KeyError, zipfile.BadZipFile, ValueError, OSError):
            pass
        out.append(meta)
    return out


def restore_backup(backup_file: str, dest_folder: str) -> int:
    n = 0
    dest = Path(dest_folder).resolve()
    with zipfile.ZipFile(backup_file) as z:
        for info in z.infolist():
            if info.filename == "__exeav_backup__.json" or info.is_dir():
                continue
            target = (dest / info.filename).resolve()
            if dest not in target.parents:  # proteção contra "zip slip"
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, open(target, "wb") as out:
                while True:
                    b = src.read(1 << 20)
                    if not b:
                        break
                    out.write(b)
            n += 1
    history.log("backup", f"Backup restaurado: {n} arquivo(s)", dest_folder)
    return n
