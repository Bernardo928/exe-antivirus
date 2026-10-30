"""Documentos: OLE/Office (macros VBA), OOXML, PDF, RTF e atalhos LNK."""
from __future__ import annotations

import io
import re
import struct
import zipfile
import zlib

from .models import Indicator

ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF


def _ind(id_, name, category, desc, weight, severity="media", evidence=None, family=""):
    return Indicator(id=id_, name=name, category=category, description=desc, weight=weight,
                     severity=severity, evidence=evidence or [], family=family)


# --------------------------------------------------------------------------- OLE / CFB
class OLEFile:
    """Leitor mínimo de Compound File Binary (documentos Office 97-2003, MSI, vbaProject.bin)."""

    def __init__(self, data: bytes):
        if data[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" or len(data) < 512:
            raise ValueError("não é OLE")
        self.data = data
        self.sector_size = 1 << struct.unpack_from("<H", data, 0x1E)[0]
        self.mini_size = 1 << struct.unpack_from("<H", data, 0x20)[0]
        if self.sector_size not in (512, 4096):
            raise ValueError("setor inválido")
        n_fat = struct.unpack_from("<I", data, 0x2C)[0]
        first_dir = struct.unpack_from("<I", data, 0x30)[0]
        self.cutoff = struct.unpack_from("<I", data, 0x38)[0]
        first_minifat = struct.unpack_from("<I", data, 0x3C)[0]
        first_difat, n_difat = struct.unpack_from("<II", data, 0x44)
        difat = [x for x in struct.unpack_from("<109I", data, 0x4C) if x < 0xFFFFFFFA]
        sid, guard = first_difat, 0
        per = self.sector_size // 4
        while sid < 0xFFFFFFFA and guard < max(n_difat, 1) + 1000:
            sec = self._sector(sid)
            if len(sec) < self.sector_size:
                break
            vals = struct.unpack_from(f"<{per}I", sec)
            difat.extend(x for x in vals[:-1] if x < 0xFFFFFFFA)
            sid = vals[-1]
            guard += 1
        difat = difat[:max(n_fat, 0) + 4096]
        fat = []
        for s in difat:
            sec = self._sector(s)
            if len(sec) == self.sector_size:
                fat.extend(struct.unpack_from(f"<{per}I", sec))
        self.fat = fat
        self.minifat = []
        mf = self._chain_bytes(first_minifat, self.fat, self._sector) if first_minifat < 0xFFFFFFFA else b""
        if mf:
            self.minifat = list(struct.unpack_from(f"<{len(mf) // 4}I", mf))
        dir_bytes = self._chain_bytes(first_dir, self.fat, self._sector)
        self.entries = []
        for i in range(0, len(dir_bytes) - 127, 128):
            e = dir_bytes[i:i + 128]
            nlen = struct.unpack_from("<H", e, 64)[0]
            name = e[:max(0, min(nlen, 64) - 2)].decode("utf-16le", "replace")
            etype = e[66]
            start = struct.unpack_from("<I", e, 116)[0]
            size = struct.unpack_from("<I", e, 120)[0]
            self.entries.append((name, etype, start, size))
        self.ministream = b""
        if self.entries and self.entries[0][1] == 5:
            _, _, rstart, rsize = self.entries[0]
            self.ministream = self._chain_bytes(rstart, self.fat, self._sector)[:rsize]

    def _sector(self, sid: int) -> bytes:
        off = (sid + 1) * self.sector_size
        return self.data[off:off + self.sector_size]

    def _mini(self, sid: int) -> bytes:
        off = sid * self.mini_size
        return self.ministream[off:off + self.mini_size]

    def _chain_bytes(self, start: int, table: list, reader) -> bytes:
        out = []
        sid, seen = start, 0
        limit = len(table) + 1
        while sid < len(table) and sid not in (ENDOFCHAIN, FREESECT) and seen < limit:
            out.append(reader(sid))
            sid = table[sid]
            seen += 1
        return b"".join(out)

    def streams(self, max_total: int = 64 * 1024 * 1024):
        total = 0
        for name, etype, start, size in self.entries:
            if etype != 2:
                continue
            if size < self.cutoff:
                raw = self._chain_bytes(start, self.minifat, self._mini)[:size]
            else:
                raw = self._chain_bytes(start, self.fat, self._sector)[:size]
            total += len(raw)
            if total > max_total:
                break
            yield name, raw


def ovba_decompress(data: bytes, pos: int) -> bytes:
    """Descompressão MS-OVBA (código-fonte das macros VBA)."""
    out = bytearray()
    n = len(data)
    if pos >= n or data[pos] != 1:
        return b""
    i = pos + 1
    while i + 2 <= n:
        header = data[i] | (data[i + 1] << 8)
        size = (header & 0x0FFF) + 3
        if (header >> 12) & 7 != 3:
            break
        chunk_end = min(n, i + size)
        i += 2
        start = len(out)
        if not header & 0x8000:
            out += data[i:i + 4096]
            i += 4096
            continue
        while i < chunk_end:
            flags = data[i]
            i += 1
            for bit in range(8):
                if i >= chunk_end:
                    break
                if not (flags >> bit) & 1:
                    out.append(data[i])
                    i += 1
                else:
                    if i + 1 >= n:
                        return bytes(out)
                    token = data[i] | (data[i + 1] << 8)
                    i += 2
                    d = len(out) - start
                    bc = max((d - 1).bit_length(), 4) if d > 0 else 4
                    offset = (token >> (16 - bc)) + 1
                    length = (token & (0xFFFF >> bc)) + 3
                    if offset > d:
                        return bytes(out)
                    for _ in range(length):
                        out.append(out[-offset])
        i = chunk_end
        if len(out) > 8 * 1024 * 1024:
            break
    return bytes(out)


_ATTR_RE = re.compile(rb"\x00Attribut")


def extract_vba(blob: bytes) -> str:
    """Extrai o código das macros VBA de um OLE (documento ou vbaProject.bin)."""
    sources = []
    try:
        ole = OLEFile(blob)
        chunks = [raw for _name, raw in ole.streams()]
    except (ValueError, struct.error, IndexError):
        chunks = [blob]
    if len(chunks) != 1 or chunks[0] is not blob:
        chunks.append(blob)  # fallback: procura também no arquivo bruto (OLE fragmentado/danificado)
    for raw in chunks:
        for m in _ATTR_RE.finditer(raw):
            p = m.start() - 3
            if p >= 0 and raw[p] == 1:
                src = ovba_decompress(raw, p)
                if b"Attribute VB_" in src or b"Attribut" in src[:20]:
                    sources.append(src.decode("latin-1", "replace"))
                    if len(sources) > 200:
                        break
    seen, uniq = set(), []
    for s in sources:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return "\n\n'=====\n".join(uniq)


def analyze_ole(data: bytes) -> tuple[list[Indicator], dict, str]:
    inds: list[Indicator] = []
    info: dict = {"formato": "OLE / Compound File"}
    names = []
    try:
        ole = OLEFile(data)
        names = [n for n, t, _s, _z in ole.entries if t in (1, 2)]
    except (ValueError, struct.error, IndexError):
        pass
    info["fluxos"] = ", ".join(names[:40])
    low = [n.lower() for n in names]
    if "worddocument" in low:
        info["aplicativo"] = "Microsoft Word"
    elif "workbook" in low or "book" in low:
        info["aplicativo"] = "Microsoft Excel"
    elif "powerpoint document" in low:
        info["aplicativo"] = "Microsoft PowerPoint"
    elif any("msi" in n or n.startswith("䡀") for n in low):
        info["aplicativo"] = "Windows Installer (MSI)"
    macro = extract_vba(data)
    info["macros VBA"] = f"Sim ({macro.count('Attribute VB_Name')} módulo(s))" if macro else "Não"
    if b"\x01Ole10Native" in data or "\x01ole10native" in low:
        inds.append(_ind("ole.package", "Objeto OLE 'Package' embutido", "Documento",
                         "O documento carrega um arquivo embutido (Ole10Native/Packager), técnica usada para "
                         "entregar executáveis e scripts dentro de documentos.", 15, "media",
                         ["Ole10Native"], "Doc.Dropper"))
    return inds, info, macro


def analyze_ooxml(data: bytes) -> tuple[list[Indicator], dict, str]:
    inds: list[Indicator] = []
    info: dict = {"formato": "Office Open XML"}
    macro = ""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError, OSError):
        return inds, info, macro
    names = z.namelist()
    info["partes"] = len(names)
    for n in names:
        ln = n.lower()
        if ln.endswith("vbaproject.bin"):
            try:
                macro += extract_vba(z.read(n))
            except Exception:
                pass
        if ln.endswith(".rels") and z.getinfo(n).file_size < 2_000_000:
            try:
                rel = z.read(n)
            except Exception:
                continue
            for m in re.finditer(rb"<Relationship[^>]+>", rel, re.I):
                tag = m.group()
                if b'TargetMode="External"' not in tag and b"TargetMode='External'" not in tag:
                    continue
                tgt = re.search(rb'Target\s*=\s*["\']([^"\']+)', tag)
                t = tgt.group(1).decode("latin-1") if tgt else ""
                tl = t.lower()
                if tl.startswith(("ms-msdt:", "mhtml:", "search-ms:", "ms-officecmd:")) or "!x-usc:" in tl:
                    inds.append(_ind("ooxml.follina", "Exploit de protocolo (Follina / MSDT)", "Exploit",
                                     "O documento aponta para um protocolo especial (ms-msdt/mhtml) que executa "
                                     "código ao abrir — CVE-2022-30190 e similares.", 70, "critica", [t[:150]],
                                     "Exploit.Follina"))
                elif b"attachedTemplate" in tag or b"oleObject" in tag or b"/frame" in tag:
                    if tl.startswith(("http", "\\\\", "file:")):
                        inds.append(_ind("ooxml.remote_template", "Carrega modelo/objeto remoto", "Exploit",
                                         "O documento baixa um modelo ou objeto de um servidor externo ao ser aberto "
                                         "(template injection), forma comum de carregar macros maliciosas sem "
                                         "que elas estejam no arquivo.", 40, "alta", [t[:150]],
                                         "Doc.TemplateInjection"))
    if any(n.lower().startswith(("word/embeddings/", "xl/embeddings/", "ppt/embeddings/")) for n in names):
        info["objetos embutidos"] = "Sim"
    info["macros VBA"] = f"Sim ({macro.count('Attribute VB_Name')} módulo(s))" if macro else "Não"
    return inds, info, macro


# --------------------------------------------------------------------------- PDF
_STREAM_RE = re.compile(rb"stream\r?\n")


def pdf_expand(data: bytes, limit: int = 16 * 1024 * 1024) -> bytes:
    """Descompacta os streams FlateDecode do PDF (onde o JavaScript costuma se esconder)."""
    out = []
    total = 0
    for m in _STREAM_RE.finditer(data):
        start = m.end()
        end = data.find(b"endstream", start)
        if end < 0:
            break
        dict_area = data[max(0, m.start() - 400):m.start()]
        if b"FlateDecode" not in dict_area and b"/Fl " not in dict_area and b"/Fl/" not in dict_area:
            continue
        chunk = data[start:end]
        try:
            d = zlib.decompressobj().decompress(chunk, limit - total)
        except zlib.error:
            continue
        if d:
            out.append(d)
            total += len(d)
            if total >= limit:
                break
    return b"\n".join(out)


def pdf_info(data: bytes) -> dict:
    info: dict = {"formato": "PDF"}
    m = re.search(rb"%PDF-(\d\.\d)", data[:1024])
    info["versão"] = m.group(1).decode() if m else "?"
    for key in (b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch", b"/EmbeddedFile", b"/URI",
                b"/AcroForm", b"/XFA", b"/RichMedia", b"/ObjStm"):
        c = len(re.findall(re.escape(key) + rb"(?![A-Za-z])", data))
        if c:
            info[key.decode()] = c
    info["objetos"] = len(re.findall(rb"\d+\s+\d+\s+obj\b", data))
    info["páginas"] = len(re.findall(rb"/Type\s*/Page(?!s)", data))
    return info


# --------------------------------------------------------------------------- LNK
def lnk_info(data: bytes) -> dict:
    info: dict = {"formato": "Atalho do Windows"}
    try:
        flags = struct.unpack_from("<I", data, 0x14)[0]
        info["flags"] = hex(flags)
        info["tamanho do alvo"] = struct.unpack_from("<I", data, 0x34)[0]
        show = struct.unpack_from("<I", data, 0x3C)[0]
        info["janela"] = {1: "normal", 3: "maximizada", 7: "minimizada"}.get(show, str(show))
    except struct.error:
        pass
    strs = [m.group().decode("utf-16le", "replace") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", data)]
    if strs:
        info["textos"] = " | ".join(strs[:8])[:600]
    return info
