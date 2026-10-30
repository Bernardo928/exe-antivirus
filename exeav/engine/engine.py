"""Motor de detecção: combina assinaturas, regras de conteúdo e análise estrutural.

A decisão é sempre baseada no CONTEÚDO do arquivo (bytes, estrutura, código,
comportamento declarado). O nome e a extensão do arquivo nunca contam pontos.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import io
import os
import re
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field

from .. import ENGINE_VERSION, config, paths, util
from . import doc_analyzer, elf_analyzer, filetype, pe_analyzer, trust
from .models import CLEAN, MALICIOUS, SUSPICIOUS, Indicator, ScanResult
from .rules import USER_RULES_NAME, RuleSet
from .signatures import SignatureDB

# Indicadores puramente estruturais/ofuscação: somados até um teto, para que um
# programa apenas "empacotado" não seja tratado como vírus.
STRUCTURAL = {"pe.wx_section", "pe.high_entropy_code", "pe.empty_exec", "pe.packer", "pe.protector",
              "pe.no_imports", "pe.min_imports", "pe.ep_outside", "pe.ep_nonexec", "pe.ep_last",
              "pe.net_obfuscator", "pe.future_ts", "pe.malformed", "elf.upx", "elf.no_sections",
              "elf.high_entropy", "elf.rwx_segment", "elf.malformed", "deobf.layer", "pe.api_antidebug"}
STRUCTURAL_CAP = 30
TRUST_BONUS = -40

PE_MARKERS = (b"This program cannot be run in DOS mode", b"This program must be run under Win32")
_B64_RE = re.compile(rb"[A-Za-z0-9+/]{80,}={0,2}")
_ENC_RE = re.compile(rb"\s[-/]e(?:nc?|ncodedcommand|ncodedc|ncoded|ncode)?\s+['\"]?([A-Za-z0-9+/=]{20,})", re.I)
_CHARS_RE = re.compile(rb"(?:\[char\]\s*\(?\s*(\d{2,3})\s*\)?\s*[+,]?\s*){8,}", re.I)
_FROMCC_RE = re.compile(rb"fromcharcode\s*\(\s*((?:\d{1,3}\s*,\s*){8,}\d{1,3})\s*\)", re.I)
_PRINTABLE = bytes(i if (32 <= i < 127 or i == 9) else 10 for i in range(256))
_HEXBLOB_RE = re.compile(rb"(?:4d5a|4D5A)[0-9a-fA-F]{200,}")


@dataclass
class Analysis:
    result: ScanResult
    info: dict = field(default_factory=dict)
    macro: str = ""
    decoded: list[str] = field(default_factory=list)
    members: list[ScanResult] = field(default_factory=list)
    hashes: dict = field(default_factory=dict)


_NON_PRINT = bytes(c for c in range(256) if not (32 <= c < 127 or c in (9, 10, 13)))


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    s = b[:4096]
    return len(s.translate(None, _NON_PRINT)) / len(s)


class Engine:
    def __init__(self, settings: config.Settings | None = None, sigdb: SignatureDB | None = None,
                 rules: RuleSet | None = None):
        self.settings = settings or config.get()
        self.sigdb = sigdb or SignatureDB()
        self.rules = rules or RuleSet(paths.data_dir() / USER_RULES_NAME)
        self.exclusions = paths.Exclusions(self.settings.exclusions)

    def reload(self) -> None:
        self.rules = RuleSet(paths.data_dir() / USER_RULES_NAME)
        self.exclusions = paths.Exclusions(self.settings.exclusions)

    @property
    def version(self) -> str:
        return f"{ENGINE_VERSION}/{self.rules.version}/{self.sigdb.version}/{self.settings.sensitivity}"

    # ------------------------------------------------------------------ arquivos
    def scan_file(self, path: str, deep: bool = False) -> Analysis:
        res = ScanResult(path=path)
        if self.exclusions.is_excluded(path):
            res.skipped = True
            res.error = "Arquivo protegido do próprio antivírus (ignorado)"
            return Analysis(res)
        try:
            st = os.stat(path)
        except OSError as e:
            res.error = f"Não foi possível acessar: {e.strerror or e}"
            res.skipped = True
            return Analysis(res)
        res.size = st.st_size
        limit = self.settings.max_file_size_mb * 1024 * 1024
        try:
            with open(path, "rb") as f:
                head = f.read(8192)
                ftype = filetype.detect(head)
                res.file_type = ftype
                if ftype == "empty":
                    return Analysis(res)
                if ftype in filetype.MEDIA_TYPES and st.st_size > 16 * 1024 * 1024 and not deep:
                    return Analysis(res)  # mídia grande: sem código executável a inspecionar
                if st.st_size > limit and not deep:
                    res.skipped = True
                    res.error = f"Maior que o limite de {self.settings.max_file_size_mb} MB"
                    return Analysis(res)
                data = head + f.read()
        except OSError as e:
            res.error = f"Não foi possível ler: {e.strerror or e}"
            res.skipped = True
            return Analysis(res)
        an = self.analyze(data, path=path, ftype=ftype, deep=deep)
        an.result.size = st.st_size
        return an

    # ------------------------------------------------------------------ conteúdo
    def analyze(self, data: bytes, path: str = "", ftype: str | None = None, depth: int = 0,
                deep: bool = False) -> Analysis:
        ftype = ftype or filetype.detect(data[:8192])
        res = ScanResult(path=path, file_type=ftype, size=len(data))
        an = Analysis(res)
        inds: list[Indicator] = []

        sha256 = hashlib.sha256(data).hexdigest()
        res.sha256 = sha256
        md5 = hashlib.md5(data).hexdigest() if (self.sigdb.has_md5 or deep) else ""
        sha1 = hashlib.sha1(data).hexdigest() if (self.sigdb.has_sha1 or deep) else ""
        an.hashes = {"md5": md5, "sha1": sha1, "sha256": sha256}
        hit = self.sigdb.lookup(sha256, md5, sha1)
        if hit:
            inds.append(Indicator(id="sig.hash", name=f"Malware conhecido: {hit[0]}", category="Assinatura",
                                  description="O hash do arquivo corresponde exatamente a uma amostra de malware "
                                              f"catalogada (fonte: {hit[1]}).", weight=100, severity="critica",
                                  evidence=[sha256], family=hit[0]))

        if ftype.startswith("pe"):
            pinds, info = pe_analyzer.analyze(data, deep=deep)
            inds += pinds
            an.info = info
            buf = self._strings_blob(data)
            inds += self.rules.run(buf, "pe")
        elif ftype.startswith("elf"):
            einds, info = elf_analyzer.analyze(data, deep=deep)
            inds += einds
            an.info = info
            inds += self.rules.run(self._strings_blob(data, wide=False), "elf")
        elif ftype == "macho":
            an.info = {"formato": "Mach-O"}
            inds += self.rules.run(self._strings_blob(data, wide=False), "macho")
        elif ftype in ("script", "html"):
            inds += self._analyze_text(data, ftype, an, depth)
        elif ftype == "ole":
            oinds, info, macro = doc_analyzer.analyze_ole(data)
            inds += oinds
            an.info, an.macro = info, macro
            if macro:
                inds += self.rules.run(macro.encode("latin-1", "replace"), "macro")
            if "MSI" not in info.get("aplicativo", ""):
                inds += self._embedded_pe(data, "documento")
        elif ftype == "ooxml":
            oinds, info, macro = doc_analyzer.analyze_ooxml(data)
            inds += oinds
            an.info, an.macro = info, macro
            if macro:
                inds += self.rules.run(macro.encode("latin-1", "replace"), "macro")
            inds += self._scan_archive(data, ftype, an, depth, only_prefixes=("word/embeddings/", "xl/embeddings/",
                                                                             "ppt/embeddings/", "word/media/"))
        elif ftype == "pdf":
            an.info = doc_analyzer.pdf_info(data)
            expanded = doc_analyzer.pdf_expand(data)
            buf = data + b"\n" + expanded
            inds += self.rules.run(buf, "pdf")
            if b"/JavaScript" in data or b"/JS" in data:
                js_inds = [i for i in self.rules.run(expanded, "html") if i.id.startswith(("js.", "ps.", "script."))]
                inds += js_inds
            inds += self._embedded_pe(buf, "PDF")
        elif ftype == "rtf":
            an.info = {"formato": "RTF", "objetos OLE": data.count(b"\\object")}
            inds += self.rules.run(data[:32 * 1024 * 1024], "rtf")
        elif ftype == "lnk":
            an.info = doc_analyzer.lnk_info(data)
            inds += self.rules.run(data + b"\n" + util.wide_strings_blob(data), "lnk")
        elif ftype in ("zip", "jar", "apk", "gzip"):
            an.info = {"formato": filetype.DESCRIPTIONS.get(ftype, ftype)}
            inds += self._scan_archive(data, ftype, an, depth)
        elif ftype in filetype.MEDIA_TYPES:
            an.info = {"formato": filetype.DESCRIPTIONS.get(ftype, ftype)}
            inds += self._embedded_pe(data, "arquivo de mídia")
        elif ftype == "binary" and len(data) <= 4 * 1024 * 1024:
            inds += self.rules.run(self._strings_blob(data), "any")
        res.indicators = self._merge(inds)
        self._finalize(res, path if depth == 0 else "")
        return an

    # ------------------------------------------------------------------ partes
    @staticmethod
    def _strings_blob(data: bytes, wide: bool = True, limit: int = 24 * 1024 * 1024) -> bytes:
        """Texto legível do binário (ASCII + UTF-16) para as regras. Implementado com translate (C puro).

        Binários enormes têm apenas o início e o fim inspecionados pelas regras (a análise
        estrutural e o hash continuam considerando o arquivo inteiro)."""
        d = data if len(data) <= limit else data[:limit - 8 * 1024 * 1024] + b"\n" + data[-8 * 1024 * 1024:]
        blob = d.translate(_PRINTABLE)
        if wide:
            blob += b"\n" + d[0::2].translate(_PRINTABLE) + b"\n" + d[1::2].translate(_PRINTABLE)
        return blob

    def _embedded_pe(self, data: bytes, where: str) -> list[Indicator]:
        for marker in PE_MARKERS:
            idx = data.find(marker, 1)
            if idx > 0 and data.rfind(b"MZ", max(0, idx - 512), idx) >= 0:
                return [Indicator(id="gen.embedded_pe", name=f"Executável escondido dentro de {where}",
                                  category="Dropper",
                                  description="Foi encontrado um programa do Windows completo escondido dentro de "
                                              "um arquivo que não deveria conter código executável.",
                                  weight=30, severity="alta", evidence=[f"offset {hex(idx)}"],
                                  family="Trojan.Dropper")]
        return []

    def _deobfuscate(self, raw: bytes, an: Analysis, depth: int) -> tuple[bytes, list[Indicator]]:
        """Decodifica camadas de ofuscação (Base64, -EncodedCommand, [char], fromCharCode, gzip)."""
        layers: list[bytes] = []
        inds: list[Indicator] = []
        payloads: list[bytes] = []
        for m in _ENC_RE.finditer(raw[:4 * 1024 * 1024]):
            try:
                dec = base64.b64decode(m.group(1) + b"=" * (-len(m.group(1)) % 4))
                txt = dec.decode("utf-16le", "ignore").encode("utf-8", "ignore")
                if _printable_ratio(txt) > 0.85:
                    layers.append(txt)
            except (binascii.Error, ValueError):
                pass
            if len(layers) > 10:
                break
        for i, m in enumerate(_B64_RE.finditer(raw[:8 * 1024 * 1024])):
            if i > 25:
                break
            blob = m.group()[:3 * 1024 * 1024]
            try:
                dec = base64.b64decode(blob + b"=" * (-len(blob) % 4))
            except (binascii.Error, ValueError):
                continue
            if dec[:2] == b"\x1f\x8b":
                try:
                    dec = gzip.decompress(dec)[:4 * 1024 * 1024]
                except (OSError, EOFError, zlib.error):
                    pass
            if dec[:2] == b"MZ" or dec[:4] == b"\x7fELF":
                payloads.append(dec)
                continue
            for cand in (dec, dec.decode("utf-16le", "ignore").encode("utf-8", "ignore") if b"\x00" in dec[:64] else b""):
                if cand and _printable_ratio(cand) > 0.9:
                    layers.append(cand[:2 * 1024 * 1024])
                    break
        for m in _CHARS_RE.finditer(raw[:4 * 1024 * 1024]):
            nums = re.findall(rb"\d{2,3}", m.group())
            layers.append(bytes(int(n) % 256 for n in nums))
        for m in _FROMCC_RE.finditer(raw[:4 * 1024 * 1024]):
            layers.append(bytes(int(n) % 256 for n in re.findall(rb"\d{1,3}", m.group(1))))
        for m in _HEXBLOB_RE.finditer(raw[:8 * 1024 * 1024]):
            h = m.group()
            try:
                dec = bytes.fromhex(h[:len(h) // 2 * 2].decode())
                if dec[:2] == b"MZ":
                    payloads.append(dec)
            except ValueError:
                pass
        for p in payloads[:4]:
            if depth < 3:
                sub = self.analyze(p, depth=depth + 1)
                sub.result.path = "(executável decodificado)"
                an.members.append(sub.result)
                inds.append(Indicator(
                    id="deobf.payload", name="Executável codificado dentro do script", category="Dropper",
                    description="O script carrega um programa inteiro escondido em Base64/hexadecimal, que é "
                                "gravado em disco ou executado na memória.",
                    weight=max(40, sub.result.score), severity="alta",
                    evidence=[f"{sub.result.file_type} {util.human_size(len(p))}", sub.result.threat_name or "sem nome"],
                    family=sub.result.threat_name.replace("Heur.", "") if sub.result.threat_name else "Trojan.Dropper"))
        if layers:
            an.decoded.extend(x.decode("utf-8", "replace")[:20000] for x in layers[:20])
            inds.append(Indicator(id="deobf.layer", name="Conteúdo ofuscado foi decodificado", category="Ofuscação",
                                  description="Parte do código estava codificada (Base64/char codes) e foi "
                                              "decodificada pelo antivírus para inspeção.",
                                  weight=5, severity="baixa", evidence=[x[:100].decode("utf-8", "replace") for x in layers[:3]],
                                  family="Script.Obfuscated"))
        return b"\n#--decoded--\n".join(layers), inds

    def _analyze_text(self, data: bytes, ftype: str, an: Analysis, depth: int) -> list[Indicator]:
        text = filetype.decode_text(data[:16 * 1024 * 1024])
        if text is None:
            text = data[:16 * 1024 * 1024].decode("latin-1")
        raw = text.encode("utf-8", "replace")
        an.info = {"formato": filetype.DESCRIPTIONS.get(ftype, ftype),
                   "linguagem": filetype.script_language(text), "linhas": text.count("\n") + 1,
                   "codificação": "UTF-16" if data[:2] in (b"\xff\xfe", b"\xfe\xff") else "UTF-8/ASCII"}
        decoded, inds = self._deobfuscate(raw, an, depth)
        buf = raw + (b"\n#--decoded--\n" + decoded if decoded else b"")
        found = {i.id: i for i in self.rules.run(buf, "script")}
        if ftype == "html":
            for i in self.rules.run(buf, "html"):
                found.setdefault(i.id, i)
        inds += list(found.values())
        inds += self._embedded_pe(data, "texto/script")
        return inds

    def _scan_archive(self, data: bytes, ftype: str, an: Analysis, depth: int,
                      only_prefixes: tuple = ()) -> list[Indicator]:
        inds: list[Indicator] = []
        if not self.settings.scan_archives or depth >= max(1, self.settings.archive_max_depth):
            return inds
        member_limit = min(self.settings.max_file_size_mb, 64) * 1024 * 1024
        budget = 256 * 1024 * 1024
        members: list[tuple[str, bytes]] = []
        encrypted = 0
        try:
            if ftype == "gzip":
                dec = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(data, member_limit)
                if len(dec) > 262 and dec[257:262] == b"ustar":
                    with tarfile.open(fileobj=io.BytesIO(dec)) as tf:
                        for ti in tf.getmembers()[:3000]:
                            if ti.isfile() and ti.size <= member_limit and budget > 0:
                                fo = tf.extractfile(ti)
                                if fo:
                                    b = fo.read()
                                    budget -= len(b)
                                    members.append((ti.name, b))
                else:
                    members.append(("(conteúdo descompactado)", dec))
            else:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    infos = z.infolist()
                    total_unc = sum(i.file_size for i in infos)
                    total_c = sum(i.compress_size for i in infos) or 1
                    an.info["arquivos internos"] = len(infos)
                    an.info["tamanho descompactado"] = util.human_size(total_unc)
                    if total_unc > 2 * 1024 ** 3 and total_unc / total_c > 200:
                        inds.append(Indicator(id="arch.bomb", name="Bomba de descompressão (zip bomb)",
                                              category="Destrutivo",
                                              description="O arquivo expande para um tamanho absurdo para travar ou "
                                                          "encher o disco de quem o abrir.",
                                              weight=40, severity="alta",
                                              evidence=[f"{util.human_size(total_unc)} (razão {total_unc // total_c}x)"],
                                              family="Archive.Bomb"))
                    for info in infos[:5000]:
                        if info.is_dir() or (only_prefixes and not info.filename.startswith(only_prefixes)):
                            continue
                        if info.flag_bits & 1:
                            encrypted += 1
                            continue
                        if info.file_size > member_limit or budget <= 0:
                            continue
                        try:
                            b = z.read(info)
                        except Exception:
                            continue
                        budget -= len(b)
                        members.append((info.filename, b))
        except (zipfile.BadZipFile, tarfile.TarError, zlib.error, OSError, EOFError, ValueError, NotImplementedError):
            pass
        if encrypted:
            an.info["itens protegidos por senha"] = encrypted
        worst: list[ScanResult] = []
        for name, b in members:
            sub = self.analyze(b, path=name, depth=depth + 1)
            sub.result.path = name
            if sub.result.is_threat:
                worst.append(sub.result)
                an.members.append(sub.result)
        worst.sort(key=lambda r: -r.score)
        for r in worst[:5]:
            inds.append(Indicator(id=f"arch.member:{r.path}", name=f"Ameaça dentro do compactado: {r.path}",
                                  category="Compactado",
                                  description=f"O item interno '{r.path}' foi classificado como {r.verdict} "
                                              f"({r.threat_name}). Motivos: {', '.join(r.reasons()[:4])}.",
                                  weight=r.score if r.verdict == MALICIOUS else min(r.score, 34),
                                  severity="critica" if r.verdict == MALICIOUS else "media",
                                  evidence=[r.threat_name] + r.reasons()[:5],
                                  family=r.threat_name.replace("Heur.", "")))
        return inds

    # ------------------------------------------------------------------ pontuação
    @staticmethod
    def _merge(inds: list[Indicator]) -> list[Indicator]:
        out: dict[str, Indicator] = {}
        for i in inds:
            if i.id in out:
                for e in i.evidence:
                    if e not in out[i.id].evidence:
                        out[i.id].evidence.append(e)
                out[i.id].weight = max(out[i.id].weight, i.weight)
            else:
                out[i.id] = i
        return list(out.values())

    def _finalize(self, res: ScanResult, path: str) -> None:
        struct_sum = sum(i.weight for i in res.indicators if i.id in STRUCTURAL)
        other = sum(i.weight for i in res.indicators if i.id not in STRUCTURAL)
        score = other + min(struct_sum, STRUCTURAL_CAP)
        hard = any(i.id in ("sig.hash", "test.eicar") for i in res.indicators)
        if path and score > 0 and not hard and (filetype.is_executable_type(res.file_type)
                                                or res.file_type in ("script", "html", "ole")):
            ok, desc = trust.check(path)
            if ok:
                res.indicators.append(Indicator(id="trust.verified", name="Origem verificada",
                                                category="Confiança", description=desc, weight=TRUST_BONUS,
                                                severity="info", evidence=[desc], family=""))
                score += TRUST_BONUS
            elif desc.startswith("ATENÇÃO") and filetype.is_executable_type(res.file_type):
                res.indicators.append(Indicator(id="trust.modified", name="Arquivo de sistema adulterado",
                                                category="Integridade", description=desc, weight=20,
                                                severity="alta", evidence=[desc], family="Trojan.Patched"))
                score += 20
        res.score = max(0, score)
        susp, mal = self.settings.thresholds()
        if hard or res.score >= mal:
            res.verdict = MALICIOUS
        elif res.score >= susp:
            res.verdict = SUSPICIOUS
        else:
            res.verdict = CLEAN
        if res.verdict != CLEAN:
            res.threat_name = self._threat_name(res)

    @staticmethod
    def _threat_name(res: ScanResult) -> str:
        for i in res.indicators:
            if i.id == "sig.hash":
                return i.family
            if i.id == "test.eicar":
                return "EICAR-Test-File"
        cands = sorted((i for i in res.indicators if i.weight > 0 and i.family),
                       key=lambda i: (i.id in STRUCTURAL, -i.weight))
        fam = cands[0].family if cands else "Generic"
        prefix = "Heur." if res.verdict == MALICIOUS else "Suspeito."
        return fam if fam.startswith(("Heur.", "Suspeito.")) else prefix + fam
