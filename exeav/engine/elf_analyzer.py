"""Análise estrutural de executáveis Linux (ELF) com parser próprio (rápido, sem dependências)."""
from __future__ import annotations

import struct

from .. import util
from .models import Indicator

HOOKABLE = {"readdir", "readdir64", "opendir", "fopen", "fopen64", "open", "open64", "stat", "stat64", "lstat",
            "lstat64", "__xstat", "__lxstat", "__xstat64", "access", "unlink", "unlinkat", "kill",
            "accept", "getdents", "getdents64"}
ROOTKIT_EXTRA = {"pam_authenticate", "pam_open_session", "pcap_loop", "audit_log_acct_message"}

MACHINES = {2: "SPARC", 3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 22: "S390", 40: "ARM",
            42: "SuperH", 50: "IA-64", 62: "x86-64", 183: "AArch64", 243: "RISC-V", 258: "LoongArch"}
SH_TYPES = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH", 6: "DYNAMIC", 7: "NOTE",
            8: "NOBITS", 9: "REL", 11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY", 0x6ffffff6: "GNU_HASH",
            0x6ffffffe: "VERNEED", 0x6fffffff: "VERSYM", 0x6ffffffd: "VERDEF"}
OSABI = {0: "SYSV", 3: "Linux", 6: "Solaris", 9: "FreeBSD", 12: "OpenBSD"}


def _ind(id_, name, category, desc, weight, severity="media", evidence=None, family=""):
    return Indicator(id=id_, name=name, category=category, description=desc, weight=weight,
                     severity=severity, evidence=evidence or [], family=family)


def _cstr(data: bytes, off: int) -> str:
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off, off + 512)
    return data[off:end if end >= 0 else off + 512].decode("latin-1", "replace")


class ELF:
    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF" or len(data) < 52:
            raise ValueError("não é ELF")
        self.is64 = data[4] == 2
        self.e = "<" if data[5] == 1 else ">"
        e = self.e
        if self.is64:
            (self.type, self.machine, _v, self.entry, phoff, shoff, _f, _eh, phentsize, phnum, shentsize, shnum,
             shstrndx) = struct.unpack_from(e + "HHIQQQIHHHHHH", data, 16)
        else:
            (self.type, self.machine, _v, self.entry, phoff, shoff, _f, _eh, phentsize, phnum, shentsize, shnum,
             shstrndx) = struct.unpack_from(e + "HHIIIIIHHHHHH", data, 16)
        self.osabi = data[7]
        self.segments = []
        for i in range(min(phnum, 256)):
            off = phoff + i * phentsize
            if off + (56 if self.is64 else 32) > len(data):
                break
            if self.is64:
                p_type, p_flags, p_off, p_vaddr, _pa, p_filesz, p_memsz, _al = struct.unpack_from(e + "IIQQQQQQ", data, off)
            else:
                p_type, p_off, p_vaddr, _pa, p_filesz, p_memsz, p_flags, _al = struct.unpack_from(e + "IIIIIIII", data, off)
            self.segments.append((p_type, p_flags, p_off, p_vaddr, p_filesz, p_memsz))
        self.sections = []
        if shoff and shnum and shoff + shnum * shentsize <= len(data):
            for i in range(min(shnum, 4096)):
                off = shoff + i * shentsize
                if self.is64:
                    vals = struct.unpack_from(e + "IIQQQQIIQQ", data, off)
                else:
                    vals = struct.unpack_from(e + "IIIIIIIIII", data, off)
                self.sections.append(list(vals))  # name, type, flags, addr, offset, size, link, info, align, entsize
            if shstrndx < len(self.sections):
                stro = self.sections[shstrndx][4]
                for s in self.sections:
                    s[0] = _cstr(data, stro + s[0])
            else:
                for s in self.sections:
                    s[0] = ""


def analyze(data: bytes, deep: bool = False) -> tuple[list[Indicator], dict]:
    info: dict = {"formato": "ELF"}
    inds: list[Indicator] = []
    if b"UPX!" in data[:4096] or (b"UPX!" in data[-4096:] and b"packed with the UPX" in data):
        inds.append(_ind("elf.upx", "Executável empacotado com UPX", "Ofuscação",
                         "O binário está compactado com UPX. Programas Linux legítimos quase nunca são "
                         "distribuídos assim; é comum em bots e mineradores.", 20, "media", ["UPX!"], "Linux.Packed"))
        info["empacotador"] = "UPX"
    try:
        elf = ELF(data)
    except (ValueError, struct.error) as ex:
        inds.append(_ind("elf.malformed", "Cabeçalho ELF malformado", "Estrutura",
                         "Cabeçalho ELF inválido ou propositalmente corrompido para atrapalhar análise.",
                         15, "media", [str(ex)[:100]], "Heur.Malformed"))
        return inds, info

    info.update({
        "classe": "64 bits" if elf.is64 else "32 bits",
        "endianness": "little-endian" if elf.e == "<" else "big-endian",
        "máquina": MACHINES.get(elf.machine, str(elf.machine)),
        "tipo": {2: "Executável", 3: "Compartilhado/PIE", 1: "Objeto", 4: "Core dump"}.get(elf.type, str(elf.type)),
        "ponto de entrada": hex(elf.entry),
        "sistema (ABI)": OSABI.get(elf.osabi, str(elf.osabi)),
        "seções": len(elf.sections),
        "segmentos": len(elf.segments),
    })

    interp = None
    rwx = False
    for p_type, p_flags, p_off, _va, p_filesz, _ms in elf.segments:
        if p_type == 3:  # PT_INTERP
            interp = _cstr(data, p_off)
        if p_type == 1 and (p_flags & 7) == 7:
            rwx = True
    info["interpretador"] = interp or "(nenhum — ligado estaticamente)"
    if rwx:
        inds.append(_ind("elf.rwx_segment", "Segmento de memória RWX", "Estrutura",
                         "Um segmento é carregado com leitura, escrita e execução ao mesmo tempo, comum em "
                         "binários que se desempacotam ou injetam código.", 15, "media", ["PT_LOAD RWX"],
                         "Linux.Packed"))

    sections = []
    has_symtab = False
    needed: list[str] = []
    imported: set[str] = set()
    exported: set[str] = set()
    secs = elf.sections
    for name, stype, flags, addr, off, size, link, _inf, _al, entsize in secs:
        if stype == 2:
            has_symtab = True
        if stype not in (0, 8) and size and len(sections) < 200:
            raw = data[off:off + min(size, 262144)]
            sections.append({"nome": name or "(sem nome)", "tipo": SH_TYPES.get(stype, hex(stype)),
                             "endereço virtual": hex(addr), "tamanho bruto": size,
                             "entropia": round(util.entropy(raw), 3) if raw else 0.0,
                             "permissões": ("A" if flags & 2 else "-") + ("W" if flags & 1 else "-") + ("X" if flags & 4 else "-")})
        if stype == 6 and link < len(secs):  # DYNAMIC
            stro = secs[link][4]
            fmt, step = (elf.e + "qQ", 16) if elf.is64 else (elf.e + "iI", 8)
            for i in range(0, min(size, 65536) - step + 1, step):
                tag, val = struct.unpack_from(fmt, data, off + i)
                if tag == 0:
                    break
                if tag == 1:
                    needed.append(_cstr(data, stro + val))
        if stype == 11 and link < len(secs):  # DYNSYM
            stro = secs[link][4]
            if elf.is64:
                fmt, step = elf.e + "IBBHQQ", 24
            else:
                fmt, step = elf.e + "IIIBBH", 16
            end = min(off + size, len(data))
            for p in range(off + step, end - step + 1, step):
                if elf.is64:
                    st_name, st_info, _o, shndx, _v, _s = struct.unpack_from(fmt, data, p)
                else:
                    st_name, _v, _s, st_info, _o, shndx = struct.unpack_from(fmt, data, p)
                if not st_name:
                    continue
                n = _cstr(data, stro + st_name).split("@")[0]
                if shndx == 0:
                    imported.add(n)
                elif (st_info & 0xF) == 2 and (st_info >> 4) in (1, 2):
                    exported.add(n)
                if len(imported) + len(exported) > 20000:
                    break
    info["_sections"] = sections
    info["bibliotecas"] = ", ".join(needed) or "(nenhuma)"
    info["_imports"] = {"(símbolos dinâmicos)": sorted(imported)[:3000]} if imported else {}
    info["_exports"] = sorted(exported)[:3000]
    info["símbolos de depuração"] = "Sim" if has_symtab else "Não (stripped)"
    is_go = b"Go build ID:" in data[:65536] or any(s[0] == ".gopclntab" for s in secs)
    info["linguagem"] = "Go" if is_go else ("Rust" if b"rust_panic" in data else "C/C++ (provável)")

    if not secs and elf.type in (2, 3):
        inds.append(_ind("elf.no_sections", "Sem tabela de seções", "Ofuscação",
                         "A tabela de seções foi removida (sstrip) — dificulta a análise e é muito comum em "
                         "malware Linux.", 15, "media", [], "Linux.Stripped"))

    ent = util.entropy(data)
    info["entropia geral"] = round(ent, 3)
    if ent > 7.4 and len(data) > 16384:
        inds.append(_ind("elf.high_entropy", "Conteúdo quase totalmente criptografado/compactado", "Ofuscação",
                         "A entropia do binário é muito alta: o código real está escondido.", 15, "media",
                         [f"entropia {ent:.2f}"], "Linux.Packed"))

    hooks = exported & HOOKABLE
    if elf.type == 3 and len(hooks) >= 3 and "dlsym" in imported and not ({"__libc_start_main"} & exported):
        extra = exported & ROOTKIT_EXTRA
        inds.append(_ind("elf.preload_hooks", "Intercepta funções do sistema (rootkit de usuário)", "Rootkit",
                         "Biblioteca que redefine funções como readdir/fopen/stat e chama as originais via dlsym — "
                         "técnica de rootkits LD_PRELOAD para esconder arquivos e processos.",
                         30 + (10 if extra else 0), "alta", sorted(hooks | extra), "Linux.Rootkit"))
    if {"socket", "connect", "dup2"} <= imported and ({"execve", "execl", "execlp", "execv", "system"} & imported) \
            and (b"/bin/sh\x00" in data or b"/bin/bash\x00" in data) and len(imported) < 60:
        inds.append(_ind("elf.bindshell", "Redireciona um shell para a rede", "Backdoor",
                         "Programa pequeno que se conecta pela rede, redireciona entrada/saída (dup2) e executa "
                         "/bin/sh: padrão de shell reverso/bind shell.", 30, "alta",
                         ["socket", "connect", "dup2", "execve", "/bin/sh"], "Backdoor.Shell"))
    if "ptrace" in imported and b"/proc/%d/mem" in data:
        inds.append(_ind("elf.ptrace_inject", "Injeção em processos via ptrace", "Injeção",
                         "Usa ptrace e escreve em /proc/<pid>/mem para alterar outros processos.", 20, "media",
                         ["ptrace", "/proc/%d/mem"], "Linux.Injector"))
    return inds, info
