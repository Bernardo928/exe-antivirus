"""Verificação de confiança para reduzir falsos positivos.

- Windows: assinatura Authenticode válida (embutida ou por catálogo do sistema)
  via WinVerifyTrust / CryptCATAdmin.
- Linux: arquivo pertence a um pacote dpkg e o MD5 confere com o registrado.
"""
from __future__ import annotations

import glob
import hashlib
import os
import threading

from .. import paths

_cache: dict[tuple, tuple[bool, str]] = {}
_cache_lock = threading.Lock()


def check(path: str) -> tuple[bool, str]:
    """Retorna (confiável, descrição)."""
    try:
        st = os.stat(path)
    except OSError:
        return False, ""
    key = (path, st.st_size, st.st_mtime_ns)
    with _cache_lock:
        if key in _cache:
            return _cache[key]
    if paths.IS_WINDOWS:
        res = _windows_trust(path)
    else:
        res = _dpkg_trust(path)
    with _cache_lock:
        if len(_cache) > 50000:
            _cache.clear()
        _cache[key] = res
    return res


# --------------------------------------------------------------------------- Linux / dpkg
_dpkg_index: dict[str, tuple[str, str]] | None = None
_dpkg_lock = threading.Lock()


def _load_dpkg() -> dict[str, tuple[str, str]]:
    global _dpkg_index
    with _dpkg_lock:
        if _dpkg_index is not None:
            return _dpkg_index
        idx: dict[str, tuple[str, str]] = {}
        for f in glob.glob("/var/lib/dpkg/info/*.md5sums"):
            pkg = os.path.basename(f)[:-8].split(":")[0]
            try:
                with open(f, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        parts = line.rstrip("\n").split("  ", 1)
                        if len(parts) == 2:
                            idx["/" + parts[1]] = (parts[0], pkg)
            except OSError:
                continue
        _dpkg_index = idx
        return idx


def _dpkg_trust(path: str) -> tuple[bool, str]:
    idx = _load_dpkg()
    if not idx:
        return False, ""
    cands = [os.path.abspath(path), os.path.realpath(path)]
    for c in list(cands):
        # usrmerge: /bin -> /usr/bin
        if c.startswith("/usr/"):
            cands.append(c[4:])
        else:
            cands.append("/usr" + c)
    for c in cands:
        ent = idx.get(c)
        if ent:
            md5 = hashlib.md5()
            try:
                with open(path, "rb") as f:
                    for b in iter(lambda: f.read(1 << 20), b""):
                        md5.update(b)
            except OSError:
                return False, ""
            if md5.hexdigest() == ent[0]:
                return True, f"Arquivo original do pacote do sistema '{ent[1]}' (MD5 confere com o dpkg)"
            return False, f"ATENÇÃO: arquivo do pacote '{ent[1]}' foi MODIFICADO (MD5 diferente do original)"
    return False, ""


# --------------------------------------------------------------------------- Windows
def _windows_trust(path: str) -> tuple[bool, str]:
    try:
        ok = _winverifytrust(path)
        if ok:
            return True, "Assinatura digital Authenticode válida"
        if _catalog_signed(path):
            return True, "Assinado pelo catálogo de segurança do Windows"
    except Exception:
        pass
    return False, ""


def _guid(s: str):
    import ctypes
    import uuid

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort), ("Data3", ctypes.c_ushort),
                    ("Data4", ctypes.c_ubyte * 8)]
    u = uuid.UUID(s)
    g = GUID()
    g.Data1, g.Data2, g.Data3 = u.fields[0], u.fields[1], u.fields[2]
    for i, b in enumerate(u.bytes[8:]):
        g.Data4[i] = b
    return g


def _winverifytrust(path: str) -> bool:
    import ctypes
    from ctypes import wintypes

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                    ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)), ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
                    ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]

    action = _guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE")  # WINTRUST_ACTION_GENERIC_VERIFY_V2
    fi = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path, None, None)
    wd = WINTRUST_DATA()
    wd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    wd.dwUIChoice = 2            # WTD_UI_NONE
    wd.fdwRevocationChecks = 0   # WTD_REVOKE_NONE
    wd.dwUnionChoice = 1         # WTD_CHOICE_FILE
    wd.pFile = ctypes.pointer(fi)
    wd.dwStateAction = 1         # WTD_STATEACTION_VERIFY
    wd.dwProvFlags = 0x1000 | 0x10  # WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE
    wvt = ctypes.windll.wintrust.WinVerifyTrust
    wvt.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p]
    wvt.restype = ctypes.c_long
    res = wvt(None, ctypes.byref(action), ctypes.byref(wd))
    wd.dwStateAction = 2         # WTD_STATEACTION_CLOSE
    wvt(None, ctypes.byref(action), ctypes.byref(wd))
    return res == 0


def _catalog_signed(path: str) -> bool:
    import ctypes
    from ctypes import wintypes

    wintrust = ctypes.windll.wintrust
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                     wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    INVALID = wintypes.HANDLE(-1).value
    h_cat_admin = wintypes.HANDLE()
    driver_action = _guid("F750E6C3-38EE-11d1-85E5-00C04FC295EE")  # DRIVER_ACTION_VERIFY
    acquired = False
    try:
        acq2 = wintrust.CryptCATAdminAcquireContext2
        acq2.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p,
                         wintypes.DWORD]
        acq2.restype = wintypes.BOOL
        acquired = bool(acq2(ctypes.byref(h_cat_admin), ctypes.byref(driver_action), "SHA256", None, 0))
        use_v2 = True
    except AttributeError:
        use_v2 = False
    if not acquired:
        acq = wintrust.CryptCATAdminAcquireContext
        acq.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p, wintypes.DWORD]
        acq.restype = wintypes.BOOL
        if not acq(ctypes.byref(h_cat_admin), ctypes.byref(driver_action), 0):
            return False
        use_v2 = False
    hfile = kernel32.CreateFileW(path, 0x80000000, 1 | 2 | 4, None, 3, 0, None)
    if hfile == INVALID or hfile is None:
        wintrust.CryptCATAdminReleaseContext(h_cat_admin, 0)
        return False
    try:
        size = wintypes.DWORD(64)
        buf = (ctypes.c_ubyte * 64)()
        if use_v2:
            calc = wintrust.CryptCATAdminCalcHashFromFileHandle2
            calc.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
                             wintypes.DWORD]
            calc.restype = wintypes.BOOL
            ok = calc(h_cat_admin, hfile, ctypes.byref(size), buf, 0)
        else:
            calc = wintrust.CryptCATAdminCalcHashFromFileHandle
            calc.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD]
            calc.restype = wintypes.BOOL
            ok = calc(hfile, ctypes.byref(size), buf, 0)
        if not ok:
            return False
        enum = wintrust.CryptCATAdminEnumCatalogFromHash
        enum.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
        enum.restype = wintypes.HANDLE
        h_info = enum(h_cat_admin, buf, size.value, 0, None)
        if h_info:
            rel = wintrust.CryptCATAdminReleaseCatalogContext
            rel.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
            rel(h_cat_admin, h_info, 0)
            return True
        return False
    finally:
        kernel32.CloseHandle(hfile)
        rc = wintrust.CryptCATAdminReleaseContext
        rc.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        rc(h_cat_admin, 0)
