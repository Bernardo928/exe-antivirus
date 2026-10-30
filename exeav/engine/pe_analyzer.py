"""Análise estrutural de executáveis Windows (PE)."""
from __future__ import annotations

import datetime as _dt
import re
import time

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None

from .. import util
from .models import Indicator

SCN_EXEC = 0x20000000
SCN_WRITE = 0x80000000
SCN_CODE = 0x00000020

PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".upx": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
    ".mpress1": "MPRESS", ".mpress2": "MPRESS", ".petite": "Petite", ".nsp0": "NsPack", ".nsp1": "NsPack",
    ".themida": "Themida", ".winlice": "WinLicense", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    ".vmp2": "VMProtect", ".enigma1": "Enigma Protector", ".enigma2": "Enigma Protector",
    "pec2": "PECompact", ".pec2": "PECompact", ".yp": "Y0da Protector", ".perplex": "Perplex",
    ".spack": "Simple Pack", ".packed": "Desconhecido (.packed)", "kkrunchy": "kkrunchy",
    ".mew": "MEW", ".boom": "The Boomerang", ".ccg": "CCG", ".rlpack": "RLPack", ".taz": "PESpin",
    ".svkp": "SVKP", ".ecode": "Easy Protector", ".obsidiu": "Obsidium",
}
PROTECTORS = {"Themida", "WinLicense", "VMProtect", "Enigma Protector", "Obsidium", "PESpin", "SVKP"}

AV_PROCESSES = [
    b"msmpeng.exe", b"mpcmdrun.exe", b"msseces.exe", b"avp.exe", b"avpui.exe", b"ekrn.exe", b"egui.exe",
    b"bdagent.exe", b"vsserv.exe", b"mbam.exe", b"mbamservice.exe", b"avastsvc.exe", b"avastui.exe",
    b"avgsvc.exe", b"avgui.exe", b"mcshield.exe", b"mfemms.exe", b"nortonsecurity.exe", b"ns.exe",
    b"savservice.exe", b"sophoshealth.exe", b"wrsa.exe", b"cylancesvc.exe", b"sentinelagent.exe",
    b"csfalconservice.exe", b"procexp.exe", b"procexp64.exe", b"procmon.exe", b"wireshark.exe",
    b"x64dbg.exe", b"x32dbg.exe", b"ollydbg.exe", b"ida64.exe", b"processhacker.exe", b"fiddler.exe",
]

DOC_EXTENSIONS = [
    b".doc", b".docx", b".xls", b".xlsx", b".ppt", b".pptx", b".pdf", b".jpg", b".jpeg", b".png",
    b".psd", b".sql", b".mdb", b".accdb", b".dbf", b".odt", b".ods", b".odp", b".rtf", b".csv",
    b".zip", b".rar", b".7z", b".tar", b".bak", b".mp3", b".mp4", b".avi", b".mkv", b".wav",
    b".dwg", b".dxf", b".pst", b".ost", b".vmdk", b".vhd", b".vdi", b".sqlite", b".wallet", b".key",
    b".pem", b".cpp", b".java", b".php", b".kdbx", b".xlsm", b".docm", b".txt",
]

API_GROUPS = {
    "injection": {"virtualallocex", "writeprocessmemory", "createremotethread", "createremotethreadex",
                  "ntcreatethreadex", "rtlcreateuserthread", "queueuserapc", "ntqueueapcthread",
                  "ntwritevirtualmemory", "zwwritevirtualmemory", "ntallocatevirtualmemory", "openprocess"},
    "hollowing": {"ntunmapviewofsection", "zwunmapviewofsection", "setthreadcontext", "wow64setthreadcontext",
                  "getthreadcontext", "resumethread"},
    "keylog": {"setwindowshookex", "getasynckeystate", "getkeyboardstate", "getkeystate", "mapvirtualkey",
               "getforegroundwindow", "getwindowtext", "registerrawinputdevices", "getrawinputdata"},
    "download": {"urldownloadtofile", "internetopenurl", "internetreadfile", "httpsendrequest",
                 "winhttpopen", "winhttpsendrequest", "internetopen", "urlopenblockingstream"},
    "exec": {"winexec", "shellexecute", "shellexecuteex", "createprocess", "createprocessasuser", "system"},
    "antidebug": {"checkremotedebuggerpresent", "ntqueryinformationprocess", "ntsetinformationthread",
                  "zwsetinformationthread", "outputdebugstring", "isdebuggerpresent"},
    "privilege": {"adjusttokenprivileges", "lookupprivilegevalue", "openprocesstoken"},
    "crypto": {"cryptencrypt", "cryptgenkey", "cryptimportkey", "cryptderivekey", "bcryptencrypt",
               "bcryptgeneratesymmetrickey", "cryptacquirecontext"},
    "fileenum": {"findfirstfile", "findfirstfileex", "findnextfile"},
    "filewrite": {"movefileex", "movefile", "writefile", "setfileattributes", "deletefile"},
    "procenum": {"createtoolhelp32snapshot", "process32first", "process32next", "enumprocesses"},
    "terminate": {"terminateprocess"},
    "clipboard": {"setclipboarddata", "getclipboarddata", "openclipboard"},
    "service": {"createservice", "startservice", "openscmanager"},
    "dynamic": {"getprocaddress", "loadlibrary", "loadlibraryex", "ldrloaddll", "ldrgetprocedureaddress"},
    "screen": {"bitblt", "getdesktopwindow", "createcompatiblebitmap", "getdc"},
    "registry": {"regsetvalueex", "regcreatekeyex", "regsetkeyvalue"},
    "network": {"wsastartup", "socket", "connect", "send", "recv", "inet_addr", "gethostbyname", "wsasocket"},
}


def _norm_api(name: str) -> str:
    n = name.lower()
    if n.endswith(("a", "w")) and n[:-1] in _ALL_APIS:
        return n[:-1]
    return n


_ALL_APIS = set().union(*API_GROUPS.values())


def _ind(id_, name, category, desc, weight, severity="media", evidence=None, family=""):
    return Indicator(id=id_, name=name, category=category, description=desc, weight=weight,
                     severity=severity, evidence=evidence or [], family=family)


def _cert_names(blob: bytes) -> list[str]:
    """Extrai os nomes comuns (CN) dos certificados de uma assinatura Authenticode (ASN.1 simplificado)."""
    names = []
    for m in re.finditer(rb"\x06\x03\x55\x04\x03[\x0c\x13\x14\x1e](.)", blob, re.S):
        ln = m.group(1)[0]
        start = m.end()
        if ln & 0x80:
            continue
        raw = blob[start:start + ln]
        try:
            s = raw.decode("utf-16-be") if blob[m.start() + 5] == 0x1E else raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if s and s not in names:
            names.append(s)
    return names


def analyze(data: bytes, deep: bool = False) -> tuple[list[Indicator], dict]:
    """Retorna (indicadores, informações estruturais)."""
    info: dict = {"formato": "PE"}
    inds: list[Indicator] = []
    if pefile is None:
        return inds, info
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except Exception as e:  # PE inválido/corrompido
        inds.append(_ind("pe.malformed", "Cabeçalho PE malformado", "Estrutura",
                         "O executável tem estrutura inválida, comum em arquivos corrompidos ou manipulados "
                         "para enganar analisadores.", 15, "media", [str(e)[:120]], "Heur.Malformed"))
        return inds, info

    dirs = [pefile.DIRECTORY_ENTRY[k] for k in ("IMAGE_DIRECTORY_ENTRY_IMPORT", "IMAGE_DIRECTORY_ENTRY_EXPORT",
                                                "IMAGE_DIRECTORY_ENTRY_SECURITY", "IMAGE_DIRECTORY_ENTRY_TLS",
                                                "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
                                                "IMAGE_DIRECTORY_ENTRY_RESOURCE")]
    try:
        pe.parse_data_directories(directories=dirs)
    except Exception:
        pass

    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    is64 = oh.Magic == 0x20B
    is_dll = bool(fh.Characteristics & 0x2000)
    is_dotnet = hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR") or (
        len(oh.DATA_DIRECTORY) > 14 and oh.DATA_DIRECTORY[14].VirtualAddress != 0)
    ts = fh.TimeDateStamp
    try:
        ts_txt = _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "0 (não definido)"
    except (OverflowError, OSError, ValueError):
        ts_txt = str(ts)
    machine = pefile.MACHINE_TYPE.get(fh.Machine, hex(fh.Machine))
    subsystem = pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, str(oh.Subsystem))
    info.update({
        "arquitetura": "64 bits" if is64 else "32 bits",
        "máquina": str(machine).replace("IMAGE_FILE_MACHINE_", ""),
        "tipo": "DLL" if is_dll else "Executável",
        ".NET": "Sim" if is_dotnet else "Não",
        "subsistema": str(subsystem).replace("IMAGE_SUBSYSTEM_", ""),
        "compilado em": ts_txt,
        "ponto de entrada": hex(oh.AddressOfEntryPoint),
        "image base": hex(oh.ImageBase),
        "seções": fh.NumberOfSections,
    })

    # ----------------------------------------------------------- seções
    sections = []
    ep = oh.AddressOfEntryPoint
    ep_section = None
    packers = set()
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        raw = s.get_data()
        ent = util.entropy(raw) if raw else 0.0
        ch = s.Characteristics
        flags = ("R" if ch & 0x40000000 else "-") + ("W" if ch & SCN_WRITE else "-") + ("X" if ch & SCN_EXEC else "-")
        sec = {"nome": name, "endereço virtual": hex(s.VirtualAddress), "tamanho virtual": s.Misc_VirtualSize,
               "tamanho bruto": s.SizeOfRawData, "entropia": round(ent, 3), "permissões": flags}
        sections.append(sec)
        low = name.lower().strip()
        if low in PACKER_SECTIONS:
            packers.add(PACKER_SECTIONS[low])
        if s.VirtualAddress <= ep < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            ep_section = (name, ch, s)
        if ch & SCN_EXEC and ch & SCN_WRITE:
            inds.append(_ind("pe.wx_section", f"Seção gravável e executável ({name})", "Estrutura",
                             "Uma seção com permissão de escrita E execução permite código que se modifica "
                             "sozinho — típico de empacotadores e malware que se descriptografa na memória.",
                             15, "media", [f"{name}: {flags}"], "Heur.Packed"))
        if ch & SCN_EXEC and ent > 7.2 and s.SizeOfRawData > 4096:
            inds.append(_ind("pe.high_entropy_code", f"Código criptografado/compactado ({name})", "Ofuscação",
                             "A seção de código tem entropia muito alta, indicando que o código real está "
                             "criptografado ou compactado para esconder sua função.",
                             15, "media", [f"{name}: entropia {ent:.2f}"], "Heur.Packed"))
        if ch & SCN_EXEC and s.SizeOfRawData == 0 and s.Misc_VirtualSize > 0x10000:
            inds.append(_ind("pe.empty_exec", f"Seção executável vazia no disco ({name})", "Ofuscação",
                             "Seção executável sem conteúdo em disco mas grande na memória: será preenchida por "
                             "um desempacotador em tempo de execução.", 10, "baixa",
                             [f"{name}: virtual {s.Misc_VirtualSize} / bruto 0"], "Heur.Packed"))
    info["_sections"] = sections

    if packers:
        prot = packers & PROTECTORS
        if prot:
            inds.append(_ind("pe.protector", f"Protegido com {', '.join(sorted(prot))}", "Ofuscação",
                             "O executável foi blindado com um protetor comercial que impede análise. "
                             "Muito usado por malware (e por alguns jogos/softwares pirateados).",
                             20, "media", sorted(prot), "Heur.Protected"))
        else:
            inds.append(_ind("pe.packer", f"Empacotado com {', '.join(sorted(packers))}", "Ofuscação",
                             "O executável está comprimido por um empacotador, o que esconde seu código real "
                             "de análises estáticas.", 12, "baixa", sorted(packers), "Heur.Packed"))
    info["empacotador"] = ", ".join(sorted(packers)) or "Nenhum detectado"

    if pe.sections:
        if ep_section is None and ep != 0 and not is_dll:
            inds.append(_ind("pe.ep_outside", "Ponto de entrada fora das seções", "Estrutura",
                             "O código começa a executar fora de qualquer seção declarada — técnica de "
                             "ofuscação para confundir antivírus.", 20, "alta", [hex(ep)], "Heur.Malformed"))
        elif ep_section is not None:
            name, ch, sec = ep_section
            last = pe.sections[-1]
            if ch & SCN_WRITE and ch & SCN_EXEC:
                pass  # já pontuado como W+X
            elif not ch & SCN_EXEC and not ch & SCN_CODE:
                inds.append(_ind("pe.ep_nonexec", f"Ponto de entrada em seção não executável ({name})", "Estrutura",
                                 "O programa começa a rodar em uma seção marcada como dados, um forte sinal "
                                 "de manipulação.", 20, "alta", [name], "Heur.Malformed"))
            if sec is last and len(pe.sections) > 2 and name.lower() not in (".text", "code", ".code"):
                inds.append(_ind("pe.ep_last", f"Execução começa na última seção ({name})", "Estrutura",
                                 "Vírus que infectam executáveis costumam anexar seu código na última seção e "
                                 "desviar o ponto de entrada para lá.", 15, "media", [name], "Heur.Infector"))
        info["seção do ponto de entrada"] = ep_section[0] if ep_section else "(nenhuma)"

    # ----------------------------------------------------------- importações
    imports: dict[str, list[str]] = {}
    api_set: set[str] = set()
    total_funcs = 0
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("latin-1", "replace") if entry.dll else "?"
        funcs = []
        for imp in entry.imports:
            if imp.name:
                n = imp.name.decode("latin-1", "replace")
                funcs.append(n)
                api_set.add(_norm_api(n))
            else:
                funcs.append(f"ordinal #{imp.ordinal}")
            total_funcs += 1
        imports[dll] = funcs
    info["_imports"] = imports
    info["total de importações"] = total_funcs

    exports = []
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp is not None:
        for s in exp.symbols[:2000]:
            exports.append(s.name.decode("latin-1", "replace") if s.name else f"ordinal #{s.ordinal}")
    info["_exports"] = exports

    def has(group: str) -> set[str]:
        return api_set & API_GROUPS[group]

    suspicious_apis: dict[str, list[str]] = {}
    inj = has("injection")
    if {"writeprocessmemory", "ntwritevirtualmemory", "zwwritevirtualmemory"} & inj and \
            ({"createremotethread", "createremotethreadex", "ntcreatethreadex", "rtlcreateuserthread",
              "queueuserapc", "ntqueueapcthread"} & inj):
        suspicious_apis["Injeção de código"] = sorted(inj)
        inds.append(_ind("pe.api_injection", "Injeção de código em outros processos", "Injeção",
                         "Importa funções para escrever na memória de outro processo e criar uma thread lá "
                         "(WriteProcessMemory + CreateRemoteThread/APC). É assim que malware se esconde dentro "
                         "de processos legítimos.", 40, "alta", sorted(inj), "Trojan.Injector"))
    hol = has("hollowing")
    if ({"ntunmapviewofsection", "zwunmapviewofsection"} & hol) and \
            ({"setthreadcontext", "wow64setthreadcontext"} & hol) and "resumethread" in hol:
        suspicious_apis["Process hollowing"] = sorted(hol)
        inds.append(_ind("pe.api_hollowing", "Process hollowing (esvaziamento de processo)", "Injeção",
                         "Cria um processo legítimo suspenso, remove seu código e coloca o malware no lugar "
                         "(NtUnmapViewOfSection + SetThreadContext + ResumeThread).", 45, "critica",
                         sorted(hol), "Trojan.Hollowing"))
    kl = has("keylog")
    if "setwindowshookex" in kl and ({"getasynckeystate", "getkeyboardstate", "mapvirtualkey"} & kl) or \
            ("getasynckeystate" in kl and "getforegroundwindow" in kl and "getwindowtext" in kl):
        suspicious_apis["Captura de teclado"] = sorted(kl)
        inds.append(_ind("pe.api_keylogger", "Captura de teclas digitadas", "Espionagem",
                         "Combina ganchos de teclado/leitura de teclas com identificação da janela ativa — "
                         "comportamento de keylogger.", 25, "media", sorted(kl), "Spyware.Keylogger"))
    dl, ex = has("download"), has("exec")
    if ({"urldownloadtofile", "urlopenblockingstream"} & dl) and ex:
        suspicious_apis["Download e execução"] = sorted(dl | ex)
        inds.append(_ind("pe.api_downloader", "Baixa e executa arquivos", "Downloader",
                         "Usa URLDownloadToFile e funções de execução: o padrão clássico de um downloader, que "
                         "baixa e roda outros malwares.", 25, "media", sorted(dl | ex), "Trojan.Downloader"))
    ad = has("antidebug") - {"isdebuggerpresent", "outputdebugstring"}
    if len(ad) >= 2:
        suspicious_apis["Antidepuração"] = sorted(ad)
        inds.append(_ind("pe.api_antidebug", "Técnicas antidepuração", "Evasão de defesa",
                         "Verifica se está sendo analisado por um depurador para mudar seu comportamento.",
                         8, "baixa", sorted(ad), "Heur.AntiDebug"))
    if has("privilege") >= {"adjusttokenprivileges", "lookupprivilegevalue"} and b"SeDebugPrivilege" in data:
        suspicious_apis["Elevação de privilégios"] = sorted(has("privilege"))
        inds.append(_ind("pe.sedebug", "Solicita privilégio de depuração (SeDebugPrivilege)", "Elevação de privilégio",
                         "Habilita SeDebugPrivilege, que permite abrir e manipular qualquer processo do sistema "
                         "(inclusive ler senhas do LSASS).", 15, "media", ["SeDebugPrivilege"], "Heur.Privilege"))

    low = data.lower() if len(data) < 64 * 1024 * 1024 else data[:64 * 1024 * 1024].lower()
    ext_hits = [e.decode() for e in DOC_EXTENSIONS if e + b"\x00" in low or e + b"\"" in low or e + b"," in low
                or e.replace(b".", b".\x00") in low]
    cr, fe, fw = has("crypto"), has("fileenum"), has("filewrite")
    if cr and fe and fw:
        w = 35 if len(ext_hits) >= 15 else 12
        suspicious_apis["Criptografia em massa de arquivos"] = sorted(cr | fe | fw)
        inds.append(_ind("pe.ransom_combo", "Percorre e criptografa arquivos", "Ransomware",
                         "Combina varredura de pastas (FindFirstFile/FindNextFile), criptografia e escrita de "
                         "arquivos" + (f", com uma lista de {len(ext_hits)} extensões de documentos-alvo" if len(ext_hits) >= 15 else "")
                         + " — o núcleo de um ransomware.", w, "alta" if w > 20 else "media",
                         sorted(cr) + ext_hits[:10], "Ransom.Generic"))
    av_hits = [p.decode() for p in AV_PROCESSES if p in low]
    if len(av_hits) >= 4:
        inds.append(_ind("pe.av_killer", "Lista de processos de antivírus/análise", "Evasão de defesa",
                         "Contém nomes de vários processos de antivírus e ferramentas de análise, geralmente "
                         "para encerrá-los ou detectar que está sendo investigado.",
                         35 if has("terminate") else 20, "alta", av_hits[:12], "Trojan.AVKiller"))
    if "setclipboarddata" in api_set and re.search(
            rb"\(bc1\|\[13\]\)|\^\(?bc1|\[13\]\[a-km-zA-HJ-NP-Z1-9\]|0x\[a-fA-F0-9\]\{40\}|\^4\[0-9AB\]", data):
        inds.append(_ind("pe.clipper", "Troca endereços de carteira na área de transferência", "Roubo financeiro",
                         "Monitora a área de transferência procurando endereços de criptomoedas para trocá-los pelo "
                         "endereço do criminoso (clipper).", 45, "alta", ["SetClipboardData", "regex de carteira"],
                         "Stealer.Clipper"))

    if not is_dotnet:
        if total_funcs == 0 and not is_dll:
            inds.append(_ind("pe.no_imports", "Nenhuma função importada", "Ofuscação",
                             "Executáveis normais importam funções do Windows. A ausência total indica que as "
                             "importações são resolvidas de forma escondida (shellcode/empacotador).",
                             15, "media", [], "Heur.Packed"))
        elif 0 < total_funcs <= 8 and has("dynamic") and not is_dll:
            inds.append(_ind("pe.min_imports", "Importações mínimas com resolução dinâmica", "Ofuscação",
                             "Importa apenas LoadLibrary/GetProcAddress e quase nada mais: as funções reais são "
                             "carregadas escondidas em tempo de execução.", 15, "media",
                             sorted(has("dynamic")), "Heur.Packed"))
    info["_suspicious_apis"] = suspicious_apis

    # ----------------------------------------------------------- recursos, overlay, TLS
    try:
        if ts and ts > time.time() + 86400 * 2:
            inds.append(_ind("pe.future_ts", "Data de compilação no futuro", "Estrutura",
                             "A data de compilação foi falsificada para uma data futura.", 5, "baixa", [ts_txt],
                             "Heur.Malformed"))
    except (OverflowError, ValueError):
        pass
    if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        info["callbacks TLS"] = "Sim"

    embedded = 0
    res_list = []
    rsrc = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if rsrc is not None:
        try:
            for t in rsrc.entries[:64]:
                tname = pefile.RESOURCE_TYPE.get(t.id, str(t.name) if t.name else str(t.id))
                for e in getattr(t, "directory", None).entries[:256] if getattr(t, "directory", None) else []:
                    for lang in e.directory.entries[:8] if getattr(e, "directory", None) else []:
                        d = lang.data.struct
                        res_list.append((str(tname).replace("RT_", ""), d.Size))
                        head = pe.get_data(d.OffsetToData, min(d.Size, 1024))
                        if head[:2] == b"MZ" and b"PE\x00\x00" in head[:1024]:
                            embedded += 1
        except Exception:
            pass
    if embedded:
        inds.append(_ind("pe.embedded_pe", "Outro executável escondido nos recursos", "Dropper",
                         "O programa carrega outro executável dentro dos seus recursos, que pode ser extraído e "
                         "executado (comportamento de dropper).", 15, "media", [f"{embedded} executável(is)"],
                         "Trojan.Dropper"))
    info["_resources"] = res_list[:300]

    overlay_off = pe.get_overlay_data_start_offset()
    if overlay_off:
        ov = data[overlay_off:]
        info["overlay"] = f"{util.human_size(len(ov))} a partir de {hex(overlay_off)} (entropia {util.entropy(ov[:1 << 20]):.2f})"
        if ov[:2] == b"MZ" and b"PE\x00\x00" in ov[:1024]:
            inds.append(_ind("pe.overlay_pe", "Executável anexado ao final do arquivo", "Dropper",
                             "Há um segundo executável colado após o fim do primeiro.", 15, "media",
                             [hex(overlay_off)], "Trojan.Dropper"))

    # ----------------------------------------------------------- versão e assinatura
    sec_dir = oh.DATA_DIRECTORY[4] if len(oh.DATA_DIRECTORY) > 4 else None
    signed = bool(sec_dir and sec_dir.VirtualAddress and sec_dir.Size)
    info["assinatura embutida"] = "Presente" if signed else "Ausente"
    if signed:
        blob = data[sec_dir.VirtualAddress:sec_dir.VirtualAddress + min(sec_dir.Size, 65536)]
        cn = _cert_names(blob)
        info["certificados"] = ", ".join(cn[:6]) or "(não identificados)"
        info["_signers"] = cn

    version = {}
    try:
        for fi in getattr(pe, "FileInfo", []) or []:
            for entry in fi:
                for st in getattr(entry, "StringTable", []) or []:
                    for k, v in st.entries.items():
                        version[k.decode("latin-1", "replace")] = v.decode("latin-1", "replace")
    except Exception:
        pass
    info["_version"] = version
    company = version.get("CompanyName", "").lower()
    if "microsoft" in company and not signed:
        inds.append(_ind("pe.fake_ms", "Diz ser da Microsoft sem assinatura embutida", "Disfarce",
                         "As informações de versão afirmam que o arquivo é da Microsoft, mas ele não tem "
                         "assinatura digital embutida. Malware frequentemente finge ser um componente do Windows. "
                         "(Arquivos genuínos do Windows são verificados pelo catálogo do sistema.)",
                         20, "media", [version.get("CompanyName", ""), version.get("OriginalFilename", "")],
                         "Trojan.Masquerade"))
    if is_dotnet:
        for marker, nm in ((b"ConfusedByAttribute", "ConfuserEx"), (b"SmartAssembly.Attributes", "SmartAssembly"),
                           (b"DotfuscatorAttribute", "Dotfuscator"), (b"BabelObfuscatorAttribute", "Babel"),
                           (b"Eazfuscator", "Eazfuscator"), (b"de4dot", "de4dot")):
            if marker in data:
                inds.append(_ind("pe.net_obfuscator", f"Código .NET ofuscado ({nm})", "Ofuscação",
                                 "O código .NET foi ofuscado para dificultar a leitura.", 10, "baixa", [nm],
                                 "Heur.Obfuscated"))
                break
    pe.close()
    return inds, info
