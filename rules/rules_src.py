"""Fonte legível das regras de detecção por CONTEÚDO.

NÃO é empacotado com o programa. O script tools/build_rules.py converte esta
lista em exeav/data/rules.bin (compactado + ofuscado), para que o executável
final não carregue strings maliciosas em texto puro (evita falsos positivos de
outros antivírus e impede que o programa se detecte).

Formato de cada regra:
  id, name, category, family, severity, weight, targets, description
  all:  padrões que TODOS precisam aparecer
  any:  padrões dos quais pelo menos `min` (padrão 1) precisam aparecer
Padrões são expressões regulares sobre bytes (sem diferenciar maiúsculas),
ou "hex:..." para sequências exatas de bytes.

Alvos (targets): pe, elf, macho, script, html, macro, pdf, rtf, lnk, any
"""

RULES = [
    # ------------------------------------------------------------------ genéricas
    dict(id="test.eicar", name="Arquivo de teste EICAR", category="Teste",
         family="EICAR-Test-File", severity="critica", weight=100, targets=["any"],
         description="Assinatura padrão EICAR, usada mundialmente para testar antivírus. É inofensiva, "
                     "mas todo antivírus deve detectá-la.",
         all=["hex:58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a"]),

    dict(id="ransom.shadow_delete", bonus=True, name="Exclusão de cópias de sombra (Shadow Copies)",
         category="Ransomware", family="Ransom.ShadowWiper", severity="critica", weight=60, targets=["any"],
         description="Apaga as cópias de sombra do Windows, impedindo a restauração de arquivos. "
                     "É o primeiro passo de praticamente todo ransomware moderno.",
         any=[r"vssadmin(?:\.exe)?[\"'\s]+delete\s+shadows", r"wmic(?:\.exe)?[\"'\s]+shadowcopy\s+delete",
              r"win32_shadowcopy[^\n]{0,80}(?:delete|remove-wmiobject|\.delete\(\))",
              r"vssadmin(?:\.exe)?[\"'\s]+resize\s+shadowstorage[^\n]{0,60}maxsize=\s*401\s*mb"]),

    dict(id="ransom.recovery_off", bonus=True, name="Desativa a recuperação do sistema",
         category="Ransomware", family="Ransom.RecoveryKiller", severity="alta", weight=40, targets=["any"],
         description="Desativa o modo de recuperação do Windows ou apaga backups (bcdedit / wbadmin).",
         any=[r"bcdedit(?:\.exe)?[^\n]{0,40}recoveryenabled\s+no", r"bcdedit(?:\.exe)?[^\n]{0,40}bootstatuspolicy\s+ignoreallfailures",
              r"wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup|backup)"]),

    dict(id="ransom.note_binary", name="Nota de resgate embutida",
         category="Ransomware", family="Ransom.Generic", severity="alta", weight=45,
         targets=["pe", "elf", "macho", "script"],
         description="Contém textos típicos de nota de resgate: arquivos criptografados, pagamento e "
                     "instruções de descriptografia.",
         any=[r"(?:all\s+)?(?:of\s+)?your\s+(?:important\s+)?(?:files|documents|data)\s+(?:have\s+been|are|were|has\s+been)\s+(?:encrypted|locked)",
              r"seus\s+arquivos\s+(?:foram|est[aã]o)\s+(?:criptografados|bloqueados)",
              r"(?:decrypt(?:ion)?\s+(?:key|tool|software|program)|to\s+decrypt\s+(?:your\s+)?files)",
              r"(?:pay|send|transfer)[^\n]{0,60}(?:bitcoin|btc|monero|xmr)",
              r"(?<![a-z0-9])(?=[a-z2-7]*[2-7])(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion\b",
              r"do\s+not\s+(?:try\s+to\s+)?(?:rename|modify|delete)\s+(?:the\s+)?encrypted\s+files"],
         min=2),

    dict(id="miner.stratum", name="Minerador de criptomoedas",
         category="Minerador", family="CoinMiner", severity="alta", weight=60, targets=["any"],
         description="Contém endereço de pool de mineração (stratum) e parâmetros de minerador, usado "
                     "para minerar criptomoedas com o seu hardware sem permissão.",
         any=[r"stratum\+(?:tcp|ssl|tls)://", r"--donate-level", r"\bcryptonight\b", r"\brandomx\b",
              r"\bxmrig\b", r"(?:supportxmr|minexmr|nanopool|hashvault|moneroocean|nicehash|c3pool|f2pool)\.(?:com|org|pro|net|stream)",
              r"--cpu-max-threads-hint", r"\"(?:pools|coin)\"\s*:\s*[\[\"]"],
         min=2),

    dict(id="cred.mimikatz", name="Ferramenta de roubo de credenciais (Mimikatz)",
         category="Roubo de credenciais", family="HackTool.Mimikatz", severity="critica", weight=80,
         targets=["any"],
         description="Comandos do Mimikatz para extrair senhas e hashes da memória do Windows (LSASS).",
         any=[r"sekurlsa::(?:logonpasswords|wdigest|pth|tickets)", r"lsadump::(?:sam|dcsync|secrets|lsa)",
              r"kerberos::(?:golden|ptt)", r"privilege::debug", r"gentilkiwi"],
         min=2),

    dict(id="cred.lsass_dump", bonus=True, name="Despejo de memória do LSASS",
         category="Roubo de credenciais", family="HackTool.LsassDump", severity="alta", weight=50,
         targets=["any"],
         description="Usa comsvcs.dll MiniDump / procdump para copiar a memória do processo LSASS, que "
                     "contém senhas do Windows.",
         any=[r"comsvcs(?:\.dll)?[\"',\s#]+(?:minidump|#24)", r"procdump(?:64)?(?:\.exe)?[^\n]{0,40}-ma\s+lsass",
              r"minidumpwritedump[^\n]{0,200}lsass|lsass[^\n]{0,200}minidumpwritedump"]),

    dict(id="steal.browser", name="Acesso aos dados de senha dos navegadores",
         category="Roubo de credenciais", family="Stealer.Browser", severity="media", weight=20,
         targets=["pe", "script", "elf"],
         description="Lê os bancos de senhas/cookies dos navegadores e a chave de criptografia (encrypted_key).",
         any=[r"\\login data|/login data", r"encrypted_key", r"\\local state|/local state",
              r"\\cookies\b|/cookies\b", r"cryptunprotectdata"], min=4),

    dict(id="steal.wallets", name="Roubo de carteiras de criptomoedas e sessões",
         category="Roubo de credenciais", family="Stealer.Wallet", severity="alta", weight=45,
         targets=["pe", "script", "elf"],
         description="Procura carteiras de criptomoedas e sessões do Telegram/Discord, comportamento "
                     "típico de infostealers (RedLine, Raccoon, Lumma...).",
         any=[r"wallet\.dat", r"telegram desktop[\\/]tdata", r"discord[\\/]local storage[\\/]leveldb",
              r"\\exodus\\|/exodus/", r"electrum[\\/]wallets", r"nkbihfbeogaeaoehlefnkodbefgpgknn",
              r"\\coinomi\\|/coinomi/", r"atomic[\\/]local storage", r"\\jaxx\\", r"ledger live"], min=2),

    dict(id="exfil.webhook", name="Envio de dados para webhook/bot",
         category="Exfiltração", family="Exfil.Webhook", severity="media", weight=25,
         targets=["any"],
         description="Envia dados para webhooks do Discord ou bots do Telegram, canal comum de "
                     "exfiltração usado por stealers e keyloggers.",
         any=[r"discord(?:app)?\.com/api/webhooks/\d+", r"api\.telegram\.org/bot\d+:"]),

    dict(id="evasion.defender", bonus=True, name="Desativa o Windows Defender",
         category="Evasão de defesa", family="Trojan.DefenderKiller", severity="critica", weight=55,
         targets=["any"],
         description="Desliga a proteção em tempo real do Windows Defender ou cria exclusões para "
                     "esconder o malware.",
         any=[r"set-mppreference[^\n]{0,80}-disable(?:realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning)\s+(?:\$true|1)",
              r"disablerealtimemonitoring[^\n]{0,30}(?:\$true|\b1\b|dword:0*1)",
              r"windows defender\\(?:exclusions|real-time protection)",
              r"\bdisableantispyware\b[^\n]{0,40}(?:\b1\b|dword:0*1|\$true)"]),

    dict(id="evasion.defender_exclusion", bonus=True, name="Exclui pastas inteiras da verificação do Defender",
         category="Evasão de defesa", family="Trojan.DefenderKiller", severity="alta", weight=40, targets=["any"],
         description="Cria exclusões amplas no Windows Defender (unidade inteira, Temp, AppData, perfil do usuário) "
                     "para que o malware possa ficar ali sem ser verificado.",
         any=[r"add-mppreference[^\n]{0,40}-exclusion(?:path|process)\s+[\"']?(?:[a-z]:\\?[\"']?(?:\s|$|;)|\$env:(?:temp|tmp|appdata|localappdata|userprofile|programdata)|c:\\users\\[^\\\n]{1,40}\\appdata)",
              r"add-mppreference[^\n]{0,40}-exclusionextension\s+[\"']?\.?(?:exe|dll|ps1|bat|vbs|js)\b",
              r"windows defender\\exclusions\\paths[^\n]{0,60}(?:[a-z]:\\\s|\\appdata|\\temp)"]),

    dict(id="net.raw_ip_download", name="Download direto de endereço IP",
         category="Downloader", family="Trojan.Downloader", severity="media", weight=20,
         targets=["script", "html", "macro", "lnk"],
         description="Baixa conteúdo de um endereço IP numérico em vez de um site com nome — servidores de "
                     "malware frequentemente não têm domínio.",
         any=[r"(?:downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|net\.webclient|start-bitstransfer|\bcurl\b|\bwget\b|xmlhttp|winhttp|urldownloadtofile|bitsadmin|certutil|fetch\s*\(|\.open\s*\(\s*[\"']get)[^\n]{0,200}(?:https?|ftp)://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?/",
              r"(?:https?|ftp)://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?/[^\s'\"]{0,200}[^\n]{0,60}\|\s*(?:iex|invoke-expression|(?:ba)?sh\b)"]),

    dict(id="evasion.uac_bypass", bonus=True, name="Contorno do Controle de Conta (UAC bypass)",
         category="Elevação de privilégio", family="Trojan.UACBypass", severity="alta", weight=55,
         targets=["any"],
         description="Sequestra chaves de registro usadas por fodhelper/eventvwr/sdclt para executar "
                     "código como administrador sem o aviso do UAC.",
         any=[r"ms-settings\\shell\\open\\command", r"mscfile\\shell\\open\\command",
              r"folder\\shell\\open\\command[^\n]{0,80}delegateexecute|delegateexecute[^\n]{0,80}folder\\shell",
              r"exefile\\shell\\runas\\command\\isolatedcommand"]),

    dict(id="evasion.log_clear", bonus=True, name="Apaga logs de eventos",
         category="Evasão de defesa", family="Trojan.LogWiper", severity="media", weight=25,
         targets=["any"],
         description="Limpa os logs de eventos do Windows para apagar rastros.",
         any=[r"wevtutil(?:\.exe)?[\"'\s]+(?:cl|clear-log)\s", r"clear-eventlog\s", r"remove-eventlog\s"]),

    dict(id="evasion.antivm", name="Detecção de máquina virtual / sandbox",
         category="Evasão de defesa", family="Trojan.AntiVM", severity="baixa", weight=15,
         targets=["pe", "elf", "script"],
         description="Verifica se está rodando em VirtualBox/VMware/sandbox para esconder seu comportamento "
                     "de analistas.",
         any=[r"vboxservice", r"vboxtray", r"vmtoolsd", r"sbiedll\.dll", r"hardware\\acpi\\dsdt\\vbox__",
              r"wine_get_unix_file_name", r"\bvmware\b", r"cuckoomon", r"\bqemu\b", r"\\\\\.\\vboxguest",
              r"sandboxie", r"dbghelp\.dll[^\n]{0,40}api_log"], min=3),

    dict(id="persist.run_key", name="Persistência via chave Run do registro",
         category="Persistência", family="Trojan.Persist", severity="baixa", weight=12, targets=["pe", "script", "macro"],
         description="Grava em Software\\Microsoft\\Windows\\CurrentVersion\\Run para iniciar junto com o Windows.",
         any=[r"software\\microsoft\\windows\\currentversion\\run(?:once)?\b"]),

    dict(id="persist.winlogon", name="Sequestro do Winlogon / IFEO",
         category="Persistência", family="Trojan.Persist", severity="alta", weight=35, targets=["any"],
         description="Altera Winlogon (Userinit/Shell) ou Image File Execution Options (Debugger), técnicas "
                     "usadas para executar malware no logon ou no lugar de outros programas.",
         any=[r"winlogon[\"'\\\s]+(?:userinit|shell)\b[^\n]{0,80}(?:,|\.exe)",
              r"image file execution options\\[^\n]{1,80}[\"'\\\s]+debugger"]),

    dict(id="persist.schtask", name="Tarefa agendada oculta",
         category="Persistência", family="Trojan.Persist", severity="media", weight=20, targets=["any"],
         description="Cria tarefa agendada no logon/minuto que executa PowerShell/CMD oculto.",
         all=[r"schtasks(?:\.exe)?[\"'\s]+/create"],
         any=[r"/sc\s+(?:onlogon|minute|onstart)", r"-w(?:indowstyle)?\s+hidden", r"/rl\s+highest"], min=2),

    dict(id="persist.startup_folder", name="Cópia para a pasta Inicializar",
         category="Persistência", family="Trojan.Persist", severity="media", weight=25,
         targets=["script", "macro", "html", "pe"],
         description="Copia arquivos para a pasta Inicializar do usuário para rodar a cada logon.",
         all=[r"(?:copyfile|copyhere|copy-item|\.copy\b|copy\s|movefile|\bxcopy\b)"],
         any=[r"start menu\\programs\\startup", r"specialfolders\([\"']startup", r"shell:startup",
              r"\[environment\]::getfolderpath\([\"']?startup"]),

    dict(id="spy.keylog_strings", name="Marcadores de teclas de keylogger",
         category="Espionagem", family="Spyware.Keylogger", severity="alta", weight=40,
         targets=["pe", "script", "elf"],
         description="Contém marcadores como [BACKSPACE], [ENTER], [CAPSLOCK] usados para registrar tudo "
                     "o que é digitado.",
         any=[r"\[backspace\]", r"\[enter\]", r"\[caps ?lock\]", r"\[shift\]", r"\[tab\]", r"\[ctrl\]",
              r"\[esc\]", r"\[del(?:ete)?\]", r"\[left\]|\[right\]"], min=4),

    dict(id="spy.screen_webcam", name="Captura de tela/webcam com envio remoto",
         category="Espionagem", family="Spyware.Capture", severity="media", weight=20,
         targets=["script"],
         description="Captura tela ou webcam e envia o resultado pela rede.",
         any=[r"imagegrab\.grab|pyautogui\.screenshot|copyfromscreen|mss\(\)\.grab",
              r"cv2\.videocapture\(0\)", r"requests\.post|smtplib|webhook|ftplib|sendfile"], min=2),

    dict(id="pe.self_delete", name="Autoexclusão após execução",
         category="Evasão de defesa", family="Trojan.SelfDelete", severity="media", weight=25,
         targets=["pe", "script"],
         description="Apaga o próprio executável depois de rodar (ping/choice + del), escondendo vestígios.",
         any=[r"/c\s+ping\s+(?:127\.0\.0\.1|localhost|1\.1\.1\.1)\s+-n\s+\d+[^\n]{0,20}&\s*del\s",
              r"choice\s+/c\s+y\s+/n\s+/d\s+y\s+/t\s+\d+\s*&\s*del\s", r"timeout\s+/t\s+\d+[^\n]{0,20}&\s*del\s+[\"']?%"]),

    dict(id="lolbin.certutil", bonus=True, name="Download via certutil/bitsadmin",
         category="Downloader", family="Trojan.Downloader", severity="alta", weight=45, targets=["any"],
         description="Usa ferramentas legítimas do Windows (certutil, bitsadmin) para baixar arquivos da "
                     "internet sem chamar atenção.",
         any=[r"certutil(?:\.exe)?[^\n]{0,30}-urlcache[^\n]{0,20}-f\s", r"certutil(?:\.exe)?[^\n]{0,30}-(?:verifyctl|ping)[^\n]{0,30}https?:",
              r"bitsadmin(?:\.exe)?[^\n]{0,30}/transfer[^\n]{0,200}https?://"]),

    dict(id="lolbin.proxyexec", bonus=True, name="Execução indireta por binários do sistema",
         category="Downloader", family="Trojan.LOLBin", severity="alta", weight=50, targets=["any"],
         description="Executa código remoto via mshta, regsvr32 (Squiblydoo) ou rundll32 javascript.",
         any=[r"mshta(?:\.exe)?[\"'\s]+(?:https?://|vbscript:|javascript:)",
              r"regsvr32(?:\.exe)?[^\n]{0,40}/i:\s*https?://", r"rundll32(?:\.exe)?[^\n]{0,40}javascript:",
              r"rundll32(?:\.exe)?[^\n]{0,40}url\.dll,\s*(?:openurl|fileprotocolhandler)[^\n]{0,20}https?:"]),

    dict(id="cmd.add_admin", name="Cria usuário administrador",
         category="Elevação de privilégio", family="Trojan.Backdoor", severity="alta", weight=40,
         targets=["any"],
         description="Cria uma conta de usuário e a adiciona ao grupo de administradores (porta dos fundos).",
         all=[r"net(?:1)?(?:\.exe)?\s+user\s+\S+\s+\S+\s+/add", r"net(?:1)?(?:\.exe)?\s+localgroup\s+administ"]),

    dict(id="cmd.firewall_off", name="Desativa o firewall",
         category="Evasão de defesa", family="Trojan.FirewallOff", severity="media", weight=30, targets=["any"],
         description="Desliga o firewall do sistema.",
         any=[r"netsh(?:\.exe)?\s+(?:adv)?firewall\s+set\s+\w*\s*(?:opmode|state)\s+(?:disable|off)",
              r"set-netfirewallprofile[^\n]{0,60}-enabled\s+(?:false|0)", r"\bufw\s+disable\b",
              r"systemctl\s+(?:stop|disable)\s+(?:firewalld|ufw)\b", r"\biptables\s+-F\b"]),

    # ------------------------------------------------------------------ PowerShell
    dict(id="ps.encoded", name="PowerShell com comando codificado (-EncodedCommand)",
         category="Ofuscação", family="PowerShell.Obfuscated", severity="alta", weight=35,
         targets=["script", "html", "macro", "lnk", "pe", "pdf"],
         description="Executa PowerShell com o comando escondido em Base64, técnica clássica de malware "
                     "para esconder o que está sendo executado.",
         any=[r"(?:powershell|pwsh)(?:\.exe)?[\"']?[^\n]{0,120}\s[-/]e(?:nc?|ncodedcommand|ncodedc|ncoded|ncode)?\s+[a-z0-9+/=]{24,}"]),

    dict(id="ps.download_exec", name="Baixa e executa código da internet (PowerShell)",
         category="Downloader", family="PowerShell.Downloader", severity="alta", weight=30,
         targets=["script", "html", "macro", "lnk", "pe", "pdf"],
         description="Baixa conteúdo da internet e o executa diretamente na memória (IEX + DownloadString). "
                     "Também é usado por instaladores legítimos (ex.: 'irm https://... | iex'), por isso pesa "
                     "mais quando a origem é insegura, ofuscada ou combinada com outras técnicas.",
         all=[r"\biex\b|invoke-expression|\.invoke\(\)"],
         any=[r"downloadstring|downloaddata|downloadfile", r"invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b",
              r"net\.webclient", r"start-bitstransfer", r"system\.net\.http"]),

    dict(id="ps.download_exec_insecure", name="Executa código baixado de origem insegura",
         category="Downloader", family="PowerShell.Downloader", severity="alta", weight=25,
         targets=["script", "html", "macro", "lnk", "pdf"],
         description="O código executado vem por HTTP sem criptografia ou de um endereço IP direto — "
                     "instaladores legítimos usam HTTPS com o domínio do fabricante.",
         all=[r"\biex\b|invoke-expression|\.invoke\(\)"],
         any=[r"(?:downloadstring|downloaddata|downloadfile|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|net\.webclient|start-bitstransfer)[^\n]{0,200}(?:http://(?!localhost|127\.)|https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"]),

    dict(id="net.paste_site", name="Baixa de site de compartilhamento usado por malware",
         category="Downloader", family="Trojan.Downloader", severity="alta", weight=25,
         targets=["script", "html", "macro", "lnk", "pe"],
         description="Busca conteúdo em serviços de colagem/compartilhamento anônimo (pastebin, transfer.sh, "
                     "anexos do Discord, túneis ngrok...), muito usados para hospedar o estágio seguinte de malware.",
         any=[r"pastebin\.com/raw|paste\.ee/r/|hastebin\.com/raw|rentry\.co/[^\s'\"]{1,40}/raw|ghostbin",
              r"transfer\.sh/|temp\.sh/|file\.io/|anonfiles\.com|gofile\.io/d|catbox\.moe/",
              r"cdn\.discordapp\.com/attachments/[^\s'\"]{10,200}\.(?:exe|dll|scr|ps1|bat|vbs|zip|rar)",
              r"(?<![a-z0-9-])[a-z0-9-]{4,63}\.ngrok(?:-free)?\.(?:io|app)"]),

    dict(id="ps.hidden_bypass", name="PowerShell oculto contornando políticas",
         category="Evasão de defesa", family="PowerShell.Stealth", severity="media", weight=20,
         targets=["script", "html", "macro", "lnk", "pe", "pdf"],
         description="Executa PowerShell em janela oculta, sem perfil e ignorando a política de execução.",
         all=[r"powershell|pwsh"],
         any=[r"\s-w(?:in(?:dowstyle)?)?\s+(?:hidden|1)\b", r"\s-ex(?:ec(?:utionpolicy)?)?\s+(?:bypass|unrestricted)\b",
              r"\s-nop(?:rofile)?\b", r"\s-noni(?:nteractive)?\b"], min=2),

    dict(id="ps.reflective_load", name="Carrega executável .NET na memória",
         category="Injeção", family="PowerShell.ReflectiveLoader", severity="alta", weight=50,
         targets=["script", "html", "macro", "pe"],
         description="Decodifica Base64 e carrega um assembly diretamente na memória, sem gravar em disco "
                     "(técnica fileless).",
         all=[r"reflection\.assembly\]\s*::\s*load|\[system\.reflection\.assembly\]::load|assembly\]::load\(",
              r"frombase64string|\.downloaddata"]),

    dict(id="ps.amsi_bypass", name="Contorno do AMSI (antimalware do Windows)",
         category="Evasão de defesa", family="PowerShell.AMSIBypass", severity="critica", weight=70,
         targets=["any"],
         description="Desativa a interface antimalware (AMSI) do Windows para que scripts maliciosos não "
                     "sejam inspecionados.",
         any=[r"amsiutils", r"amsiinitfailed", r"amsiscanbuffer[^\n]{0,200}(?:virtualprotect|0x80070057|patch)",
              r"amsi\.dll[^\n]{0,120}getprocaddress[^\n]{0,120}amsiscanbuffer"]),

    dict(id="ps.shellcode", name="Execução de shellcode por script",
         category="Injeção", family="Script.ShellcodeRunner", severity="critica", weight=60,
         targets=["script", "html", "macro"],
         description="Aloca memória executável e cria uma thread nela (VirtualAlloc + CreateThread) a partir "
                     "de um script — carregamento de shellcode.",
         all=[r"virtualalloc", r"createthread|createremotethread|enumwindows|callwindowproc"],
         any=[r"marshal\]::copy|rtlmovememory|\[byte\[\]\]\s*\$|frombase64string",
              r"add-type|\[dllimport\(|declare\s+(?:ptrsafe\s+)?function|getdelegateforfunctionpointer"], min=2),

    dict(id="ps.compressed_payload", name="Carga compactada e codificada",
         category="Ofuscação", family="Script.Packed", severity="media", weight=30,
         targets=["script", "html", "macro"],
         description="Descompacta (GZip/Deflate) dados em Base64 para revelar o código real em tempo de execução.",
         all=[r"frombase64string|b64decode|base64_decode|atob\("],
         any=[r"io\.compression\.(?:gzipstream|deflatestream)", r"zlib\.decompress|gzip\.decompress",
              r"gzinflate|gzuncompress"]),

    dict(id="script.char_obfuscation", name="Ofuscação por códigos de caracteres",
         category="Ofuscação", family="Script.Obfuscated", severity="media", weight=25,
         targets=["script", "html", "macro"],
         description="Monta o código caractere por caractere (Chr/[char]/fromCharCode) para esconder "
                     "comandos de antivírus.",
         any=[r"(?:\[char\]\s*\(?\s*0?x?[0-9a-f]{1,3}\s*\)?\s*[+,]\s*){12,}",
              r"(?:chrw?\s*\(\s*\d{1,3}\s*(?:[+\-*]\s*\d+\s*)?\)\s*&\s*){12,}",
              r"fromcharcode\s*\(\s*(?:\d{1,3}\s*,\s*){20,}",
              r"(?:\w`){4,}\w", r"(?:\"[a-z]{1,3}\"\s*\+\s*){10,}"]),

    dict(id="script.keylog_api", name="Captura de teclado por script",
         category="Espionagem", family="Spyware.Keylogger", severity="alta", weight=35,
         targets=["script", "macro"],
         description="Usa GetAsyncKeyState / ganchos de teclado a partir de um script e grava ou envia o que foi digitado.",
         any=[r"(?:add-type|\[dllimport\(|ctypes\.windll|declare\s+(?:ptrsafe\s+)?function)[\s\S]{0,600}?(?:getasynckeystate|setwindowshookex)",
              r"(?:getasynckeystate|setwindowshookex)[\s\S]{0,600}?(?:add-type|\[dllimport\(|ctypes\.windll)",
              r"pynput\.keyboard[\s\S]{0,1200}?(?:smtplib|requests\.post|webhook|ftplib)"]),

    # ------------------------------------------------------------------ VBS / JS / HTML
    dict(id="vbs.downloader", name="Downloader em VBScript/JScript",
         category="Downloader", family="Script.Downloader", severity="alta", weight=50,
         targets=["script", "html", "macro"],
         description="Baixa arquivo via XMLHTTP e o grava/executa com ADODB.Stream ou WScript.Shell.",
         all=[r"(?:msxml2\.(?:server)?xmlhttp|microsoft\.xmlhttp|winhttp\.winhttprequest)",
              r"adodb\.stream|wscript\.shell|shell\.application"]),

    dict(id="vbs.download_exec", name="Baixa, grava e executa um arquivo (VBScript/JScript)",
         category="Downloader", family="Script.Dropper", severity="critica", weight=30,
         targets=["script", "html", "macro"],
         description="Faz o ciclo completo de um dropper: baixa um arquivo da internet, grava em disco e o executa.",
         all=[r"msxml2\.(?:server)?xmlhttp|microsoft\.xmlhttp|winhttp\.winhttprequest|urldownloadtofile",
              r"savetofile|\.write\s*\(?\s*\w+\.responsebody|createtextfile",
              r"\.run\b|shellexecute|\.exec\b|win32_process"]),

    dict(id="vbs.shell_run", name="Executa programas do sistema via WScript.Shell",
         category="Execução", family="Script.Exec", severity="media", weight=25,
         targets=["script", "html", "macro"],
         description="Usa WScript.Shell para executar PowerShell/CMD/MSHTA e outros programas do sistema.",
         all=[r"createobject\s*\(\s*[\"']wscript\.shell[\"']\s*\)"],
         any=[r"\.run\s*\(?\s*[\"']?(?:%comspec%|cmd|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|bitsadmin|certutil|schtasks)",
              r"\.exec\s*\(\s*[\"'](?:cmd|powershell|pwsh)"]),

    dict(id="js.dynamic_exec", name="Execução dinâmica de código escondido",
         category="Ofuscação", family="Script.Obfuscated", severity="alta", weight=30,
         targets=["script", "html"],
         description="Monta e executa código em tempo de execução (new Function, window['eval'], setTimeout com "
                     "texto decodificado), forma comum de esconder código malicioso em páginas e scripts.",
         any=[r"new\s+function\s*\(\s*(?:atob|unescape|decodeuricomponent|string\.fromcharcode)\s*\(",
              r"(?:window|self|this|globalthis)\s*\[\s*[\"']eval[\"']\s*\]",
              r"settimeout\s*\(\s*(?:atob|unescape|decodeuricomponent)\s*\(",
              r"document\.write\s*\(\s*(?:unescape|atob|decodeuricomponent)\s*\("]),

    dict(id="js.eval_obfuscated", name="Execução de código ofuscado (eval)",
         category="Ofuscação", family="Script.Obfuscated", severity="media", weight=25,
         targets=["script", "html"],
         description="Usa eval() sobre conteúdo decodificado/empacotado para esconder o código real.",
         any=[r"eval\s*\(\s*(?:unescape|atob|decodeuricomponent|string\.fromcharcode|window\.atob)\s*\(",
              r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)",
              r"execute(?:global)?\s*\(?\s*(?:unescape|chr|strreverse)\s*\("]),

    dict(id="js.activex_shell", name="Shell do Windows a partir de script web",
         category="Execução", family="Script.ActiveX", severity="media", weight=25,
         targets=["html", "script"],
         description="Cria um objeto WScript.Shell via ActiveX para executar comandos no sistema.",
         any=[r"new\s+activexobject\s*\(\s*[\"']wscript\.shell", r"getobject\s*\(\s*[\"']new:72c24dd5-d70a-438b-8a42-98424b88afb8"]),

    dict(id="html.smuggling", name="HTML smuggling",
         category="Downloader", family="HTML.Smuggling", severity="media", weight=25,
         targets=["html"],
         description="Monta um arquivo dentro do navegador a partir de Base64 e força o download, técnica "
                     "usada para entregar malware passando por filtros de e-mail. (Também usado por páginas "
                     "legítimas para exportar arquivos; pesa mais quando o conteúdo embutido é um executável.)",
         all=[r"atob\s*\(|base64", r"createobjecturl|mssaveoropenblob|mssaveblob", r"\.download\s*=|download="]),

    dict(id="html.hidden_iframe", name="IFrame invisível",
         category="Web", family="HTML.HiddenIframe", severity="baixa", weight=15, targets=["html"],
         description="Carrega uma página externa em um iframe invisível (redirecionamento/drive-by).",
         any=[r"<iframe[^>]{0,200}(?:width\s*=\s*[\"']?0[\"'\s>]|height\s*=\s*[\"']?0[\"'\s>]|display\s*:\s*none|visibility\s*:\s*hidden)[^>]{0,200}src\s*=\s*[\"']?https?:"]),

    dict(id="php.webshell", bonus=True, name="Webshell PHP",
         category="Backdoor", family="PHP.WebShell", severity="critica", weight=70,
         targets=["script", "html"],
         description="Executa comandos recebidos por requisições web ($_GET/$_POST) — porta dos fundos em servidores.",
         any=[r"(?:eval|assert|system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*(?:base64_decode\s*\(\s*|stripslashes\s*\(\s*|gzinflate\s*\(\s*)*\$_(?:get|post|request|cookie|server)",
              r"preg_replace\s*\(\s*[\"'][^\"']{0,40}/e[\"']",
              r"\$\w{1,30}\s*\(\s*\$_(?:get|post|request|cookie)\s*\[",
              r"\$_(?:get|post|request|cookie)\s*\[[^\]]{1,40}\]\s*\(\s*\$_(?:get|post|request|cookie)",
              r"(?:system|passthru|shell_exec|exec|popen|proc_open|assert)\s*\(\s*\$_(?:get|post|request|cookie)",
              r"(?:eval|assert)\s*\(\s*(?:gzinflate|gzuncompress|str_rot13|base64_decode)\s*\(\s*(?:gzinflate|str_rot13|base64_decode)"]),

    # ------------------------------------------------------------------ Linux / Unix
    dict(id="nix.reverse_shell", bonus=True, name="Shell reverso",
         category="Backdoor", family="Backdoor.ReverseShell", severity="critica", weight=75,
         targets=["script", "elf", "macro", "html"],
         description="Conecta-se a um servidor remoto e entrega um terminal do seu sistema ao atacante.",
         any=[r"(?:ba|z|k)?sh\s+-i\s*[<>&]+\s*/dev/(?:tcp|udp)/", r"/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+",
              r"\bn(?:c|cat|etcat)\b[^\n|;]{0,60}\s-(?:e|c)\s+/bin/(?:ba)?sh",
              r"mkfifo\s+/tmp/\w+[^\n]{0,80}\|\s*n(?:c|cat)\b",
              r"socat\s+[^\n]{0,60}exec:[\"']?(?:/bin/)?(?:ba)?sh",
              r"socket\.socket\([^\n]{0,400}\.connect\(\([^\n]{0,400}(?:os\.dup2|pty\.spawn|subprocess\.call\(\[[\"']/bin/(?:ba)?sh)",
              r"use\s+socket;[^\n]{0,300}exec\s*\(\s*[\"']/bin/(?:ba)?sh",
              r"fsockopen\s*\([^\n]{0,200}(?:exec|shell_exec|system|proc_open)\s*\([\"']/bin/(?:ba)?sh"]),

    dict(id="nix.dropper_tmp", name="Baixa e executa binário em pasta temporária",
         category="Downloader", family="Linux.Dropper", severity="alta", weight=40,
         targets=["script", "elf"],
         description="Baixa um programa para /tmp, /dev/shm ou /var/tmp, dá permissão de execução e o roda "
                     "— comportamento típico de bots e mineradores Linux.",
         all=[r"\b(?:curl|wget|tftp|busybox\s+wget)\b",
              r"chmod\s+(?:\+x|[0-7]?[0-7]*7[0-7]*|u\+x|a\+x)\s+[\"']?/(?:tmp|dev/shm|var/tmp|run/shm)/"]),

    dict(id="nix.pipe_shell", name="Executa script baixado direto no shell",
         category="Downloader", family="Linux.PipeShell", severity="baixa", weight=15,
         targets=["script"],
         description="Baixa um script e o executa diretamente (curl | sh). Comum em instaladores legítimos, "
                     "mas também em ataques.",
         any=[r"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"]),

    dict(id="nix.b64_exec", name="Decodifica Base64 e executa no shell",
         category="Ofuscação", family="Linux.Obfuscated", severity="alta", weight=40,
         targets=["script", "elf"],
         description="Decodifica conteúdo Base64 e o passa direto para o shell, escondendo o comando real.",
         any=[r"base64\s+(?:-d|--decode|-D)\b[^\n]{0,80}\|\s*(?:ba|z|da)?sh\b",
              r"echo\s+[\"']?[a-z0-9+/=]{60,}[\"']?\s*\|\s*base64\s+(?:-d|--decode)",
              r"eval\s+[\"']?\$\(\s*(?:echo|printf)[^\n)]{0,300}base64\s+(?:-d|--decode)"]),

    dict(id="nix.history_wipe", name="Apaga histórico de comandos",
         category="Evasão de defesa", family="Linux.AntiForensics", severity="media", weight=20,
         targets=["script", "elf"],
         description="Desativa ou apaga o histórico do shell para esconder o que foi executado.",
         any=[r"unset\s+histfile", r"histfile=/dev/null", r"export\s+histsize=0", r"history\s+-c\b",
              r"ln\s+-sf?\s+/dev/null\s+~?/?[\w/]*\.bash_history", r"rm\s+-[rf]+\s+~?/?[\w/]*\.bash_history"]),

    dict(id="nix.ssh_implant", name="Implanta chave SSH",
         category="Backdoor", family="Linux.SSHBackdoor", severity="alta", weight=35,
         targets=["script", "elf"],
         description="Adiciona uma chave SSH ao authorized_keys, dando acesso remoto permanente.",
         any=[r"(?:echo|printf|cat)[^\n]{0,600}>>\s*[\"']?(?:~|\$home|/root|/home/\w+)?/?\.ssh/authorized_keys"]),

    dict(id="nix.cron_persist", name="Persistência via cron/systemd",
         category="Persistência", family="Linux.Persist", severity="media", weight=25,
         targets=["script", "elf"],
         description="Instala uma entrada no cron ou serviço systemd para executar a cada reinício/minuto.",
         any=[r"\(\s*crontab\s+-l[^\n]{0,40};\s*echo[^\n]{0,300}\)\s*\|\s*crontab\s+-",
              r"echo[^\n]{0,300}>>?\s*/etc/cron(?:tab|\.d/|\.hourly|\.daily)",
              r"@reboot\s+[^\n]{0,200}(?:/tmp/|/dev/shm/|curl|wget|nohup)",
              r"\*/\d+\s+\*\s+\*\s+\*\s+\*\s+[^\n]{0,100}(?:curl|wget)[^\n]{0,200}\|\s*(?:ba)?sh"]),

    dict(id="nix.preload_rootkit", name="Rootkit via ld.so.preload",
         category="Rootkit", family="Linux.PreloadRootkit", severity="critica", weight=55,
         targets=["script", "elf"],
         description="Escreve em /etc/ld.so.preload para carregar uma biblioteca em todos os processos e "
                     "esconder arquivos/processos.",
         any=[r"(?:echo|printf|cat|cp|tee)[^\n]{0,200}(?:>|\s)\s*/etc/ld\.so\.preload"]),

    dict(id="nix.immutable", name="Protege arquivos maliciosos contra remoção",
         category="Persistência", family="Linux.Persist", severity="media", weight=20,
         targets=["script", "elf"],
         description="Usa chattr +i/-i em arquivos do sistema (cron, ssh, binários) para impedir sua remoção.",
         any=[r"chattr\s+[-+]i[a]?\s+[^\n]{0,80}(?:/etc/|/root/|/tmp/|/usr/bin/|authorized_keys|cron)"]),

    dict(id="nix.kill_competitors", bonus=True, name="Encerra mineradores concorrentes / segurança",
         category="Minerador", family="Linux.CoinMiner", severity="alta", weight=35,
         targets=["script", "elf"],
         description="Mata processos de outros mineradores ou de ferramentas de segurança, comportamento "
                     "de botnets de mineração (Kinsing, TeamTNT...).",
         any=[r"(?:pkill|killall|kill\s+-9)[^\n]{0,40}(?:kinsing|kdevtmpfsi|xmrig|minerd|cryptonight|xmr-stak|kworkerds|sysupdate)",
              r"(?:setenforce\s+0|systemctl\s+(?:stop|disable)\s+(?:apparmor|aliyun|aegis|cloudmonitor|qcloud))",
              r"(?:uninstall|stop)[^\n]{0,30}(?:aliyun|aegis|yunjing|qcloud|bcm-agent)"], min=1),

    dict(id="nix.botnet_mirai", name="Bot IoT (família Mirai/Gafgyt)",
         category="Botnet", family="Linux.Mirai", severity="critica", weight=60,
         targets=["elf", "script"],
         description="Contém strings de bots IoT que fazem ataques de negação de serviço e força bruta Telnet.",
         any=[r"tsource engine query", r"/bin/busybox\s+[a-z]{5,}", r"/dev/misc/watchdog",
              r"(?:udpflood|tcpflood|httpflood|synflood|ackflood|greflood|hex-flood|std-flood)",
              r"\bscanner_init\b|\battack_init\b|\bkiller_init\b", r"POST /cdn-cgi/"], min=2),

    dict(id="nix.rm_root", bonus=True, name="Destruição do sistema de arquivos",
         category="Destrutivo", family="Linux.Wiper", severity="critica", weight=70,
         targets=["script", "elf", "macro"],
         description="Apaga todo o sistema de arquivos ou sobrescreve o disco.",
         any=[r"rm\s+-(?:rf|fr)\s+/(?:\s|\*|$)[^\n]{0,30}--no-preserve-root|rm\s+-(?:rf|fr)\s+--no-preserve-root\s+/",
              r"dd\s+if=/dev/(?:zero|urandom)\s+of=/dev/(?:sd[a-z]|nvme\d|vd[a-z]|hd[a-z]|mmcblk)",
              r"mkfs(?:\.\w+)?\s+(?:-f\s+)?/dev/(?:sd[a-z]|nvme|vd[a-z])[^\n]{0,20}(?:&&|;)",
              r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"]),

    dict(id="win.wiper", bonus=True, name="Destruição de dados no Windows",
         category="Destrutivo", family="Win.Wiper", severity="critica", weight=60, targets=["any"],
         description="Sobrescreve o MBR/disco físico ou apaga em massa os dados da unidade.",
         any=[r"cipher(?:\.exe)?\s+/w:\s*[a-z]:", r"format(?:\.com)?\s+[c-z]:\s+/(?:q|y)[^\n]{0,20}/(?:q|y)",
              r"del\s+/[fsq]\s+/[fsq]\s+/[fsq]\s+[\"']?[c-z]:\\\*"]),

    dict(id="win.raw_disk", name="Acesso direto ao disco físico",
         category="Destrutivo", family="Win.RawDisk", severity="baixa", weight=10, targets=["pe", "script"],
         description="Abre o disco físico diretamente (\\\\.\\PhysicalDrive0), o que permite sobrescrever o setor de "
                     "inicialização (MBR). Também usado por ferramentas de disco legítimas.",
         any=[r"\\\\\.\\physicaldrive0"]),

    # ------------------------------------------------------------------ Python
    dict(id="py.exec_encoded", name="Python executando código codificado",
         category="Ofuscação", family="Python.Obfuscated", severity="alta", weight=40,
         targets=["script"],
         description="Usa exec()/eval() sobre conteúdo decodificado em tempo de execução (Base64, zlib, "
                     "marshal), escondendo o código real.",
         any=[r"exec\s*\(\s*(?:__import__\s*\(\s*[\"'](?:base64|zlib|marshal|codecs)|base64\.b(?:64|32|85)decode|zlib\.decompress|marshal\.loads|codecs\.decode\([^\n]{0,20}rot)",
              r"exec\s*\(\s*(?:bytes\.fromhex|bytearray\.fromhex)\(",
              r"exec\s*\(\s*\"\"\.join\(\s*(?:chr|map\(chr)"]),

    # ------------------------------------------------------------------ Macros do Office
    dict(id="macro.autoexec", name="Macro de execução automática",
         category="Macro", family="Macro.AutoExec", severity="media", weight=15, targets=["macro"],
         description="A macro roda sozinha ao abrir/fechar o documento.",
         any=[r"\b(?:autoopen|auto_open|document_open|workbook_open|autoexec|autoclose|auto_close|document_close|workbook_activate|document_beforeclose|presentation_open)\b"]),

    dict(id="macro.exec", name="Macro executa comandos do sistema",
         category="Macro", family="Macro.Exec", severity="alta", weight=30, targets=["macro"],
         description="A macro executa programas (Shell, WScript.Shell, ShellExecute, PowerShell, CMD).",
         any=[r"\bshell\s*\(", r"wscript\.shell", r"shellexecute", r"\.run\s*\(?[\"']?(?:cmd|powershell|mshta|wscript|cscript)",
              r"powershell|cmd(?:\.exe)?\s+/[ck]", r"macscript", r"win32_process[^\n]{0,40}create", r"callbyname"]),

    dict(id="macro.download", name="Macro baixa arquivos",
         category="Macro", family="Macro.Downloader", severity="alta", weight=30, targets=["macro"],
         description="A macro baixa conteúdo da internet (URLDownloadToFile, XMLHTTP, ADODB.Stream).",
         any=[r"urldownloadtofile", r"xmlhttp", r"winhttprequest", r"adodb\.stream", r"internetexplorer\.application"]),

    dict(id="macro.api", name="Macro chama APIs nativas do Windows",
         category="Macro", family="Macro.Injector", severity="alta", weight=40, targets=["macro"],
         description="Declara funções do kernel32 para alocar memória e executar código (injeção a partir de macro).",
         all=[r"declare\s+(?:ptrsafe\s+)?(?:function|sub)"],
         any=[r"virtualalloc(?:ex)?", r"rtlmovememory", r"createthread|createremotethread", r"writeprocessmemory"]),

    dict(id="macro.obfuscation", name="Macro ofuscada",
         category="Ofuscação", family="Macro.Obfuscated", severity="media", weight=15, targets=["macro"],
         description="A macro esconde strings com Chr(), StrReverse ou concatenações excessivas.",
         any=[r"(?:chr[bw]?\$?\s*\(\s*\d{1,3}\s*\)\s*&\s*){6,}", r"strreverse\s*\(", r"(?:\"[^\"\n]{1,4}\"\s*&\s*){12,}"]),

    # ------------------------------------------------------------------ PDF / RTF / LNK
    dict(id="pdf.auto_js", name="PDF executa JavaScript ao abrir",
         category="Documento", family="PDF.JavaScript", severity="media", weight=30, targets=["pdf"],
         description="O PDF tem ação automática (OpenAction/AA) que executa JavaScript.",
         all=[r"/openaction|/aa\s*<<|/aa\s+\d+\s+0\s+r"], any=[r"/javascript|/js\s*[\(<\d]"]),

    dict(id="pdf.launch", name="PDF lança programas externos",
         category="Documento", family="PDF.Launch", severity="alta", weight=45, targets=["pdf"],
         description="O PDF usa a ação /Launch para executar comandos ou programas no computador.",
         any=[r"/launch\s*/[a-z]|/s\s*/launch", r"/type\s*/action\s*/s\s*/launch"]),

    dict(id="pdf.embedded_auto", name="PDF com arquivo embutido aberto automaticamente",
         category="Documento", family="PDF.Dropper", severity="media", weight=25, targets=["pdf"],
         description="O PDF contém um arquivo embutido e uma ação automática.",
         all=[r"/embeddedfile", r"/openaction|/aa\s*<<"]),

    dict(id="pdf.obfuscated_names", name="Nomes PDF ofuscados",
         category="Ofuscação", family="PDF.Obfuscated", severity="baixa", weight=15, targets=["pdf"],
         description="Usa codificação hexadecimal em nomes (ex.: /J#61vaScript) para enganar scanners.",
         any=[r"/(?:j|#4a)(?:#61|a)(?:#76|v)(?:#61|a)(?:#53|s)(?:#63|c)(?:#72|r)(?:#69|i)(?:#70|p)(?:#74|t)(?<!/javascript)",
              r"/(?:o|#4f)(?:p|#70)(?:e|#65)(?:n|#6e)(?:a|#41)(?:c|#63)(?:t|#74)(?:i|#69)(?:o|#6f)(?:n|#6e)(?<!/openaction)"]),

    dict(id="rtf.exploit", name="RTF com objeto OLE explorável",
         category="Exploit", family="Exploit.RTF.EquationEditor", severity="critica", weight=60, targets=["rtf"],
         description="RTF com objeto OLE do Equation Editor ou atualização automática (CVE-2017-11882 / "
                     "CVE-2017-0199), muito usado para instalar malware ao abrir o documento.",
         all=[r"\\objdata|\\object"],
         any=[r"equation\.3", r"4571756174696f6e2e33", r"\\objupdate", r"0002ce02", r"d0cf11e0a1b11ae1[^}]{0,400}(?:4571756174696f6e|equation)",
              r"(?:htmlfile|00000300-0000-0000-c000-000000000046|3050f4d8-98b5-11cf-bb82-00aa00bdce0b)"]),

    dict(id="lnk.malicious", name="Atalho executa comando oculto",
         category="Atalho malicioso", family="LNK.Downloader", severity="alta", weight=45, targets=["lnk"],
         description="O atalho, em vez de abrir um documento, executa PowerShell/CMD/MSHTA com parâmetros "
                     "ocultos ou baixa algo da internet.",
         all=[r"powershell|cmd(?:\.exe)?|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|conhost"],
         any=[r"-w(?:indowstyle)?\s+(?:hidden|1)|-enc|iex|invoke-|downloadstring|frombase64", r"https?://",
              r"/c\s+start\s+/b|&&|\.(?:vbs|js|hta|bat|ps1)\b"]),
]
