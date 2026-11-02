# Arquitetura do EXE Antivirus

Aplicação Python 3.12+ com interface Qt (PySide6), empacotada com PyInstaller (instalador `.exe` com Inno Setup
no Windows; AppImage no Linux). Um único processo de interface + processos de varredura isolados.

```
exeav/
  engine/        motor de detecção (conteúdo, estrutura, desofuscação, reputação, hashes)
  scanner.py     varreduras rápida/completa/personalizada/pen drive/boot (processos paralelos + cache)
  realtime.py    tempo real: arquivos, processos, linha de comando, anti-ransomware (cifragem em massa + iscas)
  scriptguard.py código que está rodando: PowerShell (Script Block Logging), scripts abertos pelo shell
  botnet.py      comportamento de rede por processo (C2, varredura, DDoS, beaconing, backdoor)
  usbguard.py    dispositivos removíveis
  bootguard.py   proteção ao ligar (programas que iniciam com o sistema + scan em segundo plano)
  dnsguard.py    DNS da Mullvad (DoH/DoT/servidor local) e bloqueio de sites
  firewall.py    Windows Firewall, ufw, firewalld, nftables, iptables, OpenSnitch
  intel.py       inteligência de ameaças (Feodo, URLhaus, ThreatFox, CISA KEV)
  incidents.py   centro de incidentes / ameaças desconhecidas
  fpengine.py    exclusões de falso positivo por conteúdo
  selfprotect.py autoproteção (integridade)
  canary.py      arquivos-isca anti-ransomware
  quarantine.py + vault.py   quarentena cifrada
  lab.py         Sala de Análise (relatório completo de uma amostra)
  recovery.py    reparo de arquivos corrompidos e backups protegidos
  history.py     histórico encadeado por hash (SQLite)
  gui/           interface (uma aba por função)
```

## Motor de detecção

Para cada arquivo: tipo real pelo conteúdo (nunca pelo nome/extensão) → hashes (SHA-256; MD5/SHA-1 se o banco
precisar) → banco de assinaturas e hashes da inteligência → análise pelo tipo:

- **PE/ELF**: importações perigosas, seções anormais, entropia/empacotamento, recursos, assinatura;
- **Office/PDF/RTF/LNK**: macros VBA (extraídas e descompactadas), Follina, JavaScript/Launch em PDF, atalhos;
- **scripts/HTML**: desofuscação em até 4 camadas (CMD com `^` e `SET`, PowerShell com crases, concatenação,
  `-f`, `[char]`, Base64/`-EncodedCommand`, `Chr()`, strings invertidas) antes de aplicar as regras;
- **compactados**: ZIP/7z/RAR/GZ/TAR aninhados até 5 níveis;
- **inteligência**: domínios de infraestrutura maliciosa conhecida citados no conteúdo.

Pontuação: soma dos pesos das evidências; evidências estruturais (empacotamento, entropia) limitadas a 30 pontos
juntas (nunca condenam um arquivo sozinhas); reputação verificada −40; documentação/artigo limitada a
"suspeito". Limites: suspeito ≥ 35, malicioso ≥ 70 (sensibilidade média).

**Confiança** (independente da pontuação): `confirmada` (hash catalogado/EICAR), `alta` (malicioso com 3+ tipos
independentes de evidência), `média` (2 tipos, ou 1 evidência crítica muito específica), `baixa` (1 tipo).

Regras são distribuídas cifradas/compactadas (`exeav/data/rules.bin`) para o executável não conter padrões
maliciosos em texto puro.

## Tempo real

- arquivos criados/alterados/movidos nas pastas protegidas (inotify / ReadDirectoryChangesW);
- todo processo novo: executável analisado; interpretadores (bash, python, powershell, wscript…) e ferramentas
  do sistema muito usadas por malware (vssadmin, wbadmin, bcdedit, netsh, schtasks, certutil…) têm a linha de
  comando analisada; se o comando é perigoso **e** foi disparado por programa sem origem verificável, isso
  conta como segundo sinal: o comando é encerrado e o programa que disparou é suspenso;
- anti-ransomware: arquivos-isca (reação na primeira alteração) + detecção de cifragem em massa; o processo
  responsável é identificado pela E/S medida na janela do ataque e suspenso — nunca o sistema, programas
  assinados ou o próprio antivírus.

## Firewall

Ordem de preferência para bloquear IPs: Windows Firewall · ufw (ativo) · firewalld (ativo) · nftables · iptables.
Regras do ufw/firewalld/Windows são permanentes; as de nftables/iptables são reaplicadas pelo antivírus ao abrir
e pelo serviço de boot (Linux). O antivírus só cria regras próprias (nome/tabela/policy `exeav`) e nunca apaga
regras do usuário. Bloqueio por programa: Windows Firewall (`program=`) ou OpenSnitch (Linux).

## Quarentena

O arquivo é cifrado (XOR com chave aleatória de 64 bytes por item — suficiente para nunca ser executado ou
reconhecido por acidente) e gravado sem permissão de execução, com metadados em JSON; o original é removido.
Arquivos essenciais do sistema operacional nunca são isolados. Restaurar devolve o conteúdo idêntico.

## Recuperação

Reparo de ZIP/DOCX/XLSX/PPTX/ODT, PDF, PNG, JPEG, GIF, JSON e textos; identificação de arquivos cifrados por
ransomware (entropia + formato); backups protegidos (cifrados) de pastas, com restauração validada por hash.

## Atualizações e inteligência

Ver `SEGURANCA-E-PRIVACIDADE.md` (verificação) e `ZERO-DAY-E-FALSOS-POSITIVOS.md`. Fontes: Feodo Tracker,
URLhaus, ThreatFox, CISA KEV (intel) e MalwareBazaar (hashes). Cada atualização é validada, versionada,
registrada com o SHA-256 do download e mantém a versão anterior se falhar. Indicadores expiram (30 dias sem
aparecer). Não há atualização automática do programa nesta versão.
