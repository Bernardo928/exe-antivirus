# EXE Antivirus
# O melhor anti vírus
Antivírus com interface gráfica para **Windows e Linux**, com proteção em tempo real, quarentena,
Sala de Análise, recuperação de arquivos corrompidos e varreduras rápida/completa/personalizada.

A detecção é feita **pelo conteúdo** do arquivo (estrutura, código, comportamento declarado e
assinaturas), **nunca pelo nome ou extensão** — o mesmo conteúdo recebe o mesmo veredito com
qualquer nome, e um arquivo inofensivo chamado `virus.exe` continua limpo.

## Abas

| Aba | O que faz |
|---|---|
| **Painel** | Estado da proteção, estatísticas, atalhos e atividade recente |
| **Verificação** | Scan rápido (downloads, área de trabalho, temporários, inicialização e todos os processos em execução), scan completo (todos os discos), scan de pasta e de arquivos; pausar/parar; ações sobre os resultados |
| **Tempo Real** | Monitor de arquivos (criados/alterados/movidos), monitor de processos (analisa cada programa executado, os scripts rodados por interpretadores e comandos passados direto na linha de comando — ataques "sem arquivo" — e pode encerrá-los), escudo anti-ransomware (detecta criptografia em massa e suspende o processo) e **análise de scripts por dentro**: no Windows lê o código do PowerShell já decodificado pelo próprio Windows (registro de blocos de script, mesmo com `-EncodedCommand`, `IEX` e ofuscação); no Linux lê o script que o shell está executando — inclusive o que o vírus apagou do disco — e detecta `curl \| sh` |
| **Anti-Botnet** | Impede que o PC vire parte de uma botnet: vigia a rede de cada programa e bloqueia conexão com servidores de comando (C2) conhecidos, varredura de outras máquinas para se espalhar (Telnet/SSH/SMB/RDP/ADB), ataques DDoS, contato periódico com servidor (beaconing), portas de IRC/trojans/Tor/mineração, backdoor aberto para a rede e programas rodando de pasta temporária, apagados do disco ou disfarçados de processo do sistema. Encerra o bot, isola o executável (ou o script, se rodar por um interpretador) e bloqueia o servidor de comando no firewall (Windows Firewall, nftables ou iptables). Lista de C2 atualizável (abuse.ch Feodo Tracker) ou importada |
| **Pen drives** | Verifica pen drives, cartões de memória e HDs/SSDs externos USB assim que são conectados (em segundo plano, prioridade baixa). Detecta os truques de vírus de pen drive na raiz — `autorun.inf`, **vírus de atalho** (pastas escondidas trocadas por atalhos `.lnk` que rodam o vírus) e executáveis escondidos —, isola as ameaças e faz as pastas escondidas voltarem a aparecer |
| **Proteção Web** | **DNS da Mullvad** criptografado com 6 filtros (sem filtro, anúncios, base com malware — recomendado —, estendido, família, tudo). Usa o DNS-over-HTTPS nativo do Windows 11, o DNS-over-TLS do systemd-resolved no Linux ou, sem suporte do sistema (Windows 10), um servidor DNS local do antivírus que fala com a Mullvad por HTTPS — e devolve o DNS original se o antivírus for fechado. **Bloqueio de sites** escolhidos por você (arquivo hosts; no servidor local, também todos os subdomínios) |
| **Firewall** | Integração com firewalls de código aberto: **ufw** e **firewalld** (regras permanentes), **nftables**/**iptables** (reaplicadas a cada boot) e **OpenSnitch** (cortar a internet de um programa específico); no Windows, Windows Firewall. Lista os firewalls encontrados, IPs bloqueados e programas sem internet |
| **Zero-Day & Intel** | Centro de incidentes: toda detecção vira um registro com SHA-256/SHA-512/SHA3-256, origem do download, assinatura digital, processo e cadeia de processos, conexões, regras, **nível de confiança** (multi-sinal) e evidência preservada; ameaças sem assinatura conhecida ficam "em investigação" (nunca anunciadas como zero-day confirmado). Revisão (confirmar / **falso positivo** com motivo / resolvido), exportação HTML/JSON, busca. Abas de **inteligência de ameaças** (Feodo, URLhaus, ThreatFox, CISA KEV — validados, versionados, com expiração), **falsos positivos** (exclusões por SHA-256, revogáveis, regras que mais erram) e **autoproteção** (integridade dos arquivos, configurações, histórico e quarentena) |
| **Quarentena** | Ameaças isoladas e **cifradas** (não executáveis); restaurar, restaurar em outro local, excluir, enviar para análise |
| **Sala de Análise** | Recebe o arquivo do vírus (neutralizado) e mostra **por que** ele é vírus — cada evidência, seu peso e onde foi encontrada — e **todas as informações**: hashes (MD5/SHA-1/SHA-256/SHA-512), tipo real, entropia (com gráfico), cabeçalhos, seções, importações (APIs perigosas destacadas), exportações, recursos, informações de versão, certificados, strings (URLs, IPs, e-mails, registro, caminhos, carteiras bitcoin, .onion), macros VBA extraídas, conteúdo ofuscado decodificado, hex, conteúdo de compactados e técnicas **MITRE ATT&CK**. Exporta relatório HTML/JSON |
| **Recuperação** | Encontra e repara arquivos corrompidos (ZIP/DOCX/XLSX/PPTX/ODT, PDF, PNG, JPEG, GIF, JSON, textos), identifica arquivos cifrados por ransomware e cria/restaura **backups protegidos** de pastas |
| **Processos** | Programas em execução; verificar todos, encerrar, analisar |
| **Inicialização** | **Proteção ao ligar**: toda vez que o computador liga, reaplica o firewall, avalia cada programa que inicia junto (Run, Winlogon, pasta Inicializar, tarefas agendadas; autostart, systemd, cron, `.bashrc`, `ld.so.preload`) e **bloqueia** vírus, comandos suspeitos e programas desconhecidos — encerra, corta a internet no firewall e tira da inicialização com cópia de segurança (modos: bloquear desconhecidos, bloquear tudo que não for do sistema, só avisar). Depois faz um **scan rápido em segundo plano** com prioridade baixa. Itens novos que aparecem com o PC ligado também são avaliados. "Liberar" desfaz tudo |
| **Rede** | Conexões por programa com alerta de portas de RATs/mineradores/backdoors e verificação do arquivo *hosts* contra redirecionamentos |
| **Histórico** | Registro de tudo (filtro, busca, exportação CSV) |
| **Configurações** | Sensibilidade, limites, exclusões, compactados, cache, multiprocessamento, agendamento diário, assinaturas por hash (atualização online/importação), regras personalizadas, iniciar com o sistema, bandeja |

## Motor de detecção

* **Executáveis Windows (PE):** injeção em processos, process hollowing, keylogger, downloader,
  ransomware (varredura + criptografia + lista de extensões), clipper, lista de antivírus a
  encerrar, SeDebugPrivilege, empacotadores/protetores, seções W+X, entropia, ponto de entrada
  anômalo, executáveis embutidos em recursos/overlay, disfarce de arquivo da Microsoft.
* **Executáveis Linux (ELF):** parser próprio — UPX, segmentos RWX, rootkits LD_PRELOAD (funções
  interceptadas), shell reverso, injeção via ptrace.
* **Scripts** (PowerShell, CMD, VBS, JS, HTA, Bash, Python, PHP): desofusca antes de analisar —
  circunflexos/aspas/variáveis `SET` do CMD, crases, concatenação de strings, operador `-f`, `[char]`,
  `Chr()`, `fromCharCode`, strings invertidas, `.Replace()`, `-EncodedCommand`, Base64 e GZip em até 4
  camadas e executáveis embutidos.
* **Documentos:** macros VBA (leitor OLE + descompressão MS-OVBA próprios), Follina/injeção de
  modelo em DOCX, PDF com JavaScript/Launch (streams descompactados), RTF com exploit do Equation
  Editor, atalhos LNK maliciosos, executáveis escondidos em imagens/PDF.
* **Compactados:** ZIP/JAR/APK/GZ/TAR com recursão e proteção contra zip bomb.
* **73 regras comportamentais** (ransomware, mineradores, Mimikatz, stealers, UAC bypass, desativação
  do Defender, AMSI bypass, LOLBins, webshells, botnets IoT, wipers...). As regras são distribuídas
  ofuscadas (`exeav/data/rules.bin`), então o executável não contém padrões maliciosos em texto puro.
* **Assinaturas por hash** em SQLite (EICAR incluído; atualização a partir de listas públicas como o
  MalwareBazaar, ou importação de arquivo).
* **Anti-falso-positivo:** no Windows verifica assinatura digital Authenticode e o catálogo do sistema;
  no Linux confere o arquivo com o MD5 registrado pelo pacote (dpkg). Indicadores apenas estruturais
  (ex.: "está empacotado") têm teto de pontuação.
* **Autoproteção:** o antivírus nunca analisa a si mesmo (pasta do programa, pasta temporária do
  executável, quarentena, Sala de Análise, backups e banco de dados).
* **Desempenho:** pré-filtro Aho-Corasick + regex só em janelas ao redor das âncoras, extração de
  strings em C (`bytes.translate`), parser ELF próprio, **varredura em vários processos** (usa
  todos os núcleos) e **cache incremental** (arquivos inalterados não são reanalisados).

## Executar

```bash
pip install -r requirements.txt
python main.py                 # interface gráfica
python main.py --scan PASTA    # varredura pela linha de comando (--quarantine para isolar)
python main.py --quick         # scan rápido sem interface
python main.py --analyze ARQ   # relatório da Sala de Análise no terminal (--json)
python main.py --botnet 10     # observa a rede por 10 s e lista comportamento de botnet (não age)
python main.py --selftest      # autoteste
python main.py --install-system --autostart   # integra ao sistema (--pslog no Windows, --boot-service no Linux)
python main.py --uninstall-system             # desfaz tudo o que o antivírus mudou no sistema
python main.py --selfcheck     # integridade do próprio antivírus
python main.py --update-intel  # atualiza os feeds de inteligência de ameaças
python tools/benchmark.py      # benchmark reproduzível (falsos positivos, precisão, recall, F1, tempo)
```

## Documentação técnica

[Auditoria](docs/AUDITORIA.md) · [Arquitetura e motor](docs/ARQUITETURA.md) ·
[Segurança, autoproteção e privacidade](docs/SEGURANCA-E-PRIVACIDADE.md) ·
[Zero-day e falsos positivos](docs/ZERO-DAY-E-FALSOS-POSITIVOS.md) · [Testes e benchmark](docs/TESTES-E-BENCHMARK.md) ·
[Instalação e desinstalação](docs/INSTALACAO.md) · [Maturidade, pendências e limitações](docs/MATURIDADE.md)

## Instalar

* **Windows:** `ExeAntivirus-<versão>-windows-x64-instalador.exe` — instala em Arquivos de Programas, cria
  atalhos no menu Iniciar (e na área de trabalho, opcional), configura a **proteção desde a inicialização**
  (tarefa agendada no logon com privilégios de administrador, sem pedir UAC a cada boot) e, opcionalmente,
  liga o registro de scripts do PowerShell. O desinstalador desfaz tudo: tarefa, DNS, sites bloqueados,
  regras de firewall e o registro do PowerShell.
* **Linux:** `ExeAntivirus-<versão>-linux-x64.AppImage` — roda em qualquer distribuição
  (`chmod +x` e abrir). No primeiro uso ele se adiciona ao menu de aplicativos e à inicialização automática.
  Para o firewall ser reaplicado a cada boot antes do login:
  `sudo ./ExeAntivirus-*.AppImage --install-system --autostart --boot-service`.
  Para remover tudo: `./ExeAntivirus-*.AppImage --uninstall-system`.

## Compilar

```bash
pip install -r requirements-dev.txt
python tools/build.py --onefile --installer   # Windows (precisa do Inno Setup 6)
python tools/build.py --onefile --appimage    # Linux
```

Gera em `dist/`:
* Windows: instalador `…-instalador.exe`, `ExeAntivirus-<versão>-windows-x64.zip` (pasta com
  `ExeAntivirus.exe`) e `ExeAntivirus-<versão>-windows-x64-portatil.exe` (arquivo único).
* Linux: `.AppImage`, `ExeAntivirus-<versão>-linux-x64.tar.gz` (com `install-linux.sh` para criar o
  atalho no menu) e `ExeAntivirus-<versão>-linux-x64-portatil`.

O GitHub Actions (`.github/workflows/build.yml`) roda os testes e compila para Windows e Linux a cada
push; os executáveis ficam nos *artifacts* da execução.

> Para varrer pastas protegidas do sistema, execute como administrador (Windows: Configurações →
> "Reiniciar como administrador"; Linux: `sudo`).

## Testes

```bash
python -m pytest
```

Além dos testes de funcionalidade, `tests/test_hardening.py` cobre as regressões encontradas nos testes
extremos: variantes ofuscadas de ameaças (circunflexos e `SET` no CMD, crases, concatenação e operador `-f` no
PowerShell, `Chr()`/`[char]`, Base64 em várias camadas, ZIP aninhado, scripts UTF-16), arquivos legítimos
parecidos (não podem dar falso positivo), resistência a ReDoS de todas as regras, fuzzing de arquivos
malformados, bancos de dados corrompidos, configurações inválidas, FIFO e a proteção de arquivos e processos
essenciais do sistema.

### Proteções de segurança do próprio antivírus

* Nunca isola, exclui ou suspende **arquivos essenciais e íntegros do sistema** (verificados pelo pacote no
  Linux ou por assinatura digital no Windows), nem encerra processos críticos (PID 1, `csrss.exe`,
  `lsass.exe`, `systemd`...), o próprio antivírus ou o programa que o iniciou.
* O escudo anti-ransomware aponta o culpado pelo volume escrito **durante** o ataque (não pelo total
  acumulado) e só suspende programas que não sejam do sistema/assinados (interpretadores de script podem ser
  suspensos, pois são usados por ransomware em script).
* Um analisador de formato que falhe em um arquivo manipulado não faz o arquivo escapar: as regras de
  conteúdo são aplicadas mesmo assim.
* A análise roda em processos separados: se um arquivo hostil derrubar ou travar um deles, o grupo é
  recriado e a varredura continua — a análise nunca é repetida no processo da interface. Leitores de
  formato (OLE, ZIP, ELF, PDF) têm limites de memória e detecção de ciclos.
* Arquivos grandes (> 32 MB) são analisados um de cada vez, limitando o pico de memória.

Os testes geram amostras **inofensivas** na hora (EICAR montado em tempo de execução, executáveis PE
mínimos que só contêm `ret`, macros e scripts de exemplo) e verificam detecção, ausência de falsos
positivos em binários reais do sistema, quarentena, Sala de Análise, tempo real, recuperação,
backups e a interface gráfica.
