# EXE Antivirus

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
| **Tempo Real** | Monitor de arquivos (criados/alterados/movidos), monitor de processos (analisa cada programa executado e pode encerrá-lo), escudo anti-ransomware (detecta criptografia em massa e suspende o processo) |
| **Quarentena** | Ameaças isoladas e **cifradas** (não executáveis); restaurar, restaurar em outro local, excluir, enviar para análise |
| **Sala de Análise** | Recebe o arquivo do vírus (neutralizado) e mostra **por que** ele é vírus — cada evidência, seu peso e onde foi encontrada — e **todas as informações**: hashes (MD5/SHA-1/SHA-256/SHA-512), tipo real, entropia (com gráfico), cabeçalhos, seções, importações (APIs perigosas destacadas), exportações, recursos, informações de versão, certificados, strings (URLs, IPs, e-mails, registro, caminhos, carteiras bitcoin, .onion), macros VBA extraídas, conteúdo ofuscado decodificado, hex, conteúdo de compactados e técnicas **MITRE ATT&CK**. Exporta relatório HTML/JSON |
| **Recuperação** | Encontra e repara arquivos corrompidos (ZIP/DOCX/XLSX/PPTX/ODT, PDF, PNG, JPEG, GIF, JSON, textos), identifica arquivos cifrados por ransomware e cria/restaura **backups protegidos** de pastas |
| **Processos** | Programas em execução; verificar todos, encerrar, analisar |
| **Inicialização** | Chaves Run, Winlogon, pasta Inicializar e tarefas agendadas (Windows); autostart, systemd, cron, `.bashrc`, `ld.so.preload` (Linux); verificar e desativar com backup |
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
* **Scripts** (PowerShell, CMD, VBS, JS, HTA, Bash, Python, PHP): decodifica `-EncodedCommand`,
  Base64, GZip, `[char]`, `fromCharCode` e executáveis embutidos antes de analisar.
* **Documentos:** macros VBA (leitor OLE + descompressão MS-OVBA próprios), Follina/injeção de
  modelo em DOCX, PDF com JavaScript/Launch (streams descompactados), RTF com exploit do Equation
  Editor, atalhos LNK maliciosos, executáveis escondidos em imagens/PDF.
* **Compactados:** ZIP/JAR/APK/GZ/TAR com recursão e proteção contra zip bomb.
* **66 regras comportamentais** (ransomware, mineradores, Mimikatz, stealers, UAC bypass, desativação
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
python main.py --selftest      # autoteste
```

## Compilar

```bash
pip install -r requirements-dev.txt
python tools/build.py --onefile
```

Gera em `dist/`:
* Windows: `ExeAntivirus-<versão>-windows-x64.zip` (pasta com `ExeAntivirus.exe`) e
  `ExeAntivirus-<versão>-windows-x64-portatil.exe` (arquivo único).
* Linux: `ExeAntivirus-<versão>-linux-x64.tar.gz` (com `install-linux.sh` para criar o atalho no
  menu) e `ExeAntivirus-<versão>-linux-x64-portatil`.

O GitHub Actions (`.github/workflows/build.yml`) roda os testes e compila para Windows e Linux a cada
push; os executáveis ficam nos *artifacts* da execução.

> Para varrer pastas protegidas do sistema, execute como administrador (Windows: Configurações →
> "Reiniciar como administrador"; Linux: `sudo`).

## Testes

```bash
python -m pytest
```

Os testes geram amostras **inofensivas** na hora (EICAR montado em tempo de execução, executáveis PE
mínimos que só contêm `ret`, macros e scripts de exemplo) e verificam detecção, ausência de falsos
positivos em binários reais do sistema, quarentena, Sala de Análise, tempo real, recuperação,
backups e a interface gráfica.
