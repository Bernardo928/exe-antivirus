# Segurança, autoproteção e privacidade

## Modelo de ameaças

| Ameaça | O que o EXE Antivirus faz | Limite |
|---|---|---|
| Arquivo malicioso conhecido | Hash do banco de assinaturas / ThreatFox → bloqueio com confiança "confirmada" | Depende de atualizar as assinaturas |
| Arquivo malicioso desconhecido | Heurísticas por conteúdo, estrutura e desofuscação; incidente "em investigação" | Malware novo sem nenhum traço conhecido pode passar |
| Script sem arquivo (fileless) | PowerShell decodificado pelo Windows (Script Block Logging), linha de comando, scripts lidos pelo descritor | No Linux, `curl \| sh` é visto mas o conteúdo do pipe não é lido |
| Ransomware | Arquivos-isca (reação imediata), cifragem em massa, comandos que apagam backups, cadeia de execução | O monitor de processos amostra a cada 1,5 s: um comando que termina antes disso pode não ser visto |
| Botnet / C2 | Comportamento de rede por processo + C2 conhecidos (Feodo/ThreatFox) + firewall | Conexões muito curtas entre amostras podem passar |
| Persistência | Proteção ao ligar avalia todo item de inicialização; itens novos são avaliados com o PC ligado | Rootkits de kernel estão fora do alcance de um antivírus em modo usuário |
| Pen drive | Verificação ao conectar, autorun, vírus de atalho | Nada é executado ou formatado automaticamente |
| Malware tentando desligar o antivírus | Configuração alterada por fora é detectada e pode ser restaurada; histórico encadeado; integridade dos arquivos do programa | Um processo **com privilégio de administrador** pode adulterar tudo junto |

## Autoproteção (`exeav/selfprotect.py`)

- **Arquivos do programa**: o build grava `integrity.json` (SHA-256 de cada arquivo). Ao abrir, e com
  `ExeAntivirus --selfcheck`, o antivírus confere tudo e aponta arquivos alterados, faltando ou estranhos
  (testado: alterar uma biblioteca ou injetar um `.so` é detectado). Instalado em Arquivos de Programas, só um
  administrador consegue alterar os arquivos.
- **Configurações**: o antivírus guarda o hash e uma cópia do que ele mesmo gravou. Se o arquivo for alterado
  por outro programa (ex.: desligando o tempo real), aparece em Zero-Day & Intel → Autoproteção com as chaves
  alteradas, e "Restaurar configurações" volta à última versão boa.
- **Histórico**: cada evento guarda o hash do anterior (encadeamento). Alterar um evento, apagar do meio ou
  apagar os mais recentes é detectado. "Limpar histórico" pelo próprio programa é registrado como evento de
  auditoria e reinicia a corrente.
- **Quarentena**: cada item precisa ter o cabeçalho do cofre e não pode ter permissão de execução.
- **Regras**: o pacote precisa decodificar corretamente.
- **Processos**: o antivírus nunca encerra/suspende a si mesmo, quem o iniciou, processos críticos do sistema
  ou programas assinados (esses só geram alerta).
- **Não há** ocultação, evasão ou persistência furtiva: o antivírus aparece normalmente na lista de programas,
  na bandeja e pode ser desinstalado pelos meios normais (desinstalador do Windows / `--uninstall-system`).

## Verificação criptográfica

| Recurso | Situação |
|---|---|
| SHA-256 | Em todo o motor, cache, quarentena, assinaturas, exclusões de falso positivo |
| SHA-512 e SHA3-256 | Em todos os incidentes (evidências) e na Sala de Análise |
| Authenticode (Windows) | WinVerifyTrust + catálogo de segurança do Windows (inclui revogação quando o Windows tem a informação) |
| Pacotes Linux | dpkg: o arquivo precisa pertencer a um pacote e bater com o MD5 registrado pelo pacote (MD5 é o que o dpkg registra — é fraco contra colisão proposital) |
| Integridade do próprio programa | Manifesto SHA-256 |
| Feeds de inteligência | TLS + validação de conteúdo + SHA-256 do download registrado + soma de verificação local. Os publicadores não assinam os feeds |
| GnuPG/OpenPGP, Sigstore, cosign, X.509 próprio | **Não implementado** (ver MATURIDADE.md) |
| Atualização do programa assinada | **Não existe atualização automática** nesta versão |

"Sem assinatura" nunca é tratado como "malicioso": só deixa de receber o bônus de reputação.

## Privacidade

- Nenhum arquivo, hash, caminho ou dado do usuário é enviado para fora. As únicas conexões de saída são
  **downloads** de listas públicas (assinaturas, feeds) iniciados pelo usuário ou pelo CI, e o DNS da Mullvad
  quando o usuário o ativa.
- Evidências de incidentes ficam no computador (pasta de dados do antivírus), cifradas como a quarentena.
- Os relatórios exportados (HTML/JSON) contêm caminhos e nome do computador: revise antes de compartilhar.
- Não há telemetria.
