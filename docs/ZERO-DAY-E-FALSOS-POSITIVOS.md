# Ameaças desconhecidas (zero-day) e falsos positivos

## O que o EXE Antivirus chama de "ameaça desconhecida"

Uma detecção feita por **heurística ou comportamento**, sem correspondência com malware catalogado (hash do
banco de assinaturas, ThreatFox ou EICAR). Ela é registrada como **"ameaça desconhecida em investigação"**.

O antivírus **nunca afirma que encontrou um zero-day**: isso exigiria confirmar uma vulnerabilidade ou malware
inédito, o que só uma análise humana (ou de laboratório) pode fazer. O relatório diz exatamente isso.

## Centro de incidentes (Zero-Day & Intel)

Cada detecção de qualquer proteção (tempo real, verificações, scripts, pen drives, anti-botnet,
anti-ransomware, inicialização, linha de comando) gera ou atualiza um incidente com:

| Campo | Origem |
|---|---|
| Identificador, data, sistema, computador | gerados localmente |
| SHA-256, SHA-512, SHA3-256, tipo, tamanho | calculados **antes** da quarentena |
| Origem | marca da internet do Windows (`Zone.Identifier`: URL de download, zona) ou atributo `user.xdg.origin.url` no Linux |
| Assinatura digital | Authenticode / pacote do sistema; "sem assinatura" ≠ malicioso |
| Indicadores, regras acionadas, tipos de evidência | motor de detecção / detector comportamental |
| Processo, linha de comando, usuário, cadeia de processos-pai, conexões | coletados enquanto o processo ainda existe |
| Confiança e classificação | ver abaixo |
| Ações executadas, cadeia de eventos, ocorrências | cada repetição soma ao mesmo incidente |
| Evidência preservada | cópia neutralizada (cifrada) ou referência à quarentena |
| Resultado da análise e revisão | texto do motor + decisão do usuário |

**Classificação**: informativo · suspeito · alto risco · crítico. **Status**: em investigação · ameaça confirmada ·
falso positivo · resolvido.

**Confiança**: `confirmada` (hash/EICAR) · `alta` (malicioso com 3+ tipos independentes de evidência) · `média`
(2 tipos ou 1 evidência crítica muito específica) · `baixa` (1 tipo). Contenção automática (quarentena,
encerrar processo) só acontece com veredito **malicioso**; "suspeito" apenas alerta.

**Alertas sem repetição**: o mesmo conteúdo (SHA-256) ou comportamento aberto não gera notificação nova — soma
ocorrências ao incidente existente. A notificação só aparece para incidente **novo**, desconhecido e de
**alto risco/crítico**.

Exportação: HTML (para leitura) e JSON (para outras ferramentas), de um incidente, da seleção ou de todos.
Busca por arquivo, ameaça, SHA-256 ou identificador, com filtros de classificação, status e "só desconhecidas".

## Falsos positivos

Princípios aplicados no motor:

- nunca bloquear por nome, extensão, linguagem, ausência de assinatura, entropia alta ou pasta temporária
  **sozinhos** (evidências estruturais somam no máximo 30 pontos; o limite de "malicioso" é 70);
- reputação (Authenticode / pacote do sistema) reduz a pontuação; documentação/artigos ficam no máximo "suspeito";
- comandos administrativos destrutivos isolados (ex.: `vssadmin delete shadows`) são "suspeitos"; só viram
  "maliciosos" com um segundo sinal independente (disparados por programa sem origem verificável).

### Marcar como falso positivo

Em Zero-Day & Intel → Incidentes → "Falso positivo…":

1. motivo obrigatório (fica registrado);
2. escopo: **só as regras que dispararam** (recomendado: outras evidências continuam valendo) ou **o arquivo
   inteiro**;
3. a exclusão vale para o **conteúdo exato (SHA-256)** — se o arquivo mudar (por exemplo, for infectado), a
   exclusão deixa de valer; nunca vale para uma pasta ou para outros arquivos;
4. se o arquivo estava na quarentena, o programa oferece restaurá-lo.

Malware catalogado (hash) e EICAR não podem ser marcados como falso positivo.

A aba "Falsos positivos" mostra todas as decisões (com data, regras, pontuação, veredito e motivo), permite
**revogar** (o registro é mantido) e lista **as regras que mais erraram**, para orientar ajustes no motor.

## Métricas

Medidas por `tools/benchmark.py` (ver `TESTES-E-BENCHMARK.md`): taxa de falsos positivos, precisão, recall,
F1, taxa de detecção, taxa de bloqueios incorretos, tempo médio por arquivo e até a detecção. O CI falha se a
taxa de falsos positivos passar de 1 % ou a detecção cair abaixo de 95 %.
