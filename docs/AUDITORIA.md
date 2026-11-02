# Auditoria técnica do EXE Antivirus

Data: 2026-11-02 · versão auditada: 1.1.0 (commit `14dcfb5`) · auditor: revisão de código + testes executados.

Regra seguida: uma funcionalidade só conta como existente se foi **executada e verificada** (teste automatizado,
teste ao vivo ou medição). Ter uma classe ou um botão com o nome não basta.

## Como a auditoria foi feita

1. Leitura de todos os módulos (`exeav/`, ~9 mil linhas), regras (`rules/rules_src.py`), testes e CI.
2. Medição de base com o laboratório de benchmark novo (`tools/benchmark.py`), **antes** de qualquer mudança:
   5 009 arquivos legítimos reais do sistema + 88 ameaças sintéticas inofensivas.
3. Revisão dos caminhos de ação (o que acontece de verdade quando algo é detectado).

### Resultado da medição de base (antes das mudanças)

| Métrica | Valor |
|---|---|
| Falsos positivos (5 009 arquivos legítimos) | 0 (0,000 %) — também 0 sem o bônus de reputação |
| Detecção (88 ameaças sintéticas) | 85 (96,6 %) |
| Ameaças não detectadas | shell reverso em Python escrito em várias linhas (3 variantes) |
| Tempo médio por arquivo | 19,1 ms (p95 71,9 ms) |
| Pico de memória | 68,5 MB |

## Matriz de auditoria

| Módulo | Estado encontrado | Problema | Prioridade | Situação após esta etapa |
|---|---|---|---|---|
| Detecção (motor) | Funcional: 73 regras por conteúdo, PE/ELF/OLE/OOXML/PDF/RTF/LNK, desofuscação em camadas, hashes | Shell reverso Python multilinha passava (achado pelo benchmark) | Alta | **Corrigido** e coberto por teste/benchmark |
| Zero-day | Heurísticas e comportamento existiam, mas sem registro, evidências, confiança ou revisão | Ameaça desconhecida virava só uma linha no histórico | Crítica | **Implementado**: centro de incidentes com evidências, confiança multi-sinal, revisão e exportação |
| Anti-ransomware | Detecção de cifragem em massa + identificação do processo por E/S | (1) `vssadmin/wbadmin/bcdedit` rodados direto (sem interpretador) **não eram analisados**; (2) reação só depois de 10+ arquivos cifrados | Crítica | **Corrigido**: linha de comando de ferramentas do sistema analisada, cadeia de execução como 2º sinal, arquivos-isca com reação imediata |
| Falsos positivos | 0 FP medido; reputação Authenticode/dpkg | Exclusões só por **caminho** e **globais**; sem registro de decisão, justificativa, revisão ou métricas | Crítica | **Implementado**: exclusão por SHA-256 (arquivo ou regras), justificada, auditável, revogável; estatística por regra; benchmark com FPR/precisão/recall/F1 no CI |
| Confiança da detecção | Pontuação somada | Um único indicador forte bastava, sem informar a confiança | Alta | **Implementado**: nível de confiança por tipos independentes de evidência |
| Proteção web | DNS da Mullvad (DoH/DoT/servidor local) + hosts | Sem lista própria de domínios maliciosos | Alta | **Implementado**: domínios URLhaus/ThreatFox bloqueados no DNS local e usados pelo motor |
| Inteligência de ameaças | Feodo (C2) e MalwareBazaar (hash) baixados por HTTPS | Sem validação de conteúdo, versão, expiração, histórico ou detecção de corrupção | Alta | **Implementado** para Feodo, URLhaus, ThreatFox, CISA KEV |
| Autoproteção | Nunca analisa/encerra a si mesmo nem processos críticos; quarentena cifrada | Sem verificação de integridade dos próprios arquivos, das configurações ou do histórico | Crítica | **Implementado**: manifesto SHA-256 da instalação, detecção de configuração alterada por fora (com restauração), histórico encadeado por hash, verificação da quarentena |
| Atualizações do programa | Inexistente | Não há atualização automática nem pacotes assinados | Alta | **Pendente** (ver MATURIDADE.md) |
| Assinaturas digitais | Authenticode (WinVerifyTrust + catálogo); dpkg (MD5 do pacote) | Sem GPG/Sigstore/cosign; sem checagem de revogação própria; MD5 no Linux é fraco | Média | Parcial — documentado; SHA-256/512/SHA3-256 nos incidentes |
| Anti-botnet | Funcional (testes ao vivo) | Só lista própria de C2 | Média | + IPs de C2 da inteligência |
| Pen drives | Funcional | Relatório por dispositivo só em memória | Média | Incidentes persistidos com o dispositivo |
| Desempenho | Processos paralelos, cache incremental, prioridade baixa em segundo plano | Sem limite de RAM configurável | Média | Threads configuráveis; limite de RAM **pendente** |
| Instalação/desinstalação | Instalador .exe e AppImage testados no CI | Teste do Windows quebrava com chave `Run` ausente | Alta | **Corrigido** |
| Testes | 103 testes + CI Windows/Linux | Sem métricas de eficácia | Alta | 123 testes + benchmark com limites no CI |

## Vulnerabilidades da própria aplicação revisadas

| Item | Situação |
|---|---|
| Expressões regulares com retrocesso catastrófico (ReDoS) | Já mitigado (quantificadores possessivos + teste) |
| Arquivos malformados derrubando o analisador | Já mitigado (fuzzing + processo isolado) |
| Feed externo adulterado bloqueando sites essenciais | **Mitigado agora**: lista de domínios que nunca são bloqueados, IPs locais descartados |
| Arquivo local de inteligência adulterado | **Mitigado agora**: soma de verificação, arquivo ignorado se não conferir |
| Malware desligando a proteção editando `settings.json` | **Detectado agora** (autoproteção) com restauração |
| Apagar rastros no histórico | **Detectado agora** (encadeamento por hash + cabeça gravada à parte) |
| Exclusão de pasta inteira usada para esconder malware | Exclusões novas são por conteúdo; exclusões por pasta antigas continuam funcionando (compatibilidade) |
| Arquivo malformado derrubando o processo de análise fazia a varredura **descartar outros arquivos** em análise ao mesmo tempo (inclusive ameaças) — falha intermitente, ~30 % das execuções do teste de estresse | **Corrigido** (achado pelo CI): reanálise isolada por arquivo + limpeza dos processos lida antes do encerramento; 0 falhas em 40 execuções; a varredura agora registra cada arquivo ignorado e o motivo |
| Banco SQLite "em uso" (vários processos abrindo ao mesmo tempo) era tratado como **corrompido** e renomeado — decisões do usuário podiam sumir | **Corrigido**: só corrupção real recria o banco; "em uso" espera e tenta de novo; falha no banco de exclusões nunca desliga a detecção |
| Processo com privilégio de administrador adulterando o antivírus | **Não mitigável sem componente de kernel** — documentado |
