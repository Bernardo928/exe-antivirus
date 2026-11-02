# Relatório de maturidade técnica — EXE Antivirus 1.1.0

Data: 2026-11-02. Escala qualitativa (avaliação de engenharia, não medição): **1** inicial · **2** básico ·
**3** funcional e testado · **4** robusto, medido e endurecido · **5** nível dos líderes de mercado.

Referência honesta: produtos como Bitdefender, ESET, Kaspersky e Microsoft Defender têm drivers de kernel,
nuvem de reputação com bilhões de amostras, aprendizado de máquina treinado em escala, equipes de pesquisa e
certificação contínua em laboratórios independentes. O EXE Antivirus **não tem** esses componentes; a
comparação abaixo mostra onde ele está e o que falta.

| Área | Nível | Evidência | O que falta para subir |
|---|---|---|---|
| Detecção por conteúdo/estrutura | 3 | 73 regras, PE/ELF/Office/PDF/scripts, desofuscação; 100 % do conjunto sintético; regressões travadas no CI | Regras YARA da comunidade, modelo de ML treinado, nuvem de reputação, amostras reais em laboratório isolado |
| Ameaças desconhecidas (zero-day) | 3 | Centro de incidentes com evidências, confiança multi-sinal, revisão e exportação | Perfis de comportamento por máquina (linha de base estatística), sandbox de execução isolada |
| Falsos positivos | 4 | 0 FP em 5 009 arquivos reais (com e sem reputação); 33 FP reais corrigidos antes; exclusões por SHA-256 auditáveis; limite no CI | Corpus legítimo maior e variado (milhares de instaladores Windows), telemetria opcional consentida de FP |
| Tempo real / processos | 3 | Arquivos, processos, linha de comando, ferramentas do sistema, cadeia de execução | Callbacks de kernel (minifilter / ETW / eBPF) para ver tudo, sem amostragem de 1,5 s |
| Anti-ransomware | 3 | Iscas com reação imediata (ataque simulado suspenso no teste), cifragem em massa, comandos de backup | Pastas protegidas com bloqueio de escrita por driver, cópias de segurança automáticas antes de alteração |
| Scripts | 3 | PowerShell decodificado pelo Windows, scripts que se apagam, `curl \| sh` | Provedor AMSI registrado (DLL COM), leitura do pipe no Linux |
| Rede / botnet / web | 3 | Comportamento por processo, C2 de feeds, firewall (6 mecanismos), DNS Mullvad, domínios maliciosos no DNS local | Inspeção de tráfego/TLS, proteção de navegador (extensão), anti-phishing por conteúdo de página |
| Inteligência de ameaças | 3 | 4 feeds validados, versionados, com expiração e detecção de adulteração | Feeds assinados, CERT.br, deduplicação entre fontes com pontuação de confiança por fonte |
| Criptografia / confiança | 2 | Authenticode, SHA-256/512/SHA3, manifesto de integridade | GPG/Sigstore/cosign para pacotes e regras, revogação de certificados própria, SHA-256 dos pacotes Linux (não MD5) |
| Autoproteção | 2–3 | Integridade dos arquivos, configuração, histórico e quarentena; nunca encerra a si mesmo | Serviço protegido (PPL/ELAM no Windows), IPC autenticado entre serviço e interface, logs assinados |
| Atualizações | 1 | Atualização de assinaturas e feeds; **sem** atualização do programa | Canal de atualização assinado, com reversão |
| Desempenho | 3 | 16,7 ms/arquivo, ~70 MB, processos paralelos, cache, prioridade baixa | Limite configurável de CPU/RAM, varredura em ociosidade, modo jogo |
| Testes e reprodutibilidade | 4 | 129 testes, CI Windows+Linux com instalação real, benchmark com limites e relatório | Corpus de malware real em laboratório isolado e autorizado, testes AMTSO |
| Interface / transparência | 3 | Uma aba por função, dados reais, motivo de cada detecção, relatórios | Acessibilidade, tradução, auditoria de UX com usuários |

## Funcionalidades ainda pendentes

1. Atualização automática do programa com pacotes assinados (Sigstore/cosign ou GPG) e reversão.
2. Verificação de assinatura GPG/Sigstore de regras e assinaturas distribuídas pelo projeto.
3. Limites configuráveis de CPU/RAM para as varreduras.
4. Perfis de comportamento por máquina (detecção de anomalias com linha de base aprendida).
5. Execução dinâmica em sandbox isolada para a Sala de Análise.
6. Componentes de kernel (minifilter/ETW no Windows, eBPF/fanotify no Linux) para eliminar a amostragem.
7. Provedor AMSI e proteção de navegador.
8. CERT.br e outras fontes nacionais (sem feed de IOCs legível por máquina identificado até agora).
9. Submissão a laboratórios independentes (AV-TEST, AV-Comparatives) e checagem AMTSO.

## Riscos conhecidos

- Processo com privilégio de administrador pode desativar ou adulterar o antivírus (sem componente de kernel).
- Ações que duram menos que o intervalo de amostragem (1,5 s processos, 2 s rede) podem passar.
- Feeds externos não são assinados pelos publicadores; um publicador comprometido poderia distribuir
  indicadores falsos (mitigado: validação, domínios essenciais nunca bloqueados, IPs locais descartados).
- No Linux, a confiança em binários do sistema usa o MD5 registrado pelo dpkg.
- O conjunto de ameaças do benchmark é sintético; a eficácia contra malware real **não foi medida**.
