# Testes e benchmark

## Testes automatizados

`python -m pytest` — 129 testes (123 rodam no Linux; os de Windows rodam no CI do Windows). Todos usam apenas
amostras **inofensivas**: EICAR, arquivos sintéticos montados nos testes, simuladores que só se conectam a
endereços de documentação (RFC 5737) e só reescrevem arquivos que eles mesmos criaram. Nenhum malware real.

| Arquivo | Cobre |
|---|---|
| `test_engine.py` | detecção por conteúdo (nunca pelo nome), PE/ELF, macros, PDF, scripts, compactados, autoexclusão, regras sem texto puro |
| `test_hardening.py` | variantes ofuscadas, arquivos legítimos parecidos com ameaças, ReDoS, fuzzing, bancos corrompidos, configurações inválidas, proteção de arquivos/processos do sistema |
| `test_features.py`, `test_gui.py` | quarentena, Sala de Análise, recuperação, backups, interface (todas as abas) |
| `test_botnet.py` | worm, beaconing, C2, backdoor, bot disfarçado, controle negativo, firewall real |
| `test_protecoes.py` | pen drive (inserção simulada), scripts por dentro (script que se apaga, `curl \| sh`, PowerShell real no Windows), DNS local, firewall (OpenSnitch, firewalld, reinicialização), proteção ao ligar, instalação |
| `test_inteligencia.py` | confiança multi-sinal, falsos positivos (específicos, por regra, revogação), incidentes (evidências, deduplicação, exportação, revisão), inteligência (validação, rejeição de feed corrompido, adulteração local, expiração), autoproteção (histórico adulterado, configuração alterada por fora, manifesto), arquivos-isca, **ataque de ransomware simulado suspenso pela isca**, comando destrutivo disparado por programa desconhecido, benchmark |

O CI (GitHub Actions, Windows + Linux) roda os testes, o benchmark com limites, compila, testa o executável
(`--selftest`, `--selfcheck`, interface), **instala e desinstala de verdade** o instalador do Windows e testa o
AppImage.

## Benchmark reproduzível (`tools/benchmark.py`)

```bash
python tools/benchmark.py --benign 5000 --out relatorio/
```

- **Legítimos**: amostra determinística (mesma seleção a cada execução na mesma máquina) de arquivos reais do
  sistema: Python (biblioteca padrão e pacotes), `/usr/bin`, `/usr/sbin`, bibliotecas, `/usr/share/doc`, `/etc`
  (Linux); `System32`, `SysWOW64`, Arquivos de Programas (Windows). Mais arquivos legítimos que **parecem**
  ameaças (documentação com comandos, scripts de administração).
- **Ameaças**: 88 amostras sintéticas inofensivas em 3 formas (original, renomeada, dentro de ZIP).
- **Duas medições**: motor completo e **sem reputação** (sem bônus de assinatura/pacote) — a segunda mostra o
  erro das heurísticas sozinhas.
- Relatório JSON + HTML com versão, data, sistema, conjunto, metodologia, limitações e a lista de cada falso
  positivo e de cada ameaça não detectada.

### Resultados medidos (Linux, Ubuntu 24.04, 2026-11-02)

| Métrica | Linha de base (antes) | Depois desta etapa |
|---|---|---|
| Arquivos legítimos | 5 009 | 5 009 |
| Falsos positivos | 0 (0,000 %) | 0 (0,000 %) |
| Falsos positivos sem reputação | 0 (0,000 %) | 0 (0,000 %) |
| Bloqueios incorretos | 0 | 0 |
| Ameaças sintéticas detectadas | 85 / 88 (96,6 %) | 88 / 88 (100 %) |
| Precisão / F1 | 1,000 / 0,983 | 1,000 / 1,000 |
| Tempo médio por arquivo | 19,1 ms (p95 71,9 ms) | 16,7 ms (p95 66,7 ms) |
| Pico de memória | 68,5 MB | 69,4 MB |

Os números do Windows são gerados a cada envio no CI (artefato `dist/benchmark`).

### Como ler estes números (limitações)

- **100 % em ameaças sintéticas não significa 100 % contra malware real.** O conjunto mede se as regras e
  analisadores funcionam (e impede regressões), não a eficácia contra amostras em circulação.
- **0 % de falsos positivos vale para esta amostra desta máquina.** Outros computadores têm outros programas.
  Em uma varredura anterior de 199 mil arquivos foram encontrados e corrigidos 33 falsos positivos
  (`test_hardening.py::test_lookalikes_stay_clean` guarda os casos).
- **Não é comparável com AV-TEST, AV-Comparatives ou outros laboratórios**: conjuntos, configurações e
  condições diferentes. Comparações honestas exigem o mesmo conjunto de amostras, na mesma data, com a mesma
  metodologia — o caminho é submeter o produto a esses laboratórios (ver MATURIDADE.md).
- Mapeamento MITRE ATT&CK: a Sala de Análise associa evidências a técnicas; não há medição de cobertura ATT&CK
  por emulação de adversário.
