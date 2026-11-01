# Performance

Lighthouse 12.8.2 com o Chromium do Playwright (`--headless=new --no-sandbox`), servidor local com gzip e os mesmos headers do host (`scripts/serve.mjs`). Medido em 01/11/2026.

- **Celular**: `--form-factor=mobile`, throttling simulado (Slow 4G, CPU 4x mais lenta), configuração padrão do Lighthouse.
- **Desktop**: `--preset=desktop`.

Ordem das notas: Performance, Acessibilidade, Boas práticas, SEO.

## Antes (sem otimização)

`scripts/make-baseline.mjs` gera o mesmo site sem as otimizações de mídia: JPEG original (cerca de 1 MB cada), sem AVIF/WebP, sem `srcset`, sem preload, sem `width`/`height` e sem lazy load.

| Página (celular) | Notas | LCP | CLS | TBT | FCP | Peso |
|---|---|---|---|---|---|---|
| Home | 72 / 100 / 100 / 100 | 24,5 s | 0 | 160 ms | 1,8 s | 4.428 KB |
| Cardápio | 74 / 100 / 100 / 100 | 13,8 s | 0,041 | 0 ms | 1,8 s | 2.432 KB |
| Visite | 98 / 100 / 100 / 100 | 2,0 s | 0,001 | 0 ms | 1,8 s | 165 KB |

## Depois

| Página (celular) | Notas | LCP | CLS | TBT | FCP | Peso |
|---|---|---|---|---|---|---|
| Home | 99 / 100 / 100 / 100 | 2,0 s | 0 | 0 ms | 0,8 s | 258 KB |
| Cardápio | 100 / 100 / 100 / 100 | 1,8 s | 0 | 0 ms | 0,8 s | 210 KB |
| Sobre | 100 / 100 / 100 / 100 | 1,8 s | 0 | 0 ms | 1,1 s | 182 KB |
| Visite | 100 / 100 / 100 / 100 | 1,7 s | 0 | 0 ms | 0,8 s | 105 KB |
| Privacidade | 100 / 100 / 100 / 100 | 1,5 s | 0 | 0 ms | 0,8 s | 103 KB |
| Termos | 100 / 100 / 100 / 100 | 1,5 s | 0 | 0 ms | 0,8 s | 103 KB |

| Página (desktop) | Notas | LCP | CLS | TBT |
|---|---|---|---|---|
| Home | 100 / 100 / 100 / 100 | 0,5 s | 0 | 0 ms |
| Cardápio | 100 / 100 / 100 / 100 | 0,4 s | 0 | 0 ms |
| Sobre | 100 / 100 / 100 / 100 | 0,4 s | 0 | 0 ms |
| Visite | 100 / 100 / 100 / 100 | 0,4 s | 0 | 0 ms |
| Privacidade | 100 / 100 / 100 / 100 | 0,4 s | 0 | 0 ms |
| Termos | 100 / 100 / 100 / 100 | 0,4 s | 0 | 0 ms |

A nota de performance da home no celular oscilou entre 97 e 100 nas rodadas (LCP de 1,5 s a 2,6 s), por variação da simulação. Meta: 95+, LCP < 2,5 s, CLS < 0,1, INP < 200 ms (o site quase não tem JS; TBT ficou em 0 ms).

## O que foi feito (na ordem em que mexeu no número)

1. **Imagens**: AVIF/WebP/JPEG em 400, 800 e 1200 px com `srcset`/`sizes`; recorte das faixas pretas dos prints; `width`/`height` em todas (CLS 0); lazy load fora da dobra. Home: 4,4 MB para 258 KB.
2. **LCP no celular**: o elemento LCP é o parágrafo de abertura, não a foto (ela fica abaixo da dobra no celular). Ele esperava as fontes. Correções:
   - preload das duas fontes;
   - preload da foto do hero só no desktop (`media="(min-width: 900px)"`), e a foto lazy no celular, para não disputar banda com as fontes;
   - fontes recortadas com fonttools (`scripts/subset-fonts.sh`): eixos limitados ao que o site usa e só os caracteres latinos. Archivo de 88 KB para 48 KB, Newsreader de 57 KB para 36 KB. A itálica (21 KB) só baixa na página Sobre.
   - Resultado: LCP de 2,6 s para 1,5 a 2,0 s.
3. **CSS e JS**: um CSS de 5 KB e um JS de 2 KB (gzip), com hash no nome e `Cache-Control: immutable`. Nada de framework.
4. **Terceiros**: zero requisições externas no carregamento. O mapa do Google só carrega no clique; o analytics, só depois do consentimento.

## Como medir de novo

```bash
npm run build && npm run serve &
CHROME_PATH=/opt/pw-browsers/chromium-1243/chrome-linux64/chrome \
  npx lighthouse@12 http://localhost:4173/ --form-factor=mobile \
  --chrome-flags="--headless=new --no-sandbox" --view
```

Antes/depois: `node scripts/make-baseline.mjs && node scripts/serve.mjs dist-baseline 4174`.
