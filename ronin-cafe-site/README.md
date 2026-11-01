# Site do Ronin Café

Site estático do Ronin Café (Rua das Palmeiras, 420, Santa Cecília, São Paulo). HTML e CSS gerados por um script Node, cerca de 2 KB de JavaScript, sem framework.

- `RESEARCH.md`: tudo o que se sabe da casa, com fonte.
- `DESIGN.md`: direção de arte, tokens e componentes.
- `PERFORMANCE.md`: Lighthouse antes e depois.
- `TODO.md`: o que falta confirmar com o dono. **Leia antes de publicar.**

## Rodar

Requer Node 20 ou mais novo.

```bash
npm install
npm run build          # gera dist/ (a primeira vez demora uns 4 min por causa do AVIF; depois usa cache)
npm run serve          # http://localhost:4173, com os mesmos headers do host
npm run check          # links quebrados, h1 único, travessão, emoji, noindex, console.log
```

Variáveis do build:

| Variável | Para quê |
|---|---|
| `SITE_URL` | Domínio oficial, usado em canonical, og:image, sitemap e JSON-LD. Ex.: `https://ronincafe.com.br` |
| `ANALYTICS_PROVIDER` | `ga4` ou `plausible`. Vazio = sem analytics e sem aviso de cookies |
| `GA4_ID` | ID do GA4 (`G-XXXXXXX`) |
| `PLAUSIBLE_DOMAIN` | Domínio cadastrado no Plausible |

O analytics só carrega depois que a pessoa clica em "Permitir" (LGPD). A CSP libera os domínios do provedor escolhido automaticamente.

## Onde mexer

| Quero mudar | Arquivo |
|---|---|
| Horário, endereço, cardápio, preços, FAQ, avaliações | `src/data/site.mjs` |
| Textos das páginas | `src/pages.mjs` |
| Cabeçalho, rodapé, meta tags, JSON-LD | `src/lib/layout.mjs` |
| Visual | `src/styles/main.css` (tokens no topo) |
| Fotos e textos alternativos | `assets/photos/original/` e `src/lib/images.mjs` |

Itens com `confirmed: false` ou `price: null` não aparecem no site.

**Fotos novas**: só fotos reais do Ronin. Coloque o JPEG em `assets/photos/original/`, registre em `src/lib/images.mjs` com `crop` e `alt` e rode o build. O script gera AVIF, WebP e JPEG em 400, 800 e 1200 px.

**Ícones e og:image** (só se a marca mudar): `npm run icons` (usa o Chromium do Playwright).
**Fontes**: já recortadas em `src/fonts/`. Para refazer: `pip install fonttools brotli && ./scripts/subset-fonts.sh`.

## Publicar

O build gera `dist/_headers` e `dist/_redirects` (Netlify e Cloudflare Pages) e `vercel.json` (Vercel), com CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, frame-ancestors e cache longo para os arquivos com hash.

### Cloudflare Pages
1. Conecte o repositório. Diretório raiz: `ronin-cafe-site`.
2. Comando de build: `npm run build`. Saída: `dist`.
3. Variáveis: `SITE_URL` (e as de analytics, se usar). `NODE_VERSION=20`.

### Netlify
Base directory `ronin-cafe-site`, build `npm run build`, publish `ronin-cafe-site/dist`. Mesmas variáveis.

### Vercel
Root directory `ronin-cafe-site`. O `vercel.json` já define build, saída e headers.

### Domínio próprio e HTTPS
1. No painel do host, adicione o domínio (ex.: `ronincafe.com.br` e `www`).
2. No registro do domínio (Registro.br), aponte o DNS conforme o host indicar (CNAME para `www`, A/ALIAS para a raiz).
3. **Forçar HTTPS**: Cloudflare, em SSL/TLS, ative "Always Use HTTPS" e o modo "Full (strict)". Netlify, em Domain management > HTTPS, ative "Force HTTPS". Na Vercel, o redirecionamento para HTTPS já é automático.
4. O header HSTS já vai com `preload`. Depois de uma semana com HTTPS funcionando em todos os subdomínios, cadastre em https://hstspreload.org. Se algum subdomínio ainda não tiver HTTPS, tire `includeSubDomains; preload` do `scripts/build.mjs` antes.
5. Refaça o build com `SITE_URL` apontando para o domínio final.

### Google Search Console
1. Em https://search.google.com/search-console, adicione uma propriedade "Domínio" e valide pelo registro TXT no DNS.
2. Em Sitemaps, envie `https://seudominio/sitemap.xml`.
3. Use "Inspeção de URL" na home para pedir indexação.
4. No Google Business Profile do Ronin, coloque a URL do site e o link do cardápio (`/cardapio/`).

## Segurança

- Sem formulários, sem backend, sem cookies próprios. Única chave salva no navegador: a escolha de cookies (`ronin-consent`), e só quando o analytics está ligado.
- CSP sem `unsafe-inline`. O mapa do Google só é criado no clique, e o script confere se a URL é do Google Maps.
- `npm audit`: 0 vulnerabilidades. Dependências só de build: `sharp` e duas fontes do Fontsource.
- `dist/` não tem `.env`, `.git` nem source maps (o `npm run check` reprova se tiver).
- Histórico do git verificado: nenhum segredo.

## Créditos

Ícones: [Lucide](https://lucide.dev) (ISC). Fontes: Archivo e Newsreader (SIL Open Font License), via Fontsource.
