# Site do Gaba Burger

Site institucional da hamburgueria **Gaba Burger**, Rua Mourato Coelho, 833, Pinheiros, São Paulo.

Stack: React 19 + TypeScript + Tailwind CSS 4 + Vite. Cada página é **pré-renderizada em HTML estático** no build
(SEO e carregamento rápido) e depois hidratada no navegador. Não há backend, banco de dados, formulário, cookie ou
analytics.

```bash
npm install
npm run dev          # desenvolvimento em http://localhost:5173
SITE_URL=https://www.seudominio.com.br npm run build   # gera dist/
npm run check        # testes automatizados no build (Playwright)
npm run photos       # otimiza fotos reais (ver abaixo)
npm run assets       # regera og-image.png e ícones
```

## Fotos: o que falta fazer

**Nenhuma foto do restaurante está no site ainda.** Os sites com fotos reais (Google Maps, Instagram, Tripadvisor,
iFood, YouTube, TikTok) estavam bloqueados no ambiente de desenvolvimento, e a regra do projeto proíbe foto
inventada, de banco de imagens ou gerada por IA. Cada espaço de foto mostra uma composição gráfica (marcas de grelha
+ texto) que não se passa por fotografia.

Para colocar as fotos:

1. Salve as fotos reais em `photos/originais/` (ex.: `fachada.jpg`, `gaba-melt.jpg`).
2. Rode `npm run photos`. O script gera AVIF e WebP em 640/1280/1920 px em `public/fotos/` e remove metadados
   (GPS, câmera).
3. Cole as linhas impressas em `src/data/photos.ts`, escreva um `alt` descritivo e escolha a `category`.
   - `hero`: foto principal do topo (vertical 4:5 fica melhor no arco).
   - `about` e `aboutDetail`: ambiente e detalhe na seção Sobre.
   - `menu["gaba-melt"]` etc.: foto de cada burger no card.
   - `gallery`: lista da galeria (lightbox abre ao clicar). Use fotos diferentes das outras seções.

Fotos do Google Maps e do Tripadvisor geralmente são de clientes e têm direitos autorais. Use fotos do próprio
restaurante ou peça autorização ao autor (há um campo `credit` para o crédito).

## Antes de publicar

- Defina `SITE_URL` (domínio próprio) no build: sem ele não são gerados `canonical`, `og:url`, `sitemap.xml` nem a
  URL absoluta da imagem de compartilhamento.
- Hospede com HTTPS. Os cabeçalhos de segurança e cache já estão prontos em `public/_headers` (Netlify, Cloudflare
  Pages) e `vercel.json` (Vercel). Em outro servidor, copie os mesmos cabeçalhos.
- Configure a hospedagem para servir `404.html` em endereços inexistentes (Netlify, Cloudflare e Vercel fazem isso
  sozinhos).
- Cadastre o domínio no Google Search Console e envie o `sitemap.xml`.
- Revise os textos de `privacidade/` e `termos/` com quem cuida da parte jurídica.
- Confira os preços no iFood. Para mostrar preço no card, preencha `price` em `src/data/site.ts`.

## Onde editar

| O quê | Arquivo |
| --- | --- |
| Endereço, telefone, links, cardápio, FAQ | `src/data/site.ts` |
| Horários | `src/data/hours.ts` |
| Fotos | `src/data/photos.ts` |
| Cores e fontes | `src/styles.css` (bloco `@theme`) |
| Título e descrição de cada página | `index.html`, `privacidade/index.html`, `termos/index.html`, `404.html` |

## Checklist final

Legenda: ✅ feito e verificado · ⚠️ depende de ação externa · ➖ não se aplica

### Conteúdo e regras do projeto

| Requisito | Status | Observação |
| --- | --- | --- |
| Layout baseado no site de referência (arco, título serifado gigante, selo girado, status aberto/fechado, nota) | ✅ | Paleta, textos e identidade trocados para o Gaba |
| Fotos reais do restaurante | ⚠️ | Não foi possível baixar: sites bloqueados no ambiente. Espaços reservados + script de otimização prontos |
| Nenhuma foto falsa, de IA ou genérica | ✅ | Zero fotos no site; só composições tipográficas |
| Cardápio sem preço inventado | ✅ | "Preço no iFood" até o campo `price` ser preenchido |
| Pineapple Burger não aparece como disponível | ✅ | "Edição limitada. Disponibilidade não confirmada." |
| Horários com aviso de que podem mudar | ✅ | Status aberto/fechado calculado no fuso de São Paulo |
| Nota 4,8 e 272 avaliações | ✅ | Valor informado pelo cliente, com link para o Google Maps. Atualize em `site.ts` quando mudar |
| Logotipo oficial | ⚠️ | Não encontrado. Usado um wordmark tipográfico "Gaba Burger." até receber o logo real |
| Sem gradiente roxo, neon, emoji como ícone, botão pílula, animação de cursor, selo "feito com IA", contadores ou métricas falsas, avaliações falsas, travessão (—) | ✅ | Ícones SVG próprios; o teste automatizado procura travessões |
| Sem excesso de animação | ✅ | Só revelação discreta ao rolar; desligada com "reduzir movimento" |

### Funcionalidades

| Requisito | Status |
| --- | --- |
| Menu com rolagem suave e destaque da seção atual | ✅ |
| Menu mobile (Esc fecha, foco preso no painel, fecha ao navegar) | ✅ |
| Botões com destino real (iFood, Google Maps, rota, telefone, Instagram, TikTok) | ✅ |
| Galeria com lightbox (setas do teclado, deslizar no celular, Esc, foco) | ✅ testada com imagens temporárias; aparece quando houver fotos |
| Mapa do Google (carrega ao clicar, por privacidade e desempenho) + "Abrir no Google Maps" | ✅ |
| Barra fixa no celular: "Pedir no iFood" e "Como chegar" | ✅ |
| FAQ, página 404 própria, política de privacidade, termos de uso, trilha de navegação nas páginas internas | ✅ |
| Sistema de pedido, pagamento ou reserva | ➖ não existe; tudo leva ao iFood ou ao telefone |
| Página de agradecimento | ➖ não há formulário |
| Google Analytics | ⚠️ não instalado: precisa de ID da conta e de aviso de cookies (LGPD) |

### SEO

| Requisito | Status |
| --- | --- |
| Título único e meta description por página, `lang="pt-BR"` | ✅ |
| Um único `h1` por página e hierarquia de títulos sem saltos | ✅ |
| Open Graph + Twitter Card + imagem de compartilhamento 1200×630 | ✅ |
| Favicon SVG/PNG, apple-touch-icon, manifest | ✅ |
| Dados estruturados `Restaurant` (endereço, telefone, horários, cardápio, redes) e `BreadcrumbList` | ✅ sem nota de avaliação (o Google não exibe nota autodeclarada) |
| `robots.txt`, `sitemap.xml`, `canonical` | ✅ gerados quando `SITE_URL` é definido |
| `noindex` só na página 404 | ✅ |
| Domínio próprio, Search Console | ⚠️ ação do dono |

### Desempenho e acessibilidade

| Requisito | Status |
| --- | --- |
| Lighthouse mobile (servidor com gzip e cache): Desempenho 97, Acessibilidade 100, Boas práticas 100, SEO 100 | ✅ |
| CLS 0, LCP 2,4 s no mobile simulado | ✅ |
| Fontes auto-hospedadas, pré-carregadas, só os subconjuntos usados | ✅ |
| Imagens em AVIF/WebP, `srcset`, `loading="lazy"` fora da primeira dobra, largura e altura fixas | ✅ (script `npm run photos`) |
| Cache longo para `/assets/*` com nome versionado | ✅ |
| Link "pular para o conteúdo", foco visível, textos alternativos, contraste AA | ✅ |
| Sem rolagem horizontal nem texto cortado em 360, 390, 768, 1280 e 1920 px | ✅ teste automatizado |

### Segurança

Análise feita sobre o código e o build. O site é estático, sem servidor próprio, por isso vários itens
das listas de referência não se aplicam.

| Requisito | Status | Como |
| --- | --- | --- |
| Proteção contra XSS | ✅ | React escapa todo texto; nenhum `innerHTML`, `dangerouslySetInnerHTML`, `eval` ou `new Function`. JSON-LD escapa `<` |
| Content Security Policy | ✅ | `default-src 'self'`, sem `unsafe-inline`/`unsafe-eval`; só `www.google.com` em `frame-src` (mapa). Meta tag + cabeçalho |
| Cabeçalhos de segurança | ✅ | HSTS, `X-Content-Type-Options`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, `Permissions-Policy`, COOP |
| HTTPS obrigatório | ✅ | HSTS + `upgrade-insecure-requests` (vale ao hospedar com HTTPS) |
| Links externos protegidos | ✅ | Componente `ExternalLink`: `rel="noopener noreferrer"` e só aceita `https:`/`tel:` |
| Parâmetros de URL controlando HTML | ✅ | O site não lê parâmetros de URL |
| Chaves de API, tokens, segredos no código ou no git | ✅ | Nenhum. Mapa usa a incorporação pública do Google, sem chave. `.env` ignorado no git |
| Variáveis de ambiente | ✅ | Só `SITE_URL`, usada no build e validada (rejeita valor fora do formato `https://dominio`) |
| Arquivos expostos | ✅ | Sem source maps no build; `dist/` só tem o necessário |
| Modo debug desligado | ✅ | Build de produção, sem `console.log` |
| Dependências atualizadas e mínimas | ✅ | 4 dependências de produção (react, react-dom, 2 fontes); `npm audit`: 0 vulnerabilidades |
| Dados sensíveis armazenados | ✅ | Nenhum: sem cookies, `localStorage` ou formulários |
| Iframe do mapa isolado | ✅ | `sandbox`, carregado só após clique |
| Validação/sanitização de formulários, SQL injection, hash de senha, autenticação, rotas de admin, CORS, rate limiting, acesso ao banco | ➖ | Não há formulário, login, API nem banco. Se um dia houver, isso precisa ser feito no servidor |

Verificação: `npm run build && npm run check` roda 69 testes (console sem erros nem violação de CSP, links,
âncoras, menu mobile, mapa, FAQ, galeria, títulos, travessões, responsividade em 5 tamanhos de tela).
