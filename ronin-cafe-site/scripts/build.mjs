// Build estático: gera dist/ com HTML, CSS/JS/fontes com hash, imagens otimizadas,
// sitemap, robots, manifest e headers de segurança para Netlify/Cloudflare/Vercel.
import { mkdir, rm, readFile, writeFile, copyFile, cp, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { processPhotos } from '../src/lib/images.mjs';
import { layout } from '../src/lib/layout.mjs';
import { site, menu, faq, analytics } from '../src/data/site.mjs';

const ROOT = path.resolve(import.meta.dirname, '..');
const OUT = path.join(ROOT, 'dist');
// Fontes já recortadas por scripts/subset-fonts.sh (subset latin, eixos limitados).
const FONTS = path.join(ROOT, 'src/fonts');

const hash = (buf) => createHash('sha256').update(buf).digest('hex').slice(0, 10);

async function emit(rel, buf) {
  const parsed = path.parse(rel);
  const name = `${parsed.name}.${hash(buf)}${parsed.ext}`;
  const out = path.join(OUT, parsed.dir, name);
  await mkdir(path.dirname(out), { recursive: true });
  await writeFile(out, buf);
  return `/${parsed.dir}/${name}`;
}

// Minificação conservadora: remove comentários e espaços redundantes.
const minCss = (css) =>
  css.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\s+/g, ' ').replace(/\s*([{}:;,>])\s*/g, '$1').replace(/;}/g, '}').trim();
const minJs = (js) => js.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('//')).join('\n');
const minHtml = (html) => html.replace(/<!--[\s\S]*?-->/g, '').replace(/\n\s+/g, '\n').replace(/\n{2,}/g, '\n');

async function main() {
  await rm(OUT, { recursive: true, force: true });
  await mkdir(OUT, { recursive: true });

  // Fontes (subset latin, woff2)
  const fontDisplay = await emit('fonts/archivo-latin-wdth.woff2', await readFile(path.join(FONTS, 'archivo-latin-wdth.woff2')));
  const fontText = await emit('fonts/newsreader-latin-wght.woff2', await readFile(path.join(FONTS, 'newsreader-latin-wght.woff2')));
  const fontItalic = await emit('fonts/newsreader-latin-italic.woff2', await readFile(path.join(FONTS, 'newsreader-latin-italic.woff2')));

  let css = await readFile(path.join(ROOT, 'src/styles/main.css'), 'utf8');
  css = css.replace('__FONT_DISPLAY__', fontDisplay).replace('__FONT_TEXT__', fontText).replace('__FONT_ITALIC__', fontItalic);
  const cssUrl = await emit('assets/main.css', Buffer.from(minCss(css)));
  const jsUrl = await emit('assets/main.js', Buffer.from(minJs(await readFile(path.join(ROOT, 'src/scripts/main.js'), 'utf8'))));
  const assets = { css: cssUrl, js: jsUrl, fontDisplay, fontText };

  await processPhotos(OUT);
  const { buildPages } = await import('../src/pages.mjs');
  const pages = buildPages();

  for (const p of pages) {
    const html = minHtml(layout({ ...p, assets }));
    const file = p.file ?? path.join(p.path, 'index.html');
    await mkdir(path.join(OUT, path.dirname(file)), { recursive: true });
    await writeFile(path.join(OUT, file), html);
  }

  // Estáticos (ícones, og image, _headers etc.)
  await cp(path.join(ROOT, 'src/static'), OUT, { recursive: true });

  const today = new Date().toISOString().slice(0, 10);
  const indexable = pages.filter((p) => !p.noindex);
  await writeFile(
    path.join(OUT, 'sitemap.xml'),
    `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${indexable
      .map((p) => `  <url><loc>${site.url}${p.path}</loc><lastmod>${today}</lastmod></url>`)
      .join('\n')}\n</urlset>\n`,
  );
  await writeFile(path.join(OUT, 'robots.txt'), `User-agent: *\nAllow: /\n\nSitemap: ${site.url}/sitemap.xml\n`);
  await writeFile(
    path.join(OUT, 'site.webmanifest'),
    JSON.stringify(
      {
        name: site.name,
        short_name: 'Ronin',
        lang: 'pt-BR',
        start_url: '/',
        display: 'browser',
        background_color: '#f2eee6',
        theme_color: '#1a1917',
        icons: [
          { src: '/icons/icon-192.png', sizes: '192x192', type: 'image/png' },
          { src: '/icons/icon-512.png', sizes: '512x512', type: 'image/png' },
          { src: '/icons/icon-maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
        ],
      },
      null,
      2,
    ),
  );

  // Headers de segurança: CSP liberando analytics só se configurado.
  const aScript = analytics.provider === 'ga4' ? ' https://www.googletagmanager.com' : analytics.provider === 'plausible' ? ' https://plausible.io' : '';
  const aConnect = analytics.provider === 'ga4' ? ' https://*.google-analytics.com https://*.analytics.google.com https://www.googletagmanager.com' : analytics.provider === 'plausible' ? ' https://plausible.io' : '';
  const csp = [
    "default-src 'self'",
    `script-src 'self'${aScript}`,
    "style-src 'self'",
    "img-src 'self' data:" + (analytics.provider === 'ga4' ? ' https://*.google-analytics.com https://www.googletagmanager.com' : ''),
    "font-src 'self'",
    `connect-src 'self'${aConnect}`,
    'frame-src https://www.google.com',
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    'upgrade-insecure-requests',
  ].join('; ');
  const security = {
    'Content-Security-Policy': csp,
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
  };
  const immutable = 'public, max-age=31536000, immutable';
  const headersFile = [
    '/*',
    ...Object.entries(security).map(([k, v]) => `  ${k}: ${v}`),
    '',
    ...['/assets/*', '/fonts/*', '/img/*'].flatMap((p) => [p, `  Cache-Control: ${immutable}`, '']),
    '/*.html',
    '  Cache-Control: public, max-age=0, must-revalidate',
    '',
  ].join('\n');
  await writeFile(path.join(OUT, '_headers'), headersFile);
  await writeFile(path.join(OUT, '_redirects'), '/menu /cardapio/ 301\n/contato /visite/ 301\n');
  await writeFile(
    path.join(ROOT, 'vercel.json'),
    JSON.stringify(
      {
        $schema: 'https://openapi.vercel.sh/vercel.json',
        buildCommand: 'npm run build',
        outputDirectory: 'dist',
        trailingSlash: true,
        cleanUrls: true,
        redirects: [
          { source: '/menu', destination: '/cardapio/', permanent: true },
          { source: '/contato', destination: '/visite/', permanent: true },
        ],
        headers: [
          { source: '/(.*)', headers: Object.entries(security).map(([key, value]) => ({ key, value })) },
          ...['assets', 'fonts', 'img'].map((d) => ({ source: `/${d}/(.*)`, headers: [{ key: 'Cache-Control', value: immutable }] })),
        ],
      },
      null,
      2,
    ) + '\n',
  );

  // Pendências: tudo que não foi confirmado.
  const pending = [
    ...menu.flatMap((s) => s.items).filter((i) => !i.price).map((i) => `preço: ${i.name}`),
    ...faq.filter((f) => !f.confirmed).map((f) => `FAQ: ${f.q}`),
  ];
  if (site.url.endsWith('.example')) console.warn('\n⚠ SITE_URL não definido: canonical/og usam https://ronincafe.example. Rode SITE_URL=https://seudominio npm run build');
  console.log(`\nBuild ok: ${pages.length} páginas em dist/. Pendências para confirmar com o dono: ${pending.length} (ver TODO.md).`);
  const files = await readdir(OUT, { recursive: true });
  console.log(`${files.length} arquivos gerados.`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
