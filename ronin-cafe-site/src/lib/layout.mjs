import { site, hours, hoursShort, analytics } from '../data/site.mjs';
import { icon } from './icons.mjs';

export const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const nav = [
  { href: '/cardapio/', label: 'Cardápio' },
  { href: '/sobre/', label: 'Sobre' },
  { href: '/visite/', label: 'Visite' },
];

export function localBusinessSchema() {
  const open = hours.filter((h) => h.open);
  return {
    '@context': 'https://schema.org',
    '@type': 'CafeOrCoffeeShop',
    '@id': `${site.url}/#cafe`,
    name: site.name,
    url: `${site.url}/`,
    image: [`${site.url}/og/ronin-cafe-og.jpg`],
    description: 'Cafeteria de cozinheiros em Santa Cecília, São Paulo, conhecida pelo queijo quente com caramelo de alho.',
    address: {
      '@type': 'PostalAddress',
      streetAddress: site.address.streetFull,
      addressLocality: site.address.city,
      addressRegion: site.address.state,
      postalCode: site.address.postalCode,
      addressCountry: site.address.country,
    },
    geo: { '@type': 'GeoCoordinates', latitude: site.geo.lat, longitude: site.geo.lng },
    hasMap: site.links.maps,
    openingHoursSpecification: [
      {
        '@type': 'OpeningHoursSpecification',
        dayOfWeek: open.map((h) => h.schema),
        opens: open[0].open,
        closes: open[0].close,
      },
    ],
    priceRange: site.priceRangeSchema,
    servesCuisine: ['Café', 'Lanches', 'Brunch'],
    hasMenu: `${site.url}/cardapio/`,
    founder: site.founders.map((name) => ({ '@type': 'Person', name })),
    sameAs: [site.instagram],
  };
}

export function breadcrumbs(items) {
  const all = [{ name: 'Início', href: '/' }, ...items];
  const html = `<nav class="crumbs wrap" aria-label="Você está em">
  <ol>${all
    .map((c, i) =>
      i === all.length - 1
        ? `<li><span aria-current="page">${esc(c.name)}</span></li>`
        : `<li><a href="${c.href}">${esc(c.name)}</a>${icon('chevronRight', { size: 14 })}</li>`,
    )
    .join('')}</ol>
</nav>`;
  const schema = {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: all.map((c, i) => ({ '@type': 'ListItem', position: i + 1, name: c.name, item: `${site.url}${c.href}` })),
  };
  return { html, schema };
}

const ld = (obj) => `<script type="application/ld+json">${JSON.stringify(obj).replace(/</g, '\\u003c')}</script>`;

export function layout({ path, title, description, body, assets, preload = '', schemas = [], ogImage = '/og/ronin-cafe-og.jpg', noindex = false }) {
  const canonical = `${site.url}${path}`;
  const fullTitle = path === '/' ? title : `${title} | ${site.name}`;
  const hasAnalytics = Boolean(analytics.provider);
  const analyticsAttrs = hasAnalytics
    ? ` data-analytics="${esc(analytics.provider)}" data-ga4="${esc(analytics.ga4Id)}" data-plausible="${esc(analytics.plausibleDomain)}"`
    : '';

  return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(fullTitle)}</title>
<meta name="description" content="${esc(description)}">
${noindex ? '<meta name="robots" content="noindex">' : ''}
<link rel="canonical" href="${canonical}">
<meta name="theme-color" content="#f2eee6" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#161513" media="(prefers-color-scheme: dark)">
<meta name="color-scheme" content="light dark">
<meta property="og:type" content="website">
<meta property="og:locale" content="pt_BR">
<meta property="og:site_name" content="${site.name}">
<meta property="og:title" content="${esc(fullTitle)}">
<meta property="og:description" content="${esc(description)}">
<meta property="og:url" content="${canonical}">
<meta property="og:image" content="${site.url}${ogImage}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="Bandeja de madeira com o nome Ronin gravado e três lanches do Ronin Café">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${esc(fullTitle)}">
<meta name="twitter:description" content="${esc(description)}">
<meta name="twitter:image" content="${site.url}${ogImage}">
<link rel="preload" href="${assets.fontDisplay}" as="font" type="font/woff2" crossorigin>
<link rel="preload" href="${assets.fontText}" as="font" type="font/woff2" crossorigin>
${preload}
<link rel="stylesheet" href="${assets.css}">
<link rel="icon" href="/favicon.ico" sizes="32x32">
<link rel="icon" href="/icons/icon-192.png" type="image/png" sizes="192x192">
<link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
${schemas.map(ld).join('\n')}
<script src="${assets.js}" defer></script>
</head>
<body${analyticsAttrs}>
<a class="skip" href="#conteudo">Pular para o conteúdo</a>
<header class="site-header">
  <div class="wrap header-row">
    <a class="wordmark" href="/" ${path === '/' ? 'aria-current="page"' : ''}>Ronin<span> Café</span></a>
    <nav aria-label="Principal">
      <ul class="nav">
        ${nav.map((n) => `<li><a href="${n.href}"${path.startsWith(n.href) ? ' aria-current="page"' : ''}>${n.label}</a></li>`).join('')}
        <li><a class="nav-ig" href="${site.instagram}" rel="noopener" target="_blank">${icon('instagram', { label: `Instagram ${site.instagramHandle} (abre em nova aba)` })}</a></li>
      </ul>
    </nav>
  </div>
</header>
<main id="conteudo">
${body}
</main>
<footer class="site-footer">
  <div class="wrap footer-grid">
    <div>
      <p class="wordmark wordmark--footer">Ronin<span> Café</span></p>
      <p class="footer-note">${esc(site.tagline)}. Pedro Nóbrega e Vitor Ribas na cozinha.</p>
    </div>
    <div>
      <h2 class="label">Endereço</h2>
      <address>${site.address.street}<br>${site.address.district}, ${site.address.city}, ${site.address.state}<br>${site.address.postalCode}</address>
      <a class="text-link" href="${site.links.directions}" rel="noopener" target="_blank">Como chegar<span class="sr-only"> (abre o Google Maps em nova aba)</span></a>
    </div>
    <div>
      <h2 class="label">Horário</h2>
      <p>${hoursShort}<br>Segunda e terça: fechado</p>
      <a class="text-link" href="${site.instagram}" rel="noopener" target="_blank">${site.instagramHandle}<span class="sr-only"> no Instagram (abre em nova aba)</span></a>
    </div>
    <div>
      <h2 class="label">Site</h2>
      <ul class="footer-links">
        ${nav.map((n) => `<li><a href="${n.href}">${n.label}</a></li>`).join('')}
        <li><a href="/visite/#perguntas">Perguntas frequentes</a></li>
        <li><a href="/privacidade/">Privacidade</a></li>
        <li><a href="/termos/">Termos de uso</a></li>
        ${hasAnalytics ? '<li><button type="button" class="link-button" data-consent-open>Preferências de cookies</button></li>' : ''}
      </ul>
    </div>
  </div>
</footer>
<nav class="mobile-cta" aria-label="Atalhos">
  <a class="btn btn--primary" href="${site.links.directions}" rel="noopener" target="_blank">${icon('navigation', { size: 18 })}Como chegar</a>
  <a class="btn btn--ghost-dark" href="${site.instagram}" rel="noopener" target="_blank">${icon('instagram', { size: 18 })}Instagram</a>
</nav>
${hasAnalytics ? consentBanner() : ''}
</body>
</html>`;
}

function consentBanner() {
  return `<section class="consent" data-consent hidden aria-labelledby="consent-title">
  <h2 id="consent-title" class="label">Cookies de medição</h2>
  <p>Queremos contar visitas ao site, de forma agregada, para saber o que as pessoas procuram. Só ativamos isso se você deixar. <a href="/privacidade/">Como usamos os dados</a>.</p>
  <div class="consent-actions">
    <button type="button" class="btn btn--primary" data-consent-accept>Permitir</button>
    <button type="button" class="btn btn--ghost" data-consent-reject>Recusar</button>
  </div>
</section>`;
}
