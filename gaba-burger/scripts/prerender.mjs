// Pré-renderiza cada página em HTML estático (SEO + carregamento rápido),
// injeta CSP, canonical, Open Graph e JSON-LD, e gera robots.txt e sitemap.xml.
import { readFile, writeFile, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dirname, "..");
const dist = join(root, "dist");
const ssrDir = join(root, ".ssr");

// SITE_URL: domínio final (ex.: https://www.gababurger.com.br). Sem ele não há como gerar URLs absolutas.
let SITE_URL = (process.env.SITE_URL ?? "").trim().replace(/\/+$/, "");
if (SITE_URL && !/^https:\/\/[a-z0-9.-]+\.[a-z]{2,}$/i.test(SITE_URL)) {
  console.error(`SITE_URL inválido: "${SITE_URL}". Use https://dominio.com.br`);
  process.exit(1);
}
if (!SITE_URL) {
  console.warn("Aviso: SITE_URL não definido. Canonical, og:url e sitemap.xml não serão gerados.");
}

const { render, structuredData } = await import(pathToFileURL(join(ssrDir, "entry-server.js")).href);

// Política de segurança de conteúdo. Também enviada como cabeçalho HTTP (public/_headers, vercel.json).
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "frame-src https://www.google.com",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'none'",
  "upgrade-insecure-requests",
].join("; ");

// JSON dentro de <script>: escapa "<" para impedir fechamento prematuro da tag.
const safeJson = (o) => JSON.stringify(o).replace(/</g, "\\u003c");

// Pré-carrega as fontes do primeiro quadro (título e texto), reduzindo o LCP.
const { readdir } = await import("node:fs/promises");
const assets = await readdir(join(dist, "assets"));
const preloadFonts = assets
  .filter((f) => /^(fraunces-latin-opsz-(normal|italic)|manrope-latin-wght-normal)-.*\.woff2$/.test(f))
  .map((f) => `<link rel="preload" href="/assets/${f}" as="font" type="font/woff2" crossorigin />`);

const PAGES = [
  { file: "index.html", page: "home", path: "/" },
  { file: "privacidade/index.html", page: "privacidade", path: "/privacidade/" },
  { file: "termos/index.html", page: "termos", path: "/termos/" },
  { file: "404.html", page: "notfound", path: null },
];

for (const { file, page, path } of PAGES) {
  const target = join(dist, file);
  let html = await readFile(target, "utf8");
  const head = [`<meta http-equiv="Content-Security-Policy" content="${CSP}" />`, ...preloadFonts];
  if (path === null) head.push(`<meta name="robots" content="noindex" />`);
  if (SITE_URL && path !== null) {
    head.push(`<link rel="canonical" href="${SITE_URL}${path}" />`);
    head.push(`<meta property="og:url" content="${SITE_URL}${path}" />`);
  }
  head.push(`<meta property="og:image" content="${SITE_URL}/og-image.png" />`);
  head.push(`<meta name="twitter:image" content="${SITE_URL}/og-image.png" />`);
  for (const data of structuredData(page, SITE_URL || null)) {
    head.push(`<script type="application/ld+json">${safeJson(data)}</script>`);
  }
  if (!html.includes("<!--head-->") || !html.includes("<!--app-->")) throw new Error(`Marcadores ausentes em ${file}`);
  html = html.replace("<!--head-->", head.join("\n    ")).replace("<!--app-->", render(page));
  await writeFile(target, html);
  console.log(`pré-renderizado: ${file}`);
}

const robots = ["User-agent: *", "Allow: /", ""];
if (SITE_URL) robots.push(`Sitemap: ${SITE_URL}/sitemap.xml`, "");
await writeFile(join(dist, "robots.txt"), robots.join("\n"));

if (SITE_URL) {
  const today = new Date().toISOString().slice(0, 10);
  const urls = PAGES.filter((p) => p.path !== null)
    .map((p) => `  <url><loc>${SITE_URL}${p.path}</loc><lastmod>${today}</lastmod></url>`)
    .join("\n");
  await writeFile(
    join(dist, "sitemap.xml"),
    `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`,
  );
  console.log("sitemap.xml gerado");
}

await rm(ssrDir, { recursive: true, force: true });
