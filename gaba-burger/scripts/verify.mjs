// Verificação automatizada do build (dist/). Uso: npm run build && npm run check
// Testa: erros de console e CSP, hidratação, hierarquia de títulos, links, menu mobile,
// mapa, FAQ, galeria, rolagem horizontal e regras de texto. Salva capturas em ./screenshots.
import { createRequire } from "node:module";
import { createServer } from "node:http";
import { readFile, mkdir, stat } from "node:fs/promises";
import { extname, join, resolve, normalize } from "node:path";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const root = resolve(import.meta.dirname, "..");
const dist = join(root, "dist");
const shots = join(root, "screenshots");
await mkdir(shots, { recursive: true });

const TYPES = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml",
  ".png": "image/png", ".webp": "image/webp", ".avif": "image/avif", ".woff2": "font/woff2",
  ".json": "application/json", ".webmanifest": "application/manifest+json", ".txt": "text/plain", ".xml": "application/xml",
};

// Servidor estático mínimo que imita a hospedagem: /pasta/ -> index.html, inexistente -> 404.html.
const server = createServer(async (req, res) => {
  try {
    let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
    if (p.endsWith("/")) p += "index.html";
    const file = normalize(join(dist, p));
    if (!file.startsWith(dist)) throw new Error("fora do dist");
    await stat(file);
    res.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream" });
    res.end(await readFile(file));
  } catch {
    res.writeHead(404, { "content-type": TYPES[".html"] });
    res.end(await readFile(join(dist, "404.html")));
  }
});
await new Promise((r) => server.listen(4173, "127.0.0.1", r));
const BASE = "http://127.0.0.1:4173";

const results = [];
const check = (name, ok, info = "") => {
  results.push({ name, ok, info });
  console.log(`${ok ? "OK  " : "FALHA"} ${name}${info ? ` (${info})` : ""}`);
};

const browser = await chromium.launch();

async function openPage(path, viewport) {
  const ctx = await browser.newContext({ viewport, reducedMotion: "no-preference" });
  // Bloqueia rede externa: o site precisa funcionar sem depender dela.
  await ctx.route(/^(?!http:\/\/127\.0\.0\.1:4173)/, (r) => r.abort());
  const page = await ctx.newPage();
  const errors = [];
  page.on("console", (m) => {
    // O próprio 404.html responde com status 404 de propósito.
    if (m.type() === "error" && !/net::ERR_FAILED|ERR_BLOCKED|status of 404/.test(m.text())) errors.push(m.text());
    if (m.type() === "warning" && /hydrat|Content Security Policy/i.test(m.text())) errors.push(m.text());
  });
  page.on("pageerror", (e) => errors.push(String(e)));
  const resp = await page.goto(BASE + path, { waitUntil: "networkidle" });
  return { ctx, page, errors, status: resp?.status() };
}

const PAGES = ["/", "/privacidade/", "/termos/", "/pagina-que-nao-existe"];

for (const path of PAGES) {
  const { ctx, page, errors, status } = await openPage(path, { width: 1440, height: 900 });
  check(`${path} carrega`, path.includes("nao-existe") ? status === 404 : status === 200, `HTTP ${status}`);
  await page.waitForTimeout(400);
  check(`${path} sem erros de console/CSP/hidratação`, errors.length === 0, errors.join(" | ").slice(0, 300));

  const audit = await page.evaluate(() => {
    const hs = [...document.querySelectorAll("h1,h2,h3,h4,h5,h6")].map((h) => Number(h.tagName[1]));
    let skip = false;
    for (let i = 1; i < hs.length; i++) if (hs[i] - hs[i - 1] > 1) skip = true;
    const anchors = [...document.querySelectorAll("a")];
    const badHref = anchors.filter((a) => !a.getAttribute("href") || a.getAttribute("href") === "#").map((a) => a.outerHTML.slice(0, 80));
    const unsafeBlank = anchors.filter((a) => a.target === "_blank" && !/noopener/.test(a.rel)).length;
    const missingTargets = anchors
      .map((a) => a.getAttribute("href") ?? "")
      .filter((h) => h.startsWith("#") && h.length > 1 && !document.getElementById(h.slice(1)));
    const imgsNoAlt = [...document.querySelectorAll("img")].filter((i) => !i.hasAttribute("alt")).length;
    const buttonsNoName = [...document.querySelectorAll("button")].filter((b) => !(b.getAttribute("aria-label") || b.textContent?.trim())).length;
    const text = document.body.innerText;
    return {
      h1: hs.filter((h) => h === 1).length, skip, badHref, unsafeBlank, missingTargets, imgsNoAlt, buttonsNoName,
      emDash: text.includes("—"),
      title: document.title, desc: document.querySelector('meta[name="description"]')?.getAttribute("content") ?? "",
      lang: document.documentElement.lang,
    };
  });
  check(`${path} tem exatamente 1 h1`, audit.h1 === 1, `h1=${audit.h1}`);
  check(`${path} hierarquia de títulos sem saltos`, !audit.skip);
  check(`${path} todos os links têm destino`, audit.badHref.length === 0, audit.badHref.join(" "));
  check(`${path} links _blank com noopener`, audit.unsafeBlank === 0);
  check(`${path} âncoras internas existem`, audit.missingTargets.length === 0, audit.missingTargets.join(","));
  check(`${path} imagens com alt`, audit.imgsNoAlt === 0);
  check(`${path} botões com nome acessível`, audit.buttonsNoName === 0);
  check(`${path} sem travessão (em dash) no texto`, !audit.emDash);
  check(`${path} título e descrição`, audit.title.length > 10 && audit.desc.length > 50 && audit.lang === "pt-BR", audit.title);
  const revealAll = () => page.evaluate(() => document.querySelectorAll(".reveal-pending").forEach((e) => e.classList.remove("reveal-pending")));
  if (path === "/") await revealAll();
  if (path === "/") await page.screenshot({ path: join(shots, "desktop-home-full.png"), fullPage: true });
  if (path === "/") await page.screenshot({ path: join(shots, "desktop-hero.png") });
  await ctx.close();
}

// Títulos únicos por página.
{
  const titles = new Set();
  for (const path of PAGES) {
    const html = await (await fetch(BASE + path)).text();
    titles.add(/<title>(.*?)<\/title>/.exec(html)?.[1]);
  }
  check("títulos de página únicos", titles.size === PAGES.length);
}

// Interações na home (desktop).
{
  const { ctx, page, errors } = await openPage("/", { width: 1440, height: 900 });
  const status = await page.locator("#inicio a[href='#horarios']").innerText();
  check("status aberto/fechado calculado", /Aberto agora|Fechado agora/i.test(status), status.replace(/\s+/g, " "));

  await page.click("header nav a[href='#cardapio']");
  await page.waitForTimeout(1200);
  const y = await page.evaluate(() => document.getElementById("cardapio").getBoundingClientRect().top);
  check("menu rola até a seção (rolagem suave)", Math.abs(y) < 120, `top=${Math.round(y)}`);
  const current = await page.locator("header nav a[aria-current='true']").innerText().catch(() => "");
  check("scrollspy destaca a seção atual", current === "Cardápio", current);

  await page.click("text=Carregar mapa");
  const iframe = await page.locator("#localizacao iframe").getAttribute("src");
  check("mapa carrega sob demanda", iframe?.startsWith("https://www.google.com/maps") ?? false);

  const det = page.locator("#perguntas details").first();
  await det.locator("summary").click();
  check("FAQ abre ao clicar", await det.evaluate((d) => d.open));

  const ifoodLinks = await page.locator(`a[href^="https://www.ifood.com.br/"]`).count();
  check("botões de pedido apontam para o iFood", ifoodLinks >= 5, `${ifoodLinks} links`);

  const galleryButtons = await page.locator("#galeria button").count();
  if (galleryButtons > 0) {
    await page.locator("#galeria button").first().click();
    const open = await page.locator("dialog[open]").count();
    await page.keyboard.press("ArrowRight");
    const counter = await page.locator("dialog[open] p[aria-live]").innerText();
    await page.keyboard.press("Escape");
    const closed = (await page.locator("dialog[open]").count()) === 0;
    check("galeria: lightbox abre, navega e fecha com Esc", open === 1 && /^2 \//.test(counter) && closed, counter);
  } else {
    check("galeria: sem fotos reais cadastradas, mostra espaços reservados", (await page.locator("#galeria li").count()) === 5);
  }
  check("home sem erros após interações", errors.length === 0, errors.join(" | ").slice(0, 300));
  await ctx.close();
}

// Responsividade e menu mobile.
for (const vp of [
  { name: "android-360", width: 360, height: 780 },
  { name: "iphone-390", width: 390, height: 844 },
  { name: "tablet-768", width: 768, height: 1024 },
  { name: "notebook-1280", width: 1280, height: 800 },
  { name: "monitor-1920", width: 1920, height: 1080 },
]) {
  const { ctx, page } = await openPage("/", { width: vp.width, height: vp.height });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  check(`${vp.name}: sem rolagem horizontal`, overflow <= 0, `excesso=${overflow}px`);
  // Texto ou botão cortado pela borda (overflow escondido não aparece no teste acima).
  const clipped = await page.evaluate((w) =>
    [...document.querySelectorAll("main h1, main h2, main h3, main p, main a.btn, main li")]
      .filter((el) => el.getClientRects().length && !el.closest("[aria-hidden='true']"))
      .filter((el) => { const r = el.getBoundingClientRect(); return r.right > w + 1 || r.left < -1; })
      .map((el) => el.textContent.trim().slice(0, 30)), vp.width);
  check(`${vp.name}: nenhum texto cortado na borda`, clipped.length === 0, clipped.slice(0, 3).join(" | "));
  if (vp.width === 390) await page.evaluate(() => document.querySelectorAll(".reveal-pending").forEach((e) => e.classList.remove("reveal-pending")));
  if (vp.width === 390) await page.screenshot({ path: join(shots, "iphone-390-full.png"), fullPage: true });
  await page.screenshot({ path: join(shots, `${vp.name}.png`) });

  if (vp.width < 1024) {
    const toggle = page.locator("button[aria-controls='menu-mobile']");
    await toggle.click();
    const expanded = await toggle.getAttribute("aria-expanded");
    const visible = await page.locator("#menu-mobile").isVisible();
    await page.screenshot({ path: join(shots, `${vp.name}-menu.png`) });
    await page.keyboard.press("Escape");
    const hidden = !(await page.locator("#menu-mobile").isVisible());
    await toggle.click();
    await page.locator("#menu-mobile a[href='#horarios']").click();
    await page.waitForTimeout(2500); // rolagem suave longa no celular
    const closedAfterNav = !(await page.locator("#menu-mobile").isVisible());
    const y = await page.evaluate(() => document.getElementById("horarios").getBoundingClientRect().top);
    check(`${vp.name}: menu mobile abre, fecha com Esc e navega`, expanded === "true" && visible && hidden && closedAfterNav && Math.abs(y) < 120);
    const cta = await page.locator("a:has-text('Pedir no iFood')").last().isVisible();
    check(`${vp.name}: barra fixa de pedido visível`, cta);
  }
  await ctx.close();
}

await browser.close();
server.close();

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} verificações passaram. Capturas em ./screenshots`);
process.exit(failed.length ? 1 : 0);
