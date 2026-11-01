// Screenshots de revisão: desktop 1440px e celular 390px. Uso: node scripts/screenshots.mjs [baseURL] [pasta]
import { createRequire } from 'node:module';
const { chromium } = createRequire(import.meta.url)('playwright');
const base = process.argv[2] || 'http://localhost:4173';
const dir = process.argv[3] || 'screenshots';
const pages = ['/', '/cardapio/', '/sobre/', '/visite/', '/privacidade/', '/nao-existe'];
const browser = await chromium.launch();
for (const [label, vp, mobile] of [['desktop', { width: 1440, height: 900 }, false], ['mobile', { width: 390, height: 844 }, true]]) {
  const ctx = await browser.newContext({ viewport: vp, deviceScaleFactor: mobile ? 2 : 1, isMobile: mobile, hasTouch: mobile, colorScheme: process.env.SCHEME || 'light' });
  const page = await ctx.newPage();
  const errors = [];
  page.on('console', (m) => m.type() !== 'log' && errors.push(m.text()));
  page.on('pageerror', (e) => errors.push(e.message));
  for (const p of pages) {
    await page.goto(base + p, { waitUntil: 'networkidle' });
    // Rola até o fim para disparar imagens lazy, depois volta ao topo.
    await page.evaluate(async () => { for (let y = 0; y < document.body.scrollHeight; y += 400) { window.scrollTo(0, y); await new Promise((r) => setTimeout(r, 60)); } window.scrollTo(0, 0); });
    await page.waitForLoadState('networkidle');
    const name = (p === '/' ? 'home' : p.replace(/\//g, '')) + `-${label}${process.env.SCHEME === 'dark' ? '-dark' : ''}.png`;
    await page.screenshot({ path: `${dir}/${name}`, fullPage: true });
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
    if (overflow) console.log(`OVERFLOW horizontal: ${p} ${label}`);
  }
  if (errors.length) console.log(label, 'erros no console:', errors);
  await ctx.close();
}
await browser.close();
