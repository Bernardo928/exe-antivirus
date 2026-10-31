// Gera a imagem de compartilhamento (og-image.png) e os ícones PNG a partir de HTML,
// usando apenas tipografia e cores da marca (nenhuma foto, nenhuma imagem de IA).
// Uso: npm run assets   (precisa do Playwright com Chromium instalado)
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import sharp from "sharp";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const root = resolve(import.meta.dirname, "..");
const pub = join(root, "public");
const font = (pkg, file) => pathToFileURL(join(root, "node_modules", "@fontsource-variable", pkg, "files", file)).href;

const FONTS = `
@font-face{font-family:F;font-style:normal;font-weight:100 900;src:url(${font("fraunces", "fraunces-latin-opsz-normal.woff2")})}
@font-face{font-family:F;font-style:italic;font-weight:100 900;src:url(${font("fraunces", "fraunces-latin-opsz-italic.woff2")})}
@font-face{font-family:M;font-weight:200 800;src:url(${font("manrope", "manrope-latin-wght-normal.woff2")})}
*{margin:0;box-sizing:border-box}
body{background:#15110e;color:#f3e9d8;font-family:M}
.d{font-family:F}
`;

const OG = `<!doctype html><meta charset="utf-8"><style>${FONTS}
body{width:1200px;height:630px;position:relative;overflow:hidden;padding:72px 80px}
.g{position:absolute;inset:0;background-image:repeating-linear-gradient(-38deg,transparent 0 26px,rgba(219,165,74,.06) 26px 30px),radial-gradient(70% 90% at 100% 120%,rgba(168,55,27,.55),transparent 60%)}
.e{font-size:18px;letter-spacing:.32em;text-transform:uppercase;color:#dba54a;font-weight:600;position:relative}
h1{font-family:F;font-weight:300;font-size:104px;line-height:.92;text-transform:uppercase;margin-top:48px;position:relative}
em{color:#dba54a;font-weight:400}
.f{position:absolute;left:80px;right:80px;bottom:64px;display:flex;justify-content:space-between;align-items:center;font-size:22px;color:#d9ccb6}
.w{font-family:F;font-size:34px;color:#f3e9d8}.w span{color:#dba54a}
.s{position:absolute;right:80px;top:150px;transform:rotate(-6deg);background:#a8371b;padding:12px 24px;font-family:F;font-style:italic;font-size:34px;border-radius:3px}
</style><body><div class="g"></div>
<p class="e">Pinheiros · São Paulo</p>
<h1>Hambúrguer<br><em>na brasa</em><br>em Pinheiros.</h1>
<p class="s">180g na parrilla</p>
<div class="f"><span class="w">Gaba Burger<span>.</span></span><span>Rua Mourato Coelho, 833</span></div>
</body>`;

const ICON = (size) => `<!doctype html><meta charset="utf-8"><style>${FONTS}
body{width:${size}px;height:${size}px;display:grid;place-items:center}
.c{width:78%;height:78%;border-radius:50%;border:${Math.max(2, size / 60)}px solid rgba(243,233,216,.45);display:grid;place-items:center}
.c span{font-family:F;font-style:italic;color:#dba54a;font-size:${size * 0.5}px;line-height:1;margin-top:-${size * 0.04}px}
</style><body><div class="c"><span>G</span></div></body>`;

const browser = await chromium.launch();
const page = await browser.newPage();

async function shot(html, w, h, out) {
  await page.setViewportSize({ width: w, height: h });
  await page.setContent(html, { waitUntil: "load" });
  await page.evaluate(() => document.fonts.ready);
  const buf = await page.screenshot({ type: "png" });
  await sharp(buf).png({ compressionLevel: 9, palette: w <= 512 }).toFile(join(pub, out));
  console.log(`gerado: public/${out}`);
}

await shot(OG, 1200, 630, "og-image.png");
for (const [size, name] of [
  [512, "icon-512.png"],
  [192, "icon-192.png"],
  [180, "apple-touch-icon.png"],
  [32, "favicon-32.png"],
]) {
  await shot(ICON(size), size, size, name);
}
await browser.close();
