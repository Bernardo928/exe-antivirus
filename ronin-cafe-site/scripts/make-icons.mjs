// Gera favicon, ícones de app e a imagem og:image (1200x630, foto real) em src/static.
// Usa o Chromium do Playwright para renderizar com as fontes do site. Rode só quando mudar a marca.
import { createRequire } from 'node:module';
import sharp from 'sharp';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

// Playwright vem pré-instalado no ambiente (não é dependência do projeto).
const { chromium } = createRequire(import.meta.url)('playwright');
const ROOT = path.resolve(import.meta.dirname, '..');
const OUT = path.join(ROOT, 'src/static');
const archivo = (await readFile(path.join(ROOT, 'node_modules/@fontsource-variable/archivo/files/archivo-latin-wdth-normal.woff2'))).toString('base64');
const fontFace = `@font-face{font-family:A;src:url(data:font/woff2;base64,${archivo});font-weight:100 900;font-stretch:62% 125%}`;

await mkdir(path.join(OUT, 'icons'), { recursive: true });
await mkdir(path.join(OUT, 'og'), { recursive: true });
const browser = await chromium.launch();
const page = await browser.newPage();

// Ícone: "R" largo e pesado, papel sobre preto, filete âmbar (luminária).
const iconHtml = (pad) => `<html><head><style>${fontFace}*{margin:0}body{width:512px;height:512px;background:#1a1917;display:grid;place-items:center;position:relative}
b{font:900 ${pad ? 300 : 380}px/1 A;font-stretch:125%;color:#f2eee6;transform:translateY(-4%)}
i{position:absolute;left:${pad ? 150 : 96}px;right:${pad ? 150 : 96}px;bottom:${pad ? 128 : 70}px;height:${pad ? 22 : 30}px;background:#d98a2b}</style></head><body><b>R</b><i></i></body></html>`;
await page.setViewportSize({ width: 512, height: 512 });
await page.setContent(iconHtml(false));
const icon = await page.screenshot({ type: 'png' });
await page.setContent(iconHtml(true));
const maskable = await page.screenshot({ type: 'png' });

await sharp(icon).resize(512).png().toFile(path.join(OUT, 'icons/icon-512.png'));
await sharp(maskable).resize(512).png().toFile(path.join(OUT, 'icons/icon-maskable-512.png'));
await sharp(icon).resize(192).png().toFile(path.join(OUT, 'icons/icon-192.png'));
await sharp(icon).resize(180).png().toFile(path.join(OUT, 'icons/apple-touch-icon.png'));
const ico32 = path.join(OUT, 'icons/_32.png');
const ico16 = path.join(OUT, 'icons/_16.png');
await sharp(icon).resize(32).png().toFile(ico32);
await sharp(icon).resize(16).png().toFile(ico16);
execFileSync('convert', [ico16, ico32, path.join(OUT, 'favicon.ico')]);
execFileSync('rm', [ico16, ico32]);

// og:image com a foto real da bandeja.
const photo = await sharp(path.join(ROOT, 'assets/photos/original/bandeja-lanches.jpg'))
  .extract({ left: 0, top: 2, width: 1214, height: 804 }).resize(1200, 630, { fit: 'cover', position: 'centre' }).jpeg({ quality: 85 }).toBuffer();
await page.setViewportSize({ width: 1200, height: 630 });
await page.setContent(`<html><head><style>${fontFace}*{margin:0}body{width:1200px;height:630px;position:relative;font-family:A;overflow:hidden}
img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
div{position:absolute;left:0;bottom:0;background:#1a1917;color:#f2eee6;padding:28px 40px 30px;border-top:10px solid #d98a2b}
h1{font-weight:900;font-stretch:125%;font-size:64px;line-height:1;text-transform:uppercase}
p{font-weight:600;font-size:26px;margin-top:10px;letter-spacing:.02em}</style></head>
<body><img src="data:image/jpeg;base64,${photo.toString('base64')}"><div><h1>Ronin Café</h1><p>Rua das Palmeiras, 420 · Santa Cecília, SP</p></div></body></html>`);
const og = await page.screenshot({ type: 'jpeg', quality: 82 });
await writeFile(path.join(OUT, 'og/ronin-cafe-og.jpg'), og);
await browser.close();
console.log('Ícones e og:image gerados em src/static');
