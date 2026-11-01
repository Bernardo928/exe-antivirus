// Verifica links e recursos internos de todas as páginas em dist/ (href, src, srcset, url() do CSS).
import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';

const root = path.resolve(process.argv[2] || 'dist');
const files = (await readdir(root, { recursive: true })).filter((f) => f.endsWith('.html') || f.endsWith('.css') || f.endsWith('.webmanifest'));
const exists = async (url) => {
  const clean = decodeURIComponent(url.split('#')[0].split('?')[0]);
  let p = path.join(root, clean);
  try { if ((await stat(p)).isDirectory()) p = path.join(p, 'index.html'); await stat(p); return true; } catch { return false; }
};
let broken = 0, checked = 0;
for (const f of files) {
  const txt = await readFile(path.join(root, f), 'utf8');
  const urls = new Set();
  for (const m of txt.matchAll(/(?:href|src|content)="(\/[^"]*)"/g)) urls.add(m[1]);
  for (const m of txt.matchAll(/(?:srcset|imagesrcset)="([^"]+)"/g)) m[1].split(',').forEach((s) => urls.add(s.trim().split(' ')[0]));
  for (const m of txt.matchAll(/url\((\/[^)]+)\)/g)) urls.add(m[1]);
  for (const m of txt.matchAll(/"src":\s*"(\/[^"]+)"/g)) urls.add(m[1]);
  // Âncoras internas na mesma página e em outras
  for (const u of urls) {
    if (!u.startsWith('/') || u.startsWith('//')) continue;
    checked++;
    if (!(await exists(u))) { console.log(`QUEBRADO em ${f}: ${u}`); broken++; continue; }
    const [pagePath, hash] = u.split('#');
    if (hash) {
      const target = path.join(root, pagePath, pagePath.endsWith('.html') ? '' : 'index.html');
      const html = await readFile(target, 'utf8');
      if (!html.includes(`id="${hash}"`)) { console.log(`ÂNCORA inexistente em ${f}: ${u}`); broken++; }
    }
  }
}
console.log(`${checked} links internos verificados em ${files.length} arquivos, ${broken} quebrados.`);
process.exit(broken ? 1 : 0);
