// Servidor local que imita o host: aplica dist/_headers, URLs limpas, gzip e 404 personalizada.
// Uso: node scripts/serve.mjs dist [porta]
import http from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';
import path from 'node:path';

const root = path.resolve(process.argv[2] || 'dist');
const port = Number(process.argv[3] || 4173);
const types = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.xml': 'application/xml', '.txt': 'text/plain; charset=utf-8',
  '.avif': 'image/avif', '.webp': 'image/webp', '.jpg': 'image/jpeg', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.svg': 'image/svg+xml',
};

// Parser mínimo do formato _headers (Netlify/Cloudflare Pages).
const rules = [];
try {
  let cur;
  for (const line of (await readFile(path.join(root, '_headers'), 'utf8')).split('\n')) {
    if (!line.trim()) continue;
    if (!line.startsWith(' ')) rules.push((cur = { pattern: line.trim(), headers: {} }));
    else { const i = line.indexOf(':'); cur.headers[line.slice(0, i).trim()] = line.slice(i + 1).trim(); }
  }
} catch { /* sem _headers */ }
const match = (pattern, url) => new RegExp('^' + pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$').test(url);

async function resolve(urlPath) {
  const clean = path.normalize(decodeURIComponent(urlPath)).replace(/^(\.\.[/\\])+/, '');
  if (clean.split(/[/\\]/).some((seg) => seg.startsWith('.') && seg.length > 1)) return null; // nada de dotfiles
  let file = path.join(root, clean);
  if (!file.startsWith(root)) return null;
  try {
    const s = await stat(file);
    if (s.isDirectory()) file = path.join(file, 'index.html');
    await stat(file);
    return file;
  } catch { return null; }
}

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  let file = await resolve(url.pathname);
  let status = 200;
  if (!file && !url.pathname.endsWith('/') && !path.extname(url.pathname) && (await resolve(url.pathname + '/'))) {
    res.writeHead(301, { Location: url.pathname + '/' }); return res.end();
  }
  if (!file) { file = path.join(root, '404.html'); status = 404; }
  const headers = { 'Content-Type': types[path.extname(file)] || 'application/octet-stream' };
  for (const r of rules) if (match(r.pattern, url.pathname) || (r.pattern === '/*.html' && file.endsWith('.html'))) Object.assign(headers, r.headers);
  let body = await readFile(file);
  if (/text|javascript|json|xml|svg|manifest/.test(headers['Content-Type']) && /gzip/.test(req.headers['accept-encoding'] || '')) {
    body = gzipSync(body); headers['Content-Encoding'] = 'gzip';
  }
  res.writeHead(status, headers);
  res.end(body);
}).listen(port, () => console.log(`http://localhost:${port}`));
