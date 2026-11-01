// Regras anti-slop e SEO sobre o HTML gerado.
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';

const root = path.resolve(process.argv[2] || 'dist');
const all = await readdir(root, { recursive: true });
const html = all.filter((f) => f.endsWith('.html'));
const problems = [];
const banned = [/descubra/i, /experiência (única|inesquecível)/i, /feito com ia/i, /lorem ipsum/i, /TODO/];
const titles = new Map(), descs = new Map();
for (const f of html) {
  const t = await readFile(path.join(root, f), 'utf8');
  const text = t.replace(/<script[\s\S]*?<\/script>/g, '').replace(/<[^>]+>/g, ' ');
  if (/[—]/.test(t)) problems.push(`${f}: travessão (—)`);
  if (/\p{Extended_Pictographic}/u.test(text)) problems.push(`${f}: emoji no texto`);
  for (const b of banned) if (b.test(text)) problems.push(`${f}: termo proibido ${b}`);
  const h1 = (t.match(/<h1[\s>]/g) || []).length;
  if (h1 !== 1) problems.push(`${f}: ${h1} h1`);
  if (!t.includes('<html lang="pt-BR">')) problems.push(`${f}: sem lang pt-BR`);
  const title = t.match(/<title>([^<]+)<\/title>/)?.[1];
  const desc = t.match(/<meta name="description" content="([^"]+)"/)?.[1];
  if (!title || !desc) problems.push(`${f}: sem title/description`);
  if (titles.has(title)) problems.push(`${f}: title repetido de ${titles.get(title)}`); titles.set(title, f);
  if (descs.has(desc)) problems.push(`${f}: description repetida`); descs.set(desc, f);
  if (f !== '404.html' && /noindex/.test(t)) problems.push(`${f}: noindex em página pública`);
  for (const m of t.matchAll(/<img [^>]+>/g)) if (!/width="\d+"/.test(m[0]) || !/height="\d+"/.test(m[0]) || !/alt="[^"]+"/.test(m[0])) problems.push(`${f}: img sem width/height/alt`);
  // headings sem pular nível
  let prev = 0;
  for (const m of t.matchAll(/<h([1-6])/g)) { const l = +m[1]; if (prev && l > prev + 1) problems.push(`${f}: pulo de h${prev} para h${l}`); prev = l; }
}
for (const f of all.filter((f) => f.endsWith('.js'))) {
  const t = await readFile(path.join(root, f), 'utf8');
  if (/console\.(log|debug)|debugger/.test(t)) problems.push(`${f}: console.log/debugger`);
}
for (const f of all) if (/(^|\/)\.(env|git)|\.map$/.test(f)) problems.push(`arquivo sensível exposto: ${f}`);
problems.forEach((p) => console.log('✗', p));
console.log(`${html.length} páginas verificadas, ${problems.length} problemas.`);
process.exit(problems.length ? 1 : 0);
