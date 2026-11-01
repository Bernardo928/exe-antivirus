// Gera dist-baseline/: o mesmo site SEM as otimizações (JPEG original de ~1 MB, sem srcset/AVIF/WebP,
// sem preload, sem width/height, sem lazy). Serve só para a medição "antes" do PERFORMANCE.md.
import { cp, readdir, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');
const OUT = path.join(ROOT, 'dist-baseline');
await rm(OUT, { recursive: true, force: true });
await cp(path.join(ROOT, 'dist'), OUT, { recursive: true });
await mkdir(path.join(OUT, 'original'), { recursive: true });
await cp(path.join(ROOT, 'assets/photos/original'), path.join(OUT, 'original'), { recursive: true });
for (const f of (await readdir(OUT, { recursive: true })).filter((f) => f.endsWith('.html'))) {
  let h = await readFile(path.join(OUT, f), 'utf8');
  h = h.replace(/<link rel="preload"[^>]*>/g, '')
    .replace(/<source [^>]*>/g, '')
    .replace(/<img ([^>]*?)src="\/img\/([a-z-]+)-\d+\.[a-f0-9]+\.jpg"([^>]*)>/g, (_, a, key, b) =>
      `<img ${(a + b).replace(/\s(srcset|sizes|width|height|loading|fetchpriority|decoding)="[^"]*"/g, '')} src="/original/${key}.jpg">`);
  await writeFile(path.join(OUT, f), h);
}
console.log('dist-baseline gerado');
