// Pipeline de imagens: recorta as bordas pretas dos prints, gera AVIF/WebP/JPEG
// em várias larguras com hash no nome e devolve <picture> com width/height.
import sharp from 'sharp';
import { createHash } from 'node:crypto';
import { readFile, mkdir, access, copyFile } from 'node:fs/promises';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '../..');
const SRC = path.join(ROOT, 'assets/photos/original');
const CACHE = path.join(ROOT, '.cache/img');

// crop: área útil de cada foto (as originais têm faixas pretas de print de tela).
export const photos = {
  'salao-clientes': {
    crop: { left: 4, top: 10, width: 1206, height: 1818 },
    alt: 'Salão do Ronin Café cheio: na mesa da frente, um cliente de óculos escuros e moletom branco morde um sanduíche ao lado de uma amiga de cabelo cacheado; ao fundo, a equipe de camiseta preta trabalha no balcão de concreto sob luminárias industriais pretas.',
  },
  'bandeja-lanches': {
    crop: { left: 0, top: 2, width: 1214, height: 804 },
    alt: 'Funcionário segura uma bandeja de pinus com o nome Ronin gravado a fogo, com três pratos de inox: pãezinhos com molho escuro, um hambúrguer em pão brioche com picles e um sanduíche de pão tostado recheado de frios com mostarda.',
  },
  'mesa-oval-concreto': {
    crop: { left: 4, top: 6, width: 1208, height: 1616 },
    alt: 'Canto do salão com mesa oval de madeira, cadeiras de aço com assento de ripas, tapete persa, luminária redonda de grade de madeira acesa e parede de concreto queimado.',
  },
  'mesa-vista-de-cima': {
    crop: { left: 2, top: 2, width: 1212, height: 1610 },
    alt: 'Mesa de madeira vista de cima com dois cafés filtrados em copos de cerâmica e o cartão do grão Rodomunho Ethiopian Dwarf, dois drinques com gelo, um sanduíche de empanado com alface, pãezinhos tostados com molho, um brioche com ovos mexidos e um prato com pão de fermentação natural.',
  },
  'rabanada-morango': {
    crop: { left: 2, top: 6, width: 1210, height: 1616 },
    alt: 'Fatia de pão caramelizada em cumbuca de cerâmica clara, coberta com morangos fatiados, raspas de laranja e uma bola de sorvete branco.',
  },
  'ovos-pao-fermentacao': {
    crop: { left: 2, top: 2, width: 1212, height: 1614 },
    alt: 'Cumbuca com ovos pochê sobre creme branco, cubos de embutido, tomate, azeitona roxa, óleo de pimenta e ervas frescas, acompanhada de duas fatias de pão de fermentação natural tostado.',
  },
};

const WIDTHS = [400, 800, 1200];
const FORMATS = [
  ['avif', (s) => s.avif({ quality: 50, effort: 6 })],
  ['webp', (s) => s.webp({ quality: 72, effort: 6 })],
  ['jpg', (s) => s.jpeg({ quality: 76, mozjpeg: true, progressive: true })],
];

const exists = (p) => access(p).then(() => true, () => false);
const manifest = new Map();

export async function processPhotos(outDir) {
  await mkdir(CACHE, { recursive: true });
  await mkdir(path.join(outDir, 'img'), { recursive: true });
  for (const [key, p] of Object.entries(photos)) {
    const buf = await readFile(path.join(SRC, `${key}.jpg`));
    const hash = createHash('sha256').update(buf).update(JSON.stringify(p.crop)).digest('hex').slice(0, 8);
    const ratio = p.crop.height / p.crop.width;
    const variants = {};
    for (const w of WIDTHS) {
      for (const [ext, enc] of FORMATS) {
        const name = `${key}-${w}.${hash}.${ext}`;
        const cached = path.join(CACHE, name);
        if (!(await exists(cached))) {
          await enc(sharp(buf).rotate().extract(p.crop).resize({ width: w })).toFile(cached);
        }
        await copyFile(cached, path.join(outDir, 'img', name));
        (variants[ext] ||= []).push({ w, url: `/img/${name}` });
      }
    }
    manifest.set(key, { ...p, ratio, variants });
  }
  return manifest;
}

export function getPhoto(key) {
  const m = manifest.get(key);
  if (!m) throw new Error(`Foto desconhecida: ${key}`);
  return m;
}

const srcset = (list) => list.map((v) => `${v.url} ${v.w}w`).join(', ');

// Imagem responsiva. `priority` = LCP (eager + fetchpriority high), senão lazy.
export function picture(key, { sizes, priority = false, className = '', alt } = {}) {
  const m = getPhoto(key);
  const w = 1200;
  const h = Math.round(w * m.ratio);
  const fallback = m.variants.jpg.find((v) => v.w === 800).url;
  // priority 'eager' = LCP em todas as telas; 'desktop' = LCP só no desktop (o preload com media cuida dele).
  const loading = priority === true ? 'fetchpriority="high" loading="eager"' : 'loading="lazy"';
  return `<picture>
  <source type="image/avif" srcset="${srcset(m.variants.avif)}" sizes="${sizes}">
  <source type="image/webp" srcset="${srcset(m.variants.webp)}" sizes="${sizes}">
  <img class="${className}" src="${fallback}" srcset="${srcset(m.variants.jpg)}" sizes="${sizes}" width="${w}" height="${h}" alt="${alt ?? m.alt}" decoding="async" ${loading}>
</picture>`;
}

export function preloadTag(key, sizes, media = '') {
  const m = getPhoto(key);
  return `<link rel="preload" as="image" type="image/avif" imagesrcset="${srcset(m.variants.avif)}" imagesizes="${sizes}" fetchpriority="high"${media ? ` media="${media}"` : ''}>`;
}
