// Converte as fotos reais de photos/originais/ em AVIF + WebP otimizados.
// Uso: npm run photos
import { readdir, mkdir } from "node:fs/promises";
import { extname, basename, join, resolve } from "node:path";
import sharp from "sharp";

const root = resolve(import.meta.dirname, "..");
const SRC = join(root, "photos", "originais");
const OUT = join(root, "public", "fotos");
const WIDTHS = [640, 1280, 1920];
const ACCEPTED = new Set([".jpg", ".jpeg", ".png", ".webp", ".heic", ".avif"]);

// Nome seguro para URL: apenas letras minúsculas, números e hífens.
const slug = (s) =>
  s.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

await mkdir(OUT, { recursive: true });
const files = (await readdir(SRC)).filter((f) => ACCEPTED.has(extname(f).toLowerCase()));

if (files.length === 0) {
  console.log("Nenhuma foto em photos/originais/. Adicione fotos reais do Gaba Burger e rode de novo.");
  process.exit(0);
}

for (const file of files) {
  const name = slug(basename(file, extname(file)));
  // rotate() aplica a orientação EXIF; o resultado não leva metadados (GPS, câmera).
  const base = sharp(join(SRC, file)).rotate();
  const meta = await base.metadata();
  const ratio = (meta.height ?? 1) / (meta.width ?? 1);
  for (const w of WIDTHS) {
    const width = Math.min(w, meta.width ?? w);
    const img = base.clone().resize({ width, withoutEnlargement: true });
    await img.clone().avif({ quality: 52, effort: 6 }).toFile(join(OUT, `${name}-${w}.avif`));
    await img.clone().webp({ quality: 74 }).toFile(join(OUT, `${name}-${w}.webp`));
  }
  const h = Math.round(1920 * ratio);
  console.log(`{ name: "${name}", width: 1920, height: ${h}, alt: "DESCREVA A FOTO", category: "burger" },`);
}
console.log("\nCole as linhas acima em src/data/photos.ts e ajuste alt e category.");
