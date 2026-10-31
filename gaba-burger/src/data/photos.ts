/**
 * FOTOGRAFIAS REAIS DO GABA BURGER
 *
 * Regra do projeto: apenas fotos verdadeiras do restaurante. Nada gerado por IA,
 * nada de banco de imagens. Enquanto um espaço estiver vazio (null / lista vazia),
 * o site mostra uma composição gráfica no lugar, sem fingir que é foto.
 *
 * Como adicionar uma foto:
 *   1. Coloque o arquivo original em  photos/originais/<nome>.jpg
 *   2. Rode  npm run photos  (gera AVIF + WebP em 3 tamanhos dentro de public/fotos/)
 *   3. Copie a linha que o script imprime para este arquivo, ajustando o texto alternativo.
 */

export type PhotoCategory = "burger" | "batata" | "ambiente" | "fachada" | "detalhe";

export type Photo = {
  /** Nome base gerado pelo script, sem extensão. */
  name: string;
  width: number;
  height: number;
  /** Descrição objetiva da foto, para leitores de tela e SEO. */
  alt: string;
  category: PhotoCategory;
  /** Autor ou origem, quando a foto não for do próprio restaurante. */
  credit?: string;
};

export const PHOTO_WIDTHS = [640, 1280, 1920] as const;

export const PHOTOS: {
  hero: Photo | null;
  about: Photo | null;
  aboutDetail: Photo | null;
  menu: Record<string, Photo | null>;
  gallery: Photo[];
} = {
  hero: null,
  about: null,
  aboutDetail: null,
  menu: {
    "gaba-tasty": null,
    "gaba-melt": null,
    "lua-cheia": null,
    "pineapple-burger": null,
  },
  gallery: [],
};

export const CATEGORY_LABEL: Record<PhotoCategory, string> = {
  burger: "Hambúrgueres",
  batata: "Batatas",
  ambiente: "Ambiente",
  fachada: "Fachada",
  detalhe: "Detalhes",
};
