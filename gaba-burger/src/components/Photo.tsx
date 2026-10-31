import type { ReactNode } from "react";
import { PHOTO_WIDTHS, type Photo } from "../data/photos";

const srcset = (name: string, ext: "avif" | "webp") =>
  PHOTO_WIDTHS.map((w) => `/fotos/${name}-${w}.${ext} ${w}w`).join(", ");

/** Foto real responsiva em AVIF/WebP com dimensões fixas (evita layout shift). */
export function Picture({
  photo,
  sizes,
  priority = false,
  className = "",
}: {
  photo: Photo;
  sizes: string;
  priority?: boolean;
  className?: string;
}) {
  return (
    <picture>
      <source type="image/avif" srcSet={srcset(photo.name, "avif")} sizes={sizes} />
      <source type="image/webp" srcSet={srcset(photo.name, "webp")} sizes={sizes} />
      <img
        src={`/fotos/${photo.name}-1280.webp`}
        alt={photo.alt}
        width={photo.width}
        height={photo.height}
        loading={priority ? "eager" : "lazy"}
        decoding={priority ? "sync" : "async"}
        {...(priority ? { fetchPriority: "high" as const } : {})}
        className={`h-full w-full object-cover ${className}`}
      />
    </picture>
  );
}

/**
 * Espaço para foto real. Sem foto cadastrada, mostra uma composição gráfica
 * (marcas de grelha + texto) que não se passa por fotografia.
 */
export function PhotoSlot({
  photo,
  sizes,
  priority,
  label,
  children,
  className = "",
}: {
  photo: Photo | null | undefined;
  sizes: string;
  priority?: boolean;
  /** Texto curto exibido na composição sem foto. */
  label?: string;
  children?: ReactNode;
  className?: string;
}) {
  if (photo) {
    return (
      <div className={`relative overflow-hidden bg-carvao-2 ${className}`}>
        <Picture photo={photo} sizes={sizes} priority={priority} />
        {photo.credit ? (
          <span className="absolute right-2 bottom-2 rounded-sm bg-carvao/70 px-2 py-0.5 text-[0.65rem] text-creme-2">
            Foto: {photo.credit}
          </span>
        ) : null}
      </div>
    );
  }
  return (
    <div className={`grill grain relative overflow-hidden ${className}`} role="presentation">
      {children}
      {label ? (
        <span className="absolute inset-x-0 bottom-0 p-5 text-[0.68rem] font-semibold tracking-[0.28em] text-creme/45 uppercase">
          {label}
        </span>
      ) : null}
    </div>
  );
}
