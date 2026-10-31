import { useCallback, useEffect, useRef, useState } from "react";
import { CATEGORY_LABEL, PHOTOS, type Photo, type PhotoCategory } from "../data/photos";
import { LINKS } from "../data/site";
import { IconArrowUpRight, IconChevronLeft, IconChevronRight, IconClose } from "./Icons";
import { Picture } from "./Photo";
import { ExternalLink, SectionHeading } from "./ui";

const RESERVED: PhotoCategory[] = ["burger", "batata", "ambiente", "fachada", "detalhe"];

export function Gallery({ photos = PHOTOS.gallery }: { photos?: Photo[] }) {
  const [index, setIndex] = useState<number | null>(null);

  return (
    <section id="galeria" aria-labelledby="titulo-galeria" className="py-24 sm:py-32">
      <div className="mx-auto max-w-[90rem] px-5 sm:px-8 lg:px-12">
        <div className="flex flex-col gap-8 lg:flex-row lg:items-end lg:justify-between">
          <SectionHeading
            id="titulo-galeria"
            eyebrow="Galeria"
            title={
              <>
                Da chapa <em className="text-mostarda">para a mesa</em>.
              </>
            }
          >
            {photos.length > 0 ? (
              <p>Toque em uma foto para ampliar.</p>
            ) : (
              <p>As fotos oficiais da casa entram aqui. Enquanto isso, o dia a dia do Gaba está no Instagram.</p>
            )}
          </SectionHeading>
          <ExternalLink href={LINKS.instagram} className="btn btn-ghost self-start lg:self-auto">
            Ver no Instagram
            <IconArrowUpRight />
          </ExternalLink>
        </div>

        {photos.length > 0 ? (
          <ul className="mt-14 columns-1 gap-4 sm:columns-2 lg:columns-3 [&>li]:mb-4">
            {photos.map((p, i) => (
              <li key={p.name} className="break-inside-avoid" data-reveal>
                <button
                  type="button"
                  onClick={() => setIndex(i)}
                  className="group relative block w-full overflow-hidden rounded-[6px] bg-carvao-2"
                  aria-label={`Ampliar foto: ${p.alt}`}
                >
                  <Picture
                    photo={p}
                    sizes="(min-width: 1024px) 30vw, (min-width: 640px) 46vw, 92vw"
                    className="transition-transform duration-700 ease-[var(--ease-out-soft)] group-hover:scale-[1.03]"
                  />
                  <span className="absolute top-3 left-3 rounded-[3px] bg-carvao/75 px-2.5 py-1 text-[0.65rem] font-semibold tracking-[0.2em] uppercase opacity-0 transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100">
                    {CATEGORY_LABEL[p.category]}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <ul className="mt-14 grid auto-rows-[11rem] grid-cols-2 gap-4 sm:auto-rows-[14rem] lg:grid-cols-4">
            {RESERVED.map((c, i) => (
              <li
                key={c}
                data-reveal
                className={`grill grain relative overflow-hidden rounded-[6px] ${
                  i === 0 ? "col-span-2 row-span-2" : i === 3 ? "col-span-2 lg:col-span-1" : ""
                }`}
              >
                <span className="absolute inset-x-0 bottom-0 flex items-end justify-between p-5">
                  <span className="display text-xl text-creme/70 sm:text-2xl">{CATEGORY_LABEL[c]}</span>
                  <span className="text-[0.6rem] font-semibold tracking-[0.25em] text-creme/40 uppercase">
                    Foto em breve
                  </span>
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {index !== null && photos[index] ? (
        <Lightbox photos={photos} index={index} onChange={setIndex} onClose={() => setIndex(null)} />
      ) : null}
    </section>
  );
}

function Lightbox({
  photos,
  index,
  onChange,
  onClose,
}: {
  photos: Photo[];
  index: number;
  onChange: (i: number) => void;
  onClose: () => void;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const touchX = useRef<number | null>(null);
  const photo = photos[index]!;
  const prev = useCallback(() => onChange((index - 1 + photos.length) % photos.length), [index, photos.length, onChange]);
  const next = useCallback(() => onChange((index + 1) % photos.length), [index, photos.length, onChange]);

  // <dialog> nativo: foco preso no modal, Esc fecha e o foco volta para o botão de origem.
  useEffect(() => {
    const d = dialogRef.current;
    if (!d) return;
    const opener = document.activeElement as HTMLElement | null;
    d.showModal();
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prevOverflow;
      opener?.focus();
    };
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "ArrowLeft") prev();
      if (e.key === "ArrowRight") next();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [prev, next]);

  return (
    <dialog
      ref={dialogRef}
      aria-label="Foto ampliada"
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      onTouchStart={(e) => {
        touchX.current = e.touches[0]?.clientX ?? null;
      }}
      onTouchEnd={(e) => {
        const start = touchX.current;
        const end = e.changedTouches[0]?.clientX;
        if (start == null || end == null) return;
        if (end - start > 50) prev();
        if (start - end > 50) next();
        touchX.current = null;
      }}
      className="m-0 h-dvh max-h-none w-screen max-w-none bg-carvao/95 p-0 text-creme backdrop:bg-black/70"
    >
      <div className="flex h-full flex-col">
        <div className="flex items-center justify-between px-5 py-4 sm:px-8">
          <p className="text-sm text-creme-2 tabular-nums" aria-live="polite">
            {index + 1} / {photos.length} · {CATEGORY_LABEL[photo.category]}
          </p>
          <button
            type="button"
            onClick={onClose}
            className="grid size-12 place-items-center rounded-[var(--radius-btn)] border border-linha text-2xl hover:border-creme/50"
            aria-label="Fechar"
            autoFocus
          >
            <IconClose />
          </button>
        </div>

        <figure className="relative flex min-h-0 flex-1 items-center justify-center px-4 pb-4 sm:px-20">
          <div className="max-h-full max-w-full overflow-hidden rounded-[6px] [&_img]:max-h-[calc(100dvh-10rem)] [&_img]:w-auto [&_img]:object-contain">
            <Picture key={photo.name} photo={photo} sizes="100vw" priority />
          </div>
          <figcaption className="sr-only">{photo.alt}</figcaption>

          {photos.length > 1 ? (
            <>
              <button
                type="button"
                onClick={prev}
                aria-label="Foto anterior"
                className="absolute left-2 grid size-12 place-items-center rounded-[var(--radius-btn)] bg-carvao/70 text-2xl hover:bg-carvao sm:left-5"
              >
                <IconChevronLeft />
              </button>
              <button
                type="button"
                onClick={next}
                aria-label="Próxima foto"
                className="absolute right-2 grid size-12 place-items-center rounded-[var(--radius-btn)] bg-carvao/70 text-2xl hover:bg-carvao sm:right-5"
              >
                <IconChevronRight />
              </button>
            </>
          ) : null}
        </figure>
        {photo.credit ? <p className="pb-4 text-center text-xs text-fumo">Foto: {photo.credit}</p> : null}
      </div>
    </dialog>
  );
}
