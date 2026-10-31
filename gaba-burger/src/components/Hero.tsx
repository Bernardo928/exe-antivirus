import { PHOTOS } from "../data/photos";
import { LINKS, SITE } from "../data/site";
import { useOpenStatus } from "../lib/hooks";
import { IconArrowDown, IconStar } from "./Icons";
import { PhotoSlot } from "./Photo";
import { ExternalLink } from "./ui";

export function OpenBadge() {
  const status = useOpenStatus();
  return (
    <a
      href="#horarios"
      className="inline-flex min-h-9 items-center gap-2.5 rounded-[var(--radius-btn)] border border-linha px-4 text-[0.72rem] transition-colors hover:border-creme/40"
      aria-live="polite"
    >
      <span
        aria-hidden="true"
        className={`size-2 rounded-full ${status?.open ? "bg-aberto" : status ? "bg-fumo" : "bg-fumo/50"}`}
      />
      {status ? (
        <>
          <span className="font-semibold tracking-[0.2em] uppercase">{status.label}</span>
          {status.detail ? <span className="text-creme-2">· {status.detail}</span> : null}
        </>
      ) : (
        <span className="font-semibold tracking-[0.2em] uppercase">Ver horários</span>
      )}
    </a>
  );
}

export function Hero() {
  return (
    <section id="inicio" aria-labelledby="titulo-inicio" className="relative overflow-hidden pt-28 pb-16 sm:pt-32 lg:pt-36 lg:pb-24">
      <div className="mx-auto grid max-w-[90rem] grid-cols-[minmax(0,1fr)] items-center gap-14 px-5 sm:px-8 lg:grid-cols-[1.15fr_0.85fr] lg:gap-10 lg:px-12">
        <div>
          <div className="flex flex-wrap items-center gap-x-6 gap-y-4">
            <p className="eyebrow">Pinheiros · São Paulo</p>
            <OpenBadge />
          </div>

          <h1
            id="titulo-inicio"
            className="display mt-10 text-[clamp(2.5rem,11.6vw,3.6rem)] leading-[0.92] font-light uppercase sm:text-[5.2rem] lg:text-[6.3rem] xl:text-[7.4rem]"
          >
            Hambúrguer
            <br />
            <em className="font-normal text-mostarda">na brasa</em>
            <br />
            em Pinheiros.
          </h1>

          <p className="mt-9 max-w-[34rem] text-lg leading-relaxed text-creme-2 sm:text-xl">
            A hamburgueria do Gaba na Rua Mourato Coelho. Blend de 180g grelhado na parrilla, queijo derretido e
            maionese feita na casa.
          </p>

          <div className="mt-10 flex flex-col gap-3 sm:flex-row">
            <a href="#cardapio" className="btn btn-primary">
              Ver cardápio
            </a>
            <ExternalLink href={LINKS.directions} className="btn btn-ghost">
              Como chegar
            </ExternalLink>
          </div>

          <ExternalLink
            href={LINKS.maps}
            className="group mt-10 inline-flex items-center gap-3 text-sm text-creme-2"
          >
            <span className="flex gap-0.5 text-mostarda" aria-hidden="true">
              {Array.from({ length: 5 }, (_, i) => (
                <IconStar key={i} />
              ))}
            </span>
            <span>
              <strong className="font-semibold text-creme">{SITE.rating.value}</strong> de 5 ·{" "}
              <span className="link-underline">{SITE.rating.count} avaliações no Google</span>
              <span className="sr-only"> (ver no Google Maps)</span>
            </span>
          </ExternalLink>
        </div>

        <div className="relative mx-auto w-full max-w-[34rem] lg:mr-0">
          <PhotoSlot
            photo={PHOTOS.hero}
            priority
            sizes="(min-width: 1024px) 34rem, 92vw"
            className="arch aspect-[4/5] w-full"
          >
            <HeroGraphic />
          </PhotoSlot>
          <span aria-hidden="true" className="arch pointer-events-none absolute inset-3 border border-mostarda/30" />
          <p
            aria-hidden="true"
            className="display absolute bottom-10 -left-3 -rotate-[6deg] rounded-[3px] bg-brasa px-5 py-2.5 text-xl text-creme italic shadow-[0_10px_30px_rgb(0_0_0/0.35)] sm:-left-8 sm:text-2xl"
          >
            180g na parrilla
          </p>
        </div>
      </div>

      <a
        href="#sobre"
        className="absolute right-6 bottom-6 hidden size-14 place-items-center rounded-full border border-linha text-xl text-creme-2 transition-colors hover:border-creme/50 hover:text-creme lg:grid"
        aria-label="Rolar para a seção Sobre"
      >
        <IconArrowDown />
      </a>
    </section>
  );
}

/** Composição tipográfica para o arco enquanto não houver foto real. */
function HeroGraphic() {
  return (
    <div className="absolute inset-0 flex flex-col items-center justify-center px-10 text-center">
      <span className="eyebrow text-creme/60">Rua Mourato Coelho</span>
      <span className="display mt-4 text-[9rem] leading-none text-mostarda italic sm:text-[11rem]">833</span>
      <span className="mt-4 h-px w-16 bg-mostarda/50" />
      <span className="display mt-5 text-2xl text-creme/80">Gaba Burger</span>
    </div>
  );
}
