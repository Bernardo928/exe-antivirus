import { PHOTOS } from "../data/photos";
import { LINKS, MENU, type MenuItem } from "../data/site";
import { IconArrowUpRight, IconBag } from "./Icons";
import { PhotoSlot } from "./Photo";
import { ExternalLink, SectionHeading } from "./ui";

export function Menu() {
  return (
    <section id="cardapio" aria-labelledby="titulo-cardapio" className="bg-creme py-24 text-carvao sm:py-32">
      <div className="mx-auto max-w-[90rem] px-5 sm:px-8 lg:px-12">
        <div className="flex flex-col gap-10 lg:flex-row lg:items-end lg:justify-between">
          <div className="[&_.eyebrow]:text-brasa [&_.text-creme-2]:text-carvao/70">
            <SectionHeading
              id="titulo-cardapio"
              eyebrow="Cardápio"
              title={
                <>
                  Os burgers <em className="text-brasa">da casa</em>.
                </>
              }
            >
              <p>Preços, acompanhamentos e bebidas ficam no cardápio atualizado do iFood.</p>
            </SectionHeading>
          </div>
          <ExternalLink href={LINKS.ifood} className="btn btn-dark self-start lg:self-auto">
            <IconBag className="text-lg" />
            Ver cardápio completo no iFood
          </ExternalLink>
        </div>

        <ol className="mt-16 grid gap-6 sm:grid-cols-2 xl:grid-cols-4">
          {MENU.map((item, i) => (
            <MenuCard key={item.id} item={item} index={i} />
          ))}
        </ol>
      </div>
    </section>
  );
}

function MenuCard({ item, index }: { item: MenuItem; index: number }) {
  const number = String(index + 1).padStart(2, "0");
  const titleId = `item-${item.id}`;
  return (
    <li
      className="group flex flex-col overflow-hidden rounded-[6px] border border-carvao/12 bg-[#fbf5ea] transition-[transform,box-shadow] duration-300 hover:-translate-y-1 hover:shadow-[0_24px_50px_-28px_rgb(21_17_14/0.55)]"
      aria-labelledby={titleId}
      data-reveal
    >
      <PhotoSlot photo={PHOTOS.menu[item.id]} sizes="(min-width: 1280px) 22vw, (min-width: 640px) 45vw, 92vw" className="aspect-[4/3]">
        <div className="absolute inset-0 flex items-end justify-between p-6">
          <span className="display text-7xl leading-none text-creme/15 italic">{number}</span>
          <span className="text-[0.65rem] font-semibold tracking-[0.25em] text-creme/45 uppercase">Foto em breve</span>
        </div>
      </PhotoSlot>

      <div className="flex flex-1 flex-col p-6">
        <div className="flex items-center justify-between gap-3">
          {item.tag ? (
            <span className="text-[0.68rem] font-bold tracking-[0.22em] text-brasa uppercase">{item.tag}</span>
          ) : (
            <span />
          )}
          <span className="text-xs text-carvao/60 tabular-nums">{number}</span>
        </div>
        <h3 id={titleId} className="display mt-3 text-[1.9rem] leading-tight">
          {item.name}
        </h3>
        <ul className="mt-4 space-y-1.5 text-[0.95rem] text-carvao/75">
          {item.ingredients.map((ing) => (
            <li key={ing} className="flex gap-2.5">
              <span aria-hidden="true" className="mt-[0.6em] h-px w-3 shrink-0 bg-brasa" />
              {ing}
            </li>
          ))}
        </ul>
        {item.availability ? (
          <p className="mt-4 rounded-[4px] bg-carvao/5 px-3 py-2 text-xs leading-relaxed text-carvao/70">
            {item.availability}
          </p>
        ) : null}

        <div className="mt-auto flex items-center justify-between gap-4 pt-6">
          {item.price ? (
            <span className="display text-2xl">{item.price}</span>
          ) : (
            <span className="text-xs text-carvao/70">Preço no iFood</span>
          )}
          <ExternalLink
            href={LINKS.ifood}
            className="inline-flex min-h-11 items-center gap-1.5 text-sm font-semibold text-carvao transition-colors hover:text-brasa"
            aria-label={`Pedir ${item.name} no iFood`}
          >
            <span className="link-underline">Pedir</span>
            <IconArrowUpRight className="transition-transform duration-200 group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
          </ExternalLink>
        </div>
      </div>
    </li>
  );
}
