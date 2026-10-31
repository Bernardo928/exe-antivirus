import { PHOTOS } from "../data/photos";
import { SITE } from "../data/site";
import { PhotoSlot } from "./Photo";
import { SectionHeading } from "./ui";

const POINTS = [
  { n: "180g", t: "Blend grelhado", d: "Os burgers da casa saem com 180g de carne, grelhados na parrilla." },
  { n: "Casa", t: "Maionese própria", d: "A maionese do Gaba Tasty é feita na cozinha da hamburgueria." },
  { n: "Mês", t: "Burger do mês", d: "Um burger diferente entra no cardápio por tempo limitado." },
] as const;

export function About() {
  return (
    <section id="sobre" aria-labelledby="titulo-sobre" className="border-t border-linha py-24 sm:py-32">
      <div className="mx-auto grid max-w-[90rem] grid-cols-[minmax(0,1fr)] gap-16 px-5 sm:px-8 lg:grid-cols-2 lg:gap-24 lg:px-12">
        <div className="relative order-2 lg:order-1" data-reveal>
          <PhotoSlot
            photo={PHOTOS.about}
            sizes="(min-width: 1024px) 45vw, 92vw"
            label="Ambiente · foto oficial em breve"
            className="aspect-[4/5] w-full rounded-[6px]"
          >
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="display text-[7rem] leading-none text-creme/10 italic sm:text-[10rem]">Gaba</span>
            </div>
          </PhotoSlot>
          <div className="absolute -right-3 -bottom-10 hidden w-[42%] sm:block lg:-right-10">
            <PhotoSlot
              photo={PHOTOS.aboutDetail}
              sizes="(min-width: 1024px) 18vw, 40vw"
              className="aspect-square w-full rounded-[6px] border-8 border-carvao"
            >
              <div className="absolute inset-0 grid place-items-center">
                <span className="display text-5xl text-mostarda italic">180g</span>
              </div>
            </PhotoSlot>
          </div>
        </div>

        <div className="order-1 flex flex-col justify-center lg:order-2">
          <SectionHeading
            id="titulo-sobre"
            eyebrow="Sobre o Gaba Burger"
            title={
              <>
                A hamburgueria do <em className="text-mostarda">Gaba</em>, em Pinheiros.
              </>
            }
          >
            <p>
              {SITE.owner}, o {SITE.ownerNickname}, ficou conhecido viajando pelo Brasil para provar a comida de cada
              lugar. Em Pinheiros, na Rua Mourato Coelho, ele abriu a própria casa: uma hamburgueria com burger
              grelhado na parrilla.
            </p>
            <p className="mt-4">
              Dá para comer no salão de quarta a domingo ou pedir pelo iFood.
            </p>
          </SectionHeading>

          <ul className="mt-12 grid gap-px overflow-hidden rounded-[6px] border border-linha bg-linha sm:grid-cols-3">
            {POINTS.map((p) => (
              <li key={p.t} className="bg-carvao p-6" data-reveal>
                <p className="display text-3xl text-mostarda italic">{p.n}</p>
                <p className="mt-3 font-semibold">{p.t}</p>
                <p className="mt-2 text-sm leading-relaxed text-fumo">{p.d}</p>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
