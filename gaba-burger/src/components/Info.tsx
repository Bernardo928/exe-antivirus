import { useState } from "react";
import { DISPLAY_ORDER, HOURS_NOTE, WEEK } from "../data/hours";
import { FAQ, LINKS, SITE } from "../data/site";
import { formatIntervals } from "../lib/hours";
import { useOpenStatus } from "../lib/hooks";
import { IconArrowUpRight, IconBag, IconClock, IconInstagram, IconPhone, IconPin, IconRoute, IconTiktok } from "./Icons";
import { ExternalLink, SectionHeading } from "./ui";

export function Hours() {
  const status = useOpenStatus();
  return (
    <section id="horarios" aria-labelledby="titulo-horarios" className="border-t border-linha bg-carvao-2 py-24 sm:py-32">
      <div className="mx-auto grid max-w-[90rem] grid-cols-[minmax(0,1fr)] gap-14 px-5 sm:px-8 lg:grid-cols-[0.9fr_1.1fr] lg:gap-24 lg:px-12">
        <div>
          <SectionHeading
            id="titulo-horarios"
            eyebrow="Horários"
            title={
              <>
                De quarta <em className="text-mostarda">a domingo</em>.
              </>
            }
          >
            <p>Jantar de quarta a domingo. Sábado e domingo também tem almoço.</p>
          </SectionHeading>
          <p className="mt-8 flex items-start gap-3 rounded-[6px] border border-mostarda/30 bg-mostarda/5 p-4 text-sm leading-relaxed text-creme-2">
            <IconClock className="mt-0.5 shrink-0 text-lg text-mostarda" />
            <span>
              {HOURS_NOTE} Telefone:{" "}
              <a href={LINKS.phone} className="font-semibold text-creme underline decoration-mostarda/60 underline-offset-4">
                {SITE.phone.display}
              </a>
              .
            </span>
          </p>
        </div>

        <div data-reveal>
          <table className="w-full border-collapse text-left">
            <caption className="sr-only">Horário de funcionamento do Gaba Burger</caption>
            <thead className="sr-only">
              <tr>
                <th scope="col">Dia</th>
                <th scope="col">Horário</th>
              </tr>
            </thead>
            <tbody>
              {DISPLAY_ORDER.map((d) => {
                const day = WEEK[d]!;
                const isToday = status?.dow === d;
                const closed = day.intervals.length === 0;
                return (
                  <tr
                    key={day.day}
                    className={`border-b border-linha transition-colors ${isToday ? "bg-creme/[0.04]" : ""}`}
                    aria-current={isToday ? "date" : undefined}
                  >
                    <th scope="row" className="py-5 pr-4 pl-3 align-top font-normal sm:pl-5">
                      <span className="display text-2xl">{day.day}</span>
                      {isToday ? (
                        <span className="ml-3 align-middle text-[0.65rem] font-bold tracking-[0.22em] text-mostarda uppercase">
                          Hoje
                        </span>
                      ) : null}
                    </th>
                    <td
                      className={`py-5 pr-3 text-right align-top tabular-nums sm:pr-5 ${
                        closed ? "text-fumo" : "text-creme"
                      }`}
                    >
                      {closed
                        ? "Fechado"
                        : day.intervals.map((iv, i) => (
                            <span key={i} className="block sm:inline">
                              {i > 0 ? <span className="hidden px-2 text-fumo sm:inline">·</span> : null}
                              {formatIntervals([iv])}
                            </span>
                          ))}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {status ? (
            <p className="mt-5 flex items-center gap-2.5 px-3 text-sm text-creme-2 sm:px-5" aria-live="polite">
              <span className={`size-2 rounded-full ${status.open ? "bg-aberto" : "bg-fumo"}`} aria-hidden="true" />
              {status.label}
              {status.detail ? ` · ${status.detail}` : ""} (horário de São Paulo)
            </p>
          ) : null}
        </div>
      </div>
    </section>
  );
}

export function Location() {
  const [mapLoaded, setMapLoaded] = useState(false);
  return (
    <section id="localizacao" aria-labelledby="titulo-localizacao" className="py-24 sm:py-32">
      <div className="mx-auto grid max-w-[90rem] grid-cols-[minmax(0,1fr)] gap-14 px-5 sm:px-8 lg:grid-cols-[0.9fr_1.1fr] lg:gap-24 lg:px-12">
        <div className="flex flex-col">
          <SectionHeading
            id="titulo-localizacao"
            eyebrow="Localização"
            title={
              <>
                Rua Mourato Coelho, <em className="text-mostarda">833</em>.
              </>
            }
          />
          <address className="mt-8 text-lg leading-relaxed text-creme-2 not-italic" data-reveal>
            {SITE.address.street}
            <br />
            {SITE.address.district}, {SITE.address.city} - {SITE.address.state}
            <br />
            CEP {SITE.address.postalCode}
          </address>
          <div className="mt-10 flex flex-col gap-3 sm:flex-row" data-reveal>
            <ExternalLink href={LINKS.maps} className="btn btn-primary">
              <IconPin className="text-lg" />
              Abrir no Google Maps
            </ExternalLink>
            <ExternalLink href={LINKS.directions} className="btn btn-ghost">
              <IconRoute className="text-lg" />
              Traçar rota
            </ExternalLink>
          </div>
        </div>

        <div className="relative aspect-[4/3] overflow-hidden rounded-[6px] border border-linha bg-carvao-2" data-reveal>
          {mapLoaded ? (
            <iframe
              title="Mapa do Gaba Burger no Google Maps"
              src={LINKS.mapEmbed}
              className="absolute inset-0 h-full w-full border-0 grayscale-[35%]"
              loading="lazy"
              referrerPolicy="no-referrer-when-downgrade"
              sandbox="allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox"
            />
          ) : (
            <div className="grill grain absolute inset-0 flex flex-col items-center justify-center gap-6 p-8 text-center">
              <MapMark />
              <p className="max-w-xs text-sm leading-relaxed text-creme-2">
                O mapa é carregado do Google só quando você pedir.
              </p>
              <button type="button" className="btn btn-ghost" onClick={() => setMapLoaded(true)}>
                Carregar mapa
              </button>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function MapMark() {
  return (
    <svg viewBox="0 0 220 120" className="w-56 text-mostarda" aria-hidden="true" fill="none">
      <path d="M0 78h220M0 40c60 0 90 18 130 18s60-14 90-14" stroke="currentColor" strokeOpacity=".25" strokeWidth="10" />
      <path d="M58 0v120M150 0l-20 120" stroke="currentColor" strokeOpacity=".18" strokeWidth="6" />
      <path d="M110 22c-11 0-19 8-19 18 0 14 19 32 19 32s19-18 19-32c0-10-8-18-19-18Z" fill="currentColor" />
      <circle cx="110" cy="40" r="6" fill="#15110e" />
    </svg>
  );
}

export function Faq() {
  return (
    <section id="perguntas" aria-labelledby="titulo-faq" className="border-t border-linha py-24 sm:py-32">
      <div className="mx-auto grid max-w-[90rem] grid-cols-[minmax(0,1fr)] gap-14 px-5 sm:px-8 lg:grid-cols-[0.9fr_1.1fr] lg:gap-24 lg:px-12">
        <SectionHeading
          id="titulo-faq"
          eyebrow="Perguntas frequentes"
          title={
            <>
              Antes de <em className="text-mostarda">você vir</em>.
            </>
          }
        />
        <div className="border-t border-linha" data-reveal>
          {FAQ.map((f) => (
            <details key={f.q} className="group border-b border-linha">
              <summary className="flex min-h-16 cursor-pointer list-none items-center justify-between gap-6 py-5 text-lg transition-colors hover:text-mostarda [&::-webkit-details-marker]:hidden">
                {f.q}
                <span
                  aria-hidden="true"
                  className="relative size-4 shrink-0 before:absolute before:top-1/2 before:left-0 before:h-px before:w-4 before:bg-current after:absolute after:top-0 after:left-1/2 after:h-4 after:w-px after:bg-current after:transition-transform group-open:after:scale-y-0"
                />
              </summary>
              <p className="pb-6 leading-relaxed text-creme-2">{f.a}</p>
            </details>
          ))}
        </div>
      </div>
    </section>
  );
}

const CONTACTS = [
  { label: "Telefone", value: SITE.phone.display, href: LINKS.phone, Icon: IconPhone },
  { label: "Instagram", value: SITE.social.instagramHandle, href: LINKS.instagram, Icon: IconInstagram },
  { label: "TikTok", value: SITE.social.instagramHandle, href: LINKS.tiktok, Icon: IconTiktok },
  { label: "Pedidos", value: "iFood", href: LINKS.ifood, Icon: IconBag },
] as const;

export function Contact() {
  return (
    <section id="contato" aria-labelledby="titulo-contato" className="bg-brasa py-24 sm:py-32">
      <div className="mx-auto max-w-[90rem] px-5 sm:px-8 lg:px-12">
        <div className="[&_.eyebrow]:text-creme [&_.text-creme-2]:text-creme">
          <SectionHeading
            id="titulo-contato"
            eyebrow="Contato"
            title={
              <>
                Fale com a casa ou <em>peça agora</em>.
              </>
            }
          >
            <p>{SITE.address.full}</p>
          </SectionHeading>
        </div>
        <ul className="mt-14 grid gap-px overflow-hidden rounded-[6px] border border-creme/20 bg-creme/20 sm:grid-cols-2 lg:grid-cols-4">
          {CONTACTS.map(({ label, value, href, Icon }) => (
            <li key={label} className="bg-brasa">
              <ExternalLink
                href={href}
                className="group flex h-full min-h-40 flex-col justify-between gap-8 p-6 transition-colors hover:bg-[#9a3118]"
              >
                <span className="flex items-center justify-between">
                  <Icon className="text-2xl" />
                  <IconArrowUpRight className="text-creme/60 transition-transform duration-200 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 group-hover:text-creme" />
                </span>
                <span>
                  <span className="block text-xs font-semibold tracking-[0.22em] text-creme uppercase">{label}</span>
                  <span className="display mt-1 block text-2xl">{value}</span>
                </span>
              </ExternalLink>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
