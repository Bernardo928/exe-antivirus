import { StrictMode } from "react";
import { renderToString } from "react-dom/server";
import { PAGES } from "./pages";

export function render(page: string): string {
  const Page = PAGES[page];
  if (!Page) throw new Error(`Página desconhecida: ${page}`);
  return renderToString(
    <StrictMode>
      <Page />
    </StrictMode>,
  );
}

import { LINKS, SITE } from "./data/site";
import { WEEK } from "./data/hours";

const DAY_SCHEMA = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const hhmm = (m: number) => `${String(Math.floor(m / 60)).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}`;

/** Dados estruturados (schema.org) gerados a partir de src/data, sem nada inventado. */
export function structuredData(page: string, siteUrl: string | null): object[] {
  const abs = (p: string) => (siteUrl ? new URL(p, siteUrl).href : undefined);
  if (page === "home") {
    return [
      {
        "@context": "https://schema.org",
        "@type": "Restaurant",
        name: SITE.name,
        legalName: SITE.legalName,
        ...(siteUrl ? { url: abs("/"), image: abs("/og-image.png") } : {}),
        telephone: "+55 11 93912-3396",
        priceRange: "R$ 60-80",
        servesCuisine: ["Hambúrguer"],
        address: {
          "@type": "PostalAddress",
          streetAddress: SITE.address.street,
          addressLocality: SITE.address.city,
          addressRegion: SITE.address.state,
          postalCode: SITE.address.postalCode,
          addressCountry: SITE.address.country,
        },
        hasMap: LINKS.maps,
        hasMenu: LINKS.ifood,
        sameAs: [LINKS.instagram, LINKS.tiktok],
        founder: { "@type": "Person", name: SITE.owner },
        openingHoursSpecification: WEEK.flatMap((d, i) =>
          d.intervals.map(([o, c]) => ({
            "@type": "OpeningHoursSpecification",
            dayOfWeek: `https://schema.org/${DAY_SCHEMA[i]}`,
            opens: hhmm(o),
            closes: hhmm(c),
          })),
        ),
      },
    ];
  }
  if (page === "privacidade" || page === "termos") {
    const name = page === "privacidade" ? "Política de privacidade" : "Termos de uso";
    return [
      {
        "@context": "https://schema.org",
        "@type": "BreadcrumbList",
        itemListElement: [
          { "@type": "ListItem", position: 1, name: "Início", ...(siteUrl ? { item: abs("/") } : {}) },
          { "@type": "ListItem", position: 2, name, ...(siteUrl ? { item: abs(`/${page}/`) } : {}) },
        ],
      },
    ];
  }
  return [];
}
