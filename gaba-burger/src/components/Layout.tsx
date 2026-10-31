import type { ReactNode } from "react";
import { LINKS, NAV, SITE } from "../data/site";
import { useReveal } from "../lib/hooks";
import { Header } from "./Header";
import { IconBag, IconPin } from "./Icons";
import { ExternalLink, Wordmark } from "./ui";

const YEAR = new Date().getFullYear();

export function Layout({ children, onHome = false }: { children: ReactNode; onHome?: boolean }) {
  useReveal();
  return (
    <>
      <a
        href="#conteudo"
        className="sr-only z-[60] rounded-[var(--radius-btn)] bg-mostarda px-4 py-3 font-semibold text-carvao focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
      >
        Pular para o conteúdo
      </a>
      <Header onHome={onHome} />
      <main id="conteudo" tabIndex={-1} className="outline-none">
        {children}
      </main>
      <Footer onHome={onHome} />
      <MobileCta />
    </>
  );
}

function Footer({ onHome }: { onHome: boolean }) {
  const prefix = onHome ? "" : "/";
  return (
    <footer className="border-t border-linha pt-20 pb-28 lg:pb-12">
      <div className="mx-auto max-w-[90rem] px-5 sm:px-8 lg:px-12">
        <div className="grid gap-12 lg:grid-cols-[1.2fr_1fr_1fr]">
          <div>
            <Wordmark />
            <p className="mt-6 max-w-sm leading-relaxed text-fumo">
              Hamburgueria em Pinheiros, São Paulo. {SITE.address.street}.
            </p>
          </div>
          <nav aria-label="Rodapé">
            <p className="eyebrow">Navegar</p>
            <ul className="mt-5 grid grid-cols-2 gap-x-6 gap-y-3 text-creme-2">
              {NAV.map((n) => (
                <li key={n.id}>
                  <a href={`${prefix}#${n.id}`} className="link-underline hover:text-creme">
                    {n.label}
                  </a>
                </li>
              ))}
              <li>
                <a href={`${prefix}#perguntas`} className="link-underline hover:text-creme">
                  Perguntas
                </a>
              </li>
            </ul>
          </nav>
          <div>
            <p className="eyebrow">Redes e pedidos</p>
            <ul className="mt-5 space-y-3 text-creme-2">
              <li>
                <ExternalLink href={LINKS.instagram} className="link-underline hover:text-creme">
                  Instagram {SITE.social.instagramHandle}
                </ExternalLink>
              </li>
              <li>
                <ExternalLink href={LINKS.tiktok} className="link-underline hover:text-creme">
                  TikTok {SITE.social.instagramHandle}
                </ExternalLink>
              </li>
              <li>
                <ExternalLink href={LINKS.ifood} className="link-underline hover:text-creme">
                  Pedir no iFood
                </ExternalLink>
              </li>
              <li>
                <a href={LINKS.phone} className="link-underline hover:text-creme">
                  {SITE.phone.display}
                </a>
              </li>
            </ul>
          </div>
        </div>

        <div className="mt-16 flex flex-col gap-4 border-t border-linha pt-8 text-sm text-fumo sm:flex-row sm:items-center sm:justify-between">
          <p>
            © {YEAR} {SITE.legalName} · CNPJ {SITE.cnpj}
          </p>
          <ul className="flex gap-6">
            <li>
              <a href="/privacidade/" className="link-underline hover:text-creme">
                Política de privacidade
              </a>
            </li>
            <li>
              <a href="/termos/" className="link-underline hover:text-creme">
                Termos de uso
              </a>
            </li>
          </ul>
        </div>
      </div>
    </footer>
  );
}

/** Barra fixa no celular: as duas ações principais sempre à mão. */
function MobileCta() {
  return (
    <div className="fixed inset-x-0 bottom-0 z-40 grid grid-cols-2 gap-px border-t border-linha bg-linha pb-[env(safe-area-inset-bottom)] lg:hidden">
      <ExternalLink href={LINKS.ifood} className="flex min-h-14 items-center justify-center gap-2 bg-mostarda font-semibold text-carvao active:bg-mostarda-2">
        <IconBag className="text-lg" /> Pedir no iFood
      </ExternalLink>
      <ExternalLink href={LINKS.directions} className="flex min-h-14 items-center justify-center gap-2 bg-carvao font-semibold text-creme active:bg-carvao-3">
        <IconPin className="text-lg" /> Como chegar
      </ExternalLink>
    </div>
  );
}

export function Breadcrumbs({ current }: { current: string }) {
  return (
    <nav aria-label="Trilha de navegação" className="text-sm text-fumo">
      <ol className="flex items-center gap-2">
        <li>
          <a href="/" className="link-underline hover:text-creme">
            Início
          </a>
        </li>
        <li aria-hidden="true">/</li>
        <li aria-current="page" className="text-creme-2">
          {current}
        </li>
      </ol>
    </nav>
  );
}
