import { useEffect, useRef, useState } from "react";
import { LINKS, NAV } from "../data/site";
import { useScrollSpy } from "../lib/hooks";
import { IconClose, IconMenu, IconPin } from "./Icons";
import { ExternalLink, Wordmark } from "./ui";

const NAV_IDS = NAV.map((n) => n.id);

export function Header({ onHome = true }: { onHome?: boolean }) {
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const active = useScrollSpy(onHome ? NAV_IDS : []);
  const toggleRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const prefix = onHome ? "" : "/";

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 24);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  // Menu mobile: trava a rolagem, fecha com Esc e mantém o foco dentro do painel.
  useEffect(() => {
    if (!open) return;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const first = panelRef.current?.querySelector<HTMLElement>("a,button");
    first?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        toggleRef.current?.focus();
      }
      if (e.key === "Tab" && panelRef.current) {
        const items = Array.from(panelRef.current.querySelectorAll<HTMLElement>("a,button"));
        const firstEl = items[0];
        const lastEl = items[items.length - 1];
        if (!firstEl || !lastEl) return;
        if (e.shiftKey && document.activeElement === firstEl) {
          e.preventDefault();
          lastEl.focus();
        } else if (!e.shiftKey && document.activeElement === lastEl) {
          e.preventDefault();
          firstEl.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = prevOverflow;
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  // Fecha o menu ao voltar para desktop.
  useEffect(() => {
    const mq = window.matchMedia("(min-width: 1024px)");
    const onChange = () => mq.matches && setOpen(false);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  return (
    <header
      className={`fixed inset-x-0 top-0 z-50 transition-[background-color,border-color,backdrop-filter] duration-300 ${
        scrolled || open
          ? "border-b border-linha bg-carvao/90 backdrop-blur-md"
          : "border-b border-transparent bg-transparent"
      }`}
    >
      <div className="mx-auto flex h-20 max-w-[90rem] items-center justify-between gap-6 px-5 sm:px-8 lg:px-12">
        <a href={onHome ? "#inicio" : "/"} className="shrink-0">
          <Wordmark />
          <span className="sr-only">, ir para o início</span>
        </a>

        <nav aria-label="Principal" className="hidden lg:block">
          <ul className="flex items-center gap-8 xl:gap-10">
            {NAV.map((item) => {
              const isActive = onHome && active === item.id;
              return (
                <li key={item.id}>
                  <a
                    href={`${prefix}#${item.id}`}
                    aria-current={isActive ? "true" : undefined}
                    className={`relative py-2 text-[0.95rem] transition-colors duration-200 hover:text-creme ${
                      isActive ? "text-mostarda" : "text-creme-2"
                    }`}
                  >
                    {item.label}
                    <span
                      aria-hidden="true"
                      className={`absolute inset-x-0 -bottom-0.5 h-px origin-left bg-mostarda transition-transform duration-300 ${
                        isActive ? "scale-x-100" : "scale-x-0"
                      }`}
                    />
                  </a>
                </li>
              );
            })}
          </ul>
        </nav>

        <div className="flex items-center gap-3">
          <ExternalLink href={LINKS.directions} className="btn btn-primary hidden sm:inline-flex">
            <IconPin className="text-lg" />
            Como chegar
          </ExternalLink>
          <button
            ref={toggleRef}
            type="button"
            className="grid size-12 place-items-center rounded-[var(--radius-btn)] border border-linha text-2xl text-creme transition-colors hover:border-creme/50 lg:hidden"
            aria-expanded={open}
            aria-controls="menu-mobile"
            aria-label={open ? "Fechar menu" : "Abrir menu"}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? <IconClose /> : <IconMenu />}
          </button>
        </div>
      </div>

      <div
        id="menu-mobile"
        ref={panelRef}
        hidden={!open}
        className="h-[calc(100dvh-5rem)] overflow-y-auto border-t border-linha bg-carvao px-5 pt-6 pb-10 sm:px-8 lg:hidden"
      >
        <nav aria-label="Menu mobile">
          <ul className="flex flex-col">
            {NAV.map((item, i) => (
              <li key={item.id} className="border-b border-linha">
                <a
                  href={`${prefix}#${item.id}`}
                  onClick={(e) => {
                    setOpen(false);
                    if (!onHome) return;
                    // Fecha o menu primeiro e só então rola: com o painel aberto a página está travada.
                    e.preventDefault();
                    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
                    window.setTimeout(() => {
                      document.getElementById(item.id)?.scrollIntoView({ behavior: reduce ? "auto" : "smooth" });
                      history.pushState(null, "", `#${item.id}`);
                    }, 0);
                  }}
                  className="display flex items-baseline justify-between py-4 text-[2rem] leading-none transition-colors hover:text-mostarda"
                >
                  {item.label}
                  <span className="font-sans text-xs tracking-[0.2em] text-fumo">{String(i + 1).padStart(2, "0")}</span>
                </a>
              </li>
            ))}
          </ul>
        </nav>
        <div className="mt-8 grid gap-3">
          <ExternalLink href={LINKS.directions} className="btn btn-primary w-full">
            <IconPin className="text-lg" /> Como chegar
          </ExternalLink>
          <ExternalLink href={LINKS.ifood} className="btn btn-ghost w-full">
            Pedir no iFood
          </ExternalLink>
        </div>
      </div>
    </header>
  );
}
