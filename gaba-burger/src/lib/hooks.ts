import { useEffect, useState } from "react";
import { getOpenStatus, type OpenStatus } from "./hours";

/** Status aberto/fechado calculado no navegador (fuso de São Paulo), atualizado a cada minuto. */
export function useOpenStatus(): OpenStatus | null {
  // null no HTML pré-renderizado: evita mostrar um status congelado do momento do build.
  const [status, setStatus] = useState<OpenStatus | null>(null);
  useEffect(() => {
    const update = () => setStatus(getOpenStatus());
    update();
    const t = window.setInterval(update, 60_000);
    return () => window.clearInterval(t);
  }, []);
  return status;
}

/** Seção visível no momento, para destacar o item do menu. */
export function useScrollSpy(ids: readonly string[]): string {
  const [active, setActive] = useState(ids[0] ?? "");
  useEffect(() => {
    const els = ids.map((id) => document.getElementById(id)).filter((e): e is HTMLElement => !!e);
    if (els.length === 0 || !("IntersectionObserver" in window)) return;
    const visible = new Map<string, number>();
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) visible.set(e.target.id, e.isIntersecting ? e.intersectionRatio : 0);
        let best = "";
        let bestRatio = 0;
        for (const id of ids) {
          const r = visible.get(id) ?? 0;
          if (r > bestRatio) {
            best = id;
            bestRatio = r;
          }
        }
        if (best) setActive(best);
      },
      { rootMargin: "-35% 0px -55% 0px", threshold: [0, 0.01, 0.25, 0.5, 1] },
    );
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, [ids]);
  return active;
}

/** Revela elementos [data-reveal] que começam fora da tela. Nada fica escondido sem JS. */
export function useReveal() {
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    if (!("IntersectionObserver" in window)) return;
    const vh = window.innerHeight;
    const targets = Array.from(document.querySelectorAll<HTMLElement>("[data-reveal]")).filter(
      (el) => el.getBoundingClientRect().top > vh * 0.95,
    );
    targets.forEach((el) => el.classList.add("reveal-pending"));
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (!e.isIntersecting) continue;
          const el = e.target as HTMLElement;
          el.classList.add("reveal-done");
          el.classList.remove("reveal-pending");
          io.unobserve(el);
        }
      },
      { rootMargin: "0px 0px -8% 0px" },
    );
    targets.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, []);
}
