import type { AnchorHTMLAttributes, ReactNode } from "react";

/**
 * Link externo seguro: abre em nova aba com rel="noopener noreferrer"
 * (impede que a página aberta controle esta via window.opener) e só aceita https/tel.
 */
export function ExternalLink({
  href,
  children,
  newTab = true,
  ...rest
}: AnchorHTMLAttributes<HTMLAnchorElement> & { href: string; newTab?: boolean; children: ReactNode }) {
  const safe = /^(https:\/\/|tel:)/.test(href) ? href : "#";
  const isTel = safe.startsWith("tel:");
  return (
    <a
      href={safe}
      {...(newTab && !isTel ? { target: "_blank", rel: "noopener noreferrer external" } : {})}
      {...rest}
    >
      {children}
      {newTab && !isTel ? <span className="sr-only"> (abre em nova aba)</span> : null}
    </a>
  );
}

export function Eyebrow({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <p className={`eyebrow ${className}`}>{children}</p>;
}

export function SectionHeading({
  eyebrow,
  title,
  id,
  children,
  align = "left",
}: {
  eyebrow: string;
  title: ReactNode;
  id: string;
  children?: ReactNode;
  align?: "left" | "center";
}) {
  return (
    <div className={align === "center" ? "mx-auto max-w-2xl text-center" : "max-w-2xl"} data-reveal>
      <Eyebrow>{eyebrow}</Eyebrow>
      <h2 id={id} className="display mt-5 text-[2.6rem] leading-[1.02] font-normal sm:text-6xl">
        {title}
      </h2>
      {children ? <div className="mt-6 text-lg leading-relaxed text-creme-2">{children}</div> : null}
    </div>
  );
}

export function Wordmark({ className = "" }: { className?: string }) {
  return (
    <span className={`inline-flex items-center gap-3 ${className}`}>
      <span
        aria-hidden="true"
        className="display grid size-11 place-items-center rounded-full border border-creme/40 text-xl italic text-mostarda"
      >
        G
      </span>
      <span className="display text-[1.45rem] leading-none tracking-tight">
        Gaba Burger<span className="text-mostarda">.</span>
      </span>
    </span>
  );
}
