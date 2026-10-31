import type { SVGProps } from "react";

type P = SVGProps<SVGSVGElement>;

function Base({ children, ...p }: P) {
  return (
    <svg
      viewBox="0 0 24 24"
      width="1em"
      height="1em"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...p}
    >
      {children}
    </svg>
  );
}

export const IconPin = (p: P) => (
  <Base {...p}>
    <path d="M12 21s-7-6.2-7-11.5A7 7 0 0 1 19 9.5C19 14.8 12 21 12 21Z" />
    <circle cx="12" cy="9.5" r="2.5" />
  </Base>
);

export const IconPhone = (p: P) => (
  <Base {...p}>
    <path d="M5 3.5h3l1.6 4.3-2 1.3a11 11 0 0 0 5.3 5.3l1.3-2 4.3 1.6v3A2 2 0 0 1 16.4 19 14 14 0 0 1 3 5.6a2 2 0 0 1 2-2.1Z" />
  </Base>
);

export const IconInstagram = (p: P) => (
  <Base {...p}>
    <rect x="3.5" y="3.5" width="17" height="17" rx="4.5" />
    <circle cx="12" cy="12" r="4" />
    <circle cx="17.2" cy="6.8" r="0.6" fill="currentColor" stroke="none" />
  </Base>
);

export const IconTiktok = (p: P) => (
  <Base {...p}>
    <path d="M14 3.5v11.2a3.8 3.8 0 1 1-3.8-3.8" />
    <path d="M14 3.5c.4 2.6 2.2 4.4 5 4.7" />
  </Base>
);

export const IconBag = (p: P) => (
  <Base {...p}>
    <path d="M5 8h14l-1 12H6L5 8Z" />
    <path d="M9 8V6.5a3 3 0 0 1 6 0V8" />
  </Base>
);

export const IconClock = (p: P) => (
  <Base {...p}>
    <circle cx="12" cy="12" r="8.5" />
    <path d="M12 7.5V12l3 2" />
  </Base>
);

export const IconArrowRight = (p: P) => (
  <Base {...p}>
    <path d="M5 12h14M13 6l6 6-6 6" />
  </Base>
);

export const IconArrowUpRight = (p: P) => (
  <Base {...p}>
    <path d="M7 17 17 7M8 7h9v9" />
  </Base>
);

export const IconArrowDown = (p: P) => (
  <Base {...p}>
    <path d="M12 5v14M6 13l6 6 6-6" />
  </Base>
);

export const IconMenu = (p: P) => (
  <Base {...p}>
    <path d="M4 7h16M4 12h16M4 17h10" />
  </Base>
);

export const IconClose = (p: P) => (
  <Base {...p}>
    <path d="M6 6l12 12M18 6 6 18" />
  </Base>
);

export const IconChevronLeft = (p: P) => (
  <Base {...p}>
    <path d="M15 5 8 12l7 7" />
  </Base>
);

export const IconChevronRight = (p: P) => (
  <Base {...p}>
    <path d="m9 5 7 7-7 7" />
  </Base>
);

export const IconStar = (p: P) => (
  <Base {...p} fill="currentColor" stroke="none">
    <path d="m12 3.2 2.6 5.5 6 .7-4.4 4.1 1.2 6-5.4-3-5.4 3 1.2-6L3.4 9.4l6-.7L12 3.2Z" />
  </Base>
);

export const IconFlame = (p: P) => (
  <Base {...p}>
    <path d="M12 21c-3.9 0-6.5-2.6-6.5-6.1 0-3.7 3-5.6 3.6-9.4 2.4 1.4 3.6 3.4 3.7 5.4 1-.9 1.6-2.1 1.7-3.4 2.4 1.9 4 4.4 4 7.4 0 3.5-2.6 6.1-6.5 6.1Z" />
  </Base>
);

export const IconRoute = (p: P) => (
  <Base {...p}>
    <circle cx="6" cy="18" r="2" />
    <circle cx="18" cy="6" r="2" />
    <path d="M8 18h7a3 3 0 0 0 0-6H9a3 3 0 0 1 0-6h7" />
  </Base>
);
