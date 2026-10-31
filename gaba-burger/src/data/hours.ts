/** Minutos desde 00h. */
export type Interval = readonly [open: number, close: number];

const h = (hours: number, minutes = 0) => hours * 60 + minutes;

/**
 * Horários de referência (podem sofrer alteração).
 * Índice = dia da semana, 0 = domingo.
 */
export const WEEK: readonly { day: string; short: string; intervals: readonly Interval[] }[] = [
  { day: "Domingo", short: "Dom", intervals: [[h(12), h(16)], [h(18), h(22, 30)]] },
  { day: "Segunda", short: "Seg", intervals: [] },
  { day: "Terça", short: "Ter", intervals: [] },
  { day: "Quarta", short: "Qua", intervals: [[h(18), h(23, 30)]] },
  { day: "Quinta", short: "Qui", intervals: [[h(18), h(23, 30)]] },
  { day: "Sexta", short: "Sex", intervals: [[h(18), h(23, 30)]] },
  { day: "Sábado", short: "Sáb", intervals: [[h(12), h(16)], [h(18), h(23, 30)]] },
];

export const TIMEZONE = "America/Sao_Paulo";

/** Exibição em ordem de segunda a domingo. */
export const DISPLAY_ORDER = [1, 2, 3, 4, 5, 6, 0] as const;

export const HOURS_NOTE =
  "Horários de referência, sujeitos a alteração. Confirme antes da visita.";
