import { TIMEZONE, WEEK, type Interval } from "../data/hours";

export function formatTime(minutes: number): string {
  const hh = Math.floor(minutes / 60);
  const mm = minutes % 60;
  return mm === 0 ? `${hh}h` : `${hh}h${String(mm).padStart(2, "0")}`;
}

export function formatIntervals(intervals: readonly Interval[]): string {
  if (intervals.length === 0) return "Fechado";
  return intervals.map(([o, c]) => `${formatTime(o)} às ${formatTime(c)}`).join(" · ");
}

const WEEKDAY_INDEX: Record<string, number> = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };

/** Dia da semana e minutos no fuso de São Paulo, independente do fuso do visitante. */
export function nowInSaoPaulo(date = new Date()): { dow: number; minutes: number } {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: TIMEZONE,
    weekday: "short",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).formatToParts(date);
  const get = (type: string) => parts.find((p) => p.type === type)?.value ?? "";
  const dow = WEEKDAY_INDEX[get("weekday")] ?? 0;
  const minutes = Number(get("hour")) * 60 + Number(get("minute"));
  return { dow, minutes };
}

export type OpenStatus = { open: boolean; label: string; detail: string; dow: number };

export function getOpenStatus(date = new Date()): OpenStatus {
  const { dow, minutes } = nowInSaoPaulo(date);
  const today = WEEK[dow]!.intervals;

  const current = today.find(([o, c]) => minutes >= o && minutes < c);
  if (current) {
    return { open: true, label: "Aberto agora", detail: `fecha às ${formatTime(current[1])}`, dow };
  }

  const laterToday = today.find(([o]) => o > minutes);
  if (laterToday) {
    return { open: false, label: "Fechado agora", detail: `abre hoje às ${formatTime(laterToday[0])}`, dow };
  }

  for (let i = 1; i <= 7; i++) {
    const d = (dow + i) % 7;
    const first = WEEK[d]!.intervals[0];
    if (first) {
      const when = i === 1 ? "amanhã" : WEEK[d]!.day.toLowerCase();
      return { open: false, label: "Fechado agora", detail: `abre ${when} às ${formatTime(first[0])}`, dow };
    }
  }
  return { open: false, label: "Fechado", detail: "", dow };
}
