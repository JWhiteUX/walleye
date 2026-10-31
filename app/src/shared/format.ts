// Display helpers shared by all views. Timestamps are microseconds (UTC).

/** "2026-03-12 09:04:05.123456Z" */
export function formatTs(us: number): string {
  const ms = Math.floor(us / 1000);
  const frac = String(((us % 1_000_000) + 1_000_000) % 1_000_000).padStart(6, "0");
  return new Date(ms).toISOString().slice(0, 19).replace("T", " ") + "." + frac + "Z";
}

/** "09:04:05.123" — for dense columns and axes. */
export function formatTime(us: number): string {
  return new Date(Math.floor(us / 1000)).toISOString().slice(11, 23);
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

export function formatDuration(us: number): string {
  if (us < 1000) return `${us} µs`;
  if (us < 1_000_000) return `${(us / 1000).toFixed(1)} ms`;
  const s = us / 1_000_000;
  if (s < 60) return `${s.toFixed(s < 10 ? 2 : 1)} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${Math.round(s % 60)}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

const PROTO: Record<number, string> = { 1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6" };
export const protoName = (p: number): string => PROTO[p] ?? `IP/${p}`;

/** Defang for display: never show a live, clickable indicator. */
export function defang(v: string): string {
  return v.replace(/^http/i, "hxxp").replace(/\./g, "[.]");
}
