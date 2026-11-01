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

/**
 * Make invisible and direction-changing characters visible, so a hostile
 * capture can't spoof an indicator (e.g. a U+202E right-to-left override in a
 * domain, or an SSID "CorpNet" + U+E0041 TAG LATIN CAPITAL A posing as
 * "CorpNet"). Each such code point becomes `\u{xxxx}` (by code point, so an
 * astral character is one escape, not two UTF-16 halves):
 *
 * - every control (Cc), format (Cf), line (Zl) and paragraph (Zp) separator:
 *   bidi controls, zero-width characters, BOM, soft hyphen, tag characters\u2026
 * - the whole tag block U+E0000\u2013E007F (including unassigned slots)
 * - U+2060\u2013206F (including the unassigned U+2065)
 * - Hangul fillers U+115F, U+1160, U+3164, U+FFA0 (render as blank)
 * - combining grapheme joiner U+034F
 * - variation selectors U+FE00\u2013FE0F, U+E0100\u2013E01EF
 * - Mongolian free variation selectors U+180B\u2013180D (and U+180E, Cf)
 *
 * Keep in sync with `sanitize()` in crates/walleye-case/src/report.rs.
 */
const INVISIBLE =
  // Combining marks (CGJ, the selectors) sit outside the bracket class:
  // \p{Variation_Selector} = U+180B\u2013180D, U+180F, U+FE00\u2013FE0F, U+E0100\u2013E01EF.
  /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\u{E0000}-\u{E007F}\u2060-\u206f\u115f\u1160\u3164\uffa0\u180e]|\p{Variation_Selector}|\u034f/gu;
export function visible(v: string): string {
  return v.replace(INVISIBLE, (c) => `\\u{${c.codePointAt(0)!.toString(16)}}`);
}
