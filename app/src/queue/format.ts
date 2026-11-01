// Display helpers for the suspicion queue. Pure; see format.test.ts.
import type { Evidence } from "../shared/bindings/Evidence";
import type { Finding } from "../shared/bindings/Finding";
import type { Verdict } from "../shared/bindings/Verdict";

export const VERDICTS: { value: Verdict; label: string; key: string }[] = [
  { value: "suspicious", label: "Suspicious", key: "s" },
  { value: "benign", label: "Benign", key: "b" },
  { value: "needs_review", label: "Needs review", key: "r" },
];

export const verdictLabel = (v: Verdict | null): string =>
  v ? (VERDICTS.find((x) => x.value === v)?.label ?? v) : "No verdict";

function num(v: number): string {
  if (!Number.isFinite(v)) return String(v);
  if (Number.isInteger(v)) return v.toLocaleString("en-US");
  const abs = Math.abs(v);
  const digits = abs >= 100 ? 0 : abs >= 10 ? 1 : abs >= 1 ? 2 : 3;
  return v.toFixed(digits);
}

/** A reason's measured value with its unit, e.g. "59.8 s", "1.4%", "yes". */
export function formatValue(value: number, unit: string | null): string {
  switch (unit) {
    case null:
    case undefined:
    case "":
      return num(value);
    case "bool":
      return value ? "yes" : "no";
    case "ratio":
      return `${num(value)} (${(value * 100).toFixed(1)}%)`;
    case "pct":
    case "%":
      return `${num(value)}%`;
    case "count":
      return `${num(value)}`;
    default:
      return `${num(value)} ${unit}`;
  }
}

const plural = (n: number, one: string, many: string) => `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;

/** "56 flows · 56 frames", plus the true total when the lists were capped. */
export function evidenceLabel(e: Evidence): string {
  const parts: string[] = [];
  if (e.flow_ids.length) parts.push(plural(e.flow_ids.length, "flow", "flows"));
  if (e.frame_nos.length) parts.push(plural(e.frame_nos.length, "frame", "frames"));
  let s = parts.join(" · ") || "no evidence";
  if (e.truncated) s += ` (first ${Math.max(e.flow_ids.length, e.frame_nos.length)} of ${e.total.toLocaleString("en-US")})`;
  return s;
}

/**
 * SSID context of an 802.11 (device) finding: the first quoted name in its
 * explanations, e.g. `SSID "Corner-Cafe" is advertised as wpa2 by …`. Null for
 * other findings or when none is quoted. The caller renders it as text.
 */
export function ssidContext(f: Pick<Finding, "entity_type" | "reasons">): string | null {
  if (f.entity_type !== "device") return null;
  for (const r of f.reasons) {
    const m = /"([^"]{1,32})"/.exec(r.explanation);
    if (m) return m[1]!;
  }
  return null;
}

/** Clamp a score to 0..100 for the bar width. */
export const barPct = (score: number): number => Math.max(0, Math.min(100, Number.isFinite(score) ? score : 0));
