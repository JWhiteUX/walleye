// Visual encoding shared by the timeline, legends and the queue. Colour is
// never the only signal: every kind also has a shape and a text label.
import type { EventKind } from "./bindings/EventKind";

export type Shape = "circle" | "square" | "triangle" | "diamond" | "cross";

export const EVENT_ENCODING: Record<EventKind, { label: string; shape: Shape; cssVar: string }> = {
  dns: { label: "DNS", shape: "circle", cssVar: "--wl-kind-dns" },
  tls: { label: "TLS", shape: "square", cssVar: "--wl-kind-tls" },
  http: { label: "HTTP", shape: "triangle", cssVar: "--wl-kind-http" },
  bulk: { label: "Bulk transfer", shape: "diamond", cssVar: "--wl-kind-bulk" },
  other: { label: "Other", shape: "cross", cssVar: "--wl-kind-other" },
};

/** Score bands for findings. Text label always shown next to the bar. */
export function scoreBand(score: number): { label: "High" | "Medium" | "Low"; cssVar: string } {
  if (score >= 70) return { label: "High", cssVar: "--wl-score-high" };
  if (score >= 40) return { label: "Medium", cssVar: "--wl-score-medium" };
  return { label: "Low", cssVar: "--wl-score-low" };
}
