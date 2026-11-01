// Visual encoding shared by the timeline, legends and the queue. Colour is
// never the only signal: every kind also has a shape and a text label.
import type { EventKind } from "./bindings/EventKind";

export type Shape =
  | "circle"
  | "square"
  | "triangle"
  | "diamond"
  | "cross"
  // 802.11 device lanes (contract v2)
  | "ring"
  | "triangle-down"
  | "bar"
  | "star";

export interface KindEncoding {
  label: string;
  shape: Shape;
  cssVar: string;
}

export const EVENT_ENCODING: Record<EventKind, KindEncoding> = {
  dns: { label: "DNS", shape: "circle", cssVar: "--wl-kind-dns" },
  tls: { label: "TLS", shape: "square", cssVar: "--wl-kind-tls" },
  http: { label: "HTTP", shape: "triangle", cssVar: "--wl-kind-http" },
  bulk: { label: "Bulk transfer", shape: "diamond", cssVar: "--wl-kind-bulk" },
  other: { label: "Other", shape: "cross", cssVar: "--wl-kind-other" },
};

/** Frame classes counted on 802.11 device lanes (`Bucket.wifi_*`). */
export type WifiMarkKind = "wifi_mgmt" | "wifi_probe" | "wifi_data" | "wifi_deauth";

/** Shapes differ from the IP kinds' too, so a mark is never ambiguous. */
export const WIFI_ENCODING: Record<WifiMarkKind, KindEncoding> = {
  wifi_mgmt: { label: "Management", shape: "ring", cssVar: "--wl-kind-wifi-mgmt" },
  wifi_probe: { label: "Probe", shape: "triangle-down", cssVar: "--wl-kind-wifi-probe" },
  wifi_data: { label: "Data", shape: "bar", cssVar: "--wl-kind-wifi-data" },
  wifi_deauth: { label: "Deauth", shape: "star", cssVar: "--wl-kind-wifi-deauth" },
};

/** Any mark the timeline draws: an IP event kind or an 802.11 frame class. */
export type MarkKind = EventKind | WifiMarkKind;
export const MARK_ENCODING: Record<MarkKind, KindEncoding> = { ...EVENT_ENCODING, ...WIFI_ENCODING };

/** Score bands for findings. Text label always shown next to the bar. */
export function scoreBand(score: number): { label: "High" | "Medium" | "Low"; cssVar: string } {
  if (score >= 70) return { label: "High", cssVar: "--wl-score-high" };
  if (score >= 40) return { label: "Medium", cssVar: "--wl-score-medium" };
  return { label: "Low", cssVar: "--wl-score-low" };
}
