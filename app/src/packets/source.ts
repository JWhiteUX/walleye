// Which frames the packet list shows (CONTRACTS §11.4): the selected flow's
// frames when a flow is selected, else the focused 802.11 device's frames
// (within the brushed time range), else nothing. Pure; see source.test.ts.
import type { FrameRef } from "../shared/bindings/FrameRef";
import type { TimeRange } from "../shared/bindings/TimeRange";
import type { Selection } from "../shared/selection";
import { visible } from "../shared/format";
import { macLabel } from "../shared/wifi";

export type FrameSource =
  | { kind: "flow"; flowId: number }
  | { kind: "device"; mac: string; timeRange: TimeRange | null }
  | { kind: "none" };

export function frameSource(s: Pick<Selection, "flow_ids" | "device" | "time_range">): FrameSource {
  const flowId = s.flow_ids[0];
  if (flowId !== undefined) return { kind: "flow", flowId };
  if (s.device) return { kind: "device", mac: s.device, timeRange: s.time_range };
  return { kind: "none" };
}

/** Stable cache key: a new key means a new fetch. */
export function sourceKey(src: FrameSource): string | null {
  switch (src.kind) {
    case "flow":
      return `flow:${src.flowId}`;
    case "device":
      return `device:${src.mac}:${src.timeRange ? `${src.timeRange.start}-${src.timeRange.end}` : "all"}`;
    case "none":
      return null;
  }
}

export function fetchSource(
  src: FrameSource,
  api: { flowFrames: (id: number) => Promise<FrameRef[]>; deviceFrames: (mac: string, r: TimeRange | null) => Promise<FrameRef[]> },
): Promise<FrameRef[]> {
  switch (src.kind) {
    case "flow":
      return api.flowFrames(src.flowId);
    case "device":
      return api.deviceFrames(src.mac, src.timeRange);
    case "none":
      return Promise.resolve([]);
  }
}

/** Heading over the frame list: says whose frames these are. */
export function sourceTitle(src: FrameSource, count: number | null): string {
  const n = count === null ? "" : ` (${count.toLocaleString("en-US")}${count >= 10_000 ? ", first 10,000" : ""})`;
  switch (src.kind) {
    case "flow":
      return `Frames of flow ${src.flowId}${n}`;
    case "device":
      return `Frames of device ${macLabel(visible(src.mac))}${src.timeRange ? " in time range" : ""}${n}`;
    case "none":
      return "Frames";
  }
}
