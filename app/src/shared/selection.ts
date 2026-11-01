// The one shared selection. Every view subscribes to it and writes to it;
// no view keeps its own copy of "what is selected". See CONTRACTS.md §4.
//
//   timeline brush      -> setTimeRange
//   lane / host click   -> setHosts / toggleHost
//   table row           -> selectFlows([id]) (+ selectFrame(first_frame))
//   packet list row     -> selectFrame
//   queue evidence link -> applyEvidence
//   wifi row / device lane -> selectDevice (802.11 captures; contract v2)
//   filter bar submit   -> setFilter
import { create } from "zustand";
import type { Evidence } from "./bindings/Evidence";
import type { TimeRange } from "./bindings/TimeRange";
import type { QueryRequest } from "./bindings/QueryRequest";

export interface Selection {
  time_range: TimeRange | null;
  hosts: string[];
  flow_ids: number[];
  frame_no: number | null;
  /** Committed filter text (what the filter bar last submitted). */
  filter: string;
  /**
   * Focused 802.11 device (lowercase MAC), set by Wi-Fi table rows, device
   * lanes and device findings. Drives the packet list when no flow is
   * selected (`api.deviceFrames`). It never filters the table or timeline:
   * filter by MAC with `mac X` in the filter text.
   */
  device: string | null;
}

export interface SelectionActions {
  setTimeRange: (r: TimeRange | null) => void;
  setHosts: (hosts: string[]) => void;
  toggleHost: (host: string) => void;
  selectFlows: (ids: number[]) => void;
  selectFrame: (frame_no: number | null) => void;
  setFilter: (filter: string) => void;
  /** Focus an 802.11 device (MAC) and clear the selected flows. */
  selectDevice: (mac: string | null) => void;
  /**
   * Jump to evidence: selects its flows and its first frame. For evidence
   * without flows (802.11 findings), pass the finding's device to focus it.
   */
  applyEvidence: (e: Evidence, device?: string | null) => void;
  /** Clear everything except the filter. */
  clearSelection: () => void;
  reset: () => void;
}

export const EMPTY_SELECTION: Selection = {
  time_range: null,
  hosts: [],
  flow_ids: [],
  frame_no: null,
  filter: "",
  device: null,
};

export const useSelection = create<Selection & SelectionActions>()((set) => ({
  ...EMPTY_SELECTION,
  setTimeRange: (time_range) =>
    set({ time_range: time_range && time_range.end > time_range.start ? time_range : null }),
  setHosts: (hosts) => set({ hosts: [...new Set(hosts)] }),
  toggleHost: (host) =>
    set((s) => ({ hosts: s.hosts.includes(host) ? s.hosts.filter((h) => h !== host) : [...s.hosts, host] })),
  selectFlows: (flow_ids) => set({ flow_ids: [...new Set(flow_ids)] }),
  selectFrame: (frame_no) => set({ frame_no }),
  setFilter: (filter) => set({ filter }),
  selectDevice: (device) => set({ device, flow_ids: device ? [] : useSelection.getState().flow_ids }),
  applyEvidence: (e, device) =>
    set({
      flow_ids: [...new Set(e.flow_ids)],
      frame_no: e.frame_nos[0] ?? null,
      device: e.flow_ids.length === 0 && device ? device : null,
    }),
  clearSelection: () => set((s) => ({ ...EMPTY_SELECTION, filter: s.filter })),
  reset: () => set({ ...EMPTY_SELECTION }),
}));

/** The structured scope of a query, derived from the selection. */
export function selectionScope(
  s: Selection,
): Pick<QueryRequest, "filter" | "time_range" | "hosts" | "flow_ids"> {
  return { filter: s.filter, time_range: s.time_range, hosts: s.hosts, flow_ids: s.flow_ids };
}
