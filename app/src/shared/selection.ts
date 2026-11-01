// The one shared selection. Every view subscribes to it and writes to it;
// no view keeps its own copy of "what is selected". See CONTRACTS.md §4.
//
//   timeline brush      -> setTimeRange
//   lane / host click   -> setHosts / toggleHost
//   table row           -> selectFlows([id]) (+ selectFrame(first_frame))
//   packet list row     -> selectFrame
//   queue evidence link -> applyEvidence
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
}

export interface SelectionActions {
  setTimeRange: (r: TimeRange | null) => void;
  setHosts: (hosts: string[]) => void;
  toggleHost: (host: string) => void;
  selectFlows: (ids: number[]) => void;
  selectFrame: (frame_no: number | null) => void;
  setFilter: (filter: string) => void;
  /** Jump to evidence: selects its flows and its first frame. */
  applyEvidence: (e: Evidence) => void;
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
  applyEvidence: (e) => set({ flow_ids: [...new Set(e.flow_ids)], frame_no: e.frame_nos[0] ?? null }),
  clearSelection: () => set((s) => ({ ...EMPTY_SELECTION, filter: s.filter })),
  reset: () => set({ ...EMPTY_SELECTION }),
}));

/** The structured scope of a query, derived from the selection. */
export function selectionScope(
  s: Selection,
): Pick<QueryRequest, "filter" | "time_range" | "hosts" | "flow_ids"> {
  return { filter: s.filter, time_range: s.time_range, hosts: s.hosts, flow_ids: s.flow_ids };
}
