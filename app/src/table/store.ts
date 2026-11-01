// Table-local UI state that the shell also drives (saved queries carry a
// view; the palette switches views). Not part of the shared selection.
import { create } from "zustand";
import type { Sort } from "../shared/bindings/Sort";
import type { View } from "../shared/bindings/View";

export type TableView = Exclude<View, "frames">;
/** Views of a wired (IP) capture. */
export const WIRED_VIEWS: readonly TableView[] = ["flows", "dns", "http", "tls", "files"];
/** Views of an 802.11 capture (CONTRACTS §11.4). */
export const WIFI_VIEWS: readonly TableView[] = ["wifi_aps", "wifi_clients", "wifi"];
export const TABLE_VIEWS: readonly TableView[] = [...WIRED_VIEWS, ...WIFI_VIEWS];

export const isWifiView = (v: View): v is "wifi" | "wifi_aps" | "wifi_clients" =>
  v === "wifi" || v === "wifi_aps" || v === "wifi_clients";

/**
 * Tabs to show. A wired capture shows the IP views. An 802.11 capture shows
 * the Wi-Fi views, plus the IP views only when it has flows (open networks
 * carry decodable IP traffic); otherwise those tabs would all be empty.
 */
export function visibleViews(wifiCapture: boolean, hasFlows: boolean): readonly TableView[] {
  if (!wifiCapture) return WIRED_VIEWS;
  return hasFlows ? [...WIFI_VIEWS, ...WIRED_VIEWS] : WIFI_VIEWS;
}

interface TableState {
  view: TableView;
  sort: Record<TableView, Sort | null>;
  setView: (v: TableView) => void;
  setSort: (v: TableView, s: Sort | null) => void;
}

export const useTableStore = create<TableState>()((set) => ({
  view: "flows",
  sort: { flows: null, dns: null, http: null, tls: null, files: null, wifi: null, wifi_aps: null, wifi_clients: null },
  setView: (view) => set({ view }),
  setSort: (v, s) => set((st) => ({ sort: { ...st.sort, [v]: s } })),
}));

export function asTableView(v: View): TableView {
  return v === "frames" ? "flows" : v;
}
