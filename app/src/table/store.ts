// Table-local UI state that the shell also drives (saved queries carry a
// view; the palette switches views). Not part of the shared selection.
import { create } from "zustand";
import type { Sort } from "../shared/bindings/Sort";
import type { View } from "../shared/bindings/View";

// The 802.11 views (wifi, wifi_aps, wifi_clients) join TABLE_VIEWS in the Wi-Fi UI work.
export type TableView = Exclude<View, "frames" | "wifi" | "wifi_aps" | "wifi_clients">;
export const TABLE_VIEWS: readonly TableView[] = ["flows", "dns", "http", "tls", "files"];

interface TableState {
  view: TableView;
  sort: Record<TableView, Sort | null>;
  setView: (v: TableView) => void;
  setSort: (v: TableView, s: Sort | null) => void;
}

export const useTableStore = create<TableState>()((set) => ({
  view: "flows",
  sort: { flows: null, dns: null, http: null, tls: null, files: null },
  setView: (view) => set({ view }),
  setSort: (v, s) => set((st) => ({ sort: { ...st.sort, [v]: s } })),
}));

export function asTableView(v: View): TableView {
  return v === "frames" || v === "wifi" || v === "wifi_aps" || v === "wifi_clients" ? "flows" : v;
}
