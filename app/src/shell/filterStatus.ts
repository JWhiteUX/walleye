// The last invalid_filter error for the committed filter, reported by the
// views that run queries (the session table) and shown inline by the filter bar.
import { create } from "zustand";
import type { Span } from "../shared/bindings/Span";

export interface FilterProblem {
  filter: string;
  message: string;
  span: Span | null;
}

interface FilterStatus {
  problem: FilterProblem | null;
  report: (p: FilterProblem | null) => void;
}

export const useFilterStatus = create<FilterStatus>()((set) => ({
  problem: null,
  report: (problem) => set({ problem }),
}));
