// Cursor-paginated rows for one view and scope. A new scope (filter, time
// range, hosts, view, sort, capture) resets to the first page; stale
// responses from an older scope are dropped.
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import type { Sort } from "../shared/bindings/Sort";
import type { TimeRange } from "../shared/bindings/TimeRange";
import { api, WalleyeError } from "../shared/ipc";
import type { AnyRow } from "./columns";
import type { TableView } from "./store";

export const PAGE_SIZE = 500;

export interface RowsScope {
  captureId: string | null;
  view: TableView;
  filter: string;
  time_range: TimeRange | null;
  hosts: string[];
  sort: Sort | null;
}

export interface RowsState {
  rows: AnyRow[];
  total: number | null;
  nextCursor: string | null;
  loading: boolean;
  error: WalleyeError | null;
  sql: string | null;
  elapsedMs: number | null;
}

const EMPTY: RowsState = { rows: [], total: null, nextCursor: null, loading: false, error: null, sql: null, elapsedMs: null };

export function useRows(scope: RowsScope): RowsState & { loadMore: () => void } {
  const [state, setState] = useState<RowsState>(EMPTY);
  const gen = useRef(0);
  const inflight = useRef(false);
  const stateRef = useRef(state);
  const scopeRef = useRef(scope);
  useLayoutEffect(() => {
    stateRef.current = state;
    scopeRef.current = scope;
  });
  const key = JSON.stringify(scope);

  const fetchPage = useCallback(async (cursor: string | null, g: number) => {
    const s = scopeRef.current;
    inflight.current = true;
    setState((st) => ({ ...st, loading: true }));
    try {
      const page = await api.query({
        filter: s.filter,
        view: s.view,
        time_range: s.time_range,
        hosts: s.hosts,
        // CONTRACTS §4: the table never filters itself to the selected flows.
        flow_ids: [],
        sort: s.sort,
        limit: PAGE_SIZE,
        cursor,
      });
      if (g !== gen.current) return;
      const rows = page.data.rows as AnyRow[];
      setState((st) => ({
        rows: cursor ? [...st.rows, ...rows] : rows,
        total: page.total,
        nextCursor: page.next_cursor,
        loading: false,
        error: null,
        sql: page.sql,
        elapsedMs: page.elapsed_ms,
      }));
    } catch (e) {
      if (g !== gen.current) return;
      const err = e instanceof WalleyeError ? e : new WalleyeError({ code: "internal", message: String(e), span: null });
      setState((st) => ({ ...(cursor ? st : EMPTY), loading: false, error: err }));
    } finally {
      if (g === gen.current) inflight.current = false;
    }
  }, []);

  useEffect(() => {
    const g = ++gen.current;
    inflight.current = false;
    if (!scopeRef.current.captureId) {
      setState(EMPTY);
      return;
    }
    setState((st) => ({ ...st, loading: true }));
    void fetchPage(null, g);
  }, [key, fetchPage]);

  const loadMore = useCallback(() => {
    const st = stateRef.current;
    if (inflight.current || !st.nextCursor || st.error) return;
    void fetchPage(st.nextCursor, gen.current);
  }, [fetchPage]);

  return { ...state, loadMore };
}
