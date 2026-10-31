// Session table (Agent D). Views: flows, dns, http, tls, files.
// Reads the shared selection's filter/time_range/hosts (never flow_ids, per
// CONTRACTS §4) and writes selectFlows + selectFrame on row activation.
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { useShallow } from "zustand/react/shallow";
import { pinEvidence } from "../shared/caseEvents";
import { useRegisterCommands, type Command } from "../shared/commands";
import { useSelection } from "../shared/selection";
import { useSession } from "../shared/session";
import { useFilterStatus } from "../shell/filterStatus";
import { COLUMNS, rowFrame, VIEW_LABEL, type AnyRow } from "./columns";
import { appendPredicate, composePredicate, fieldType } from "./predicates";
import { TABLE_VIEWS, useTableStore, type TableView } from "./store";
import { useRows } from "./useRows";
import { VirtualGrid } from "./VirtualGrid";
import "./table.css";

const VIEW_KEYS: Record<TableView, string> = { flows: "v f", dns: "v d", http: "v h", tls: "v t", files: "v i" };

export function SessionTable() {
  const session = useSession((s) => s.session);
  const { filter, time_range, hosts, flow_ids } = useSelection(
    useShallow((s) => ({ filter: s.filter, time_range: s.time_range, hosts: s.hosts, flow_ids: s.flow_ids })),
  );
  const selectFlows = useSelection((s) => s.selectFlows);
  const selectFrame = useSelection((s) => s.selectFrame);
  const setFilter = useSelection((s) => s.setFilter);
  const { view, sort, setView, setSort } = useTableStore(
    useShallow((s) => ({ view: s.view, sort: s.sort[s.view], setView: s.setView, setSort: s.setSort })),
  );
  const reportFilter = useFilterStatus((s) => s.report);
  const [status, setStatus] = useState("");

  const scope = useMemo(
    () => ({ captureId: session?.capture.capture_id ?? null, view, filter, time_range, hosts, sort }),
    [session, view, filter, time_range, hosts, sort],
  );
  const rows = useRows(scope);

  // Report filter errors to the filter bar (inline underline) and clear on success.
  useEffect(() => {
    if (rows.loading) return;
    if (rows.error?.code === "invalid_filter") {
      reportFilter({ filter, message: rows.error.message, span: rows.error.span });
    } else if (!rows.error && session && useFilterStatus.getState().problem) {
      reportFilter(null);
    }
  }, [rows.error, rows.loading, filter, session, reportFilter]);

  const columns = COLUMNS[view];
  const selectedSet = useMemo(() => new Set(flow_ids), [flow_ids]);
  const isSelected = useCallback((r: AnyRow) => selectedSet.has(r.flow_id), [selectedSet]);
  const onActivate = useCallback(
    (r: AnyRow) => {
      selectFlows([r.flow_id]);
      selectFrame(rowFrame(r));
    },
    [selectFlows, selectFrame],
  );
  const sorting = useMemo(() => (sort ? [{ id: sort.column, desc: sort.desc }] : []), [sort]);
  const onSortingChange = useCallback(
    (s: { id: string; desc: boolean }[]) => setSort(view, s[0] ? { column: s[0].id, desc: s[0].desc } : null),
    [setSort, view],
  );

  const pinFlow = useCallback(async () => {
    const id = useSelection.getState().flow_ids[0];
    if (id === undefined) return;
    try {
      await pinEvidence({ kind: "flow", flow_id: id });
      setStatus(`Pinned flow ${id} to the case.`);
    } catch (e) {
      setStatus(`Could not pin flow ${id}: ${(e as Error).message}`);
    }
  }, []);

  // Column filter form.
  const filterable = columns.filter((c) => c.field && fieldType(c.field));
  const [colField, setColField] = useState<string>("");
  const [colValue, setColValue] = useState("");
  const [colError, setColError] = useState<string | null>(null);
  const valueRef = useRef<HTMLInputElement>(null);
  const field = filterable.some((c) => c.field === colField) ? colField : (filterable[0]?.field ?? "");
  const addColumnFilter = (e: FormEvent) => {
    e.preventDefault();
    const ty = fieldType(field);
    if (!ty) return;
    const r = composePredicate(field, ty, colValue);
    if (!r.ok) {
      setColError(r.error);
      return;
    }
    setColError(null);
    setColValue("");
    setFilter(appendPredicate(useSelection.getState().filter, r.text));
    setStatus(`Added "${r.text}" to the filter.`);
  };

  const commands = useMemo<Command[]>(
    () => [
      ...TABLE_VIEWS.map((v) => ({
        id: `table.view-${v}`,
        title: `Show ${VIEW_LABEL[v]} view`,
        group: "Session table",
        shortcut: VIEW_KEYS[v],
        run: () => useTableStore.getState().setView(v),
      })),
      {
        id: "table.pin-flow",
        title: "Pin selected flow to case",
        group: "Session table",
        shortcut: "shift+p",
        run: () => void pinFlow(),
        enabled: () => useSelection.getState().flow_ids.length > 0 && !!useSession.getState().session,
      },
      {
        id: "table.column-filter",
        title: "Add a column filter",
        group: "Session table",
        shortcut: "mod+shift+f",
        run: () => valueRef.current?.focus(),
      },
      {
        id: "table.clear-sort",
        title: "Clear sort",
        group: "Session table",
        shortcut: "v 0",
        run: () => {
          const st = useTableStore.getState();
          st.setSort(st.view, null);
        },
      },
    ],
    [pinFlow],
  );
  useRegisterCommands(commands);

  const count =
    rows.total !== null ? `${rows.rows.length.toLocaleString()} of ${rows.total.toLocaleString()} rows` : `${rows.rows.length.toLocaleString()} rows`;

  return (
    <section aria-label="Sessions" data-testid="table-panel" className="wl-table">
      <div className="wl-table-bar">
        <h2 className="wl-panel-title">Sessions</h2>
        <div role="group" aria-label="View" className="wl-seg">
          {TABLE_VIEWS.map((v) => (
            <button
              key={v}
              type="button"
              aria-pressed={view === v}
              onClick={() => setView(v)}
              title={`${VIEW_LABEL[v]} (${VIEW_KEYS[v].toUpperCase()})`}
            >
              {VIEW_LABEL[v]}
            </button>
          ))}
        </div>
        <form className="wl-colfilter" onSubmit={addColumnFilter} aria-label="Column filter">
          <label className="wl-visually-hidden" htmlFor="wl-colfilter-field">
            Column
          </label>
          <select id="wl-colfilter-field" value={field} onChange={(e) => setColField(e.target.value)}>
            {filterable.map((c) => (
              <option key={c.id} value={c.field}>
                {c.header}
              </option>
            ))}
          </select>
          <label className="wl-visually-hidden" htmlFor="wl-colfilter-value">
            Column filter value
          </label>
          <input
            id="wl-colfilter-value"
            ref={valueRef}
            value={colValue}
            onChange={(e) => {
              setColValue(e.target.value);
              setColError(null);
            }}
            placeholder="value, >1MB, *.top"
            aria-invalid={colError ? true : undefined}
            aria-describedby={colError ? "wl-colfilter-err" : undefined}
            spellCheck={false}
            autoComplete="off"
          />
          <button type="submit">Add filter</button>
          {colError && (
            <span id="wl-colfilter-err" className="wl-error-text" role="alert">
              ⚠ {colError}
            </span>
          )}
        </form>
        <button type="button" onClick={() => void pinFlow()} disabled={!flow_ids.length || !session} title="Pin selected flow (Shift+P)">
          Pin flow
        </button>
      </div>

      <div className="wl-table-body">
        {!session ? (
          <p className="wl-empty">No capture open. Open one to see sessions.</p>
        ) : rows.error && rows.rows.length === 0 ? (
          <p className="wl-empty wl-error-text" role="alert">
            ⚠ {rows.error.code === "invalid_filter" ? "Filter error: " : "Query failed: "}
            {rows.error.message}
          </p>
        ) : (
          <VirtualGrid
            label={`${VIEW_LABEL[view]} sessions`}
            columns={columns}
            rows={rows.rows}
            totalRows={rows.total}
            sorting={sorting}
            onSortingChange={onSortingChange}
            isSelected={isSelected}
            onActivate={onActivate}
            onNeedMore={rows.loadMore}
            testId="table-grid"
          />
        )}
      </div>

      <div className="wl-table-status">
        <span aria-live="polite" data-testid="table-count">
          {session ? (rows.loading && rows.rows.length === 0 ? "Loading…" : count) : ""}
        </span>
        {rows.elapsedMs !== null && session && <span>{rows.elapsedMs.toFixed(1)} ms</span>}
        {rows.sql && session && (
          <details className="wl-sql">
            <summary>SQL</summary>
            <code className="wl-mono">{rows.sql}</code>
          </details>
        )}
        <span className="wl-table-msg" role="status">
          {status}
        </span>
      </div>
    </section>
  );
}
