// Virtualized, keyboard-navigable data grid (TanStack Table + TanStack Virtual).
// Sorting is server-side (manualSorting); rows arrive page by page and
// `onNeedMore` asks for the next page as the viewport nears the end.
//
// ARIA: role=grid with aria-activedescendant on the scroll container, so
// focus never lands on a row that virtualization may unmount.
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { memo, useCallback, useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from "react";
import type { ColumnSpec } from "./columns";

export const ROW_HEIGHT = 24;
const HEADER_HEIGHT = 26;
/** Larger than the most rows ever rendered at once (viewport / ROW_HEIGHT + overscan). */
const ROW_POOL = 1024;

export interface VirtualGridProps<R> {
  label: string;
  columns: ColumnSpec[];
  rows: R[];
  /** Total rows on the server when known (for aria-rowcount and the status line). */
  totalRows?: number | null;
  sorting: SortingState;
  onSortingChange: (s: SortingState) => void;
  isSelected: (row: R) => boolean;
  onActivate: (row: R, index: number) => void;
  onNeedMore?: () => void;
  /** For benchmarks: receives the scroll element. */
  scrollRef?: (el: HTMLDivElement | null) => void;
  testId?: string;
}

type Cell = Record<string, unknown>;

function nextSort(cur: SortingState, id: string): SortingState {
  const s = cur[0];
  if (!s || s.id !== id) return [{ id, desc: false }];
  if (!s.desc) return [{ id, desc: true }];
  return [];
}

const GridRow = memo(function GridRow({
  id,
  index,
  start,
  cells,
  columns,
  template,
  selected,
  active,
  onClick,
}: {
  id: string;
  index: number;
  start: number;
  cells: Cell;
  columns: ColumnSpec[];
  template: string;
  selected: boolean;
  active: boolean;
  onClick: (index: number) => void;
}) {
  return (
    <div
      role="row"
      id={id}
      aria-rowindex={index + 2}
      aria-selected={selected}
      className={`wl-grid-row${selected ? " is-selected" : ""}${active ? " is-active" : ""}`}
      style={{ transform: `translateY(${start}px)`, gridTemplateColumns: template }}
      onClick={() => onClick(index)}
    >
      <div role="gridcell" className="wl-grid-mark" aria-label={selected ? "selected" : undefined}>
        {selected ? "▶" : ""}
      </div>
      {columns.map((c) => {
        const t = c.text(cells);
        return (
          <div
            key={c.id}
            role="gridcell"
            className={`wl-grid-cell${c.align === "right" ? " is-right" : ""}${c.mono ? " wl-mono" : ""}`}
            title={t.length > 24 ? t : undefined}
          >
            {t}
          </div>
        );
      })}
    </div>
  );
});

export function VirtualGrid<R extends object>(props: VirtualGridProps<R>) {
  const { columns, rows, sorting, onSortingChange, isSelected, onActivate, onNeedMore } = props;
  const gridId = useId().replace(/:/g, "");
  const scrollEl = useRef<HTMLDivElement | null>(null);
  const [active, setActive] = useState<number | null>(null);

  const defs = useMemo<ColumnDef<R>[]>(
    () =>
      columns.map((c) => ({
        id: c.id,
        header: c.header,
        size: c.width,
        enableSorting: c.sortable,
        accessorFn: (r: R) => (r as Cell)[c.id],
      })),
    [columns],
  );

  // TanStack hooks are the mandated stack; we do not use the React Compiler.
  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data: rows,
    columns: defs,
    state: { sorting },
    manualSorting: true,
    enableMultiSort: false,
    onSortingChange: (u) => onSortingChange(typeof u === "function" ? u(sorting) : u),
    getCoreRowModel: getCoreRowModel(),
  });

  const template = useMemo(() => ["28px", ...columns.map((c) => `${c.width}px`)].join(" "), [columns]);
  const width = useMemo(() => 28 + columns.reduce((a, c) => a + c.width, 0), [columns]);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollEl.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 6,
    // The sticky header sits above the body inside the scroll element.
    paddingStart: 0,
    scrollPaddingStart: HEADER_HEIGHT,
  });
  const items = virtualizer.getVirtualItems();

  // Infinite scroll: ask for more when the last rendered row is near the end.
  const lastIndex = items.length ? items[items.length - 1]!.index : -1;
  useEffect(() => {
    if (onNeedMore && rows.length > 0 && lastIndex >= rows.length - 40) onNeedMore();
  }, [lastIndex, rows.length, onNeedMore]);

  // Keep the active index valid when the row set changes.
  useEffect(() => {
    setActive((a) => (a === null ? null : rows.length === 0 ? null : Math.min(a, rows.length - 1)));
  }, [rows]);

  const coreRows = table.getRowModel().rows;
  const moveTo = useCallback(
    (i: number) => {
      if (rows.length === 0) return;
      const n = Math.max(0, Math.min(rows.length - 1, i));
      setActive(n);
      virtualizer.scrollToIndex(n, { align: "auto" });
    },
    [rows.length, virtualizer],
  );

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.target !== e.currentTarget) return; // header buttons handle their own keys
    const page = Math.max(1, Math.floor((scrollEl.current?.clientHeight ?? 240) / ROW_HEIGHT) - 2);
    const cur = active ?? -1;
    switch (e.key) {
      case "ArrowDown":
        moveTo(cur + 1);
        break;
      case "ArrowUp":
        moveTo(cur <= 0 ? 0 : cur - 1);
        break;
      case "PageDown":
        moveTo(cur + page);
        break;
      case "PageUp":
        moveTo(cur - page);
        break;
      case "Home":
        moveTo(0);
        break;
      case "End":
        moveTo(rows.length - 1);
        break;
      case "Enter":
      case " ": {
        const i = active ?? 0;
        const r = rows[i];
        if (r) {
          setActive(i);
          onActivate(r, i);
        }
        break;
      }
      default:
        return;
    }
    e.preventDefault();
  };

  const onRowClick = useCallback(
    (i: number) => {
      const r = rows[i];
      if (!r) return;
      setActive(i);
      onActivate(r, i);
      scrollEl.current?.focus({ preventScroll: true });
    },
    [rows, onActivate],
  );

  // The header does not change while scrolling; keep it out of per-frame renders.
  const headerGroups = table.getHeaderGroups();
  const header = useMemo(
    () => (
          <div role="rowgroup" className="wl-grid-head" style={{ width }}>
            {headerGroups.map((hg) => (
              <div role="row" aria-rowindex={1} key={hg.id} className="wl-grid-row is-head" style={{ gridTemplateColumns: template }}>
                <div role="columnheader" className="wl-grid-mark">
                  <span className="wl-visually-hidden">Selected</span>
                </div>
                {hg.headers.map((h) => {
                  const spec = columns.find((c) => c.id === h.column.id)!;
                  const s = sorting[0]?.id === h.column.id ? (sorting[0]!.desc ? "descending" : "ascending") : "none";
                  const label = flexRender(h.column.columnDef.header, h.getContext());
                  return (
                    <div
                      key={h.id}
                      role="columnheader"
                      aria-sort={spec.sortable ? s : undefined}
                      className={`wl-grid-cell${spec.align === "right" ? " is-right" : ""}`}
                    >
                      {spec.sortable ? (
                        <button
                          type="button"
                          className="wl-sort"
                          onClick={() => onSortingChange(nextSort(sorting, spec.id))}
                          title={`Sort by ${spec.header}`}
                        >
                          {label}
                          <span aria-hidden="true" className="wl-sort-ind">
                            {s === "ascending" ? " ▲" : s === "descending" ? " ▼" : ""}
                          </span>
                        </button>
                      ) : (
                        label
                      )}
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
    ),
    [headerGroups, columns, sorting, onSortingChange, template, width],
  );

  const activeVisible = active !== null && items.some((v) => v.index === active);
  const setScroll = (el: HTMLDivElement | null) => {
    scrollEl.current = el;
    props.scrollRef?.(el);
  };

  return (
    <div
      ref={setScroll}
      role="grid"
      tabIndex={0}
      aria-label={props.label}
      aria-rowcount={(props.totalRows ?? rows.length) + 1}
      aria-colcount={columns.length + 1}
      aria-activedescendant={activeVisible ? `${gridId}-r${active}` : undefined}
      className="wl-grid"
      data-testid={props.testId}
      onKeyDown={onKeyDown}
    >
      {header}
      <div role="rowgroup" className="wl-grid-body" style={{ height: virtualizer.getTotalSize(), width }}>
        {items.map((v) => {
          const r = coreRows[v.index]?.original ?? rows[v.index];
          if (!r) return null;
          return (
            <GridRow
              // Slot keys: a row scrolled out hands its DOM to the row scrolled
              // in, so fast scrolling updates text instead of building nodes.
              key={v.index % ROW_POOL}
              id={`${gridId}-r${v.index}`}
              index={v.index}
              start={v.start}
              cells={r as Cell}
              columns={columns}
              template={template}
              selected={isSelected(r)}
              active={active === v.index}
              onClick={onRowClick}
            />
          );
        })}
      </div>
    </div>
  );
}
