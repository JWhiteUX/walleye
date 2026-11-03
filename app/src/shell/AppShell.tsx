// Application shell (Agent D): header (open capture, filter bar, saved
// queries, palette), resizable panes, the global key handler, F6 pane cycling.
//
//   ┌ header ─────────────────────────────────────────────────┐
//   │ scope bar (time, hosts, flows, device chips)             │
//   │ timeline                                │ Findings | Case │
//   │─────────────────────────────────────────│  (one column,   │
//   │ session table (never squeezed below     │   two tabs)     │
//   │   TABLE_MIN: other panes shrink first)  │                 │
//   │─────────────────────────────────────────│                 │
//   │ packet pane                             │                 │
//   └─────────────────────────────────────────┴─────────────────┘
import { useCallback, useEffect, useMemo, useRef, useState, type RefObject } from "react";
import { PacketPane } from "../packets";
import { useRegisterCommands, type Command } from "../shared/commands";
import { api } from "../shared/ipc";
import { useSelection } from "../shared/selection";
import { useSession } from "../shared/session";
import { SessionTable } from "../table";
import { TimelinePanel } from "../timeline";
import { CommandPalette } from "./CommandPalette";
import { FilterBar, type FilterBarHandle } from "./FilterBar";
import { IngestDialog } from "./IngestDialog";
import { formatShortcut, isMacPlatform } from "./keys";
import { SavedQueries, type SavedQueriesHandle } from "./SavedQueries";
import { ScopeBar } from "./ScopeBar";
import {
  DEFAULT_LAYOUT,
  fitLayout,
  LAYOUT_KEY,
  PACKETS_MIN,
  SIDE_MAX_SHARE,
  SIDE_MIN,
  SPLITTERS_H,
  TABLE_MIN,
  TIMELINE_MIN,
  type Layout,
} from "./layout";
import { SidePanel, type SideTab } from "./SidePanel";
import { Splitter } from "./Splitter";
import { useGlobalKeys } from "./useGlobalKeys";
import { useIngest } from "./useIngest";
import "./shell.css";

export type PaneId = "filter" | "timeline" | "table" | "packets" | "queue" | "case";

/** Observed content-box size of an element (0×0 until first measured). */
function useSize<T extends HTMLElement>(): [RefObject<T | null>, { w: number; h: number }] {
  const ref = useRef<T>(null);
  const [size, setSize] = useState({ w: 0, h: 0 });
  useEffect(() => {
    const el = ref.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(([e]) => {
      if (e) setSize({ w: Math.round(e.contentRect.width), h: Math.round(e.contentRect.height) });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, size];
}

function loadLayout(): Layout {
  try {
    const raw = localStorage.getItem(LAYOUT_KEY);
    if (!raw) return DEFAULT_LAYOUT;
    const v = JSON.parse(raw) as Partial<Layout>;
    const num = (x: unknown) => (typeof x === "number" && Number.isFinite(x) ? x : null);
    return {
      timelineH: num(v.timelineH),
      packetsH: num(v.packetsH),
      sideW: num(v.sideW),
      sideTab: v.sideTab === "case" ? "case" : "findings",
    };
  } catch {
    return DEFAULT_LAYOUT;
  }
}

/** Focus a pane: its preferred target (grid, tree…) or the pane itself. */
export function focusPane(id: PaneId): boolean {
  const pane = document.querySelector<HTMLElement>(`[data-pane="${id}"]`);
  if (!pane) return false;
  const target =
    id === "filter"
      ? pane.querySelector<HTMLElement>("input")
      : pane.querySelector<HTMLElement>('[role="grid"], [role="tree"], [role="listbox"][tabindex="0"]');
  (target ?? pane).focus();
  return true;
}

function currentPane(): PaneId | null {
  const el = document.activeElement?.closest?.("[data-pane]");
  return (el?.getAttribute("data-pane") as PaneId | null) ?? null;
}

/** Owns the global key listener; isolated so registry updates don't re-render the shell. */
function GlobalKeys() {
  const { pending } = useGlobalKeys();
  return (
    <span className="wl-pending" aria-live="polite">
      {pending ? `${pending} …` : ""}
    </span>
  );
}

export function AppShell() {
  const session = useSession((s) => s.session);
  const setSession = useSession((s) => s.setSession);
  const ingest = useIngest();
  const [layout, setLayout] = useState<Layout>(loadLayout);
  const [palette, setPalette] = useState(false);
  const filterRef = useRef<FilterBarHandle>(null);
  const savedRef = useRef<SavedQueriesHandle>(null);
  const mac = useMemo(() => isMacPlatform(), []);
  // Commands must be a stable array (useRegisterCommands); read live values through a ref.
  const live = useRef({ ingest, sideTab: layout.sideTab });
  useEffect(() => {
    live.current = { ingest, sideTab: layout.sideTab };
  });
  const [shellRef, shellSize] = useSize<HTMLDivElement>();
  const [mainRef, mainSize] = useSize<HTMLElement>();
  const fit = fitLayout(layout, shellSize.w, mainSize.h);
  const avail = mainSize.h > 0 ? mainSize.h - SPLITTERS_H : Infinity;

  useEffect(() => {
    try {
      localStorage.setItem(LAYOUT_KEY, JSON.stringify(layout));
    } catch {
      // Storage may be unavailable; the layout just won't persist.
    }
  }, [layout]);

  // Pick up a capture the backend already has open (e.g. WALLEYE_BACKEND=mock-open, ?mock=open).
  useEffect(() => {
    let live = true;
    api.currentCapture().then(
      (s) => {
        if (live && s && !useSession.getState().session) setSession(s);
      },
      () => {},
    );
    return () => {
      live = false;
    };
  }, [setSession]);

  const cycle = useCallback((d: 1 | -1) => {
    // Only the visible side tab takes part in the cycle.
    const order: PaneId[] = ["filter", "timeline", "table", "packets", live.current.sideTab === "case" ? "case" : "queue"];
    const cur = currentPane();
    const i = cur ? order.indexOf(cur) : -1;
    focusPane(order[(i + d + order.length) % order.length]!);
  }, []);

  const goSide = useCallback((tab: SideTab) => {
    setLayout((l) => ({ ...l, sideTab: tab }));
    // Wait for the tab panel to un-hide before focusing into it.
    requestAnimationFrame(() => focusPane(tab === "case" ? "case" : "queue"));
  }, []);

  const commands = useMemo<Command[]>(
    () => [
      { id: "shell.open-capture", title: "Open capture…", group: "General", shortcut: "mod+o", run: () => void live.current.ingest.open() },
      { id: "shell.command-palette", title: "Command palette", group: "General", shortcut: "mod+k", run: () => setPalette((p) => !p) },
      { id: "shell.shortcuts", title: "Show keyboard shortcuts", group: "General", shortcut: "shift+/", run: () => setPalette(true) },
      { id: "shell.focus-filter", title: "Focus filter bar", group: "Filter", shortcut: "/", run: () => filterRef.current?.focus() },
      {
        id: "shell.clear-filter",
        title: "Clear filter",
        group: "Filter",
        shortcut: "mod+shift+backspace",
        run: () => useSelection.getState().setFilter(""),
      },
      { id: "shell.saved-queries", title: "Saved queries…", group: "Filter", shortcut: "mod+shift+s", run: () => savedRef.current?.open() },
      { id: "shell.save-query", title: "Save applied filter…", group: "Filter", shortcut: "mod+s", run: () => savedRef.current?.open(true) },
      {
        id: "shell.clear-selection",
        title: "Clear selection (time range, hosts, flows, frame)",
        group: "Selection",
        shortcut: "mod+shift+x",
        run: () => useSelection.getState().clearSelection(),
      },
      { id: "shell.next-pane", title: "Focus next pane", group: "Navigation", shortcut: "f6", run: () => cycle(1) },
      { id: "shell.prev-pane", title: "Focus previous pane", group: "Navigation", shortcut: "shift+f6", run: () => cycle(-1) },
      { id: "shell.go-timeline", title: "Go to timeline", group: "Navigation", shortcut: "g t", run: () => focusPane("timeline") },
      { id: "shell.go-table", title: "Go to session table", group: "Navigation", shortcut: "g s", run: () => focusPane("table") },
      { id: "shell.go-packets", title: "Go to packet pane", group: "Navigation", shortcut: "g p", run: () => focusPane("packets") },
      { id: "shell.go-queue", title: "Go to findings (suspicion queue)", group: "Navigation", shortcut: "g q", run: () => goSide("findings") },
      { id: "shell.go-case", title: "Go to case", group: "Navigation", shortcut: "g c", run: () => goSide("case") },
      {
        id: "shell.toggle-case",
        title: "Switch between the Findings and Case tabs",
        group: "Layout",
        shortcut: "mod+\\",
        run: () => setLayout((l) => ({ ...l, sideTab: l.sideTab === "case" ? "findings" : "case" })),
      },
      { id: "shell.reset-layout", title: "Reset pane sizes", group: "Layout", shortcut: "g 0", run: () => setLayout(DEFAULT_LAYOUT) },
    ],
    [cycle, goSide],
  );
  useRegisterCommands(commands);

  const sha = session?.capture.sha256 ?? "";
  const capName = session ? (session.capture.path.split(/[\\/]/).pop() ?? session.capture.path) : "";
  const kbd = (s: string) => formatShortcut(s, mac);

  return (
    <div ref={shellRef} className="wl-shell" style={{ gridTemplateColumns: `minmax(0, 1fr) 6px ${fit.sideW}px` }}>
      <header className="wl-header" data-pane="filter" tabIndex={-1}>
        <h1 className="wl-brand">Walleye</h1>
        <button type="button" onClick={() => void ingest.open()} title={`Open capture (${kbd("mod+o")})`} data-testid="open-capture">
          Open capture…
        </button>
        {session && (
          <span className="wl-capture" title={`${session.capture.path}\nSHA-256 ${sha}`} data-testid="capture-info">
            <span className="wl-capture-name">{capName}</span>{" "}
            <span className="wl-mono wl-text-muted">
              {session.capture.frame_count.toLocaleString()} frames · sha256 {sha.slice(0, 12)}…
            </span>
          </span>
        )}
        <FilterBar ref={filterRef} />
        <SavedQueries ref={savedRef} />
        <button type="button" onClick={() => setPalette(true)} title={`Command palette (${kbd("mod+k")})`} data-testid="open-palette">
          Commands <kbd className="wl-kbd">{kbd("mod+k")}</kbd>
        </button>
        <GlobalKeys />
      </header>

      {session && <ScopeBar />}

      <main
        ref={mainRef}
        className="wl-main"
        style={{ gridTemplateRows: `${fit.timelineH}px 6px minmax(80px, 1fr) 6px ${fit.packetsH}px` }}
        aria-label="Analysis"
      >
        <div className="wl-pane" data-pane="timeline" tabIndex={-1} id="wl-pane-timeline">
          <TimelinePanel />
        </div>
        <Splitter
          label="Resize timeline"
          orientation="horizontal"
          value={fit.timelineH}
          min={TIMELINE_MIN}
          max={Math.max(TIMELINE_MIN, Math.min(600, avail - fit.packetsH - TABLE_MIN))}
          sign={1}
          controls="wl-pane-timeline"
          onChange={(v) => setLayout((l) => ({ ...l, timelineH: v }))}
        />
        <div className="wl-pane" data-pane="table" tabIndex={-1}>
          <SessionTable />
        </div>
        <Splitter
          label="Resize packet pane"
          orientation="horizontal"
          value={fit.packetsH}
          min={PACKETS_MIN}
          max={Math.max(PACKETS_MIN, Math.min(800, avail - fit.timelineH - TABLE_MIN))}
          sign={-1}
          controls="wl-pane-packets"
          onChange={(v) => setLayout((l) => ({ ...l, packetsH: v }))}
        />
        <div className="wl-pane" data-pane="packets" tabIndex={-1} id="wl-pane-packets">
          <PacketPane />
        </div>
      </main>

      <Splitter
        label="Resize side panel"
        orientation="vertical"
        value={fit.sideW}
        min={SIDE_MIN}
        max={Math.max(SIDE_MIN, Math.floor(shellSize.w * SIDE_MAX_SHARE)) || 720}
        sign={-1}
        controls="wl-side"
        onChange={(v) => setLayout((l) => ({ ...l, sideW: v }))}
      />
      <aside className="wl-side" id="wl-side" aria-label="Findings and case">
        <SidePanel tab={layout.sideTab} onTab={(sideTab) => setLayout((l) => ({ ...l, sideTab }))} />
      </aside>

      <IngestDialog
        state={ingest.state}
        onCancel={() => void ingest.cancel()}
        onDismiss={ingest.dismiss}
        onRetry={() => {
          const p = ingest.state.kind === "failed" || ingest.state.kind === "cancelled" ? ingest.state.path : null;
          if (p) void ingest.openPath(p);
          else void ingest.open();
        }}
      />
      {palette && <CommandPalette onClose={() => setPalette(false)} />}
    </div>
  );
}
