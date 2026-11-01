// Application shell (Agent D): header (open capture, filter bar, saved
// queries, palette), resizable panes, the global key handler, F6 pane cycling.
//
//   ┌ header ───────────────────────────────────────────────┐
//   │ timeline                                │ queue │ case │
//   │─────────────────────────────────────────│       │      │
//   │ session table                           │       │      │
//   │─────────────────────────────────────────│       │      │
//   │ packet pane                             │       │      │
//   └─────────────────────────────────────────┴───────┴──────┘
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { CasePanel } from "../case";
import { PacketPane } from "../packets";
import { QueuePanel } from "../queue";
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
import { Splitter } from "./Splitter";
import { useGlobalKeys } from "./useGlobalKeys";
import { useIngest } from "./useIngest";
import "./shell.css";

export type PaneId = "filter" | "timeline" | "table" | "packets" | "queue" | "case";

interface Layout {
  timelineH: number;
  packetsH: number;
  queueW: number;
  caseW: number;
  caseOpen: boolean;
}

const DEFAULT_LAYOUT: Layout = { timelineH: 200, packetsH: 300, queueW: 320, caseW: 300, caseOpen: true };
const LAYOUT_KEY = "walleye.layout.v1";

function loadLayout(): Layout {
  try {
    const raw = localStorage.getItem(LAYOUT_KEY);
    if (!raw) return DEFAULT_LAYOUT;
    const v = JSON.parse(raw) as Partial<Layout>;
    const num = (x: unknown, d: number) => (typeof x === "number" && Number.isFinite(x) ? x : d);
    return {
      timelineH: num(v.timelineH, DEFAULT_LAYOUT.timelineH),
      packetsH: num(v.packetsH, DEFAULT_LAYOUT.packetsH),
      queueW: num(v.queueW, DEFAULT_LAYOUT.queueW),
      caseW: num(v.caseW, DEFAULT_LAYOUT.caseW),
      caseOpen: typeof v.caseOpen === "boolean" ? v.caseOpen : true,
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
  const live = useRef({ ingest, caseOpen: layout.caseOpen });
  useEffect(() => {
    live.current = { ingest, caseOpen: layout.caseOpen };
  });

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
    const order: PaneId[] = ["filter", "timeline", "table", "packets", "queue"];
    if (live.current.caseOpen) order.push("case");
    const cur = currentPane();
    const i = cur ? order.indexOf(cur) : -1;
    focusPane(order[(i + d + order.length) % order.length]!);
  }, []);

  const goCase = useCallback(() => {
    setLayout((l) => ({ ...l, caseOpen: true }));
    requestAnimationFrame(() => focusPane("case"));
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
      { id: "shell.go-queue", title: "Go to suspicion queue", group: "Navigation", shortcut: "g q", run: () => focusPane("queue") },
      { id: "shell.go-case", title: "Go to case", group: "Navigation", shortcut: "g c", run: goCase },
      {
        id: "shell.toggle-case",
        title: "Show or hide the case panel",
        group: "Layout",
        shortcut: "mod+\\",
        run: () => setLayout((l) => ({ ...l, caseOpen: !l.caseOpen })),
      },
      { id: "shell.reset-layout", title: "Reset pane sizes", group: "Layout", shortcut: "g 0", run: () => setLayout(DEFAULT_LAYOUT) },
    ],
    [cycle, goCase],
  );
  useRegisterCommands(commands);

  const sha = session?.capture.sha256 ?? "";
  const capName = session ? (session.capture.path.split(/[\\/]/).pop() ?? session.capture.path) : "";
  const kbd = (s: string) => formatShortcut(s, mac);

  return (
    <div
      className="wl-shell"
      style={{
        gridTemplateColumns: `minmax(0, 1fr) 6px ${layout.queueW}px${layout.caseOpen ? ` 6px ${layout.caseW}px` : ""}`,
      }}
    >
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
        <button
          type="button"
          aria-pressed={layout.caseOpen}
          onClick={() => setLayout((l) => ({ ...l, caseOpen: !l.caseOpen }))}
          title={`Case panel (${kbd("mod+\\")})`}
        >
          Case
        </button>
        <GlobalKeys />
      </header>

      <main
        className="wl-main"
        style={{ gridTemplateRows: `${layout.timelineH}px 6px minmax(80px, 1fr) 6px ${layout.packetsH}px` }}
        aria-label="Analysis"
      >
        <div className="wl-pane" data-pane="timeline" tabIndex={-1} id="wl-pane-timeline">
          <TimelinePanel />
        </div>
        <Splitter
          label="Resize timeline"
          orientation="horizontal"
          value={layout.timelineH}
          min={80}
          max={600}
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
          value={layout.packetsH}
          min={120}
          max={800}
          sign={-1}
          controls="wl-pane-packets"
          onChange={(v) => setLayout((l) => ({ ...l, packetsH: v }))}
        />
        <div className="wl-pane" data-pane="packets" tabIndex={-1} id="wl-pane-packets">
          <PacketPane />
        </div>
      </main>

      <Splitter
        label="Resize suspicion queue"
        orientation="vertical"
        value={layout.queueW}
        min={220}
        max={720}
        sign={-1}
        controls="wl-pane-queue"
        onChange={(v) => setLayout((l) => ({ ...l, queueW: v }))}
      />
      <aside className="wl-pane wl-side" data-pane="queue" tabIndex={-1} id="wl-pane-queue" aria-label="Suspicion queue pane">
        <QueuePanel />
      </aside>
      {layout.caseOpen && (
        <>
          <Splitter
            label="Resize case panel"
            orientation="vertical"
            value={layout.caseW}
            min={240}
            max={800}
            sign={-1}
            controls="wl-pane-case"
            onChange={(v) => setLayout((l) => ({ ...l, caseW: v }))}
          />
          <aside className="wl-pane wl-side" data-pane="case" tabIndex={-1} id="wl-pane-case" aria-label="Case pane">
            <CasePanel />
          </aside>
        </>
      )}

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
