// Timeline: Canvas 2D swimlanes, one per host (top N + "other"), with marks
// per bucket by event kind (on 802.11 captures: one per device MAC, with
// marks per Wi-Fi frame class, and a lane click focuses the device), a brush that sets the shared `time_range`, zoom,
// pan, hover details and full keyboard control. A visually-hidden table and a
// live region give screen-reader users the same information.
//
// The timeline queries with `filter` + its own *view window* (zoom/pan), not
// with the brush: the brush is drawn on top as an overlay so the analyst keeps
// the surrounding context while every other view filters to it. "Zoom to
// brush" (z) narrows the view to the brush on request.
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { LaneKind } from "../shared/bindings/LaneKind";
import type { Lanes } from "../shared/bindings/Lanes";
import type { TimeRange } from "../shared/bindings/TimeRange";
import { useRegisterCommands, type Command } from "../shared/commands";
import { MARK_ENCODING } from "../shared/encoding";
import { formatDuration, formatTime, formatTs } from "../shared/format";
import { api, WalleyeError } from "../shared/ipc";
import { useSelection } from "../shared/selection";
import { useSession } from "../shared/session";
import { getTimelineSnapshot, registerTimelineSnapshot } from "../shared/snapshots";
import { useCaptureKind } from "../shared/captureKind";
import { RANDOMIZED_HELP } from "../shared/wifi";
import { cursorStep, inRange, keyBrush, MIN_BRUSH_PX, normalizeBrush } from "./brush";
import { drawTimeline, readTheme, type Scene, type Theme } from "./draw";
import { createLatestRunner } from "./latest";
import {
  buildLaneModels,
  columnAt,
  columnStart,
  contentHeight,
  describeCounts,
  hitTest,
  kindsFor,
  labelWidth,
  laneLabel,
  LAYOUT,
  type LaneModel,
  plotWidth,
  plotX,
  scoreBadge,
} from "./layout";
import { chooseBucketMs, clampView, columnUs, pan, span, toIpcRange, xToTime, zoomAt } from "./scale";
import { ShapeIcon } from "./ShapeIcon";
import { exposeTestHook } from "./testHooks";
import "./timeline.css";

/** Lanes requested from the backend (top N hosts) before the "other" lane. */
export const MAX_LANES = 50;
const QUERY_DEBOUNCE_MS = 100;
const ZOOM_STEP = 0.5;
const PAN_FRACTION = 0.25;
const FALLBACK_WIDTH = 800;

type LoadState =
  | { kind: "ok"; key: string; lanes: Lanes }
  | { kind: "error"; key: string; message: string; noCapture: boolean };

interface Req {
  key: string;
  filter: string;
  time_range: TimeRange | null;
  bucket_ms: number;
}

export function TimelinePanel() {
  const captureId = useSession((s) => s.session?.capture.capture_id ?? null);
  // Remount on capture change so zoom, cursor and data reset together.
  return <TimelineView key={captureId ?? "none"} />;
}

function TimelineView() {
  const filter = useSelection((s) => s.filter);
  const brush = useSelection((s) => s.time_range);
  const hosts = useSelection((s) => s.hosts);
  const setTimeRange = useSelection((s) => s.setTimeRange);
  const toggleHost = useSelection((s) => s.toggleHost);
  const device = useSelection((s) => s.device);
  const selectDevice = useSelection((s) => s.selectDevice);
  const capture = useSession((s) => s.session?.capture ?? null);
  // Only a guess for the label width before the first answer; once lanes
  // arrive, `lanes.lane_kind` decides.
  const captureWifi = useCaptureKind().wifi === true;

  const [load, setLoad] = useState<LoadState | null>(null);
  const [dataExtent, setDataExtent] = useState<TimeRange | null>(null);
  const [userView, setUserView] = useState<TimeRange | null>(null);
  const [size, setSize] = useState({ w: 0, h: 0 });
  const [scrollY, setScrollY] = useState(0);
  const [draft, setDraft] = useState<TimeRange | null>(null);
  const [hover, setHover] = useState<{ lane: number; t: number; x: number; y: number } | null>(null);
  const [cursor, setCursor] = useState<number | null>(null);
  const [focusedLane, setFocusedLane] = useState<number | null>(null);
  const [focused, setFocused] = useState(false);
  const [announce, setAnnounce] = useState("");

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const scrollerRef = useRef<HTMLDivElement | null>(null);
  const themeRef = useRef<Theme | null>(null);
  const drawsRef = useRef(0);
  const anchorRef = useRef<number | null>(null);
  const dragRef = useRef<{ x0: number; t0: number; dragging: boolean; pointerId: number } | null>(null);

  // ----- extent and view -----
  const extent = useMemo<TimeRange | null>(
    () => (capture ? { start: capture.first_ts, end: capture.last_ts + 1 } : dataExtent),
    [capture, dataExtent],
  );
  const view = useMemo<TimeRange | null>(
    () => (extent ? (userView ? clampView(userView, extent) : extent) : null),
    [extent, userView],
  );
  // Device lanes (802.11) are keyed by MAC and draw the Wi-Fi frame classes.
  const laneKind: LaneKind = (load?.kind === "ok" ? load.lanes.lane_kind : null) ?? (captureWifi ? "device" : "host");
  const isDevice = laneKind === "device";
  const kinds = useMemo(() => kindsFor(laneKind), [laneKind]);
  const lw = labelWidth(laneKind);
  const pw = plotWidth(size.w || FALLBACK_WIDTH, lw);

  // ----- query -----
  const req = useMemo<Req>(() => {
    const zoomed = userView !== null && view !== null;
    const time_range = zoomed ? toIpcRange(view) : null;
    const bucket_ms = view ? chooseBucketMs(view, pw) : 1;
    return { key: JSON.stringify([filter, time_range, bucket_ms]), filter, time_range, bucket_ms };
  }, [filter, userView, view, pw]);

  const [runner] = useState(() =>
    createLatestRunner<Req, Lanes>(
      (r) => api.timeline({ filter: r.filter, time_range: r.time_range, bucket_ms: r.bucket_ms, max_lanes: MAX_LANES }),
      (lanes, r) => {
        setLoad({ kind: "ok", key: r.key, lanes });
        if (r.time_range === null)
          setDataExtent((prev) =>
            prev && prev.start === lanes.range.start && prev.end === lanes.range.end ? prev : lanes.range,
          );
      },
      (e, r) =>
        setLoad({
          kind: "error",
          key: r.key,
          message: e instanceof Error ? e.message : String(e),
          noCapture: e instanceof WalleyeError && e.code === "no_capture",
        }),
    ),
  );
  const hasData = load !== null;
  // Keyed on the request's content, not its identity, so re-renders never refetch.
  const reqRef = useRef(req);
  useEffect(() => {
    reqRef.current = req;
  });
  useEffect(() => {
    runner.schedule(reqRef.current, hasData ? QUERY_DEBOUNCE_MS : 0);
  }, [runner, req.key, hasData]);
  useEffect(() => () => runner.cancel(), [runner]);

  const lanesData = load?.kind === "ok" ? load.lanes : null;
  const loading = load === null || load.key !== req.key;
  const status = load?.kind === "error" ? (load.noCapture ? "no-capture" : "error") : lanesData ? (lanesData.lanes.length ? "ready" : "empty") : "loading";

  // ----- lane models -----
  const colUs = useMemo(
    () => (lanesData && view ? columnUs(lanesData.bucket_ms * 1000, view, pw) : 1),
    [lanesData, view, pw],
  );
  const colOrigin = lanesData?.range.start ?? 0;
  const lanes = useMemo<LaneModel[]>(
    () => (lanesData ? buildLaneModels(lanesData.lanes, colOrigin, colUs, kindsFor(lanesData.lane_kind)) : []),
    [lanesData, colOrigin, colUs],
  );
  // Device lanes highlight the focused device; host lanes the selected hosts.
  const selectedHosts = useMemo(() => new Set(isDevice ? (device ? [device] : []) : hosts), [isDevice, device, hosts]);
  const laneIdx = focusedLane === null || lanes.length === 0 ? null : Math.min(focusedLane, lanes.length - 1);

  // ----- size / theme -----
  useLayoutEffect(() => {
    const el = scrollerRef.current;
    if (!el) return;
    const measure = () => setSize({ w: el.clientWidth, h: el.clientHeight });
    measure();
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    const onChange = () => {
      themeRef.current = null;
      setSize((s) => ({ ...s }));
    };
    mq.addEventListener?.("change", onChange);
    return () => mq.removeEventListener?.("change", onChange);
  }, []);

  // ----- draw -----
  const scene = useMemo<Scene | null>(() => {
    if (!view || size.w === 0 || size.h === 0) return null;
    return {
      width: size.w,
      height: size.h,
      dpr: typeof window !== "undefined" ? window.devicePixelRatio || 1 : 1,
      scrollY,
      view,
      lanes,
      colUs,
      colOrigin,
      selectedHosts,
      brush,
      draft,
      cursor,
      focusedLane: laneIdx,
      focused,
      hover: hover ? { lane: hover.lane, t: hover.t } : null,
      laneKind,
      kinds,
      labelW: lw,
    };
  }, [view, size, scrollY, lanes, colUs, colOrigin, selectedHosts, brush, draft, cursor, laneIdx, focused, hover, laneKind, kinds, lw]);

  useLayoutEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !scene) return;
    const bw = Math.round(scene.width * scene.dpr);
    const bh = Math.round(scene.height * scene.dpr);
    if (canvas.width !== bw) canvas.width = bw;
    if (canvas.height !== bh) canvas.height = bh;
    const ctx = canvas.getContext("2d", { alpha: false });
    if (!ctx) return;
    themeRef.current ??= readTheme(canvas);
    drawTimeline(ctx, scene, themeRef.current);
    drawsRef.current++;
    canvas.dataset.draws = String(drawsRef.current);
  }, [scene]);

  // Snapshot for report export: all lanes, not just the visible ones.
  const sceneRef = useRef<Scene | null>(null);
  useEffect(() => {
    sceneRef.current = scene;
  }, [scene]);
  useEffect(
    () =>
      registerTimelineSnapshot(() => {
        const s = sceneRef.current;
        const canvas = canvasRef.current;
        if (!s || !canvas || s.lanes.length === 0) return null;
        const full = document.createElement("canvas");
        const h = Math.min(contentHeight(s.lanes.length), 8000);
        const dpr = 2;
        full.width = Math.round(s.width * dpr);
        full.height = Math.round(h * dpr);
        const ctx = full.getContext("2d", { alpha: false });
        if (!ctx) return null;
        const th = readTheme(canvas);
        drawTimeline(ctx, { ...s, height: h, dpr, scrollY: 0, hover: null, draft: null, cursor: null, focused: false }, th);
        return full.toDataURL("image/png").replace(/^data:image\/png;base64,/, "");
      }),
    [],
  );

  // ----- view actions -----
  const latest = useRef({ view, extent, cursor, brush, colUs, lanes, laneIdx, pw, lw });
  useEffect(() => {
    latest.current = { view, extent, cursor, brush, colUs, lanes, laneIdx, pw, lw };
  });

  const zoomBy = useCallback((factor: number, anchor?: number) => {
    const { view: v, extent: e, cursor: c } = latest.current;
    if (!v || !e) return;
    const a = anchor ?? (c !== null && c >= v.start && c <= v.end ? c : (v.start + v.end) / 2);
    const next = zoomAt(v, e, factor, a);
    setUserView(span(next) >= span(e) ? null : next);
  }, []);
  const panBy = useCallback((fraction: number) => {
    const { view: v, extent: e } = latest.current;
    if (!v || !e) return;
    const next = pan(v, e, span(v) * fraction);
    setUserView(span(next) >= span(e) ? null : next);
  }, []);
  const resetZoom = useCallback(() => setUserView(null), []);
  const zoomToBrush = useCallback(() => {
    const { brush: b, extent: e } = latest.current;
    if (!b || !e) return;
    const pad = span(b) * 0.05;
    setUserView(clampView({ start: b.start - pad, end: b.end + pad }, e));
  }, []);
  const clearBrush = useCallback(() => {
    anchorRef.current = null;
    setTimeRange(null);
    setAnnounce("Time range cleared");
  }, [setTimeRange]);
  const focusCanvas = useCallback(() => canvasRef.current?.focus(), []);
  /** Device lane activation: focus the device (or unfocus it when it already is). */
  const activateDevice = useCallback(
    (mac: string) => {
      const was = useSelection.getState().device === mac;
      selectDevice(was ? null : mac);
      setAnnounce(was ? `${mac} unfocused` : `${mac} focused; the packet list shows its frames`);
    },
    [selectDevice],
  );

  const commands = useMemo<Command[]>(
    () => [
      { id: "timeline.focus", title: "Focus timeline", group: "Timeline", shortcut: "g t", run: focusCanvas },
      { id: "timeline.zoom-in", title: "Zoom in (+)", group: "Timeline", run: () => zoomBy(ZOOM_STEP) },
      { id: "timeline.zoom-out", title: "Zoom out (−)", group: "Timeline", run: () => zoomBy(1 / ZOOM_STEP) },
      { id: "timeline.pan-left", title: "Pan earlier ([)", group: "Timeline", run: () => panBy(-PAN_FRACTION) },
      { id: "timeline.pan-right", title: "Pan later (])", group: "Timeline", run: () => panBy(PAN_FRACTION) },
      { id: "timeline.reset-zoom", title: "Show whole capture (0)", group: "Timeline", run: resetZoom },
      {
        id: "timeline.zoom-to-brush",
        title: "Zoom to selected time range (z)",
        group: "Timeline",
        run: zoomToBrush,
        enabled: () => useSelection.getState().time_range !== null,
      },
      {
        id: "timeline.clear-brush",
        title: "Clear time range (Esc)",
        group: "Timeline",
        run: clearBrush,
        enabled: () => useSelection.getState().time_range !== null,
      },
    ],
    [focusCanvas, zoomBy, panBy, resetZoom, zoomToBrush, clearBrush],
  );
  useRegisterCommands(commands);

  // ----- describing things (live region, tooltip) -----
  const describeAt = useCallback(
    (lane: number, t: number): string => {
      const l = lanes[lane];
      if (!l) return "";
      const c0 = columnStart(t, colOrigin, colUs);
      const col = columnAt(l, t, colUs);
      return `${laneLabel(l, laneKind)}, ${formatTime(c0)} to ${formatTime(c0 + colUs)}: ${describeCounts(col?.counts ?? {}, kinds)}`;
    },
    [lanes, colOrigin, colUs, laneKind, kinds],
  );
  const describeLane = (i: number): string => {
    const l = lanes[i];
    if (!l) return "";
    const badge = scoreBadge(l.maxScore);
    const sel = !l.isOther && selectedHosts.has(l.host) ? (isDevice ? ", focused" : ", selected") : "";
    return `Lane ${i + 1} of ${lanes.length}: ${laneLabel(l, laneKind)}, ${l.total} ${isDevice ? "frames" : "flows"}${badge ? `, score ${badge.text}` : ""}${sel}. ${describeCounts(l.kindTotals, kinds)}`;
  };

  const scrollLaneIntoView = (i: number) => {
    const el = scrollerRef.current;
    if (!el) return;
    const top = i * LAYOUT.laneH;
    const visibleH = el.clientHeight - LAYOUT.axisH;
    if (top < el.scrollTop) el.scrollTop = top;
    else if (top + LAYOUT.laneH > el.scrollTop + visibleH) el.scrollTop = top + LAYOUT.laneH - visibleH;
  };

  // ----- keyboard -----
  const onKeyDown = (e: React.KeyboardEvent<HTMLCanvasElement>) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (!view || !extent) return;
    let handled = true;
    switch (e.key) {
      case "ArrowLeft":
      case "ArrowRight": {
        const dir = e.key === "ArrowLeft" ? -1 : 1;
        const r = keyBrush({ cursor, anchor: anchorRef.current }, dir, e.shiftKey, cursorStep(colUs, view), view, extent);
        anchorRef.current = r.anchor;
        setCursor(r.cursor);
        if (r.cursor !== null && (r.cursor < view.start || r.cursor > view.end)) {
          const next = pan(view, extent, r.cursor < view.start ? r.cursor - view.start : r.cursor - view.end);
          setUserView(span(next) >= span(extent) ? null : next);
        }
        if (r.brush !== undefined) {
          setTimeRange(r.brush);
          setAnnounce(r.brush ? `Time range ${formatTs(r.brush.start)} to ${formatTs(r.brush.end)}` : "Time range cleared");
        } else if (r.cursor !== null) {
          setAnnounce(laneIdx !== null ? describeAt(laneIdx, r.cursor) : `Cursor at ${formatTime(r.cursor)}`);
        }
        break;
      }
      case "ArrowUp":
      case "ArrowDown": {
        if (lanes.length === 0) break;
        const next =
          laneIdx === null ? 0 : Math.max(0, Math.min(lanes.length - 1, laneIdx + (e.key === "ArrowUp" ? -1 : 1)));
        setFocusedLane(next);
        scrollLaneIntoView(next);
        setAnnounce(describeLane(next) + (cursor !== null ? ` At cursor: ${describeAt(next, cursor)}` : ""));
        break;
      }
      case "Home":
      case "End": {
        if (lanes.length === 0) break;
        const next = e.key === "Home" ? 0 : lanes.length - 1;
        setFocusedLane(next);
        scrollLaneIntoView(next);
        setAnnounce(describeLane(next));
        break;
      }
      case "Enter":
      case " ": {
        const l = laneIdx !== null ? lanes[laneIdx] : undefined;
        if (l && !l.isOther && isDevice) activateDevice(l.host);
        else if (l && !l.isOther) {
          const wasSelected = selectedHosts.has(l.host);
          toggleHost(l.host);
          setAnnounce(`${l.host} ${wasSelected ? "removed from" : "added to"} host selection`);
        }
        break;
      }
      case "Escape":
        if (brush) clearBrush();
        else handled = false;
        break;
      case "+":
      case "=":
        zoomBy(ZOOM_STEP);
        break;
      case "-":
      case "_":
        zoomBy(1 / ZOOM_STEP);
        break;
      case "0":
        resetZoom();
        break;
      case "[":
        panBy(-PAN_FRACTION);
        break;
      case "]":
        panBy(PAN_FRACTION);
        break;
      case "z":
        zoomToBrush();
        break;
      default:
        handled = false;
    }
    if (handled) {
      // Tell the shell's global shortcut handler this key was consumed here.
      e.preventDefault();
      e.stopPropagation();
    }
  };

  // ----- pointer: brush, hover, lane clicks -----
  const local = (e: { clientX: number; clientY: number }) => {
    const r = canvasRef.current!.getBoundingClientRect();
    return { x: e.clientX - r.left, y: e.clientY - r.top };
  };
  const hit = (x: number, y: number) =>
    view
      ? hitTest(x, y, { width: size.w, height: size.h, scrollY, laneCount: lanes.length, view, labelW: lw })
      : ({ region: "none" } as const);

  const onPointerDown = (e: React.PointerEvent<HTMLCanvasElement>) => {
    if (e.button !== 0 || !view) return;
    const { x, y } = local(e);
    const h = hit(x, y);
    if (h.region === "plot" || h.region === "axis") {
      dragRef.current = { x0: x, t0: h.t, dragging: false, pointerId: e.pointerId };
      e.currentTarget.setPointerCapture?.(e.pointerId);
    }
  };
  const onPointerMove = (e: React.PointerEvent<HTMLCanvasElement>) => {
    if (!view || !extent) return;
    const { x, y } = local(e);
    const d = dragRef.current;
    if (d && d.pointerId === e.pointerId) {
      if (!d.dragging && Math.abs(x - d.x0) >= MIN_BRUSH_PX) d.dragging = true;
      if (d.dragging) {
        const px = plotX(lw);
        const t = xToTime(Math.min(Math.max(x, px), px + pw), view, px, pw);
        setDraft(normalizeBrush(d.t0, t, extent));
        setHover(null);
        return;
      }
    }
    const h = hit(x, y);
    if (h.region === "plot" && h.lane !== null) setHover({ lane: h.lane, t: h.t, x, y });
    else if (hover) setHover(null);
  };
  const onPointerUp = (e: React.PointerEvent<HTMLCanvasElement>) => {
    if (!view || !extent) return;
    const { x, y } = local(e);
    const d = dragRef.current;
    dragRef.current = null;
    if (d && d.dragging) {
      const px = plotX(lw);
      const t = xToTime(Math.min(Math.max(x, px), px + pw), view, px, pw);
      const r = normalizeBrush(d.t0, t, extent);
      setDraft(null);
      anchorRef.current = null;
      setTimeRange(r);
      if (r) setAnnounce(`Time range ${formatTs(r.start)} to ${formatTs(r.end)}`);
      return;
    }
    const h = hit(x, y);
    if (h.region === "label") {
      setFocusedLane(h.lane);
      const l = lanes[h.lane];
      if (l && !l.isOther && isDevice) activateDevice(l.host);
      else if (l && !l.isOther) toggleHost(l.host);
    } else if (h.region === "plot") {
      if (h.lane !== null) setFocusedLane(h.lane);
      setCursor(h.t);
      if (brush && !inRange(h.t, brush)) clearBrush();
    }
  };
  const onPointerCancel = () => {
    dragRef.current = null;
    setDraft(null);
  };

  // Wheel needs a non-passive listener to stop page scroll while zooming.
  useEffect(() => {
    const el = canvasRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      const { view: v, extent: ex, pw: w, lw: labelW } = latest.current;
      if (!v || !ex) return;
      const r = el.getBoundingClientRect();
      const x = e.clientX - r.left;
      const px = plotX(labelW);
      if (x < px) return; // over lane labels: let the lanes scroll natively
      e.preventDefault();
      const horizontal = Math.abs(e.deltaX) > Math.abs(e.deltaY) || e.shiftKey;
      if (horizontal) {
        const d = e.shiftKey && e.deltaX === 0 ? e.deltaY : e.deltaX;
        const next = pan(v, ex, (d / w) * span(v));
        setUserView(span(next) >= span(ex) ? null : next);
      } else {
        const anchor = xToTime(Math.min(Math.max(x, px), px + w), v, px, w);
        const next = zoomAt(v, ex, Math.exp(e.deltaY * 0.002), anchor);
        setUserView(span(next) >= span(ex) ? null : next);
      }
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  // ----- derived text -----
  const tooltip = useMemo(() => {
    if (!hover) return null;
    const l = lanes[hover.lane];
    if (!l) return null;
    const c0 = columnStart(hover.t, colOrigin, colUs);
    const col = columnAt(l, hover.t, colUs);
    return { lane: l, c0, col, x: hover.x, y: hover.y };
  }, [hover, lanes, colOrigin, colUs]);

  const viewText = view ? `${formatTime(view.start)} – ${formatTime(view.end)}` : "";
  const brushText = brush
    ? `${formatTs(brush.start)} – ${formatTs(brush.end)} (${formatDuration(brush.end - brush.start)})`
    : null;
  const innerH = Math.max(contentHeight(lanes.length), size.h);

  return (
    <section
      aria-labelledby="wl-tl-title"
      data-testid="timeline-panel"
      data-state={status}
      data-loading={loading ? "true" : "false"}
      data-view-start={view?.start}
      data-view-end={view?.end}
      className="wl-tl"
    >
      <header className="wl-tl-head">
        <h2 id="wl-tl-title" className="wl-tl-title">
          Timeline
        </h2>
        <ul className="wl-tl-legend" aria-label="Legend">
          {kinds.map((k) => (
            <li key={k}>
              <ShapeIcon kind={k} />
              {MARK_ENCODING[k].label}
            </li>
          ))}
          {isDevice && (
            <li title={RANDOMIZED_HELP}>
              <span className="wl-tl-chip" aria-hidden="true">
                R
              </span>
              Randomized MAC
            </li>
          )}
        </ul>
        <div className="wl-tl-tools" role="group" aria-label="Timeline view">
          <button type="button" onClick={() => zoomBy(ZOOM_STEP)} aria-keyshortcuts="+" title="Zoom in (+)">
            Zoom in
          </button>
          <button type="button" onClick={() => zoomBy(1 / ZOOM_STEP)} aria-keyshortcuts="-" title="Zoom out (−)">
            Zoom out
          </button>
          <button type="button" onClick={resetZoom} disabled={userView === null} aria-keyshortcuts="0" title="Show whole capture (0)">
            Reset
          </button>
          <button type="button" onClick={zoomToBrush} disabled={!brush} aria-keyshortcuts="z" title="Zoom to selected range (z)">
            Zoom to range
          </button>
          <button type="button" onClick={clearBrush} disabled={!brush} aria-keyshortcuts="Escape" title="Clear time range (Esc)">
            Clear range
          </button>
        </div>
      </header>
      <p className="wl-tl-status" data-testid="timeline-brush-readout">
        {brushText ? (
          <>
            <span className="wl-tl-status-label">Time range:</span> <span className="wl-mono">{brushText}</span>
          </>
        ) : (
          <span className="wl-tl-muted">No time range selected. Drag across the lanes, or focus the timeline and press Shift+←/→.</span>
        )}
        {viewText && (
          <span className="wl-tl-muted wl-tl-viewtext">
            {" "}
            · Showing <span className="wl-mono">{viewText}</span>
            {loading && status !== "no-capture" ? " · loading…" : ""}
          </span>
        )}
      </p>
      <div className="wl-tl-body">
        <div ref={scrollerRef} className="wl-tl-scroller" onScroll={(e) => setScrollY(e.currentTarget.scrollTop)}>
          <div style={{ height: innerH, position: "relative" }}>
            <canvas
              ref={canvasRef}
              className="wl-tl-canvas"
              style={{ height: size.h || undefined }}
              tabIndex={0}
              role="application"
              aria-roledescription="timeline"
              aria-label={`Timeline, ${lanes.length} ${isDevice ? "device" : "host"} lanes`}
              aria-describedby="wl-tl-help wl-tl-summary-caption"
              data-testid="timeline-canvas"
              onKeyDown={onKeyDown}
              onPointerDown={onPointerDown}
              onPointerMove={onPointerMove}
              onPointerUp={onPointerUp}
              onPointerCancel={onPointerCancel}
              onPointerLeave={() => setHover(null)}
              onFocus={() => setFocused(true)}
              onBlur={() => setFocused(false)}
            />
          </div>
        </div>
        {status !== "ready" && (
          <p className="wl-tl-empty" role={status === "error" ? "alert" : undefined}>
            {status === "loading" && "Loading timeline…"}
            {status === "empty" &&
              (isDevice
                ? "No 802.11 frames match the current filter in this time window."
                : "No flows match the current filter in this time window.")}
            {status === "no-capture" && "Open a capture to see the timeline."}
            {status === "error" && load?.kind === "error" && `Timeline query failed: ${load.message}`}
          </p>
        )}
        {tooltip && (
          <div
            className="wl-tl-tip"
            aria-hidden="true"
            style={{ left: Math.min(tooltip.x + 14, Math.max(0, size.w - 220)), top: Math.min(tooltip.y + 14, Math.max(0, size.h - 120)) }}
          >
            <div className="wl-tl-tip-host">{laneLabel(tooltip.lane, laneKind)}</div>
            <div className="wl-mono">
              {formatTime(tooltip.c0)} – {formatTime(tooltip.c0 + colUs)}
            </div>
            <ul>
              {kinds.map((k) => (
                <li key={k}>
                  <ShapeIcon kind={k} /> {MARK_ENCODING[k].label}: {tooltip.col?.counts[k] ?? 0}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
      <p id="wl-tl-help" className="wl-visually-hidden">
        {isDevice
          ? "Arrow left and right move a time cursor; Shift with arrow left or right extends the selected time range. Arrow up and down move between device lanes; Enter focuses that device so the packet list shows its frames. Plus and minus zoom, brackets pan, 0 shows the whole capture, z zooms to the selected range, Escape clears it."
          : "Arrow left and right move a time cursor; Shift with arrow left or right extends the selected time range. Arrow up and down move between host lanes; Enter toggles the focused host in the selection. Plus and minus zoom, brackets pan, 0 shows the whole capture, z zooms to the selected range, Escape clears it."}
      </p>
      <div className="wl-visually-hidden" aria-live="polite" data-testid="timeline-live">
        {announce}
      </div>
      <table className="wl-visually-hidden" data-testid="timeline-summary">
        <caption id="wl-tl-summary-caption">
          {`Timeline summary: ${lanes.length} lanes, showing ${viewText || "nothing"}. ${
            brushText ? `Selected time range ${brushText}.` : "No time range selected."
          }`}
        </caption>
        <thead>
          <tr>
            <th scope="col">{isDevice ? "Device" : "Host"}</th>
            <th scope="col">{isDevice ? "Frames" : "Flows"}</th>
            <th scope="col">Highest score</th>
            {kinds.map((k) => (
              <th scope="col" key={k}>
                {MARK_ENCODING[k].label}
              </th>
            ))}
            <th scope="col">{isDevice ? "Focused" : "In host selection"}</th>
          </tr>
        </thead>
        <tbody>
          {lanes.map((l) => (
            <tr key={l.host} data-host={l.host}>
              <th scope="row">{laneLabel(l, laneKind)}</th>
              <td>{l.total}</td>
              <td>{scoreBadge(l.maxScore)?.text ?? "none"}</td>
              {kinds.map((k) => (
                <td key={k}>{l.kindTotals[k] ?? 0}</td>
              ))}
              <td>{!l.isOther && selectedHosts.has(l.host) ? "yes" : "no"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

// ---- dev/test-only hooks ----
exposeTestHook("timelineSnapshot", () => getTimelineSnapshot());
if (import.meta.env.DEV) {
  exposeTestHook("timelineBench", async (o: import("./bench").BenchOptions) => {
    const { runTimelineBench } = await import("./bench");
    const canvas = document.querySelector("[data-testid=timeline-canvas]") ?? document.documentElement;
    return runTimelineBench(canvas, {
      ...o,
      width: o.width ?? (canvas.clientWidth || undefined),
      height: o.height ?? (canvas.clientHeight || undefined),
      dpr: o.dpr ?? window.devicePixelRatio,
    });
  });
}
