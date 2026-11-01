// Dev-only benchmark (`?bench=table`): the real VirtualGrid fed 1,000,000
// synthetic flow rows, scrolled programmatically while frame times are
// recorded with requestAnimationFrame. Results go to `window.__tableBench`
// and the page, for e2e/table-perf.spec.ts.
import { useCallback, useMemo, useRef, useState } from "react";
import type { FlowRow } from "../shared/bindings/FlowRow";
import { COLUMNS } from "./columns";
import { VirtualGrid } from "./VirtualGrid";
import "./table.css";

export interface BenchResult {
  rows: number;
  buildMs: number;
  frames: number;
  seconds: number;
  fps: number;
  p50FrameMs: number;
  p95FrameMs: number;
  p99FrameMs: number;
  maxFrameMs: number;
  framesOver20ms: number;
  scrolledPx: number;
  finalTopRow: number;
  /** Time spent in the scroll handler (virtualizer + synchronous React render), per scroll event. */
  p50ScrollRenderMs: number;
  p95ScrollRenderMs: number;
}

declare global {
  interface Window {
    __tableBench?: BenchResult;
  }
}

function makeRows(n: number): FlowRow[] {
  const out = new Array<FlowRow>(n);
  const t0 = 1_773_306_000_000_000;
  for (let i = 0; i < n; i++) {
    const a = i % 250;
    out[i] = {
      flow_id: i + 1,
      ts_start: t0 + i * 1000,
      ts_end: t0 + i * 1000 + (i % 977) * 1000,
      src_ip: `10.0.${(i >> 8) & 255}.${a}`,
      src_port: 1024 + (i % 60000),
      dst_ip: `192.168.${a}.${(i * 7) & 255}`,
      dst_port: [53, 443, 80, 22][i & 3]!,
      proto: i & 1 ? 6 : 17,
      app_proto: ["dns", "tls", "http", null][i & 3]!,
      bytes_up: (i * 37) % 100_000,
      bytes_down: (i * 91) % 5_000_000,
      pkts_up: i % 50,
      pkts_down: i % 70,
      first_frame: i * 4 + 1,
      last_frame: i * 4 + 4,
    };
  }
  return out;
}

const pct = (sorted: number[], p: number) => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))] ?? 0;

export function TableBench() {
  const params = new URLSearchParams(window.location.search);
  const n = Math.min(5_000_000, Math.max(1, Number(params.get("rows")) || 1_000_000));
  const built = useMemo(() => {
    const t = performance.now();
    const rows = makeRows(n);
    return { rows, ms: performance.now() - t };
  }, [n]);
  const el = useRef<HTMLDivElement | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [result, setResult] = useState<BenchResult | null>(null);
  const [running, setRunning] = useState(false);

  const run = useCallback((seconds: number, pxPerFrame: number, jumps: boolean) => {
    const scroller = el.current;
    if (!scroller) return;
    setRunning(true);
    scroller.scrollTop = 0;
    const deltas: number[] = [];
    const renders: number[] = [];
    let t0 = 0;
    const before = () => {
      t0 = performance.now();
    };
    // Registered after the virtualizer's listener, so it runs after its render.
    const after = () => {
      if (t0) renders.push(performance.now() - t0);
    };
    scroller.addEventListener("scroll", before, { capture: true });
    scroller.addEventListener("scroll", after);
    let last = 0;
    let start = 0;
    let scrolled = 0;
    let dir = 1;
    // The first 0.5 s warms up (JIT, first renders) and is not measured.
    let warmUntil = 0;
    const step = (now: number) => {
      if (!warmUntil) warmUntil = now + 500;
      if (now < warmUntil) {
        renders.length = 0;
      } else if (!start) {
        start = now;
        last = now;
      } else {
        deltas.push(now - last);
        last = now;
      }
      if (start && now - start >= seconds * 1000) {
        scroller.removeEventListener("scroll", before, { capture: true });
        scroller.removeEventListener("scroll", after);
        const sorted = [...deltas].sort((a, b) => a - b);
        const rs = [...renders].sort((a, b) => a - b);
        const secs = (now - start) / 1000;
        const r: BenchResult = {
          rows: built.rows.length,
          buildMs: Math.round(built.ms),
          frames: deltas.length,
          seconds: Number(secs.toFixed(2)),
          fps: Number((deltas.length / secs).toFixed(1)),
          p50FrameMs: Number(pct(sorted, 0.5).toFixed(2)),
          p95FrameMs: Number(pct(sorted, 0.95).toFixed(2)),
          p99FrameMs: Number(pct(sorted, 0.99).toFixed(2)),
          maxFrameMs: Number((sorted[sorted.length - 1] ?? 0).toFixed(2)),
          framesOver20ms: deltas.filter((d) => d > 20).length,
          scrolledPx: scrolled,
          finalTopRow: Math.floor(scroller.scrollTop / 24),
          p50ScrollRenderMs: Number(pct(rs, 0.5).toFixed(2)),
          p95ScrollRenderMs: Number(pct(rs, 0.95).toFixed(2)),
        };
        window.__tableBench = r;
        setResult(r);
        setRunning(false);
        return;
      }
      // Fling down through the list; every 60 frames jump to a random spot
      // so the run touches the whole million-row range.
      const max = scroller.scrollHeight - scroller.clientHeight;
      if (jumps && deltas.length % 60 === 59) {
        scroller.scrollTop = Math.floor(Math.random() * max);
      } else {
        if (scroller.scrollTop >= max - pxPerFrame) dir = -1;
        if (scroller.scrollTop <= pxPerFrame) dir = 1;
        scroller.scrollTop += dir * pxPerFrame;
      }
      scrolled += pxPerFrame;
      requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [built]);

  return (
    <main style={{ display: "flex", flexDirection: "column", height: "100%" }} aria-label="Table benchmark">
      <div style={{ padding: 8, display: "flex", gap: 8, alignItems: "center" }}>
        <h1 style={{ fontSize: 14, margin: 0 }}>Table benchmark</h1>
        <span data-testid="bench-rows">{built.rows.length.toLocaleString()} rows built in {Math.round(built.ms)} ms</span>
        <button type="button" disabled={running} onClick={() => run(Number(params.get("seconds")) || 5, Number(params.get("px")) || 1200, params.get("jumps") !== "0")}>
          Run scroll benchmark
        </button>
        <output data-testid="bench-result" className="wl-mono">
          {result ? JSON.stringify(result) : running ? "running…" : ""}
        </output>
      </div>
      <div style={{ flex: 1, minHeight: 0 }}>
        <VirtualGrid
          label="Benchmark flows"
          columns={COLUMNS.flows}
          rows={built.rows}
          totalRows={built.rows.length}
          sorting={[]}
          onSortingChange={() => {}}
          isSelected={(r) => r.flow_id === selected}
          onActivate={(r) => setSelected(r.flow_id)}
          scrollRef={(e) => {
            el.current = e;
          }}
          testId="bench-grid"
        />
      </div>
    </main>
  );
}
