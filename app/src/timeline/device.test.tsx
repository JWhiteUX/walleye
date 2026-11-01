import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Bucket } from "../shared/bindings/Bucket";
import { MARK_ENCODING, WIFI_ENCODING } from "../shared/encoding";
import { api } from "../shared/ipc";
import { resetMock } from "../shared/mock";
import { useSelection } from "../shared/selection";
import { useSession } from "../shared/session";
import { type PathSink, shapePath, STROKED } from "./draw";
import {
  aggregateColumns,
  buildLaneModels,
  describeCounts,
  DEVICE_KINDS,
  hitTest,
  KINDS,
  kindsFor,
  labelWidth,
  laneLabel,
  LAYOUT,
  rowY,
} from "./layout";
import { TimelinePanel } from "./TimelinePanel";

const wb = (t: number, p: Partial<Bucket> = {}): Bucket => ({
  t,
  dns: 0,
  tls: 0,
  http: 0,
  bulk: 0,
  other: 0,
  wifi_mgmt: 0,
  wifi_probe: 0,
  wifi_data: 0,
  wifi_deauth: 0,
  ...p,
});

describe("device lanes: layout", () => {
  it("uses the four Wi-Fi kinds, each with its own row, label, shape and colour token", () => {
    expect(kindsFor("device")).toEqual(["wifi_mgmt", "wifi_probe", "wifi_data", "wifi_deauth"]);
    expect(kindsFor("host")).toBe(KINDS);
    const shapes = DEVICE_KINDS.map((k) => MARK_ENCODING[k].shape);
    // Distinct among themselves and from every IP kind, so a mark is never ambiguous.
    expect(new Set([...shapes, ...KINDS.map((k) => MARK_ENCODING[k].shape)]).size).toBe(9);
    for (const k of DEVICE_KINDS) {
      expect(WIFI_ENCODING[k].label).toMatch(/\w/);
      expect(WIFI_ENCODING[k].cssVar).toMatch(/^--wl-kind-wifi-/);
    }
    const ys = DEVICE_KINDS.map((k) => rowY(0, k, DEVICE_KINDS));
    expect(new Set(ys).size).toBe(4);
    for (const y of ys) expect(y).toBeGreaterThan(0);
    expect(Math.max(...ys)).toBeLessThan(LAYOUT.laneH);
  });

  it("aggregates wifi_* counts (sorted or not) and ignores the IP kinds", () => {
    const cols = aggregateColumns([wb(25, { wifi_deauth: 3, dns: 9 }), wb(0, { wifi_mgmt: 1 }), wb(10, { wifi_probe: 2 })], 0, 20, DEVICE_KINDS);
    expect(cols).toEqual([
      { t: 0, counts: { wifi_mgmt: 1, wifi_probe: 2, wifi_data: 0, wifi_deauth: 0 }, total: 3 },
      { t: 20, counts: { wifi_mgmt: 0, wifi_probe: 0, wifi_data: 0, wifi_deauth: 3 }, total: 3 },
    ]);
    const [lane] = buildLaneModels(
      [{ host: "d6:5e:00:53:de:ad", is_other: false, total: 6, max_score: 95, buckets: [wb(0, { wifi_deauth: 5 }), wb(40, { wifi_mgmt: 1 })] }],
      0,
      20,
      DEVICE_KINDS,
    );
    expect(lane!.kindTotals).toEqual({ wifi_mgmt: 1, wifi_probe: 0, wifi_data: 0, wifi_deauth: 5 });
    expect(describeCounts(lane!.kindTotals, DEVICE_KINDS)).toBe("Management 1 · Deauth 5");
    expect(describeCounts({}, DEVICE_KINDS)).toBe("no frames");
  });

  it("labels device lanes by MAC, saying 'randomized' in words", () => {
    expect(laneLabel({ host: "d6:5e:00:53:de:ad", isOther: false }, "device")).toBe("d6:5e:00:53:de:ad, randomized");
    expect(laneLabel({ host: "00:00:5e:00:53:01", isOther: false }, "device")).toBe("00:00:5e:00:53:01");
    expect(laneLabel({ host: "other", isOther: true }, "device")).toBe("Other devices");
  });

  it("widens the label column for MACs and hit-tests against it", () => {
    const lw = labelWidth("device");
    expect(lw).toBeGreaterThan(LAYOUT.labelW);
    const opts = { width: 1000, height: 300, scrollY: 0, laneCount: 3, view: { start: 0, end: 1 } };
    const x = LAYOUT.labelW + 10;
    expect(hitTest(x, LAYOUT.axisH + 1, opts).region).toBe("plot");
    expect(hitTest(x, LAYOUT.axisH + 1, { ...opts, labelW: lw }).region).toBe("label");
  });

  it("draws distinct, filled geometry for the Wi-Fi shapes", () => {
    const geometry = (shape: Parameters<typeof shapePath>[1]) => {
      const pts: number[] = [];
      const sink: PathSink = {
        moveTo: (x, y) => pts.push(x, y),
        lineTo: (x, y) => pts.push(x, y),
        arc: (x, y, r) => pts.push(x, y, r),
        rect: (x, y, w, h) => pts.push(x, y, w, h),
        closePath: () => {},
      };
      shapePath(sink, shape, 10, 10, 3);
      return pts.map((v) => v.toFixed(2)).join(",");
    };
    const sigs = DEVICE_KINDS.map((k) => geometry(MARK_ENCODING[k].shape));
    expect(new Set(sigs).size).toBe(4);
    for (const k of DEVICE_KINDS) expect(STROKED.has(MARK_ENCODING[k].shape)).toBe(false);
  });
});

describe("TimelinePanel on an 802.11 capture", () => {
  beforeEach(async () => {
    vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(null);
    resetMock({ open: true, dataset: "wifi" });
    useSelection.getState().reset();
    useSession.getState().setSession(await api.currentCapture());
  });
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    useSession.getState().setSession(null);
  });

  async function renderTimeline() {
    render(<TimelinePanel />);
    const panel = screen.getByTestId("timeline-panel");
    await waitFor(() => expect(panel).toHaveAttribute("data-state", "ready"));
    await waitFor(() => expect(panel).toHaveAttribute("data-loading", "false"));
    return { panel, canvas: screen.getByTestId("timeline-canvas"), table: screen.getByTestId("timeline-summary") };
  }

  it("shows device lanes with the Wi-Fi legend and an accessible table", async () => {
    const { canvas, table } = await renderTimeline();
    const legend = screen.getByRole("list", { name: "Legend" });
    const items = within(legend).getAllByRole("listitem");
    expect(items.map((i) => i.textContent)).toEqual(["Management", "Probe", "Data", "Deauth", "RRandomized MAC"]);
    expect(items.slice(0, 4).map((i) => i.querySelector("svg")?.getAttribute("data-shape"))).toEqual(["ring", "triangle-down", "bar", "star"]);
    expect(canvas).toHaveAttribute("aria-label", expect.stringMatching(/device lanes$/));
    expect(within(table).getByRole("columnheader", { name: "Device" })).toBeInTheDocument();
    expect(within(table).getByRole("columnheader", { name: "Frames" })).toBeInTheDocument();
    const flood = table.querySelector('tr[data-host="d6:5e:00:53:de:ad"]')!;
    expect(flood).toHaveTextContent("d6:5e:00:53:de:ad, randomized");
    expect(flood).toHaveTextContent("95 High");
  });

  it("Enter on a device lane focuses the device (selectDevice), not the host selection", async () => {
    const { canvas, table } = await renderTimeline();
    const first = table.querySelector("tbody tr")!.getAttribute("data-host")!;
    canvas.focus();
    fireEvent.keyDown(canvas, { key: "ArrowDown" });
    expect(screen.getByTestId("timeline-live")).toHaveTextContent(/frames/);
    fireEvent.keyDown(canvas, { key: "Enter" });
    expect(useSelection.getState().device).toBe(first);
    expect(useSelection.getState().hosts).toEqual([]);
    expect(screen.getByTestId("timeline-live")).toHaveTextContent("focused");
    expect(table.querySelector("tbody tr")).toHaveTextContent(/yes$/);
    fireEvent.keyDown(canvas, { key: "Enter" });
    expect(useSelection.getState().device).toBeNull();
  });

  it("the brush still sets the shared time range", async () => {
    const { canvas } = await renderTimeline();
    canvas.focus();
    fireEvent.keyDown(canvas, { key: "ArrowRight" });
    for (let i = 0; i < 3; i++) fireEvent.keyDown(canvas, { key: "ArrowRight", shiftKey: true });
    const r = useSelection.getState().time_range;
    expect(r).not.toBeNull();
    expect(r!.end).toBeGreaterThan(r!.start);
  });

  it("filters lanes with the Wi-Fi filter fields", async () => {
    const { table, panel } = await renderTimeline();
    const before = table.querySelectorAll("tbody tr").length;
    act(() => useSelection.getState().setFilter("wifi.kind == deauth"));
    await waitFor(() => expect(panel).toHaveAttribute("data-loading", "false"));
    await waitFor(() => expect(table.querySelectorAll("tbody tr").length).toBeLessThan(before));
    expect(table.querySelector("tbody tr")!.getAttribute("data-host")).toBe("d6:5e:00:53:de:ad");
  });
});
