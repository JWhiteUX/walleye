import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useCommands } from "../shared/commands";
import { api } from "../shared/ipc";
import { resetMock } from "../shared/mock";
import { useSelection } from "../shared/selection";
import { useSession } from "../shared/session";
import { getTimelineSnapshot } from "../shared/snapshots";
import { TimelinePanel } from "./TimelinePanel";

// jsdom has no 2D canvas; the panel must cope (it skips drawing).
beforeEach(() => {
  vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(null);
  resetMock({ open: true });
  useSelection.getState().reset();
  useSession.getState().setSession(null);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

async function renderTimeline() {
  render(<TimelinePanel />);
  const panel = screen.getByTestId("timeline-panel");
  await waitFor(() => expect(panel).toHaveAttribute("data-state", "ready"));
  await waitFor(() => expect(panel).toHaveAttribute("data-loading", "false"));
  const canvas = screen.getByTestId("timeline-canvas");
  const table = screen.getByTestId("timeline-summary");
  return { panel, canvas, table };
}
const hostRows = (table: HTMLElement) => within(table).getAllByRole("row").slice(1);

describe("TimelinePanel", () => {
  it("summarises lanes in an accessible table with score text", async () => {
    const { table } = await renderTimeline();
    const rows = hostRows(table);
    expect(rows.length).toBeGreaterThan(3);
    const beacon = rows.find((r) => r.getAttribute("data-host") === "10.0.0.23")!;
    expect(beacon).toHaveTextContent("92 High");
    expect(within(table).getByRole("columnheader", { name: "Bulk transfer" })).toBeInTheDocument();
  });

  it("has a legend with a shape and a label for every kind", async () => {
    await renderTimeline();
    const legend = screen.getByRole("list", { name: "Legend" });
    const items = within(legend).getAllByRole("listitem");
    expect(items.map((i) => i.textContent)).toEqual(["DNS", "TLS", "HTTP", "Bulk transfer", "Other"]);
    expect(items.map((i) => i.querySelector("svg")?.getAttribute("data-shape"))).toEqual([
      "circle",
      "square",
      "triangle",
      "diamond",
      "cross",
    ]);
  });

  it("keyboard: arrows focus lanes, Enter toggles the host", async () => {
    const { canvas, table } = await renderTimeline();
    const firstHost = hostRows(table)[0]!.getAttribute("data-host")!;
    canvas.focus();
    fireEvent.keyDown(canvas, { key: "ArrowDown" });
    expect(screen.getByTestId("timeline-live")).toHaveTextContent(`Lane 1 of`);
    fireEvent.keyDown(canvas, { key: "Enter" });
    expect(useSelection.getState().hosts).toEqual([firstHost]);
    expect(hostRows(table)[0]).toHaveTextContent(/yes$/);
    fireEvent.keyDown(canvas, { key: "Enter" });
    expect(useSelection.getState().hosts).toEqual([]);
  });

  it("keyboard brushing: shift+arrows set time_range, Escape clears it", async () => {
    const { canvas } = await renderTimeline();
    canvas.focus();
    fireEvent.keyDown(canvas, { key: "ArrowRight" });
    expect(useSelection.getState().time_range).toBeNull();
    for (let i = 0; i < 3; i++) fireEvent.keyDown(canvas, { key: "ArrowRight", shiftKey: true });
    const r = useSelection.getState().time_range;
    expect(r).not.toBeNull();
    expect(r!.end).toBeGreaterThan(r!.start);
    expect(screen.getByTestId("timeline-brush-readout")).toHaveTextContent("Time range:");
    fireEvent.keyDown(canvas, { key: "Escape" });
    expect(useSelection.getState().time_range).toBeNull();
    expect(screen.getByTestId("timeline-brush-readout")).toHaveTextContent("No time range selected");
  });

  it("zoom re-queries with the view window; 0 resets to the whole capture", async () => {
    const spy = vi.spyOn(api, "timeline");
    const { panel, canvas } = await renderTimeline();
    const full = Number(panel.getAttribute("data-view-end")) - Number(panel.getAttribute("data-view-start"));
    spy.mockClear();
    canvas.focus();
    fireEvent.keyDown(canvas, { key: "+" });
    const zoomed = Number(panel.getAttribute("data-view-end")) - Number(panel.getAttribute("data-view-start"));
    expect(zoomed).toBeCloseTo(full / 2, -2);
    await waitFor(() => expect(spy).toHaveBeenCalled());
    expect(spy.mock.calls.at(-1)![0].time_range).not.toBeNull();
    fireEvent.keyDown(canvas, { key: "0" });
    expect(Number(panel.getAttribute("data-view-end")) - Number(panel.getAttribute("data-view-start"))).toBe(full);
  });

  it("re-queries when the filter changes (debounced, latest wins)", async () => {
    const spy = vi.spyOn(api, "timeline");
    const { table, panel } = await renderTimeline();
    const before = hostRows(table).length;
    spy.mockClear();
    act(() => useSelection.getState().setFilter("host 10.0.0.99"));
    act(() => useSelection.getState().setFilter("host 10.0.0.23"));
    await waitFor(() => expect(panel).toHaveAttribute("data-loading", "false"));
    await waitFor(() => expect(hostRows(table).length).toBeLessThan(before));
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0]![0].filter).toBe("host 10.0.0.23");
  });

  it("ignores the brush when querying (the brush is an overlay)", async () => {
    const spy = vi.spyOn(api, "timeline");
    await renderTimeline();
    spy.mockClear();
    act(() => useSelection.getState().setTimeRange({ start: 1, end: 2 }));
    await new Promise((r) => setTimeout(r, 150));
    expect(spy).not.toHaveBeenCalled();
  });

  it("registers commands and a snapshot provider", async () => {
    await renderTimeline();
    const cmds = useCommands.getState().commands;
    expect(cmds["timeline.focus"]?.shortcut).toBe("g t");
    for (const id of ["zoom-in", "zoom-out", "pan-left", "pan-right", "reset-zoom", "zoom-to-brush", "clear-brush"])
      expect(cmds[`timeline.${id}`]).toBeDefined();
    // No 2D context in jsdom, so nothing to snapshot; must not throw.
    expect(getTimelineSnapshot()).toBeNull();
  });

  it("shows an empty state when no capture is open", async () => {
    resetMock({ open: false });
    render(<TimelinePanel />);
    await waitFor(() => expect(screen.getByTestId("timeline-panel")).toHaveAttribute("data-state", "no-capture"));
    expect(screen.getByText("Open a capture to see the timeline.")).toBeInTheDocument();
  });
});
