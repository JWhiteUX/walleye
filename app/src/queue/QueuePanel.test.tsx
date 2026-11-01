import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useCommands } from "../shared/commands";
import { api, WalleyeError } from "../shared/ipc";
import { resetMock } from "../shared/mock";
import { useSelection } from "../shared/selection";
import { useSession } from "../shared/session";
import { QueuePanel } from "./QueuePanel";

async function renderQueue() {
  const user = userEvent.setup();
  render(<QueuePanel />);
  const list = await screen.findByRole("list", { name: /findings/i });
  return { user, list };
}

const rows = () => screen.getAllByRole("button", { expanded: false }).concat(screen.queryAllByRole("button", { expanded: true }));
const heads = (list: HTMLElement) => within(list).getAllByRole("button").filter((b) => b.hasAttribute("aria-expanded"));

beforeEach(() => {
  resetMock({ open: true });
  useSelection.getState().reset();
  useSession.getState().setSession(null);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("QueuePanel", () => {
  it("lists findings ranked by score with number, band word and bar", async () => {
    const { list } = await renderQueue();
    const items = within(list).getAllByRole("listitem").filter((li) => li.hasAttribute("data-finding-id"));
    expect(items).toHaveLength(4);
    const scores = items.map((li) => Number(li.querySelector(".wl-q-num")!.textContent));
    expect(scores).toEqual([...scores].sort((a, b) => b - a));
    expect(items[0]).toHaveTextContent("92");
    expect(items[0]).toHaveTextContent("High");
    expect(items[0]).toHaveTextContent("10.0.0.23");
    expect(items[0]).toHaveTextContent("T1071");
    expect(items[3]).toHaveTextContent("Low");
    expect(items[0]!.querySelector(".wl-q-bar > span")).toHaveStyle({ width: "92%" });
    expect(rows().length).toBeGreaterThan(0);
  });

  it("renders indicators as text, never links", async () => {
    const { list } = await renderQueue();
    expect(within(list).queryAllByRole("link")).toHaveLength(0);
    await userEvent.click(heads(list)[0]!);
    expect(within(list).queryAllByRole("link")).toHaveLength(0);
    expect(list.querySelectorAll("a")).toHaveLength(0);
  });

  it("expands to reasons; an evidence link drives the shared selection", async () => {
    const { user, list } = await renderQueue();
    const first = heads(list)[0]!;
    await user.click(first);
    expect(first).toHaveAttribute("aria-expanded", "true");
    const region = screen.getByRole("region", { name: /Beaconing/ });
    expect(within(region).getByText(/contacted 185\.199\.110\.77 56 times/)).toBeInTheDocument();
    expect(within(region).getByText("+46 pts")).toBeInTheDocument();
    const ev = within(region).getAllByTestId("queue-evidence")[0]!;
    expect(ev).toHaveTextContent("56 flows · 56 frames");
    await user.click(ev);
    const s = useSelection.getState();
    expect(s.flow_ids).toHaveLength(56);
    expect(s.flow_ids[0]).toBe(27);
    expect(s.frame_no).toBe(140);
    expect(s.hosts).toEqual(["10.0.0.23"]);
    expect(screen.getByTestId("queue-status")).toHaveTextContent("frame 140");
  });

  it("verdicts are optimistic and persist", async () => {
    const spy = vi.spyOn(api, "setVerdict");
    const { user, list } = await renderQueue();
    await user.click(heads(list)[0]!);
    const btn = screen.getByRole("button", { name: "Suspicious" });
    await user.click(btn);
    expect(screen.getByRole("button", { name: "✓ Suspicious" })).toHaveAttribute("aria-pressed", "true");
    expect(spy).toHaveBeenCalledWith("f1b2c3d4e5f60001", "suspicious");
    const persisted = await api.findings();
    expect(persisted.find((f) => f.finding_id === "f1b2c3d4e5f60001")?.verdict).toBe("suspicious");
  });

  it("rolls a verdict back when the backend refuses it", async () => {
    let reject!: (e: unknown) => void;
    vi.spyOn(api, "setVerdict").mockImplementation(
      () =>
        new Promise((_, r) => {
          reject = r;
        }),
    );
    const { user, list } = await renderQueue();
    await user.click(heads(list)[0]!);
    await user.click(screen.getByRole("button", { name: "Benign" }));
    // Optimistic: shown before the backend answers.
    expect(screen.getByRole("button", { name: "✓ Benign" })).toHaveAttribute("aria-pressed", "true");
    expect(within(list).getAllByTestId("queue-verdict")[0]).toHaveTextContent("Benign");
    await act(async () => reject(new WalleyeError({ code: "io", message: "disk full", span: null })));
    expect(screen.getByRole("button", { name: "Benign" })).toHaveAttribute("aria-pressed", "false");
    expect(within(list).getAllByTestId("queue-verdict")[0]).toHaveTextContent("No verdict");
    expect(screen.getByTestId("queue-status")).toHaveTextContent(/disk full/);
    expect(screen.getByTestId("queue-status")).toHaveAttribute("data-error", "true");
  });

  it("keyboard: j/k move, Enter expands, v then s/b/r sets a verdict", async () => {
    const spy = vi.spyOn(api, "setVerdict");
    const { user, list } = await renderQueue();
    const h = heads(list);
    h[0]!.focus();
    await user.keyboard("j");
    expect(h[1]).toHaveFocus();
    await user.keyboard("{ArrowDown}");
    expect(h[2]).toHaveFocus();
    await user.keyboard("k");
    expect(h[1]).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(h[1]).toHaveAttribute("aria-expanded", "true");
    await user.keyboard("vr");
    expect(spy).toHaveBeenCalledWith(list.querySelectorAll("li[data-finding-id]")[1]!.getAttribute("data-finding-id"), "needs_review");
    expect(within(list).getAllByTestId("queue-verdict")[1]).toHaveTextContent("Needs review");
    // "s" without a preceding "v" does nothing.
    spy.mockClear();
    await user.keyboard("s");
    expect(spy).not.toHaveBeenCalled();
    // Roving tabindex: only the active row is in the tab order.
    expect(h.filter((b) => b.tabIndex === 0)).toEqual([h[1]]);
  });

  it("registers its commands (with v-sequences) in the palette registry", async () => {
    const { list } = await renderQueue();
    // The list can render before the findings load; the verdict command acts on
    // the first finding, so wait for it (this raced under load).
    await waitFor(() => expect(heads(list).length).toBeGreaterThan(0));
    const cmds = useCommands.getState().commands;
    expect(cmds["queue.verdict-suspicious"]?.shortcut).toBe("v s");
    expect(cmds["queue.verdict-benign"]?.shortcut).toBe("v b");
    expect(cmds["queue.verdict-needs-review"]?.shortcut).toBe("v r");
    expect(cmds["queue.focus"]?.shortcut).toBe("g q");
    const spy = vi.spyOn(api, "setVerdict");
    act(() => cmds["queue.verdict-benign"]!.run());
    expect(spy).toHaveBeenCalledWith("f1b2c3d4e5f60001", "benign");
  });

  it("filters by the selected time range, and the toggle turns it off", async () => {
    const { user } = await renderQueue();
    const all = (await api.findings()).length;
    const f = await api.findings();
    // A range that only overlaps the DGA finding window start, before the beacon starts.
    const cap = (await api.currentCapture())!.capture;
    const range = { start: cap.first_ts, end: cap.first_ts + 1 };
    const expected = f.filter((x) => x.ts_first < range.end && x.ts_last >= range.start).length;
    act(() => useSelection.getState().setTimeRange(range));
    await waitFor(() => expect(screen.getByTestId("queue-count")).toHaveTextContent(`${expected} finding`));
    expect(expected).toBeLessThan(all);
    await user.click(screen.getByRole("checkbox", { name: /only in selected time range/i }));
    await waitFor(() => expect(screen.getByTestId("queue-count")).toHaveTextContent(`${all} findings`));
  });

  it("pin reports an error without an open case, and pins with one", async () => {
    const { user, list } = await renderQueue();
    await user.click(heads(list)[0]!);
    await user.click(screen.getByRole("button", { name: "Pin finding" }));
    await waitFor(() => expect(screen.getByTestId("queue-status")).toHaveTextContent(/Could not pin/));
  });

  it("shows an empty state when no capture is open", async () => {
    resetMock({ open: false });
    render(<QueuePanel />);
    expect(await screen.findByText(/Open a capture to see findings/)).toBeInTheDocument();
  });
});

describe("QueuePanel with a case open", () => {
  it("pins the finding to the case", async () => {
    useSession.getState().setSession(await api.currentCapture());
    const spy = vi.spyOn(api, "casePin");
    const { user, list } = await renderQueue();
    await user.click(heads(list)[0]!);
    await user.click(screen.getByRole("button", { name: "Pin finding" }));
    await waitFor(() => expect(screen.getByTestId("queue-status")).toHaveTextContent(/Pinned/));
    expect(spy).toHaveBeenCalledWith("a3f1c9e07b5d2e64", { kind: "finding", finding_id: "f1b2c3d4e5f60001" }, "");
  });
});
