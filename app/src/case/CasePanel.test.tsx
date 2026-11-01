import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { pinEvidence, useCaseEvents } from "../shared/caseEvents";
import { api } from "../shared/ipc";
import { resetMock } from "../shared/mock";
import { useSelection } from "../shared/selection";
import { useSession } from "../shared/session";
import { registerTimelineSnapshot } from "../shared/snapshots";
import { CasePanel } from ".";
import { describePin, evidenceCount } from "./describe";
import type { Finding } from "../shared/bindings/Finding";

const CASE_ID = "a3f1c9e07b5d2e64";

async function openCase() {
  resetMock({ open: true });
  const s = await api.currentCapture();
  useSession.getState().setSession(s);
}

async function renderPanel() {
  render(<CasePanel />);
  await screen.findByTestId("ioc-table");
}

describe("CasePanel", () => {
  beforeEach(async () => {
    await openCase();
    useSelection.getState().reset();
  });
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    useSession.getState().setSession(null);
  });

  it("asks to open a capture when no case is open", async () => {
    resetMock();
    useSession.getState().setSession(null);
    render(<CasePanel />);
    expect(await screen.findByText(/open a capture/i)).toBeInTheDocument();
    expect(screen.getByTestId("case-panel")).toHaveAccessibleName("Case");
  });

  it("lists defanged IOCs as text, never as links, with allowlist reasons", async () => {
    await renderPanel();
    const table = screen.getByTestId("ioc-table");
    expect(within(table).getAllByTestId("ioc-row")).toHaveLength(12);
    expect(within(table).getByText("hxxp://cdn-update[.]top/gate[.]php?id=7f3a")).toBeInTheDocument();
    expect(within(table).queryByText("cdn-update.top")).toBeNull();
    expect(table.querySelectorAll("a")).toHaveLength(0);
    const badges = within(table).getAllByTestId("allowlisted-badge");
    expect(badges).toHaveLength(2);
    expect(within(table).getByText("Microsoft Update")).toBeInTheDocument();
  });

  it("filters IOCs by type", async () => {
    await renderPanel();
    await userEvent.selectOptions(screen.getByLabelText("Type"), "domain");
    const rows = screen.getAllByTestId("ioc-row");
    expect(rows.length).toBe(7);
    expect(rows.every((r) => r.dataset.iocType === "domain")).toBe(true);
  });

  it("evidence buttons apply the IOC's evidence to the shared selection", async () => {
    await renderPanel();
    await userEvent.click(screen.getByRole("button", { name: /Show evidence for hxxp:\/\/cdn-update/ }));
    const sel = useSelection.getState();
    expect(sel.flow_ids.length).toBe(1);
    expect(sel.frame_no).not.toBeNull();
  });

  it("re-reads the case when another panel pins evidence", async () => {
    await renderPanel();
    expect(screen.queryByTestId("pin-list")).toBeNull();
    await act(async () => {
      await pinEvidence({ kind: "flow", flow_id: 27 }, "first beacon");
    });
    const item = await screen.findByTestId("pin-item");
    expect(within(item).getByText("Flow 27")).toBeInTheDocument();
    expect(within(item).getByText("first beacon")).toBeInTheDocument();
  });

  it("adds, edits and removes notes; unpins pins", async () => {
    const user = userEvent.setup();
    await renderPanel();
    await user.type(screen.getByLabelText("New note"), "Escalated <b>to</b> IR");
    await user.click(screen.getByRole("button", { name: "Add note" }));
    const note = await screen.findByTestId("pin-item");
    expect(note.dataset.kind).toBe("note");
    // rendered as text, not HTML
    expect(within(note).getByTestId("pin-note").textContent).toContain("Escalated <b>to</b> IR");
    expect(note.querySelector("b")).toBeNull();

    await user.click(within(note).getByRole("button", { name: /Edit note/ }));
    const box = within(screen.getByTestId("pin-item")).getByRole("textbox");
    await user.clear(box);
    await user.type(box, "Escalated to IR (ticket 42)");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(screen.getByTestId("pin-note").textContent).toContain("ticket 42"));
    expect(screen.getAllByTestId("pin-item")).toHaveLength(1);

    await user.click(screen.getByRole("button", { name: /Pin indicator 185\[\.\]199/ }));
    await waitFor(() => expect(screen.getAllByTestId("pin-item")).toHaveLength(2));
    await user.click(screen.getByRole("button", { name: "Unpin IP 185[.]199[.]110[.]77" }));
    await waitFor(() => expect(screen.getAllByTestId("pin-item")).toHaveLength(1));
    await user.click(screen.getByRole("button", { name: "Delete note" }));
    await waitFor(() => expect(screen.queryByTestId("pin-item")).toBeNull());
  });

  it("export buttons call the API; the report passes the timeline snapshot", async () => {
    const user = userEvent.setup();
    const iocSpy = vi.spyOn(api, "exportIocs");
    const repSpy = vi.spyOn(api, "exportReport");
    const off = registerTimelineSnapshot(() => "iVBORw0KGgo=");
    await renderPanel();
    await user.click(screen.getByRole("button", { name: "Export IOCs CSV" }));
    expect(iocSpy).toHaveBeenCalledWith(CASE_ID, "csv");
    expect(await screen.findByTestId("case-status")).toHaveTextContent("/exports/iocs.csv");
    await user.click(screen.getByRole("button", { name: "Export IOCs JSON" }));
    expect(iocSpy).toHaveBeenCalledWith(CASE_ID, "json");
    await user.click(screen.getByRole("button", { name: "Export Report Markdown" }));
    expect(repSpy).toHaveBeenCalledWith(CASE_ID, "markdown", "iVBORw0KGgo=");
    await waitFor(() => expect(screen.getByTestId("case-status")).toHaveTextContent("report.md"));
    // the browser mock refuses PDF: the error is announced
    await user.click(screen.getByRole("button", { name: "Export Report PDF" }));
    expect(repSpy).toHaveBeenCalledWith(CASE_ID, "pdf", "iVBORw0KGgo=");
    expect(await screen.findByRole("alert")).toHaveTextContent(/PDF export failed/);
    off();
  });

  it("falls back to the backend's current capture when the shell has not set a session", async () => {
    useSession.getState().setSession(null);
    await renderPanel();
    expect(screen.getByText(CASE_ID)).toBeInTheDocument();
    expect(useCaseEvents.getState().version).toBeGreaterThanOrEqual(0);
  });
});

describe("describe helpers", () => {
  it("counts evidence", () => {
    expect(evidenceCount({ flow_ids: [1], frame_nos: [5], truncated: false, total: 1 })).toBe("1 frame");
    expect(evidenceCount({ flow_ids: [1], frame_nos: [5, 6], truncated: true, total: 300 })).toBe("300 frames");
    expect(evidenceCount({ flow_ids: [1, 2], frame_nos: [], truncated: false, total: 2 })).toBe("2 flows");
  });
  it("describes pins", () => {
    expect(describePin({ kind: "frame", frame_no: 3 }, [])).toBe("Frame 3");
    expect(describePin({ kind: "query", filter: "", view: "dns", time_range: null }, [])).toBe(
      "Query on dns: (no filter)",
    );
    expect(describePin({ kind: "ioc", ioc_id: "zz" }, [])).toBe("Indicator zz");
    expect(describePin({ kind: "finding", finding_id: "f1" }, [])).toBe("Finding f1");
    const f = { finding_id: "f1", title: "Beaconing to x\u202E", entity: "10.0.0.5" } as unknown as Finding;
    expect(describePin({ kind: "finding", finding_id: "f1" }, [], [f])).toBe(
      "Finding: Beaconing to x\\u{202e} (10.0.0.5)",
    );
  });
});
