import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { pinEvidence } from "../shared/caseEvents";
import { api } from "../shared/ipc";
import { resetMock } from "../shared/mock";
import { useSelection } from "../shared/selection";
import { useSession } from "../shared/session";
import { SidePanel, type SideTab } from "./SidePanel";

/** SidePanel with its tab held in local state, as AppShell holds it in the layout. */
function Harness({ initial = "findings" }: { initial?: SideTab }) {
  const [tab, setTab] = useState<SideTab>(initial);
  return <SidePanel tab={tab} onTab={setTab} />;
}

const tab = (name: "Findings" | "Case") => screen.getByRole("tab", { name: new RegExp(`^${name}`) });
const pane = (p: "queue" | "case") => document.querySelector<HTMLElement>(`[role="tabpanel"][data-pane="${p}"]`)!;

beforeEach(async () => {
  resetMock({ open: true });
  useSelection.getState().reset();
  useSession.getState().setSession(await api.currentCapture());
});
afterEach(() => {
  cleanup();
  useSession.getState().setSession(null);
});

describe("SidePanel", () => {
  it("renders both panels, with only the active tab's panel shown", async () => {
    render(<Harness />);
    expect(screen.getByRole("tablist", { name: "Side panel" })).toBeInTheDocument();
    expect(tab("Findings")).toHaveAttribute("aria-selected", "true");
    expect(tab("Case")).toHaveAttribute("aria-selected", "false");
    expect(pane("queue")).not.toHaveAttribute("hidden");
    expect(pane("case")).toHaveAttribute("hidden");
    expect(screen.getByTestId("queue-panel")).toBeInTheDocument();
    expect(screen.getByTestId("case-panel")).toBeInTheDocument();
  });

  it("switches tabs on click", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByTestId("side-tab-case"));
    expect(tab("Case")).toHaveAttribute("aria-selected", "true");
    expect(tab("Findings")).toHaveAttribute("aria-selected", "false");
    expect(pane("case")).not.toHaveAttribute("hidden");
    expect(pane("queue")).toHaveAttribute("hidden");
    await user.click(screen.getByTestId("side-tab-findings"));
    expect(tab("Findings")).toHaveAttribute("aria-selected", "true");
    expect(pane("queue")).not.toHaveAttribute("hidden");
    expect(pane("case")).toHaveAttribute("hidden");
  });

  it("moves between tabs with Left/Right/Home/End and keeps focus on the selected tab", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    tab("Findings").focus();
    expect(tab("Findings")).toHaveAttribute("tabindex", "0");
    expect(tab("Case")).toHaveAttribute("tabindex", "-1");
    await user.keyboard("{ArrowRight}");
    expect(tab("Case")).toHaveAttribute("aria-selected", "true");
    expect(tab("Case")).toHaveFocus();
    expect(pane("case")).not.toHaveAttribute("hidden");
    await user.keyboard("{ArrowLeft}");
    expect(tab("Findings")).toHaveAttribute("aria-selected", "true");
    expect(tab("Findings")).toHaveFocus();
    expect(pane("case")).toHaveAttribute("hidden");
    await user.keyboard("{End}");
    expect(tab("Case")).toHaveAttribute("aria-selected", "true");
    expect(tab("Case")).toHaveFocus();
    await user.keyboard("{Home}");
    expect(tab("Findings")).toHaveAttribute("aria-selected", "true");
    expect(tab("Findings")).toHaveFocus();
  });

  it("shows the case's pin count on the Case tab", async () => {
    const pins = (await api.getCase(useSession.getState().session!.case_id)).pins.length;
    render(<Harness />);
    const count = await screen.findByTestId("case-pin-count");
    expect(count).toHaveTextContent(String(pins));
    expect(count).not.toHaveClass("is-new");
  });

  it("marks the count new and announces a pin made while Findings is open; opening Case clears it", async () => {
    const user = userEvent.setup();
    const before = (await api.getCase(useSession.getState().session!.case_id)).pins.length;
    render(<Harness />);
    await waitFor(() => expect(screen.getByTestId("case-pin-count")).toHaveTextContent(String(before)));
    expect(screen.getByTestId("case-announce")).toHaveTextContent("");

    await act(async () => {
      await pinEvidence({ kind: "frame", frame_no: 140 }, "beacon");
    });
    const n = before + 1;
    await waitFor(() => expect(screen.getByTestId("case-pin-count")).toHaveTextContent(String(n)));
    expect(screen.getByTestId("case-pin-count")).toHaveClass("is-new");
    expect(screen.getByTestId("case-announce")).toHaveTextContent(`Added to case. ${n} ${n === 1 ? "pin" : "pins"}.`);

    await user.click(screen.getByTestId("side-tab-case"));
    expect(screen.getByTestId("case-pin-count")).not.toHaveClass("is-new");
    expect(screen.getByTestId("case-pin-count")).toHaveTextContent(String(n));
  });

  it("does not mark the count new for a pin made while Case is open", async () => {
    const before = (await api.getCase(useSession.getState().session!.case_id)).pins.length;
    render(<Harness initial="case" />);
    await waitFor(() => expect(screen.getByTestId("case-pin-count")).toHaveTextContent(String(before)));
    await act(async () => {
      await pinEvidence({ kind: "note" }, "a note");
    });
    await waitFor(() => expect(screen.getByTestId("case-pin-count")).toHaveTextContent(String(before + 1)));
    expect(screen.getByTestId("case-pin-count")).not.toHaveClass("is-new");
    expect(screen.getByTestId("case-announce")).toHaveTextContent(/Added to case\./);
  });
});
