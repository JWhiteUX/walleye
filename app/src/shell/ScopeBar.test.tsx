import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { useSelection } from "../shared/selection";
import { useTableStore } from "../table/store";
import { ScopeBar } from "./ScopeBar";

beforeEach(() => {
  useSelection.getState().reset();
  useTableStore.getState().setView("flows");
});
afterEach(cleanup);

describe("ScopeBar", () => {
  it("says 'Whole capture' and hides Clear all when nothing narrows the panes", () => {
    act(() => useSelection.getState().setFilter("dns"));
    render(<ScopeBar />);
    expect(screen.getByTestId("scope-empty")).toHaveTextContent("Whole capture");
    expect(screen.queryByTestId("scope-clear")).toBeNull();
  });

  it("shows one chip per scope part", () => {
    act(() => {
      const s = useSelection.getState();
      s.setTimeRange({ start: 1_000_000, end: 61_000_000 });
      s.setHosts(["10.0.0.23", "10.0.0.5"]);
      s.selectFlows([7, 9, 11]);
    });
    render(<ScopeBar />);
    expect(screen.getByTestId("scope-time")).toHaveTextContent("00:00:01.000–00:01:01.000");
    expect(screen.getAllByTestId("scope-host").map((c) => c.textContent)).toEqual(["Host10.0.0.23×", "Host10.0.0.5×"]);
    expect(screen.getByTestId("scope-flows")).toHaveTextContent("3 selected");
    expect(screen.getByTestId("scope-flows")).toHaveAttribute("title", expect.stringContaining("flow #7"));
  });

  it("removes a single part with its × and leaves the rest", async () => {
    const user = userEvent.setup();
    act(() => {
      const s = useSelection.getState();
      s.setTimeRange({ start: 1, end: 2 });
      s.setHosts(["10.0.0.23", "10.0.0.5"]);
    });
    render(<ScopeBar />);
    await user.click(screen.getByRole("button", { name: "Remove host 10.0.0.23" }));
    expect(useSelection.getState().hosts).toEqual(["10.0.0.5"]);
    await user.click(screen.getByRole("button", { name: "Remove time range" }));
    expect(useSelection.getState().time_range).toBeNull();
    expect(useSelection.getState().hosts).toEqual(["10.0.0.5"]);
  });

  it("Clear all clears the selection but keeps the filter", async () => {
    const user = userEvent.setup();
    act(() => {
      const s = useSelection.getState();
      s.setFilter("dns");
      s.setHosts(["10.0.0.23"]);
      s.selectDevice("02:00:5e:00:53:01");
    });
    render(<ScopeBar />);
    expect(screen.getByTestId("scope-device")).toHaveTextContent("02:00:5e:00:53:01");
    await user.click(screen.getByTestId("scope-clear"));
    const s = useSelection.getState();
    expect(s.hosts).toEqual([]);
    expect(s.device).toBeNull();
    expect(s.filter).toBe("dns");
    expect(screen.getByTestId("scope-empty")).toBeInTheDocument();
  });

  it("marks host chips as not applied on 802.11 views", () => {
    act(() => {
      useSelection.getState().setHosts(["10.0.0.23"]);
      useTableStore.getState().setView("wifi");
    });
    render(<ScopeBar />);
    const chip = screen.getByTestId("scope-host");
    expect(chip).toHaveClass("is-inactive");
    expect(chip).toHaveAttribute("title", expect.stringMatching(/^Not applied/));
  });
});
