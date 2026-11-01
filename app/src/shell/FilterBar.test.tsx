import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resetMock } from "../shared/mock";
import { useSelection } from "../shared/selection";
import { FilterBar } from "./FilterBar";
import { useFilterStatus } from "./filterStatus";

beforeEach(() => {
  resetMock({ open: true });
  useSelection.getState().reset();
  useFilterStatus.getState().report(null);
});
afterEach(cleanup);

const input = () => screen.getByRole("combobox", { name: "Filter expression" });

describe("FilterBar", () => {
  it("submits the typed text to the shared selection on Enter", async () => {
    const user = userEvent.setup();
    render(<FilterBar />);
    await user.click(input());
    await user.type(input(), "host 10.0.0.23");
    // Enter with no highlighted suggestion submits.
    await user.keyboard("{Enter}");
    expect(useSelection.getState().filter).toBe("host 10.0.0.23");
  });

  it("shows backend suggestions and applies the chosen one with arrow keys", async () => {
    const user = userEvent.setup();
    render(<FilterBar />);
    await user.click(input());
    await user.type(input(), "host 10.0.0.2 and dns.q");
    await waitFor(() => expect(screen.getByRole("listbox", { name: "Filter suggestions" })).toBeVisible());
    await waitFor(() => expect(screen.getAllByRole("option")[0]).toHaveTextContent("dns.query"));
    await user.keyboard("{ArrowDown}");
    expect(input()).toHaveAttribute("aria-activedescendant", screen.getAllByRole("option")[0]!.id);
    await user.keyboard("{Enter}");
    expect(input()).toHaveValue("host 10.0.0.2 and dns.query ");
    // Accepting a suggestion does not submit.
    expect(useSelection.getState().filter).toBe("");
  });

  it("Tab accepts the first suggestion", async () => {
    const user = userEvent.setup();
    render(<FilterBar />);
    await user.click(input());
    await user.type(input(), "src_p");
    await waitFor(() => expect(screen.getAllByRole("option")[0]).toHaveTextContent("src_port"));
    await user.keyboard("{Tab}");
    expect(input()).toHaveValue("src_port ");
  });

  it("never offers suggestions computed for older text", async () => {
    const user = userEvent.setup();
    render(<FilterBar />);
    await user.click(input());
    await waitFor(() => expect(screen.queryAllByRole("option").length).toBeGreaterThan(0));
    await user.type(input(), "x");
    // Immediately after typing, the previous (empty-text) list is hidden.
    expect(screen.queryAllByRole("option")).toHaveLength(0);
  });

  it("underlines the error span and describes the error", async () => {
    render(<FilterBar />);
    act(() => {
      useSelection.getState().setFilter('dns.query ~ "abc');
      useFilterStatus.getState().report({ filter: 'dns.query ~ "abc', message: "unterminated string", span: { start: 12, end: 16 } });
    });
    expect(screen.getByTestId("filter-error-underline")).toHaveTextContent('"abc');
    expect(input()).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByRole("alert")).toHaveTextContent("Column 13: unterminated string");
  });

  it("follows external filter changes and Escape reverts unapplied edits", async () => {
    const user = userEvent.setup();
    render(<FilterBar />);
    act(() => useSelection.getState().setFilter("src_ip == 10.0.0.5"));
    expect(input()).toHaveValue("src_ip == 10.0.0.5");
    await user.click(input());
    await user.type(input(), "zzz");
    await user.keyboard("{Escape}");
    if ((input() as HTMLInputElement).value !== "src_ip == 10.0.0.5") await user.keyboard("{Escape}");
    expect(input()).toHaveValue("src_ip == 10.0.0.5");
  });
});
