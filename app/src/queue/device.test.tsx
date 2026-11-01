import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, onTestFinished, vi } from "vitest";
import type { Finding } from "../shared/bindings/Finding";
import { api } from "../shared/ipc";
import { resetMock } from "../shared/mock";
import { useSelection } from "../shared/selection";
import { useSession } from "../shared/session";
import { ssidContext } from "./format";
import { QueuePanel } from "./QueuePanel";

const reason = (explanation: string) => ({
  rule_id: "r",
  signal: "s",
  value: 1,
  unit: null,
  weight: 1,
  explanation,
  attack_technique: null,
  evidence: { flow_ids: [], frame_nos: [1], truncated: false, total: 1 },
});

describe("ssidContext", () => {
  it("takes the first quoted SSID from a device finding's explanations", () => {
    const f = { entity_type: "device", reasons: [reason("no ssid here"), reason('SSID "Corner-Cafe" is open on ch 11')] } as Pick<Finding, "entity_type" | "reasons">;
    expect(ssidContext(f)).toBe("Corner-Cafe");
    expect(ssidContext({ ...f, entity_type: "host" })).toBeNull();
    expect(ssidContext({ entity_type: "device", reasons: [reason("none")] })).toBeNull();
  });

  it("honours backslash-escaped quotes, so an SSID can't end the quote early", () => {
    const f = { entity_type: "device", reasons: [reason('SSID "Evil\\" is open; trusted \\"Bank" from 02:…')] };
    expect(ssidContext(f)).toBe('Evil" is open; trusted "Bank');
  });

  it("a long escaped SSID with a quoted name inside can't make the box show that name", () => {
    // 14 control bytes (stored escaped) then "Corp" with quotes, as quote_ssid writes it.
    const stored = "\\u{1}".repeat(14) + '"Corp"';
    const expl = `02:5e:00:53:e7:01 advertises ${'"' + stored.replace(/"/g, '\\"') + '"'} as open on 11`;
    const f = { entity_type: "device", reasons: [reason(expl)] };
    expect(ssidContext(f)).toBe(stored);
    expect(ssidContext(f)).not.toBe("Corp");
  });

  it("shows nothing when the first quoted SSID does not parse", () => {
    expect(ssidContext({ entity_type: "device", reasons: [reason('x advertises "never closed')] })).toBeNull();
    expect(ssidContext({ entity_type: "device", reasons: [reason('x advertises "' + "y".repeat(300) + '" then "Corp"')] })).toBeNull();
  });

  it("renders the SSID in its own element, with quotes and invisibles as text", async () => {
    resetMock({ open: true, dataset: "wifi" });
    onTestFinished(cleanup);
    const [finding] = await api.findings();
    const evil: Finding = {
      ...finding!,
      reasons: [{ ...finding!.reasons[0]!, explanation: 'SSID "Cafe\\" verified\u{E0041}" spoof' }],
    };
    const spy = vi.spyOn(api, "findings").mockResolvedValue([evil]);
    render(<QueuePanel />);
    const chip = await screen.findByTestId("queue-ssid");
    expect(chip.textContent).toBe('Cafe" verified\\u{e0041}');
    expect(chip.children).toHaveLength(0);
    spy.mockRestore();
  });
});

describe("QueuePanel with device (802.11) findings", () => {
  beforeEach(() => {
    resetMock({ open: true, dataset: "wifi" });
    useSelection.getState().reset();
    useSession.getState().setSession(null);
  });
  afterEach(cleanup);

  it("shows the MAC with its randomized marker, ATT&CK id and SSID context", async () => {
    render(<QueuePanel />);
    const list = await screen.findByRole("list", { name: /findings/i });
    const items = within(list).getAllByRole("listitem").filter((li) => li.hasAttribute("data-finding-id"));
    expect(items).toHaveLength(3);
    expect(items[0]).toHaveTextContent("Deauthentication flood");
    expect(items[0]).toHaveTextContent("d6:5e:00:53:de:ad (rand)");
    expect(items[0]).toHaveTextContent("T1498");
    expect(within(items[1]!).getByTestId("queue-ssid")).toHaveTextContent(/^Corner-Cafe$/);
    expect(items[1]).toHaveTextContent("T1557");
    expect(list.querySelectorAll("a")).toHaveLength(0);
  });

  it("Show evidence focuses the device and opens the first evidence frame", async () => {
    const user = userEvent.setup();
    selectSomeHost();
    render(<QueuePanel />);
    const list = await screen.findByRole("list", { name: /findings/i });
    const head = within(list).getAllByRole("button").find((b) => b.hasAttribute("aria-expanded"))!;
    await user.click(head);
    const [f] = await api.findings();
    await user.click(within(list).getAllByTestId("queue-evidence")[0]!);
    const s = useSelection.getState();
    expect(s.device).toBe(f!.entity);
    expect(s.flow_ids).toEqual([]);
    expect(s.frame_no).toBe(f!.reasons[0]!.evidence.frame_nos[0]);
    // Device findings never touch the host selection.
    expect(s.hosts).toEqual(["10.0.0.99"]);
    expect(screen.getByTestId("queue-status")).toHaveTextContent(`for ${f!.entity}`);
  });
});

/** A pre-existing host selection, to prove device evidence leaves it alone. */
function selectSomeHost() {
  useSelection.getState().setHosts(["10.0.0.99"]);
}
