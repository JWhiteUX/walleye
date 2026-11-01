import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { WifiApRow } from "../shared/bindings/WifiApRow";
import type { WifiClientRow } from "../shared/bindings/WifiClientRow";
import type { WifiRow } from "../shared/bindings/WifiRow";
import { useCommands } from "../shared/commands";
import { api } from "../shared/ipc";
import { resetCaptureKinds } from "../shared/captureKind";
import { resetMock } from "../shared/mock";
import { useSelection } from "../shared/selection";
import { useSession } from "../shared/session";
import { COLUMNS, LIST_CELL_MAX, listCell, wifiRowTarget } from "./columns";
import { composePredicate } from "./predicates";
import { asTableView, useTableStore, visibleViews, WIFI_VIEWS, WIRED_VIEWS } from "./store";
import { SessionTable } from ".";

const cell = (view: keyof typeof COLUMNS, id: string, row: object) => {
  const c = COLUMNS[view].find((x) => x.id === id)!;
  return { text: c.text(row as Record<string, unknown>), placeholder: c.placeholder?.(row as Record<string, unknown>) ?? false };
};

const AP: WifiApRow = {
  bssid: "02:5e:00:53:e7:01",
  ssid: "Corner‮Cafe",
  channel: 11,
  security: "open",
  first_ts: 1_773_306_000_000_000,
  last_ts: 1_773_306_060_000_000,
  beacons: 360,
  frames: 417,
  clients: 1,
  signal_max: -41,
  randomized: true,
  first_frame: 1234,
};

describe("Wi-Fi columns", () => {
  it("marks randomized MACs in text, keeps universal ones bare", () => {
    expect(cell("wifi_aps", "bssid", AP).text).toBe("02:5e:00:53:e7:01 (rand)");
    expect(cell("wifi_aps", "bssid", { ...AP, bssid: "00:00:5e:00:53:10" }).text).toBe("00:00:5e:00:53:10");
    expect(cell("wifi", "dst", { dst: "ff:ff:ff:ff:ff:ff" }).text).toBe("ff:ff:ff:ff:ff:ff (broadcast)");
    for (const v of ["wifi_aps", "wifi_clients", "wifi"] as const)
      for (const c of COLUMNS[v].filter((x) => /bssid|mac|tx|dst/.test(x.id))) expect(c.mono).toBe(true);
  });

  it("shows SSIDs through visible() and hidden SSIDs as a styled placeholder", () => {
    expect(cell("wifi_aps", "ssid", AP)).toEqual({ text: "Corner\\u{202e}Cafe", placeholder: false });
    expect(cell("wifi_aps", "ssid", { ...AP, ssid: null })).toEqual({ text: "(hidden)", placeholder: true });
    // A network literally named "(hidden)" is text, not the placeholder.
    expect(cell("wifi_aps", "ssid", { ...AP, ssid: "(hidden)" })).toEqual({ text: "(hidden)", placeholder: false });
    expect(cell("wifi", "ssid", { kind: "beacon", ssid: "" })).toEqual({ text: "(hidden)", placeholder: true });
    expect(cell("wifi", "ssid", { kind: "probe_req", ssid: "" })).toEqual({ text: "(wildcard)", placeholder: true });
    expect(cell("wifi", "ssid", { kind: "data", ssid: null }).text).toBe("");
  });

  it("renders security, channel, signal, counts and times", () => {
    expect(cell("wifi_aps", "security", AP).text).toBe("open");
    expect(cell("wifi_aps", "channel", AP).text).toBe("11");
    expect(cell("wifi_aps", "signal_max", AP).text).toBe("-41 dBm");
    expect(cell("wifi_aps", "beacons", AP).text).toBe("360");
    expect(cell("wifi_aps", "first_ts", AP).text).toMatch(/^2026-03-12 /);
    const cl: Partial<WifiClientRow> = { mac: "4a:5e:00:53:21:9c", probed_ssids: ["Airport_Free", "Hotel-Lobby"], bssids: ["00:00:5e:00:53:01"] };
    expect(cell("wifi_clients", "probed_ssids", cl).text).toBe('"Airport_Free", "Hotel-Lobby"');
    expect(cell("wifi_clients", "bssids", cl).text).toBe("00:00:5e:00:53:01");
    expect(cell("wifi", "kind", { kind: "probe_req" }).text).toBe("Probe request");
    expect(cell("wifi", "protected", { protected: true }).text).toBe("yes");
  });

  it("caps list cells (probed SSIDs, access points) so a hostile row can't build a huge cell", () => {
    const ssids = Array.from({ length: 64 }, (_, i) => `net-${i}`);
    const t = cell("wifi_clients", "probed_ssids", { probed_ssids: ssids }).text;
    expect(t).toBe(`${ssids.slice(0, LIST_CELL_MAX).map((s) => `"${s}"`).join(", ")} … 56 more`);
    const aps = Array.from({ length: 20 }, (_, i) => `02:00:5e:00:53:${i.toString(16).padStart(2, "0")}`);
    const a = cell("wifi_clients", "bssids", { bssids: aps }).text;
    expect(a.endsWith(" … 12 more")).toBe(true);
    expect(a.split(", ")).toHaveLength(LIST_CELL_MAX);
    // Long items are clipped too; non-arrays render empty.
    expect(listCell(["x".repeat(500)], (s) => s)).toBe(`${"x".repeat(64)}…`);
    expect(listCell("nope", (s) => s)).toBe("");
  });

  it("quotes probed SSIDs with escapes, so a quote or comma inside one can't forge another", () => {
    // Stored SSIDs already escape `\` (as \u{5c}); only `"` is escaped here, like quote_ssid.
    const t = cell("wifi_clients", "probed_ssids", { probed_ssids: ['a", "Bank', "b\\u{5c}c", "Corp\u{E0041}"] }).text;
    expect(t).toBe('"a\\", \\"Bank", "b\\u{5c}c", "Corp\\u{e0041}"');
  });

  it("every Wi-Fi column filter names a field of its own view", async () => {
    const { FILTER_FIELDS } = await import("../shared/filterFields");
    const table = { wifi_aps: "wifi_aps", wifi_clients: "wifi_clients", wifi: "wifi" } as const;
    for (const v of WIFI_VIEWS) {
      for (const c of COLUMNS[v].filter((x) => x.field)) {
        const f = FILTER_FIELDS.find((x) => x.name === c.field);
        expect(f, `${v}.${c.id} -> ${c.field}`).toBeDefined();
        expect(f!.table).toBe(table[v as keyof typeof table]);
      }
    }
  });

  it("row targets: AP and client focus the device and their first frame; frames focus tx", () => {
    expect(wifiRowTarget("wifi_aps", AP)).toEqual({ device: AP.bssid, frame: 1234 });
    expect(wifiRowTarget("wifi_clients", { mac: "4a:5e:00:53:21:9c", first_frame: 7 } as WifiClientRow)).toEqual({
      device: "4a:5e:00:53:21:9c",
      frame: 7,
    });
    expect(wifiRowTarget("wifi", { frame_no: 42, tx: "00:00:5e:00:53:01", src: "x" } as unknown as WifiRow)).toEqual({
      device: "00:00:5e:00:53:01",
      frame: 42,
    });
    expect(wifiRowTarget("flows", AP)).toBeNull();
  });

  it("composes MAC column filters", () => {
    expect(composePredicate("ap.bssid", "mac", "02:5E:00:53:E7:01")).toEqual({ ok: true, text: "ap.bssid == 02:5e:00:53:e7:01" });
    expect(composePredicate("wifi.tx", "mac", "!=00:00:5e:00:53:01")).toEqual({ ok: true, text: "wifi.tx != 00:00:5e:00:53:01" });
    expect(composePredicate("wifi.tx", "mac", "02:5e:*")).toEqual({ ok: true, text: 'wifi.tx ~ "02:5e:*"' });
    expect(composePredicate("wifi.tx", "mac", "not a mac").ok).toBe(false);
  });
});

describe("view tabs", () => {
  it("wired captures show the IP views; 802.11 ones the Wi-Fi views (plus IP views only with flows)", () => {
    expect(visibleViews(false, true)).toEqual(WIRED_VIEWS);
    expect(visibleViews(true, false)).toEqual(["wifi_aps", "wifi_clients", "wifi"]);
    expect(visibleViews(true, true)).toEqual([...WIFI_VIEWS, ...WIRED_VIEWS]);
    expect(asTableView("frames")).toBe("flows");
    expect(asTableView("wifi_aps")).toBe("wifi_aps");
  });
});

// jsdom has no layout: give elements a size so the virtualized grid renders rows.
const sizes = { clientHeight: 600, clientWidth: 1200 } as const;
const saved: Partial<Record<keyof typeof sizes, PropertyDescriptor | undefined>> = {};
beforeAll(() => {
  for (const k of Object.keys(sizes) as (keyof typeof sizes)[]) {
    saved[k] = Object.getOwnPropertyDescriptor(Element.prototype, k);
    Object.defineProperty(Element.prototype, k, { configurable: true, get: () => sizes[k] });
  }
});
afterAll(() => {
  for (const k of Object.keys(sizes) as (keyof typeof sizes)[]) {
    const d = saved[k];
    if (d) Object.defineProperty(Element.prototype, k, d);
  }
});

describe("SessionTable on an 802.11 capture", () => {
  beforeEach(async () => {
    resetMock({ open: true, dataset: "wifi" });
    resetCaptureKinds();
    useSelection.getState().reset();
    useTableStore.setState({ view: "flows" });
    useSession.getState().setSession(await api.currentCapture());
  });
  afterEach(() => {
    cleanup();
    useSession.getState().setSession(null);
  });

  it("switches to the Access points tab and hides the empty IP tabs", async () => {
    render(<SessionTable />);
    const group = screen.getByRole("group", { name: "View" });
    await waitFor(() => expect(within(group).getByRole("button", { name: "Access points" })).toHaveAttribute("aria-pressed", "true"));
    expect(within(group).getAllByRole("button").map((b) => b.textContent)).toEqual(["Access points", "Clients", "Wi-Fi frames"]);
    await waitFor(() => expect(screen.getByTestId("table-count")).toHaveTextContent("8 of 8 rows"));
    expect(screen.queryByRole("button", { name: "Pin flow" })).toBeNull();
    const cmds = useCommands.getState().commands;
    expect(cmds["table.view-wifi-aps"]?.shortcut).toBe("v a");
    expect(cmds["table.view-wifi-clients"]?.shortcut).toBe("v c");
    expect(cmds["table.view-wifi"]?.shortcut).toBe("v w");
    expect(cmds["table.view-dns"]?.enabled?.()).toBe(false);
    expect(cmds["table.view-wifi"]?.enabled?.()).toBe(true);
  });

  it("AP row click focuses the device and selects its first frame; a frame row selects that frame", async () => {
    render(<SessionTable />);
    const grid = await screen.findByTestId("table-grid");
    const row = await waitFor(() => within(grid).getByText("d6:5e:00:53:de:ad (rand)").closest("[role=row]")!);
    act(() => useSelection.getState().selectFlows([3]));
    fireEvent.click(row);
    const s = useSelection.getState();
    expect(s.device).toBe("d6:5e:00:53:de:ad");
    expect(s.flow_ids).toEqual([]);
    const ap = (await api.query({ filter: "mac d6:5e:00:53:de:ad", view: "wifi_aps", limit: 1 })).data.rows[0] as WifiApRow;
    expect(s.frame_no).toBe(ap.first_frame);
    expect(row).toHaveAttribute("aria-selected", "true");

    act(() => useTableStore.getState().setView("wifi"));
    await waitFor(() => expect(screen.getByTestId("table-count")).toHaveTextContent(/of [\d,]+ rows/));
    const first = await waitFor(() => within(screen.getByTestId("table-grid")).getAllByRole("row")[1]!);
    fireEvent.click(first);
    const w = (await api.query({ filter: "", view: "wifi", limit: 1 })).data.rows[0] as WifiRow;
    expect(useSelection.getState().frame_no).toBe(w.frame_no);
    expect(useSelection.getState().device).toBe(w.tx);
  });

  it("decides 802.11 from data: a pcapng whose first interface is Ethernet still gets the Wi-Fi tabs", async () => {
    const s = useSession.getState().session!;
    act(() => useSession.getState().setSession({ ...s, capture: { ...s.capture, capture_id: "mixed-0001", link_type: 1 } }));
    render(<SessionTable />);
    const group = screen.getByRole("group", { name: "View" });
    await waitFor(() =>
      expect(within(group).getAllByRole("button").map((b) => b.textContent)).toEqual(["Access points", "Clients", "Wi-Fi frames"]),
    );
    expect(useCommands.getState().commands["table.view-wifi-aps"]?.enabled?.()).toBe(true);
  });

  it("does not send hosts on Wi-Fi views", async () => {
    const spy = vi.spyOn(api, "query");
    act(() => useSelection.getState().setHosts(["10.0.0.23"]));
    render(<SessionTable />);
    await waitFor(() => expect(screen.getByTestId("table-count")).toHaveTextContent("8 of 8 rows"));
    const wifiCalls = spy.mock.calls.filter(([r]) => r.view === "wifi_aps");
    expect(wifiCalls.length).toBeGreaterThan(0);
    for (const [r] of wifiCalls) expect(r.hosts).toEqual([]);
    spy.mockRestore();
  });
});
