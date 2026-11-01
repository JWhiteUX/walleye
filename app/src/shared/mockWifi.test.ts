import { beforeEach, describe, expect, it } from "vitest";
import type { DecodeNode } from "./bindings/DecodeNode";
import type { WifiApRow } from "./bindings/WifiApRow";
import type { WifiClientRow } from "./bindings/WifiClientRow";
import type { WifiRow } from "./bindings/WifiRow";
import { api } from "./ipc";
import { datasetForPath, resetMock } from "./mock";
import { ATTACKERS, wifiDataset } from "./mockWifi";
import { isRandomizedMac } from "./wifi";

const walk = (ns: DecodeNode[], f: (n: DecodeNode) => void) =>
  ns.forEach((n) => {
    f(n);
    walk(n.children, f);
  });

describe("802.11 sample dataset", () => {
  const d = wifiDataset();

  it("is deterministic", () => {
    expect(d.wifi.length).toBeGreaterThan(5000);
    expect(d.wifi[0]!.frame_no).toBe(1);
    expect(d.capture.link_type).toBe(127);
    expect(d.capture.frame_count).toBe(d.wifi.length);
    // Same values every run (seeded generator); spot-check a stable aggregate.
    expect(d.wifi_aps.map((a) => a.bssid)).toContain(ATTACKERS.deauth);
  });

  it("has 8 APs (3-AP mesh, one hidden SSID) and 30 clients, half randomized", () => {
    expect(d.wifi_aps).toHaveLength(8);
    expect(d.wifi_aps.filter((a) => a.ssid === "Lakeside-Office" && !a.randomized)).toHaveLength(3);
    expect(d.wifi_aps.filter((a) => a.ssid === null)).toHaveLength(1);
    expect(d.wifi_clients).toHaveLength(30);
    expect(d.wifi_clients.filter((c) => c.randomized)).toHaveLength(15);
    for (const a of d.wifi_aps) expect(a.randomized).toBe(isRandomizedMac(a.bssid));
  });

  it("covers the frame kinds and keeps frames in time order", () => {
    const kinds = new Set(d.wifi.map((w) => w.kind));
    for (const k of ["beacon", "probe_req", "probe_resp", "auth", "assoc_req", "assoc_resp", "eapol", "data", "null", "deauth"])
      expect(kinds).toContain(k);
    for (let i = 1; i < d.wifi.length; i++) expect(d.wifi[i]!.ts).toBeGreaterThanOrEqual(d.wifi[i - 1]!.ts);
  });

  it("stages the three attacks with device findings (MAC entity, frame evidence only)", () => {
    expect(d.findings.map((f) => [f.detector, f.entity, f.attack_technique])).toEqual([
      ["wifi_deauth", ATTACKERS.deauth, "T1498"],
      ["wifi_evil_twin", ATTACKERS.twin, "T1557"],
      ["wifi_karma", ATTACKERS.karma, "T1557"],
    ]);
    for (const f of d.findings) {
      expect(f.entity_type).toBe("device");
      for (const r of f.reasons) {
        expect(r.evidence.flow_ids).toEqual([]);
        expect(r.evidence.frame_nos.length).toBeGreaterThan(0);
        expect(r.evidence.frame_nos.length).toBeLessThanOrEqual(200);
      }
    }
    const deauths = d.wifi.filter((w) => w.kind === "deauth" && w.tx === ATTACKERS.deauth);
    expect(deauths.length).toBeGreaterThanOrEqual(300);
    const karma = new Set(d.wifi.filter((w) => w.kind === "probe_resp" && w.tx === ATTACKERS.karma).map((w) => w.ssid));
    expect(karma.size).toBeGreaterThanOrEqual(10);
    const twin = d.wifi_aps.find((a) => a.bssid === ATTACKERS.twin)!;
    expect([twin.ssid, twin.security, twin.randomized]).toEqual(["Corner-Cafe", "open", true]);
  });

  it("uses documentation or locally administered addresses only", () => {
    const macs = new Set(d.wifi.flatMap((w) => [w.src, w.dst, w.tx, w.bssid]).filter((m): m is string => !!m));
    for (const m of macs) expect(m === "ff:ff:ff:ff:ff:ff" || m.startsWith("00:00:5e:00:53:") || isRandomizedMac(m)).toBe(true);
  });
});

describe("browser mock on the 802.11 sample", () => {
  beforeEach(() => resetMock({ open: true, dataset: "wifi" }));

  it("opens the 802.11 sample for wifi-looking paths", () => {
    expect(datasetForPath("/cases/lobby-wifi.pcapng")).toBe("wifi");
    expect(datasetForPath("/x/802.11-monitor.pcap")).toBe("wifi");
    expect(datasetForPath("/mock/office-beacon.pcap")).toBe("wired");
  });

  it("reports an 802.11 capture with no flows", async () => {
    const s = await api.currentCapture();
    expect(s?.capture.link_type).toBe(127);
    const flows = await api.query({ filter: "", view: "flows", limit: 10 });
    expect(flows.total).toBe(0);
  });

  it("serves the three views with paging", async () => {
    const aps = await api.query({ filter: "", view: "wifi_aps", limit: 100 });
    expect(aps.data.view).toBe("wifi_aps");
    expect(aps.total).toBe(8);
    const cl = await api.query({ filter: "", view: "wifi_clients", limit: 100 });
    expect(cl.total).toBe(30);
    const fr = await api.query({ filter: "", view: "wifi", limit: 500 });
    expect(fr.data.rows).toHaveLength(500);
    expect(fr.next_cursor).toBe("500");
  });

  it("filters with `mac X` and `wifi.kind == x`", async () => {
    const p = await api.query({ filter: `mac ${ATTACKERS.deauth} and wifi.kind == deauth`, view: "wifi", limit: 10_000 });
    const rows = p.data.rows as WifiRow[];
    expect(rows.length).toBeGreaterThanOrEqual(300);
    expect(rows.every((r) => r.kind === "deauth" && r.tx === ATTACKERS.deauth)).toBe(true);
    const aps = await api.query({ filter: `ap.security == open`, view: "wifi_aps", limit: 100 });
    expect((aps.data.rows as WifiApRow[]).map((a) => a.bssid).sort()).toEqual([ATTACKERS.twin, ATTACKERS.karma].sort());
    const cl = await api.query({ filter: `client.probed == "Hotel-Lobby"`, view: "wifi_clients", limit: 100 });
    expect((cl.data.rows as WifiClientRow[]).every((c) => c.probed_ssids.includes("Hotel-Lobby"))).toBe(true);
  });

  it("rejects a field of another 802.11 view with a span", async () => {
    const e = await api.query({ filter: "wifi.kind == beacon", view: "wifi_aps", limit: 10 }).catch((x) => x);
    expect(e.code).toBe("invalid_filter");
    expect(e.span).toEqual({ start: 0, end: 9 });
  });

  it("timeline: device lanes with wifi_* frame counts and finding scores", async () => {
    const l = await api.timeline({ filter: "", bucket_ms: 1000, max_lanes: 20 });
    expect(l.lane_kind).toBe("device");
    const flood = l.lanes.find((x) => x.host === ATTACKERS.deauth)!;
    expect(flood.max_score).toBe(95);
    const deauths = flood.buckets.reduce((a, b) => a + (b.wifi_deauth ?? 0), 0);
    expect(deauths).toBeGreaterThanOrEqual(300);
    expect(l.lanes.at(-1)!.is_other).toBe(true);
  });

  it("device_frames lists a MAC's frames and validates the MAC", async () => {
    const f = await api.deviceFrames(ATTACKERS.deauth);
    expect(f.length).toBeGreaterThan(300);
    expect(f[0]!.summary).toMatch(/^Beacon "Lakeside-Office" ch 6 wpa2$/);
    expect(f.some((x) => /^Deauth d6:5e:00:53:de:ad → ff:ff:ff:ff:ff:ff reason 7$/.test(x.summary))).toBe(true);
    const all = await api.deviceFrames(ATTACKERS.deauth, { start: f[0]!.ts, end: f[0]!.ts + 1 });
    expect(all).toHaveLength(1);
    await expect(api.deviceFrames("not-a-mac")).rejects.toMatchObject({ code: "invalid_argument" });
  });

  it("decodes 802.11 frames with in-bounds ranges and filter fields", async () => {
    const d = wifiDataset();
    const sample = ["beacon", "probe_req", "probe_resp", "auth", "assoc_req", "assoc_resp", "eapol", "data", "null", "deauth"].map(
      (k) => d.wifi.find((w) => w.kind === k)!,
    );
    for (const w of sample) {
      const p = await api.packet(w.frame_no);
      expect(p.link_type).toBe(127);
      expect(p.bytes_hex.length).toBe(p.caplen * 2);
      expect(p.decode_tree[0]!.label).toBe("Radiotap header");
      expect(p.decode_tree[1]!.label).toMatch(/^IEEE 802\.11 /);
      const fields = new Set<string>();
      walk(p.decode_tree, (n) => {
        if (n.field) fields.add(n.field);
        if (n.range) expect(n.range.start + n.range.len).toBeLessThanOrEqual(p.caplen);
      });
      expect(fields).toContain("wifi.bssid");
    }
  });

  it("autocompletes MACs after `mac` and kinds after `wifi.kind ==`", async () => {
    const m = await api.autocomplete("mac ", 4);
    expect(m[0]!.kind).toBe("value");
    expect(m[0]!.insert_text).toMatch(/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/);
    const k = await api.autocomplete("wifi.kind == de", 15);
    expect(k.map((s) => s.label)).toEqual(["deauth"]);
    const s = await api.autocomplete('ap.ssid == "Corn', 16);
    expect(s[0]!.insert_text).toBe("Corner-Cafe");
    const kw = await api.autocomplete("ma", 2);
    expect(kw.find((x) => x.label === "mac")?.detail).toMatch(/MAC/);
    const first = await api.autocomplete("", 0);
    expect(first[0]!.label).toMatch(/^wifi\./);
  });
});
