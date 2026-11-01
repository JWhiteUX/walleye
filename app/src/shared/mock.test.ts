import { beforeEach, describe, expect, it } from "vitest";
import { api, WalleyeError } from "./ipc";
import { resetMock } from "./mock";

describe("browser mock backend", () => {
  beforeEach(() => resetMock({ open: true }));

  it("pages flows for a host", async () => {
    const p = await api.query({ filter: "host 10.0.0.23", view: "flows", limit: 5 });
    expect(p.data.view).toBe("flows");
    expect(p.data.rows).toHaveLength(5);
    expect(p.next_cursor).toBe("5");
  });

  it("returns filter errors with a span", async () => {
    const e = await api.query({ filter: '(dns.query ~ "x"', view: "dns", limit: 5 }).catch((x) => x);
    expect(e).toBeInstanceOf(WalleyeError);
    expect(e.code).toBe("invalid_filter");
    expect(e.span).toEqual({ start: 0, end: 1 });
  });

  it("ranks findings and serves evidence packets", async () => {
    const f = await api.findings();
    expect(f[0]!.entity).toBe("10.0.0.23");
    const frame = f[0]!.reasons[0]!.evidence.frame_nos[0]!;
    const p = await api.packet(frame);
    expect(p.bytes_hex.length).toBe(p.caplen * 2);
  });

  it("requires an open capture", async () => {
    resetMock();
    await expect(api.findings()).rejects.toMatchObject({ code: "no_capture" });
  });
});
