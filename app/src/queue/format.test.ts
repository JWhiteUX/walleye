import { describe, expect, it } from "vitest";
import { barPct, evidenceLabel, formatValue, verdictLabel } from "./format";

describe("formatValue", () => {
  it("formats by unit", () => {
    expect(formatValue(59.8, "s")).toBe("59.8 s");
    expect(formatValue(0.0138, "ratio")).toBe("0.014 (1.4%)");
    expect(formatValue(1, "bool")).toBe("yes");
    expect(formatValue(0, "bool")).toBe("no");
    expect(formatValue(1200, "count")).toBe("1,200");
    expect(formatValue(3.91, "bits")).toBe("3.91 bits");
    expect(formatValue(54.8, "min")).toBe("54.8 min");
    expect(formatValue(7, null)).toBe("7");
  });
});

describe("evidenceLabel", () => {
  it("counts flows and frames", () => {
    expect(evidenceLabel({ flow_ids: [1, 2], frame_nos: [5], truncated: false, total: 2 })).toBe("2 flows · 1 frame");
    expect(evidenceLabel({ flow_ids: [], frame_nos: [9], truncated: false, total: 1 })).toBe("1 frame");
  });
  it("reports the real total when capped", () => {
    const e = { flow_ids: Array.from({ length: 200 }, (_, i) => i), frame_nos: [], truncated: true, total: 1234 };
    expect(evidenceLabel(e)).toBe("200 flows (first 200 of 1,234)");
  });
});

describe("misc", () => {
  it("verdict labels and bar clamping", () => {
    expect(verdictLabel("needs_review")).toBe("Needs review");
    expect(verdictLabel(null)).toBe("No verdict");
    expect(barPct(140)).toBe(100);
    expect(barPct(-3)).toBe(0);
    expect(barPct(NaN)).toBe(0);
  });
});
