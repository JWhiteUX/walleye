import { describe, expect, it } from "vitest";
import type { DecodeNode } from "../shared/bindings/DecodeNode";
import {
  ancestorIds,
  asciiChar,
  clampRange,
  deepestNodeAt,
  effectiveRange,
  flattenTree,
  parseHex,
  truncationNote,
} from "./hex";

const n = (label: string, range: [number, number] | null, children: DecodeNode[] = []): DecodeNode => ({
  label,
  field: null,
  value: null,
  range: range ? { start: range[0], len: range[1] } : null,
  warning: null,
  children,
});

// frame(0..60) > eth(0..14){dst 0..6, src 6..12, type 12..14} ip(14..34){ttl 22..23, info(no range)}
const tree: DecodeNode[] = [
  n("Frame", [0, 60], [n("Frame number", null)]),
  n("Ethernet", [0, 14], [n("Destination", [0, 6]), n("Source", [6, 6]), n("Type", [12, 2])]),
  n("IPv4", [14, 20], [n("TTL", [22, 1]), n("Note", null)]),
];

describe("parseHex", () => {
  it("parses pairs", () => {
    expect([...parseHex("00ff7f41")]).toEqual([0, 255, 127, 65]);
  });
  it("stops at the first invalid pair and ignores an odd tail", () => {
    expect([...parseHex("0102zz03")]).toEqual([1, 2]);
    expect([...parseHex("abc")]).toEqual([0xab]);
    expect(parseHex("").length).toBe(0);
  });
});

describe("asciiChar", () => {
  it("shows printable ASCII only", () => {
    expect(asciiChar(0x41)).toBe("A");
    expect(asciiChar(0x0a)).toBe(".");
    expect(asciiChar(0x7f)).toBe(".");
    expect(asciiChar(0xe9)).toBe(".");
  });
});

describe("tree -> bytes", () => {
  const flat = flattenTree(tree, 60);
  const byId = new Map(flat.map((f) => [f.id, f]));

  it("assigns path ids depth-first", () => {
    expect(flat.map((f) => f.id)).toEqual(["0", "0.0", "1", "1.0", "1.1", "1.2", "2", "2.0", "2.1"]);
    expect(byId.get("1.2")!.node.label).toBe("Type");
  });

  it("maps a node to its byte range, inheriting from the parent when it has none", () => {
    expect(effectiveRange(byId, "1.1")).toEqual({ start: 6, len: 6 });
    expect(effectiveRange(byId, "2.1")).toEqual({ start: 14, len: 20 });
    expect(effectiveRange(byId, null)).toBeNull();
  });

  it("clamps ranges to the frame bytes", () => {
    expect(clampRange({ start: 50, len: 100 }, 60)).toEqual({ start: 50, len: 10 });
    expect(clampRange({ start: 70, len: 4 }, 60)).toBeNull();
    expect(clampRange({ start: -3, len: 5 }, 60)).toEqual({ start: 0, len: 2 });
    expect(clampRange({ start: Number.NaN, len: 1 }, 60)).toBeNull();
  });
});

describe("bytes -> tree", () => {
  const flat = flattenTree(tree, 60);

  it("picks the deepest node containing the byte", () => {
    expect(deepestNodeAt(flat, 3)!.id).toBe("1.0");
    expect(deepestNodeAt(flat, 13)!.id).toBe("1.2");
    expect(deepestNodeAt(flat, 22)!.id).toBe("2.0");
    expect(deepestNodeAt(flat, 20)!.id).toBe("2");
  });

  it("falls back to the frame node, or null outside any range", () => {
    expect(deepestNodeAt(flat, 40)!.id).toBe("0");
    expect(deepestNodeAt(flat, 60)).toBeNull();
  });

  it("prefers the narrowest node at equal depth", () => {
    const t = [n("A", [0, 10]), n("B", [2, 2])];
    expect(deepestNodeAt(flattenTree(t, 10), 2)!.id).toBe("1");
  });

  it("lists ancestors so the tree can expand to the node", () => {
    expect(ancestorIds("2.0.1")).toEqual(["2", "2.0"]);
    expect(ancestorIds("0")).toEqual([]);
  });
});

describe("hostile trees", () => {
  it("caps depth", () => {
    let deep: DecodeNode = n("leaf", [0, 1]);
    for (let i = 0; i < 100; i++) deep = n(`l${i}`, [0, 1], [deep]);
    expect(flattenTree([deep], 1).length).toBe(33);
  });
});

describe("truncationNote", () => {
  it("reports snaplen truncation and missing bytes", () => {
    expect(truncationNote(64, 1514, 64)).toMatch(/64 of 1514/);
    expect(truncationNote(64, 64, 20)).toMatch(/20 of 64/);
    expect(truncationNote(64, 64, 64)).toBeNull();
  });
});
