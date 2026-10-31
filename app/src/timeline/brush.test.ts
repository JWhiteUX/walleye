import { describe, expect, it } from "vitest";
import { cursorStep, inRange, keyBrush, normalizeBrush } from "./brush";

const EXT = { start: 0, end: 1_000_000 };
const VIEW = { start: 100_000, end: 300_000 };

describe("normalizeBrush", () => {
  it("orders endpoints and rounds outwards", () => {
    expect(normalizeBrush(500.6, 200.2, EXT)).toEqual({ start: 200, end: 501 });
  });
  it("clamps to the extent", () => {
    expect(normalizeBrush(-50, 2_000_000, EXT)).toEqual(EXT);
  });
  it("returns null for an empty brush", () => {
    expect(normalizeBrush(10, 10, EXT)).toBeNull();
    expect(normalizeBrush(-20, -10, EXT)).toBeNull();
  });
});

describe("inRange", () => {
  it("is half-open", () => {
    const r = { start: 10, end: 20 };
    expect(inRange(10, r)).toBe(true);
    expect(inRange(19, r)).toBe(true);
    expect(inRange(20, r)).toBe(false);
    expect(inRange(5, null)).toBe(false);
  });
});

describe("keyboard brushing", () => {
  it("first plain arrow places the cursor at the view centre", () => {
    const r = keyBrush({ cursor: null, anchor: null }, 1, false, 1000, VIEW, EXT);
    expect(r).toEqual({ cursor: 200_000, anchor: null });
    expect(r.brush).toBeUndefined();
  });
  it("plain arrows move by one step", () => {
    const r = keyBrush({ cursor: 200_000, anchor: null }, -1, false, 1000, VIEW, EXT);
    expect(r.cursor).toBe(199_000);
  });
  it("shift+arrows extend a brush from the anchor and keep extending", () => {
    let st = keyBrush({ cursor: 200_000, anchor: null }, 1, true, 1000, VIEW, EXT);
    expect(st.anchor).toBe(200_000);
    expect(st.brush).toEqual({ start: 200_000, end: 201_000 });
    st = keyBrush(st, 1, true, 1000, VIEW, EXT);
    expect(st.brush).toEqual({ start: 200_000, end: 202_000 });
    // Reversing past the anchor flips the brush.
    for (let i = 0; i < 4; i++) st = keyBrush(st, -1, true, 1000, VIEW, EXT);
    expect(st.brush).toEqual({ start: 198_000, end: 200_000 });
  });
  it("a plain arrow ends the extension", () => {
    const st = keyBrush({ cursor: 201_000, anchor: 200_000 }, 1, false, 1000, VIEW, EXT);
    expect(st.anchor).toBeNull();
  });
  it("cursor stays inside the extent", () => {
    const r = keyBrush({ cursor: 999_500, anchor: null }, 1, false, 1000, VIEW, EXT);
    expect(r.cursor).toBe(EXT.end);
  });
  it("step is at least 1/200 of the view", () => {
    expect(cursorStep(10, VIEW)).toBe(1000);
    expect(cursorStep(5000, VIEW)).toBe(5000);
  });
});
