import { describe, expect, it } from "vitest";
import { visible } from "./format";

describe("visible", () => {
  it("escapes bidi, zero-width and control characters", () => {
    expect(visible("evil\u202Egnp.exe")).toBe("evil\\u{202e}gnp.exe");
    expect(visible("a\u200Bb\u0000c\uFEFF")).toBe("a\\u{200b}b\\u{0}c\\u{feff}");
    expect(visible("example.com")).toBe("example.com");
    expect(visible("bücher.de")).toBe("bücher.de");
  });
});
