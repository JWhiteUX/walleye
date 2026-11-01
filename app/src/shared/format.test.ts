import { describe, expect, it } from "vitest";
import { visible } from "./format";

describe("visible", () => {
  it("escapes bidi, zero-width and control characters", () => {
    expect(visible("evil\u202Egnp.exe")).toBe("evil\\u{202e}gnp.exe");
    expect(visible("a\u200Bb\u0000c\uFEFF")).toBe("a\\u{200b}b\\u{0}c\\u{feff}");
    expect(visible("example.com")).toBe("example.com");
    expect(visible("bücher.de")).toBe("bücher.de");
  });

  it("escapes astral and blank-rendering code points by code point", () => {
    // Tag character: the SSID must not render identical to "CorpNet".
    expect(visible("CorpNet\u{E0041}")).toBe("CorpNet\\u{e0041}");
    expect(visible("a\u{E0001}\u{E0000}\u{E007F}b")).toBe("a\\u{e0001}\\u{e0000}\\u{e007f}b");
    // Hangul fillers, CGJ, variation selectors, Mongolian FVS.
    expect(visible("ᅟᅠㅤﾠ")).toBe("\\u{115f}\\u{1160}\\u{3164}\\u{ffa0}");
    expect(visible("e͏x")).toBe("e\\u{34f}x");
    expect(visible("x︀️\u{E0100}\u{E01EF}")).toBe("x\\u{fe00}\\u{fe0f}\\u{e0100}\\u{e01ef}");
    expect(visible("᠋᠌᠍᠎")).toBe("\\u{180b}\\u{180c}\\u{180d}\\u{180e}");
    // Other Cf/Zl/Zp: Arabic number sign, line/paragraph separators, U+2065 (unassigned, in the range).
    expect(visible("؀  ⁥")).toBe("\\u{600}\\u{2028}\\u{2029}\\u{2065}");
  });

  it("leaves visible astral characters and emoji alone", () => {
    expect(visible("café 🙂 𝔸")).toBe("café 🙂 𝔸");
  });
});

describe("visible() matches the Rust set (walleye_core::text)", () => {
  it("escapes the Braille blank and U+2065", () => {
    expect(visible("a⠀b⁥c")).toBe("a\\u{2800}b\\u{2065}c");
  });
});
