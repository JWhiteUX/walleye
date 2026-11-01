import { describe, expect, it } from "vitest";
import { parseQuotedSsid, QUOTED_SSID_MAX, quoteSsid } from "./wifi";

describe("quoteSsid / parseQuotedSsid (same form as walleye_core::text::quote_ssid)", () => {
  it("escapes only the double quote", () => {
    expect(quoteSsid("Corner-Cafe")).toBe('"Corner-Cafe"');
    expect(quoteSsid('a"b')).toBe('"a\\"b"');
    // Stored SSIDs carry `\` as \u{5c}; it is not escaped again.
    expect(quoteSsid("x\\u{5c}y")).toBe('"x\\u{5c}y"');
  });

  it("round-trips, including quotes and escapes inside", () => {
    for (const s of ["", "Corp", 'a"b"', "\\u{5c}\\u{1}" + "\\u{0}".repeat(32), "é🙂"]) {
      const text = `prefix ${quoteSsid(s)} suffix`;
      expect(parseQuotedSsid(text, 7)).toEqual({ ssid: s, end: 7 + quoteSsid(s).length });
    }
  });

  it("returns null rather than guessing", () => {
    expect(parseQuotedSsid('no quote', 0)).toBeNull();
    expect(parseQuotedSsid('"never closed', 0)).toBeNull();
    expect(parseQuotedSsid('"ends with escaped quote\\"', 0)).toBeNull();
    expect(parseQuotedSsid(`"${"x".repeat(QUOTED_SSID_MAX + 1)}"`, 0)).toBeNull();
    // The longest stored SSID (32 bytes, each escaped as \u{xx}) still parses.
    const longest = "\\u{1f}".repeat(32);
    expect(longest.length).toBeLessThanOrEqual(QUOTED_SSID_MAX);
    expect(parseQuotedSsid(quoteSsid(longest), 0)?.ssid).toBe(longest);
  });
});
