import { describe, expect, it } from "vitest";
import type { Suggestion } from "../shared/bindings/Suggestion";
import { applySuggestion, byteToUtf16, splitAtSpan, utf16ToByte } from "./filterText";

const sug = (p: Partial<Suggestion>): Suggestion => ({
  label: "x",
  insert_text: "x",
  kind: "field",
  detail: null,
  replace_start: 0,
  replace_end: 0,
  ...p,
});

describe("offset conversion", () => {
  it("is identity for ASCII", () => {
    expect(utf16ToByte("host 10", 4)).toBe(4);
    expect(byteToUtf16("host 10", 4)).toBe(4);
  });

  it("handles multi-byte characters", () => {
    const t = 'dns.query ~ "é😀" and ';
    // é = 2 bytes, 😀 = 4 bytes (2 UTF-16 units)
    const idxAnd = t.indexOf("and");
    const bAnd = utf16ToByte(t, idxAnd);
    expect(bAnd).toBe(idxAnd + 1 + 2);
    expect(byteToUtf16(t, bAnd)).toBe(idxAnd);
  });

  it("clamps out-of-range offsets", () => {
    expect(byteToUtf16("abc", 99)).toBe(3);
    expect(byteToUtf16("abc", -5)).toBe(0);
    expect(utf16ToByte("abc", 99)).toBe(3);
  });
});

describe("applySuggestion", () => {
  it("replaces the partial word with the field and adds a space", () => {
    const r = applySuggestion("host 10.0.0.5 and dns.q", sug({ insert_text: "dns.query", replace_start: 18, replace_end: 23 }));
    expect(r.text).toBe("host 10.0.0.5 and dns.query ");
    expect(r.caret).toBe(r.text.length);
  });

  it("replaces in the middle and keeps the tail", () => {
    const text = "src_ip == 1 and bytes_up > 5";
    const r = applySuggestion(text, sug({ insert_text: "dst_ip", replace_start: 0, replace_end: 6 }));
    expect(r.text).toBe("dst_ip == 1 and bytes_up > 5");
    expect(r.caret).toBe(6);
  });

  it("uses byte offsets after multi-byte text", () => {
    const text = 'dns.query ~ "ü" and sr';
    const start = utf16ToByte(text, text.length - 2);
    const r = applySuggestion(text, sug({ insert_text: "src_ip", replace_start: start, replace_end: start + 2 }));
    expect(r.text).toBe('dns.query ~ "ü" and src_ip ');
  });

  it("replaces everything for saved queries without a trailing space", () => {
    const r = applySuggestion("Lar", sug({ kind: "saved", insert_text: "bytes_up > 1MB", replace_start: 0, replace_end: 3 }));
    expect(r).toEqual({ text: "bytes_up > 1MB", caret: 14 });
  });
});

describe("splitAtSpan", () => {
  it("splits on a byte span", () => {
    expect(splitAtSpan('a "bc', { start: 2, end: 5 })).toEqual(["a ", '"bc', ""]);
  });
  it("widens empty spans and marks end-of-input", () => {
    expect(splitAtSpan("(a", { start: 0, end: 0 })).toEqual(["", "(", "a"]);
    expect(splitAtSpan("ab", { start: 2, end: 2 })).toEqual(["ab", " ", ""]);
    expect(splitAtSpan("ab", null)).toBeNull();
  });
});
