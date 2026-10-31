// Text helpers for the filter bar. The backend speaks UTF-8 byte offsets
// (`cursor_pos`, `replace_start/end`, `WalleyeError.span`); the DOM speaks
// UTF-16 code-unit indices. Convert at the boundary, nowhere else.
import type { Suggestion } from "../shared/bindings/Suggestion";

const enc = new TextEncoder();

/** UTF-8 byte length of `s`. */
export function byteLen(s: string): number {
  return enc.encode(s).length;
}

/** UTF-16 index -> UTF-8 byte offset. */
export function utf16ToByte(text: string, index: number): number {
  return byteLen(text.slice(0, Math.max(0, Math.min(index, text.length))));
}

/** UTF-8 byte offset -> UTF-16 index (clamped; mid-character offsets round down). */
export function byteToUtf16(text: string, byteOffset: number): number {
  if (byteOffset <= 0) return 0;
  let bytes = 0;
  let i = 0;
  while (i < text.length) {
    const cp = text.codePointAt(i)!;
    const w = cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
    if (bytes + w > byteOffset) return i;
    bytes += w;
    i += cp > 0xffff ? 2 : 1;
  }
  return text.length;
}

/**
 * Apply a suggestion: replace bytes [replace_start, replace_end) of `text`
 * with `insert_text`. Returns the new text and the caret (UTF-16) after it.
 * Adds one trailing space after fields/operators/keywords/values so typing
 * can continue, unless the next character is already whitespace or ")".
 */
export function applySuggestion(text: string, s: Suggestion): { text: string; caret: number } {
  const startB = Math.max(0, Math.min(s.replace_start, s.replace_end));
  const endB = Math.max(s.replace_start, s.replace_end);
  const start = byteToUtf16(text, startB);
  const end = byteToUtf16(text, endB);
  const before = text.slice(0, start);
  const after = text.slice(end);
  const wantsSpace = s.kind !== "saved" && !/^[\s)]/.test(after);
  const insert = s.insert_text + (wantsSpace ? " " : "");
  return { text: before + insert + after, caret: before.length + insert.length };
}

/** Split text into [before, error, after] for the inline underline. */
export function splitAtSpan(text: string, span: { start: number; end: number } | null): [string, string, string] | null {
  if (!span) return null;
  const a = byteToUtf16(text, span.start);
  let b = byteToUtf16(text, span.end);
  if (b <= a) b = Math.min(text.length, a + 1);
  // An error at end-of-input still needs something visible to underline.
  if (a >= text.length) return [text, " ", ""];
  return [text.slice(0, a), text.slice(a, b), text.slice(b)];
}
