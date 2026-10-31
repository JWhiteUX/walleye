import { describe, expect, it } from "vitest";
import { eventChord, formatShortcut, parseChord, parseShortcut, ShortcutMatcher } from "./keys";

const ev = (key: string, mods: Partial<{ meta: boolean; ctrl: boolean; alt: boolean; shift: boolean }> = {}) => ({
  key,
  metaKey: !!mods.meta,
  ctrlKey: !!mods.ctrl,
  altKey: !!mods.alt,
  shiftKey: !!mods.shift,
});

describe("chords", () => {
  it("maps mod to meta on mac and ctrl elsewhere", () => {
    expect(parseChord("mod+k", true)).toBe("meta+k");
    expect(parseChord("mod+k", false)).toBe("ctrl+k");
    expect(eventChord(ev("k", { meta: true }))).toBe("meta+k");
    expect(eventChord(ev("K", { ctrl: true, shift: true }))).toBe("ctrl+shift+k");
    expect(parseChord("mod+shift+K", false)).toBe("ctrl+shift+k");
  });

  it("folds shift into punctuation", () => {
    expect(parseChord("shift+/", false)).toBe("?");
    expect(eventChord(ev("?", { shift: true }))).toBe("?");
    expect(parseChord("/", false)).toBe("/");
  });

  it("handles named keys and bare modifiers", () => {
    expect(parseChord("F6", false)).toBe("f6");
    expect(eventChord(ev("F6"))).toBe("f6");
    expect(eventChord(ev("F6", { shift: true }))).toBe("shift+f6");
    expect(parseChord("shift+f6", false)).toBe("shift+f6");
    expect(parseChord("esc", false)).toBe("escape");
    expect(eventChord(ev("Shift", { shift: true }))).toBeNull();
    expect(eventChord(ev("Meta", { meta: true }))).toBeNull();
  });

  it("parses sequences", () => {
    expect(parseShortcut("g t", false)).toEqual(["g", "t"]);
    expect(parseShortcut("  mod+k ", true)).toEqual(["meta+k"]);
  });

  it("formats for display", () => {
    expect(formatShortcut("mod+k", true)).toBe("⌘K");
    expect(formatShortcut("mod+k", false)).toBe("Ctrl+K");
    expect(formatShortcut("g t", false)).toBe("G then T");
  });
});

describe("ShortcutMatcher", () => {
  const bindings = [
    { id: "palette", shortcut: "mod+k" },
    { id: "go-timeline", shortcut: "g t" },
    { id: "go-table", shortcut: "g s" },
    { id: "help", shortcut: "shift+/" },
    { id: "next-pane", shortcut: "f6" },
    { id: "focus-filter", shortcut: "/" },
  ];

  it("matches single chords", () => {
    const m = new ShortcutMatcher(bindings, false);
    expect(m.handle("ctrl+k", 0)).toEqual({ kind: "match", id: "palette" });
    expect(m.handle("?", 10)).toEqual({ kind: "match", id: "help" });
    expect(m.handle("x", 20)).toEqual({ kind: "none" });
  });

  it("matches sequences and keeps the prefix pending", () => {
    const m = new ShortcutMatcher(bindings, false);
    expect(m.handle("g", 0)).toEqual({ kind: "pending" });
    expect(m.hasPending).toBe(true);
    expect(m.handle("t", 100)).toEqual({ kind: "match", id: "go-timeline" });
    expect(m.hasPending).toBe(false);
    expect(m.handle("g", 200)).toEqual({ kind: "pending" });
    expect(m.handle("s", 300)).toEqual({ kind: "match", id: "go-table" });
  });

  it("drops the prefix after the timeout", () => {
    const m = new ShortcutMatcher(bindings, false, 1000);
    expect(m.handle("g", 0)).toEqual({ kind: "pending" });
    expect(m.handle("t", 5000)).toEqual({ kind: "none" });
  });

  it("restarts from the current chord when the sequence breaks", () => {
    const m = new ShortcutMatcher(bindings, false);
    m.handle("g", 0);
    expect(m.handle("ctrl+k", 10)).toEqual({ kind: "match", id: "palette" });
  });

  it("ignores plain chords while typing but not modifier chords or F-keys", () => {
    const m = new ShortcutMatcher(bindings, false);
    expect(m.handle("g", 0, true)).toEqual({ kind: "none" });
    expect(m.handle("/", 0, true)).toEqual({ kind: "none" });
    expect(m.handle("ctrl+k", 0, true)).toEqual({ kind: "match", id: "palette" });
    expect(m.handle("f6", 0, true)).toEqual({ kind: "match", id: "next-pane" });
  });

  it("picks up new bindings", () => {
    const m = new ShortcutMatcher([], false);
    expect(m.handle("ctrl+k", 0)).toEqual({ kind: "none" });
    m.setBindings(bindings);
    expect(m.handle("ctrl+k", 0)).toEqual({ kind: "match", id: "palette" });
  });
});
