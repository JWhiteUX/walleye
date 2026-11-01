// Keyboard shortcut parsing and matching for the global key handler.
//
// Shortcut syntax (shared/commands.ts): chords joined by "+", sequences
// separated by a space: "mod+k", "shift+/", "f6", "g t". "mod" is Cmd on
// macOS and Ctrl elsewhere. Matching is pure so it can be unit tested.

export interface KeyLike {
  key: string;
  metaKey: boolean;
  ctrlKey: boolean;
  altKey: boolean;
  shiftKey: boolean;
}

const MODIFIER_KEYS = new Set(["Shift", "Control", "Alt", "Meta", "OS", "CapsLock", "Dead"]);

// US-layout shifted punctuation: "shift+/" in a shortcut is the "?" key event.
const SHIFTED: Record<string, string> = {
  "/": "?", "1": "!", "2": "@", "3": "#", "4": "$", "5": "%", "6": "^", "7": "&", "8": "*",
  "9": "(", "0": ")", "-": "_", "=": "+", "[": "{", "]": "}", "\\": "|", ";": ":", "'": '"',
  ",": "<", ".": ">", "`": "~",
};

const KEY_ALIASES: Record<string, string> = {
  esc: "escape",
  return: "enter",
  space: " ",
  spacebar: " ",
  up: "arrowup",
  down: "arrowdown",
  left: "arrowleft",
  right: "arrowright",
  del: "delete",
  plus: "+",
};

export function isMacPlatform(): boolean {
  if (typeof navigator === "undefined") return false;
  const p = (navigator as Navigator & { userAgentData?: { platform?: string } }).userAgentData?.platform || navigator.platform || "";
  return /mac|iphone|ipad/i.test(p);
}

/** True when a key produces visible text with shift folded in (punctuation, digits). */
function isSymbol(key: string): boolean {
  return key.length === 1 && !/[a-z]/i.test(key);
}

function canonical(mods: { ctrl: boolean; meta: boolean; alt: boolean; shift: boolean }, key: string): string {
  const parts: string[] = [];
  if (mods.ctrl) parts.push("ctrl");
  if (mods.meta) parts.push("meta");
  if (mods.alt) parts.push("alt");
  if (mods.shift) parts.push("shift");
  parts.push(key);
  return parts.join("+");
}

/** Canonical chord for a keyboard event, or null for a bare modifier press. */
export function eventChord(e: KeyLike): string | null {
  if (MODIFIER_KEYS.has(e.key)) return null;
  let key = e.key.length === 1 ? e.key.toLowerCase() : e.key.toLowerCase();
  // Shift is already folded into the produced symbol ("?" not "shift+/").
  const shift = e.shiftKey && !isSymbol(e.key);
  if (key === "") return null;
  if (key === "spacebar") key = " ";
  return canonical({ ctrl: e.ctrlKey, meta: e.metaKey, alt: e.altKey, shift }, key);
}

/** Canonical chord for one chord of a shortcut string ("mod+shift+k"). */
export function parseChord(chord: string, mac: boolean): string {
  // "mod++" means mod and the plus key.
  const raw = chord.trim().toLowerCase();
  const parts = raw.endsWith("++") ? [...raw.slice(0, -2).split("+").filter(Boolean), "+"] : raw.split("+");
  const mods = { ctrl: false, meta: false, alt: false, shift: false };
  let key = "";
  for (const p of parts) {
    if (p === "mod") {
      if (mac) mods.meta = true;
      else mods.ctrl = true;
    } else if (p === "ctrl" || p === "control") mods.ctrl = true;
    else if (p === "cmd" || p === "meta") mods.meta = true;
    else if (p === "alt" || p === "option") mods.alt = true;
    else if (p === "shift") mods.shift = true;
    else key = KEY_ALIASES[p] ?? p;
  }
  const shifted = SHIFTED[key];
  if (mods.shift && shifted) {
    key = shifted;
    mods.shift = false;
  } else if (mods.shift && isSymbol(key)) {
    mods.shift = false;
  }
  return canonical(mods, key);
}

/** A shortcut string as a list of canonical chords ("g t" -> ["g", "t"]). */
export function parseShortcut(shortcut: string, mac: boolean): string[] {
  return shortcut
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map((c) => parseChord(c, mac));
}

/** Human label: "⌘K", "Ctrl+K", "G then T". */
export function formatShortcut(shortcut: string, mac: boolean): string {
  return shortcut
    .trim()
    .split(/\s+/)
    .map((chord) =>
      chord
        .split("+")
        .map((p) => {
          const k = p.toLowerCase();
          if (k === "mod") return mac ? "⌘" : "Ctrl";
          if (k === "shift") return mac ? "⇧" : "Shift";
          if (k === "alt") return mac ? "⌥" : "Alt";
          if (k === "ctrl") return mac ? "⌃" : "Ctrl";
          if (k === "escape" || k === "esc") return "Esc";
          if (k.length === 1) return k.toUpperCase();
          return k.charAt(0).toUpperCase() + k.slice(1);
        })
        .join(mac ? "" : "+"),
    )
    .join(" then ");
}

/** True when the chord has no ctrl/meta/alt (plain typing would trigger it). */
export function isPlainChord(chord: string): boolean {
  if (/^f\d{1,2}$/.test(chord.replace(/^shift\+/, ""))) return false; // F-keys never type text
  return !/(^|\+)(ctrl|meta|alt)\+/.test(chord);
}

export interface Binding {
  id: string;
  shortcut: string;
}

export type MatchResult = { kind: "match"; id: string } | { kind: "pending" } | { kind: "none" };

/**
 * Sequence-aware matcher. Feed it one canonical chord per keydown; it keeps
 * the pending prefix (e.g. "g" of "g t") until `timeoutMs` passes.
 */
export class ShortcutMatcher {
  private pending: string[] = [];
  private lastAt = 0;
  private table: { id: string; chords: string[] }[] = [];

  constructor(
    bindings: Binding[],
    private readonly mac: boolean,
    private readonly timeoutMs = 1200,
  ) {
    this.setBindings(bindings);
  }

  setBindings(bindings: Binding[]): void {
    this.table = bindings
      .filter((b) => b.shortcut.trim())
      .map((b) => ({ id: b.id, chords: parseShortcut(b.shortcut, this.mac) }));
  }

  reset(): void {
    this.pending = [];
  }

  get hasPending(): boolean {
    return this.pending.length > 0;
  }

  /**
   * @param typing true when focus is in a text field: plain chords (no
   *   ctrl/meta/alt) do not start or continue a shortcut then.
   */
  handle(chord: string, now: number, typing = false): MatchResult {
    if (this.pending.length && now - this.lastAt > this.timeoutMs) this.pending = [];
    this.lastAt = now;
    if (typing && isPlainChord(chord)) {
      this.pending = [];
      return { kind: "none" };
    }
    const tryWith = (prefix: string[]): MatchResult | null => {
      const seq = [...prefix, chord];
      let partial = false;
      for (const b of this.table) {
        if (b.chords.length < seq.length) continue;
        if (!seq.every((c, i) => b.chords[i] === c)) continue;
        if (b.chords.length === seq.length) {
          this.pending = [];
          return { kind: "match", id: b.id };
        }
        partial = true;
      }
      if (partial) {
        this.pending = seq;
        return { kind: "pending" };
      }
      return null;
    };
    const r = (this.pending.length && tryWith(this.pending)) || tryWith([]);
    if (r) return r;
    this.pending = [];
    return { kind: "none" };
  }
}

/** Whether a DOM element accepts text input (shortcuts without modifiers stay off). */
export function isTextInput(el: Element | null): boolean {
  if (!el) return false;
  if (el instanceof HTMLTextAreaElement) return true;
  if (el instanceof HTMLInputElement) {
    return !["button", "checkbox", "radio", "range", "submit", "reset", "file", "color"].includes(el.type);
  }
  return (el as HTMLElement).isContentEditable === true;
}
