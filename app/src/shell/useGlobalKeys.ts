// The one global keydown listener. Runs registered commands by shortcut
// (sequences included). Component handlers run first; a handled event
// (defaultPrevented) is ignored here.
import { useEffect, useMemo, useRef, useState } from "react";
import { useCommands } from "../shared/commands";
import { eventChord, isMacPlatform, isTextInput, ShortcutMatcher } from "./keys";

export function useGlobalKeys(): { pending: string } {
  const commands = useCommands((s) => s.commands);
  const mac = useMemo(() => isMacPlatform(), []);
  const matcher = useRef<ShortcutMatcher | null>(null);
  const [pending, setPending] = useState("");

  useEffect(() => {
    const bindings = Object.values(commands)
      .filter((c) => c.shortcut)
      .map((c) => ({ id: c.id, shortcut: c.shortcut! }));
    if (!matcher.current) matcher.current = new ShortcutMatcher(bindings, mac);
    else matcher.current.setBindings(bindings);
  }, [commands, mac]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.isComposing) return;
      const m = matcher.current;
      if (!m) return;
      const chord = eventChord(e);
      if (!chord) return;
      // Inside a modal dialog, only modifier shortcuts apply (e.g. closing the palette).
      const inDialog = !!(document.activeElement as HTMLElement | null)?.closest?.('[aria-modal="true"]');
      const r = m.handle(chord, performance.now(), isTextInput(document.activeElement) || inDialog);
      if (r.kind === "pending") {
        e.preventDefault();
        setPending(chord.toUpperCase());
        return;
      }
      setPending("");
      if (r.kind !== "match") return;
      const cmd = useCommands.getState().commands[r.id];
      if (!cmd || cmd.enabled?.() === false) return;
      e.preventDefault();
      cmd.run();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Clear the visible pending hint once the matcher times out.
  useEffect(() => {
    if (!pending) return;
    const t = setTimeout(() => setPending(""), 1300);
    return () => clearTimeout(t);
  }, [pending]);

  return { pending };
}
