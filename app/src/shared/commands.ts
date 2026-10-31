// Command registry for keyboard shortcuts and the command palette.
// Any panel registers its actions here; the shell (Agent D) renders the
// palette and owns the global key listener. Shortcut syntax: "mod+k",
// "shift+/", "g t" (sequence). "mod" = Cmd on macOS, Ctrl elsewhere.
import { useEffect } from "react";
import { create } from "zustand";

export interface Command {
  id: string;
  title: string;
  /** Group label in the palette, e.g. "Timeline". */
  group: string;
  shortcut?: string;
  run: () => void;
  /** Return false to hide/disable (e.g. nothing selected). */
  enabled?: () => boolean;
}

interface Registry {
  commands: Record<string, Command>;
  register: (c: Command) => () => void;
}

export const useCommands = create<Registry>()((set) => ({
  commands: {},
  register: (c) => {
    set((s) => ({ commands: { ...s.commands, [c.id]: c } }));
    return () =>
      set((s) => {
        const next = { ...s.commands };
        if (next[c.id] === c) delete next[c.id];
        return { commands: next };
      });
  },
}));

/** Register commands for the lifetime of a component. Pass a stable array. */
export function useRegisterCommands(cmds: Command[]): void {
  const register = useCommands((s) => s.register);
  useEffect(() => {
    const offs = cmds.map(register);
    return () => offs.forEach((off) => off());
  }, [cmds, register]);
}
