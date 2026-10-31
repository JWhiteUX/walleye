// Command palette (mod+k): every registered command, filterable, with its shortcut.
import { useId, useMemo, useState } from "react";
import { useCommands, type Command } from "../shared/commands";
import { Dialog } from "./Dialog";
import { formatShortcut, isMacPlatform } from "./keys";

/** Subsequence match score (lower is better), or null when no match. */
export function matchScore(query: string, text: string): number | null {
  const q = query.trim().toLowerCase();
  if (!q) return 0;
  const t = text.toLowerCase();
  const direct = t.indexOf(q);
  if (direct >= 0) return direct;
  let ti = 0;
  let gaps = 0;
  for (const ch of q) {
    if (ch === " ") continue;
    const at = t.indexOf(ch, ti);
    if (at < 0) return null;
    gaps += at - ti;
    ti = at + 1;
  }
  return 1000 + gaps;
}

/** "General" first, so Enter on an empty query never runs something destructive. */
const groupRank = (c: Command) => (c.group === "General" ? 0 : 1);

export function filterCommands(cmds: Command[], query: string): Command[] {
  return cmds
    .filter((c) => c.enabled?.() !== false)
    .map((c) => ({ c, s: matchScore(query, `${c.title} ${c.group}`) }))
    .filter((x): x is { c: Command; s: number } => x.s !== null)
    .sort((a, b) => a.s - b.s || groupRank(a.c) - groupRank(b.c) || a.c.group.localeCompare(b.c.group) || a.c.title.localeCompare(b.c.title))
    .map((x) => x.c);
}

export function CommandPalette({ onClose }: { onClose: () => void }) {
  const base = useId().replace(/:/g, "");
  const all = useCommands((s) => s.commands);
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const mac = isMacPlatform();
  const list = useMemo(() => filterCommands(Object.values(all), q), [all, q]);
  const idx = Math.min(active, Math.max(0, list.length - 1));

  const run = (c: Command | undefined) => {
    if (!c) return;
    onClose();
    // Run after the dialog unmounts and focus is restored, so commands that
    // move focus win.
    setTimeout(() => c.run(), 0);
  };

  return (
    <Dialog labelledBy={`${base}-title`} onClose={onClose} className="wl-palette" testId="command-palette">
      <h2 id={`${base}-title`} className="wl-visually-hidden">
        Command palette
      </h2>
      <input
        role="combobox"
        aria-label="Search commands"
        aria-expanded="true"
        aria-controls={`${base}-list`}
        aria-autocomplete="list"
        aria-activedescendant={list.length ? `${base}-o${idx}` : undefined}
        className="wl-palette-input"
        value={q}
        placeholder="Type a command…"
        data-autofocus
        spellCheck={false}
        autoComplete="off"
        onChange={(e) => {
          setQ(e.target.value);
          setActive(0);
        }}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") setActive((idx + 1) % Math.max(1, list.length));
          else if (e.key === "ArrowUp") setActive((idx - 1 + list.length) % Math.max(1, list.length));
          else if (e.key === "Home" && e.ctrlKey) setActive(0);
          else if (e.key === "Enter") run(list[idx]);
          else return;
          e.preventDefault();
        }}
      />
      <ul role="listbox" id={`${base}-list`} aria-label="Commands" className="wl-palette-list">
        {list.map((c, i) => (
          <li
            key={c.id}
            id={`${base}-o${i}`}
            role="option"
            aria-selected={i === idx}
            className={`wl-palette-item${i === idx ? " is-active" : ""}`}
            onMouseMove={() => setActive(i)}
            onClick={() => run(c)}
          >
            <span className="wl-palette-group">{c.group}</span>
            <span className="wl-palette-title">{c.title}</span>
            {c.shortcut && <kbd className="wl-kbd">{formatShortcut(c.shortcut, mac)}</kbd>}
          </li>
        ))}
        {list.length === 0 && (
          <li role="option" aria-selected="false" aria-disabled="true" className="wl-palette-item">
            No matching commands
          </li>
        )}
      </ul>
    </Dialog>
  );
}
