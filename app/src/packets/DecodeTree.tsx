// Collapsible decode tree (WAI-ARIA tree pattern, aria-activedescendant).
// Labels and values come from a hostile capture: text only.
import { useEffect, useId, useMemo, useRef, type KeyboardEvent } from "react";
import type { FlatNode, NodeId } from "./hex";

export interface DecodeTreeProps {
  flat: FlatNode[];
  expanded: Set<NodeId>;
  selected: NodeId | null;
  onSelect: (id: NodeId) => void;
  onToggle: (id: NodeId, open?: boolean) => void;
}

const MAX_RENDERED = 5000;

export function DecodeTree({ flat, expanded, selected, onSelect, onToggle }: DecodeTreeProps) {
  const base = useId().replace(/:/g, "");
  const ref = useRef<HTMLDivElement>(null);
  const byId = useMemo(() => new Map(flat.map((f) => [f.id, f])), [flat]);
  const hasKids = useMemo(() => {
    const s = new Set<NodeId>();
    for (const f of flat) if (f.parent !== null) s.add(f.parent);
    return s;
  }, [flat]);
  const siblings = useMemo(() => {
    const m = new Map<string, NodeId[]>();
    for (const f of flat) {
      const k = f.parent ?? "";
      const arr = m.get(k) ?? [];
      arr.push(f.id);
      m.set(k, arr);
    }
    return m;
  }, [flat]);

  // Visible = every ancestor expanded.
  const visible = useMemo(() => {
    const out: FlatNode[] = [];
    for (const f of flat) {
      let p = f.parent;
      let show = true;
      while (p !== null) {
        if (!expanded.has(p)) {
          show = false;
          break;
        }
        p = byId.get(p)?.parent ?? null;
      }
      if (show) out.push(f);
      if (out.length >= MAX_RENDERED) break;
    }
    return out;
  }, [flat, expanded, byId]);

  const domId = (id: NodeId) => `${base}-n${id.replace(/\./g, "_")}`;

  useEffect(() => {
    if (!selected) return;
    document.getElementById(domId(selected))?.scrollIntoView?.({ block: "nearest" });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);

  const onKeyDown = (e: KeyboardEvent) => {
    const idx = visible.findIndex((v) => v.id === selected);
    const cur = idx >= 0 ? visible[idx]! : null;
    const go = (i: number) => {
      const v = visible[Math.max(0, Math.min(visible.length - 1, i))];
      if (v) onSelect(v.id);
    };
    switch (e.key) {
      case "ArrowDown":
        go(idx + 1);
        break;
      case "ArrowUp":
        go(idx <= 0 ? 0 : idx - 1);
        break;
      case "Home":
        go(0);
        break;
      case "End":
        go(visible.length - 1);
        break;
      case "ArrowRight":
        if (!cur) go(0);
        else if (hasKids.has(cur.id) && !expanded.has(cur.id)) onToggle(cur.id, true);
        else if (hasKids.has(cur.id)) go(idx + 1);
        break;
      case "ArrowLeft":
        if (!cur) go(0);
        else if (hasKids.has(cur.id) && expanded.has(cur.id)) onToggle(cur.id, false);
        else if (cur.parent !== null) onSelect(cur.parent);
        break;
      case "Enter":
      case " ":
        if (cur && hasKids.has(cur.id)) onToggle(cur.id);
        else if (!cur) go(0);
        break;
      default:
        return;
    }
    e.preventDefault();
  };

  return (
    <div
      ref={ref}
      role="tree"
      aria-label="Protocol decode"
      tabIndex={0}
      className="wl-tree"
      data-testid="decode-tree"
      aria-activedescendant={selected && visible.some((v) => v.id === selected) ? domId(selected) : undefined}
      onKeyDown={onKeyDown}
      onFocus={() => {
        if (!selected && visible[0]) onSelect(visible[0].id);
      }}
    >
      {visible.map((f) => {
        const kids = hasKids.has(f.id);
        const open = expanded.has(f.id);
        const sibs = siblings.get(f.parent ?? "") ?? [];
        return (
          <div
            key={f.id}
            id={domId(f.id)}
            role="treeitem"
            aria-level={f.depth + 1}
            aria-setsize={sibs.length}
            aria-posinset={sibs.indexOf(f.id) + 1}
            aria-expanded={kids ? open : undefined}
            aria-selected={selected === f.id}
            className={`wl-tree-item${selected === f.id ? " is-selected" : ""}`}
            style={{ paddingLeft: 4 + f.depth * 14 }}
            data-node={f.id}
            onClick={() => {
              onSelect(f.id);
              ref.current?.focus({ preventScroll: true });
            }}
          >
            <span
              className="wl-tree-twisty"
              aria-hidden="true"
              onClick={(e) => {
                if (!kids) return;
                e.stopPropagation();
                onSelect(f.id);
                onToggle(f.id);
              }}
            >
              {kids ? (open ? "▾" : "▸") : ""}
            </span>
            <span className="wl-tree-label">{f.node.label}</span>
            {f.node.warning && (
              <span className="wl-tree-warn">
                {" "}
                ⚠ <span>{f.node.warning}</span>
              </span>
            )}
            {f.range && (
              <span className="wl-tree-range wl-mono" aria-label={`bytes ${f.range.start} to ${f.range.start + f.range.len - 1}`}>
                {" "}
                [{f.range.start}–{f.range.start + f.range.len - 1}]
              </span>
            )}
          </div>
        );
      })}
      {flat.length > MAX_RENDERED && <p className="wl-empty">Showing the first {MAX_RENDERED} nodes.</p>}
    </div>
  );
}
