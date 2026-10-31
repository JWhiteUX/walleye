// Frames of the selected flow (virtualized listbox). Selecting one writes
// `selectFrame` to the shared selection.
import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useId, useRef, type KeyboardEvent } from "react";
import type { FrameRef } from "../shared/bindings/FrameRef";
import { formatTime } from "../shared/format";

const ROW_H = 22;

export function FrameList({
  frames,
  selected,
  onSelect,
}: {
  frames: FrameRef[];
  selected: number | null;
  onSelect: (frameNo: number) => void;
}) {
  const base = useId().replace(/:/g, "");
  const scroll = useRef<HTMLDivElement>(null);
  // TanStack hooks are the mandated stack; we do not use the React Compiler.
  // eslint-disable-next-line react-hooks/incompatible-library
  const v = useVirtualizer({ count: frames.length, getScrollElement: () => scroll.current, estimateSize: () => ROW_H, overscan: 8 });
  const idx = frames.findIndex((f) => f.frame_no === selected);

  useEffect(() => {
    if (idx >= 0) v.scrollToIndex(idx, { align: "auto" });
  }, [idx, v]);

  const onKeyDown = (e: KeyboardEvent) => {
    const page = Math.max(1, Math.floor((scroll.current?.clientHeight ?? 200) / ROW_H) - 1);
    const to = (i: number) => {
      const f = frames[Math.max(0, Math.min(frames.length - 1, i))];
      if (f) onSelect(f.frame_no);
    };
    switch (e.key) {
      case "ArrowDown":
        to(idx + 1);
        break;
      case "ArrowUp":
        to(idx <= 0 ? 0 : idx - 1);
        break;
      case "PageDown":
        to(idx + page);
        break;
      case "PageUp":
        to(idx - page);
        break;
      case "Home":
        to(0);
        break;
      case "End":
        to(frames.length - 1);
        break;
      default:
        return;
    }
    e.preventDefault();
  };

  const items = v.getVirtualItems();
  const activeVisible = idx >= 0 && items.some((i) => i.index === idx);

  return (
    <div
      ref={scroll}
      role="listbox"
      aria-label={`Frames in flow (${frames.length})`}
      tabIndex={0}
      className="wl-frames"
      data-testid="frame-list"
      aria-activedescendant={activeVisible ? `${base}-f${idx}` : undefined}
      onKeyDown={onKeyDown}
    >
      <div style={{ height: v.getTotalSize(), position: "relative" }}>
        {items.map((it) => {
          const f = frames[it.index]!;
          const sel = f.frame_no === selected;
          return (
            <div
              key={f.frame_no}
              id={`${base}-f${it.index}`}
              role="option"
              aria-selected={sel}
              className={`wl-frame${sel ? " is-selected" : ""}`}
              style={{ transform: `translateY(${it.start}px)` }}
              onClick={() => {
                onSelect(f.frame_no);
                scroll.current?.focus({ preventScroll: true });
              }}
            >
              <span className="wl-frame-no wl-mono">{f.frame_no}</span>
              <span className="wl-frame-dir" aria-label={f.direction === "down" ? "responder to initiator" : "initiator to responder"}>
                {f.direction === "down" ? "←" : "→"}
              </span>
              <span className="wl-frame-time wl-mono">{formatTime(f.ts)}</span>
              <span className="wl-frame-sum">{f.summary}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
