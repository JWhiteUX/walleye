// Keyboard- and pointer-resizable divider (WAI-ARIA window splitter).
// `orientation="horizontal"` separates stacked panes (drag vertically).
import { useRef, type KeyboardEvent, type PointerEvent } from "react";

export interface SplitterProps {
  label: string;
  orientation: "horizontal" | "vertical";
  value: number;
  min: number;
  max: number;
  /** +1 when dragging down/right grows the controlled pane, -1 when it shrinks it. */
  sign: 1 | -1;
  onChange: (v: number) => void;
  controls?: string;
}

export function Splitter({ label, orientation, value, min, max, sign, onChange, controls }: SplitterProps) {
  const drag = useRef<{ start: number; value: number } | null>(null);
  const clamp = (v: number) => Math.round(Math.max(min, Math.min(max, v)));

  const onKeyDown = (e: KeyboardEvent) => {
    const step = e.shiftKey ? 64 : 16;
    const grow: Record<string, number> =
      orientation === "horizontal" ? { ArrowDown: sign, ArrowUp: -sign } : { ArrowRight: sign, ArrowLeft: -sign };
    const d = grow[e.key];
    if (d !== undefined) onChange(clamp(value + d * step));
    else if (e.key === "Home") onChange(min);
    else if (e.key === "End") onChange(max);
    else return;
    e.preventDefault();
  };

  const pos = (e: PointerEvent) => (orientation === "horizontal" ? e.clientY : e.clientX);

  return (
    <div
      role="separator"
      tabIndex={0}
      aria-label={label}
      aria-orientation={orientation}
      aria-valuenow={Math.round(value)}
      aria-valuemin={min}
      aria-valuemax={max}
      aria-controls={controls}
      className={`wl-splitter is-${orientation}`}
      onKeyDown={onKeyDown}
      onPointerDown={(e) => {
        e.currentTarget.setPointerCapture(e.pointerId);
        drag.current = { start: pos(e), value };
      }}
      onPointerMove={(e) => {
        if (!drag.current) return;
        onChange(clamp(drag.current.value + sign * (pos(e) - drag.current.start)));
      }}
      onPointerUp={(e) => {
        drag.current = null;
        e.currentTarget.releasePointerCapture(e.pointerId);
      }}
    />
  );
}
