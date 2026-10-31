import type { EventKind } from "../shared/bindings/EventKind";
import { EVENT_ENCODING } from "../shared/encoding";

/** Inline SVG of an event kind's mark, matching the canvas shapes. Decorative. */
export function ShapeIcon({ kind, size = 10 }: { kind: EventKind; size?: number }) {
  const { shape, cssVar } = EVENT_ENCODING[kind];
  const colour = `var(${cssVar})`;
  const c = 5;
  const r = 4;
  let el;
  switch (shape) {
    case "circle":
      el = <circle cx={c} cy={c} r={r} fill={colour} />;
      break;
    case "square":
      el = <rect x={c - r * 0.85} y={c - r * 0.85} width={r * 1.7} height={r * 1.7} fill={colour} />;
      break;
    case "triangle":
      el = <polygon points={`${c},${c - r} ${c + r},${c + r * 0.85} ${c - r},${c + r * 0.85}`} fill={colour} />;
      break;
    case "diamond":
      el = <polygon points={`${c},${c - r} ${c + r},${c} ${c},${c + r} ${c - r},${c}`} fill={colour} />;
      break;
    case "cross":
      el = (
        <path
          d={`M${c - r} ${c - r}L${c + r} ${c + r}M${c + r} ${c - r}L${c - r} ${c + r}`}
          stroke={colour}
          strokeWidth={1.6}
          fill="none"
        />
      );
      break;
  }
  return (
    <svg width={size} height={size} viewBox="0 0 10 10" aria-hidden="true" focusable="false" data-shape={shape}>
      {el}
    </svg>
  );
}
