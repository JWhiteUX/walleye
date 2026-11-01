import { MARK_ENCODING, type MarkKind } from "../shared/encoding";

/** Inline SVG of a mark kind's shape, matching the canvas shapes. Decorative. */
export function ShapeIcon({ kind, size = 10 }: { kind: MarkKind; size?: number }) {
  const { shape, cssVar } = MARK_ENCODING[kind];
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
    case "ring":
      el = <circle cx={c} cy={c} r={r * 0.75} stroke={colour} strokeWidth={r * 0.5} fill="none" />;
      break;
    case "triangle-down":
      el = <polygon points={`${c},${c + r} ${c + r},${c - r * 0.85} ${c - r},${c - r * 0.85}`} fill={colour} />;
      break;
    case "bar":
      el = <rect x={c - r * 0.45} y={c - r} width={r * 0.9} height={r * 2} fill={colour} />;
      break;
    case "star": {
      const pts = Array.from({ length: 16 }, (_, i) => {
        const a = (i * Math.PI) / 8 - Math.PI / 2;
        const rr = i % 2 === 0 ? r * 1.1 : r * 0.45;
        return `${(c + rr * Math.cos(a)).toFixed(2)},${(c + rr * Math.sin(a)).toFixed(2)}`;
      }).join(" ");
      el = <polygon points={pts} fill={colour} />;
      break;
    }
  }
  return (
    <svg width={size} height={size} viewBox="0 0 10 10" aria-hidden="true" focusable="false" data-shape={shape}>
      {el}
    </svg>
  );
}
