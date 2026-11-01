// Hex dump: offset | 16 hex bytes | ASCII. Virtualized by row so a 256 KiB
// frame stays cheap. Highlighted bytes get a background AND an underline
// (colour is never the only signal); the byte cursor gets an outline.
import { useVirtualizer } from "@tanstack/react-virtual";
import { memo, useEffect, useRef, type KeyboardEvent, type MouseEvent } from "react";
import type { ByteRange } from "../shared/bindings/ByteRange";
import { asciiChar, BYTES_PER_ROW, hex2, offsetLabel } from "./hex";

const ROW_H = 18;

export interface HexViewProps {
  bytes: Uint8Array;
  highlight: ByteRange | null;
  cursor: number | null;
  onPick: (offset: number) => void;
  readout: string;
}

const HexRow = memo(function HexRow({
  bytes,
  row,
  hlStart,
  hlEnd,
  cursor,
}: {
  bytes: Uint8Array;
  row: number;
  hlStart: number;
  hlEnd: number;
  cursor: number | null;
}) {
  const off = row * BYTES_PER_ROW;
  const end = Math.min(bytes.length, off + BYTES_PER_ROW);
  const hex = [];
  const asc = [];
  for (let i = off; i < end; i++) {
    const b = bytes[i]!;
    const cls = `wl-byte${i >= hlStart && i < hlEnd ? " is-hl" : ""}${i === cursor ? " is-cursor" : ""}`;
    hex.push(
      <span key={i} className={cls} data-off={i}>
        {hex2(b)}
      </span>,
    );
    asc.push(
      <span key={i} className={cls} data-off={i}>
        {asciiChar(b)}
      </span>,
    );
  }
  return (
    <>
      <span className="wl-hex-off">{offsetLabel(off)}</span>
      <span className="wl-hex-bytes">{hex}</span>
      <span className="wl-hex-ascii">{asc}</span>
    </>
  );
});

export function HexView({ bytes, highlight, cursor, onPick, readout }: HexViewProps) {
  const scroll = useRef<HTMLDivElement>(null);
  const rows = Math.ceil(bytes.length / BYTES_PER_ROW);
  // TanStack hooks are the mandated stack; we do not use the React Compiler.
  // eslint-disable-next-line react-hooks/incompatible-library
  const v = useVirtualizer({
    count: rows,
    getScrollElement: () => scroll.current,
    estimateSize: () => ROW_H,
    overscan: 8,
  });
  const hlStart = highlight ? highlight.start : -1;
  const hlEnd = highlight ? highlight.start + highlight.len : -1;

  // Bring the highlighted range into view.
  useEffect(() => {
    if (highlight) v.scrollToIndex(Math.floor(highlight.start / BYTES_PER_ROW), { align: "auto" });
  }, [highlight, v]);

  const onClick = (e: MouseEvent) => {
    const t = (e.target as HTMLElement).closest("[data-off]");
    if (!t) return;
    const off = Number(t.getAttribute("data-off"));
    if (Number.isInteger(off)) onPick(off);
  };

  const onKeyDown = (e: KeyboardEvent) => {
    if (!bytes.length) return;
    const cur = cursor ?? -1;
    const delta = { ArrowRight: 1, ArrowLeft: -1, ArrowDown: BYTES_PER_ROW, ArrowUp: -BYTES_PER_ROW }[e.key];
    let next: number | null = null;
    if (delta !== undefined) next = cur < 0 ? 0 : cur + delta;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = bytes.length - 1;
    if (next === null) return;
    e.preventDefault();
    next = Math.max(0, Math.min(bytes.length - 1, next));
    onPick(next);
    v.scrollToIndex(Math.floor(next / BYTES_PER_ROW), { align: "auto" });
  };

  return (
    <div className="wl-hex-wrap">
      <div
        ref={scroll}
        role="region"
        aria-label="Packet bytes (hex and ASCII). Arrow keys move the byte cursor."
        aria-describedby="wl-hex-readout"
        tabIndex={0}
        className="wl-hex wl-mono"
        data-testid="hex-view"
        onClick={onClick}
        onKeyDown={onKeyDown}
      >
        <div style={{ height: v.getTotalSize(), position: "relative" }}>
          {v.getVirtualItems().map((it) => (
            <div key={it.index} className="wl-hex-row" style={{ transform: `translateY(${it.start}px)` }}>
              <HexRow bytes={bytes} row={it.index} hlStart={hlStart} hlEnd={hlEnd} cursor={cursor} />
            </div>
          ))}
        </div>
      </div>
      <p id="wl-hex-readout" className="wl-hex-readout" aria-live="polite" data-testid="hex-readout">
        {readout}
      </p>
    </div>
  );
}
