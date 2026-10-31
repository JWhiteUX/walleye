// Hex view and decode-tree <-> byte mapping. Pure functions; every input
// comes from a hostile capture, so parse defensively and never trust ranges.
import type { ByteRange } from "../shared/bindings/ByteRange";
import type { DecodeNode } from "../shared/bindings/DecodeNode";

export const BYTES_PER_ROW = 16;

/** Parse `bytes_hex` (two lowercase hex chars per byte). Stops at the first bad pair. */
export function parseHex(hex: string): Uint8Array {
  const n = Math.floor(hex.length / 2);
  const out = new Uint8Array(n);
  let i = 0;
  for (; i < n; i++) {
    const v = parseInt(hex.substr(i * 2, 2), 16);
    if (!/^[0-9a-fA-F]{2}$/.test(hex.substr(i * 2, 2)) || Number.isNaN(v)) break;
    out[i] = v;
  }
  return i === n ? out : out.slice(0, i);
}

/** Printable ASCII or "." — the hex view never shows control characters. */
export function asciiChar(b: number): string {
  return b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
}

export const hex2 = (b: number): string => b.toString(16).padStart(2, "0");

export function offsetLabel(offset: number): string {
  return offset.toString(16).padStart(4, "0");
}

/** Node path id, e.g. "1.0.2" (indices from the root list). */
export type NodeId = string;

export interface FlatNode {
  id: NodeId;
  node: DecodeNode;
  depth: number;
  parent: NodeId | null;
  /** Range clamped to the frame bytes, or null. */
  range: ByteRange | null;
}

/** Clamp a range to `[0, len)`; null when empty or outside. */
export function clampRange(r: ByteRange | null | undefined, len: number): ByteRange | null {
  if (!r || !Number.isFinite(r.start) || !Number.isFinite(r.len)) return null;
  const start = Math.max(0, Math.floor(r.start));
  const end = Math.min(len, Math.floor(r.start + r.len));
  return end > start ? { start, len: end - start } : null;
}

/** Depth-first flattening with path ids. Caps depth to defend against hostile trees. */
export function flattenTree(tree: DecodeNode[], byteCount: number, maxDepth = 32): FlatNode[] {
  const out: FlatNode[] = [];
  const walk = (nodes: DecodeNode[], depth: number, parent: NodeId | null) => {
    if (depth > maxDepth) return;
    nodes.forEach((node, i) => {
      const id = parent === null ? String(i) : `${parent}.${i}`;
      out.push({ id, node, depth, parent, range: clampRange(node.range, byteCount) });
      if (node.children?.length) walk(node.children, depth + 1, id);
    });
  };
  walk(tree, 0, null);
  return out;
}

/**
 * Deepest node whose range contains `offset`. Ties at equal depth go to the
 * narrowest range, then to the first in document order.
 */
export function deepestNodeAt(flat: FlatNode[], offset: number): FlatNode | null {
  let best: FlatNode | null = null;
  for (const f of flat) {
    const r = f.range;
    if (!r || offset < r.start || offset >= r.start + r.len) continue;
    if (!best || f.depth > best.depth || (f.depth === best.depth && r.len < best.range!.len)) best = f;
  }
  return best;
}

/** Ids of every ancestor of `id` ("1.0.2" -> ["1", "1.0"]). */
export function ancestorIds(id: NodeId): NodeId[] {
  const parts = id.split(".");
  const out: NodeId[] = [];
  for (let i = 1; i < parts.length; i++) out.push(parts.slice(0, i).join("."));
  return out;
}

/** Nearest node with a range at or above `id` (leaves without ranges inherit the parent's). */
export function effectiveRange(byId: Map<NodeId, FlatNode>, id: NodeId | null): ByteRange | null {
  let cur = id ? byId.get(id) : undefined;
  while (cur) {
    if (cur.range) return cur.range;
    cur = cur.parent ? byId.get(cur.parent) : undefined;
  }
  return null;
}

/** True when the frame was cut short at capture time or a layer reports a problem. */
export function truncationNote(caplen: number, wirelen: number, byteCount: number): string | null {
  if (wirelen > caplen) return `Truncated at capture: ${caplen} of ${wirelen} bytes captured.`;
  if (byteCount < caplen) return `Only ${byteCount} of ${caplen} captured bytes are available.`;
  return null;
}
