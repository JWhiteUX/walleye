// Pane sizing for the shell (UI usability PR 3).
import type { SideTab } from "./SidePanel";

/** Pane sizes in px; `null` = not resized by the user, so sized by share of the window. */
export interface Layout {
  timelineH: number | null;
  packetsH: number | null;
  sideW: number | null;
  sideTab: SideTab;
}

export const DEFAULT_LAYOUT: Layout = { timelineH: null, packetsH: null, sideW: null, sideTab: "findings" };
/** Auto sizes: shares of the analysis column's height / the window's width. */
export const TIMELINE_SHARE = 0.27;
export const PACKETS_SHARE = 0.33;
export const SIDE_SHARE = 0.28;
/** Auto side width never goes below this (findings wrap badly when narrower). */
export const SIDE_AUTO_MIN = 360;
// v2: Findings and Case became tabs in one column (v1 had two columns).
export const LAYOUT_KEY = "walleye.layout.v2";
/** The session table keeps at least this height; timeline and packets shrink first. */
export const TABLE_MIN = 280;
export const TIMELINE_MIN = 80;
export const PACKETS_MIN = 120;
export const SIDE_MIN = 280;
/** The side column never takes more than this share of the window. */
export const SIDE_MAX_SHARE = 0.4;
export const SPLITTERS_H = 12;

/**
 * Fit the stored pane sizes into the space there is. Stored sizes are what
 * the user chose; on a smaller window the timeline and packet pane give up
 * height (in proportion) so the session table keeps TABLE_MIN, and the side
 * column gives up width so the analysis column keeps the rest.
 */
export function fitLayout(l: Layout, shellW: number, mainH: number): { timelineH: number; packetsH: number; sideW: number } {
  const sideMax = Math.max(SIDE_MIN, Math.floor(shellW * SIDE_MAX_SHARE));
  const sideWanted = l.sideW ?? Math.max(SIDE_AUTO_MIN, Math.round(shellW * SIDE_SHARE));
  const sideW = shellW > 0 ? Math.min(Math.max(sideWanted, SIDE_MIN), sideMax) : (l.sideW ?? SIDE_AUTO_MIN);
  if (mainH <= 0) return { timelineH: l.timelineH ?? 200, packetsH: l.packetsH ?? 300, sideW };
  const avail = mainH - SPLITTERS_H;
  const t0 = l.timelineH ?? Math.max(TIMELINE_MIN, Math.round(avail * TIMELINE_SHARE));
  const p0 = l.packetsH ?? Math.max(PACKETS_MIN, Math.round(avail * PACKETS_SHARE));
  let t = t0;
  let p = p0;
  const over = t0 + p0 + TABLE_MIN - avail;
  if (over > 0) {
    t = Math.max(TIMELINE_MIN, Math.round(t0 - (over * t0) / (t0 + p0)));
    p = Math.max(PACKETS_MIN, Math.round(p0 - (over * p0) / (t0 + p0)));
    // If the timeline hit its minimum, the packet pane takes the rest of the cut.
    p = Math.max(PACKETS_MIN, Math.min(p, avail - t - TABLE_MIN));
    // ...and if the packet pane hit its minimum, the timeline does.
    t = Math.max(TIMELINE_MIN, Math.min(t, avail - p - TABLE_MIN));
  }
  return { timelineH: t, packetsH: p, sideW };
}

