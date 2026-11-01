// What the open capture contains, decided from data (CONTRACTS §11): whether
// it has 802.11 rows and whether it has flows. A pcapng can mix interfaces
// (Ethernet first, radiotap second), so `capture.link_type` (the FIRST
// interface) is only a fast path: 105/127 means 802.11 without asking.
// Otherwise one-row probes of `wifi_aps` / `wifi` decide. Results are cached
// per capture id; every panel reads the same answer.
import { useEffect } from "react";
import { create } from "zustand";
import type { CaptureRow } from "./bindings/CaptureRow";
import { api } from "./ipc";
import { useSession } from "./session";
import { isWifiLinkType } from "./wifi";

export interface CaptureKind {
  /** 802.11 rows present; null while unknown. */
  wifi: boolean | null;
  /** Flows present; null while unknown. */
  hasFlows: boolean | null;
}

const UNKNOWN: CaptureKind = { wifi: null, hasFlows: null };

interface Store {
  byCapture: Record<string, CaptureKind>;
  set: (id: string, k: Partial<CaptureKind>) => void;
}

export const useCaptureKindStore = create<Store>()((set) => ({
  byCapture: {},
  set: (id, k) => set((s) => ({ byCapture: { ...s.byCapture, [id]: { ...(s.byCapture[id] ?? UNKNOWN), ...k } } })),
}));

const inflight = new Set<string>();

async function hasRows(view: "wifi_aps" | "wifi" | "flows"): Promise<boolean> {
  const p = await api.query({ filter: "", view, limit: 1 });
  return p.data.rows.length > 0 || (p.total ?? 0) > 0;
}

/** Probe once per capture id (idempotent; safe to call from many panels). */
export function probeCapture(capture: Pick<CaptureRow, "capture_id" | "link_type">): void {
  const id = capture.capture_id;
  if (inflight.has(id) || useCaptureKindStore.getState().byCapture[id]) return;
  inflight.add(id);
  const st = useCaptureKindStore.getState();
  const fast = isWifiLinkType(capture.link_type);
  void (async () => {
    try {
      const [wifi, hasFlows] = await Promise.all([
        fast ? Promise.resolve(true) : hasRows("wifi_aps").then(async (a) => a || (await hasRows("wifi"))),
        hasRows("flows"),
      ]);
      st.set(id, { wifi, hasFlows });
    } catch {
      // Not cached: the next panel that mounts probes again.
    } finally {
      inflight.delete(id);
    }
  })();
}

/** Test hook: forget every cached answer. */
export function resetCaptureKinds(): void {
  inflight.clear();
  useCaptureKindStore.setState({ byCapture: {} });
}

/**
 * The open capture's kind. `wifi` is true immediately for link types
 * 105/127, otherwise once a probe finds 802.11 rows.
 */
export function useCaptureKind(): CaptureKind {
  const capture = useSession((s) => s.session?.capture ?? null);
  const id = capture?.capture_id ?? null;
  const fast = capture ? isWifiLinkType(capture.link_type) : false;
  useEffect(() => {
    if (capture) probeCapture(capture);
  }, [capture]);
  const k = useCaptureKindStore((s) => (id ? s.byCapture[id] : undefined));
  if (!capture) return { wifi: false, hasFlows: null };
  return { wifi: fast ? true : (k?.wifi ?? null), hasFlows: k?.hasFlows ?? null };
}

/** Non-hook read for command `enabled()` callbacks. */
export function currentCaptureKind(): CaptureKind {
  const c = useSession.getState().session?.capture;
  if (!c) return { wifi: false, hasFlows: null };
  const k = useCaptureKindStore.getState().byCapture[c.capture_id] ?? UNKNOWN;
  return { wifi: isWifiLinkType(c.link_type) ? true : k.wifi, hasFlows: k.hasFlows };
}
