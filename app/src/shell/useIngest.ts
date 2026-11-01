// Open-capture flow: pick a file, start the job, poll ingest_status until it
// is done, failed or cancelled, then publish the session.
import { useCallback, useEffect, useRef, useState } from "react";
import type { IngestStatus } from "../shared/bindings/IngestStatus";
import { api, pickCaptureFile, WalleyeError } from "../shared/ipc";
import { useSelection } from "../shared/selection";
import { useSession } from "../shared/session";

export const POLL_MS = 200;

export type IngestState =
  | { kind: "idle" }
  | { kind: "starting"; path: string }
  | { kind: "running"; path: string; job: string; status: IngestStatus | null }
  | { kind: "failed"; path: string | null; message: string }
  | { kind: "cancelled"; path: string };

export function useIngest() {
  const [state, setState] = useState<IngestState>({ kind: "idle" });
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const alive = useRef(true);
  const cancelRequested = useRef(false);

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  const poll = useCallback((path: string, job: string) => {
    const tick = async () => {
      if (!alive.current) return;
      let s: IngestStatus;
      try {
        s = await api.ingestStatus(job);
      } catch (e) {
        if (alive.current) setState({ kind: "failed", path, message: (e as Error).message });
        return;
      }
      if (!alive.current) return;
      if (s.phase === "done" && s.session) {
        useSelection.getState().reset();
        useSession.getState().setSession(s.session);
        setState({ kind: "idle" });
        return;
      }
      if (s.phase === "failed") {
        setState({ kind: "failed", path, message: s.error ?? "Indexing failed." });
        return;
      }
      if (s.phase === "cancelled") {
        setState({ kind: "cancelled", path });
        return;
      }
      setState({ kind: "running", path, job, status: s });
      timer.current = setTimeout(tick, POLL_MS);
    };
    void tick();
  }, []);

  const openPath = useCallback(
    async (path: string) => {
      setState({ kind: "starting", path });
      cancelRequested.current = false;
      try {
        const job = await api.openCapture(path);
        if (!alive.current) return;
        if (cancelRequested.current) {
          await api.cancelIngest(job).catch(() => {});
          setState({ kind: "cancelled", path });
          return;
        }
        setState({ kind: "running", path, job, status: null });
        poll(path, job);
      } catch (e) {
        const msg = e instanceof WalleyeError ? `${e.message} (${e.code})` : String(e);
        if (alive.current) setState({ kind: "failed", path, message: msg });
      }
    },
    [poll],
  );

  const open = useCallback(async () => {
    let path: string | null;
    try {
      path = await pickCaptureFile();
    } catch (e) {
      setState({ kind: "failed", path: null, message: `Could not open the file picker: ${(e as Error).message}` });
      return;
    }
    if (path) await openPath(path);
  }, [openPath]);

  const cancel = useCallback(async () => {
    if (state.kind === "starting") {
      cancelRequested.current = true;
      return;
    }
    if (state.kind !== "running") return;
    if (timer.current) clearTimeout(timer.current);
    try {
      await api.cancelIngest(state.job);
    } catch {
      // The job may have just finished; the next status read tells us.
    }
    setState({ kind: "cancelled", path: state.path });
  }, [state]);

  const dismiss = useCallback(() => setState({ kind: "idle" }), []);

  return { state, open, openPath, cancel, dismiss };
}

const PHASE_TEXT: Record<string, string> = {
  queued: "Queued",
  hashing: "Hashing (SHA-256)",
  indexing: "Indexing packets",
  detecting: "Running detections",
  done: "Done",
  failed: "Failed",
  cancelled: "Cancelled",
};

export function phaseText(phase: string): string {
  return PHASE_TEXT[phase] ?? phase;
}

export function etaText(eta: number | null | undefined): string {
  if (eta === null || eta === undefined || !Number.isFinite(eta)) return "estimating time left";
  if (eta < 1) return "less than a second left";
  if (eta < 60) return `about ${Math.ceil(eta)} s left`;
  const m = Math.floor(eta / 60);
  if (m < 60) return `about ${m} min ${Math.round(eta % 60)} s left`;
  return `about ${Math.floor(m / 60)} h ${m % 60} min left`;
}
