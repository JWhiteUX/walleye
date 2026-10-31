// Loads the open case and its IOCs, and re-reads whenever any panel bumps
// `useCaseEvents.version` (pinEvidence does) or this panel mutates the case.
import { useEffect, useState } from "react";
import type { Case } from "../shared/bindings/Case";
import type { Finding } from "../shared/bindings/Finding";
import type { Ioc } from "../shared/bindings/Ioc";
import { useCaseEvents } from "../shared/caseEvents";
import { api } from "../shared/ipc";
import { useSession } from "../shared/session";

export interface CaseData {
  caseId: string | null;
  caseData: Case | null;
  iocs: Ioc[];
  /** For pin titles; empty if findings could not be read. */
  findings: Finding[];
  error: string | null;
  loaded: boolean;
}

/** The open case id: from the shell's session, else asked of the backend. */
export function useCaseId(): string | null {
  const session = useSession((s) => s.session);
  const version = useCaseEvents((s) => s.version);
  const [fallback, setFallback] = useState<string | null>(null);
  useEffect(() => {
    if (session) return;
    let alive = true;
    api
      .currentCapture()
      .then((s) => {
        if (alive) setFallback(s?.case_id ?? null);
      })
      .catch(() => {
        if (alive) setFallback(null);
      });
    return () => {
      alive = false;
    };
  }, [session, version]);
  return session?.case_id ?? fallback;
}

export function useCaseData(caseId: string | null): CaseData {
  const version = useCaseEvents((s) => s.version);
  const [state, setState] = useState<Omit<CaseData, "caseId"> & { for: string | null }>({
    for: null,
    caseData: null,
    iocs: [],
    findings: [],
    error: null,
    loaded: false,
  });
  useEffect(() => {
    if (!caseId) return;
    let alive = true;
    Promise.all([api.getCase(caseId), api.iocs(caseId), api.findings().catch(() => [] as Finding[])])
      .then(([c, iocs, findings]) => {
        if (alive) setState({ for: caseId, caseData: c, iocs, findings, error: null, loaded: true });
      })
      .catch((e: unknown) => {
        if (alive)
          setState((s) => ({ ...s, for: caseId, error: e instanceof Error ? e.message : String(e), loaded: true }));
      });
    return () => {
      alive = false;
    };
  }, [caseId, version]);
  if (!caseId || state.for !== caseId) {
    return { caseId, caseData: null, iocs: [], findings: [], error: null, loaded: false };
  }
  return {
    caseId,
    caseData: state.caseData,
    iocs: state.iocs,
    findings: state.findings,
    error: state.error,
    loaded: state.loaded,
  };
}

/** Tell every listener (this panel included) that the case changed. */
export function caseChanged(): void {
  useCaseEvents.getState().bump();
}
