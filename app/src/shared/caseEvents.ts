// Cross-panel case actions. Any panel can pin evidence; the case panel
// (Agent F) re-reads the case whenever `version` changes.
import { create } from "zustand";
import type { EvidenceRef } from "./bindings/EvidenceRef";
import type { Pin } from "./bindings/Pin";
import { api } from "./ipc";
import { useSession } from "./session";

interface CaseEvents {
  version: number;
  bump: () => void;
}

export const useCaseEvents = create<CaseEvents>()((set) => ({
  version: 0,
  bump: () => set((s) => ({ version: s.version + 1 })),
}));

/** Pin evidence to the open case. Throws WalleyeError if no capture is open. */
export async function pinEvidence(evidence: EvidenceRef, note = ""): Promise<Pin> {
  const caseId = useSession.getState().session?.case_id;
  if (!caseId) throw new Error("no case is open");
  const pin = await api.casePin(caseId, evidence, note);
  useCaseEvents.getState().bump();
  return pin;
}
