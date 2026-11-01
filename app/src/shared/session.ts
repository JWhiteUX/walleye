// Which capture/case is open. Set by the shell's open-capture flow.
import { create } from "zustand";
import type { CaptureSession } from "./bindings/CaptureSession";

interface SessionState {
  session: CaptureSession | null;
  setSession: (s: CaptureSession | null) => void;
}

export const useSession = create<SessionState>()((set) => ({
  session: null,
  setSession: (session) => set({ session }),
}));
