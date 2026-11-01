// Dev/test-only hooks for Playwright (`window.__walleyeE2E`). Compiled out of
// production builds: `import.meta.env.DEV` is false there and Vite drops the
// branch. They expose read access to shared state plus a few setters so e2e
// specs can assert on the selection without depending on other panels' DOM.
import { api } from "../shared/ipc";
import { useSelection } from "../shared/selection";
import { useSession } from "../shared/session";

declare global {
  interface Window {
    __walleyeE2E?: Record<string, unknown>;
  }
}

export function exposeTestHook(name: string, value: unknown): void {
  if (!import.meta.env.DEV || typeof window === "undefined") return;
  window.__walleyeE2E = { ...window.__walleyeE2E, [name]: value };
}

exposeTestHook("selection", () => {
  const { time_range, hosts, flow_ids, frame_no, filter, device } = useSelection.getState();
  return { time_range, hosts, flow_ids, frame_no, filter, device };
});
exposeTestHook("selectionActions", () => useSelection.getState());
/** Load the open capture into the session store (normally the shell does this). */
exposeTestHook("loadSession", async () => {
  const s = await api.currentCapture();
  useSession.getState().setSession(s);
  return s;
});
