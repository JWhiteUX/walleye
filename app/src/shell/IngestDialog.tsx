// Progress / error UI for the open-capture flow.
import { formatBytes } from "../shared/format";
import { Dialog } from "./Dialog";
import { etaText, phaseText, type IngestState } from "./useIngest";

export function IngestDialog({
  state,
  onCancel,
  onDismiss,
  onRetry,
}: {
  state: IngestState;
  onCancel: () => void;
  onDismiss: () => void;
  onRetry: () => void;
}) {
  if (state.kind === "idle") return null;

  if (state.kind === "failed" || state.kind === "cancelled") {
    const failed = state.kind === "failed";
    return (
      <Dialog labelledBy="wl-ingest-title" describedBy="wl-ingest-msg" role="alertdialog" onClose={onDismiss} testId="ingest-dialog">
        <h2 id="wl-ingest-title" className="wl-dialog-title">
          {failed ? "⚠ Could not open the capture" : "Indexing cancelled"}
        </h2>
        {state.path && <p className="wl-mono wl-path">{state.path}</p>}
        <p id="wl-ingest-msg" className={failed ? "wl-error-text" : undefined}>
          {failed
            ? state.message
            : "The last checkpoint was kept. Opening the same capture again resumes from it."}
        </p>
        <div className="wl-dialog-actions">
          <button type="button" onClick={onRetry} data-autofocus>
            {failed ? "Try again" : "Resume"}
          </button>
          <button type="button" onClick={onDismiss}>
            Close
          </button>
        </div>
      </Dialog>
    );
  }

  const st = state.kind === "running" ? state.status : null;
  const pct = st ? Math.max(0, Math.min(100, st.pct)) : 0;
  const phase = st ? phaseText(st.phase) : "Starting";
  return (
    <Dialog labelledBy="wl-ingest-title" describedBy="wl-ingest-msg" onClose={onCancel} testId="ingest-dialog">
      <h2 id="wl-ingest-title" className="wl-dialog-title">
        Opening capture
      </h2>
      <p className="wl-mono wl-path">{state.path}</p>
      <progress className="wl-progress" max={100} value={pct} aria-labelledby="wl-ingest-phase" aria-valuetext={`${pct}% · ${phase}`} />
      <p id="wl-ingest-msg" aria-live="polite">
        <strong id="wl-ingest-phase" data-testid="ingest-phase">
          {phase}
        </strong>{" "}
        · <span data-testid="ingest-pct">{pct}%</span>
        {st && (
          <>
            {" "}
            · {formatBytes(st.bytes_done)} of {formatBytes(st.bytes_total)} · <span data-testid="ingest-eta">{etaText(st.eta_s)}</span>
            {st.resumed && " · resumed from checkpoint"}
          </>
        )}
      </p>
      <div className="wl-dialog-actions">
        <button type="button" onClick={onCancel} data-autofocus>
          Cancel (Esc)
        </button>
      </div>
    </Dialog>
  );
}
