// Case panel (Agent F): IOC table, exports, pins and analyst notes.
import { useCallback, useMemo, useState } from "react";
import type { EvidenceRef } from "../shared/bindings/EvidenceRef";
import type { Ioc } from "../shared/bindings/Ioc";
import type { IocFormat } from "../shared/bindings/IocFormat";
import type { Pin } from "../shared/bindings/Pin";
import type { ReportFormat } from "../shared/bindings/ReportFormat";
import { type Command, useRegisterCommands } from "../shared/commands";
import { api } from "../shared/ipc";
import { getTimelineSnapshot } from "../shared/snapshots";
import { IocTable } from "./IocTable";
import { PinList } from "./PinList";
import { caseChanged, useCaseData, useCaseId } from "./useCaseData";
import "./case.css";

type Status = { kind: "ok" | "error"; text: string } | null;

type ExportKind = { what: "iocs"; format: IocFormat } | { what: "report"; format: ReportFormat };

const EXPORTS: { id: string; label: string; kind: ExportKind }[] = [
  { id: "case.export-iocs-csv", label: "IOCs CSV", kind: { what: "iocs", format: "csv" } },
  { id: "case.export-iocs-json", label: "IOCs JSON", kind: { what: "iocs", format: "json" } },
  { id: "case.export-report-md", label: "Report Markdown", kind: { what: "report", format: "markdown" } },
  { id: "case.export-report-pdf", label: "Report PDF", kind: { what: "report", format: "pdf" } },
];

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

export function CasePanel() {
  const caseId = useCaseId();
  const { caseData, iocs, error, loaded } = useCaseData(caseId);
  const [status, setStatus] = useState<Status>(null);
  const [busy, setBusy] = useState(false);

  /** Run a case mutation; report failures; re-read on success. */
  const run = useCallback(async (label: string, fn: () => Promise<unknown>): Promise<boolean> => {
    setBusy(true);
    try {
      await fn();
      caseChanged();
      return true;
    } catch (e) {
      setStatus({ kind: "error", text: `${label} failed: ${message(e)}` });
      return false;
    } finally {
      setBusy(false);
    }
  }, []);

  const doExport = useCallback(
    async (label: string, kind: ExportKind) => {
      if (!caseId) return;
      setBusy(true);
      setStatus(null);
      try {
        const path =
          kind.what === "iocs"
            ? await api.exportIocs(caseId, kind.format)
            : await api.exportReport(caseId, kind.format, getTimelineSnapshot() ?? undefined);
        setStatus({ kind: "ok", text: `${label} saved to ${path}` });
      } catch (e) {
        setStatus({ kind: "error", text: `${label} export failed: ${message(e)}` });
      } finally {
        setBusy(false);
      }
    },
    [caseId],
  );

  const commands = useMemo<Command[]>(
    () =>
      EXPORTS.map((x) => ({
        id: x.id,
        title: `Export ${x.label}`,
        group: "Case",
        run: () => void doExport(x.label, x.kind),
        enabled: () => !!caseId,
      })),
    [doExport, caseId],
  );
  useRegisterCommands(commands);

  const pin = (evidence: EvidenceRef, note: string) => {
    if (!caseId) return Promise.resolve(false);
    return run("Pin", () => api.casePin(caseId, evidence, note));
  };
  const onPinIoc = (i: Ioc) => void pin({ kind: "ioc", ioc_id: i.ioc_id }, "");
  const onAddNote = (text: string) => pin({ kind: "note" }, text.trim());
  // No in-place edit command exists yet (requested from the lead as
  // `case_update_note`): pin the same evidence with the new note, then
  // remove the old pin. If re-pinning fails the old pin is kept.
  const onEditNote = async (p: Pin, text: string) => {
    if (!caseId) return false;
    if (text === p.note) return true;
    return run("Edit note", async () => {
      await api.casePin(caseId, p.evidence, p.evidence.kind === "note" ? text.trim() : text);
      await api.caseUnpin(caseId, p.pin_id);
    });
  };
  const onUnpin = (p: Pin) => {
    if (!caseId) return;
    void run("Unpin", () => api.caseUnpin(caseId, p.pin_id));
  };

  return (
    <section aria-label="Case" data-testid="case-panel" className="wl-case">
      <div className="wl-case-header">
        <h2>Case</h2>
        {caseId && <span className="wl-case-muted wl-mono">{caseId}</span>}
      </div>
      {!caseId ? (
        <p className="wl-case-muted">Open a capture to start a case.</p>
      ) : (
        <>
          <div className="wl-case-exports" role="group" aria-label="Export">
            <span className="wl-case-inline-label" aria-hidden="true">
              Export
            </span>
            {EXPORTS.map((x) => (
              <button
                key={x.id}
                type="button"
                disabled={busy}
                onClick={() => void doExport(x.label, x.kind)}
                aria-label={`Export ${x.label}`}
                data-testid={x.id}
              >
                {x.label}
              </button>
            ))}
          </div>
          <div role="status" aria-live="polite" className="wl-case-status" data-testid="case-status">
            {status?.kind === "ok" && <span>{status.text}</span>}
          </div>
          <div role="alert" className="wl-case-status wl-case-error" data-testid="case-error">
            {status?.kind === "error" && <span>{status.text}</span>}
            {error && <span>Could not load the case: {error}</span>}
          </div>
          {!loaded ? (
            <p className="wl-case-muted">Loading case…</p>
          ) : (
            <>
              <IocTable iocs={iocs} onPin={onPinIoc} busy={busy} />
              <PinList
                pins={caseData?.pins ?? []}
                iocs={iocs}
                busy={busy}
                onAddNote={onAddNote}
                onEditNote={onEditNote}
                onUnpin={onUnpin}
              />
            </>
          )}
        </>
      )}
    </section>
  );
}
