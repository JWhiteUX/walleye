// Pinned evidence and analyst notes: add a note, edit a note, unpin.
import { useId, useState } from "react";
import type { Ioc } from "../shared/bindings/Ioc";
import type { Pin } from "../shared/bindings/Pin";
import { formatTs } from "../shared/format";
import { useSelection } from "../shared/selection";
import { describePin, evidenceCount, hasEvidence } from "./describe";

interface Props {
  pins: Pin[];
  iocs: Ioc[];
  busy: boolean;
  onAddNote: (text: string) => Promise<boolean>;
  onEditNote: (pin: Pin, text: string) => Promise<boolean>;
  onUnpin: (pin: Pin) => void;
}

export function PinList({ pins, iocs, busy, onAddNote, onEditNote, onUnpin }: Props) {
  const headId = useId();
  const noteId = useId();
  const [draft, setDraft] = useState("");
  const [editing, setEditing] = useState<{ pin_id: string; text: string } | null>(null);
  const applyEvidence = useSelection((s) => s.applyEvidence);

  const submitDraft = async () => {
    if (!draft.trim()) return;
    if (await onAddNote(draft)) setDraft("");
  };
  const submitEdit = async (p: Pin) => {
    if (!editing) return;
    if (await onEditNote(p, editing.text)) setEditing(null);
  };

  return (
    <section className="wl-case-section" aria-labelledby={headId}>
      <h3 id={headId}>Pins and notes ({pins.length})</h3>
      <form
        className="wl-case-note-form"
        onSubmit={(e) => {
          e.preventDefault();
          void submitDraft();
        }}
      >
        <label htmlFor={noteId}>New note</label>
        <textarea
          id={noteId}
          value={draft}
          rows={2}
          maxLength={16000}
          placeholder="Analyst note (not a claim). Ctrl/⌘+Enter to add."
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
              e.preventDefault();
              void submitDraft();
            }
          }}
        />
        <button type="submit" disabled={busy || !draft.trim()}>
          Add note
        </button>
      </form>
      {pins.length === 0 ? (
        <p className="wl-case-muted">Nothing pinned yet. Pin frames, flows, findings or indicators from any view.</p>
      ) : (
        <ol className="wl-case-pins" data-testid="pin-list">
          {pins.map((p) => {
            const isNote = p.evidence.kind === "note";
            const what = describePin(p.evidence, iocs);
            const isEditing = editing?.pin_id === p.pin_id;
            return (
              <li key={p.pin_id} data-testid="pin-item" data-pin-id={p.pin_id} data-kind={p.evidence.kind}>
                <div className="wl-case-pin-head">
                  <span className="wl-case-kind">{isNote ? "Note" : "Pin"}</span>
                  <span className="wl-case-pin-what">{isNote ? "Analyst note" : what}</span>
                  <span className="wl-case-muted wl-mono">{formatTs(p.created_at)}</span>
                </div>
                {isEditing ? (
                  <div className="wl-case-edit">
                    <label htmlFor={`${noteId}-${p.pin_id}`} className="wl-visually-hidden">
                      Edit note for {isNote ? "analyst note" : what}
                    </label>
                    <textarea
                      id={`${noteId}-${p.pin_id}`}
                      value={editing.text}
                      rows={3}
                      maxLength={16000}
                      autoFocus
                      onChange={(e) => setEditing({ pin_id: p.pin_id, text: e.target.value })}
                      onKeyDown={(e) => {
                        if (e.key === "Escape") setEditing(null);
                        if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                          e.preventDefault();
                          void submitEdit(p);
                        }
                      }}
                    />
                    <div className="wl-case-actions">
                      <button
                        type="button"
                        onClick={() => void submitEdit(p)}
                        disabled={busy || (isNote && !editing.text.trim())}
                      >
                        Save
                      </button>
                      <button type="button" onClick={() => setEditing(null)}>
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  p.note && (
                    <p className="wl-case-note" data-testid="pin-note">
                      <span className="wl-visually-hidden">Note: </span>
                      {p.note}
                    </p>
                  )
                )}
                {!isEditing && (
                  <div className="wl-case-actions">
                    {!isNote && hasEvidence(p.resolved) && (
                      <button
                        type="button"
                        className="wl-case-link"
                        onClick={() => applyEvidence(p.resolved)}
                        aria-label={`Show evidence for ${what}: ${evidenceCount(p.resolved)}`}
                      >
                        {evidenceCount(p.resolved)}
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => setEditing({ pin_id: p.pin_id, text: p.note })}
                      disabled={busy}
                      aria-label={`${p.note ? "Edit" : "Add"} note for ${isNote ? "analyst note" : what}`}
                    >
                      {p.note ? "Edit note" : "Add note"}
                    </button>
                    <button
                      type="button"
                      onClick={() => onUnpin(p)}
                      disabled={busy}
                      aria-label={`${isNote ? "Delete note" : "Unpin"} ${isNote ? "" : what}`.trim()}
                    >
                      {isNote ? "Delete" : "Unpin"}
                    </button>
                  </div>
                )}
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}
