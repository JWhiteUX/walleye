// Saved queries popover: apply, save the applied filter + current view, delete.
import { forwardRef, useCallback, useEffect, useId, useImperativeHandle, useRef, useState } from "react";
import type { SavedQuery } from "../shared/bindings/SavedQuery";
import { api } from "../shared/ipc";
import { useSelection } from "../shared/selection";
import { asTableView, useTableStore } from "../table/store";

export interface SavedQueriesHandle {
  open: (focusSave?: boolean) => void;
}

export const SavedQueries = forwardRef<SavedQueriesHandle>(function SavedQueries(_p, ref) {
  const base = useId().replace(/:/g, "");
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<SavedQuery[]>([]);
  const [name, setName] = useState("");
  const [msg, setMsg] = useState<{ text: string; error: boolean } | null>(null);
  const button = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const nameInput = useRef<HTMLInputElement>(null);
  const focusSaveNext = useRef(false);

  const reload = useCallback(async () => {
    try {
      setItems(await api.listSavedQueries());
    } catch (e) {
      setMsg({ text: `Could not load saved queries: ${(e as Error).message}`, error: true });
    }
  }, []);

  useImperativeHandle(ref, () => ({
    open: (focusSave = false) => {
      focusSaveNext.current = focusSave;
      setOpen(true);
    },
  }));

  useEffect(() => {
    if (!open) return;
    void reload();
    requestAnimationFrame(() => {
      if (focusSaveNext.current) nameInput.current?.focus();
      else panel.current?.querySelector<HTMLElement>("button, input")?.focus();
    });
  }, [open, reload]);

  const close = () => {
    setOpen(false);
    setMsg(null);
    button.current?.focus();
  };

  const apply = (q: SavedQuery) => {
    useTableStore.getState().setView(asTableView(q.view));
    useSelection.getState().setFilter(q.filter);
    close();
  };

  const save = async () => {
    const n = name.trim();
    if (!n) {
      setMsg({ text: "Enter a name.", error: true });
      return;
    }
    const filter = useSelection.getState().filter;
    try {
      await api.saveQuery({ name: n, filter, view: useTableStore.getState().view });
      setName("");
      setMsg({ text: `Saved "${n}".`, error: false });
      await reload();
    } catch (e) {
      setMsg({ text: `Could not save: ${(e as Error).message}`, error: true });
    }
  };

  const remove = async (q: SavedQuery) => {
    try {
      await api.deleteSavedQuery(q.name);
      setMsg({ text: `Deleted "${q.name}".`, error: false });
      await reload();
    } catch (e) {
      setMsg({ text: `Could not delete: ${(e as Error).message}`, error: true });
    }
  };

  return (
    <div className="wl-saved">
      <button
        ref={button}
        type="button"
        aria-expanded={open}
        aria-controls={`${base}-panel`}
        onClick={() => (open ? close() : setOpen(true))}
        title="Saved queries (Ctrl/⌘+Shift+S)"
      >
        Saved ▾
      </button>
      {open && (
        <div
          ref={panel}
          id={`${base}-panel`}
          role="dialog"
          aria-label="Saved queries"
          className="wl-popover"
          data-testid="saved-queries"
          onKeyDown={(e) => {
            if (e.key === "Escape") {
              e.preventDefault();
              e.stopPropagation();
              close();
            }
          }}
        >
          <ul className="wl-saved-list" aria-label="Saved queries">
            {items.map((q) => (
              <li key={q.name} className="wl-saved-item">
                <button type="button" className="wl-saved-apply" onClick={() => apply(q)}>
                  <span className="wl-saved-name">{q.name}</span>
                  <span className="wl-mono wl-saved-filter">
                    {q.view}: {q.filter || "(no filter)"}
                  </span>
                </button>
                <button type="button" aria-label={`Delete saved query ${q.name}`} onClick={() => void remove(q)}>
                  Delete
                </button>
              </li>
            ))}
            {items.length === 0 && <li className="wl-empty">No saved queries yet.</li>}
          </ul>
          <form
            className="wl-saved-form"
            onSubmit={(e) => {
              e.preventDefault();
              void save();
            }}
          >
            <label htmlFor={`${base}-name`}>Save applied filter and view as</label>
            <input id={`${base}-name`} ref={nameInput} value={name} onChange={(e) => setName(e.target.value)} maxLength={120} />
            <button type="submit">Save</button>
          </form>
          {msg && (
            <p role="status" className={msg.error ? "wl-error-text" : undefined}>
              {msg.error ? "⚠ " : ""}
              {msg.text}
            </p>
          )}
        </div>
      )}
    </div>
  );
});
