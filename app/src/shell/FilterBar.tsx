// Filter bar: combobox with backend autocomplete, inline error underline from
// WalleyeError.span, submit -> setFilter. Text the user sees is exactly the
// filter that is sent; the backend binds every literal as a SQL parameter.
import { forwardRef, useCallback, useEffect, useId, useImperativeHandle, useRef, useState, type KeyboardEvent } from "react";
import type { Suggestion } from "../shared/bindings/Suggestion";
import { api } from "../shared/ipc";
import { useSelection } from "../shared/selection";
import { useSession } from "../shared/session";
import { isWifiCapture } from "../shared/wifi";
import { useFilterStatus } from "./filterStatus";
import { applySuggestion, byteToUtf16, splitAtSpan, utf16ToByte } from "./filterText";
import { visible } from "../shared/format";

export const AUTOCOMPLETE_DEBOUNCE_MS = 60;

export interface FilterBarHandle {
  focus: () => void;
}

const KIND_LABEL: Record<Suggestion["kind"], string> = {
  field: "field",
  operator: "op",
  keyword: "keyword",
  value: "value",
  saved: "saved",
};

export const FilterBar = forwardRef<FilterBarHandle>(function FilterBar(_props, ref) {
  const base = useId().replace(/:/g, "");
  const committed = useSelection((s) => s.filter);
  const setFilter = useSelection((s) => s.setFilter);
  const problem = useFilterStatus((s) => s.problem);
  const wifi = useSession((s) => isWifiCapture(s.session?.capture));
  const [draft, setDraft] = useState(committed);
  const [seen, setSeen] = useState(committed);
  // Suggestions plus the exact text they were computed for; stale ones are never shown.
  const [sugg, setSugg] = useState<{ text: string; items: Suggestion[] }>({ text: "", items: [] });
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const input = useRef<HTMLInputElement>(null);
  const mirror = useRef<HTMLDivElement>(null);
  const seq = useRef(0);
  const debounce = useRef<ReturnType<typeof setTimeout> | null>(null);

  useImperativeHandle(ref, () => ({ focus: () => input.current?.focus() }), []);

  // Follow external changes to the committed filter (column filters, saved queries).
  if (committed !== seen) {
    setSeen(committed);
    setDraft(committed);
  }

  const fetchSuggestions = useCallback((text: string, caret: number) => {
    if (debounce.current) clearTimeout(debounce.current);
    const my = ++seq.current;
    debounce.current = setTimeout(() => {
      api.autocomplete(text, utf16ToByte(text, caret)).then(
        (s) => {
          if (my !== seq.current) return;
          setSugg({ text, items: s });
          setActive(-1);
          setOpen(s.length > 0);
        },
        () => {
          if (my === seq.current) setSugg({ text, items: [] });
        },
      );
    }, AUTOCOMPLETE_DEBOUNCE_MS);
  }, []);

  useEffect(
    () => () => {
      if (debounce.current) clearTimeout(debounce.current);
    },
    [],
  );

  const syncMirror = () => {
    if (mirror.current && input.current) mirror.current.scrollLeft = input.current.scrollLeft;
  };

  const close = () => {
    seq.current++;
    setOpen(false);
    setActive(-1);
  };

  const accept = (s: Suggestion) => {
    const r = applySuggestion(draft, s);
    setDraft(r.text);
    close();
    requestAnimationFrame(() => {
      const el = input.current;
      if (!el) return;
      el.focus();
      el.setSelectionRange(r.caret, r.caret);
      syncMirror();
      if (s.kind !== "saved") fetchSuggestions(r.text, r.caret);
    });
  };

  const submit = () => {
    close();
    setFilter(draft.trim());
  };

  const suggestions = sugg.text === draft ? sugg.items : [];
  const listOpen = open && suggestions.length > 0;

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    const n = suggestions.length;
    const open = listOpen;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (!open) fetchSuggestions(draft, e.currentTarget.selectionStart ?? draft.length);
      else if (n) setActive((a) => (a + 1) % n);
    } else if (e.key === "ArrowUp") {
      if (!open || !n) return;
      e.preventDefault();
      setActive((a) => (a <= 0 ? n - 1 : a - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (open && active >= 0 && suggestions[active]) accept(suggestions[active]!);
      else submit();
    } else if (e.key === "Tab" && !e.shiftKey && open && n) {
      e.preventDefault();
      accept(suggestions[active >= 0 ? active : 0]!);
    } else if (e.key === "Escape") {
      if (open) {
        e.preventDefault();
        e.stopPropagation();
        close();
      } else if (draft !== committed) {
        e.preventDefault();
        e.stopPropagation();
        setDraft(committed);
      }
    } else if (e.key === " " && e.ctrlKey) {
      e.preventDefault();
      fetchSuggestions(draft, e.currentTarget.selectionStart ?? draft.length);
    }
  };

  const showProblem = problem && problem.filter === committed ? problem : null;
  const parts = showProblem && draft === showProblem.filter ? splitAtSpan(draft, showProblem.span) : null;
  const errCol = showProblem?.span ? byteToUtf16(showProblem.filter, showProblem.span.start) + 1 : null;
  const listId = `${base}-list`;
  const errId = `${base}-err`;
  const dirty = draft.trim() !== committed;

  return (
    <form
      role="search"
      aria-label="Filter"
      className="wl-filter"
      onSubmit={(e) => {
        e.preventDefault();
        submit();
      }}
    >
      <label htmlFor={`${base}-input`} className="wl-visually-hidden">
        Filter expression
      </label>
      <div className={`wl-filter-field${showProblem ? " is-invalid" : ""}`}>
        <div ref={mirror} className="wl-filter-mirror wl-mono" aria-hidden="true">
          {parts ? (
            <>
              {parts[0]}
              <span className="wl-filter-err" data-testid="filter-error-underline">
                {parts[1]}
              </span>
              {parts[2]}
            </>
          ) : (
            draft
          )}
        </div>
        <input
          ref={input}
          id={`${base}-input`}
          data-testid="filter-input"
          className="wl-filter-input wl-mono"
          role="combobox"
          aria-expanded={listOpen}
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={listOpen && active >= 0 ? `${base}-o${active}` : undefined}
          aria-invalid={showProblem ? true : undefined}
          aria-describedby={showProblem ? errId : `${base}-hint`}
          value={draft}
          placeholder={wifi ? "mac 02:00:5e:00:53:01 and wifi.kind == deauth" : 'host 10.0.0.5 and dns.query ~ "*.top"'}
          spellCheck={false}
          autoComplete="off"
          autoCapitalize="off"
          maxLength={4096}
          onChange={(e) => {
            setDraft(e.target.value);
            setActive(-1);
            fetchSuggestions(e.target.value, e.target.selectionStart ?? e.target.value.length);
            syncMirror();
          }}
          onKeyDown={onKeyDown}
          onKeyUp={syncMirror}
          onScroll={syncMirror}
          onBlur={() => setTimeout(close, 120)}
          onFocus={(e) => fetchSuggestions(e.currentTarget.value, e.currentTarget.selectionStart ?? e.currentTarget.value.length)}
        />
        <ul role="listbox" id={listId} aria-label="Filter suggestions" className="wl-suggest" hidden={!listOpen}>
          {suggestions.map((s, i) => (
            <li
              key={`${s.kind}:${s.label}:${i}`}
              id={`${base}-o${i}`}
              role="option"
              aria-selected={i === active}
              className={`wl-suggest-item${i === active ? " is-active" : ""}`}
              onMouseDown={(e) => {
                e.preventDefault();
                accept(s);
              }}
            >
              <span className="wl-suggest-kind">{KIND_LABEL[s.kind]}</span>
              <span className="wl-mono wl-suggest-label">{visible(s.label)}</span>
              {s.detail && <span className="wl-suggest-detail">{visible(s.detail)}</span>}
            </li>
          ))}
        </ul>
      </div>
      <button type="submit" title="Apply filter (Enter)" aria-label={dirty ? "Apply filter (unapplied changes)" : "Apply filter"}>
        Apply{dirty ? " •" : ""}
      </button>
      <span id={`${base}-hint`} className="wl-visually-hidden">
        Press Down for suggestions, Enter to apply, Escape to revert.
        {wifi ? " On 802.11 captures, mac followed by an address matches any address field; wifi., ap. and client. fields apply to their own tab." : ""}
      </span>
      {showProblem && (
        <p id={errId} className="wl-filter-msg wl-error-text" role="alert" data-testid="filter-error">
          ⚠ {errCol !== null ? `Column ${errCol}: ` : ""}
          {showProblem.message}
        </p>
      )}
    </form>
  );
});
