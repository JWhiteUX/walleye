// Right-hand column (UI usability PR 3): the suspicion queue and the case
// share one column as two tabs, Findings and Case. Both panels stay mounted
// (inactive one is `hidden`) so scroll position, expanded findings and the
// case's commands survive a tab switch.
//
// Analysts don't need to see the case while triaging, only to know that a pin
// landed: the Case tab carries the pin count, and the count is highlighted
// ("new") after a pin made from another tab until the Case tab is opened.
import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { CasePanel } from "../case";
import { useCaseEvents } from "../shared/caseEvents";
import { api } from "../shared/ipc";
import { useSession } from "../shared/session";
import { QueuePanel } from "../queue";

export type SideTab = "findings" | "case";

const TABS: { id: SideTab; label: string; pane: "queue" | "case" }[] = [
  { id: "findings", label: "Findings", pane: "queue" },
  { id: "case", label: "Case", pane: "case" },
];

/** Pin count of the open case, re-read whenever a panel changes the case. */
function usePinCount(): number | null {
  const caseId = useSession((s) => s.session?.case_id ?? null);
  const version = useCaseEvents((s) => s.version);
  const [count, setCount] = useState<{ for: string; n: number } | null>(null);
  useEffect(() => {
    if (!caseId) return;
    let alive = true;
    api.getCase(caseId).then(
      (c) => {
        if (alive) setCount({ for: caseId, n: c.pins.length });
      },
      () => {},
    );
    return () => {
      alive = false;
    };
  }, [caseId, version]);
  return count && count.for === caseId ? count.n : null;
}

export function SidePanel({ tab, onTab }: { tab: SideTab; onTab: (t: SideTab) => void }) {
  const pins = usePinCount();
  // Derived during render (React's "adjust state when a prop changes"
  // pattern): `seen` is the pin count last shown on the Case tab, `last` the
  // previous count, so a rise can be announced.
  const [seen, setSeen] = useState<number | null>(null);
  const [last, setLast] = useState<number | null>(null);
  const [announce, setAnnounce] = useState("");
  if (pins !== last) {
    setLast(pins);
    if (pins !== null && last !== null && pins > last) setAnnounce(`Added to case. ${pins} ${pins === 1 ? "pin" : "pins"}.`);
  }
  if (pins === null && seen !== null) setSeen(null);
  if (pins !== null && seen !== pins && (seen === null || tab === "case" || pins < seen)) setSeen(pins);
  const unseen = tab !== "case" && pins !== null && seen !== null && pins > seen;

  const tabRefs = useRef<Record<SideTab, HTMLButtonElement | null>>({ findings: null, case: null });
  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight" && e.key !== "Home" && e.key !== "End") return;
    e.preventDefault();
    const next: SideTab = e.key === "Home" ? "findings" : e.key === "End" ? "case" : tab === "findings" ? "case" : "findings";
    onTab(next);
    tabRefs.current[next]?.focus();
  };

  return (
    <div className="wl-sidecol">
      <div role="tablist" aria-label="Side panel" className="wl-tabs" onKeyDown={onKeyDown}>
        {TABS.map((t) => (
          <button
            key={t.id}
            ref={(el) => {
              tabRefs.current[t.id] = el;
            }}
            type="button"
            role="tab"
            id={`wl-tab-${t.id}`}
            aria-selected={tab === t.id}
            aria-controls={`wl-pane-${t.pane}`}
            tabIndex={tab === t.id ? 0 : -1}
            className="wl-tab"
            onClick={() => onTab(t.id)}
            data-testid={`side-tab-${t.id}`}
          >
            {t.label}
            {t.id === "case" && pins !== null && (
              <span
                className={`wl-tab-count${unseen ? " is-new" : ""}`}
                data-testid="case-pin-count"
                aria-label={unseen ? `${pins} pins, new since you last looked` : `${pins} pins`}
              >
                {pins}
              </span>
            )}
          </button>
        ))}
      </div>
      <span className="wl-visually-hidden" aria-live="polite" data-testid="case-announce">
        {announce}
      </span>
      {TABS.map((t) => (
        <div
          key={t.id}
          role="tabpanel"
          id={`wl-pane-${t.pane}`}
          aria-labelledby={`wl-tab-${t.id}`}
          className="wl-pane wl-tabpanel"
          data-pane={t.pane}
          tabIndex={-1}
          hidden={tab !== t.id}
        >
          {t.id === "findings" ? <QueuePanel /> : <CasePanel />}
        </div>
      ))}
    </div>
  );
}
