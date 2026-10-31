// Suspicion queue: findings ranked by score, each expanding to its reasons
// with evidence links that drive the shared selection (table + packet pane
// follow), verdict buttons (optimistic, rolled back on error) and "pin".
// Every captured string (titles, entities, explanations) is rendered as text;
// indicators are never links.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Finding } from "../shared/bindings/Finding";
import type { Reason } from "../shared/bindings/Reason";
import type { TimeRange } from "../shared/bindings/TimeRange";
import type { Verdict } from "../shared/bindings/Verdict";
import { pinEvidence } from "../shared/caseEvents";
import { type Command, useRegisterCommands } from "../shared/commands";
import { scoreBand } from "../shared/encoding";
import { formatTime, visible } from "../shared/format";
import { api, WalleyeError } from "../shared/ipc";
import { useSelection } from "../shared/selection";
import { useSession } from "../shared/session";
import { createLatestRunner } from "../timeline/latest";
import "../timeline/testHooks";
import { barPct, evidenceLabel, formatValue, VERDICTS, verdictLabel } from "./format";
import "./queue.css";

type Load =
  | { kind: "ok"; key: string; findings: Finding[] }
  | { kind: "error"; key: string; message: string; noCapture: boolean };

const QUERY_DEBOUNCE_MS = 80;
/** Max gap between "v" and the verdict key. */
const SEQUENCE_MS = 1500;

export function QueuePanel() {
  const captureId = useSession((s) => s.session?.capture.capture_id ?? null);
  return <QueueView key={captureId ?? "none"} />;
}

function QueueView() {
  const timeRange = useSelection((s) => s.time_range);
  const applyEvidence = useSelection((s) => s.applyEvidence);
  const setHosts = useSelection((s) => s.setHosts);

  const [onlyInRange, setOnlyInRange] = useState(true);
  const range: TimeRange | null = onlyInRange ? timeRange : null;
  const key = JSON.stringify(range);

  const [load, setLoad] = useState<Load | null>(null);
  const [runner] = useState(() =>
    createLatestRunner<{ key: string; range: TimeRange | null }, Finding[]>(
      (r) => api.findings(r.range ? { time_range: r.range } : undefined),
      (findings, r) => setLoad({ kind: "ok", key: r.key, findings }),
      (e, r) =>
        setLoad({
          kind: "error",
          key: r.key,
          message: e instanceof Error ? e.message : String(e),
          noCapture: e instanceof WalleyeError && e.code === "no_capture",
        }),
    ),
  );
  const hasData = load !== null;
  useEffect(() => {
    runner.schedule({ key, range }, hasData ? QUERY_DEBOUNCE_MS : 0);
    // `range` is derived from `key`; depending on the string avoids refetching on identity changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runner, key, hasData]);
  useEffect(() => () => runner.cancel(), [runner]);

  // Optimistic verdicts: shown immediately, rolled back if the backend refuses.
  const [overrides, setOverrides] = useState<Record<string, Verdict | null>>({});
  const verdictSeq = useRef(new Map<string, number>());
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());
  const [activeId, setActiveId] = useState<string | null>(null);
  const [status, setStatus] = useState<{ text: string; error: boolean } | null>(null);
  const headRefs = useRef(new Map<string, HTMLButtonElement>());
  const vPressedAt = useRef<number | null>(null);

  const findings = useMemo(() => {
    const list = load?.kind === "ok" ? load.findings : [];
    return list.map((f) => (f.finding_id in overrides ? { ...f, verdict: overrides[f.finding_id] ?? null } : f));
  }, [load, overrides]);
  const loading = load === null || load.key !== key;
  const active = findings.find((f) => f.finding_id === activeId) ?? findings[0] ?? null;

  const latest = useRef({ findings, active });
  useEffect(() => {
    latest.current = { findings, active };
  });

  const setVerdict = useCallback((f: Finding, v: Verdict) => {
    const prev = f.verdict;
    if (prev === v) return;
    const seq = (verdictSeq.current.get(f.finding_id) ?? 0) + 1;
    verdictSeq.current.set(f.finding_id, seq);
    setOverrides((o) => ({ ...o, [f.finding_id]: v }));
    setStatus({ text: `Marked “${visible(f.title)}” as ${verdictLabel(v)}.`, error: false });
    api.setVerdict(f.finding_id, v).catch((e: unknown) => {
      if (verdictSeq.current.get(f.finding_id) !== seq) return; // a newer verdict superseded this one
      setOverrides((o) => ({ ...o, [f.finding_id]: prev }));
      setStatus({
        text: `Could not save verdict for “${visible(f.title)}”: ${e instanceof Error ? e.message : String(e)}. Reverted to ${verdictLabel(prev)}.`,
        error: true,
      });
    });
  }, []);

  const pin = useCallback(async (f: Finding) => {
    try {
      await pinEvidence({ kind: "finding", finding_id: f.finding_id });
      setStatus({ text: `Pinned “${visible(f.title)}” to the case.`, error: false });
    } catch (e) {
      setStatus({ text: `Could not pin: ${e instanceof Error ? e.message : String(e)}`, error: true });
    }
  }, []);

  const showEvidence = useCallback(
    (f: Finding, r: Reason) => {
      applyEvidence(r.evidence);
      if (f.entity_type === "host") setHosts([f.entity]);
      const frame = r.evidence.frame_nos[0];
      setStatus({
        text: `Selected ${evidenceLabel(r.evidence)} for ${visible(f.entity)}${frame !== undefined ? `; frame ${frame} opened` : ""}.`,
        error: false,
      });
    },
    [applyEvidence, setHosts],
  );

  const toggle = (id: string) =>
    setExpanded((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  const focusItem = useCallback((id: string | undefined) => {
    if (!id) return;
    setActiveId(id);
    headRefs.current.get(id)?.focus();
  }, []);
  const move = useCallback(
    (delta: number) => {
      const { findings: list, active: a } = latest.current;
      if (!list.length) return;
      const i = a ? list.findIndex((f) => f.finding_id === a.finding_id) : -1;
      const next = Math.max(0, Math.min(list.length - 1, i + delta));
      focusItem(list[next]?.finding_id);
    },
    [focusItem],
  );
  const verdictActive = useCallback(
    (v: Verdict) => {
      const a = latest.current.active;
      if (a) setVerdict(a, v);
    },
    [setVerdict],
  );

  const commands = useMemo<Command[]>(
    () => [
      {
        id: "queue.focus",
        title: "Focus suspicion queue",
        group: "Queue",
        shortcut: "g q",
        run: () => focusItem(latest.current.active?.finding_id),
      },
      { id: "queue.next", title: "Next finding (j / ↓)", group: "Queue", run: () => move(1) },
      { id: "queue.prev", title: "Previous finding (k / ↑)", group: "Queue", run: () => move(-1) },
      ...VERDICTS.map((v) => ({
        id: `queue.verdict-${v.value.replace("_", "-")}`,
        title: `Mark current finding ${v.label.toLowerCase()}`,
        group: "Queue",
        shortcut: `v ${v.key}`,
        run: () => verdictActive(v.value),
        enabled: () => latest.current.active !== null,
      })),
      {
        id: "queue.pin",
        title: "Pin current finding to case (p)",
        group: "Queue",
        run: () => {
          const a = latest.current.active;
          if (a) void pin(a);
        },
        enabled: () => latest.current.active !== null,
      },
    ],
    [focusItem, move, verdictActive, pin],
  );
  useRegisterCommands(commands);

  const onKeyDown = (e: React.KeyboardEvent<HTMLElement>) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    const t = e.target as HTMLElement;
    if (t.tagName === "INPUT" || t.tagName === "TEXTAREA") return;
    let handled = true;
    const now = Date.now();
    const afterV = vPressedAt.current !== null && now - vPressedAt.current < SEQUENCE_MS;
    vPressedAt.current = null;
    const verdictKey = afterV ? VERDICTS.find((v) => v.key === e.key.toLowerCase()) : undefined;
    if (verdictKey) verdictActive(verdictKey.value);
    else
      switch (e.key) {
        case "j":
        case "ArrowDown":
          move(1);
          break;
        case "k":
        case "ArrowUp":
          move(-1);
          break;
        case "Home":
          move(-Infinity);
          break;
        case "End":
          move(Infinity);
          break;
        case "v":
          vPressedAt.current = now;
          break;
        case "p":
          if (active) void pin(active);
          break;
        default:
          handled = false;
      }
    if (handled) {
      e.preventDefault();
      e.stopPropagation();
    }
  };

  const total = findings.length;
  return (
    <section aria-labelledby="wl-q-title" data-testid="queue-panel" data-loading={loading ? "true" : "false"} className="wl-q">
      <header className="wl-q-head">
        <h2 id="wl-q-title" className="wl-q-title">
          Suspicion queue
        </h2>
        <span className="wl-q-count" data-testid="queue-count">
          {load?.kind === "ok" ? `${total} finding${total === 1 ? "" : "s"}` : ""}
          {range && load?.kind === "ok" ? " in time range" : ""}
        </span>
        <label className="wl-q-range">
          <input
            type="checkbox"
            checked={onlyInRange}
            onChange={(e) => setOnlyInRange(e.target.checked)}
            disabled={!timeRange}
          />
          Only in selected time range
        </label>
      </header>
      <p className="wl-q-status" role="status" data-testid="queue-status" data-error={status?.error ? "true" : "false"}>
        {status?.text ?? ""}
      </p>
      {load?.kind === "error" ? (
        <p className="wl-q-empty" role={load.noCapture ? undefined : "alert"}>
          {load.noCapture ? "Open a capture to see findings." : `Could not load findings: ${load.message}`}
        </p>
      ) : load === null ? (
        <p className="wl-q-empty">Loading findings…</p>
      ) : total === 0 ? (
        <p className="wl-q-empty">{range ? "No findings in the selected time range." : "No findings for this capture."}</p>
      ) : (
        <ol className="wl-q-list" aria-label="Findings, highest score first" onKeyDown={onKeyDown}>
          {findings.map((f, i) => {
            const isOpen = expanded.has(f.finding_id);
            const band = scoreBand(f.score);
            const detailsId = `wl-q-d-${f.finding_id}`;
            const isActive = active?.finding_id === f.finding_id;
            return (
              <li key={f.finding_id} className="wl-q-item" data-finding-id={f.finding_id} data-active={isActive || undefined}>
                <button
                  type="button"
                  ref={(el) => {
                    if (el) headRefs.current.set(f.finding_id, el);
                    else headRefs.current.delete(f.finding_id);
                  }}
                  className="wl-q-row"
                  aria-expanded={isOpen}
                  aria-controls={detailsId}
                  tabIndex={isActive ? 0 : -1}
                  onFocus={() => setActiveId(f.finding_id)}
                  onClick={() => toggle(f.finding_id)}
                >
                  <span className="wl-q-rank" aria-hidden="true">
                    {i + 1}
                  </span>
                  <span className="wl-q-score">
                    <span className="wl-q-bar" aria-hidden="true">
                      <span style={{ width: `${barPct(f.score)}%`, background: `var(${band.cssVar})` }} />
                    </span>
                    <span className="wl-q-num">{Math.round(f.score)}</span>
                    <span className={`wl-q-band wl-q-band-${band.label.toLowerCase()}`}>{band.label}</span>
                  </span>
                  <span className="wl-q-main">
                    <span className="wl-q-ftitle">{visible(f.title)}</span>
                    <span className="wl-q-meta">
                      <span className="wl-mono">{visible(f.entity)}</span>
                      {f.attack_technique && (
                        <>
                          {" · "}
                          <span className="wl-mono" title="MITRE ATT&CK technique">
                            {f.attack_technique}
                          </span>
                        </>
                      )}
                      {" · "}
                      <span data-testid="queue-verdict">{verdictLabel(f.verdict)}</span>
                    </span>
                  </span>
                  <span className="wl-q-chev" aria-hidden="true">
                    {isOpen ? "▾" : "▸"}
                  </span>
                </button>
                {isOpen && (
                  <div id={detailsId} className="wl-q-details" role="region" aria-label={`Details: ${f.title}`}>
                    <p className="wl-q-when">
                      Active <span className="wl-mono">{formatTime(f.ts_first)}</span> –{" "}
                      <span className="wl-mono">{formatTime(f.ts_last)}</span> UTC · detector {f.detector}
                    </p>
                    <div className="wl-q-actions">
                      <div role="group" aria-label="Verdict" className="wl-q-verdicts">
                        {VERDICTS.map((v) => (
                          <button
                            type="button"
                            key={v.value}
                            aria-pressed={f.verdict === v.value}
                            aria-keyshortcuts={`v ${v.key}`}
                            title={`${v.label} (v then ${v.key})`}
                            onClick={() => setVerdict(f, v.value)}
                          >
                            {f.verdict === v.value ? "✓ " : ""}
                            {v.label}
                          </button>
                        ))}
                      </div>
                      <button type="button" onClick={() => void pin(f)} aria-keyshortcuts="p" title="Pin finding to case (p)">
                        Pin finding
                      </button>
                    </div>
                    <ol className="wl-q-reasons" aria-label="Reasons">
                      {f.reasons.map((r, ri) => (
                        <li key={`${r.rule_id}-${r.signal}-${ri}`} className="wl-q-reason">
                          <p className="wl-q-expl">{visible(r.explanation)}</p>
                          <p className="wl-q-rmeta">
                            <span>
                              {r.signal}: <span className="wl-mono">{formatValue(r.value, r.unit)}</span>
                            </span>
                            <span>
                              +{Math.round(r.weight)} pts
                            </span>
                            {r.attack_technique && <span className="wl-mono">{r.attack_technique}</span>}
                            <button
                              type="button"
                              className="wl-q-evidence"
                              data-testid="queue-evidence"
                              onClick={() => showEvidence(f, r)}
                            >
                              Show evidence: {evidenceLabel(r.evidence)}
                            </button>
                          </p>
                        </li>
                      ))}
                    </ol>
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
