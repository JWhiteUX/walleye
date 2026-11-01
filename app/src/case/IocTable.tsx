// IOC table. Indicators are shown defanged, as text: never as links.
import { useId, useMemo, useState } from "react";
import type { Ioc } from "../shared/bindings/Ioc";
import type { IocType } from "../shared/bindings/IocType";
import { formatTs, visible } from "../shared/format";
import { useSelection } from "../shared/selection";
import { evidenceCount, hasEvidence, IOC_TYPE_LABEL, IOC_TYPES } from "./describe";

interface Props {
  iocs: Ioc[];
  onPin: (ioc: Ioc) => void;
  busy: boolean;
}

export function IocTable({ iocs, onPin, busy }: Props) {
  const [type, setType] = useState<IocType | "all">("all");
  const applyEvidence = useSelection((s) => s.applyEvidence);
  const selectId = useId();
  const counts = useMemo(() => {
    const c: Partial<Record<IocType, number>> = {};
    for (const i of iocs) c[i.type] = (c[i.type] ?? 0) + 1;
    return c;
  }, [iocs]);
  const rows = type === "all" ? iocs : iocs.filter((i) => i.type === type);

  return (
    <section className="wl-case-section" aria-labelledby={`${selectId}-h`}>
      <div className="wl-case-section-head">
        <h3 id={`${selectId}-h`}>Indicators ({iocs.length})</h3>
        <label htmlFor={selectId} className="wl-case-inline-label">
          Type
        </label>
        <select
          id={selectId}
          value={type}
          onChange={(e) => setType(e.target.value as IocType | "all")}
          data-testid="ioc-type-filter"
        >
          <option value="all">All types ({iocs.length})</option>
          {IOC_TYPES.filter((t) => counts[t]).map((t) => (
            <option key={t} value={t}>
              {IOC_TYPE_LABEL[t]} ({counts[t]})
            </option>
          ))}
        </select>
      </div>
      {rows.length === 0 ? (
        <p className="wl-case-muted">No indicators{type === "all" ? "" : ` of type ${IOC_TYPE_LABEL[type]}`}.</p>
      ) : (
        <div className="wl-case-table-wrap">
          <table className="wl-case-table" data-testid="ioc-table">
            <caption className="wl-visually-hidden">Indicators of compromise, defanged</caption>
            <thead>
              <tr>
                <th scope="col">Type</th>
                <th scope="col">Indicator (defanged)</th>
                <th scope="col">First seen</th>
                <th scope="col">Evidence</th>
                <th scope="col">Allowlist</th>
                <th scope="col">
                  <span className="wl-visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((i) => (
                <tr key={i.ioc_id} data-testid="ioc-row" data-ioc-type={i.type}>
                  <td>{IOC_TYPE_LABEL[i.type]}</td>
                  <td>
                    <code className="wl-mono wl-case-value">{visible(i.defanged)}</code>
                  </td>
                  <td className="wl-mono">{formatTs(i.first_seen)}</td>
                  <td>
                    {hasEvidence(i.evidence) ? (
                      <button
                        type="button"
                        className="wl-case-link"
                        onClick={() => applyEvidence(i.evidence)}
                        aria-label={`Show evidence for ${i.defanged}: ${evidenceCount(i.evidence)}`}
                      >
                        {evidenceCount(i.evidence)}
                      </button>
                    ) : (
                      <span className="wl-case-muted">none</span>
                    )}
                  </td>
                  <td>
                    {i.allowlisted ? (
                      <span className="wl-case-allow">
                        <span className="wl-case-badge" data-testid="allowlisted-badge">
                          Allowlisted
                        </span>{" "}
                        <span>{i.allowlist_reason ?? "known good"}</span>
                      </span>
                    ) : (
                      <span className="wl-case-muted">no</span>
                    )}
                  </td>
                  <td>
                    <button
                      type="button"
                      onClick={() => onPin(i)}
                      disabled={busy}
                      aria-label={`Pin indicator ${i.defanged}`}
                    >
                      Pin
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
