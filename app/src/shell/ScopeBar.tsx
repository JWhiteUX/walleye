// Scope bar (UI usability PR 1). Shows, as removable chips, every part of the
// shared selection that narrows what the panes show: time range, hosts,
// selected flows and the focused 802.11 device. The filter text stays in the
// filter bar. Read-only over the selection store (CONTRACTS §4): it only calls
// the existing actions, and never splices selection into the filter (D11).
import { useMemo } from "react";
import { useShallow } from "zustand/react/shallow";
import { formatDuration, formatTime } from "../shared/format";
import { useSelection } from "../shared/selection";
import { isWifiView, useTableStore } from "../table/store";
import { formatShortcut, isMacPlatform } from "./keys";

interface ChipProps {
  kind: string;
  value: string;
  /** What this part of the scope narrows; shown as the tooltip. */
  affects: string;
  removeLabel: string;
  onRemove: () => void;
  inactive?: boolean;
  testId: string;
}

function Chip({ kind, value, affects, removeLabel, onRemove, inactive, testId }: ChipProps) {
  return (
    <li className={`wl-chip${inactive ? " is-inactive" : ""}`} title={affects} data-testid={testId}>
      <span className="wl-chip-kind">{kind}</span>
      <span className="wl-chip-value wl-mono">{value}</span>
      <button type="button" className="wl-chip-remove" aria-label={removeLabel} onClick={onRemove}>
        ×
      </button>
    </li>
  );
}

export function ScopeBar() {
  const { time_range, hosts, flow_ids, device } = useSelection(
    useShallow((s) => ({ time_range: s.time_range, hosts: s.hosts, flow_ids: s.flow_ids, device: s.device })),
  );
  const view = useTableStore((s) => s.view);
  const mac = useMemo(() => isMacPlatform(), []);
  const wifiView = isWifiView(view);
  const empty = !time_range && hosts.length === 0 && flow_ids.length === 0 && !device;

  const sel = useSelection.getState;
  return (
    <div className="wl-scope" role="region" aria-label="Scope" data-testid="scope-bar">
      <span className="wl-scope-label">Scope</span>
      {empty ? (
        <span className="wl-text-muted" data-testid="scope-empty">
          Whole capture
        </span>
      ) : (
        <ul className="wl-chips" aria-label="Active scope">
          {time_range && (
            <Chip
              kind="Time"
              value={`${formatTime(time_range.start)}–${formatTime(time_range.end)} (${formatDuration(time_range.end - time_range.start)})`}
              affects="Limits the session table, a device's packet list, and the queue when “Only in range” is on."
              removeLabel="Remove time range"
              onRemove={() => sel().setTimeRange(null)}
              testId="scope-time"
            />
          )}
          {hosts.map((h) => (
            <Chip
              key={h}
              kind="Host"
              value={h}
              affects={
                wifiView
                  ? "Not applied: host scope only narrows the IP views (Flows, DNS, HTTP, TLS, Files)."
                  : "Limits the session table to flows that involve this host."
              }
              inactive={wifiView}
              removeLabel={`Remove host ${h}`}
              onRemove={() => sel().toggleHost(h)}
              testId="scope-host"
            />
          ))}
          {flow_ids.length > 0 && (
            <Chip
              kind="Flows"
              value={flow_ids.length === 1 ? `#${flow_ids[0]}` : `${flow_ids.length.toLocaleString()} selected`}
              affects={
                flow_ids.length === 1
                  ? "The packet pane shows this flow; the table highlights it."
                  : `The packet pane shows flow #${flow_ids[0]}; the table highlights all ${flow_ids.length}.`
              }
              removeLabel="Clear selected flows"
              onRemove={() => sel().selectFlows([])}
              testId="scope-flows"
            />
          )}
          {device && (
            <Chip
              kind="Device"
              value={device}
              affects="The packet pane shows this device's frames."
              removeLabel={`Remove device ${device}`}
              onRemove={() => sel().selectDevice(null)}
              testId="scope-device"
            />
          )}
        </ul>
      )}
      <span className="wl-spacer" />
      {!empty && (
        <button type="button" className="wl-scope-clear" onClick={() => sel().clearSelection()} data-testid="scope-clear">
          Clear all <kbd className="wl-kbd">{formatShortcut("mod+shift+x", mac)}</kbd>
        </button>
      )}
    </div>
  );
}
