// Text helpers for the case panel. Everything here returns plain strings;
// the panel renders them as text nodes only (captured data is hostile).
import type { Evidence } from "../shared/bindings/Evidence";
import type { EvidenceRef } from "../shared/bindings/EvidenceRef";
import type { Finding } from "../shared/bindings/Finding";
import type { Ioc } from "../shared/bindings/Ioc";
import type { IocType } from "../shared/bindings/IocType";
import { formatTs, visible } from "../shared/format";

export const IOC_TYPE_LABEL: Record<IocType, string> = {
  ip: "IP",
  domain: "Domain",
  url: "URL",
  ja4: "JA4",
  cert_serial: "Cert serial",
};

export const IOC_TYPES: IocType[] = ["ip", "domain", "url", "ja4", "cert_serial"];

/** "1 frame", "57 frames", or flows when no frames were recorded. */
export function evidenceCount(e: Evidence): string {
  if (e.frame_nos.length > 0) {
    const n = Math.max(e.total, e.frame_nos.length);
    return `${n} ${n === 1 ? "frame" : "frames"}`;
  }
  const n = Math.max(e.total, e.flow_ids.length);
  return `${n} ${n === 1 ? "flow" : "flows"}`;
}

export function hasEvidence(e: Evidence): boolean {
  return e.frame_nos.length > 0 || e.flow_ids.length > 0;
}

/** One-line description of what a pin points at. */
export function describePin(ref: EvidenceRef, iocs: Ioc[], findings: Finding[] = []): string {
  switch (ref.kind) {
    case "frame":
      return `Frame ${ref.frame_no}`;
    case "flow":
      return `Flow ${ref.flow_id}`;
    case "finding": {
      const f = findings.find((x) => x.finding_id === ref.finding_id);
      return f ? `Finding: ${visible(f.title)} (${visible(f.entity)})` : `Finding ${ref.finding_id}`;
    }
    case "ioc": {
      const i = iocs.find((x) => x.ioc_id === ref.ioc_id);
      return i ? `${IOC_TYPE_LABEL[i.type]} ${i.defanged}` : `Indicator ${ref.ioc_id}`;
    }
    case "query": {
      const scope = ref.time_range ? `, ${formatTs(ref.time_range.start)} → ${formatTs(ref.time_range.end)}` : "";
      return `Query on ${ref.view}: ${ref.filter || "(no filter)"}${scope}`;
    }
    case "note":
      return "Note";
  }
}
