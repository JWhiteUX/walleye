// Column specs per view. Every cell renders as plain text (captured strings
// are hostile); indicators are never links.
import type { DnsRow } from "../shared/bindings/DnsRow";
import type { FileRow } from "../shared/bindings/FileRow";
import type { FlowRow } from "../shared/bindings/FlowRow";
import type { HttpRow } from "../shared/bindings/HttpRow";
import type { TlsRow } from "../shared/bindings/TlsRow";
import { formatBytes, formatDuration, formatTs, protoName, visible } from "../shared/format";
import type { TableView } from "./store";

export type AnyRow = FlowRow | DnsRow | HttpRow | TlsRow | FileRow;

export interface ColumnSpec {
  /** Row key; also the `Sort.column` sent to the backend when `sortable`. */
  id: string;
  header: string;
  width: number;
  /** Filter-language field for column filters, when one applies to this view. */
  field?: string;
  sortable: boolean;
  align?: "right";
  mono?: boolean;
  text: (row: Record<string, unknown>) => string;
}

const str = (k: string) => (r: Record<string, unknown>) => {
  const v = r[k];
  return v === null || v === undefined ? "" : visible(String(v));
};
const num = str;
const bytes = (k: string) => (r: Record<string, unknown>) => (typeof r[k] === "number" ? formatBytes(r[k] as number) : "");
const ts = (k: string) => (r: Record<string, unknown>) => (typeof r[k] === "number" ? formatTs(r[k] as number) : "");
const bool = (k: string) => (r: Record<string, unknown>) => (r[k] === true ? "yes" : r[k] === false ? "no" : "");

const col = (id: string, header: string, width: number, text: ColumnSpec["text"], o: Partial<ColumnSpec> = {}): ColumnSpec => ({
  id,
  header,
  width,
  text,
  sortable: true,
  ...o,
});

export const COLUMNS: Record<TableView, ColumnSpec[]> = {
  flows: [
    col("flow_id", "Flow", 70, num("flow_id"), { field: "flow_id", align: "right", mono: true }),
    col("ts_start", "Start (UTC)", 210, ts("ts_start"), { mono: true }),
    col(
      "duration",
      "Duration",
      90,
      (r) => formatDuration(Math.max(0, (r.ts_end as number) - (r.ts_start as number))),
      { sortable: false, field: "duration", align: "right" },
    ),
    col("src_ip", "Source", 130, str("src_ip"), { field: "src_ip", mono: true }),
    col("src_port", "Src port", 80, num("src_port"), { field: "src_port", align: "right", mono: true }),
    col("dst_ip", "Destination", 130, str("dst_ip"), { field: "dst_ip", mono: true }),
    col("dst_port", "Dst port", 80, num("dst_port"), { field: "dst_port", align: "right", mono: true }),
    col("proto", "Proto", 64, (r) => protoName(r.proto as number), { field: "proto" }),
    col("app_proto", "App", 64, str("app_proto"), { field: "app_proto" }),
    col("bytes_up", "Bytes up", 90, bytes("bytes_up"), { field: "bytes_up", align: "right" }),
    col("bytes_down", "Bytes down", 96, bytes("bytes_down"), { field: "bytes_down", align: "right" }),
    col("pkts_up", "Pkts up", 72, num("pkts_up"), { field: "pkts_up", align: "right" }),
    col("pkts_down", "Pkts down", 80, num("pkts_down"), { field: "pkts_down", align: "right" }),
  ],
  dns: [
    col("ts", "Time (UTC)", 210, ts("ts"), { mono: true }),
    col("flow_id", "Flow", 70, num("flow_id"), { field: "flow_id", align: "right", mono: true }),
    col("frame_no", "Frame", 70, num("frame_no"), { align: "right", mono: true }),
    col("is_response", "Resp", 56, bool("is_response"), { field: "dns.is_response" }),
    col("query", "Query", 300, str("query"), { field: "dns.query", mono: true }),
    col("qtype", "Type", 64, str("qtype"), { field: "dns.qtype" }),
    col("rcode", "Rcode", 96, str("rcode"), { field: "dns.rcode" }),
    col("answers", "Answers", 260, (r) => visible(((r.answers as string[] | undefined) ?? []).join(", ")), {
      field: "dns.answer",
      sortable: false,
      mono: true,
    }),
    col("ttl", "TTL", 64, num("ttl"), { field: "dns.ttl", align: "right" }),
  ],
  http: [
    col("ts", "Time (UTC)", 210, ts("ts"), { mono: true }),
    col("flow_id", "Flow", 70, num("flow_id"), { field: "flow_id", align: "right", mono: true }),
    col("method", "Method", 72, str("method"), { field: "http.method" }),
    col("host", "Host", 200, str("host"), { field: "http.host", mono: true }),
    col("uri", "URI", 280, str("uri"), { field: "http.uri", mono: true }),
    col("status", "Status", 64, num("status"), { field: "http.status", align: "right" }),
    col("user_agent", "User agent", 240, str("user_agent"), { field: "http.user_agent" }),
    col("req_bytes", "Req bytes", 90, bytes("req_bytes"), { field: "http.req_bytes", align: "right" }),
    col("resp_bytes", "Resp bytes", 96, bytes("resp_bytes"), { field: "http.resp_bytes", align: "right" }),
  ],
  tls: [
    col("ts", "Time (UTC)", 210, ts("ts"), { mono: true }),
    col("flow_id", "Flow", 70, num("flow_id"), { field: "flow_id", align: "right", mono: true }),
    col("sni", "SNI", 220, str("sni"), { field: "tls.sni", mono: true }),
    col("version", "Version", 80, str("version"), { field: "tls.version" }),
    col("ja4", "JA4", 300, str("ja4"), { field: "tls.ja4", mono: true }),
    col("ja4s", "JA4S", 200, str("ja4s"), { field: "tls.ja4s", mono: true }),
    col("cert_subject", "Cert subject", 220, str("cert_subject"), { field: "tls.cert_subject" }),
    col("cert_issuer", "Cert issuer", 220, str("cert_issuer"), { field: "tls.cert_issuer" }),
    col("cert_self_signed", "Self-signed", 90, bool("cert_self_signed"), { field: "tls.cert_self_signed" }),
  ],
  files: [
    col("ts", "Time (UTC)", 210, ts("ts"), { mono: true }),
    col("flow_id", "Flow", 70, num("flow_id"), { field: "flow_id", align: "right", mono: true }),
    col("source", "Source", 70, str("source")),
    col("direction", "Dir", 56, str("direction")),
    col("filename", "File name", 260, str("filename"), { field: "file.name", mono: true }),
    col("mime_type", "MIME type", 180, str("mime_type"), { field: "file.mime_type" }),
    col("size_bytes", "Size", 90, bytes("size_bytes"), { field: "file.size", align: "right" }),
  ],
};

export const VIEW_LABEL: Record<TableView, string> = {
  flows: "Flows",
  dns: "DNS",
  http: "HTTP",
  tls: "TLS",
  files: "Files",
};

/** The frame to show when a row is selected: the row's own frame, else the flow's first. */
export function rowFrame(row: AnyRow): number | null {
  if ("frame_no" in row && typeof row.frame_no === "number") return row.frame_no;
  if ("first_frame" in row && typeof row.first_frame === "number") return row.first_frame;
  return null;
}
