// Filter field registry for the UI, generated from
// crates/walleye-core/src/fields.rs by `cargo test -p walleye-core`.
import registry from "./bindings/filter_fields.json";

export interface FilterField {
  name: string;
  table: "flows" | "dns" | "http" | "tls" | "files" | "frames" | "wifi" | "wifi_aps" | "wifi_clients";
  sql: string;
  ty: "ip" | "int" | "bytes" | "time" | "duration" | "str" | "bool" | "str_list" | "proto" | "mac";
  doc: string;
}

export const FILTER_FIELDS: readonly FilterField[] = registry.fields as FilterField[];
export const FILTER_OPERATORS: readonly string[] = registry.operators;
/** Shorthands, boolean keywords and bare protocol names. */
export const FILTER_KEYWORDS: readonly string[] = [...registry.shorthands, ...registry.keywords, ...registry.bare_protocols];
