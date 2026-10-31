// Column filters compose into filter-language text that the user can see
// and edit in the filter bar. The backend parses that text and binds every
// literal as a SQL parameter (CONTRACTS §5); nothing here builds SQL.
import { FILTER_FIELDS, type FilterField } from "../shared/filterFields";

export type FieldType = FilterField["ty"];

const NUM = /^(==|!=|>=|<=|>|<)?\s*(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|us|ms|s|m|h)?$/i;
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?$/;
const IPV6 = /^[0-9a-fA-F:]*:[0-9a-fA-F:.]*(?:\/\d{1,3})?$/;
const IDENT = /^[A-Za-z_][A-Za-z0-9_-]*$/;

export type Composed = { ok: true; text: string } | { ok: false; error: string };

/** Quote a string literal for the filter language. */
export function quote(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/**
 * Turn what the user typed into a column filter into one predicate.
 * ip: `10.0.0.5`, `10.0.0.0/8`, `!=10.0.0.5`. numbers: `443`, `>1MB`, `<= 10`.
 * strings: plain text is an exact match; `*`/`?` make it a glob (`~`);
 * a leading `!=` negates.
 */
export function composePredicate(field: string, ty: FieldType, raw: string): Composed {
  const input = raw.trim();
  if (!input) return { ok: false, error: "Enter a value." };
  if (input.length > 512) return { ok: false, error: "Value is too long." };
  switch (ty) {
    case "int":
    case "bytes":
    case "duration":
    case "time": {
      const m = NUM.exec(input);
      if (!m) return { ok: false, error: "Use a number, optionally with an operator (>, <=, !=) and unit." };
      const unit = m[3] ?? "";
      if (ty === "int" && unit) return { ok: false, error: "This column takes a plain number." };
      return { ok: true, text: `${field} ${m[1] ?? "=="} ${m[2]}${unit}` };
    }
    case "ip": {
      const neg = input.startsWith("!=");
      const v = (neg ? input.slice(2) : input.replace(/^==/, "")).trim();
      if (!IPV4.test(v) && !IPV6.test(v)) return { ok: false, error: "Use an IP address or CIDR." };
      return { ok: true, text: `${field} ${neg ? "!=" : "=="} ${v}` };
    }
    case "proto": {
      const v = input.replace(/^==/, "").trim().toLowerCase();
      const num = { tcp: 6, udp: 17, icmp: 1, icmpv6: 58 }[v] ?? (/^\d+$/.test(v) ? Number(v) : null);
      if (num === null) return { ok: false, error: "Use tcp, udp, icmp or a protocol number." };
      return { ok: true, text: `${field} == ${num}` };
    }
    case "bool": {
      const v = input.toLowerCase();
      if (!["true", "false", "yes", "no"].includes(v)) return { ok: false, error: "Use true or false." };
      return { ok: true, text: `${field} == ${v === "true" || v === "yes"}` };
    }
    case "str":
    case "str_list": {
      const neg = input.startsWith("!=");
      const v = neg ? input.slice(2).trim() : input;
      if (!v) return { ok: false, error: "Enter a value." };
      const glob = /[*?]/.test(v);
      if (glob && neg) return { ok: false, error: "Negated globs are not supported here; edit the filter bar instead." };
      const lit = IDENT.test(v) && !glob ? v : quote(v);
      return { ok: true, text: `${field} ${glob ? "~" : neg ? "!=" : "=="} ${lit}` };
    }
  }
}

/** AND a predicate onto existing filter text, parenthesising an `or`. */
export function appendPredicate(filter: string, predicate: string): string {
  const f = filter.trim();
  if (!f) return predicate;
  const wrapped = /\bor\b/i.test(f.replace(/"(?:[^"\\]|\\.)*"/g, '""')) ? `(${f})` : f;
  return `${wrapped} and ${predicate}`;
}

export function fieldType(name: string): FieldType | null {
  return FILTER_FIELDS.find((f) => f.name === name)?.ty ?? null;
}
