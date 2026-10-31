import { describe, expect, it } from "vitest";
import { appendPredicate, composePredicate, fieldType, quote } from "./predicates";

const ok = (field: string, ty: Parameters<typeof composePredicate>[1], raw: string) => {
  const r = composePredicate(field, ty, raw);
  if (!r.ok) throw new Error(r.error);
  return r.text;
};

describe("composePredicate", () => {
  it("builds ip predicates and rejects non-ips", () => {
    expect(ok("src_ip", "ip", "10.0.0.5")).toBe("src_ip == 10.0.0.5");
    expect(ok("src_ip", "ip", "10.0.0.0/8")).toBe("src_ip == 10.0.0.0/8");
    expect(ok("dst_ip", "ip", "!= 2001:db8::1")).toBe("dst_ip != 2001:db8::1");
    expect(composePredicate("src_ip", "ip", "evil; drop").ok).toBe(false);
  });

  it("builds numeric predicates with operators and units", () => {
    expect(ok("dst_port", "int", "443")).toBe("dst_port == 443");
    expect(ok("bytes_up", "bytes", ">1MB")).toBe("bytes_up > 1MB");
    expect(ok("bytes_up", "bytes", "<= 10 KB")).toBe("bytes_up <= 10KB");
    expect(composePredicate("dst_port", "int", "1MB").ok).toBe(false);
    expect(composePredicate("dst_port", "int", "443 or 1==1").ok).toBe(false);
  });

  it("quotes strings and escapes quotes and backslashes", () => {
    expect(ok("app_proto", "str", "tls")).toBe("app_proto == tls");
    expect(ok("dns.query", "str", "*.top")).toBe('dns.query ~ "*.top"');
    expect(ok("http.uri", "str", 'a" or host 1.2.3.4 "\\')).toBe('http.uri == "a\\" or host 1.2.3.4 \\"\\\\"');
    expect(ok("http.host", "str", "!= example.com")).toBe('http.host != "example.com"');
    expect(quote('x"y')).toBe('"x\\"y"');
  });

  it("handles proto and bool", () => {
    expect(ok("proto", "proto", "UDP")).toBe("proto == 17");
    expect(ok("proto", "proto", "6")).toBe("proto == 6");
    expect(ok("dns.is_response", "bool", "yes")).toBe("dns.is_response == true");
    expect(composePredicate("proto", "proto", "sctp?").ok).toBe(false);
  });

  it("rejects empty input", () => {
    expect(composePredicate("src_ip", "ip", "  ").ok).toBe(false);
  });
});

describe("appendPredicate", () => {
  it("ANDs onto the filter and parenthesises a top-level or", () => {
    expect(appendPredicate("", "dst_port == 53")).toBe("dst_port == 53");
    expect(appendPredicate("host 10.0.0.5", "dst_port == 53")).toBe("host 10.0.0.5 and dst_port == 53");
    expect(appendPredicate("dns or tls", "dst_port == 53")).toBe("(dns or tls) and dst_port == 53");
    expect(appendPredicate('dns.query ~ "or"', "tls")).toBe('dns.query ~ "or" and tls');
  });
});

describe("fieldType", () => {
  it("reads the generated registry", () => {
    expect(fieldType("src_ip")).toBe("ip");
    expect(fieldType("dns.query")).toBe("str");
    expect(fieldType("nope")).toBeNull();
  });
});
