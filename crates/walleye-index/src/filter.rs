//! Filter language (CONTRACTS §5): lexer, recursive-descent parser,
//! type-checker against `walleye_core::fields::FIELDS`, and a compiler to a
//! **parameterized** SQL predicate.
//!
//! Filter text is untrusted. Guarantees, covered by unit and property tests:
//! - `parse` and `compile` never panic, on any input.
//! - Every literal from the input becomes a bound [`Param`]. The SQL text is
//!   built only from registry expressions (`FieldDef::sql`, trusted code),
//!   table names, fixed keywords, `?` placeholders and the fixed `ESCAPE '\'`.
//! - Limits: 4 KiB of text, nesting depth 64, 256 terms.
//! - Errors are `ApiError::invalid_filter` with a byte span into the text.

use std::net::IpAddr;

use walleye_core::{
    ApiError,
    error::ApiResult,
    error::Span,
    fields::{self, FieldDef, FieldType, Table},
    ipc::View,
};

pub const MAX_LEN: usize = 4096;
pub const MAX_DEPTH: usize = 64;
pub const MAX_TERMS: usize = 256;

/// Comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    /// `~`: case-insensitive glob.
    Glob,
    /// `in [a, b, ...]`.
    In,
}

/// A typed literal. Every literal reaches SQL only as a bound parameter.
#[derive(Debug, Clone, PartialEq)]
pub enum Lit {
    Int(i64),
    Str(String),
    Bool(bool),
    /// IP address or network. `prefix` equals the address width for a host.
    Net {
        addr: IpAddr,
        prefix: u8,
    },
    /// Glob pattern as typed (`*` any run, `?` one char).
    Glob(String),
    /// Exact addresses an IPv6 network resolved to (see [`resolve_ipv6_nets`]).
    IpSet(Vec<String>),
}

/// One `field op value(s)` comparison after type-checking.
#[derive(Debug, Clone, PartialEq)]
pub struct Cmp {
    pub field: &'static FieldDef,
    pub op: Op,
    /// One value, or several for `in`.
    pub values: Vec<Lit>,
    /// The term's span in the filter text.
    pub span: Span,
}

/// Parsed, type-checked filter.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// Empty filter.
    True,
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
    Cmp(Cmp),
    /// `mac X` (CONTRACTS §11.2): any address column of the queried 802.11
    /// view equals X. Which columns depends on the view, so it resolves at
    /// compile time. `value` is the canonical lowercase MAC (`Lit::Str`).
    Mac {
        value: Lit,
        span: Span,
    },
}

impl Expr {
    /// Every literal in the tree (for tests and audits).
    pub fn literals(&self) -> Vec<&Lit> {
        let mut out = Vec::new();
        self.collect_literals(&mut out);
        out
    }

    fn collect_literals<'a>(&'a self, out: &mut Vec<&'a Lit>) {
        match self {
            Expr::True => {}
            Expr::And(v) | Expr::Or(v) => v.iter().for_each(|e| e.collect_literals(out)),
            Expr::Not(e) => e.collect_literals(out),
            Expr::Cmp(c) => out.extend(c.values.iter()),
            Expr::Mac { value, .. } => out.push(value),
        }
    }

    fn walk_mut(&mut self, f: &mut dyn FnMut(&mut Cmp) -> ApiResult<()>) -> ApiResult<()> {
        match self {
            Expr::True | Expr::Mac { .. } => Ok(()),
            Expr::And(v) | Expr::Or(v) => v.iter_mut().try_for_each(|e| e.walk_mut(f)),
            Expr::Not(e) => e.walk_mut(f),
            Expr::Cmp(c) => f(c),
        }
    }
}

/// A bound parameter.
#[derive(Debug, Clone, PartialEq)]
pub enum Param {
    Int(i64),
    Str(String),
    Bool(bool),
}

impl duckdb::ToSql for Param {
    fn to_sql(&self) -> duckdb::Result<duckdb::types::ToSqlOutput<'_>> {
        use duckdb::types::{ToSqlOutput, Value};
        Ok(ToSqlOutput::Owned(match self {
            Param::Int(i) => Value::BigInt(*i),
            Param::Str(s) => Value::Text(s.clone()),
            Param::Bool(b) => Value::Boolean(*b),
        }))
    }
}

/// A boolean SQL predicate over the queried view's columns, with `?`
/// placeholders, and its parameters in order.
#[derive(Debug, Clone, PartialEq)]
pub struct Compiled {
    pub sql: String,
    pub params: Vec<Param>,
}

// ---------------------------------------------------------------- lexer

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    LParen,
    RParen,
    LBrack,
    RBrack,
    Comma,
    Bang,
    Op(Op),
    Str(String),
    Word(String),
}

#[derive(Debug, Clone)]
struct Token {
    tok: Tok,
    span: Span,
}

fn span(start: usize, end: usize) -> Span {
    // Inputs are capped at MAX_LEN before lexing, so this never truncates.
    Span {
        start: u32::try_from(start).unwrap_or(u32::MAX),
        end: u32::try_from(end).unwrap_or(u32::MAX),
    }
}

fn err(msg: impl Into<String>, start: usize, end: usize) -> ApiError {
    ApiError::invalid_filter(msg, span(start, end))
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '/' | '-')
}

/// Shortens user text quoted back in an error message.
fn quote(s: &str) -> String {
    let mut out: String = s.chars().take(40).collect();
    if s.chars().count() > 40 {
        out.push('…');
    }
    out
}

fn lex(text: &str) -> ApiResult<Vec<Token>> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let start = i;
        let single = |t: Tok| Token {
            tok: t,
            span: span(start, start + 1),
        };
        match c {
            b' ' | b'\t' | b'\n' | b'\r' => {
                i += 1;
            }
            b'(' => {
                out.push(single(Tok::LParen));
                i += 1;
            }
            b')' => {
                out.push(single(Tok::RParen));
                i += 1;
            }
            b'[' => {
                out.push(single(Tok::LBrack));
                i += 1;
            }
            b']' => {
                out.push(single(Tok::RBrack));
                i += 1;
            }
            b',' => {
                out.push(single(Tok::Comma));
                i += 1;
            }
            b'~' => {
                out.push(single(Tok::Op(Op::Glob)));
                i += 1;
            }
            b'=' | b'!' | b'<' | b'>' => {
                let next_eq = b.get(i + 1) == Some(&b'=');
                let (tok, len) = match (c, next_eq) {
                    (b'=', true) => (Tok::Op(Op::Eq), 2),
                    (b'=', false) => return Err(err("use `==` for equality", i, i + 1)),
                    (b'!', true) => (Tok::Op(Op::Ne), 2),
                    (b'!', false) => (Tok::Bang, 1),
                    (b'<', true) => (Tok::Op(Op::Le), 2),
                    (b'<', false) => (Tok::Op(Op::Lt), 1),
                    (b'>', true) => (Tok::Op(Op::Ge), 2),
                    _ => (Tok::Op(Op::Gt), 1),
                };
                out.push(Token {
                    tok,
                    span: span(i, i + len),
                });
                i += len;
            }
            b'"' => {
                let mut s = String::new();
                let mut j = i + 1;
                let mut closed = false;
                // Iterate chars (not bytes) so multi-byte text stays intact.
                let rest = &text[j..];
                let mut it = rest.char_indices();
                while let Some((k, ch)) = it.next() {
                    match ch {
                        '"' => {
                            j = i + 1 + k + 1;
                            closed = true;
                            break;
                        }
                        '\\' => match it.next() {
                            Some((_, e @ ('"' | '\\'))) => s.push(e),
                            Some((k2, e)) => {
                                let at = i + 1 + k2;
                                return Err(err(
                                    "only \\\" and \\\\ are valid escapes",
                                    at - 1,
                                    at + e.len_utf8(),
                                ));
                            }
                            None => break,
                        },
                        _ => s.push(ch),
                    }
                }
                if !closed {
                    return Err(err("unterminated string", i, b.len()));
                }
                out.push(Token {
                    tok: Tok::Str(s),
                    span: span(i, j),
                });
                i = j;
            }
            _ => {
                let ch = text[i..].chars().next().unwrap_or('\u{fffd}');
                if !is_word_char(ch) {
                    let hint = if ch == '*' || ch == '?' {
                        "; quote glob patterns, e.g. \"*.top\""
                    } else {
                        ""
                    };
                    return Err(err(
                        format!("unexpected character `{}`{hint}", ch.escape_default()),
                        i,
                        i + ch.len_utf8(),
                    ));
                }
                let mut j = i;
                while j < b.len() && is_word_char(b[j] as char) {
                    j += 1;
                }
                out.push(Token {
                    tok: Tok::Word(text[i..j].to_string()),
                    span: span(i, j),
                });
                i = j;
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- parser

/// Parses and type-checks a filter. `""` (or whitespace) is [`Expr::True`].
pub fn parse(text: &str) -> ApiResult<Expr> {
    if text.len() > MAX_LEN {
        return Err(err(
            format!("filter is longer than {MAX_LEN} bytes"),
            MAX_LEN,
            text.len().min(u32::MAX as usize),
        ));
    }
    let toks = lex(text)?;
    if toks.is_empty() {
        return Ok(Expr::True);
    }
    let mut p = Parser {
        toks,
        pos: 0,
        depth: 0,
        terms: 0,
        end: text.len(),
    };
    let e = p.or_expr()?;
    if let Some(t) = p.toks.get(p.pos) {
        let msg = match t.tok {
            Tok::RParen => "unbalanced `)`".to_string(),
            _ => "expected `and`, `or` or end of filter".to_string(),
        };
        return Err(ApiError::invalid_filter(msg, t.span));
    }
    Ok(e)
}

/// Fuzz entry point: parse, then compile for every view. Never panics.
pub fn fuzz_parse_compile(text: &str) {
    if let Ok(e) = parse(text) {
        for v in ALL_VIEWS {
            let _ = compile(&e, v);
        }
    }
}

pub const ALL_VIEWS: [View; 9] = [
    View::Flows,
    View::Dns,
    View::Http,
    View::Tls,
    View::Files,
    View::Frames,
    View::Wifi,
    View::WifiAps,
    View::WifiClients,
];

struct Parser {
    toks: Vec<Token>,
    pos: usize,
    depth: usize,
    terms: usize,
    end: usize,
}

fn kw(t: Option<&Token>, k: &str) -> bool {
    matches!(t, Some(Token { tok: Tok::Word(w), .. }) if w.eq_ignore_ascii_case(k))
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.toks.get(self.pos)
    }
    fn bump(&mut self) -> Option<Token> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }
    fn eof_err(&self, msg: &str) -> ApiError {
        err(msg, self.end, self.end)
    }

    fn enter(&mut self, at: Span) -> ApiResult<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(ApiError::invalid_filter(
                format!("filter nests deeper than {MAX_DEPTH}"),
                at,
            ));
        }
        Ok(())
    }

    fn term(&mut self, at: Span) -> ApiResult<()> {
        self.terms += 1;
        if self.terms > MAX_TERMS {
            return Err(ApiError::invalid_filter(
                format!("filter has more than {MAX_TERMS} terms"),
                at,
            ));
        }
        Ok(())
    }

    fn or_expr(&mut self) -> ApiResult<Expr> {
        let mut v = vec![self.and_expr()?];
        while kw(self.peek(), "or") {
            self.bump();
            v.push(self.and_expr()?);
        }
        Ok(if v.len() == 1 {
            v.pop().unwrap_or(Expr::True)
        } else {
            Expr::Or(v)
        })
    }

    fn and_expr(&mut self) -> ApiResult<Expr> {
        let mut v = vec![self.unary()?];
        loop {
            if kw(self.peek(), "and") {
                self.bump();
                v.push(self.unary()?);
            } else if self.starts_unary() {
                v.push(self.unary()?);
            } else {
                break;
            }
        }
        Ok(if v.len() == 1 {
            v.pop().unwrap_or(Expr::True)
        } else {
            Expr::And(v)
        })
    }

    fn starts_unary(&self) -> bool {
        match self.peek() {
            Some(Token {
                tok: Tok::LParen | Tok::Bang,
                ..
            }) => true,
            Some(Token {
                tok: Tok::Word(w), ..
            }) => !w.eq_ignore_ascii_case("or"),
            _ => false,
        }
    }

    fn unary(&mut self) -> ApiResult<Expr> {
        let Some(t) = self.peek().cloned() else {
            return Err(self.eof_err("expected a term"));
        };
        self.enter(t.span)?;
        let r = if matches!(t.tok, Tok::Bang) || kw(Some(&t), "not") {
            self.bump();
            self.unary().map(|e| Expr::Not(Box::new(e)))
        } else {
            self.primary()
        };
        self.depth -= 1;
        r
    }

    fn primary(&mut self) -> ApiResult<Expr> {
        let Some(t) = self.bump() else {
            return Err(self.eof_err("expected a term"));
        };
        match &t.tok {
            Tok::LParen => {
                // Depth is counted once per nesting level, in `unary`.
                let e = self.or_expr()?;
                match self.bump() {
                    Some(Token {
                        tok: Tok::RParen, ..
                    }) => Ok(e),
                    Some(o) => Err(ApiError::invalid_filter("expected `)`", o.span)),
                    None => Err(ApiError::invalid_filter("unclosed `(`", t.span)),
                }
            }
            Tok::Word(w) => {
                let lower = w.to_ascii_lowercase();
                match lower.as_str() {
                    "and" | "or" | "in" => Err(ApiError::invalid_filter(
                        format!("expected a term before `{lower}`"),
                        t.span,
                    )),
                    "host" | "src" | "dst" => self.shorthand_ip(&lower, t.span),
                    "port" => self.shorthand_port(t.span),
                    "mac" => self.shorthand_mac(t.span),
                    "dns" | "http" | "tls" | "tcp" | "udp" | "icmp" if !self.next_is_op() => {
                        self.term(t.span)?;
                        let (name, lit) = match lower.as_str() {
                            "tcp" => ("proto", Lit::Int(6)),
                            "udp" => ("proto", Lit::Int(17)),
                            "icmp" => ("proto", Lit::Int(1)),
                            p => ("app_proto", Lit::Str(p.to_string())),
                        };
                        Ok(Expr::Cmp(Cmp {
                            field: reg(name)?,
                            op: Op::Eq,
                            values: vec![lit],
                            span: t.span,
                        }))
                    }
                    _ => self.comparison(w.clone(), t.span),
                }
            }
            Tok::RParen => Err(ApiError::invalid_filter(
                "unbalanced `)`, expected a term",
                t.span,
            )),
            Tok::Str(_) => Err(ApiError::invalid_filter(
                "expected a field name before the value",
                t.span,
            )),
            _ => Err(ApiError::invalid_filter("expected a term", t.span)),
        }
    }

    fn next_is_op(&self) -> bool {
        matches!(
            self.peek(),
            Some(Token {
                tok: Tok::Op(_),
                ..
            })
        ) || kw(self.peek(), "in")
    }

    fn shorthand_ip(&mut self, which: &str, kspan: Span) -> ApiResult<Expr> {
        self.term(kspan)?;
        let Some(v) = self.bump() else {
            return Err(self.eof_err(&format!("expected an IP address after `{which}`")));
        };
        let text = match &v.tok {
            Tok::Word(w) | Tok::Str(w) => w.clone(),
            _ => String::new(),
        };
        let lit = parse_net(&text).ok_or_else(|| {
            ApiError::invalid_filter(
                format!("expected an IP address or CIDR after `{which}`"),
                v.span,
            )
        })?;
        let full = span(kspan.start as usize, v.span.end as usize);
        let mk = |name: &str| -> ApiResult<Expr> {
            Ok(Expr::Cmp(Cmp {
                field: reg(name)?,
                op: Op::Eq,
                values: vec![lit.clone()],
                span: full,
            }))
        };
        match which {
            "src" => mk("src_ip"),
            "dst" => mk("dst_ip"),
            _ => Ok(Expr::Or(vec![mk("src_ip")?, mk("dst_ip")?])),
        }
    }

    fn shorthand_port(&mut self, kspan: Span) -> ApiResult<Expr> {
        self.term(kspan)?;
        let Some(v) = self.bump() else {
            return Err(self.eof_err("expected a port number after `port`"));
        };
        let n = match &v.tok {
            Tok::Word(w) => w.parse::<u16>().ok(),
            _ => None,
        }
        .ok_or_else(|| ApiError::invalid_filter("expected a port number 0..65535", v.span))?;
        let full = span(kspan.start as usize, v.span.end as usize);
        let mk = |name: &str| -> ApiResult<Expr> {
            Ok(Expr::Cmp(Cmp {
                field: reg(name)?,
                op: Op::Eq,
                values: vec![Lit::Int(i64::from(n))],
                span: full,
            }))
        };
        Ok(Expr::Or(vec![mk("src_port")?, mk("dst_port")?]))
    }

    /// `mac X`: X is a bare (`aa:bb:cc:dd:ee:ff`, one word token) or quoted
    /// MAC; stored lowercase.
    fn shorthand_mac(&mut self, kspan: Span) -> ApiResult<Expr> {
        self.term(kspan)?;
        let Some(v) = self.bump() else {
            return Err(self.eof_err("expected a MAC address after `mac`"));
        };
        let text = match &v.tok {
            Tok::Word(w) | Tok::Str(w) => w.as_str(),
            _ => "",
        };
        let mac = walleye_core::mac::parse_mac(text).ok_or_else(|| {
            ApiError::invalid_filter(
                "expected a MAC address after `mac`, e.g. aa:bb:cc:dd:ee:ff",
                v.span,
            )
        })?;
        Ok(Expr::Mac {
            value: Lit::Str(mac),
            span: span(kspan.start as usize, v.span.end as usize),
        })
    }

    fn comparison(&mut self, name: String, fspan: Span) -> ApiResult<Expr> {
        self.term(fspan)?;
        let field = fields::field(&name).ok_or_else(|| {
            let hint = if fields::field(&name.to_ascii_lowercase()).is_some() {
                " (field names are lowercase)"
            } else {
                ""
            };
            ApiError::invalid_filter(format!("unknown field `{}`{hint}", quote(&name)), fspan)
        })?;
        let op = match self.peek2_op() {
            Some(op) => op,
            None => {
                let at = self.peek().map(|t| t.span);
                return Err(match at {
                    Some(s) => ApiError::invalid_filter(
                        format!("expected an operator after `{}`", field.name),
                        s,
                    ),
                    None => self.eof_err(&format!("expected an operator after `{}`", field.name)),
                });
            }
        };
        let op_tok = self.bump().map(|t| t.span).unwrap_or(fspan);
        check_op(field, op, op_tok)?;
        if op == Op::In {
            match self.bump() {
                Some(Token {
                    tok: Tok::LBrack, ..
                }) => {}
                Some(t) => return Err(ApiError::invalid_filter("expected `[` after `in`", t.span)),
                None => return Err(self.eof_err("expected `[` after `in`")),
            }
            let mut values = Vec::new();
            loop {
                let v = self.value_token()?;
                values.push(typed_value(field, Op::Eq, &v)?);
                if values.len() > MAX_TERMS {
                    return Err(ApiError::invalid_filter(
                        format!("`in` list has more than {MAX_TERMS} values"),
                        v.span,
                    ));
                }
                match self.bump() {
                    Some(Token {
                        tok: Tok::Comma, ..
                    }) => continue,
                    Some(Token {
                        tok: Tok::RBrack,
                        span: s,
                    }) => {
                        return Ok(Expr::Cmp(Cmp {
                            field,
                            op,
                            values,
                            span: span(fspan.start as usize, s.end as usize),
                        }));
                    }
                    Some(t) => return Err(ApiError::invalid_filter("expected `,` or `]`", t.span)),
                    None => return Err(self.eof_err("unclosed `[`")),
                }
            }
        }
        let v = self.value_token()?;
        let lit = typed_value(field, op, &v)?;
        Ok(Expr::Cmp(Cmp {
            field,
            op,
            values: vec![lit],
            span: span(fspan.start as usize, v.span.end as usize),
        }))
    }

    /// The operator at the current position, if any (does not consume).
    fn peek2_op(&self) -> Option<Op> {
        match self.peek() {
            Some(Token {
                tok: Tok::Op(op), ..
            }) => Some(*op),
            t if kw(t, "in") => Some(Op::In),
            _ => None,
        }
    }

    fn value_token(&mut self) -> ApiResult<Token> {
        match self.bump() {
            Some(
                t @ Token {
                    tok: Tok::Word(_) | Tok::Str(_),
                    ..
                },
            ) => Ok(t),
            Some(t) => Err(ApiError::invalid_filter("expected a value", t.span)),
            None => Err(self.eof_err("expected a value")),
        }
    }
}

fn reg(name: &str) -> ApiResult<&'static FieldDef> {
    fields::field(name).ok_or_else(|| ApiError::internal(format!("registry lacks {name}")))
}

fn type_name(t: FieldType) -> &'static str {
    match t {
        FieldType::Ip => "an IP field",
        FieldType::Int => "a number field",
        FieldType::Bytes => "a size field",
        FieldType::Time => "a time field",
        FieldType::Duration => "a duration field",
        FieldType::Str => "a text field",
        FieldType::Bool => "a boolean field",
        FieldType::StrList => "a text-list field",
        FieldType::Proto => "a protocol field",
        FieldType::Mac => "a MAC address field",
    }
}

fn check_op(f: &FieldDef, op: Op, at: Span) -> ApiResult<()> {
    use FieldType as T;
    let ok = match f.ty {
        T::Int | T::Bytes | T::Time | T::Duration => op != Op::Glob,
        T::Ip | T::Str | T::StrList | T::Mac => {
            matches!(op, Op::Eq | Op::Ne | Op::Glob | Op::In)
        }
        T::Bool => matches!(op, Op::Eq | Op::Ne),
        T::Proto => matches!(op, Op::Eq | Op::Ne | Op::In),
    };
    if ok {
        Ok(())
    } else {
        Err(ApiError::invalid_filter(
            format!(
                "`{}` is {}; this operator does not apply",
                f.name,
                type_name(f.ty)
            ),
            at,
        ))
    }
}

fn typed_value(f: &FieldDef, op: Op, v: &Token) -> ApiResult<Lit> {
    use FieldType as T;
    let (text, quoted) = match &v.tok {
        Tok::Word(w) => (w.as_str(), false),
        Tok::Str(s) => (s.as_str(), true),
        _ => ("", false),
    };
    let bad = |what: &str| ApiError::invalid_filter(format!("`{}` expects {what}", f.name), v.span);
    if op == Op::Glob {
        // MACs are stored canonical (lowercase, `:`): normalize the pattern
        // the same way so `AA-BB-*` matches (case alone is also covered by
        // ILIKE, but the pattern should not depend on it).
        if f.ty == T::Mac {
            return Ok(Lit::Glob(text.to_ascii_lowercase().replace('-', ":")));
        }
        return Ok(Lit::Glob(text.to_string()));
    }
    match f.ty {
        T::Ip => {
            parse_net(text).ok_or_else(|| bad("an IP address or CIDR, e.g. 10.0.0.5 or 10.0.0.0/8"))
        }
        T::Int => {
            if quoted {
                return Err(bad("a number"));
            }
            text.parse::<i64>()
                .map(Lit::Int)
                .map_err(|_| bad("a whole number"))
        }
        T::Bytes => {
            if quoted {
                return Err(bad("a size"));
            }
            parse_scaled(
                text,
                &[
                    ("", 1),
                    ("B", 1),
                    ("KB", 1 << 10),
                    ("MB", 1 << 20),
                    ("GB", 1 << 30),
                ],
                true,
            )
            .map(Lit::Int)
            .ok_or_else(|| bad("a size such as 1500, 10KB or 1MB"))
        }
        T::Duration => {
            if quoted {
                return Err(bad("a duration"));
            }
            parse_scaled(
                text,
                &[
                    ("", 1_000_000),
                    ("us", 1),
                    ("ms", 1_000),
                    ("s", 1_000_000),
                    ("m", 60_000_000),
                    ("h", 3_600_000_000),
                ],
                false,
            )
            .map(Lit::Int)
            .ok_or_else(|| bad("a duration such as 30s, 10m or 1h (no unit = seconds)"))
        }
        T::Time => {
            if !quoted && let Ok(n) = text.parse::<i64>() {
                return Ok(Lit::Int(n));
            }
            parse_rfc3339(text)
                .map(Lit::Int)
                .ok_or_else(|| bad("an RFC 3339 time (\"2024-05-01T12:00:00Z\") or microseconds"))
        }
        T::Str | T::StrList => Ok(Lit::Str(text.to_string())),
        T::Mac => walleye_core::mac::parse_mac(text)
            .map(Lit::Str)
            .ok_or_else(|| bad("a MAC address, e.g. \"aa:bb:cc:dd:ee:ff\"")),
        T::Bool => match text.to_ascii_lowercase().as_str() {
            "true" if !quoted => Ok(Lit::Bool(true)),
            "false" if !quoted => Ok(Lit::Bool(false)),
            _ => Err(bad("true or false")),
        },
        T::Proto => {
            let n = match text.to_ascii_lowercase().as_str() {
                "tcp" => Some(6),
                "udp" => Some(17),
                "icmp" => Some(1),
                "icmp6" => Some(58),
                s => s.parse::<u8>().ok().map(i64::from),
            };
            n.map(Lit::Int)
                .ok_or_else(|| bad("tcp, udp, icmp, icmp6 or 0..255"))
        }
    }
}

/// `addr` or `addr/prefix`, canonicalized.
fn parse_net(text: &str) -> Option<Lit> {
    let (a, p) = match text.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (text, None),
    };
    let addr: IpAddr = a.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = match p {
        None => max,
        Some(p) if !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()) => {
            p.parse::<u8>().ok().filter(|n| *n <= max)?
        }
        Some(_) => return None,
    };
    Some(Lit::Net { addr, prefix })
}

/// `digit+ [. digit+] [unit]` scaled by the unit's multiplier.
fn parse_scaled(text: &str, units: &[(&str, i64)], ci: bool) -> Option<i64> {
    let num_end = text
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(text.len());
    let (num, unit) = text.split_at(num_end);
    let mult = units
        .iter()
        .find(|(u, _)| {
            if ci {
                u.eq_ignore_ascii_case(unit)
            } else {
                *u == unit
            }
        })?
        .1;
    let (int, frac) = match num.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (num, None),
    };
    if int.is_empty() || !int.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let ip: i64 = int.parse().ok()?;
    let mut v = ip.checked_mul(mult)?;
    if let Some(f) = frac {
        if f.is_empty() || f.len() > 9 || !f.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let fv: i64 = f.parse().ok()?;
        let scale = 10i64.checked_pow(f.len() as u32)?;
        v = v.checked_add(fv.checked_mul(mult)? / scale)?;
    }
    Some(v)
}

/// RFC 3339 → microseconds since the epoch. `YYYY-MM-DD[T ]HH:MM:SS[.f](Z|±HH:MM)`.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        if t.bytes().all(|c| c.is_ascii_digit()) {
            t.parse().ok()
        } else {
            None
        }
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't' | b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut i = 19;
    let mut micros = 0i64;
    if b.get(i) == Some(&b'.') {
        let st = i + 1;
        let mut j = st;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j == st {
            return None;
        }
        let digits = &s[st..j.min(st + 6)];
        micros = digits.parse::<i64>().ok()? * 10i64.pow(6 - digits.len() as u32);
        i = j;
    }
    let off = match b.get(i) {
        Some(b'Z' | b'z') if i + 1 == b.len() => 0,
        Some(c @ (b'+' | b'-')) if i + 6 == b.len() && b[i + 3] == b':' => {
            let (oh, om) = (num(i + 1..i + 3)?, num(i + 4..i + 6)?);
            if oh > 23 || om > 59 {
                return None;
            }
            let o = oh * 3600 + om * 60;
            if *c == b'+' { o } else { -o }
        }
        _ => return None,
    };
    // Days from civil (Howard Hinnant).
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 + sec - off;
    secs.checked_mul(1_000_000)?.checked_add(micros)
}

// ---------------------------------------------------------------- compiler

pub fn table_of(view: View) -> Table {
    match view {
        View::Flows => Table::Flows,
        View::Dns => Table::Dns,
        View::Http => Table::Http,
        View::Tls => Table::Tls,
        View::Files => Table::Files,
        View::Frames => Table::Frames,
        View::Wifi => Table::Wifi,
        View::WifiAps => Table::WifiAps,
        View::WifiClients => Table::WifiClients,
    }
}

fn wifi_view_name(t: Table) -> Option<&'static str> {
    match t {
        Table::Wifi => Some("Wi-Fi frames"),
        Table::WifiAps => Some("access points"),
        Table::WifiClients => Some("Wi-Fi clients"),
        _ => None,
    }
}

pub fn table_name(t: Table) -> &'static str {
    match t {
        Table::Flows => "flows",
        Table::Dns => "dns",
        Table::Http => "http",
        Table::Tls => "tls",
        Table::Files => "files",
        Table::Frames => "frames",
        Table::Wifi => "wifi",
        Table::WifiAps => "wifi_aps",
        Table::WifiClients => "wifi_clients",
    }
}

/// Rewrites IPv6 networks (non-host prefixes) into exact address sets using
/// `lookup(field, addr, prefix)`, which returns the matching addresses seen in
/// the index. IPv6 canonical text cannot be prefix-matched in SQL, so the
/// index resolves them before [`compile`].
pub fn resolve_ipv6_nets(
    expr: &mut Expr,
    lookup: &mut dyn FnMut(&'static FieldDef, std::net::Ipv6Addr, u8) -> ApiResult<Vec<String>>,
) -> ApiResult<()> {
    expr.walk_mut(&mut |c| {
        if c.field.ty != FieldType::Ip {
            return Ok(());
        }
        let field = c.field;
        for v in &mut c.values {
            if let Lit::Net {
                addr: IpAddr::V6(a),
                prefix,
            } = v
                && *prefix < 128
            {
                *v = Lit::IpSet(lookup(field, *a, *prefix)?);
            }
        }
        Ok(())
    })
}

/// Compiles a filter to a predicate over `view`'s columns.
pub fn compile(expr: &Expr, view: View) -> ApiResult<Compiled> {
    let mut c = Compiler {
        view: table_of(view),
        params: Vec::new(),
    };
    let mut sql = String::new();
    c.expr(expr, &mut sql)?;
    Ok(Compiled {
        sql,
        params: c.params,
    })
}

struct Compiler {
    view: Table,
    params: Vec<Param>,
}

impl Compiler {
    fn expr(&mut self, e: &Expr, out: &mut String) -> ApiResult<()> {
        match e {
            Expr::True => out.push_str("TRUE"),
            Expr::And(v) | Expr::Or(v) => {
                let sep = if matches!(e, Expr::And(_)) {
                    " AND "
                } else {
                    " OR "
                };
                out.push('(');
                for (i, x) in v.iter().enumerate() {
                    if i > 0 {
                        out.push_str(sep);
                    }
                    self.expr(x, out)?;
                }
                out.push(')');
            }
            Expr::Not(x) => {
                // Two-valued logic: NULL comparisons count as false, so `not`
                // keeps rows whose column is NULL (`not app_proto == tls`
                // includes flows with no app protocol).
                out.push_str("(NOT coalesce(");
                self.expr(x, out)?;
                out.push_str(", FALSE))");
            }
            Expr::Cmp(c) => self.cmp(c, out)?,
            Expr::Mac { value, span } => self.mac(value, *span, out)?,
        }
        Ok(())
    }

    /// `mac X` on the queried view: `src`/`dst`/`tx`/`bssid` on `wifi`,
    /// `bssid` on `wifi_aps`, `mac` on `wifi_clients`.
    fn mac(&mut self, value: &Lit, at: Span, out: &mut String) -> ApiResult<()> {
        let names: &[&str] = match self.view {
            Table::Wifi => &["wifi.src", "wifi.dst", "wifi.tx", "wifi.bssid"],
            Table::WifiAps => &["ap.bssid"],
            Table::WifiClients => &["client.mac"],
            _ => {
                return Err(ApiError::invalid_filter(
                    "`mac` only applies on the 802.11 views (Wi-Fi frames, access points, clients)",
                    at,
                ));
            }
        };
        out.push('(');
        for (i, n) in names.iter().enumerate() {
            if i > 0 {
                out.push_str(" OR ");
            }
            let c = Cmp {
                field: reg(n)?,
                op: Op::Eq,
                values: vec![value.clone()],
                span: at,
            };
            self.pred(&c, out)?;
        }
        out.push(')');
        Ok(())
    }

    fn cmp(&mut self, c: &Cmp, out: &mut String) -> ApiResult<()> {
        let t = c.field.table;
        if t == self.view {
            return self.pred(c, out);
        }
        if t == Table::Frames {
            return Err(ApiError::invalid_filter(
                format!("`{}` only applies on the frames view", c.field.name),
                c.span,
            ));
        }
        // 802.11 tables have no flow_id: their fields apply only on their own
        // view, and flow-family fields do not apply on them (contract v2).
        if let Some(v) = wifi_view_name(t) {
            return Err(ApiError::invalid_filter(
                format!("`{}` only applies on the {v} view", c.field.name),
                c.span,
            ));
        }
        if wifi_view_name(self.view).is_some() {
            return Err(ApiError::invalid_filter(
                format!(
                    "`{}` does not apply to 802.11 views; use wifi.*, ap.* or client.* fields",
                    c.field.name
                ),
                c.span,
            ));
        }
        out.push_str("(flow_id IN (SELECT flow_id FROM ");
        out.push_str(table_name(t));
        out.push_str(" WHERE ");
        self.pred(c, out)?;
        out.push_str("))");
        Ok(())
    }

    fn bind(&mut self, p: Param, out: &mut String) {
        self.params.push(p);
        out.push('?');
    }

    fn pred(&mut self, c: &Cmp, out: &mut String) -> ApiResult<()> {
        let col = c.field.sql;
        match c.op {
            Op::Ne => {
                out.push_str("(NOT coalesce(");
                self.eq(col, c, &c.values[..1.min(c.values.len())], out)?;
                out.push_str(", FALSE))");
            }
            Op::Eq | Op::In => self.eq(col, c, &c.values, out)?,
            Op::Gt | Op::Ge | Op::Lt | Op::Le => {
                let op = match c.op {
                    Op::Gt => ">",
                    Op::Ge => ">=",
                    Op::Lt => "<",
                    _ => "<=",
                };
                let Some(Lit::Int(n)) = c.values.first() else {
                    return Err(ApiError::invalid_filter("expected a number", c.span));
                };
                out.push('(');
                out.push_str(col);
                out.push(' ');
                out.push_str(op);
                out.push(' ');
                self.bind(Param::Int(*n), out);
                out.push(')');
            }
            Op::Glob => {
                let Some(Lit::Glob(g)) = c.values.first() else {
                    return Err(ApiError::invalid_filter("expected a pattern", c.span));
                };
                let pat = glob_to_like(g);
                if c.field.ty == FieldType::StrList {
                    out.push_str("list_bool_or(list_transform(");
                    out.push_str(col);
                    out.push_str(", lambda x: x ILIKE ");
                    self.bind(Param::Str(pat), out);
                    out.push_str(" ESCAPE '\\'))");
                } else {
                    out.push('(');
                    out.push_str(col);
                    out.push_str(" ILIKE ");
                    self.bind(Param::Str(pat), out);
                    out.push_str(" ESCAPE '\\')");
                }
            }
        }
        Ok(())
    }

    /// `col == v` (or any of `vs`), as a parenthesized predicate.
    fn eq(&mut self, col: &str, c: &Cmp, vs: &[Lit], out: &mut String) -> ApiResult<()> {
        if vs.is_empty() {
            return Err(ApiError::invalid_filter("expected a value", c.span));
        }
        let list = c.field.ty == FieldType::StrList;
        // Fast path: scalar exact values → col IN (?, ...).
        let simple: Option<Vec<Param>> = vs
            .iter()
            .map(|v| match v {
                Lit::Int(n) => Some(Param::Int(*n)),
                Lit::Str(s) if !list => Some(Param::Str(s.clone())),
                Lit::Bool(b) => Some(Param::Bool(*b)),
                Lit::Net { addr, prefix } if u32::from(*prefix) == max_prefix(addr) => {
                    Some(Param::Str(addr.to_string()))
                }
                _ => None,
            })
            .collect();
        if let Some(ps) = simple {
            out.push('(');
            out.push_str(col);
            if ps.len() == 1 {
                out.push_str(" = ");
            } else {
                out.push_str(" IN (");
            }
            for (i, p) in ps.into_iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                self.bind(p, out);
            }
            if vs.len() > 1 {
                out.push(')');
            }
            out.push(')');
            return Ok(());
        }
        out.push('(');
        for (i, v) in vs.iter().enumerate() {
            if i > 0 {
                out.push_str(" OR ");
            }
            self.eq_one(col, c, v, list, out)?;
        }
        out.push(')');
        Ok(())
    }

    fn eq_one(
        &mut self,
        col: &str,
        c: &Cmp,
        v: &Lit,
        list: bool,
        out: &mut String,
    ) -> ApiResult<()> {
        match v {
            Lit::Str(s) if list => {
                out.push_str("list_contains(");
                out.push_str(col);
                out.push_str(", ");
                self.bind(Param::Str(s.clone()), out);
                out.push(')');
            }
            Lit::Int(n) => {
                out.push_str(col);
                out.push_str(" = ");
                self.bind(Param::Int(*n), out);
            }
            Lit::Str(s) => {
                out.push_str(col);
                out.push_str(" = ");
                self.bind(Param::Str(s.clone()), out);
            }
            Lit::Bool(b) => {
                out.push_str(col);
                out.push_str(" = ");
                self.bind(Param::Bool(*b), out);
            }
            Lit::Net { addr, prefix } => self.net(col, c, addr, *prefix, out)?,
            Lit::IpSet(set) => {
                if set.is_empty() {
                    out.push_str("FALSE");
                } else {
                    out.push_str(col);
                    out.push_str(" IN (");
                    for (i, a) in set.iter().enumerate() {
                        if i > 0 {
                            out.push_str(", ");
                        }
                        self.bind(Param::Str(a.clone()), out);
                    }
                    out.push(')');
                }
            }
            Lit::Glob(_) => {
                return Err(ApiError::invalid_filter("a pattern needs `~`", c.span));
            }
        }
        Ok(())
    }

    fn net(
        &mut self,
        col: &str,
        c: &Cmp,
        addr: &IpAddr,
        prefix: u8,
        out: &mut String,
    ) -> ApiResult<()> {
        match addr {
            _ if u32::from(prefix) == max_prefix(addr) => {
                out.push_str(col);
                out.push_str(" = ");
                self.bind(Param::Str(addr.to_string()), out);
            }
            IpAddr::V4(a) => {
                let n = u32::from(*a);
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(prefix))
                };
                let lo = n & mask;
                let hi = lo | !mask;
                if prefix % 8 == 0 && prefix > 0 {
                    // Octet-aligned: canonical dotted text shares the prefix.
                    let octs = lo.to_be_bytes();
                    let k = usize::from(prefix / 8);
                    let mut p = octs[..k]
                        .iter()
                        .map(u8::to_string)
                        .collect::<Vec<_>>()
                        .join(".");
                    p.push('.');
                    out.push_str("starts_with(");
                    out.push_str(col);
                    out.push_str(", ");
                    self.bind(Param::Str(p), out);
                    out.push(')');
                } else {
                    out.push_str("(wl_ip_num(");
                    out.push_str(col);
                    out.push_str(") BETWEEN ");
                    self.bind(Param::Int(i64::from(lo)), out);
                    out.push_str(" AND ");
                    self.bind(Param::Int(i64::from(hi)), out);
                    out.push(')');
                }
            }
            IpAddr::V6(_) => {
                return Err(ApiError::invalid_filter(
                    "IPv6 networks need an open index to resolve",
                    c.span,
                ));
            }
        }
        Ok(())
    }
}

fn max_prefix(a: &IpAddr) -> u32 {
    if a.is_ipv4() { 32 } else { 128 }
}

/// Glob → LIKE pattern with `\` as the escape character.
pub fn glob_to_like(g: &str) -> String {
    let mut s = String::with_capacity(g.len() + 2);
    for ch in g.chars() {
        match ch {
            '*' => s.push('%'),
            '?' => s.push('_'),
            '%' | '_' | '\\' => {
                s.push('\\');
                s.push(ch);
            }
            c => s.push(c),
        }
    }
    s
}

/// The SQL macro `wl_ip_num(text)`: IPv4 dotted text → integer, NULL
/// otherwise. Installed on every read connection by `Index::open`.
pub const IP_NUM_MACRO: &str = "CREATE OR REPLACE MACRO wl_ip_num(s) AS CASE \
    WHEN regexp_full_match(s, '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}') THEN \
    TRY_CAST(split_part(s, '.', 1) AS BIGINT) * 16777216 + \
    TRY_CAST(split_part(s, '.', 2) AS BIGINT) * 65536 + \
    TRY_CAST(split_part(s, '.', 3) AS BIGINT) * 256 + \
    TRY_CAST(split_part(s, '.', 4) AS BIGINT) ELSE NULL END";

// ---------------------------------------------------------------- autocomplete

/// What the cursor is completing.
#[derive(Debug, Clone, PartialEq)]
pub enum CompletionKind {
    /// Start of a term: fields, shorthands, keywords.
    Term,
    /// After a field: operators.
    Operator(&'static FieldDef),
    /// After `field op`: values of that field.
    Value(&'static FieldDef),
    /// After `host`/`src`/`dst`: addresses.
    Host,
    /// After `port`.
    Port,
    /// After `mac`: MAC addresses seen in `wifi`.
    Mac,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Completion {
    pub kind: CompletionKind,
    /// Replace `[start, end)` of the input.
    pub start: usize,
    pub end: usize,
    /// Text being completed (without an opening quote).
    pub word: String,
    /// The word is inside an opening `"`.
    pub quoted: bool,
    /// The previous token ends a term (so `and`/`or` make sense).
    pub after_term: bool,
}

/// Works out what is being completed at byte offset `cursor_pos`.
pub fn completion_context(partial: &str, cursor_pos: u32) -> Completion {
    let cap = partial.len().min(MAX_LEN);
    let mut cur = (cursor_pos as usize).min(cap);
    while cur > 0 && !partial.is_char_boundary(cur) {
        cur -= 1;
    }
    let before = &partial[..cur];
    // Inside an open string?
    let quotes = before.bytes().filter(|b| *b == b'"').count() - before.matches("\\\"").count();
    let (start, quoted) = if quotes % 2 == 1 {
        (before.rfind('"').map(|i| i + 1).unwrap_or(0), true)
    } else {
        let s = before
            .char_indices()
            .rev()
            .find(|(_, c)| !is_word_char(*c))
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        (s, false)
    };
    let word = before[start..].to_string();
    let head_end = if quoted { start - 1 } else { start };
    // Tokens before the word, leniently.
    let toks: Vec<Tok> = lex_lenient(&before[..head_end]);
    let last = toks.last();
    let prev = if toks.len() >= 2 {
        toks.get(toks.len() - 2)
    } else {
        None
    };
    let word_of = |t: Option<&Tok>| match t {
        Some(Tok::Word(w)) => Some(w.to_ascii_lowercase()),
        _ => None,
    };
    let after_term = matches!(
        last,
        Some(Tok::Word(_) | Tok::Str(_) | Tok::RParen | Tok::RBrack)
    );
    let kind = match last {
        Some(Tok::Word(w)) if fields::field(w).is_some() => {
            CompletionKind::Operator(fields::field(w).unwrap_or(&fields::FIELDS[0]))
        }
        Some(Tok::Word(w)) if ["host", "src", "dst"].contains(&w.to_ascii_lowercase().as_str()) => {
            CompletionKind::Host
        }
        Some(Tok::Word(w)) if w.eq_ignore_ascii_case("port") => CompletionKind::Port,
        Some(Tok::Word(w)) if w.eq_ignore_ascii_case("mac") => CompletionKind::Mac,
        Some(Tok::Op(_)) => match word_of(prev).and_then(|w| fields::field(&w)) {
            Some(f) => CompletionKind::Value(f),
            None => CompletionKind::Term,
        },
        Some(Tok::LBrack | Tok::Comma) => {
            // Walk back to the `field in [`.
            let open = toks.iter().rposition(|t| *t == Tok::LBrack);
            match open
                .and_then(|i| i.checked_sub(2))
                .and_then(|i| word_of(toks.get(i)))
                .and_then(|w| fields::field(&w))
            {
                Some(f) => CompletionKind::Value(f),
                None => CompletionKind::Term,
            }
        }
        _ => CompletionKind::Term,
    };
    Completion {
        kind,
        start,
        end: cur,
        word,
        quoted,
        after_term: after_term && !matches!(last, Some(Tok::Word(w)) if is_connective(w)),
    }
}

fn is_connective(w: &str) -> bool {
    ["and", "or", "not"]
        .iter()
        .any(|k| w.eq_ignore_ascii_case(k))
}

fn lex_lenient(s: &str) -> Vec<Tok> {
    match lex(s) {
        Ok(t) => t.into_iter().map(|t| t.tok).collect(),
        Err(_) => s
            .split_whitespace()
            .map(|w| match w {
                "==" => Tok::Op(Op::Eq),
                "!=" => Tok::Op(Op::Ne),
                "~" => Tok::Op(Op::Glob),
                _ => Tok::Word(w.to_string()),
            })
            .collect(),
    }
}

/// Static suggestions (fields, operators, keywords, fixed values) that need no
/// index. `Index::autocomplete` adds values from the index.
pub fn autocomplete_static(partial: &str, cursor_pos: u32) -> Vec<walleye_core::ipc::Suggestion> {
    let ctx = completion_context(partial, cursor_pos);
    static_suggestions(&ctx)
}

pub(crate) fn static_suggestions(ctx: &Completion) -> Vec<walleye_core::ipc::Suggestion> {
    use walleye_core::ipc::{Suggestion, SuggestionKind as K};
    let mk = |label: &str, insert: &str, kind: K, detail: Option<&str>| Suggestion {
        label: label.to_string(),
        insert_text: insert.to_string(),
        kind,
        detail: detail.map(str::to_string),
        replace_start: ctx.start as u32,
        replace_end: ctx.end as u32,
    };
    let w = ctx.word.to_ascii_lowercase();
    let mut out = Vec::new();
    match &ctx.kind {
        CompletionKind::Operator(f) => {
            let ops: &[&str] = match f.ty {
                FieldType::Int | FieldType::Bytes | FieldType::Time | FieldType::Duration => {
                    &["==", "!=", ">", ">=", "<", "<=", "in"]
                }
                FieldType::Ip | FieldType::Str | FieldType::StrList | FieldType::Mac => {
                    &["==", "!=", "~", "in"]
                }
                FieldType::Bool => &["==", "!="],
                FieldType::Proto => &["==", "!=", "in"],
            };
            for o in ops.iter().filter(|o| o.starts_with(&w)) {
                let ins = if *o == "in" { "in [" } else { o };
                out.push(mk(o, ins, K::Operator, None));
            }
        }
        CompletionKind::Value(f) => {
            let kinds: Vec<&str>;
            let fixed: &[&str] = match (f.ty, f.name) {
                (FieldType::Bool, _) => &["true", "false"],
                (FieldType::Proto, _) => &["tcp", "udp", "icmp", "icmp6"],
                (_, "app_proto") => &["dns", "http", "tls"],
                (_, "wifi.kind") => {
                    kinds = walleye_core::WifiKind::ALL
                        .iter()
                        .map(|k| k.as_str())
                        .collect();
                    &kinds
                }
                (_, "wifi.security" | "ap.security") => &WIFI_SECURITY,
                _ => &[],
            };
            for v in fixed.iter().filter(|v| v.starts_with(&w)) {
                out.push(mk(v, v, K::Value, Some(f.name)));
            }
        }
        CompletionKind::Host | CompletionKind::Port | CompletionKind::Mac => {}
        CompletionKind::Term => {
            if ctx.after_term {
                for k in ["and", "or"].iter().filter(|k| k.starts_with(&w)) {
                    out.push(mk(k, k, K::Keyword, None));
                }
            }
            for f in fields::FIELDS.iter().filter(|f| f.name.starts_with(&w)) {
                out.push(mk(f.name, f.name, K::Field, Some(f.doc)));
            }
            for k in fields::SHORTHANDS
                .iter()
                .chain(fields::BARE_PROTOCOLS)
                .chain(["not"].iter())
                .filter(|k| !w.is_empty() && k.starts_with(&w))
            {
                out.push(mk(k, k, K::Keyword, None));
            }
        }
    }
    out
}

/// `security` values ingest writes (CONTRACTS §11.1).
const WIFI_SECURITY: [&str; 7] = ["open", "wep", "wpa", "wpa2", "wpa3", "wpa2/wpa3", "owe"];

/// Renders a value for insertion: bare when it lexes as a plain word,
/// otherwise a quoted, escaped string.
pub fn render_value(v: &str, quoted_ctx: bool) -> String {
    let bare_ok = !v.is_empty()
        && v.chars().all(is_word_char)
        && !is_connective(v)
        && !v.eq_ignore_ascii_case("in");
    if bare_ok && !quoted_ctx {
        return v.to_string();
    }
    // In a quoted context the replace range includes the opening quote, so
    // the inserted text always carries both quotes.
    let mut s = String::with_capacity(v.len() + 2);
    s.push('"');
    for c in v.chars() {
        if c == '"' || c == '\\' {
            s.push('\\');
        }
        s.push(c);
    }
    s.push('"');
    s
}
