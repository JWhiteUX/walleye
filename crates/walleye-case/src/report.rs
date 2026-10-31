//! Case report: one document model rendered to Markdown and PDF.
//!
//! Principle: *evidence or it didn't happen*. Every line that makes a claim
//! (a finding, a reason, an ATT&CK technique, an IOC, a pinned item) carries
//! an evidence link with plain frame numbers and the capture's SHA-256:
//!
//! ```text
//! [frames 41, 57, 63](walleye://sha256/<64-hex capture sha256>/frames/41,57,63)
//! ```
//!
//! When an evidence record has flows but no frames, the link names flows:
//! `walleye://sha256/<sha>/flows/3,4`. Analyst content (notes, verdicts) is
//! rendered as block quotes labelled "not a claim".
//!
//! Captured strings are hostile. In Markdown they are only ever emitted as
//! code spans (never parsed as Markdown, never autolinked) with control and
//! bidi characters made visible; analyst prose is backslash-escaped. No HTML
//! is ever emitted.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use walleye_core::{
    ApiError, CaptureRow, ErrorCode, Evidence, Finding, Ioc, Verdict,
    error::ApiResult,
    ipc::{Case, EvidenceRef, ReportFormat, View},
};

use crate::{export::write_atomic, ioc::type_name, pdf, timefmt};

/// Inputs for a report (CONTRACTS §7).
pub struct ReportInput<'a> {
    pub capture: &'a CaptureRow,
    pub case: &'a Case,
    pub findings: &'a [Finding],
    pub iocs: &'a [Ioc],
    /// PNG bytes of the timeline snapshot, when the UI provided one.
    pub timeline_png: Option<&'a [u8]>,
}

/// URL scheme of evidence links.
pub const LINK_SCHEME: &str = "walleye://sha256/";
/// Frame numbers listed in one evidence label.
pub const MAX_LISTED: usize = 10;
/// Longest captured string shown in a report, in characters.
pub const MAX_VALUE_CHARS: usize = 300;
/// Distinct queries listed in "Queries used".
pub const MAX_QUERIES_LISTED: usize = 200;
/// Largest timeline PNG accepted.
pub const MAX_PNG_BYTES: usize = 20 * 1024 * 1024;
/// File name of the timeline image written next to `report.md`.
pub const TIMELINE_PNG_NAME: &str = "report-timeline.png";

/// Section titles. Sections in [`CLAIM_SECTIONS`] must link every claim line.
pub mod section {
    pub const CAPTURE: &str = "Capture";
    pub const TIMELINE: &str = "Timeline";
    pub const FINDINGS: &str = "Findings";
    pub const ATTACK: &str = "ATT&CK techniques";
    pub const IOCS: &str = "Indicators of compromise";
    pub const PINS: &str = "Pinned evidence";
    pub const NOTES: &str = "Analyst notes";
    pub const QUERIES: &str = "Queries used";
    pub const ABOUT: &str = "About this report";
}

pub const CLAIM_SECTIONS: &[&str] = &[
    section::FINDINGS,
    section::ATTACK,
    section::IOCS,
    section::PINS,
];

// ---------------------------------------------------------------------------
// document model

#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceLink {
    /// Plain text with the frame (or flow) numbers, e.g. "frames 41, 57".
    pub label: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Inline {
    /// Trusted text written by this module (labels, numbers). Never capture data.
    Lit(String),
    /// Trusted, emphasized.
    Strong(String),
    /// Untrusted value (captured string or id): code span / monospace.
    Code(String),
    /// Untrusted prose (analyst text): escaped.
    Prose(String),
    Link(EvidenceLink),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Block {
    Title(String),
    Section(&'static str),
    Sub(Vec<Inline>),
    Para(Vec<Inline>),
    /// Italic trusted sentence (section intros, empty states).
    Aside(String),
    Bullet(Vec<Inline>),
    /// Analyst content: label + untrusted text, possibly multi-line.
    Note {
        label: String,
        text: String,
    },
    Table {
        header: Vec<&'static str>,
        rows: Vec<Vec<Vec<Inline>>>,
    },
    Image {
        alt: String,
        file: String,
    },
}

pub struct Doc {
    pub blocks: Vec<Block>,
    /// Decoded timeline image (RGB8), for the PDF.
    pub image: Option<pdf::RgbImage>,
    pub sha256: String,
}

fn lit(s: impl Into<String>) -> Inline {
    Inline::Lit(s.into())
}
fn code(s: impl Into<String>) -> Inline {
    Inline::Code(s.into())
}

/// Build the evidence link for `ev` in capture `sha256`.
pub fn evidence_link(sha256: &str, ev: &Evidence) -> Option<EvidenceLink> {
    let (noun, ids): (&str, &[u64]) = if !ev.frame_nos.is_empty() {
        ("frame", &ev.frame_nos)
    } else if !ev.flow_ids.is_empty() {
        ("flow", &ev.flow_ids)
    } else {
        return None;
    };
    let shown: Vec<String> = ids.iter().take(MAX_LISTED).map(u64::to_string).collect();
    let total = (ev.total as usize).max(ids.len());
    let mut label = format!(
        "{noun}{} {}",
        if ids.len() == 1 && total == 1 {
            ""
        } else {
            "s"
        },
        shown.join(", ")
    );
    if total > shown.len() {
        label.push_str(&format!(" … ({total} total)"));
    }
    Some(EvidenceLink {
        label,
        url: format!("{LINK_SCHEME}{sha256}/{noun}s/{}", shown.join(",")),
    })
}

fn link_or_none(sha: &str, ev: &Evidence) -> Inline {
    match evidence_link(sha, ev) {
        Some(l) => Inline::Link(l),
        None => lit("(no evidence recorded)"),
    }
}

/// Union of several evidence records (sorted, capped like the index).
fn merge_evidence<'a>(evs: impl IntoIterator<Item = &'a Evidence>) -> Evidence {
    let mut frames = BTreeSet::new();
    let mut flows = BTreeSet::new();
    let mut truncated = false;
    for e in evs {
        frames.extend(e.frame_nos.iter().copied());
        flows.extend(e.flow_ids.iter().copied());
        truncated |= e.truncated;
    }
    let cap = walleye_core::findings::EVIDENCE_CAP;
    let total = frames.len().max(flows.len()) as u64;
    Evidence {
        truncated: truncated || frames.len() > cap || flows.len() > cap,
        frame_nos: frames.into_iter().take(cap).collect(),
        flow_ids: flows.into_iter().take(cap).collect(),
        total,
    }
}

/// Ids shown as trusted text keep only `[A-Za-z0-9_-]`.
fn safe_id(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .take(64)
        .collect()
}

fn technique_name(t: &str) -> Option<&'static str> {
    Some(match t {
        "T1071" => "Application Layer Protocol",
        "T1071.001" => "Application Layer Protocol: Web Protocols",
        "T1071.004" => "Application Layer Protocol: DNS",
        "T1568" => "Dynamic Resolution",
        "T1568.002" => "Dynamic Resolution: Domain Generation Algorithms",
        "T1048" => "Exfiltration Over Alternative Protocol",
        "T1572" => "Protocol Tunneling",
        "T1573" => "Encrypted Channel",
        _ => return None,
    })
}

fn verdict_text(v: Verdict) -> &'static str {
    match v {
        Verdict::Suspicious => "suspicious",
        Verdict::Benign => "benign",
        Verdict::NeedsReview => "needs review",
    }
}

fn view_text(v: View) -> &'static str {
    match v {
        View::Flows => "flows",
        View::Dns => "dns",
        View::Http => "http",
        View::Tls => "tls",
        View::Files => "files",
        View::Frames => "frames",
    }
}

fn score_band(score: f64) -> &'static str {
    if score >= 70.0 {
        "High"
    } else if score >= 40.0 {
        "Medium"
    } else {
        "Low"
    }
}

fn fmt_num(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{v:.0}")
    } else {
        let s = format!("{v:.4}");
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

/// Assemble the document. `generated_at` (µs) is shown in the header when
/// given; golden tests pass `None` for stable output.
pub fn build(input: &ReportInput, generated_at: Option<i64>) -> ApiResult<Doc> {
    let cap = input.capture;
    let sha = cap.sha256.as_str();
    let mut b = Vec::new();

    let image = match input.timeline_png {
        Some(png) => Some(pdf::decode_png(png)?),
        None => None,
    };

    b.push(Block::Title("Walleye case report".into()));
    let mut head = vec![
        lit("Case "),
        code(&input.case.case_id),
        lit(" · capture SHA-256 "),
        code(sha),
    ];
    if let Some(t) = generated_at {
        head.push(lit(format!(" · generated {}", timefmt::display(t))));
    }
    b.push(Block::Para(head));
    b.push(Block::Aside(
        "Every claim below links to frame numbers in this capture; analyst notes and verdicts are marked as such and are not claims."
            .into(),
    ));

    // -- capture header
    b.push(Block::Section(section::CAPTURE));
    let span = cap.last_ts - cap.first_ts;
    b.push(Block::Table {
        header: vec!["Field", "Value"],
        rows: vec![
            vec![vec![lit("Path")], vec![code(&cap.path)]],
            vec![vec![lit("SHA-256")], vec![code(sha)]],
            vec![vec![lit("Capture ID")], vec![code(&cap.capture_id)]],
            vec![
                vec![lit("Size")],
                vec![lit(format!("{} bytes", cap.size_bytes))],
            ],
            vec![
                vec![lit("Format")],
                vec![lit(match cap.format {
                    walleye_core::CaptureFormat::Pcap => "pcap",
                    walleye_core::CaptureFormat::Pcapng => "pcapng",
                })],
            ],
            vec![vec![lit("Frames")], vec![lit(cap.frame_count.to_string())]],
            vec![
                vec![lit("Time span")],
                vec![lit(format!(
                    "{} → {} ({})",
                    timefmt::display(cap.first_ts),
                    timefmt::display(cap.last_ts),
                    timefmt::duration(span)
                ))],
            ],
        ],
    });

    // -- timeline
    if image.is_some() {
        b.push(Block::Section(section::TIMELINE));
        b.push(Block::Image {
            alt: "Timeline snapshot at export time".into(),
            file: TIMELINE_PNG_NAME.into(),
        });
    }

    // -- findings
    let mut findings: Vec<&Finding> = input.findings.iter().collect();
    findings.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.finding_id.cmp(&b.finding_id))
    });
    let label_of: HashMap<&str, String> = findings
        .iter()
        .enumerate()
        .map(|(i, f)| (f.finding_id.as_str(), format!("F{}", i + 1)))
        .collect();
    let verdicts: HashMap<&str, &walleye_core::ipc::VerdictEntry> = input
        .case
        .verdicts
        .iter()
        .map(|v| (v.finding_id.as_str(), v))
        .collect();

    b.push(Block::Section(section::FINDINGS));
    if findings.is_empty() {
        b.push(Block::Aside("No findings.".into()));
    }
    for (i, f) in findings.iter().enumerate() {
        let all = merge_evidence(f.reasons.iter().map(|r| &r.evidence));
        b.push(Block::Sub(vec![
            lit(format!("F{}. ", i + 1)),
            code(&f.title),
            lit(" — "),
            link_or_none(sha, &all),
        ]));
        let mut meta = vec![
            lit("Score "),
            Inline::Strong(fmt_num(f.score.round())),
            lit(format!(" ({}) · ", score_band(f.score))),
            code(&f.entity_type),
            lit(" "),
            code(&f.entity),
            lit(" · detector "),
            code(&f.detector),
        ];
        if let Some(t) = &f.attack_technique {
            meta.extend([lit(" · ATT&CK "), code(t)]);
        }
        meta.extend([
            lit(format!(
                " · seen {} → {} · finding ",
                timefmt::display(f.ts_first),
                timefmt::display(f.ts_last)
            )),
            code(&f.finding_id),
            lit(" · capture SHA-256 "),
            code(sha),
            lit(" — "),
            link_or_none(sha, &all),
        ]);
        b.push(Block::Bullet(meta));
        for r in &f.reasons {
            let mut line = vec![
                Inline::Strong(format!("{} pts", fmt_num(r.weight))),
                lit(" · rule "),
                code(&r.rule_id),
                lit(" · "),
                code(&r.signal),
                lit(format!(" = {}", fmt_num(r.value))),
            ];
            if let Some(u) = &r.unit {
                line.extend([lit(" "), code(u)]);
            }
            line.extend([
                lit(" · "),
                code(&r.explanation),
                lit(" · capture SHA-256 "),
                code(sha),
                lit(" — "),
                link_or_none(sha, &r.evidence),
            ]);
            b.push(Block::Bullet(line));
        }
        let verdict = verdicts
            .get(f.finding_id.as_str())
            .map(|v| (v.verdict, v.note.as_str()))
            .or(f.verdict.map(|v| (v, "")));
        if let Some((v, note)) = verdict {
            let text = if note.trim().is_empty() {
                verdict_text(v).to_string()
            } else {
                format!("{} — {}", verdict_text(v), note)
            };
            b.push(Block::Note {
                label: "Analyst verdict (not a claim):".into(),
                text,
            });
        }
    }

    // -- ATT&CK
    b.push(Block::Section(section::ATTACK));
    let mut techniques: BTreeMap<String, (BTreeSet<usize>, Vec<&Evidence>)> = BTreeMap::new();
    for (i, f) in findings.iter().enumerate() {
        for r in &f.reasons {
            if let Some(t) = r.attack_technique.as_ref().or(f.attack_technique.as_ref()) {
                let e = techniques.entry(t.clone()).or_default();
                e.0.insert(i);
                e.1.push(&r.evidence);
            }
        }
    }
    if techniques.is_empty() {
        b.push(Block::Aside("No ATT&CK techniques were attributed.".into()));
    }
    for (t, (fs, evs)) in &techniques {
        let mut line = vec![code(t)];
        if let Some(name) = technique_name(t) {
            line.push(lit(format!(" {name}")));
        }
        let labels: Vec<String> = fs.iter().map(|i| format!("F{}", i + 1)).collect();
        line.extend([
            lit(format!(" · findings {}", labels.join(", "))),
            lit(" — "),
            link_or_none(sha, &merge_evidence(evs.iter().copied())),
        ]);
        b.push(Block::Bullet(line));
    }

    // -- IOCs
    b.push(Block::Section(section::IOCS));
    b.push(Block::Aside(
        "Values are defanged. Allowlisted indicators are known-good destinations, kept and flagged."
            .into(),
    ));
    if input.iocs.is_empty() {
        b.push(Block::Aside("No indicators were extracted.".into()));
    } else {
        let rows = input
            .iocs
            .iter()
            .map(|i| {
                vec![
                    vec![lit(type_name(i.ioc_type))],
                    vec![code(&i.defanged)],
                    vec![lit(timefmt::display(i.first_seen))],
                    vec![link_or_none(sha, &i.evidence)],
                    match (&i.allowlisted, &i.allowlist_reason) {
                        (true, Some(r)) => vec![lit("yes: "), code(r)],
                        (true, None) => vec![lit("yes")],
                        _ => vec![lit("no")],
                    },
                    match i.source_finding_id.as_deref() {
                        Some(id) => match label_of.get(id) {
                            Some(l) => vec![lit(l.clone())],
                            None => vec![code(id)],
                        },
                        None => vec![lit("—")],
                    },
                ]
            })
            .collect();
        b.push(Block::Table {
            header: vec![
                "Type",
                "Indicator (defanged)",
                "First seen",
                "Evidence",
                "Allowlisted",
                "Finding",
            ],
            rows,
        });
    }

    // -- pins
    let iocs_by_id: HashMap<&str, &Ioc> =
        input.iocs.iter().map(|i| (i.ioc_id.as_str(), i)).collect();
    let titles: HashMap<&str, &str> = findings
        .iter()
        .map(|f| (f.finding_id.as_str(), f.title.as_str()))
        .collect();
    b.push(Block::Section(section::PINS));
    let (notes, pins): (Vec<_>, Vec<_>) = input
        .case
        .pins
        .iter()
        .partition(|p| matches!(p.evidence, EvidenceRef::Note));
    if pins.is_empty() {
        b.push(Block::Aside("Nothing was pinned.".into()));
    }
    for p in &pins {
        let mut line = vec![Inline::Strong(safe_id(&p.pin_id)), lit(" · ")];
        match &p.evidence {
            EvidenceRef::Frame { frame_no } => line.push(lit(format!("frame {frame_no}"))),
            EvidenceRef::Flow { flow_id } => line.push(lit(format!("flow {flow_id}"))),
            EvidenceRef::Finding { finding_id } => {
                line.extend([lit("finding "), code(finding_id)]);
                if let (Some(l), Some(t)) = (
                    label_of.get(finding_id.as_str()),
                    titles.get(finding_id.as_str()),
                ) {
                    line.extend([lit(format!(" ({l} ")), code(*t), lit(")")]);
                }
            }
            EvidenceRef::Ioc { ioc_id } => match iocs_by_id.get(ioc_id.as_str()) {
                Some(i) => line.extend([
                    lit(format!("{} ", type_name(i.ioc_type))),
                    code(&i.defanged),
                ]),
                None => line.extend([lit("indicator "), code(ioc_id)]),
            },
            EvidenceRef::Query {
                filter,
                view,
                time_range,
            } => {
                line.extend([
                    lit(format!("query on {} ", view_text(*view))),
                    code(if filter.is_empty() {
                        "(no filter)"
                    } else {
                        filter
                    }),
                ]);
                if let Some(r) = time_range {
                    line.push(lit(format!(
                        " in {} → {}",
                        timefmt::display(r.start),
                        timefmt::display(r.end)
                    )));
                }
            }
            EvidenceRef::Note => {}
        }
        line.extend([
            lit(format!(" · pinned {}", timefmt::display(p.created_at))),
            lit(" — "),
            link_or_none(sha, &p.resolved),
        ]);
        b.push(Block::Bullet(line));
        if !p.note.trim().is_empty() {
            b.push(Block::Note {
                label: "Analyst note (not a claim):".into(),
                text: p.note.clone(),
            });
        }
    }

    // -- notes
    b.push(Block::Section(section::NOTES));
    if notes.is_empty() {
        b.push(Block::Aside("No analyst notes.".into()));
    }
    for p in &notes {
        b.push(Block::Note {
            label: format!(
                "Analyst note (not a claim), {} at {}:",
                safe_id(&p.pin_id),
                timefmt::display(p.created_at)
            ),
            text: p.note.clone(),
        });
    }

    // -- queries
    b.push(Block::Section(section::QUERIES));
    b.push(Block::Aside(
        "A log of the queries run in this case (a record, not a claim). SQL shows placeholders, never values."
            .into(),
    ));
    type QKey = (String, String, Option<(i64, i64)>, Option<String>);
    let mut order: Vec<QKey> = Vec::new();
    let mut agg: HashMap<QKey, (i64, usize, u64)> = HashMap::new();
    for q in &input.case.queries {
        let k: QKey = (
            view_text(q.view).to_string(),
            q.filter.clone(),
            q.time_range.map(|r| (r.start, r.end)),
            q.sql.clone(),
        );
        let e = agg.entry(k.clone()).or_insert_with(|| {
            order.push(k);
            (q.at, 0, 0)
        });
        e.1 += 1;
        e.2 = q.rows;
    }
    if order.is_empty() {
        b.push(Block::Aside("No queries were logged.".into()));
    } else {
        let rows = order
            .iter()
            .take(MAX_QUERIES_LISTED)
            .enumerate()
            .map(|(n, k)| {
                let (at, runs, rows) = agg[k];
                vec![
                    vec![lit((n + 1).to_string())],
                    vec![lit(timefmt::display(at))],
                    vec![lit(runs.to_string())],
                    vec![lit(k.0.clone())],
                    vec![code(if k.1.is_empty() { "(no filter)" } else { &k.1 })],
                    vec![lit(match k.2 {
                        Some((s, e)) => {
                            format!("{} → {}", timefmt::display(s), timefmt::display(e))
                        }
                        None => "whole capture".into(),
                    })],
                    vec![lit(rows.to_string())],
                    match &k.3 {
                        Some(sql) => vec![code(sql)],
                        None => vec![lit("—")],
                    },
                ]
            })
            .collect();
        b.push(Block::Table {
            header: vec![
                "#",
                "First run",
                "Runs",
                "View",
                "Filter",
                "Time range",
                "Rows",
                "SQL",
            ],
            rows,
        });
        if order.len() > MAX_QUERIES_LISTED {
            b.push(Block::Aside(format!(
                "{} more distinct queries are not listed.",
                order.len() - MAX_QUERIES_LISTED
            )));
        }
    }

    // -- about
    b.push(Block::Section(section::ABOUT));
    b.push(Block::Bullet(vec![
        lit("Evidence links have the form "),
        code(format!("{LINK_SCHEME}<capture SHA-256>/frames/<n>[,<n>…]")),
        lit(" (or "),
        code("/flows/<id>…"),
        lit(" when only flows were recorded). The link text lists the frame numbers; open them in Walleye or Wireshark (Go to packet)."),
    ]));
    b.push(Block::Bullet(vec![
        lit(format!(
            "At most {MAX_LISTED} frame numbers are listed per claim; the total is given when there are more."
        )),
    ]));
    b.push(Block::Bullet(vec![
        lit(format!(
            "Generated by Walleye {} from the capture with SHA-256 ",
            env!("CARGO_PKG_VERSION")
        )),
        code(sha),
        lit("."),
    ]));

    Ok(Doc {
        blocks: b,
        image,
        sha256: sha.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Markdown

/// Make control, zero-width and bidi characters visible (`\u{202e}`) and
/// cap the length, so a captured string cannot reorder, hide or break lines.
pub fn sanitize(s: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (n, c) in s.chars().enumerate() {
        if n >= max_chars {
            out.push('…');
            break;
        }
        let invisible = c.is_control()
            || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}' | '\u{2028}' | '\u{2029}');
        if invisible {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// Backslash-escape every ASCII punctuation character (always valid in
/// CommonMark), so prose cannot open emphasis, links, HTML, headings, lists
/// or autolinks.
pub fn escape_prose(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in sanitize(s, usize::MAX).chars() {
        if c.is_ascii_punctuation() {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Code span that holds `s` verbatim. In a table cell, `|` is escaped as
/// GFM requires even inside code spans.
pub fn code_span(s: &str, in_table: bool) -> String {
    let s = sanitize(s, MAX_VALUE_CHARS);
    let s = if in_table { s.replace('|', "\\|") } else { s };
    let mut longest = 0;
    let mut run = 0;
    for c in s.chars() {
        run = if c == '`' { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    let fence = "`".repeat(longest + 1);
    let pad = s.starts_with('`') || s.ends_with('`') || s.starts_with(' ') || s.ends_with(' ');
    if s.is_empty() {
        return "` `".into();
    }
    if pad {
        format!("{fence} {s} {fence}")
    } else {
        format!("{fence}{s}{fence}")
    }
}

fn md_inlines(v: &[Inline], in_table: bool) -> String {
    let mut out = String::new();
    for i in v {
        match i {
            Inline::Lit(s) => out.push_str(s),
            Inline::Strong(s) => out.push_str(&format!("**{s}**")),
            Inline::Code(s) => out.push_str(&code_span(s, in_table)),
            Inline::Prose(s) => out.push_str(&escape_prose(s)),
            Inline::Link(l) => out.push_str(&format!("[{}]({})", l.label, l.url)),
        }
    }
    out
}

pub fn render_markdown(doc: &Doc) -> String {
    let mut out = String::new();
    for b in &doc.blocks {
        match b {
            Block::Title(t) => out.push_str(&format!("# {t}\n\n")),
            Block::Section(t) => out.push_str(&format!("## {t}\n\n")),
            Block::Sub(v) => out.push_str(&format!("### {}\n\n", md_inlines(v, false))),
            Block::Para(v) => out.push_str(&format!("{}\n\n", md_inlines(v, false))),
            Block::Aside(t) => out.push_str(&format!("_{t}_\n\n")),
            Block::Bullet(v) => {
                out.push_str(&format!("- {}\n", md_inlines(v, false)));
            }
            Block::Note { label, text } => {
                let mut lines = text.lines();
                let first = lines.next().unwrap_or("");
                out.push_str(&format!("> **{label}** {}\n", escape_prose(first)));
                for l in lines {
                    out.push_str(&format!(">\n> {}\n", escape_prose(l)));
                }
                out.push('\n');
            }
            Block::Table { header, rows } => {
                out.push_str(&format!("| {} |\n", header.join(" | ")));
                out.push_str(&format!("|{}\n", "---|".repeat(header.len())));
                for r in rows {
                    let cells: Vec<String> = r.iter().map(|c| md_inlines(c, true)).collect();
                    out.push_str(&format!("| {} |\n", cells.join(" | ")));
                }
                out.push('\n');
            }
            Block::Image { alt, file } => out.push_str(&format!("![{alt}]({file})\n\n")),
        }
    }
    // Bullets are emitted without trailing blank lines; normalize runs of
    // blank lines and make sure a list is followed by one.
    let mut tidy = String::with_capacity(out.len());
    let mut prev_bullet = false;
    for line in out.lines() {
        let is_bullet = line.starts_with("- ");
        if prev_bullet && !is_bullet && !line.is_empty() {
            tidy.push('\n');
        }
        tidy.push_str(line);
        tidy.push('\n');
        prev_bullet = is_bullet;
    }
    while tidy.ends_with("\n\n") {
        tidy.pop();
    }
    tidy
}

// ---------------------------------------------------------------------------
// export

/// Contract entry point (CONTRACTS §7). Writes `report.md` (plus
/// `report-timeline.png` when a snapshot is given) or `report.pdf` into
/// `out_dir` and returns the report's absolute path.
pub fn export_report(
    input: &ReportInput,
    format: ReportFormat,
    out_dir: &Path,
) -> ApiResult<PathBuf> {
    export_report_at(input, format, out_dir, Some(timefmt::now_us()))
}

pub fn export_report_at(
    input: &ReportInput,
    format: ReportFormat,
    out_dir: &Path,
    generated_at: Option<i64>,
) -> ApiResult<PathBuf> {
    if let Some(png) = input.timeline_png {
        if png.len() > MAX_PNG_BYTES {
            return Err(ApiError::new(
                ErrorCode::InvalidArgument,
                "timeline snapshot is too large",
            ));
        }
    }
    let doc = build(input, generated_at)?;
    match format {
        ReportFormat::Markdown => {
            if let Some(png) = input.timeline_png {
                write_atomic(out_dir, TIMELINE_PNG_NAME, png)?;
            }
            write_atomic(out_dir, "report.md", render_markdown(&doc).as_bytes())
        }
        ReportFormat::Pdf => write_atomic(out_dir, "report.pdf", &pdf::render(&doc)),
    }
}

/// Decode the `timeline_png_base64` IPC argument (no `data:` prefix).
pub fn decode_timeline_png(b64: &str) -> ApiResult<Vec<u8>> {
    use base64::Engine as _;
    if b64.len() > MAX_PNG_BYTES / 3 * 4 + 4 {
        return Err(ApiError::new(
            ErrorCode::InvalidArgument,
            "timeline snapshot is too large",
        ));
    }
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| {
            ApiError::new(
                ErrorCode::InvalidArgument,
                "timeline snapshot is not base64",
            )
        })
}
