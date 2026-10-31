#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;

use common::*;
use walleye_case::{
    ExportOptions,
    export::{csv_cell, iocs_csv, iocs_json},
    export_iocs, extract_iocs,
    report::{
        self, CLAIM_SECTIONS, LINK_SCHEME, ReportInput, build, export_report_at, render_markdown,
    },
};
use walleye_core::{
    Evidence, Finding, Ioc, IocType,
    ipc::{IocFormat, ReportFormat},
};

fn scenario_iocs() -> (Vec<Finding>, Vec<Ioc>) {
    let (src, findings) = scenario();
    let iocs = extract_iocs(&findings, &src, &allowlist()).unwrap();
    (findings, iocs)
}

// ------------------------------------------------------------------- CSV/JSON

#[test]
fn csv_golden() {
    let (_, iocs) = scenario_iocs();
    let csv = iocs_csv(&iocs, &capture(), ExportOptions::default());
    assert_golden("iocs.csv", &csv);
    // RFC 4180: CRLF everywhere, header + one record per IOC
    assert!(csv.ends_with("\r\n"));
    assert_eq!(csv.matches("\r\n").count(), iocs.len() + 1);
    assert!(!csv.replace("\r\n", "").contains('\n'));
    // every record carries the capture hash and frame numbers
    for line in csv.lines().skip(1) {
        assert!(line.ends_with(SHA), "{line}");
    }
    // defanged by default: no live values
    assert!(!csv.contains("cdn-update.top"));
    assert!(csv.contains("cdn-update[.]top"));
}

#[test]
fn json_golden() {
    let (_, iocs) = scenario_iocs();
    let json = iocs_json(&iocs, &capture(), ExportOptions::default()).unwrap();
    assert_golden("iocs.json", &json);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["capture"]["sha256"], SHA);
    assert_eq!(v["defanged"], true);
    assert_eq!(v["iocs"].as_array().unwrap().len(), iocs.len());
    for i in v["iocs"].as_array().unwrap() {
        assert!(!i["evidence"]["frame_nos"].as_array().unwrap().is_empty());
        assert!(!i["indicator"].as_str().unwrap().contains("cdn-update.top"));
    }
}

#[test]
fn live_values_on_request() {
    let (_, iocs) = scenario_iocs();
    let csv = iocs_csv(&iocs, &capture(), ExportOptions { defang: false });
    assert!(csv.contains(",cdn-update.top,false,"));
}

#[test]
fn csv_cells_are_formula_safe_and_quoted() {
    assert_eq!(csv_cell("=1+1"), "'=1+1");
    assert_eq!(csv_cell("+1"), "'+1");
    assert_eq!(csv_cell("-1"), "'-1");
    assert_eq!(csv_cell("@SUM(A1)"), "'@SUM(A1)");
    assert_eq!(csv_cell("\tx"), "'\tx");
    assert_eq!(csv_cell("\rx"), "\"'\rx\"");
    assert_eq!(csv_cell("a,b"), "\"a,b\"");
    assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
    assert_eq!(
        csv_cell("=HYPERLINK(\"x\",\"y\")"),
        "\"'=HYPERLINK(\"\"x\"\",\"\"y\"\")\""
    );
    assert_eq!(csv_cell("plain"), "plain");
}

#[test]
fn hostile_allowlist_reason_is_neutralized_in_csv() {
    let (_, mut iocs) = scenario_iocs();
    iocs[0].allowlisted = true;
    iocs[0].allowlist_reason = Some("=cmd|' /C calc'!A0".into());
    let csv = iocs_csv(&iocs, &capture(), ExportOptions::default());
    assert!(csv.contains(",'=cmd|' /C calc'!A0,"), "{csv}");
    assert!(!csv.contains(",=cmd"));
}

#[test]
fn export_writes_files_in_out_dir() {
    let (_, iocs) = scenario_iocs();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("exports");
    let p = export_iocs(&iocs, &capture(), IocFormat::Csv, &out).unwrap();
    assert!(p.is_absolute());
    assert_eq!(p.file_name().unwrap(), "iocs.csv");
    assert!(std::fs::read_to_string(&p).unwrap().contains(SHA));
    let p = export_iocs(&iocs, &capture(), IocFormat::Json, &out).unwrap();
    assert_eq!(p.file_name().unwrap(), "iocs.json");
    // no temp files left behind
    let names: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
}

// --------------------------------------------------------------------- report

fn input<'a>(
    findings: &'a [Finding],
    iocs: &'a [Ioc],
    case: &'a walleye_core::ipc::Case,
    png: Option<&'a [u8]>,
) -> ReportInput<'a> {
    ReportInput {
        capture: &case.capture,
        case,
        findings,
        iocs,
        timeline_png: png,
    }
}

/// Lines in claim sections that are not claims: blank lines, section
/// headings, italic asides, block quotes (analyst notes/verdicts) and table
/// header/separator rows.
fn is_structural(line: &str) -> bool {
    line.trim().is_empty()
        || line.starts_with("## ")
        || line.starts_with('_')
        || line.starts_with('>')
        || line.starts_with("|---")
        || line.starts_with("| Type |")
}

/// Every claim line carries `[<frames|flows> n, ...](walleye://sha256/<sha>/<frames|flows>/n,...)`
/// whose label lists the same leading numbers as the link.
fn assert_claims_linked(md: &str) {
    let mut section = "";
    let mut checked = 0;
    let link_re = format!("]({LINK_SCHEME}{SHA}/");
    for line in md.lines() {
        if let Some(s) = line.strip_prefix("## ") {
            section = s.trim();
            continue;
        }
        if !CLAIM_SECTIONS.contains(&section) || is_structural(line) {
            continue;
        }
        let at = line
            .find(&link_re)
            .unwrap_or_else(|| panic!("claim without evidence link in {section}: {line}"));
        let label_start = line[..at].rfind('[').expect("link label");
        let label = &line[label_start + 1..at];
        let rest = &line[at + link_re.len()..];
        let (kind, ids) = rest.split_once('/').unwrap();
        let ids = &ids[..ids.find(')').unwrap()];
        assert!(kind == "frames" || kind == "flows", "{line}");
        assert!(label.starts_with(&kind[..kind.len() - 1]), "{line}");
        let listed: Vec<&str> = ids.split(',').collect();
        assert!(listed.iter().all(|n| n.parse::<u64>().is_ok()), "{line}");
        // the plain label text repeats the same numbers
        let label_nums: Vec<&str> = label
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .take(listed.len())
            .collect();
        assert_eq!(label_nums, listed, "{line}");
        checked += 1;
    }
    assert!(checked > 0, "no claim lines found");
}

#[test]
fn markdown_golden_and_every_claim_linked() {
    let (findings, iocs) = scenario_iocs();
    let case = case(pins());
    let doc = build(&input(&findings, &iocs, &case, None), None).unwrap();
    let md = render_markdown(&doc);
    assert_golden("report.md", &md);
    assert_claims_linked(&md);

    // required content
    for needle in [
        "## Capture",
        SHA,
        "/cases/office-beacon.pcap",
        "238862 bytes",
        "2026-03-12 09:00:26.906498Z → 2026-03-12 09:58:46.976582Z (58m 20s)",
        "## Findings",
        "## ATT&CK techniques",
        "`T1071.004` Application Layer Protocol: DNS",
        "## Indicators of compromise",
        "`cdn-update[.]top`",
        "## Pinned evidence",
        "## Analyst notes",
        "## Queries used",
        "`host 10.0.0.23`",
        "> **Analyst note (not a claim):**",
        "> **Analyst verdict (not a claim):** suspicious",
    ] {
        assert!(md.contains(needle), "missing {needle:?}");
    }
    // the duplicated query is listed once, with its run count
    assert_eq!(md.matches("`host 10.0.0.23`").count(), 1);
    // IOCs are defanged: no live indicator appears in the IOC table
    let ioc_section = md
        .split("## Indicators of compromise")
        .nth(1)
        .unwrap()
        .split("\n## ")
        .next()
        .unwrap();
    assert!(!ioc_section.contains("cdn-update.top"));
    assert!(!ioc_section.contains("http://"));
}

#[test]
fn markdown_has_one_finding_heading_per_finding_and_a_link_per_reason() {
    let (findings, iocs) = scenario_iocs();
    let case = case(vec![]);
    let md = render_markdown(&build(&input(&findings, &iocs, &case, None), None).unwrap());
    assert_eq!(md.matches("\n### F").count(), findings.len());
    let reasons: usize = findings.iter().map(|f| f.reasons.len()).sum();
    // one line per reason starting with "- **<n> pts**"
    let reason_lines = md
        .lines()
        .filter(|l| l.starts_with("- **") && l.contains(" pts** · rule "))
        .count();
    assert_eq!(reason_lines, reasons);
    assert!(md.contains("_Nothing was pinned._"));
    assert_claims_linked(&md);
}

#[test]
fn captured_strings_cannot_inject_markdown() {
    let (_, iocs) = scenario_iocs();
    let mut findings = scenario().1;
    findings[0].title = "Evil\n\n## Injected heading\n[click](http://evil.example) <script>alert(1)</script> `tick` | pipe".into();
    findings[0].reasons[0].explanation =
        "x\r\n# h1\n![img](http://evil.example/p.png)\u{202e}gnp.exe".into();
    findings[0].entity = "10.0.0.15`` <b>".into();
    let mut case = case(pins());
    case.queries[0].filter = "a | b\n## q".into();
    let md = render_markdown(&build(&input(&findings, &iocs, &case, None), None).unwrap());

    // Parse as GFM: the only links are evidence links, there is no HTML or
    // image from captured data, and every heading is one we wrote.
    use pulldown_cmark::{Event, Options, Parser, Tag};
    let mut headings = 0;
    for ev in Parser::new_ext(&md, Options::ENABLE_TABLES) {
        match ev {
            Event::Start(Tag::Link { dest_url, .. }) => {
                assert!(dest_url.starts_with(LINK_SCHEME), "live link {dest_url}")
            }
            Event::Start(Tag::Image { .. }) => panic!("image injected"),
            Event::Html(h) | Event::InlineHtml(h) => panic!("html injected: {h}"),
            Event::Start(Tag::Heading { .. }) => headings += 1,
            _ => {}
        }
    }
    // title + 8 sections + one per finding
    assert_eq!(headings, 1 + 8 + findings.len());
    for bad in ["\n## Injected", "\n# h1", "\u{202e}"] {
        assert!(!md.contains(bad), "injected {bad:?}");
    }
    // structure intact: still exactly the expected sections
    let sections: Vec<&str> = md.lines().filter(|l| l.starts_with("## ")).collect();
    assert_eq!(
        sections,
        [
            "## Capture",
            "## Findings",
            "## ATT&CK techniques",
            "## Indicators of compromise",
            "## Pinned evidence",
            "## Analyst notes",
            "## Queries used",
            "## About this report"
        ]
    );
    // the analyst note with markdown is escaped, not rendered
    assert!(md.contains("\\# not a heading \\[x\\]\\(http\\:\\/\\/evil\\.example\\) \\<b\\>"));
    // control/bidi chars are made visible
    assert!(md.contains("\\u{202e}"));
    // table rows still have the right number of cells (pipes escaped)
    for line in md
        .lines()
        .filter(|l| l.starts_with("| ") && !l.starts_with("|---"))
    {
        let cells = line.replace("\\|", "").matches('|').count();
        assert!(cells == 3 || cells == 7 || cells == 9, "{cells} in {line}");
    }
    assert_claims_linked(&md);
}

#[test]
fn evidence_link_format() {
    let e = Evidence {
        flow_ids: vec![3],
        frame_nos: vec![41, 57],
        truncated: false,
        total: 2,
    };
    let l = report::evidence_link(SHA, &e).unwrap();
    assert_eq!(l.label, "frames 41, 57");
    assert_eq!(l.url, format!("walleye://sha256/{SHA}/frames/41,57"));
    let one = report::evidence_link(
        SHA,
        &Evidence {
            flow_ids: vec![],
            frame_nos: vec![41],
            truncated: false,
            total: 1,
        },
    )
    .unwrap();
    assert_eq!(one.label, "frame 41");
    let many: Vec<u64> = (1..=30).collect();
    let l = report::evidence_link(
        SHA,
        &Evidence {
            flow_ids: vec![],
            frame_nos: many,
            truncated: true,
            total: 412,
        },
    )
    .unwrap();
    assert_eq!(
        l.label,
        "frames 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 … (412 total)"
    );
    assert!(l.url.ends_with("/frames/1,2,3,4,5,6,7,8,9,10"));
    let flows = report::evidence_link(
        SHA,
        &Evidence {
            flow_ids: vec![7, 8],
            frame_nos: vec![],
            truncated: false,
            total: 2,
        },
    )
    .unwrap();
    assert_eq!(flows.url, format!("walleye://sha256/{SHA}/flows/7,8"));
    assert!(report::evidence_link(SHA, &Evidence::default()).is_none());
}

#[test]
fn code_spans_hold_backticks() {
    assert_eq!(report::code_span("a`b", false), "``a`b``");
    assert_eq!(report::code_span("`x`", false), "`` `x` ``");
    assert_eq!(report::code_span("a|b", true), "`a\\|b`");
    assert_eq!(report::code_span("", false), "` `");
    assert_eq!(report::code_span("a\nb", false), "`a\\u{a}b`");
}

fn tiny_png() -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, 4, 2);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        let mut w = enc.write_header().unwrap();
        w.write_image_data(&[200u8; 4 * 2 * 4]).unwrap();
    }
    out
}

#[test]
fn markdown_export_writes_report_and_timeline() {
    let (findings, iocs) = scenario_iocs();
    let case = case(pins());
    let png = tiny_png();
    let dir = tempfile::tempdir().unwrap();
    let p = export_report_at(
        &input(&findings, &iocs, &case, Some(&png)),
        ReportFormat::Markdown,
        dir.path(),
        Some(T0),
    )
    .unwrap();
    assert_eq!(p.file_name().unwrap(), "report.md");
    let md = std::fs::read_to_string(&p).unwrap();
    assert!(md.contains("![Timeline snapshot at export time](report-timeline.png)"));
    assert!(md.contains("generated 2026-03-12 09:00:26.906498Z"));
    assert_eq!(
        std::fs::read(dir.path().join("report-timeline.png")).unwrap(),
        png
    );
    assert_claims_linked(&md);
}

#[test]
fn rejects_non_png_snapshot() {
    let (findings, iocs) = scenario_iocs();
    let case = case(vec![]);
    let dir = tempfile::tempdir().unwrap();
    let err = export_report_at(
        &input(&findings, &iocs, &case, Some(b"<svg onload=alert(1)>")),
        ReportFormat::Pdf,
        dir.path(),
        None,
    )
    .unwrap_err();
    assert_eq!(err.code, walleye_core::ErrorCode::InvalidArgument);
    assert!(report::decode_timeline_png("!!!").is_err());
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(tiny_png());
    assert_eq!(report::decode_timeline_png(&b64).unwrap(), tiny_png());
}

// ------------------------------------------------------------------------ PDF

struct PdfFacts {
    pages: usize,
    count: usize,
    text: String,
}

/// Structural check: header, EOF marker, xref offsets point at their
/// objects, startxref points at the xref table, page count agrees.
fn check_pdf(bytes: &[u8]) -> PdfFacts {
    assert!(bytes.starts_with(b"%PDF-1.4\n"), "header");
    assert!(bytes.ends_with(b"%%EOF\n"), "eof");
    // One char per byte so string offsets equal file offsets.
    let text: String = bytes
        .iter()
        .map(|&b| if b.is_ascii() { b as char } else { '?' })
        .collect();
    let sx = text.rfind("startxref\n").unwrap() + "startxref\n".len();
    let xref_off: usize = text[sx..].lines().next().unwrap().parse().unwrap();
    assert!(text[xref_off..].starts_with("xref\n0 "), "startxref");
    let mut lines = text[xref_off..].lines().skip(1);
    let n: usize = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(lines.next().unwrap(), "0000000000 65535 f ");
    for obj in 1..n {
        let entry = lines.next().unwrap();
        assert_eq!(entry.len() + 1, 20, "xref entries are 20 bytes: {entry:?}");
        let off: usize = entry[..10].parse().unwrap();
        assert!(
            text[off..].starts_with(&format!("{obj} 0 obj\n")),
            "object {obj} offset"
        );
    }
    assert!(text.contains(&format!("/Size {n}")));
    let pages = text.matches("/Type /Page /Parent").count();
    let ci = text.find("/Type /Pages").unwrap();
    let count: usize = text[ci..]
        .split("/Count ")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    PdfFacts { pages, count, text }
}

#[test]
fn pdf_is_structurally_valid_and_carries_the_hash() {
    let (findings, iocs) = scenario_iocs();
    let case = case(pins());
    let png = tiny_png();
    let dir = tempfile::tempdir().unwrap();
    let p = export_report_at(
        &input(&findings, &iocs, &case, Some(&png)),
        ReportFormat::Pdf,
        dir.path(),
        None,
    )
    .unwrap();
    assert_eq!(p.file_name().unwrap(), "report.pdf");
    let bytes = std::fs::read(&p).unwrap();
    // `WALLEYE_PDF_OUT=<path>` keeps a copy for viewing.
    if let Some(out) = std::env::var_os("WALLEYE_PDF_OUT") {
        std::fs::write(out, &bytes).unwrap();
    }
    let f = check_pdf(&bytes);
    assert!(f.pages >= 1);
    assert_eq!(f.pages, f.count);
    // the SHA-256 is printed in the body and in every page footer
    assert!(f.text.matches(SHA).count() > f.pages);
    assert!(f.text.contains("/Subtype /Image /Width 4 /Height 2"));
    assert!(f.text.contains("cdn-update[.]top"));
    assert!(f.text.contains("[frames 100, 110, 120]"));
    assert!(f.text.contains("Analyst note \\(not a claim\\):"));
    // deterministic
    let again = walleye_case::pdf::render(
        &build(&input(&findings, &iocs, &case, Some(&png)), None).unwrap(),
    );
    assert_eq!(again, bytes);
}

#[test]
fn pdf_paginates_long_reports() {
    let (findings, mut iocs) = scenario_iocs();
    let template = iocs[0].clone();
    for n in 0..400 {
        let mut i = template.clone();
        i.ioc_type = IocType::Domain;
        i.value = format!("host{n}.example.org");
        i.defanged = format!("host{n}[.]example[.]org");
        iocs.push(i);
    }
    let case = case(pins());
    let bytes =
        walleye_case::pdf::render(&build(&input(&findings, &iocs, &case, None), None).unwrap());
    let f = check_pdf(&bytes);
    assert!(f.pages > 5, "{} pages", f.pages);
    assert_eq!(f.pages, f.count);
    assert!(f.text.contains(&format!("page {} of {}", f.pages, f.pages)));
}

#[test]
fn pdf_escapes_hostile_text() {
    let mut findings = scenario().1;
    findings[0].title = "a) Tj ET BT (b\\ \u{202e}".into();
    let case = case(vec![]);
    let bytes =
        walleye_case::pdf::render(&build(&input(&findings, &[], &case, None), None).unwrap());
    let f = check_pdf(&bytes);
    assert!(
        f.text.contains("a\\) Tj ET BT \\(b\\\\ \\\\u{202e}"),
        "escaped"
    );
}
