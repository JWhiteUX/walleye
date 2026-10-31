//! Minimal, dependency-light PDF writer for the case report.
//!
//! Why hand-rolled: the report is text, bullets, a few tables and one image.
//! The PDF base-14 fonts (Helvetica, Courier) need no embedding, so a ~400-line
//! writer covers it with no external binaries, no network and no large
//! dependency tree (typst or printpdf would add hundreds of crates and
//! minutes of build time). The only dependencies are `png` (decode the
//! timeline snapshot) and `miniz_oxide` (deflate the image stream).
//!
//! Text uses WinAnsiEncoding; characters outside it print as `?`. Text
//! streams are left uncompressed so the output is easy to audit (and to grep
//! for the capture SHA-256). Output is deterministic: no timestamps, no ids.

use walleye_core::{ApiError, ErrorCode, error::ApiResult};

use crate::report::{Block, Doc, Inline, MAX_VALUE_CHARS, sanitize};

pub struct RgbImage {
    pub width: u32,
    pub height: u32,
    /// Row-major RGB8.
    pub rgb: Vec<u8>,
}

/// Largest decoded image accepted, in pixels.
const MAX_PIXELS: u64 = 16_000_000;

/// Decode a PNG (any colour type) to RGB8, compositing alpha over white.
pub fn decode_png(bytes: &[u8]) -> ApiResult<RgbImage> {
    let bad = |m: &str| {
        ApiError::new(
            ErrorCode::InvalidArgument,
            format!("timeline snapshot: {m}"),
        )
    };
    let mut dec = png::Decoder::new_with_limits(
        std::io::Cursor::new(bytes),
        png::Limits { bytes: 128 << 20 },
    );
    dec.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = dec.read_info().map_err(|_| bad("not a PNG"))?;
    let (w, h) = reader.info().size();
    if w == 0 || h == 0 || u64::from(w) * u64::from(h) > MAX_PIXELS {
        return Err(bad("bad dimensions"));
    }
    let size = reader
        .output_buffer_size()
        .ok_or_else(|| bad("too large"))?;
    let mut buf = vec![0u8; size];
    let info = reader
        .next_frame(&mut buf)
        .map_err(|_| bad("corrupt PNG"))?;
    let (ct, _) = reader.output_color_type();
    let ch = match ct {
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
        png::ColorType::Indexed => return Err(bad("unexpanded palette")),
    };
    let mut rgb = Vec::with_capacity(w as usize * h as usize * 3);
    for row in buf.chunks(info.line_size).take(h as usize) {
        for px in row.chunks(ch).take(w as usize) {
            let (r, g, b, a) = match ch {
                1 => (px[0], px[0], px[0], 255),
                2 => (px[0], px[0], px[0], px[1]),
                3 => (px[0], px[1], px[2], 255),
                _ => (px[0], px[1], px[2], px[3]),
            };
            let over =
                |c: u8| ((u32::from(c) * u32::from(a) + 255 * (255 - u32::from(a))) / 255) as u8;
            rgb.extend([over(r), over(g), over(b)]);
        }
    }
    Ok(RgbImage {
        width: w,
        height: h,
        rgb,
    })
}

// ---------------------------------------------------------------------------
// fonts and text

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Font {
    Regular,
    Bold,
    Mono,
    Italic,
}

impl Font {
    fn name(self) -> &'static str {
        match self {
            Font::Regular => "F1",
            Font::Bold => "F2",
            Font::Mono => "F3",
            Font::Italic => "F4",
        }
    }
}

/// Helvetica advance widths (1/1000 em) for ASCII 32..=126, from the AFM.
const HELVETICA: [u16; 95] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556,
    556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667,
    611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667,
    667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500,
    222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
];

/// Map a char to one WinAnsiEncoding byte (`?` when it has none).
fn win_ansi(c: char) -> u8 {
    match c {
        ' '..='~' => c as u8,
        '\u{a0}'..='\u{ff}' => c as u32 as u8,
        '€' => 0x80,
        '…' => 0x85,
        '•' => 0x95,
        '–' => 0x96,
        '—' => 0x97,
        '‘' => 0x91,
        '’' => 0x92,
        '“' => 0x93,
        '”' => 0x94,
        _ => b'?',
    }
}

fn encode(s: &str) -> Vec<u8> {
    s.chars()
        .flat_map(|c| match c {
            '→' => vec![b'-', b'>'],
            _ => vec![win_ansi(c)],
        })
        .collect()
}

fn width(font: Font, size: f32, bytes: &[u8]) -> f32 {
    let units: u32 = bytes
        .iter()
        .map(|&b| match font {
            Font::Mono => 600,
            _ => {
                let w = match b {
                    32..=126 => u32::from(HELVETICA[(b - 32) as usize]),
                    0x85 | 0x97 => 1000, // ellipsis, em dash
                    0x95 => 350,         // bullet
                    0xb7 => 278,         // middle dot
                    0xb1 | 0xd7 => 584,  // plus-minus, multiply
                    _ => 556,
                };
                // Bold glyphs are a little wider; err on the wide side.
                if font == Font::Bold { w * 11 / 10 } else { w }
            }
        })
        .sum();
    units as f32 * size / 1000.0
}

/// PDF literal string body: escape `\`, `(`, `)` and non-printing bytes.
fn pdf_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() + 8);
    for &b in bytes {
        match b {
            b'\\' | b'(' | b')' => {
                s.push('\\');
                s.push(b as char);
            }
            32..=126 => s.push(b as char),
            _ => s.push_str(&format!("\\{b:03o}")),
        }
    }
    s
}

#[derive(Clone)]
struct Piece {
    font: Font,
    size: f32,
    bytes: Vec<u8>,
    blue: bool,
}

/// Turn inlines into styled pieces, split at spaces for wrapping.
fn pieces(inl: &[Inline], size: f32, base: Font) -> Vec<Piece> {
    let mut out = Vec::new();
    let mut push = |font: Font, text: &str, blue: bool| {
        let bytes = encode(text);
        let mut cur = Vec::new();
        for &b in &bytes {
            cur.push(b);
            if b == b' ' {
                out.push(Piece {
                    font,
                    size,
                    bytes: std::mem::take(&mut cur),
                    blue,
                });
            }
        }
        if !cur.is_empty() {
            out.push(Piece {
                font,
                size,
                bytes: cur,
                blue,
            });
        }
    };
    for i in inl {
        match i {
            Inline::Lit(s) => push(base, s, false),
            Inline::Strong(s) => push(Font::Bold, s, false),
            Inline::Code(s) => push(Font::Mono, &sanitize(s, MAX_VALUE_CHARS), false),
            Inline::Prose(s) => push(base, &sanitize(s, usize::MAX), false),
            Inline::Link(l) => push(base, &format!("[{}]", l.label), true),
        }
    }
    out
}

/// Greedy line breaking; over-long pieces are split by character.
fn wrap(ps: Vec<Piece>, max: f32) -> Vec<Vec<Piece>> {
    let mut lines: Vec<Vec<Piece>> = vec![Vec::new()];
    let mut w = 0.0;
    for p in ps {
        let pw = width(p.font, p.size, &p.bytes);
        let line_empty = lines.last().is_none_or(Vec::is_empty);
        if w + pw <= max || line_empty && pw <= max {
            w += pw;
            if let Some(l) = lines.last_mut() {
                l.push(p);
            }
            continue;
        }
        if pw <= max {
            lines.push(vec![p.clone()]);
            w = pw;
            continue;
        }
        // Split a long token across lines.
        let mut cur = Vec::new();
        for &b in &p.bytes {
            let cw = width(p.font, p.size, &[b]);
            if w + width(p.font, p.size, &cur) + cw > max && (!cur.is_empty() || w > 0.0) {
                if let Some(l) = lines.last_mut() {
                    l.push(Piece {
                        bytes: std::mem::take(&mut cur),
                        ..p.clone()
                    });
                }
                lines.push(Vec::new());
                w = 0.0;
            }
            cur.push(b);
        }
        w += width(p.font, p.size, &cur);
        if let Some(l) = lines.last_mut() {
            l.push(Piece {
                bytes: cur,
                ..p.clone()
            });
        }
    }
    lines
}

// ---------------------------------------------------------------------------
// pages

const PAGE_W: f32 = 595.0;
const PAGE_H: f32 = 842.0;
const MARGIN: f32 = 50.0;
const BOTTOM: f32 = 60.0;
const BODY: f32 = 9.5;

struct Writer {
    pages: Vec<String>,
    cur: String,
    y: f32,
    image_on: Vec<usize>,
}

impl Writer {
    fn new() -> Self {
        Self {
            pages: Vec::new(),
            cur: String::new(),
            y: PAGE_H - MARGIN,
            image_on: Vec::new(),
        }
    }
    fn new_page(&mut self) {
        self.pages.push(std::mem::take(&mut self.cur));
        self.y = PAGE_H - MARGIN;
    }
    fn ensure(&mut self, h: f32) {
        if self.y - h < BOTTOM {
            self.new_page();
        }
    }
    fn gap(&mut self, h: f32) {
        self.y -= h;
    }
    fn line(&mut self, x: f32, line: &[Piece], lead: f32) {
        self.ensure(lead);
        self.y -= lead;
        // Merge adjacent pieces of the same style into one text run, so the
        // line reads (and searches) as continuous text in a viewer.
        let mut runs: Vec<Piece> = Vec::new();
        for p in line.iter().filter(|p| !p.bytes.is_empty()) {
            match runs.last_mut() {
                Some(r) if r.font == p.font && r.size == p.size && r.blue == p.blue => {
                    r.bytes.extend_from_slice(&p.bytes);
                }
                _ => runs.push(p.clone()),
            }
        }
        let mut cx = x;
        for p in &runs {
            let color = if p.blue { "0 0.25 0.6 rg" } else { "0 g" };
            self.cur.push_str(&format!(
                "{color} BT /{} {:.1} Tf 1 0 0 1 {:.2} {:.2} Tm ({}) Tj ET\n",
                p.font.name(),
                p.size,
                cx,
                self.y,
                pdf_string(&p.bytes)
            ));
            cx += width(p.font, p.size, &p.bytes);
        }
    }
    fn para(&mut self, x: f32, ps: Vec<Piece>, size: f32) {
        let lead = size * 1.35;
        for l in wrap(ps, PAGE_W - MARGIN - x) {
            self.line(x, &l, lead);
        }
    }
    fn finish(mut self) -> (Vec<String>, Vec<usize>) {
        if !self.cur.is_empty() || self.pages.is_empty() {
            self.pages.push(std::mem::take(&mut self.cur));
        }
        (self.pages, self.image_on)
    }
}

fn lit(s: &str) -> Inline {
    Inline::Lit(s.to_string())
}

/// Render the document to PDF bytes.
pub fn render(doc: &Doc) -> Vec<u8> {
    let mut w = Writer::new();
    for b in &doc.blocks {
        match b {
            Block::Title(t) => {
                w.para(
                    MARGIN,
                    pieces(&[Inline::Strong(t.clone())], 18.0, Font::Bold),
                    18.0,
                );
                w.gap(4.0);
            }
            Block::Section(t) => {
                w.ensure(40.0);
                w.gap(10.0);
                w.para(
                    MARGIN,
                    pieces(&[Inline::Strong(t.to_string())], 13.0, Font::Bold),
                    13.0,
                );
                w.gap(2.0);
            }
            Block::Sub(v) => {
                w.ensure(30.0);
                w.gap(6.0);
                w.para(MARGIN, pieces(v, 11.0, Font::Bold), 11.0);
            }
            Block::Para(v) => {
                w.para(MARGIN, pieces(v, BODY, Font::Regular), BODY);
                w.gap(4.0);
            }
            Block::Aside(t) => {
                w.para(MARGIN, pieces(&[lit(t)], BODY, Font::Italic), BODY);
                w.gap(3.0);
            }
            Block::Bullet(v) => {
                let mut ps = pieces(&[lit("• ")], BODY, Font::Regular);
                ps.extend(pieces(v, BODY, Font::Regular));
                w.para(MARGIN + 8.0, ps, BODY);
            }
            Block::Note { label, text } => {
                let mut ps = pieces(&[Inline::Strong(format!("{label} "))], BODY, Font::Bold);
                let mut first = true;
                for l in text.lines() {
                    if !first {
                        w.para(MARGIN + 16.0, std::mem::take(&mut ps), BODY);
                    }
                    ps.extend(pieces(&[Inline::Prose(l.to_string())], BODY, Font::Italic));
                    first = false;
                }
                w.para(MARGIN + 16.0, ps, BODY);
                w.gap(2.0);
            }
            Block::Table { header, rows } => {
                // Each row becomes one "Header: value · Header: value" entry.
                for r in rows {
                    let mut v = vec![lit("• ")];
                    for (i, cell) in r.iter().enumerate() {
                        if i > 0 {
                            v.push(lit(" · "));
                        }
                        v.push(Inline::Strong(format!(
                            "{}: ",
                            header.get(i).copied().unwrap_or("")
                        )));
                        v.extend(cell.iter().cloned());
                    }
                    w.para(MARGIN + 8.0, pieces(&v, BODY, Font::Regular), BODY);
                }
                w.gap(4.0);
            }
            Block::Image { alt, .. } => {
                if let Some(img) = &doc.image {
                    let max_w = PAGE_W - 2.0 * MARGIN;
                    let scale = (max_w / img.width as f32).min(300.0 / img.height as f32);
                    let (dw, dh) = (img.width as f32 * scale, img.height as f32 * scale);
                    w.ensure(dh + 20.0);
                    w.y -= dh;
                    w.cur.push_str(&format!(
                        "q {dw:.2} 0 0 {dh:.2} {MARGIN:.2} {:.2} cm /Im1 Do Q\n",
                        w.y
                    ));
                    let page = w.pages.len();
                    w.image_on.push(page);
                    w.para(MARGIN, pieces(&[lit(alt)], 8.0, Font::Italic), 8.0);
                    w.gap(4.0);
                }
            }
        }
    }
    let (mut pages, image_on) = w.finish();
    let n = pages.len();
    for (i, p) in pages.iter_mut().enumerate() {
        let footer = format!(
            "Walleye case report · capture SHA-256 {} · page {} of {n}",
            doc.sha256,
            i + 1
        );
        p.push_str(&format!(
            "0.35 g BT /F1 7.0 Tf 1 0 0 1 {MARGIN:.2} 30.00 Tm ({}) Tj ET\n",
            pdf_string(&encode(&footer))
        ));
    }
    assemble(
        &pages,
        doc.image.as_ref().filter(|_| !image_on.is_empty()),
        &image_on,
        &doc.sha256,
    )
}

/// Write objects, xref table and trailer.
fn assemble(pages: &[String], image: Option<&RgbImage>, image_on: &[usize], sha: &str) -> Vec<u8> {
    // Object numbers: 1 catalog, 2 pages, 3-6 fonts, 7 info, 8 image (if any),
    // then a (page, content) pair per page.
    let first_page = 9;
    let mut objs: Vec<Vec<u8>> = Vec::new();
    let kids: Vec<String> = (0..pages.len())
        .map(|i| format!("{} 0 R", first_page + 2 * i))
        .collect();
    objs.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());
    objs.push(
        format!(
            "<< /Type /Pages /Kids [{}] /Count {} >>",
            kids.join(" "),
            pages.len()
        )
        .into_bytes(),
    );
    for base in [
        "Helvetica",
        "Helvetica-Bold",
        "Courier",
        "Helvetica-Oblique",
    ] {
        objs.push(
            format!(
                "<< /Type /Font /Subtype /Type1 /BaseFont /{base} /Encoding /WinAnsiEncoding >>"
            )
            .into_bytes(),
        );
    }
    objs.push(
        format!(
            "<< /Title (Walleye case report) /Subject (Capture SHA-256 {sha}) /Producer (Walleye {}) >>",
            env!("CARGO_PKG_VERSION")
        )
        .into_bytes(),
    );
    match image {
        Some(img) => {
            let data = miniz_oxide::deflate::compress_to_vec_zlib(&img.rgb, 6);
            let mut o = format!(
                "<< /Type /XObject /Subtype /Image /Width {} /Height {} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length {} >>\nstream\n",
                img.width,
                img.height,
                data.len()
            )
            .into_bytes();
            o.extend_from_slice(&data);
            o.extend_from_slice(b"\nendstream");
            objs.push(o);
        }
        None => objs.push(b"null".to_vec()),
    }
    for (i, content) in pages.iter().enumerate() {
        let xobj = if image.is_some() && image_on.contains(&i) {
            " /XObject << /Im1 8 0 R >>"
        } else {
            ""
        };
        objs.push(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W:.0} {PAGE_H:.0}] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R /F4 6 0 R >>{xobj} >> /Contents {} 0 R >>",
                first_page + 2 * i + 1
            )
            .into_bytes(),
        );
        let mut c = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
        c.extend_from_slice(content.as_bytes());
        c.extend_from_slice(b"endstream");
        objs.push(c);
    }

    let mut out: Vec<u8> = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n".to_vec();
    let mut offsets = Vec::with_capacity(objs.len());
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(o);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for off in offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R /Info 7 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objs.len() + 1
        )
        .as_bytes(),
    );
    out
}
