//! PDF executive summary, written with `pdf-writer` (pure Rust, offline).
//!
//! Text uses the PDF standard Helvetica / Helvetica-Bold fonts with WinAnsiEncoding, so no
//! font file is embedded; widths for line wrapping come from the Adobe Core 14 AFM metrics
//! (freely distributable). Characters outside Windows-1252 are rendered as `?`.

use anyhow::{bail, Context, Result};
use miniz_oxide::deflate::compress_to_vec_zlib;
use pdf_writer::{Content, Filter, Finish, Name, Pdf, Rect, Ref, Str, TextStr};

use crate::{
    audit::{format_utc, Finding, Severity, SCORING_METHOD},
    report::{plural, Logo, Report, SwitchUtil, LIMITATIONS, METHODOLOGY},
    report_html::meta_rows,
};

const PAGE_W: f32 = 595.0;
const PAGE_H: f32 = 842.0;
const MARGIN: f32 = 42.0;
const CONTENT_W: f32 = PAGE_W - 2.0 * MARGIN;
const TOP: f32 = 64.0;
const BOTTOM: f32 = 56.0;
/// Most findings detailed in the PDF (the HTML / JSON carry all of them).
const MAX_PDF_FINDINGS: usize = 15;

type Rgb = (f32, f32, f32);

const fn hex(c: u32) -> Rgb {
    (
        ((c >> 16) & 0xff) as f32 / 255.0,
        ((c >> 8) & 0xff) as f32 / 255.0,
        (c & 0xff) as f32 / 255.0,
    )
}

const INK: Rgb = hex(0x16181d);
const INK_2: Rgb = hex(0x4a4f59);
const MUTED: Rgb = hex(0x7a808c);
const LINE: Rgb = hex(0xe1e3e8);
const PANEL: Rgb = hex(0xf5f6f8);
const TRACK: Rgb = hex(0xe9ebf0);
const BRAND: Rgb = hex(0x0b5cc7);
const BRAND_LIGHT: Rgb = hex(0x2f7fe0);
const WHITE: Rgb = (1.0, 1.0, 1.0);
const OK: Rgb = hex(0x138a36);
const SERIES: [Rgb; 8] = [
    hex(0x2a78d6),
    hex(0xeb6834),
    hex(0x1baf7a),
    hex(0xeda100),
    hex(0xe87ba4),
    hex(0x008300),
    hex(0x6250d6),
    hex(0xe34948),
];

fn sev_color(s: Severity) -> Rgb {
    match s {
        Severity::Critical => hex(0xd03b3b),
        Severity::High => hex(0xec835a),
        Severity::Medium => hex(0xfab219),
        Severity::Low => hex(0x6f8fb8),
        Severity::Info => hex(0x9a9890),
    }
}

fn sev_bg(s: Severity) -> Rgb {
    match s {
        Severity::Critical => hex(0xfbe4e4),
        Severity::High => hex(0xfdeadf),
        Severity::Medium => hex(0xfff3d6),
        Severity::Low => hex(0xe6edf6),
        Severity::Info => hex(0xefeeea),
    }
}

fn grade_color(g: &str) -> Rgb {
    match g {
        "A" => hex(0x138a36),
        "B" => hex(0x4f9a2c),
        "C" => hex(0xc98500),
        "D" => hex(0xd0622b),
        _ => hex(0xc22f2f),
    }
}

// ---------------------------------------------------------------------------------------------
// Fonts
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Font {
    Regular,
    Bold,
}

impl Font {
    fn name(self) -> Name<'static> {
        match self {
            Font::Regular => Name(b"F1"),
            Font::Bold => Name(b"F2"),
        }
    }

    fn widths(self) -> &'static [u16; 224] {
        match self {
            Font::Regular => &HELVETICA,
            Font::Bold => &HELVETICA_BOLD,
        }
    }
}

/// Encode text as WinAnsi (Windows-1252); unsupported characters become `?`.
fn winansi(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| match c as u32 {
            0x20..=0x7e | 0xa0..=0xff => c as u32 as u8,
            _ => match c {
                '\u{20ac}' => 0x80,
                '\u{201a}' => 0x82,
                '\u{0192}' => 0x83,
                '\u{201e}' => 0x84,
                '\u{2026}' => 0x85,
                '\u{2020}' => 0x86,
                '\u{2021}' => 0x87,
                '\u{02c6}' => 0x88,
                '\u{2030}' => 0x89,
                '\u{0160}' => 0x8a,
                '\u{2039}' => 0x8b,
                '\u{0152}' => 0x8c,
                '\u{017d}' => 0x8e,
                '\u{2018}' => 0x91,
                '\u{2019}' => 0x92,
                '\u{201c}' => 0x93,
                '\u{201d}' => 0x94,
                '\u{2022}' => 0x95,
                '\u{2013}' => 0x96,
                '\u{2014}' => 0x97,
                '\u{02dc}' => 0x98,
                '\u{2122}' => 0x99,
                '\u{0161}' => 0x9a,
                '\u{203a}' => 0x9b,
                '\u{0153}' => 0x9c,
                '\u{017e}' => 0x9e,
                '\u{0178}' => 0x9f,
                '\t' | '\n' | '\r' => b' ',
                _ => b'?',
            },
        })
        .collect()
}

fn text_width(s: &str, font: Font, size: f32) -> f32 {
    let w = font.widths();
    winansi(s)
        .iter()
        .map(|b| {
            if *b >= 32 {
                f32::from(w[usize::from(*b - 32)])
            } else {
                0.0
            }
        })
        .sum::<f32>()
        * size
        / 1000.0
}

/// Greedy word wrap; words longer than the line are broken by character.
fn wrap(text: &str, font: Font, size: f32, width: f32) -> Vec<String> {
    let mut lines = Vec::new();
    for para in text.split('\n') {
        let mut line = String::new();
        for word in para.split_whitespace() {
            let candidate = if line.is_empty() {
                word.to_string()
            } else {
                format!("{line} {word}")
            };
            if text_width(&candidate, font, size) <= width {
                line = candidate;
                continue;
            }
            if !line.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            if text_width(word, font, size) <= width {
                line = word.to_string();
            } else {
                let mut chunk = String::new();
                for c in word.chars() {
                    chunk.push(c);
                    if text_width(&chunk, font, size) > width {
                        chunk.pop();
                        lines.push(std::mem::take(&mut chunk));
                        chunk.push(c);
                    }
                }
                line = chunk;
            }
        }
        lines.push(line);
    }
    lines
}

/// Shorten `s` with an ellipsis so it fits in `width`.
fn fit(s: &str, font: Font, size: f32, width: f32) -> String {
    if text_width(s, font, size) <= width {
        return s.to_string();
    }
    let mut out: String = String::new();
    for c in s.chars() {
        out.push(c);
        if text_width(&format!("{out}..."), font, size) > width {
            out.pop();
            break;
        }
    }
    format!("{}...", out.trim_end())
}

// ---------------------------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------------------------

struct Builder<'a> {
    pages: Vec<Content>,
    /// Page drawn on by the primitives (`None`: the last page).
    target: Option<usize>,
    /// Cursor, measured from the top of the page.
    y: f32,
    report: &'a Report<'a>,
}

impl<'a> Builder<'a> {
    fn new(report: &'a Report<'a>) -> Self {
        Builder {
            pages: vec![Content::new()],
            target: None,
            y: TOP,
            report,
        }
    }

    fn c(&mut self) -> &mut Content {
        let i = self.target.unwrap_or(self.pages.len() - 1);
        &mut self.pages[i]
    }

    fn new_page(&mut self) {
        self.pages.push(Content::new());
        self.y = TOP;
        // Running header.
        let title = fit(&self.report.opts.title, Font::Bold, 8.5, CONTENT_W - 160.0);
        self.fill_rect(0.0, 0.0, PAGE_W, 6.0, BRAND);
        self.text(MARGIN, 30.0, &title, Font::Bold, 8.5, BRAND);
        if let Some(org) = self.report.opts.org.clone() {
            let org = fit(&org, Font::Regular, 8.5, 150.0);
            let w = text_width(&org, Font::Regular, 8.5);
            self.text(PAGE_W - MARGIN - w, 30.0, &org, Font::Regular, 8.5, MUTED);
        }
        self.hline(MARGIN, 38.0, CONTENT_W, LINE, 0.6);
    }

    /// Start a new page unless `h` points still fit.
    fn ensure(&mut self, h: f32) {
        if self.y + h > PAGE_H - BOTTOM {
            self.new_page();
        }
    }

    fn text(&mut self, x: f32, y_top: f32, s: &str, font: Font, size: f32, color: Rgb) {
        let bytes = winansi(s);
        let c = self.c();
        c.begin_text();
        c.set_fill_rgb(color.0, color.1, color.2);
        c.set_font(font.name(), size);
        c.next_line(x, PAGE_H - y_top);
        c.show(Str(&bytes));
        c.end_text();
    }

    fn text_right(&mut self, x_right: f32, y_top: f32, s: &str, font: Font, size: f32, color: Rgb) {
        let w = text_width(s, font, size);
        self.text(x_right - w, y_top, s, font, size, color);
    }

    fn text_center(&mut self, cx: f32, y_top: f32, s: &str, font: Font, size: f32, color: Rgb) {
        let w = text_width(s, font, size);
        self.text(cx - w / 2.0, y_top, s, font, size, color);
    }

    fn fill_rect(&mut self, x: f32, y_top: f32, w: f32, h: f32, color: Rgb) {
        let c = self.c();
        c.set_fill_rgb(color.0, color.1, color.2);
        c.rect(x, PAGE_H - y_top - h, w, h);
        c.fill_nonzero();
    }

    /// Rounded rectangle (fill).
    fn round_rect(&mut self, x: f32, y_top: f32, w: f32, h: f32, r: f32, color: Rgb) {
        let r = r.min(w / 2.0).min(h / 2.0);
        let k = 0.552_284_8 * r;
        let (x0, y0, x1, y1) = (x, PAGE_H - y_top - h, x + w, PAGE_H - y_top);
        let c = self.c();
        c.set_fill_rgb(color.0, color.1, color.2);
        c.move_to(x0 + r, y0);
        c.line_to(x1 - r, y0);
        c.cubic_to(x1 - r + k, y0, x1, y0 + r - k, x1, y0 + r);
        c.line_to(x1, y1 - r);
        c.cubic_to(x1, y1 - r + k, x1 - r + k, y1, x1 - r, y1);
        c.line_to(x0 + r, y1);
        c.cubic_to(x0 + r - k, y1, x0, y1 - r + k, x0, y1 - r);
        c.line_to(x0, y0 + r);
        c.cubic_to(x0, y0 + r - k, x0 + r - k, y0, x0 + r, y0);
        c.close_path();
        c.fill_nonzero();
    }

    fn hline(&mut self, x: f32, y_top: f32, w: f32, color: Rgb, width: f32) {
        let c = self.c();
        c.set_stroke_rgb(color.0, color.1, color.2);
        c.set_line_width(width);
        c.move_to(x, PAGE_H - y_top);
        c.line_to(x + w, PAGE_H - y_top);
        c.stroke();
    }

    /// Circle path (fill or stroke).
    fn circle(&mut self, cx: f32, cy_top: f32, r: f32, color: Rgb, stroke: Option<f32>) {
        let cy = PAGE_H - cy_top;
        let k = 0.552_284_8 * r;
        let c = self.c();
        match stroke {
            Some(w) => {
                c.set_stroke_rgb(color.0, color.1, color.2);
                c.set_line_width(w);
            }
            None => {
                c.set_fill_rgb(color.0, color.1, color.2);
            }
        }
        c.move_to(cx + r, cy);
        c.cubic_to(cx + r, cy + k, cx + k, cy + r, cx, cy + r);
        c.cubic_to(cx - k, cy + r, cx - r, cy + k, cx - r, cy);
        c.cubic_to(cx - r, cy - k, cx - k, cy - r, cx, cy - r);
        c.cubic_to(cx + k, cy - r, cx + r, cy - k, cx + r, cy);
        c.close_path();
        if stroke.is_some() {
            c.stroke();
        } else {
            c.fill_nonzero();
        }
    }

    /// Append an arc (angles in radians, PDF orientation: counter-clockwise, y up) to the path.
    fn arc_path(c: &mut Content, cx: f32, cy: f32, r: f32, a0: f32, a1: f32) {
        let segs = ((a1 - a0).abs() / std::f32::consts::FRAC_PI_2)
            .ceil()
            .max(1.0) as usize;
        let step = (a1 - a0) / segs as f32;
        let mut a = a0;
        for _ in 0..segs {
            let b = a + step;
            let k = 4.0 / 3.0 * ((b - a) / 4.0).tan();
            let (x0, y0) = (cx + r * a.cos(), cy + r * a.sin());
            let (x3, y3) = (cx + r * b.cos(), cy + r * b.sin());
            let (x1, y1) = (x0 - k * r * a.sin(), y0 + k * r * a.cos());
            let (x2, y2) = (x3 + k * r * b.sin(), y3 - k * r * b.cos());
            c.cubic_to(x1, y1, x2, y2, x3, y3);
            a = b;
        }
    }

    /// Ring segment from `a0` to `a1` (clockwise from 12 o'clock, radians).
    #[allow(clippy::too_many_arguments)]
    fn ring_segment(
        &mut self,
        cx: f32,
        cy_top: f32,
        r: f32,
        ri: f32,
        a0: f32,
        a1: f32,
        color: Rgb,
    ) {
        let cy = PAGE_H - cy_top;
        // Convert "clockwise from top" to PDF angles.
        let p0 = std::f32::consts::FRAC_PI_2 - a0;
        let p1 = std::f32::consts::FRAC_PI_2 - a1;
        let c = self.c();
        c.set_fill_rgb(color.0, color.1, color.2);
        c.move_to(cx + r * p0.cos(), cy + r * p0.sin());
        Self::arc_path(c, cx, cy, r, p0, p1);
        c.line_to(cx + ri * p1.cos(), cy + ri * p1.sin());
        Self::arc_path(c, cx, cy, ri, p1, p0);
        c.close_path();
        c.fill_nonzero();
    }

    /// Wrapped paragraph at the cursor; returns its height.
    fn para(&mut self, x: f32, width: f32, text: &str, font: Font, size: f32, color: Rgb) -> f32 {
        let lead = size * 1.38;
        let lines = wrap(text, font, size, width);
        for line in &lines {
            self.ensure(lead);
            let y = self.y + size;
            self.text(x, y, line, font, size, color);
            self.y += lead;
        }
        lines.len() as f32 * lead
    }

    fn heading(&mut self, s: &str) {
        self.ensure(60.0);
        self.y += 6.0;
        self.text(MARGIN, self.y + 15.0, s, Font::Bold, 15.0, INK);
        self.y += 22.0;
        self.hline(MARGIN, self.y, 28.0, BRAND, 2.0);
        self.y += 12.0;
    }

    fn subheading(&mut self, s: &str) {
        self.ensure(40.0);
        self.text(MARGIN, self.y + 11.0, s, Font::Bold, 11.0, INK);
        self.y += 18.0;
    }

    /// Severity pill; returns its width.
    fn pill(&mut self, x: f32, y_top: f32, sev: Severity, text: &str) -> f32 {
        let w = text_width(text, Font::Bold, 7.5) + 16.0;
        self.round_rect(x, y_top, w, 13.0, 6.5, sev_bg(sev));
        self.circle(x + 6.0, y_top + 6.5, 2.4, sev_color(sev), None);
        self.text(x + 11.0, y_top + 9.3, text, Font::Bold, 7.5, INK);
        w
    }

    /// Horizontal bar chart at the cursor.
    fn hbar(&mut self, rows: &[(String, usize, Rgb)], x: f32, width: f32) {
        if rows.is_empty() {
            self.ensure(16.0);
            self.text(
                x,
                self.y + 10.0,
                "No data collected.",
                Font::Regular,
                9.0,
                MUTED,
            );
            self.y += 16.0;
            return;
        }
        let max = rows.iter().map(|r| r.1).max().unwrap_or(1).max(1) as f32;
        let label_w = 120.0;
        let bar_w = width - label_w - 40.0;
        for (label, v, color) in rows {
            self.ensure(17.0);
            let y = self.y;
            let label = fit(label, Font::Regular, 8.5, label_w - 8.0);
            self.text_right(
                x + label_w - 8.0,
                y + 9.5,
                &label,
                Font::Regular,
                8.5,
                INK_2,
            );
            self.round_rect(x + label_w, y + 2.0, bar_w, 9.0, 3.0, TRACK);
            let len = (*v as f32 / max * bar_w).max(if *v > 0 { 3.0 } else { 0.0 });
            if len > 0.0 {
                self.round_rect(x + label_w, y + 2.0, len, 9.0, 3.0, *color);
            }
            self.text(
                x + label_w + len + 5.0,
                y + 9.6,
                &v.to_string(),
                Font::Bold,
                8.5,
                INK,
            );
            self.y += 15.0;
        }
    }

    /// Simple table with a shaded header; columns are (title, width, right-aligned).
    fn table(&mut self, cols: &[(&str, f32, bool)], rows: &[Vec<String>]) {
        let size = 8.0;
        let header = |b: &mut Builder| {
            b.ensure(36.0);
            b.fill_rect(MARGIN, b.y, CONTENT_W, 16.0, PANEL);
            let mut x = MARGIN + 6.0;
            for (title, w, right) in cols {
                if *right {
                    b.text_right(x + w - 12.0, b.y + 11.0, title, Font::Bold, size, INK_2);
                } else {
                    b.text(x, b.y + 11.0, title, Font::Bold, size, INK_2);
                }
                x += w;
            }
            b.y += 16.0;
        };
        header(self);
        for row in rows {
            // Wrap the cells; the row is as tall as its tallest cell (max 3 lines).
            let cells: Vec<Vec<String>> = row
                .iter()
                .zip(cols)
                .map(|(cell, (_, w, _))| {
                    let mut l = wrap(cell, Font::Regular, size, w - 12.0);
                    if l.len() > 3 {
                        l.truncate(3);
                        if let Some(last) = l.last_mut() {
                            *last = fit(&format!("{last}..."), Font::Regular, size, w - 12.0);
                        }
                    }
                    l
                })
                .collect();
            let lines = cells.iter().map(Vec::len).max().unwrap_or(1).max(1);
            let h = lines as f32 * 10.5 + 6.0;
            if self.y + h > PAGE_H - BOTTOM {
                self.new_page();
                header(self);
            }
            let mut x = MARGIN + 6.0;
            for (cell, (_, w, right)) in cells.iter().zip(cols) {
                for (i, line) in cell.iter().enumerate() {
                    let ty = self.y + 11.0 + i as f32 * 10.5;
                    if *right {
                        self.text_right(x + w - 12.0, ty, line, Font::Regular, size, INK);
                    } else {
                        self.text(x, ty, line, Font::Regular, size, INK);
                    }
                }
                x += w;
            }
            self.y += h;
            self.hline(MARGIN, self.y, CONTENT_W, LINE, 0.5);
        }
        self.y += 8.0;
    }
}

// ---------------------------------------------------------------------------------------------
// Logo
// ---------------------------------------------------------------------------------------------

struct PdfImage {
    width: u32,
    height: u32,
    data: Vec<u8>,
    filter: Filter,
    components: u8,
    alpha: Option<Vec<u8>>,
}

/// Decode a PNG to RGB (+ alpha mask), or pass a baseline JPEG through as DCT data.
fn pdf_image(logo: &Logo) -> Result<PdfImage> {
    if logo.mime == "image/jpeg" {
        let (width, height, components) =
            jpeg_dimensions(&logo.bytes).context("unreadable JPEG")?;
        return Ok(PdfImage {
            width,
            height,
            data: logo.bytes.clone(),
            filter: Filter::DctDecode,
            components,
            alpha: None,
        });
    }
    let mut decoder = png::Decoder::new(std::io::Cursor::new(&logo.bytes));
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = decoder.read_info().context("unreadable PNG")?;
    let (w, h) = reader.info().size();
    if w == 0 || h == 0 || u64::from(w) * u64::from(h) > 16_000_000 {
        bail!("logo dimensions out of range");
    }
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let frame = reader.next_frame(&mut buf).context("unreadable PNG")?;
    let buf = &buf[..frame.buffer_size()];
    let (mut rgb, mut alpha) = (Vec::new(), Vec::new());
    let has_alpha = matches!(
        frame.color_type,
        png::ColorType::Rgba | png::ColorType::GrayscaleAlpha
    );
    match frame.color_type {
        png::ColorType::Rgb => rgb.extend_from_slice(buf),
        png::ColorType::Rgba => {
            for px in buf.as_chunks::<4>().0 {
                rgb.extend_from_slice(&px[..3]);
                alpha.push(px[3]);
            }
        }
        png::ColorType::Grayscale => buf.iter().for_each(|g| rgb.extend([*g, *g, *g])),
        png::ColorType::GrayscaleAlpha => {
            for px in buf.as_chunks::<2>().0 {
                rgb.extend([px[0], px[0], px[0]]);
                alpha.push(px[1]);
            }
        }
        png::ColorType::Indexed => bail!("unsupported PNG color type"),
    }
    Ok(PdfImage {
        width: w,
        height: h,
        data: compress_to_vec_zlib(&rgb, 6),
        filter: Filter::FlateDecode,
        components: 3,
        alpha: has_alpha.then(|| compress_to_vec_zlib(&alpha, 6)),
    })
}

/// Width, height and component count from a JPEG SOFn marker.
fn jpeg_dimensions(b: &[u8]) -> Option<(u32, u32, u8)> {
    let mut i = 2;
    while i + 9 < b.len() {
        if b[i] != 0xff {
            return None;
        }
        let marker = b[i + 1];
        let len = usize::from(u16::from_be_bytes([b[i + 2], b[i + 3]]));
        if matches!(marker, 0xc0..=0xc2) {
            let h = u32::from(u16::from_be_bytes([b[i + 5], b[i + 6]]));
            let w = u32::from(u16::from_be_bytes([b[i + 7], b[i + 8]]));
            let comps = b[i + 9];
            return (w > 0 && h > 0 && matches!(comps, 1 | 3)).then_some((w, h, comps));
        }
        i += 2 + len;
    }
    None
}

// ---------------------------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------------------------

/// The radar glyph: rounded square with rings and a sweep.
fn draw_glyph(b: &mut Builder, x: f32, y: f32, size: f32, bg: Rgb, fg: Rgb) {
    let s = size / 64.0;
    b.round_rect(x, y, size, size, 14.0 * s, bg);
    let (cx, cy) = (x + 32.0 * s, y + 32.0 * s);
    {
        let c = b.c();
        c.set_stroke_rgb(fg.0, fg.1, fg.2);
        c.set_line_width(2.4 * s);
        c.move_to(cx, PAGE_H - cy);
        c.line_to(x + 54.6 * s, PAGE_H - (y + 18.9 * s));
        c.stroke();
    }
    for r in [24.0, 15.5, 7.0] {
        b.circle(cx, cy, r * s, fg, Some(3.2 * s));
    }
    b.circle(x + 46.5 * s, y + 23.5 * s, 3.4 * s, fg, None);
}

fn mix(a: Rgb, b: Rgb, t: f32) -> Rgb {
    (
        a.0 + (b.0 - a.0) * t,
        a.1 + (b.1 - a.1) * t,
        a.2 + (b.2 - a.2) * t,
    )
}

/// Placement `(x, y_top, w, h)` of a `width` x `height` image fitted (aspect ratio kept)
/// and centred in the box `(bx, by, bw, bh)`.
fn fit_box(width: u32, height: u32, bx: f32, by: f32, bw: f32, bh: f32) -> (f32, f32, f32, f32) {
    let (iw, ih) = (width.max(1) as f32, height.max(1) as f32);
    let scale = (bw / iw).min(bh / ih);
    let (w, h) = (iw * scale, ih * scale);
    (bx + (bw - w) / 2.0, by + (bh - h) / 2.0, w, h)
}

/// Title lines for the cover: the largest size (26 / 21 / 17 pt) at which the title wraps
/// to at most two lines; at the smallest size the second line is cut with an ellipsis.
fn cover_title(title: &str) -> (f32, Vec<String>) {
    for size in [26.0, 21.0] {
        let lines = wrap(title, Font::Bold, size, CONTENT_W - 40.0);
        if lines.len() <= 2
            && lines
                .iter()
                .all(|l| text_width(l, Font::Bold, size) <= CONTENT_W - 40.0)
        {
            return (size, lines);
        }
    }
    let size = 17.0;
    let mut lines = wrap(title, Font::Bold, size, CONTENT_W - 40.0);
    let rest = if lines.len() > 1 {
        lines[1..].join(" ")
    } else {
        String::new()
    };
    lines.truncate(1);
    if let Some(first) = lines.first_mut() {
        *first = fit(first, Font::Bold, size, CONTENT_W - 40.0);
    }
    if !rest.is_empty() {
        lines.push(fit(&rest, Font::Bold, size, CONTENT_W - 40.0));
    }
    (size, lines)
}

fn cover(b: &mut Builder, logo: Option<(u32, u32)>) {
    let r = b.report;
    let band_h = 260.0;
    b.fill_rect(0.0, 0.0, PAGE_W, band_h, BRAND);
    // Decorative radar rings on the right of the band.
    for (i, rad) in [70.0f32, 120.0, 170.0, 220.0].iter().enumerate() {
        b.circle(
            PAGE_W - 70.0,
            150.0,
            *rad,
            mix(BRAND, BRAND_LIGHT, 0.9 - i as f32 * 0.15),
            Some(10.0),
        );
    }
    b.fill_rect(0.0, band_h, PAGE_W, PAGE_H - band_h, WHITE);
    draw_glyph(b, MARGIN, 44.0, 46.0, WHITE, BRAND);
    if let Some((w, h)) = logo {
        b.round_rect(PAGE_W - MARGIN - 128.0, 40.0, 128.0, 56.0, 8.0, WHITE);
        let (x, y_top, iw, ih) = fit_box(w, h, PAGE_W - MARGIN - 122.0, 46.0, 116.0, 44.0);
        let c = b.c();
        c.save_state();
        c.transform([iw, 0.0, 0.0, ih, x, PAGE_H - y_top - ih]);
        c.x_object(Name(b"Im1"));
        c.restore_state();
    }
    b.text(
        MARGIN,
        120.0,
        "SWEEPR NETWORK AUDIT REPORT",
        Font::Bold,
        9.5,
        mix(WHITE, BRAND, 0.15),
    );
    let mut y = 150.0;
    let (size, lines) = cover_title(&r.opts.title);
    for line in &lines {
        b.text(MARGIN, y, line, Font::Bold, size, WHITE);
        y += size * 1.2;
    }
    if let Some(org) = &r.opts.org {
        b.text(
            MARGIN,
            y + 2.0,
            &fit(
                &format!("Prepared for {org}"),
                Font::Regular,
                12.0,
                CONTENT_W,
            ),
            Font::Regular,
            12.0,
            WHITE,
        );
        y += 20.0;
    }
    b.text(
        MARGIN,
        y + 4.0,
        &format!("Generated {}", format_utc(r.opts.now_ms)),
        Font::Regular,
        10.0,
        mix(WHITE, BRAND, 0.2),
    );

    // Grade + summary cards.
    b.y = band_h + 28.0;
    let score = &r.audit.score;
    let card_h = 130.0;
    b.round_rect(MARGIN, b.y, 150.0, card_h, 10.0, PANEL);
    b.text_center(
        MARGIN + 75.0,
        b.y + 18.0,
        "RISK GRADE",
        Font::Bold,
        8.0,
        MUTED,
    );
    b.circle(
        MARGIN + 75.0,
        b.y + 56.0,
        30.0,
        grade_color(&score.grade),
        None,
    );
    b.text_center(
        MARGIN + 75.0,
        b.y + 68.0,
        &score.grade,
        Font::Bold,
        32.0,
        WHITE,
    );
    b.text_center(
        MARGIN + 75.0,
        b.y + 100.0,
        &format!("Score {} / 100", score.score),
        Font::Bold,
        9.5,
        INK,
    );
    b.text_center(
        MARGIN + 75.0,
        b.y + 114.0,
        &format!(
            "graded on {} of {} checks",
            score.evaluated_checks, score.total_checks
        ),
        Font::Regular,
        7.5,
        MUTED,
    );
    let s = &r.stats;
    let infra: Vec<String> = s
        .roles
        .iter()
        .filter(|x| x.role.is_infrastructure())
        .map(|x| format!("{} {}", x.count, x.label))
        .collect();
    let cards = [
        (
            "DEVICES",
            s.total_hosts.to_string(),
            format!("{} with open ports", s.port_scanned_hosts),
        ),
        (
            "INFRASTRUCTURE",
            s.infrastructure.to_string(),
            if infra.is_empty() {
                "none identified".into()
            } else {
                infra.join(", ")
            },
        ),
        (
            "VLANS",
            s.vlan_count.to_string(),
            format!("{} CDP/LLDP neighbor{}", s.neighbors, plural(s.neighbors)),
        ),
        ("FINDINGS", score.counts.total().to_string(), String::new()),
    ];
    let gx = MARGIN + 162.0;
    let cw = (CONTENT_W - 162.0 - 10.0) / 2.0;
    let ch = (card_h - 10.0) / 2.0;
    for (i, (label, value, detail)) in cards.iter().enumerate() {
        let x = gx + (i % 2) as f32 * (cw + 10.0);
        let y = b.y + (i / 2) as f32 * (ch + 10.0);
        b.round_rect(x, y, cw, ch, 8.0, PANEL);
        b.text(x + 12.0, y + 15.0, label, Font::Bold, 7.5, MUTED);
        b.text(x + 12.0, y + 37.0, value, Font::Bold, 20.0, INK);
        if i == 3 {
            let mut px = x + 12.0 + text_width(value, Font::Bold, 20.0) + 8.0;
            for sev in [
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low,
            ] {
                let n = score.counts.get(sev);
                if n > 0 && px < x + cw - 40.0 {
                    px += b.pill(px, y + 26.0, sev, &format!("{n} {}", sev.label())) + 4.0;
                }
            }
        } else {
            let d = fit(detail, Font::Regular, 8.0, cw - 24.0);
            b.text(x + 12.0, y + 51.0, &d, Font::Regular, 8.0, INK_2);
        }
    }
    b.y += card_h + 22.0;
    if let Some(cap) = &score.capped_by {
        b.text(
            MARGIN,
            b.y - 8.0,
            &format!("Grade capped: {cap}."),
            Font::Regular,
            8.0,
            MUTED,
        );
        b.y += 6.0;
    }

    b.subheading("Executive summary");
    for p in r.narrative() {
        b.para(MARGIN, CONTENT_W, &p, Font::Regular, 9.5, INK_2);
        b.y += 4.0;
    }
    b.y += 6.0;
    b.subheading("Scan details");
    for (i, (k, v)) in meta_rows(r).iter().enumerate() {
        let lines = wrap(v, Font::Regular, 8.5, CONTENT_W - 120.0);
        let lines = &lines[..lines.len().min(3)];
        let h = lines.len().max(1) as f32 * 11.0 + 5.0;
        b.ensure(h);
        if i % 2 == 0 {
            b.fill_rect(MARGIN, b.y, CONTENT_W, h, PANEL);
        }
        b.text(MARGIN + 6.0, b.y + 11.0, k, Font::Bold, 8.5, MUTED);
        for (j, line) in lines.iter().enumerate() {
            b.text(
                MARGIN + 110.0,
                b.y + 11.0 + j as f32 * 11.0,
                line,
                Font::Regular,
                8.5,
                INK,
            );
        }
        b.y += h;
    }
}

fn overview(b: &mut Builder) {
    let r = b.report;
    b.new_page();
    b.heading("Network overview");
    b.subheading("Hosts per VLAN");
    let mut vlans: Vec<(String, usize, Rgb)> = r
        .stats
        .hosts_per_vlan
        .iter()
        .map(|v| {
            (
                match &v.name {
                    Some(n) => format!("{} ({n})", v.label),
                    None => v.label.clone(),
                },
                v.hosts,
                SERIES[0],
            )
        })
        .collect();
    if vlans.len() > 16 {
        let rest: usize = vlans[15..].iter().map(|v| v.1).sum();
        vlans.truncate(15);
        vlans.push(("Other VLANs".into(), rest, SERIES[0]));
    }
    b.hbar(&vlans, MARGIN, CONTENT_W);
    b.y += 8.0;

    // Roles donut (left) and severity bars (right).
    b.ensure(170.0);
    let top = b.y;
    b.subheading("Device roles");
    let total: usize = r.stats.roles.iter().map(|x| x.count).sum();
    let (cx, cy) = (MARGIN + 62.0, b.y + 62.0);
    if total > 0 {
        let mut a = 0.0f32;
        for (i, role) in r.stats.roles.iter().enumerate() {
            let sweep = role.count as f32 / total as f32 * std::f32::consts::TAU;
            if role.count > 0 {
                let gap = if r.stats.roles.len() > 1 { 0.015 } else { 0.0 };
                b.ring_segment(cx, cy, 58.0, 36.0, a + gap, a + sweep - gap, SERIES[i % 8]);
            }
            a += sweep;
        }
        b.text_center(cx, cy + 5.0, &total.to_string(), Font::Bold, 16.0, INK);
        b.text_center(cx, cy + 16.0, "devices", Font::Regular, 7.5, MUTED);
        let mut ly = b.y + 14.0;
        for (i, role) in r.stats.roles.iter().enumerate() {
            b.round_rect(MARGIN + 136.0, ly - 7.0, 8.0, 8.0, 2.0, SERIES[i % 8]);
            b.text(MARGIN + 150.0, ly, &role.label, Font::Regular, 8.5, INK_2);
            b.text_right(
                MARGIN + 250.0,
                ly,
                &format!("{} ({})", role.count, percent(role.count, total)),
                Font::Bold,
                8.5,
                INK,
            );
            ly += 15.0;
        }
    } else {
        b.text(MARGIN, b.y + 10.0, "No devices.", Font::Regular, 9.0, MUTED);
    }
    let left_bottom = b.y + 130.0;
    b.y = top;
    let half = CONTENT_W / 2.0;
    b.text(
        MARGIN + half + 10.0,
        b.y + 11.0,
        "Findings by severity",
        Font::Bold,
        11.0,
        INK,
    );
    b.y += 18.0;
    let sev_rows: Vec<(String, usize, Rgb)> = Severity::ALL_DESC
        .iter()
        .map(|s| {
            (
                s.label().to_string(),
                r.audit.score.counts.get(*s),
                sev_color(*s),
            )
        })
        .collect();
    b.hbar(&sev_rows, MARGIN + half + 10.0 - 50.0, half + 40.0);
    b.y = b.y.max(left_bottom) + 8.0;

    b.subheading("Top vendors");
    let mut vendors: Vec<(String, usize, Rgb)> = r
        .stats
        .top_vendors
        .iter()
        .map(|v| (v.name.clone(), v.count, SERIES[2]))
        .collect();
    if r.stats.unknown_vendor > 0 {
        vendors.push((
            "Unknown vendor".into(),
            r.stats.unknown_vendor,
            sev_color(Severity::Info),
        ));
    }
    b.hbar(&vendors, MARGIN, CONTENT_W);
    b.y += 8.0;
    b.subheading("Open services (hosts per TCP port)");
    let services: Vec<(String, usize, Rgb)> = r
        .stats
        .services
        .iter()
        .take(12)
        .map(|p| {
            (
                if p.service.is_empty() {
                    format!("TCP {}", p.port)
                } else {
                    format!("{} ({})", p.service, p.port)
                },
                p.hosts,
                if p.risky {
                    sev_color(Severity::High)
                } else {
                    SERIES[0]
                },
            )
        })
        .collect();
    b.hbar(&services, MARGIN, CONTENT_W);
    if !services.is_empty() {
        b.text(
            MARGIN,
            b.y + 6.0,
            "Orange: cleartext or legacy protocol.",
            Font::Regular,
            7.5,
            MUTED,
        );
        b.y += 12.0;
    }
}

fn finding_block(b: &mut Builder, f: &Finding) {
    let text_w = CONTENT_W - 24.0;
    let desc = wrap(
        &f.description.replace('`', "\""),
        Font::Regular,
        8.8,
        text_w,
    );
    let fix = wrap(
        &f.remediation.replace('`', "\""),
        Font::Regular,
        8.8,
        text_w - 12.0,
    );
    let sample: Vec<String> = f
        .affected
        .iter()
        .take(6)
        .map(|a| {
            let mut s =
                a.ip.clone()
                    .or_else(|| a.vlan.map(|v| format!("VLAN {v}")))
                    .unwrap_or_default();
            if let Some(n) = &a.name {
                s = if s.is_empty() {
                    n.clone()
                } else {
                    format!("{s} ({n})")
                };
            }
            if let Some(p) = &a.port {
                s.push_str(&format!(" {p}"));
            }
            s
        })
        .collect();
    let mut affected_text = sample.join(", ");
    if f.affected_count > sample.len() {
        affected_text.push_str(&format!(" and {} more", f.affected_count - sample.len()));
    }
    let aff = wrap(
        &format!("Affected: {affected_text}"),
        Font::Regular,
        8.3,
        text_w,
    );
    let aff_lines = aff.len().min(3);
    let lead = 12.0;
    let h = 26.0
        + desc.len() as f32 * lead
        + aff_lines as f32 * 11.5
        + 8.0
        + fix.len() as f32 * lead
        + 20.0;
    b.ensure(h.min(PAGE_H - TOP - BOTTOM));
    let top = b.y;
    b.round_rect(MARGIN, top, CONTENT_W, h - 8.0, 8.0, PANEL);
    b.fill_rect(MARGIN, top + 4.0, 3.0, h - 16.0, sev_color(f.severity));
    let x = MARGIN + 12.0;
    let pw = b.pill(x, top + 9.0, f.severity, f.severity.label());
    b.text(x + pw + 6.0, top + 19.0, &f.id, Font::Bold, 8.0, MUTED);
    let idw = text_width(&f.id, Font::Bold, 8.0);
    let title = fit(&f.title, Font::Bold, 10.5, text_w - pw - idw - 90.0);
    b.text(
        x + pw + idw + 14.0,
        top + 19.5,
        &title,
        Font::Bold,
        10.5,
        INK,
    );
    b.text_right(
        MARGIN + CONTENT_W - 12.0,
        top + 19.0,
        &format!("{} affected", f.affected_count),
        Font::Bold,
        8.0,
        INK_2,
    );
    let mut y = top + 26.0;
    for line in &desc {
        b.text(x, y + 9.0, line, Font::Regular, 8.8, INK_2);
        y += lead;
    }
    for (i, line) in aff.iter().take(3).enumerate() {
        let line = if i == 2 && aff.len() > 3 {
            fit(&format!("{line}..."), Font::Regular, 8.3, text_w)
        } else {
            line.clone()
        };
        b.text(x, y + 9.0, &line, Font::Regular, 8.3, MUTED);
        y += 11.5;
    }
    y += 4.0;
    b.fill_rect(x, y + 1.0, 2.0, fix.len() as f32 * lead + 12.0, OK);
    b.text(x + 8.0, y + 9.0, "Remediation", Font::Bold, 8.0, OK);
    y += 12.0;
    for line in &fix {
        b.text(x + 8.0, y + 9.0, line, Font::Regular, 8.8, INK);
        y += lead;
    }
    b.y = top + h;
}

fn findings(b: &mut Builder) {
    let r = b.report;
    b.new_page();
    b.heading("Top findings");
    if r.audit.findings.is_empty() {
        b.para(
            MARGIN,
            CONTENT_W,
            "No findings on the data collected. See Rule coverage for checks that could not run.",
            Font::Regular,
            9.5,
            INK_2,
        );
        return;
    }
    let shown = r.audit.findings.len().min(MAX_PDF_FINDINGS);
    if r.audit.findings.len() > shown {
        b.para(
            MARGIN,
            CONTENT_W,
            &format!(
                "The {shown} highest-priority of {} findings. The HTML report lists every finding; the JSON export also lists every affected device (up to 100,000 per finding).",
                r.audit.findings.len()
            ),
            Font::Regular,
            8.5,
            MUTED,
        );
        b.y += 4.0;
    }
    for f in r.audit.findings.iter().take(shown) {
        finding_block(b, f);
    }
}

/// Switch rows shown in the PDF before the rest is summarized.
const MAX_PDF_SWITCHES: usize = 40;

fn switch_section(b: &mut Builder) {
    let r = b.report;
    b.ensure(120.0);
    b.y += 6.0;
    b.heading("Switch port utilization");
    if r.stats.switches.is_empty() {
        b.para(
            MARGIN,
            CONTENT_W,
            "Not available: no switches were identified and no SNMP MAC-to-port data was collected. Scan with --snmp-community or --snmp-user to include switch port utilization.",
            Font::Regular,
            9.0,
            INK_2,
        );
        return;
    }
    let cols = [
        ("Switch", 150.0, false),
        ("Active / total ports", 150.0, false),
        ("Access", 50.0, true),
        ("Trunks", 50.0, true),
        ("MACs", 50.0, true),
        ("Endpoints", CONTENT_W - 450.0, true),
    ];
    // Header.
    b.ensure(40.0);
    b.fill_rect(MARGIN, b.y, CONTENT_W, 16.0, PANEL);
    let mut x = MARGIN + 6.0;
    for (t, w, right) in cols {
        if right {
            b.text_right(x + w - 12.0, b.y + 11.0, t, Font::Bold, 8.0, INK_2);
        } else {
            b.text(x, b.y + 11.0, t, Font::Bold, 8.0, INK_2);
        }
        x += w;
    }
    b.y += 16.0;
    // Switches with SNMP data first; a huge inventory is summarized.
    let mut order: Vec<&SwitchUtil> = r.stats.switches.iter().collect();
    order.sort_by_key(|s| !s.has_data);
    for sw in order.iter().take(MAX_PDF_SWITCHES) {
        switch_row(b, sw, &cols);
    }
    if order.len() > MAX_PDF_SWITCHES {
        b.y += 4.0;
        b.para(
            MARGIN,
            CONTENT_W,
            &format!(
                "and {} more switch(es); the HTML report and JSON export list all of them.",
                order.len() - MAX_PDF_SWITCHES
            ),
            Font::Regular,
            8.5,
            MUTED,
        );
    }
    b.y += 6.0;
    let poe: Vec<Vec<String>> = order
        .iter()
        .filter_map(|sw| {
            crate::report_html::poe_line(sw)
                .map(|l| vec![sw.name.clone(), l.trim_start_matches("PoE: ").to_string()])
        })
        .take(MAX_PDF_SWITCHES)
        .collect();
    if !poe.is_empty() {
        b.subheading("Power over Ethernet");
        b.table(
            &[("Switch", 170.0, false), ("PoE", CONTENT_W - 170.0, false)],
            &poe,
        );
        b.y += 6.0;
    }
    let mut busiest: Vec<(String, String, u32, bool)> = r
        .stats
        .switches
        .iter()
        .flat_map(|s| {
            s.busiest
                .iter()
                .map(move |p| (s.name.clone(), p.port.clone(), p.macs, p.access_point))
        })
        .collect();
    busiest.sort_by_key(|a| std::cmp::Reverse(a.2));
    busiest.truncate(10);
    if !busiest.is_empty() {
        b.subheading("Busiest access ports");
        let rows: Vec<Vec<String>> = busiest
            .into_iter()
            .map(|(s, p, n, ap)| {
                let note = if ap {
                    "access point (wireless clients)"
                } else {
                    ""
                };
                vec![s, p, note.to_string(), n.to_string()]
            })
            .collect();
        b.table(
            &[
                ("Switch", 170.0, false),
                ("Port", 110.0, false),
                ("Note", 170.0, false),
                ("MACs", CONTENT_W - 450.0, true),
            ],
            &rows,
        );
    }
}

fn switch_row(b: &mut Builder, sw: &SwitchUtil, cols: &[(&str, f32, bool)]) {
    let h = 30.0;
    if b.y + h > PAGE_H - BOTTOM {
        b.new_page();
    }
    let y = b.y;
    let mut x = MARGIN + 6.0;
    let name = fit(&sw.name, Font::Bold, 8.5, cols[0].1 - 10.0);
    b.text(x, y + 12.0, &name, Font::Bold, 8.5, INK);
    let sub = sw.ip.clone().unwrap_or_default() + if sw.partial { "  (partial SNMP)" } else { "" };
    b.text(
        x,
        y + 23.0,
        &fit(&sub, Font::Regular, 7.5, cols[0].1 - 10.0),
        Font::Regular,
        7.5,
        MUTED,
    );
    x += cols[0].1;
    if !sw.has_data {
        b.text(
            x,
            y + 16.0,
            "Not available (no SNMP data)",
            Font::Regular,
            8.0,
            MUTED,
        );
    } else {
        let bar_w = cols[1].1 - 16.0;
        b.round_rect(x, y + 6.0, bar_w, 7.0, 3.5, TRACK);
        if let Some(u) = sw.utilization() {
            b.round_rect(x, y + 6.0, (bar_w * u as f32).max(3.0), 7.0, 3.5, SERIES[0]);
        }
        let label = match sw.total_ports {
            Some(t) => format!(
                "{} / {}{t} ({:.0}%){}",
                sw.active_ports,
                if sw.total_estimated { "~" } else { "" },
                sw.utilization().unwrap_or(0.0) * 100.0,
                if sw.total_estimated { " est." } else { "" }
            ),
            None => format!("{} active, total unknown", sw.active_ports),
        };
        b.text(x, y + 24.0, &label, Font::Regular, 7.8, INK_2);
        x += cols[1].1;
        for (v, (_, w, _)) in [
            sw.access_ports,
            sw.trunk_ports.len(),
            sw.mac_total,
            sw.endpoints,
        ]
        .iter()
        .zip(&cols[2..])
        {
            b.text_right(
                x + w - 12.0,
                y + 16.0,
                &v.to_string(),
                Font::Regular,
                8.5,
                INK,
            );
            x += w;
        }
    }
    b.y += h;
    b.hline(MARGIN, b.y, CONTENT_W, LINE, 0.5);
}

/// Bulleted paragraph with a hanging indent.
fn bullet(b: &mut Builder, text: &str) {
    // Room for the first line, so the dot and the text start on the same page; the dot is
    // drawn before the paragraph (which may continue on the next page).
    b.ensure(8.8 * 1.38 + 1.0);
    let y = b.y;
    b.circle(MARGIN + 4.0, y + 5.8, 1.6, INK_2, None);
    b.para(
        MARGIN + 12.0,
        CONTENT_W - 12.0,
        text,
        Font::Regular,
        8.8,
        INK_2,
    );
    b.y += 2.0;
}

/// `12%`, or `<1%` for small non-zero shares.
fn percent(n: usize, total: usize) -> String {
    let p = n as f32 * 100.0 / total.max(1) as f32;
    if n > 0 && p < 1.0 {
        "<1%".into()
    } else {
        format!("{p:.0}%")
    }
}

fn appendix(b: &mut Builder) {
    let r = b.report;
    b.new_page();
    b.heading("Appendix");
    b.subheading("Rule coverage");
    let rows: Vec<Vec<String>> = r
        .audit
        .checks
        .iter()
        .map(|c| {
            let result = if !c.evaluated {
                format!("Not evaluated: {}", c.note.as_deref().unwrap_or(""))
            } else if c.findings > 0 {
                let sev = r
                    .audit
                    .findings
                    .iter()
                    .filter(|f| f.id == c.id)
                    .map(|f| f.severity)
                    .max()
                    .unwrap_or(Severity::Info);
                format!("{} finding", sev.label())
            } else {
                "Passed".into()
            };
            vec![c.id.clone(), c.title.clone(), result]
        })
        .collect();
    b.table(
        &[
            ("ID", 76.0, false),
            ("Check", 230.0, false),
            ("Result", CONTENT_W - 306.0, false),
        ],
        &rows,
    );
    b.subheading("Methodology");
    for m in METHODOLOGY {
        bullet(b, m);
    }
    b.y += 6.0;
    b.subheading("Risk score");
    b.para(MARGIN, CONTENT_W, SCORING_METHOD, Font::Regular, 8.8, INK_2);
    b.y += 8.0;
    b.subheading("Limitations");
    for l in LIMITATIONS {
        bullet(b, l);
    }
    if r.input.skipped_records > 0 || r.input.meta.cancelled || !r.input.warnings.is_empty() {
        b.y += 6.0;
        b.subheading("Data quality");
        if r.input.meta.cancelled {
            b.para(
                MARGIN,
                CONTENT_W,
                "The scan was stopped before it finished; results are partial.",
                Font::Regular,
                8.8,
                INK_2,
            );
        }
        if r.input.skipped_records > 0 {
            b.para(
                MARGIN,
                CONTENT_W,
                &format!(
                    "{} input record(s) could not be read and were skipped.",
                    r.input.skipped_records
                ),
                Font::Regular,
                8.8,
                INK_2,
            );
        }
        for w in &r.input.warnings {
            b.para(MARGIN, CONTENT_W, w, Font::Regular, 8.8, INK_2);
        }
    }
}

/// Render the PDF executive summary.
pub fn render_pdf(report: &Report) -> Result<Vec<u8>> {
    let image = match &report.opts.logo {
        Some(l) => Some(pdf_image(l)?),
        None => None,
    };
    let mut b = Builder::new(report);
    cover(&mut b, image.as_ref().map(|i| (i.width, i.height)));
    overview(&mut b);
    findings(&mut b);
    switch_section(&mut b);
    appendix(&mut b);

    // Footers (need the page count).
    let total = b.pages.len();
    let generated = format!(
        "SweepR {} - generated {}",
        env!("CARGO_PKG_VERSION"),
        format_utc(report.opts.now_ms)
    );
    for i in 0..total {
        b.target = Some(i);
        let footer_y = PAGE_H - 28.0;
        b.hline(MARGIN, footer_y - 12.0, CONTENT_W, LINE, 0.5);
        b.text(MARGIN, footer_y, &generated, Font::Regular, 7.5, MUTED);
        b.text_right(
            PAGE_W - MARGIN,
            footer_y,
            &format!("Page {} of {total}", i + 1),
            Font::Regular,
            7.5,
            MUTED,
        );
    }

    let mut pdf = Pdf::new();
    let mut next = 1;
    let mut alloc = || {
        let r = Ref::new(next);
        next += 1;
        r
    };
    let catalog = alloc();
    let tree = alloc();
    let f_regular = alloc();
    let f_bold = alloc();
    let info = alloc();
    let img_ids = image
        .as_ref()
        .map(|i| (alloc(), i.alpha.as_ref().map(|_| alloc())));
    let page_ids: Vec<(Ref, Ref)> = (0..total).map(|_| (alloc(), alloc())).collect();

    pdf.catalog(catalog).pages(tree);
    pdf.pages(tree)
        .kids(page_ids.iter().map(|p| p.0))
        .count(total as i32);
    pdf.type1_font(f_regular)
        .base_font(Name(b"Helvetica"))
        .encoding_predefined(Name(b"WinAnsiEncoding"));
    pdf.type1_font(f_bold)
        .base_font(Name(b"Helvetica-Bold"))
        .encoding_predefined(Name(b"WinAnsiEncoding"));
    let title = winansi_lossy(&report.opts.title);
    let mut di = pdf.document_info(info);
    di.title(TextStr(&title));
    di.producer(TextStr(concat!("SweepR ", env!("CARGO_PKG_VERSION"))));
    di.creator(TextStr("SweepR"));
    if let Some(org) = &report.opts.org {
        di.subject(TextStr(&winansi_lossy(&format!("Network audit for {org}"))));
    }
    di.finish();
    if let (Some(img), Some((id, mask_id))) = (&image, img_ids) {
        if let (Some(alpha), Some(mask_id)) = (&img.alpha, mask_id) {
            let mut m = pdf.image_xobject(mask_id, alpha);
            m.filter(Filter::FlateDecode);
            m.width(img.width as i32);
            m.height(img.height as i32);
            m.color_space().device_gray();
            m.bits_per_component(8);
            m.finish();
        }
        let mut x = pdf.image_xobject(id, &img.data);
        x.filter(img.filter);
        x.width(img.width as i32);
        x.height(img.height as i32);
        if img.components == 1 {
            x.color_space().device_gray();
        } else {
            x.color_space().device_rgb();
        }
        x.bits_per_component(8);
        if let Some(mask_id) = mask_id {
            x.s_mask(mask_id);
        }
        x.finish();
    }
    for (content, (page_id, content_id)) in b.pages.into_iter().zip(&page_ids) {
        let mut page = pdf.page(*page_id);
        page.media_box(Rect::new(0.0, 0.0, PAGE_W, PAGE_H));
        page.parent(tree);
        page.contents(*content_id);
        let mut res = page.resources();
        res.fonts()
            .pair(Font::Regular.name(), f_regular)
            .pair(Font::Bold.name(), f_bold);
        if let Some((img, _)) = img_ids {
            res.x_objects().pair(Name(b"Im1"), img);
        }
        res.finish();
        page.finish();
        let raw = content.finish();
        let compressed = compress_to_vec_zlib(&raw, 6);
        pdf.stream(*content_id, &compressed)
            .filter(Filter::FlateDecode);
    }
    Ok(pdf.finish())
}

/// Document-info strings: keep printable ASCII / Latin-1 only.
fn winansi_lossy(s: &str) -> String {
    s.chars()
        .map(|c| {
            if (' '..='\u{ff}').contains(&c) && c != '\u{7f}' {
                c
            } else {
                '?'
            }
        })
        .collect()
}

// Glyph widths (1/1000 em) for WinAnsi codes 32..=255, from the Adobe Core 14 AFM files
// for Helvetica and Helvetica-Bold ("may be used, copied, and distributed for any purpose and
// without charge, with or without modification").
#[rustfmt::skip]
const HELVETICA: [u16; 224] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
    1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
    333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
    556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584, 0,
    556, 0, 222, 556, 333, 1000, 556, 556, 333, 1000, 667, 333, 1000, 0, 611, 0,
    0, 222, 222, 333, 333, 350, 556, 1000, 333, 1000, 500, 333, 944, 0, 500, 667,
    278, 333, 556, 556, 556, 556, 260, 556, 333, 737, 370, 556, 584, 333, 737, 333,
    400, 584, 333, 333, 333, 556, 537, 278, 333, 333, 365, 556, 834, 834, 834, 611,
    667, 667, 667, 667, 667, 667, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278,
    722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611,
    556, 556, 556, 556, 556, 556, 889, 500, 556, 556, 556, 556, 278, 278, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 584, 611, 556, 556, 556, 556, 500, 556, 500,
];

#[rustfmt::skip]
const HELVETICA_BOLD: [u16; 224] = [
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
    975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
    333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
    611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584, 0,
    556, 0, 278, 556, 500, 1000, 556, 556, 333, 1000, 667, 333, 1000, 0, 611, 0,
    0, 278, 278, 500, 500, 350, 556, 1000, 333, 1000, 556, 333, 944, 0, 500, 667,
    278, 333, 556, 556, 556, 556, 280, 556, 333, 737, 370, 556, 584, 333, 737, 333,
    400, 584, 333, 333, 333, 611, 556, 278, 333, 333, 365, 556, 834, 834, 834, 611,
    722, 722, 722, 722, 722, 722, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278,
    722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611,
    556, 556, 556, 556, 556, 556, 889, 556, 556, 556, 556, 556, 278, 278, 278, 278,
    611, 611, 611, 611, 611, 611, 611, 584, 611, 611, 611, 611, 611, 556, 611, 556,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{tests::NOW, AuditInput};
    use crate::report::{render, ReportFormat, ReportOptions};
    use serde_json::json;

    #[test]
    fn widths_and_wrapping() {
        // Helvetica 'A' is 667/1000 em.
        assert!((text_width("A", Font::Regular, 10.0) - 6.67).abs() < 0.01);
        assert!(text_width("WWW", Font::Bold, 10.0) > text_width("iii", Font::Bold, 10.0));
        let lines = wrap(
            "the quick brown fox jumps over the lazy dog",
            Font::Regular,
            10.0,
            80.0,
        );
        assert!(lines.len() > 1);
        assert!(lines
            .iter()
            .all(|l| text_width(l, Font::Regular, 10.0) <= 80.0));
        let long = wrap(&"x".repeat(200), Font::Regular, 10.0, 50.0);
        assert!(long.len() > 3);
        assert!(fit("a very long switch name indeed", Font::Regular, 10.0, 60.0).ends_with("..."));
        assert_eq!(winansi("é€\u{4e2d}"), vec![0xe9, 0x80, b'?']);
    }

    #[test]
    fn pdf_is_well_formed_with_hostile_text() {
        let input = AuditInput::from_json_value(json!({
            "meta": { "portSpec": "23,80" },
            "devices": [
                { "ip": "10.0.0.1", "role": "switch", "hostname": "sw (1) \\ ) ( <script>", "openPorts": [23, 80] },
                { "ip": "10.0.0.2", "hostname": "\u{4e2d}\u{6587}", "vendor": "Ac\u{e9}me" }
            ]
        }))
        .unwrap();
        let mut opts = ReportOptions::new(Some("Audit (Q3) \\ test"), Some("Org ) ("));
        opts.now_ms = NOW;
        let pdf = render(&input, &opts, ReportFormat::Pdf).unwrap();
        assert!(pdf.starts_with(b"%PDF-"));
        assert!(pdf.ends_with(b"%%EOF") || pdf.ends_with(b"%%EOF\n"));
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.contains("/Helvetica-Bold"));
        assert!(text.contains("/Count "));
    }

    #[test]
    fn logo_png_and_jpeg() {
        // 1x1 RGBA PNG.
        let mut png_bytes = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut png_bytes, 2, 1);
            enc.set_color(png::ColorType::Rgba);
            enc.set_depth(png::BitDepth::Eight);
            let mut w = enc.write_header().unwrap();
            w.write_image_data(&[255, 0, 0, 255, 0, 0, 255, 128])
                .unwrap();
        }
        let logo = Logo::from_bytes(png_bytes).unwrap();
        let img = pdf_image(&logo).unwrap();
        assert_eq!((img.width, img.height, img.components), (2, 1, 3));
        assert!(img.alpha.is_some());
        let jpeg = [
            0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0x00, 0x00, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00,
            0x20, 0x00, 0x40, 0x03, 0x00, 0x00,
        ];
        assert_eq!(jpeg_dimensions(&jpeg), Some((64, 32, 3)));
        assert_eq!(jpeg_dimensions(&[0xff, 0xd8, 0x00]), None);
        let mut opts = ReportOptions::new(None, None);
        opts.logo = Some(logo);
        let pdf = render(&AuditInput::default(), &opts, ReportFormat::Pdf).unwrap();
        assert!(String::from_utf8_lossy(&pdf).contains("/SMask"));
    }

    #[test]
    fn logo_keeps_its_aspect_ratio() {
        // A square logo in the 116 x 44 box: 44 x 44, centred horizontally.
        let (x, y, w, h) = fit_box(100, 100, 0.0, 0.0, 116.0, 44.0);
        assert!((w - 44.0).abs() < 0.01 && (h - 44.0).abs() < 0.01);
        assert!((x - 36.0).abs() < 0.01 && y.abs() < 0.01);
        // A wide banner fills the width.
        let (_, _, w, h) = fit_box(1000, 100, 0.0, 0.0, 116.0, 44.0);
        assert!((w - 116.0).abs() < 0.01 && (h - 11.6).abs() < 0.01);
    }

    #[test]
    fn long_cover_titles_fit_the_band() {
        let (size, lines) = cover_title("Short title");
        assert_eq!((size, lines.len()), (26.0, 1));
        let long = "Quarterly network security and hygiene audit of the headquarters campus, \
                    both data centres and all branch offices including remote warehouses";
        let (size, lines) = cover_title(long);
        assert!(lines.len() <= 2, "{lines:?}");
        assert!(lines
            .iter()
            .all(|l| text_width(l, Font::Bold, size) <= CONTENT_W - 40.0 + 0.01));
        let (_, lines) = cover_title(&"W".repeat(300));
        assert!(lines.len() <= 2 && lines.iter().all(|l| l.len() < 300));
    }

    /// A huge switch inventory is summarized (bounded table) and PoE budgets appear.
    #[test]
    fn many_switches_and_poe_render() {
        let mut maps = Vec::new();
        let mut infos = Vec::new();
        for i in 0..120u32 {
            maps.push(
                json!({ "switchName": format!("sw{i}"), "portName": "Gi1/0/1",
                              "mac": format!("00:11:22:00:{:02x}:{:02x}", i / 256, i % 256),
                              "poe": { "status": "delivering", "watts": 5.5 } }),
            );
            infos.push(json!({ "ip": format!("10.1.{}.{}", i / 250, i % 250 + 1), "sysName": format!("sw{i}"),
                               "poeBudget": { "nominalWatts": 370.0, "consumedWatts": 100.0 } }));
        }
        let input =
            AuditInput::from_json_value(json!({ "portMappings": maps, "snmpInfos": infos }))
                .unwrap();
        let opts = ReportOptions::new(None, None);
        let pdf = render(&input, &opts, ReportFormat::Pdf).unwrap();
        assert!(pdf.starts_with(b"%PDF-"));
        let report = crate::report::Report::build(&input, &opts);
        let line = crate::report_html::poe_line(&report.stats.switches[0]).unwrap();
        assert!(line.contains("100 W of 370 W"), "{line}");
        let html = String::from_utf8(render(&input, &opts, ReportFormat::Html).unwrap()).unwrap();
        assert!(html.contains("PoE: 100 W of 370 W budget in use (27%)"));
        assert!(html.contains("Graded on "));
    }
}
