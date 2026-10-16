//! Self-contained interactive HTML audit report.
//!
//! One file, no network requests: CSS and JS are embedded and pinned by SHA-256 hashes in a
//! strict Content-Security-Policy, images are `data:` URIs, charts are inline SVG. Every
//! string from the scan is HTML-escaped ([`esc`]); the machine-readable copy of the report is
//! embedded as JSON in a non-executable `<script type="application/json">` block with `<`,
//! `>` and `&` escaped ([`json_for_script`]) so it cannot close the element.

use std::fmt::Write as _;

use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::{
    audit::{format_utc, AuditDevice, AuditNeighbor, Finding, Severity, SCORING_METHOD},
    report::{plural, Report, SwitchUtil, DEFAULT_TITLE, LIMITATIONS, METHODOLOGY},
};

const CSS: &str = include_str!("../templates/report.css");
const JS: &str = include_str!("../templates/report.js");
/// Most affected rows rendered per finding (the JSON export keeps up to `audit::MAX_AFFECTED`).
const MAX_AFFECTED_ROWS: usize = 200;
/// Most rows in the device-attachment table.
const MAX_ATTACHMENT_ROWS: usize = 1000;

/// HTML-escape text for element content and quoted attribute values.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Serialize JSON for embedding inside `<script type="application/json">`: `<`, `>`, `&`
/// and the JS line separators are escaped so `</script>` / `<!--` cannot appear.
pub fn json_for_script(v: &serde_json::Value) -> String {
    let raw = serde_json::to_string(v).unwrap_or_else(|_| "null".into());
    let mut out = String::with_capacity(raw.len() + 64);
    for c in raw.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out
}

fn csp_hash(s: &str) -> String {
    format!(
        "'sha256-{}'",
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(s.as_bytes()))
    )
}

/// Sort key that orders embedded numbers naturally (`Gi1/0/2` < `Gi1/0/10`) and IPv4 before
/// IPv6.
fn natural_key(s: &str) -> String {
    let mut out = String::new();
    let mut digits = String::new();
    for c in s.chars().chain(std::iter::once('\0')) {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        if !digits.is_empty() {
            let _ = write!(out, "{:0>8}", digits.trim_start_matches('0'));
            digits.clear();
        }
        if c != '\0' {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

fn ip_key(ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => format!("4{:010}", u32::from(v4)),
        Ok(std::net::IpAddr::V6(v6)) => format!("6{:039}", u128::from(v6)),
        Err(_) => format!("9{ip}"),
    }
}

fn opt(s: Option<&str>) -> String {
    s.map(esc).unwrap_or_default()
}

/// Escape `s` and render `code` spans (backticks) as `<code>`.
fn rich(s: &str) -> String {
    let mut out = String::new();
    for (i, part) in s.split('`').enumerate() {
        if i % 2 == 1 && s.matches('`').count().is_multiple_of(2) {
            let _ = write!(out, "<code>{}</code>", esc(part));
        } else {
            out.push_str(&esc(part));
        }
    }
    out
}

/// `12%`, or `<1%` for small non-zero shares.
fn percent(n: usize, total: usize) -> String {
    let p = n as f64 * 100.0 / total.max(1) as f64;
    if n > 0 && p < 1.0 {
        "<1%".replace('<', "&lt;")
    } else {
        format!("{p:.0}%")
    }
}

fn sev_chip(s: Severity) -> String {
    format!("<span class=\"sev sev-{}\">{}</span>", s.key(), s.label())
}

fn rank(s: Severity) -> u8 {
    s as u8
}

/// The SweepR radar glyph (same motif as the app icon), drawn inline.
pub const LOGO_SVG: &str = r##"<svg class="brand-logo" viewBox="0 0 64 64" role="img" aria-label="SweepR"><defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#1976d2"/><stop offset="1" stop-color="#4fc3f7"/></linearGradient></defs><rect width="64" height="64" rx="14" fill="url(#lg)"/><path d="M32 32 L54.6 18.9 A26 26 0 0 1 58 32 Z" fill="#ffffff" fill-opacity="0.28"/><g fill="none" stroke="#fff" stroke-width="3.2"><circle cx="32" cy="32" r="24"/><circle cx="32" cy="32" r="15.5"/><circle cx="32" cy="32" r="7"/></g><path d="M32 32 L54.6 18.9" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/><circle cx="46.5" cy="23.5" r="3.4" fill="#fff"/></svg>"##;

// ---------------------------------------------------------------------------------------------
// Charts (inline SVG)
// ---------------------------------------------------------------------------------------------

struct Bar {
    label: String,
    sub: Option<String>,
    value: usize,
    class: String,
    tip: String,
}

/// Horizontal bar chart. Labels on the left, value at the bar end, a tooltip per row.
fn hbar_chart(bars: &[Bar], aria: &str) -> String {
    if bars.is_empty() {
        return "<p class=\"empty\">No data collected.</p>".into();
    }
    let max = bars.iter().map(|b| b.value).max().unwrap_or(1).max(1) as f64;
    let (w, label_w, row_h) = (560.0, 170.0, 30.0);
    let bar_w = w - label_w - 56.0;
    let h = row_h * bars.len() as f64 + 4.0;
    let mut s = format!(
        "<svg class=\"chart\" viewBox=\"0 0 {w} {h}\" role=\"img\" aria-label=\"{}\">",
        esc(aria)
    );
    for (i, b) in bars.iter().enumerate() {
        let y = i as f64 * row_h + 4.0;
        let len = (b.value as f64 / max * bar_w).max(if b.value > 0 { 3.0 } else { 0.0 });
        let label: String = b.label.chars().take(26).collect();
        let _ = write!(
            s,
            "<g class=\"row\"><title>{tip}</title>\
             <rect class=\"track\" x=\"{label_w}\" y=\"{y1}\" width=\"{bar_w}\" height=\"14\" rx=\"4\"/>\
             <rect class=\"bar {cls}\" x=\"{label_w}\" y=\"{y1}\" width=\"{len:.1}\" height=\"14\" rx=\"4\"/>\
             <text class=\"lbl\" x=\"{lx}\" y=\"{ty}\" text-anchor=\"end\">{label}</text>\
             <text class=\"val\" x=\"{vx:.1}\" y=\"{ty}\">{v}</text>",
            tip = esc(&b.tip),
            y1 = y + 3.0,
            cls = b.class,
            lx = label_w - 10.0,
            ty = y + 14.5,
            label = esc(&label),
            vx = label_w + len + 6.0,
            v = b.value,
        );
        if let Some(sub) = &b.sub {
            let sub: String = sub.chars().take(28).collect();
            let _ = write!(
                s,
                "<text class=\"sublbl\" x=\"{}\" y=\"{}\" text-anchor=\"end\">{}</text>",
                label_w - 10.0,
                y + 26.0,
                esc(&sub)
            );
        }
        s.push_str("</g>");
    }
    s.push_str("</svg>");
    s
}

/// Donut chart with an HTML legend (label, count, share).
fn donut(items: &[(String, usize)], center_label: &str) -> String {
    let total: usize = items.iter().map(|i| i.1).sum();
    if total == 0 {
        return "<p class=\"empty\">No data collected.</p>".into();
    }
    let (cx, cy, r, ri) = (90.0f64, 90.0f64, 80.0f64, 52.0f64);
    let mut svg = format!(
        "<svg class=\"chart\" viewBox=\"0 0 180 180\" role=\"img\" aria-label=\"{}\">",
        esc(center_label)
    );
    let mut angle = -std::f64::consts::FRAC_PI_2;
    for (i, (label, n)) in items.iter().enumerate() {
        let class = format!("c{}", i % 8 + 1);
        let sweep = *n as f64 / total as f64 * std::f64::consts::TAU;
        let tip = format!("{label}: {n} ({:.0}%)", *n as f64 * 100.0 / total as f64);
        if items.len() == 1 || sweep >= std::f64::consts::TAU - 1e-6 {
            let _ = write!(
                svg,
                "<g><title>{}</title><circle class=\"{class}\" cx=\"{cx}\" cy=\"{cy}\" r=\"{r}\"/></g>",
                esc(&tip)
            );
        } else if *n > 0 {
            let (a0, a1) = (angle, angle + sweep);
            let large = i32::from(sweep > std::f64::consts::PI);
            let p = |a: f64, rad: f64| (cx + rad * a.cos(), cy + rad * a.sin());
            let (x0, y0) = p(a0, r);
            let (x1, y1) = p(a1, r);
            let (x2, y2) = p(a1, ri);
            let (x3, y3) = p(a0, ri);
            let _ = write!(
                svg,
                "<g><title>{}</title><path class=\"donut-seg {class}\" d=\"M{x0:.2} {y0:.2} A{r} {r} 0 {large} 1 {x1:.2} {y1:.2} L{x2:.2} {y2:.2} A{ri} {ri} 0 {large} 0 {x3:.2} {y3:.2} Z\"/></g>",
                esc(&tip)
            );
        }
        angle += sweep;
    }
    let _ = write!(
        svg,
        "<circle class=\"donut-hole\" cx=\"{cx}\" cy=\"{cy}\" r=\"{}\"/>\
         <text class=\"donut-center\" x=\"{cx}\" y=\"{}\" text-anchor=\"middle\">{total}</text>\
         <text class=\"donut-center-sub\" x=\"{cx}\" y=\"{}\" text-anchor=\"middle\">{}</text></svg>",
        ri - 0.5,
        cy + 6.0,
        cy + 22.0,
        esc(center_label)
    );
    let mut legend = String::from("<ul class=\"legend\">");
    for (i, (label, n)) in items.iter().enumerate() {
        let _ = write!(
            legend,
            "<li><span class=\"sw bg{}\"></span>{}<span class=\"n\">{n}</span><span class=\"pct\">{}</span></li>",
            i % 8 + 1,
            esc(label),
            percent(*n, total)
        );
    }
    legend.push_str("</ul>");
    format!("<div class=\"donut-wrap\">{svg}{legend}</div>")
}

// ---------------------------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------------------------

/// Generated CSS: column toggles (`hide-c<n>` hides column n) and meter widths (`w<pct>`),
/// since the CSP forbids inline `style` attributes.
fn generated_css() -> String {
    let mut s = String::new();
    for i in 1..=24 {
        let _ = writeln!(
            s,
            ".tbl.hide-c{i} tr > :nth-child({i}) {{ display: none; }}"
        );
    }
    for w in 0..=100 {
        let _ = writeln!(s, ".meter > span.w{w} {{ width: {w}%; }}");
    }
    s
}

/// Render the full HTML document.
pub fn render_html(r: &Report) -> String {
    let css = format!("{CSS}\n{}", generated_css());
    let data = json_for_script(&r.to_json());
    let csp = format!(
        "default-src 'none'; img-src data:; style-src {}; script-src {}; base-uri 'none'; form-action 'none'",
        csp_hash(&css),
        csp_hash(JS)
    );
    let title = &r.opts.title;
    let page_title = match &r.opts.org {
        Some(org) => format!("{title} - {org}"),
        None => title.clone(),
    };
    let mut h = String::with_capacity(256 * 1024);
    let _ = write!(
        h,
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"{csp}\">\n\
         <meta name=\"referrer\" content=\"no-referrer\">\n\
         <meta name=\"generator\" content=\"SweepR {ver}\">\n\
         <title>{pt}</title>\n<style>{css}</style>\n</head>\n<body>\n",
        csp = esc(&csp),
        ver = env!("CARGO_PKG_VERSION"),
        pt = esc(&page_title),
    );
    masthead(&mut h, r);
    h.push('\n');
    h.push_str(
        "<nav class=\"toc\" aria-label=\"Sections\"><div class=\"toc-inner\">\
         <a href=\"#summary\">Summary</a><a href=\"#overview\">Overview</a>\
         <a href=\"#ports\">Switch ports</a><a href=\"#services\">Vendors &amp; services</a>\
         <a href=\"#findings\">Findings</a><a href=\"#inventory\">Inventory</a>\
         <a href=\"#topology\">Neighbors</a><a href=\"#coverage\">Rule coverage</a>\
         <a href=\"#appendix\">Appendix</a></div></nav>\n<main>\n",
    );
    summary(&mut h, r);
    overview(&mut h, r);
    switch_ports(&mut h, r);
    vendors_services(&mut h, r);
    findings(&mut h, r);
    inventory(&mut h, r);
    topology(&mut h, r);
    coverage(&mut h, r);
    appendix(&mut h, r);
    let _ = write!(
        h,
        "</main>\n<footer><span>Generated by SweepR {} on {}</span><span>{}</span></footer>\n\
         <script type=\"application/json\" id=\"report-data\">{data}</script>\n<script>{JS}</script>\n</body>\n</html>\n",
        env!("CARGO_PKG_VERSION"),
        format_utc(r.opts.now_ms),
        opt(r.opts.org.as_deref()),
    );
    h
}

fn masthead(h: &mut String, r: &Report) {
    let title = &r.opts.title;
    let mut sub = Vec::new();
    if let Some(org) = &r.opts.org {
        sub.push(format!("Prepared for <strong>{}</strong>", esc(org)));
    }
    sub.push(format!("Generated {}", esc(&format_utc(r.opts.now_ms))));
    let logo = r
        .opts
        .logo
        .as_ref()
        .map(|l| {
            format!(
                "<img class=\"org-logo\" alt=\"Organization logo\" src=\"data:{};base64,{}\">",
                l.mime,
                base64::engine::general_purpose::STANDARD.encode(&l.bytes)
            )
        })
        .unwrap_or_default();
    let _ = write!(
        h,
        "<header class=\"masthead\"><div class=\"masthead-inner\">{LOGO_SVG}\
         <div class=\"brand-text\"><div class=\"eyebrow\">{eyebrow}</div><h1>{t}</h1><div class=\"sub\">{sub}</div></div>\
         {logo}<div class=\"actions no-print\">\
         <button class=\"btn\" type=\"button\" data-action=\"print\">Print / PDF</button>\
         <button class=\"btn\" type=\"button\" data-action=\"json\">Download JSON</button>\
         <button class=\"btn\" type=\"button\" data-action=\"theme\">Light / dark</button>\
         </div></div></header>",
        eyebrow = if title == DEFAULT_TITLE {
            "SweepR"
        } else {
            "SweepR Network Audit Report"
        },
        t = esc(title),
        sub = sub.join(" &middot; "),
    );
}

fn duration(ms: u64) -> String {
    let s = ms / 1000;
    if s >= 3600 {
        format!("{}h {:02}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m {:02}s", s / 60, s % 60)
    } else {
        format!("{:.1} s", ms as f64 / 1000.0)
    }
}

/// Scan metadata rows (label, value) shared by HTML and PDF.
pub fn meta_rows(r: &Report) -> Vec<(&'static str, String)> {
    let m = &r.input.meta;
    let mut rows = Vec::new();
    let yes = |b: Option<bool>| b.map(|b| if b { "yes" } else { "no" }.to_string());
    if let Some(i) = &m.interface {
        rows.push(("Interface", i.clone()));
    }
    if !m.ranges.is_empty() {
        rows.push(("Ranges", m.ranges.join(", ")));
    }
    if let Some(v) = &m.vlans {
        rows.push(("VLANs probed", v.clone()));
    }
    if let Some(p) = &m.port_spec {
        rows.push(("TCP ports", p.replace(',', ", ")));
    }
    if let Some(s) = m.started_ms {
        rows.push(("Scan started", format_utc(s)));
    }
    if let (Some(s), Some(f)) = (m.started_ms, m.finished_ms) {
        rows.push((
            "Duration",
            format!(
                "{}{}",
                duration(f.saturating_sub(s)),
                if m.cancelled { " (stopped early)" } else { "" }
            ),
        ));
    }
    if let Some(snmp) = &m.snmp {
        let community = match snmp.community_kind.as_deref() {
            Some("public") => ", community \"public\" (default)",
            Some("private") => ", community \"private\" (default)",
            Some("custom") => ", custom community",
            _ => "",
        };
        rows.push((
            "SNMP",
            format!(
                "{}{community}{}",
                snmp.version.as_deref().unwrap_or("v2c"),
                if m.snmp_all == Some(true) {
                    ", all hosts"
                } else {
                    ""
                }
            ),
        ));
    } else {
        rows.push(("SNMP", "not used".into()));
    }
    if let Some(v) = yes(m.cdp_lldp.or(m.discover_vlans)) {
        rows.push(("CDP/LLDP listen", v));
    }
    if let Some(v) = yes(m.ipv6) {
        rows.push(("IPv6", v));
    }
    if let Some(v) = &m.tool_version {
        rows.push(("Scanner", v.clone()));
    }
    if let Some(v) = &m.scanner_host {
        rows.push(("Scanned from", v.clone()));
    }
    rows
}

fn summary(h: &mut String, r: &Report) {
    let s = &r.stats;
    let score = &r.audit.score;
    let c = &score.counts;
    h.push_str(
        "<section id=\"summary\"><div class=\"section-head\"><h2>Executive summary</h2></div>",
    );
    h.push_str("<div class=\"summary\">");
    let _ = write!(
        h,
        "<div class=\"card grade-card\"><div class=\"stat\"><div class=\"label\">Risk grade</div></div>\
         <div class=\"grade grade-{g}\" role=\"img\" aria-label=\"Grade {g}\">{g}</div>\
         <div class=\"score\">Score {sc} / 100</div>\
         <div class=\"capped\">Graded on {ev} of {tot} checks</div>{cap}</div>",
        g = esc(&score.grade),
        sc = score.score,
        ev = score.evaluated_checks,
        tot = score.total_checks,
        cap = score
            .capped_by
            .as_deref()
            .map(|w| format!("<div class=\"capped\">Capped: {}</div>", esc(w)))
            .unwrap_or_default()
    );
    h.push_str("<div class=\"stats\">");
    let infra_detail = s
        .roles
        .iter()
        .filter(|r| r.role.is_infrastructure())
        .map(|r| format!("{} {}", r.count, esc(&r.label)))
        .collect::<Vec<_>>()
        .join(" &middot; ");
    let switches_with_data = s.switches.iter().filter(|x| x.has_data).count();
    let stat = |h: &mut String, label: &str, value: String, detail: String| {
        let _ = write!(
            h,
            "<div class=\"card stat\"><div class=\"label\">{label}</div><div class=\"value\">{value}</div><div class=\"detail\">{detail}</div></div>"
        );
    };
    stat(
        h,
        "Devices",
        s.total_hosts.to_string(),
        format!(
            "{} with open ports &middot; {} with IPv6",
            s.port_scanned_hosts, s.ipv6_hosts
        ),
    );
    stat(
        h,
        "Infrastructure",
        s.infrastructure.to_string(),
        if infra_detail.is_empty() {
            "none identified".into()
        } else {
            infra_detail
        },
    );
    stat(
        h,
        "VLANs",
        s.vlan_count.to_string(),
        format!(
            "{} with hosts &middot; {} CDP/LLDP neighbor{}",
            s.hosts_per_vlan.iter().filter(|b| b.vlan.is_some()).count(),
            s.neighbors,
            plural(s.neighbors)
        ),
    );
    stat(
        h,
        "Switches",
        s.switches.len().to_string(),
        format!("{switches_with_data} with SNMP port data"),
    );
    let mut chips = String::from("<div class=\"sevbar\">");
    for sev in Severity::ALL_DESC {
        let _ = write!(
            chips,
            "<span class=\"sev sev-{}\">{} {}</span>",
            sev.key(),
            c.get(sev),
            sev.label()
        );
    }
    chips.push_str("</div>");
    let _ = write!(
        h,
        "<div class=\"card stat\"><div class=\"label\">Findings</div><div class=\"value\">{}</div>{chips}</div>",
        c.total()
    );
    h.push_str("</div></div>");
    h.push_str("<div class=\"card narrative\">");
    for p in r.narrative() {
        let _ = write!(h, "<p>{}</p>", esc(&p));
    }
    h.push_str("<dl class=\"meta\">");
    for (k, v) in meta_rows(r) {
        let _ = write!(h, "<div><dt>{k}</dt><dd>{}</dd></div>", esc(&v));
    }
    h.push_str("</dl></div></section>\n");
}

fn overview(h: &mut String, r: &Report) {
    let s = &r.stats;
    h.push_str("<section id=\"overview\"><div class=\"section-head\"><h2>Network overview</h2></div><div class=\"grid grid-2\">");
    let vlan_bars: Vec<Bar> = s
        .hosts_per_vlan
        .iter()
        .map(|b| Bar {
            label: b.label.clone(),
            sub: b.name.clone(),
            value: b.hosts,
            class: "c1".into(),
            tip: format!(
                "{}{}: {} host{} ({} infrastructure)",
                b.label,
                b.name
                    .as_deref()
                    .map(|n| format!(" ({n})"))
                    .unwrap_or_default(),
                b.hosts,
                plural(b.hosts),
                b.infrastructure
            ),
        })
        .collect();
    let _ = write!(
        h,
        "<div class=\"card chart-card\"><h3>Hosts per VLAN</h3>{}<div class=\"caption\">Untagged hosts are counted in the native VLAN when CDP/LLDP advertised it on the scanning port.</div></div>",
        hbar_chart(&vlan_bars, "Hosts per VLAN")
    );
    let roles: Vec<(String, usize)> = s.roles.iter().map(|r| (r.label.clone(), r.count)).collect();
    let _ = write!(
        h,
        "<div class=\"card chart-card\"><h3>Device roles</h3>{}</div>",
        donut(&roles, "devices")
    );
    let c = &r.audit.score.counts;
    let sev_bars: Vec<Bar> = Severity::ALL_DESC
        .iter()
        .map(|sev| Bar {
            label: sev.label().into(),
            sub: None,
            value: c.get(*sev),
            class: format!("f-{}", sev.key()),
            tip: format!("{} findings: {}", sev.label(), c.get(*sev)),
        })
        .collect();
    let _ = write!(
        h,
        "<div class=\"card chart-card\"><h3>Findings by severity</h3>{}</div>",
        hbar_chart(&sev_bars, "Findings by severity")
    );
    // Category breakdown of the findings.
    let mut cats: Vec<(String, usize)> = Vec::new();
    for f in &r.audit.findings {
        match cats.iter_mut().find(|(c, _)| *c == f.category) {
            Some(e) => e.1 += 1,
            None => cats.push((f.category.clone(), 1)),
        }
    }
    cats.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let cat_bars: Vec<Bar> = cats
        .iter()
        .map(|(c, n)| Bar {
            label: c.clone(),
            sub: None,
            value: *n,
            class: "c7".into(),
            tip: format!("{c}: {n} finding{}", plural(*n)),
        })
        .collect();
    let _ = write!(
        h,
        "<div class=\"card chart-card\"><h3>Findings by category</h3>{}</div>",
        hbar_chart(&cat_bars, "Findings by category")
    );
    h.push_str("</div></section>\n");
}

fn port_rows_table(rows: &[crate::report::PortRow]) -> String {
    let mut s = String::from(
        "<table class=\"tbl\"><thead><tr><th>Port</th><th class=\"num\">MACs</th><th>VLANs</th><th></th></tr></thead><tbody>",
    );
    for p in rows {
        let _ = write!(
            s,
            "<tr><td class=\"mono\">{}</td><td class=\"num\">{}</td><td>{}</td><td>{}</td></tr>",
            esc(&p.port),
            p.macs,
            p.vlans
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            if p.trunk {
                "<span class=\"badge badge-trunk\">uplink / trunk</span>"
            } else if p.access_point {
                "<span class=\"badge\">access point</span>"
            } else {
                ""
            }
        );
    }
    s.push_str("</tbody></table>");
    s
}

fn switch_card(sw: &SwitchUtil, uplink: u32) -> String {
    let mut s = format!(
        "<div class=\"card switch\"><h3>{}<span class=\"ip\">{}</span>{}</h3>",
        esc(&sw.name),
        opt(sw.ip.as_deref()),
        if sw.partial {
            " <span class=\"badge badge-warn\">partial SNMP data</span>"
        } else {
            ""
        }
    );
    if let Some(m) = &sw.model {
        let _ = write!(s, "<div class=\"model\">{}</div>", esc(m));
    }
    if !sw.has_data {
        s.push_str(
            "<div class=\"na\">Port utilization not available (no SNMP data). Enable SNMP polling \
             (<code>--snmp-community</code> / <code>--snmp-user</code>) or poll it with \
             <code>sweepr snmp &lt;ip&gt;</code>.</div></div>",
        );
        return s;
    }
    match (sw.utilization(), sw.total_ports) {
        (Some(u), Some(total)) => {
            let _ = write!(
                s,
                "<div class=\"meter\" role=\"img\" aria-label=\"{pct:.0}% of ports active\"><span class=\"w{w}\"></span></div>\
                 <div class=\"meter-label\"><span>{a} of {pre}{total} ports with learned MACs</span><span>{pct:.0}%{est}</span></div>",
                pct = u * 100.0,
                w = (u * 100.0).round() as u32,
                a = sw.active_ports,
                pre = if sw.total_estimated { "~" } else { "" },
                est = if sw.total_estimated {
                    " (port count estimated from port names)"
                } else {
                    ""
                }
            );
        }
        _ => {
            let _ = write!(
                s,
                "<div class=\"meter-label\"><span>{} ports with learned MACs; total port count unknown</span></div>",
                sw.active_ports
            );
        }
    }
    let _ = write!(
        s,
        "<div class=\"kv\"><div><b>{}</b><span>access ports</span></div><div><b>{}</b><span>uplinks / trunks</span></div>\
         <div><b>{}</b><span>MACs learned</span></div><div><b>{}</b><span>endpoints mapped</span></div></div>",
        sw.access_ports,
        sw.trunk_ports.len(),
        sw.mac_total,
        sw.endpoints
    );
    if let Some(line) = poe_line(sw) {
        let _ = write!(s, "<div class=\"caption\">{}</div>", esc(&line));
    }
    if !sw.busiest.is_empty() {
        let _ = write!(
            s,
            "<h4 class=\"muted\">Busiest access ports</h4>{}",
            port_rows_table(&sw.busiest)
        );
    }
    if !sw.trunk_ports.is_empty() {
        let shown: Vec<_> = sw.trunk_ports.iter().take(8).cloned().collect();
        let _ = write!(
            s,
            "<h4 class=\"muted\">Uplinks / trunks (&gt; {uplink} MACs or leading to other infrastructure)</h4>{}",
            port_rows_table(&shown)
        );
    }
    if !sw.vlans.is_empty() {
        let _ = write!(
            s,
            "<div class=\"caption\">VLANs: {}</div>",
            sw.vlans
                .iter()
                .take(64)
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    for w in sw.warnings.iter().take(3) {
        let _ = write!(s, "<div class=\"caption\">Warning: {}</div>", esc(w));
    }
    s.push_str("</div>");
    s
}

/// One line of PoE facts for a switch, when it reported any.
pub(crate) fn poe_line(sw: &SwitchUtil) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(b) = &sw.poe_budget {
        match (b.consumed_watts, b.nominal_watts) {
            (Some(c), Some(n)) if n > 0.0 => parts.push(format!(
                "{c:.0} W of {n:.0} W budget in use ({:.0}%)",
                c * 100.0 / n
            )),
            (None, Some(n)) => parts.push(format!("{n:.0} W budget")),
            (Some(c), None) => parts.push(format!("{c:.0} W in use")),
            _ => {}
        }
        if let Some(p) = b.ports_delivering.filter(|p| *p > 0) {
            parts.push(format!("{p} ports delivering"));
        }
    }
    if sw.poe_ports_delivering > 0
        && sw
            .poe_budget
            .as_ref()
            .and_then(|b| b.ports_delivering)
            .is_none()
    {
        parts.push(format!(
            "{} mapped ports delivering{}",
            sw.poe_ports_delivering,
            sw.poe_watts
                .map(|w| format!(" ({w:.1} W)"))
                .unwrap_or_default()
        ));
    }
    (!parts.is_empty()).then(|| format!("PoE: {}", parts.join(" · ")))
}

fn switch_ports(h: &mut String, r: &Report) {
    let s = &r.stats;
    h.push_str("<section id=\"ports\"><div class=\"section-head\"><h2>Switch port utilization</h2>\
                <span class=\"hint\">From SNMP bridge / CAM tables: ports with at least one learned MAC.</span></div>");
    if s.switches.is_empty() {
        h.push_str("<div class=\"card\"><div class=\"na\">Not available: no switches were identified and no SNMP MAC-to-port data was collected. \
                    Scan with <code>--snmp-community</code> or <code>--snmp-user</code> to include switch port utilization.</div></div></section>\n");
        return;
    }
    h.push_str("<div class=\"grid grid-2\">");
    for sw in &s.switches {
        h.push_str(&switch_card(sw, r.opts.thresholds.uplink_mac_threshold));
    }
    h.push_str("</div></section>\n");
}

fn vendors_services(h: &mut String, r: &Report) {
    let s = &r.stats;
    h.push_str("<section id=\"services\"><div class=\"section-head\"><h2>Vendors &amp; services</h2></div><div class=\"grid grid-2\">");
    let mut vendor_bars: Vec<Bar> = s
        .top_vendors
        .iter()
        .map(|v| Bar {
            label: v.name.clone(),
            sub: None,
            value: v.count,
            class: "c3".into(),
            tip: format!("{}: {} device{}", v.name, v.count, plural(v.count)),
        })
        .collect();
    if s.unknown_vendor > 0 {
        vendor_bars.push(Bar {
            label: "Unknown vendor".into(),
            sub: None,
            value: s.unknown_vendor,
            class: "f-info".into(),
            tip: format!("{} device(s) without an OUI vendor match", s.unknown_vendor),
        });
    }
    let _ = write!(
        h,
        "<div class=\"card chart-card\"><h3>Top vendors</h3>{}<div class=\"caption\">From the IEEE OUI registry; randomized MACs have no vendor.</div></div>",
        hbar_chart(&vendor_bars, "Top vendors")
    );
    let svc_bars: Vec<Bar> = s
        .services
        .iter()
        .map(|p| Bar {
            label: if p.service.is_empty() {
                format!("TCP {}", p.port)
            } else {
                format!("{} ({})", p.service, p.port)
            },
            sub: p.risky.then(|| "cleartext / legacy".to_string()),
            value: p.hosts,
            class: if p.risky {
                "f-high".into()
            } else {
                "c1".into()
            },
            tip: format!(
                "TCP {} {}: open on {} host{}{}",
                p.port,
                p.service,
                p.hosts,
                plural(p.hosts),
                if p.risky {
                    " (cleartext / legacy protocol)"
                } else {
                    ""
                }
            ),
        })
        .collect();
    let caption = match r.input.meta.port_spec.as_deref() {
        Some(spec) => format!(
            "Ports scanned: {}. Orange bars are cleartext or legacy protocols.",
            esc(spec)
        ),
        None => "Orange bars are cleartext or legacy protocols.".into(),
    };
    let _ = write!(
        h,
        "<div class=\"card chart-card\"><h3>Open services</h3>{}<div class=\"caption\">{caption}</div></div>",
        hbar_chart(&svc_bars, "Open services")
    );
    h.push_str("</div></section>\n");
}

fn finding_detail(f: &Finding) -> String {
    let mut s = format!("<p>{}</p>", rich(&f.description));
    if !f.evidence.is_empty() {
        s.push_str("<h4>Evidence</h4><ul>");
        for e in &f.evidence {
            let _ = write!(s, "<li>{}</li>", esc(e));
        }
        s.push_str("</ul>");
    }
    if !f.affected.is_empty() {
        let _ = write!(
            s,
            "<h4>Affected ({})</h4><div class=\"affected table-wrap\"><table class=\"tbl\"><thead><tr>\
             <th>IP</th><th>Name</th><th>MAC</th><th>VLAN</th><th>Port</th><th>Detail</th></tr></thead><tbody>",
            f.affected_count
        );
        for a in f.affected.iter().take(MAX_AFFECTED_ROWS) {
            let _ = write!(
                s,
                "<tr><td class=\"mono nowrap\">{}</td><td class=\"wrap\">{}</td><td class=\"mono nowrap\">{}</td><td>{}</td><td class=\"wrap\">{}</td><td class=\"wrap\">{}</td></tr>",
                opt(a.ip.as_deref()),
                opt(a.name.as_deref()),
                opt(a.mac.as_deref()),
                a.vlan.map(|v| v.to_string()).unwrap_or_default(),
                opt(a.port.as_deref()),
                opt(a.detail.as_deref()),
            );
        }
        s.push_str("</tbody></table></div>");
        if f.affected_count > MAX_AFFECTED_ROWS.min(f.affected.len()) {
            let where_ = if f.affected_truncated == 0 {
                "complete list in the JSON export".to_string()
            } else {
                format!(
                    "the JSON export lists the first {}",
                    crate::audit::MAX_AFFECTED
                )
            };
            let _ = write!(
                s,
                "<div class=\"more\">and {} more ({where_})</div>",
                f.affected_count - MAX_AFFECTED_ROWS.min(f.affected.len())
            );
        }
    }
    let _ = write!(
        s,
        "<h4>Remediation</h4><div class=\"remediation\">{}</div>",
        rich(&f.remediation)
    );
    if !f.references.is_empty() {
        let _ = write!(
            s,
            "<h4>References</h4><div class=\"sub\">{}</div>",
            f.references
                .iter()
                .map(|r| esc(r))
                .collect::<Vec<_>>()
                .join(" &middot; ")
        );
    }
    s
}

fn findings(h: &mut String, r: &Report) {
    let c = &r.audit.score.counts;
    h.push_str("<section id=\"findings\"><div class=\"section-head\"><h2>Findings</h2>\
                <span class=\"hint\">Click a finding for evidence, affected devices and remediation.</span></div>");
    if r.audit.findings.is_empty() {
        h.push_str("<div class=\"card\"><p class=\"ok-text\">No findings on the data collected.</p>\
                    <p class=\"muted\">See Rule coverage for checks that could not run.</p></div></section>\n");
        return;
    }
    h.push_str("<div class=\"toolbar\"><input type=\"search\" id=\"finding-search\" placeholder=\"Filter findings, IPs, names...\" aria-label=\"Filter findings\">");
    for sev in Severity::ALL_DESC {
        let _ = write!(
            h,
            "<button type=\"button\" class=\"chip sev-filter\" data-sev=\"{}\" aria-pressed=\"true\">{} ({})</button>",
            sev.key(),
            sev.label(),
            c.get(sev)
        );
    }
    h.push_str("<button type=\"button\" class=\"linkbtn\" data-action=\"expand\">Expand all</button>\
                <button type=\"button\" class=\"linkbtn\" data-action=\"collapse\">Collapse all</button>\
                <span class=\"count\" id=\"finding-count\"></span></div>");
    h.push_str("<div class=\"table-wrap\"><table class=\"tbl sortable grouped\" id=\"findings-table\"><thead><tr>\
                <th><span class=\"no-print\"></span></th>\
                <th data-type=\"num\"><button type=\"button\">Severity</button></th>\
                <th><button type=\"button\">ID</button></th>\
                <th><button type=\"button\">Finding</button></th>\
                <th><button type=\"button\">Category</button></th>\
                <th class=\"num\" data-type=\"num\"><button type=\"button\">Affected</button></th></tr></thead>");
    for f in &r.audit.findings {
        let _ = write!(
            h,
            "<tbody class=\"f-group\" data-sev=\"{sevk}\"><tr class=\"f-row\">\
             <td><button type=\"button\" class=\"toggle\" aria-expanded=\"false\" aria-label=\"Show details\"></button></td>\
             <td data-v=\"{rank}\">{chip}</td><td class=\"mono nowrap\">{id}</td><td class=\"f-title wrap\">{title}</td>\
             <td>{cat}</td><td class=\"num\" data-v=\"{n}\">{n}</td></tr>\
             <tr class=\"f-detail\" hidden><td colspan=\"6\">{detail}</td></tr></tbody>",
            sevk = f.severity.key(),
            rank = rank(f.severity),
            chip = sev_chip(f.severity),
            id = esc(&f.id),
            title = esc(&f.title),
            cat = esc(&f.category),
            n = f.affected_count,
            detail = finding_detail(f),
        );
    }
    h.push_str("</table></div></section>\n");
}

/// One inventory column: header, default visibility, cell renderer `(sort key, html)`.
type CellFn = fn(&AuditDevice, &CellEnv) -> (Option<String>, String);

/// Shared state for inventory cells (built once per table).
struct CellEnv<'a> {
    ctx: crate::audit::Ctx<'a>,
    now_ms: u64,
}
struct Col {
    name: &'static str,
    visible: bool,
    numeric: bool,
    cell: CellFn,
}

/// Free-text inventory columns wrap; identifiers (IP, MAC, VLAN, port) stay on one line.
fn cell_class(column: &str) -> &'static str {
    match column {
        "Name"
        | "Vendor"
        | "Web interface"
        | "TLS certificate"
        | "DNS / mDNS / NetBIOS"
        | "Comments"
        | "Other IPs"
        | "Open TCP ports"
        | "DHCP OS" => "wrap",
        _ => "nowrap",
    }
}

fn text_cell(s: Option<&str>) -> (Option<String>, String) {
    (None, opt(s))
}

fn inventory_columns(r: &Report) -> Vec<Col> {
    let has = |key: &str| r.input.devices.iter().any(|d| d.extra.contains_key(key));
    let mut cols = vec![
        Col {
            name: "IP",
            visible: true,
            numeric: false,
            cell: |d, _| {
                (
                    Some(ip_key(&d.ip)),
                    format!("<span class=\"mono\">{}</span>", esc(&d.ip)),
                )
            },
        },
        Col {
            name: "Name",
            visible: true,
            numeric: false,
            cell: |d, _| text_cell(d.name()),
        },
        Col {
            name: "MAC",
            visible: true,
            numeric: false,
            cell: |d, _| {
                (
                    None,
                    format!("<span class=\"mono\">{}</span>", opt(d.mac.as_deref())),
                )
            },
        },
        Col {
            name: "Vendor",
            visible: true,
            numeric: false,
            cell: |d, _| text_cell(d.vendor.as_deref()),
        },
        Col {
            name: "Role",
            visible: true,
            numeric: false,
            cell: |d, _| (None, d.role.label().to_string()),
        },
        Col {
            name: "VLAN",
            visible: true,
            numeric: true,
            cell: |d, env| {
                let v = env.ctx.effective_vlan(d);
                (
                    Some(v.map(|v| v.to_string()).unwrap_or_else(|| "-1".into())),
                    match (d.vlan_id, v) {
                        (Some(t), _) => t.to_string(),
                        (None, Some(n)) => format!("{n} <span class=\"sub\">native</span>"),
                        _ => String::new(),
                    },
                )
            },
        },
        Col {
            name: "Switch port",
            visible: true,
            numeric: false,
            cell: |d, _| {
                let label = d.switch_port.as_ref().map(|p| p.label());
                (label.as_deref().map(natural_key), opt(label.as_deref()))
            },
        },
        Col {
            name: "Open TCP ports",
            visible: true,
            numeric: true,
            cell: |d, _| {
                (
                    Some(d.open_ports.len().to_string()),
                    d.open_ports
                        .iter()
                        .map(|p| match crate::report::service_name(*p) {
                            Some(n) => format!("{p}<span class=\"sub\">/{n}</span>"),
                            None => p.to_string(),
                        })
                        .collect::<Vec<_>>()
                        .join(", "),
                )
            },
        },
        Col {
            name: "Other IPs",
            visible: false,
            numeric: false,
            cell: |d, _| {
                (
                    None,
                    format!(
                        "<span class=\"mono\">{}</span>",
                        esc(&d.extra_ips.join(", "))
                    ),
                )
            },
        },
        Col {
            name: "DNS / mDNS / NetBIOS",
            visible: false,
            numeric: false,
            cell: |d, _| {
                let names: Vec<&str> = [&d.dns_name, &d.mdns_name, &d.smb_name, &d.smb_domain]
                    .into_iter()
                    .filter_map(|n| n.as_deref())
                    .collect();
                (None, esc(&names.join(" / ")))
            },
        },
        Col {
            name: "Sources",
            visible: false,
            numeric: false,
            cell: |d, _| (None, esc(&d.sources.join(", "))),
        },
        Col {
            name: "Comments",
            visible: false,
            numeric: false,
            cell: |d, _| text_cell(d.comments.as_deref()),
        },
    ];
    if has("webTitle") || has("webIdentity") {
        cols.push(Col {
            name: "Web interface",
            visible: true,
            numeric: false,
            cell: |d, _| {
                let t = d
                    .extra_str("webIdentity")
                    .or_else(|| d.extra_str("webTitle"));
                text_cell(t.as_deref())
            },
        });
    }
    if has("tlsCert") || has("tlsCerts") {
        cols.push(Col {
            name: "TLS certificate",
            visible: true,
            numeric: true,
            cell: |d, env| {
                let certs = d.certificates();
                let Some(c) = certs.first() else {
                    return (Some("999999".into()), String::new());
                };
                let days = c.days_left(env.now_ms);
                let mut s = opt(c.subject_cn.as_deref());
                if let Some(days) = days {
                    let _ = write!(
                        s,
                        " <span class=\"sub\">{}</span>",
                        if c.is_expired(env.now_ms) == Some(true) {
                            match days.unsigned_abs() {
                                0 => "expired today".to_string(),
                                n => format!("expired {n} d ago"),
                            }
                        } else {
                            format!("{days} d left")
                        }
                    );
                }
                if c.self_signed {
                    s.push_str(" <span class=\"badge\">self-signed</span>");
                }
                (Some(days.unwrap_or(999_999).to_string()), s)
            },
        });
    }
    if has("latency") {
        cols.push(Col {
            name: "Latency",
            visible: true,
            numeric: true,
            cell: |d, _| {
                let avg = d.extra_f64("latency.avgMs");
                let loss = d.extra_f64("latency.lossPct");
                (
                    avg.map(|a| format!("{a:.3}")),
                    match (avg, loss) {
                        (Some(a), Some(l)) => {
                            format!("{a:.1} ms <span class=\"sub\">{l:.0}% loss</span>")
                        }
                        (Some(a), None) => format!("{a:.1} ms"),
                        _ => String::new(),
                    },
                )
            },
        });
    }
    if has("poeWatts") || has("poe") {
        cols.push(Col {
            name: "PoE (W)",
            visible: true,
            numeric: true,
            cell: |d, _| {
                let w = d.extra_f64("poeWatts").or_else(|| d.extra_f64("poe.watts"));
                (
                    w.map(|w| format!("{w:.2}")),
                    w.map(|w| format!("{w:.1}")).unwrap_or_default(),
                )
            },
        });
    }
    if has("voiceVlan") {
        cols.push(Col {
            name: "Voice VLAN",
            visible: true,
            numeric: true,
            cell: |d, _| {
                let v = d.voice_vlan();
                (
                    v.map(|v| v.to_string()),
                    v.map(|v| v.to_string()).unwrap_or_default(),
                )
            },
        });
    }
    if has("dhcpFingerprint") || has("dhcpOs") {
        cols.push(Col {
            name: "DHCP OS",
            visible: false,
            numeric: false,
            cell: |d, _| {
                let v = d.extra_str("dhcpOs").or_else(|| {
                    d.extra
                        .get("dhcpFingerprint")
                        .and_then(|f| f.get("os"))
                        .and_then(|v| v.as_str())
                        .map(crate::models::sanitize_text)
                });
                text_cell(v.as_deref())
            },
        });
    }
    cols.truncate(24);
    cols
}

fn inventory(h: &mut String, r: &Report) {
    let cols = inventory_columns(r);
    let n = r.input.devices.len();
    let _ = write!(
        h,
        "<section id=\"inventory\"><div class=\"section-head\"><h2>Device inventory</h2><span class=\"hint\">{n} device{}</span></div>",
        plural(n)
    );
    if n == 0 {
        h.push_str(
            "<div class=\"card\"><p class=\"empty\">No devices in the input.</p></div></section>\n",
        );
        return;
    }
    h.push_str("<div class=\"toolbar\"><input type=\"search\" id=\"inventory-search\" placeholder=\"Search IP, name, MAC, vendor, port...\" aria-label=\"Search devices\">\
                <details class=\"cols\"><summary class=\"chip\">Columns</summary><div class=\"cols-menu\">");
    for (i, c) in cols.iter().enumerate() {
        let _ = write!(
            h,
            "<label><input type=\"checkbox\" class=\"col-toggle\" data-table=\"inventory-table\" data-col=\"{}\"{}> {}</label>",
            i + 1,
            if c.visible { " checked" } else { "" },
            c.name
        );
    }
    h.push_str("</div></details><span class=\"count\" id=\"inventory-count\"></span></div>");
    let hidden: String = cols
        .iter()
        .enumerate()
        .filter(|(_, c)| !c.visible)
        .map(|(i, _)| format!(" hide-c{}", i + 1))
        .collect();
    let _ = write!(
        h,
        "<div class=\"table-wrap\"><table class=\"tbl inv sortable{hidden}\" id=\"inventory-table\"><thead><tr>"
    );
    for c in &cols {
        let _ = write!(
            h,
            "<th{}><button type=\"button\">{}</button></th>",
            if c.numeric { " data-type=\"num\"" } else { "" },
            c.name
        );
    }
    h.push_str("</tr></thead><tbody>");
    let env = CellEnv {
        ctx: crate::audit::Ctx::new(r.input, &r.opts.thresholds, r.opts.now_ms),
        now_ms: r.opts.now_ms,
    };
    for d in &r.input.devices {
        h.push_str("<tr>");
        for c in &cols {
            let (key, html) = (c.cell)(d, &env);
            match key {
                Some(k) => {
                    let _ = write!(
                        h,
                        "<td data-v=\"{}\" class=\"{}\">{html}</td>",
                        esc(&k),
                        cell_class(c.name)
                    );
                }
                None => {
                    let _ = write!(h, "<td class=\"{}\">{html}</td>", cell_class(c.name));
                }
            }
        }
        h.push_str("</tr>");
    }
    h.push_str("</tbody></table></div></section>\n");
}

fn neighbor_row(n: &AuditNeighbor) -> String {
    format!(
        "<tr><td class=\"wrap\"><strong>{}</strong><div class=\"sub\">{}</div></td><td class=\"wrap\">{}</td><td class=\"mono nowrap\">{}</td>\
         <td class=\"mono\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"wrap\">{}</td><td class=\"nowrap\">{} on {}</td></tr>",
        esc(n.display_name()),
        opt(n.software_version.as_deref().map(|v| v.get(..80).unwrap_or(v))),
        opt(n.platform.as_deref()),
        esc(&n.management_addrs.join(", ")),
        opt(n.port_id.as_deref()),
        n.native_vlan.map(|v| v.to_string()).unwrap_or_default(),
        n.voice_vlan.map(|v| v.to_string()).unwrap_or_default(),
        esc(&n.capabilities.join(", ").replace('_', " ")),
        esc(&n.protocol.to_ascii_uppercase()),
        esc(&n.local_interface),
    )
}

fn topology(h: &mut String, r: &Report) {
    h.push_str("<section id=\"topology\"><div class=\"section-head\"><h2>Neighbors &amp; topology</h2></div>");
    if r.input.neighbors.is_empty() {
        h.push_str("<div class=\"card\"><div class=\"na\">No CDP/LLDP advertisements were captured (scan with <code>--cdp-lldp</code> or run <code>sweepr vlans</code> on a switch port).</div></div>");
    } else {
        h.push_str("<div class=\"card\"><h3>CDP / LLDP neighbors</h3><div class=\"table-wrap\"><table class=\"tbl sortable\" id=\"neighbor-table\"><thead><tr>\
                    <th><button type=\"button\">Device</button></th><th><button type=\"button\">Platform</button></th>\
                    <th><button type=\"button\">Mgmt IP</button></th><th><button type=\"button\">Remote port</button></th>\
                    <th data-type=\"num\"><button type=\"button\">Native</button></th><th data-type=\"num\"><button type=\"button\">Voice</button></th>\
                    <th><button type=\"button\">Capabilities</button></th><th><button type=\"button\">Heard</button></th></tr></thead><tbody>");
        for n in &r.input.neighbors {
            h.push_str(&neighbor_row(n));
        }
        h.push_str("</tbody></table></div></div>");
    }
    // Device attachment: which endpoints sit behind which switch port.
    let mut attach: std::collections::BTreeMap<(String, String), Vec<&AuditDevice>> =
        std::collections::BTreeMap::new();
    for d in &r.input.devices {
        if let Some(p) = &d.switch_port {
            attach
                .entry((p.switch_name.clone(), natural_key(&p.port_name)))
                .or_default()
                .push(d);
        }
    }
    if !attach.is_empty() {
        let _ = write!(
            h,
            "<div class=\"card\" ><h3>Device attachment ({} switch port{})</h3><div class=\"table-wrap\"><table class=\"tbl sortable\" id=\"attach-table\"><thead><tr>\
             <th><button type=\"button\">Switch</button></th><th><button type=\"button\">Port</button></th>\
             <th data-type=\"num\"><button type=\"button\">Devices</button></th><th>Attached</th></tr></thead><tbody>",
            attach.len(),
            plural(attach.len())
        );
        for ((sw, _), devs) in attach.iter().take(MAX_ATTACHMENT_ROWS) {
            let port = devs[0]
                .switch_port
                .as_ref()
                .map(|p| p.port_name.as_str())
                .unwrap_or("");
            let names: Vec<String> = devs
                .iter()
                .take(4)
                .map(|d| match d.name() {
                    Some(n) => format!("{} <span class=\"sub\">{}</span>", esc(n), esc(&d.ip)),
                    None => format!("<span class=\"mono\">{}</span>", esc(&d.ip)),
                })
                .collect();
            let more = devs.len().saturating_sub(4);
            let _ = write!(
                h,
                "<tr><td class=\"nowrap\">{}</td><td class=\"mono nowrap\" data-v=\"{}\">{}</td><td class=\"num\">{}</td><td class=\"wrap\">{}{}</td></tr>",
                esc(sw),
                esc(&natural_key(port)),
                esc(port),
                devs.len(),
                names.join(", "),
                if more > 0 { format!(" <span class=\"sub\">+{more} more</span>") } else { String::new() }
            );
        }
        h.push_str("</tbody></table></div></div>");
    }
    h.push_str("</section>\n");
}

fn coverage(h: &mut String, r: &Report) {
    let evaluated = r.audit.checks.iter().filter(|c| c.evaluated).count();
    let _ = write!(
        h,
        "<section id=\"coverage\"><div class=\"section-head\"><h2>Rule coverage</h2><span class=\"hint\">{evaluated} of {} checks evaluated</span></div>\
         <div class=\"table-wrap\"><table class=\"tbl sortable\" id=\"coverage-table\"><thead><tr>\
         <th><button type=\"button\">ID</button></th><th><button type=\"button\">Check</button></th>\
         <th><button type=\"button\">Category</button></th><th><button type=\"button\">Result</button></th></tr></thead><tbody>",
        r.audit.checks.len()
    );
    for c in &r.audit.checks {
        let result = if !c.evaluated {
            format!(
                "<span class=\"muted\">Not evaluated: {}</span>",
                opt(c.note.as_deref())
            )
        } else if c.findings > 0 {
            let sev = r
                .audit
                .findings
                .iter()
                .filter(|f| f.id == c.id)
                .map(|f| f.severity)
                .max()
                .unwrap_or(Severity::Info);
            format!(
                "{} finding{}",
                sev_chip(sev),
                if c.findings > 1 { "s" } else { "" }
            )
        } else {
            "<span class=\"ok-text\">Passed</span>".into()
        };
        let _ = write!(
            h,
            "<tr><td class=\"mono nowrap\">{}</td><td>{}</td><td>{}</td><td>{result}</td></tr>",
            esc(&c.id),
            esc(&c.title),
            esc(&c.category)
        );
    }
    h.push_str("</tbody></table></div></section>\n");
}

fn appendix(h: &mut String, r: &Report) {
    h.push_str("<section id=\"appendix\"><div class=\"section-head\"><h2>Appendix: methodology &amp; limitations</h2></div><div class=\"card prose\">");
    h.push_str("<h3>Methodology</h3><ul>");
    for m in METHODOLOGY {
        let _ = write!(h, "<li>{}</li>", esc(m));
    }
    h.push_str("</ul><h3>Risk score</h3>");
    let _ = write!(h, "<p>{}</p>", esc(SCORING_METHOD));
    let t = &r.audit.thresholds;
    let _ = write!(
        h,
        "<h3>Thresholds used</h3><ul><li>Certificate expiry warning: {} days; minimum keys RSA {} / EC {} bits</li>\
         <li>Broad SMB exposure: at least {} hosts and {:.0}% of port-scanned hosts</li>\
         <li>VLAN 1 host limit: {}; access port with {} or more MACs flagged; ports with more than {} MACs treated as uplinks</li>\
         <li>Expected DHCP servers: at most {}; IPv6 routers: at most {}</li></ul>",
        t.cert_expiry_warn_days,
        t.min_rsa_bits,
        t.min_ec_bits,
        t.smb_broad_min_hosts,
        t.smb_broad_fraction * 100.0,
        t.vlan1_max_hosts,
        t.hub_port_min_macs,
        t.uplink_mac_threshold,
        t.max_dhcp_servers,
        t.max_ipv6_routers
    );
    h.push_str("<h3>Limitations</h3><ul>");
    for l in LIMITATIONS {
        let _ = write!(h, "<li>{}</li>", esc(l));
    }
    h.push_str("</ul><h3>Data quality</h3><ul>");
    let m = &r.input.meta;
    if m.cancelled {
        h.push_str("<li>The scan was stopped before it finished; results are partial.</li>");
    }
    if r.input.skipped_records > 0 {
        let _ = write!(
            h,
            "<li>{} input record(s) could not be read and were skipped.</li>",
            r.input.skipped_records
        );
    }
    for w in &r.input.warnings {
        let _ = write!(h, "<li>{}</li>", esc(w));
    }
    let partial: Vec<&str> = r
        .stats
        .switches
        .iter()
        .filter(|s| s.partial)
        .map(|s| s.name.as_str())
        .collect();
    if !partial.is_empty() {
        let _ = write!(
            h,
            "<li>SNMP data is partial for: {}.</li>",
            esc(&partial.join(", "))
        );
    }
    let _ = write!(
        h,
        "<li>{} device(s), {} VLAN record(s), {} neighbor advertisement(s), {} MAC-to-port mapping(s), {} SNMP poll result(s).</li>",
        r.input.devices.len(),
        r.input.vlans.len(),
        r.input.neighbors.len(),
        r.input.port_mappings.len(),
        r.input.snmp_infos.len()
    );
    if !r.stats.extra_fields.is_empty() {
        let _ = write!(
            h,
            "<li>Additional device data present: {}.</li>",
            esc(&r.stats.extra_fields.join(", "))
        );
    }
    h.push_str("</ul></div></section>\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{tests::NOW, AuditInput};
    use crate::report::{render, ReportFormat, ReportOptions};
    use serde_json::json;

    /// Optional columns appear only when some device has data: every scanned `Device`
    /// serializes `null` for the optional fields, which must not count (review H1).
    #[test]
    fn null_optional_fields_do_not_add_columns() {
        let mut d = crate::models::Device::new("10.0.0.5".parse().unwrap());
        d.mac = Some("00:11:22:33:44:55".into());
        let input =
            AuditInput::from_json_value(json!([serde_json::to_value(&d).unwrap()])).unwrap();
        let mut opts = ReportOptions::new(None, None);
        opts.now_ms = NOW;
        let report = crate::report::Report::build(&input, &opts);
        let names: Vec<&str> = inventory_columns(&report).iter().map(|c| c.name).collect();
        for absent in ["Web interface", "TLS certificate", "Voice VLAN"] {
            assert!(!names.contains(&absent), "{absent} in {names:?}");
        }
        d.web_title = Some("Router".into());
        let input =
            AuditInput::from_json_value(json!([serde_json::to_value(&d).unwrap()])).unwrap();
        let report = crate::report::Report::build(&input, &opts);
        assert!(inventory_columns(&report)
            .iter()
            .any(|c| c.name == "Web interface"));
    }

    const PAYLOADS: [&str; 4] = [
        "<script>alert(1)</script>",
        "\"onerror=alert(2) x=\"",
        "</script><!--<script>alert(3)</script>",
        "<img src=x onerror=alert(4)>",
    ];

    fn hostile_input() -> AuditInput {
        let p = |i: usize| PAYLOADS[i % PAYLOADS.len()].to_string();
        AuditInput::from_json_value(json!({
            "meta": { "interface": p(0), "ranges": [p(1)], "portSpec": "22,23,80,443", "scannerHost": p(2),
                      "snmp": { "version": "v2c", "community": "public" } },
            "devices": [
                { "ip": "10.0.0.1", "mac": "00:11:22:33:44:55", "role": "switch", "hostname": p(0), "vendor": p(1),
                  "dnsName": p(2), "comments": p(3), "openPorts": [23, 80], "webTitle": p(0),
                  "switchPort": { "switchName": p(1), "portName": p(2), "mac": "00:11:22:33:44:55" },
                  "tlsCert": { "subjectCn": p(3), "notAfterMs": 1, "selfSigned": true },
                  "neighbor": { "deviceId": p(0), "systemName": p(1), "platform": p(2), "capabilities": ["switch"] } },
                { "ip": "10.0.0.2", "smbName": p(3), "vendor": p(0), "extraIps": [p(1)] }
            ],
            "vlans": [{ "id": 10, "name": p(0), "sources": ["snmp"] }, { "id": 30, "name": p(3), "sources": ["vtp"] }],
            "neighbors": [{ "protocol": "cdp", "localInterface": p(1), "sourceMac": "00:aa:bb:cc:dd:ee",
                            "deviceId": p(2), "systemName": p(3), "platform": p(0), "softwareVersion": p(1),
                            "portId": p(2), "nativeVlan": 1, "capabilities": ["switch"],
                            "managementAddrs": ["10.0.0.1"] }],
            "portMappings": [{ "switchName": p(0), "switchIp": "10.0.0.1", "portName": p(3), "mac": p(1), "vlanId": 10 }],
            "snmpInfos": [{ "ip": "10.0.0.1", "sysName": p(2), "sysDescr": p(3), "role": "switch",
                            "partial": true, "warnings": [p(0)], "vlans": [{ "id": 99, "name": p(1), "sources": ["snmp"] }],
                            "portMacCounts": [{ "portName": p(0), "macCount": 7 }] }]
        }))
        .unwrap()
    }

    fn html(input: &AuditInput) -> String {
        let mut opts = ReportOptions::new(Some(PAYLOADS[0]), Some(PAYLOADS[1]));
        opts.now_ms = NOW;
        String::from_utf8(render(input, &opts, ReportFormat::Html).unwrap()).unwrap()
    }

    #[test]
    fn xss_payloads_are_escaped_everywhere() {
        let page = html(&hostile_input());
        // Exactly the two script elements we emit: the JSON data block and the app code.
        assert_eq!(
            page.matches("<script").count(),
            2,
            "unexpected <script> in output"
        );
        assert_eq!(page.matches("</script>").count(), 2);
        // The embedded JSON block contains no raw angle brackets or ampersands.
        let start = page.find("id=\"report-data\">").unwrap() + "id=\"report-data\">".len();
        let end = start + page[start..].find("</script>").unwrap();
        let data = &page[start..end];
        let markup = format!("{}{}", &page[..start], &page[end..]);
        assert!(!markup.contains("<img src=x"));
        assert!(!markup.contains("\"onerror="), "attribute payload leaked");
        assert!(!markup.contains("<!--"));
        assert!(markup.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(markup.contains("&quot;onerror=alert(2) x=&quot;"));
        assert!(!data.contains('<') && !data.contains('>') && !data.contains('&'));
        let v: serde_json::Value = serde_json::from_str(data).unwrap();
        assert_eq!(v["title"], PAYLOADS[0]);
        // The SNMP community is never written out.
        assert!(!page.contains("\"community\""));
    }

    #[test]
    fn csp_pins_inline_code_and_blocks_network() {
        let page = html(&hostile_input());
        let csp_start = page.find("Content-Security-Policy\" content=\"").unwrap();
        let csp = &page[csp_start..csp_start + 400];
        assert!(csp.contains("default-src &#39;none&#39;"));
        assert!(csp.contains("script-src &#39;sha256-"));
        assert!(!csp.contains("unsafe-inline"));
        assert!(
            !page.contains("http://") && !page.contains("https://"),
            "no external URLs"
        );
        // The script hash matches the emitted script.
        let js_hash = csp_hash(JS);
        assert!(page.contains(&esc(&js_hash)));
        assert!(page.contains(&format!("<script>{JS}</script>")));
    }

    #[test]
    fn sections_and_graceful_empty_states() {
        let page = html(&AuditInput::default());
        for id in [
            "summary",
            "overview",
            "ports",
            "findings",
            "inventory",
            "topology",
            "coverage",
            "appendix",
        ] {
            assert!(page.contains(&format!("id=\"{id}\"")), "{id}");
        }
        assert!(page.contains("Not available"));
        assert!(page.contains("No findings"));
        let page = html(&hostile_input());
        assert!(page.contains("grade-"));
        assert!(page.contains("SWR-SNP-001"));
        assert!(page.contains("partial SNMP data"));
    }

    #[test]
    fn helpers() {
        assert_eq!(
            esc("<a href='x'>&\""),
            "&lt;a href=&#39;x&#39;&gt;&amp;&quot;"
        );
        assert_eq!(
            json_for_script(&json!({ "a": "</script><!--\u{2028}&" })),
            "{\"a\":\"\\u003c/script\\u003e\\u003c!--\\u2028\\u0026\"}"
        );
        assert!(natural_key("Gi1/0/2") < natural_key("Gi1/0/10"));
        assert!(ip_key("10.0.0.9") < ip_key("10.0.0.10"));
        assert!(ip_key("255.0.0.1") < ip_key("fe80::1"));
    }
}
