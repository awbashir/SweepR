//! Device list export (CSV, JSON, XLSX) and CLI table rendering.

use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, Write},
    path::Path,
    str::FromStr,
};

use anyhow::{bail, Context, Result};
use comfy_table::{presets::UTF8_FULL_CONDENSED, ContentArrangement, Table};
use rust_xlsxwriter::{Color, Format, FormatBorder, Workbook};
use serde::{Deserialize, Serialize};

use crate::models::{sanitize_text, Device};

/// Number of columns in every tabular export.
pub const NUM_COLUMNS: usize = 14;

/// Column headers shared by every tabular export.
pub const COLUMNS: [&str; NUM_COLUMNS] = [
    "IP",
    "Other IPs",
    "MAC",
    "VLAN",
    "Role",
    "Hostname",
    "Vendor",
    "Switch/Port",
    "DNS",
    "mDNS",
    "SMB Name",
    "SMB Domain",
    "TCP Ports",
    "Comments",
];

const COL_VLAN: usize = 3;

/// Columns always shown by [`render_table`], even when empty (IP, MAC, VLAN, Role).
const ALWAYS_SHOWN: [usize; 4] = [0, 2, COL_VLAN, 4];

/// Excel column widths (characters), aligned with [`COLUMNS`].
const XLSX_WIDTHS: [f64; NUM_COLUMNS] = [
    16.0, 30.0, 19.0, 7.0, 13.0, 22.0, 24.0, 28.0, 30.0, 26.0, 18.0, 16.0, 20.0, 36.0,
];

/// File formats supported by [`export_to_path`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Csv,
    Json,
    Xlsx,
}

impl ExportFormat {
    /// Guess the format from a file extension.
    pub fn from_path(path: &Path) -> Option<Self> {
        path.extension()?.to_str()?.parse().ok()
    }
}

impl FromStr for ExportFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "csv" => Ok(Self::Csv),
            "json" => Ok(Self::Json),
            "xlsx" | "excel" => Ok(Self::Xlsx),
            other => bail!("unsupported export format '{other}' (expected csv, json or xlsx)"),
        }
    }
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Csv => "csv",
            Self::Json => "json",
            Self::Xlsx => "xlsx",
        })
    }
}

/// Devices ordered by VLAN (untagged first), then numerically by IP.
pub fn sorted(devices: &[Device]) -> Vec<&Device> {
    let mut v: Vec<&Device> = devices.iter().collect();
    v.sort_by_key(|d| (d.vlan_id, d.ip));
    v
}

/// One export row, aligned with [`COLUMNS`]. Text is passed through [`sanitize_text`]
/// so names learned from the network cannot smuggle terminal escape sequences into
/// tables or files.
pub fn device_row(d: &Device) -> [String; NUM_COLUMNS] {
    let opt = |s: &Option<String>| s.as_deref().map(sanitize_text).unwrap_or_default();
    [
        d.ip.to_string(),
        d.extra_ips
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        opt(&d.mac),
        d.vlan_id.map(|v| v.to_string()).unwrap_or_default(),
        d.role.label().to_string(),
        opt(&d.hostname),
        opt(&d.vendor),
        d.switch_port
            .as_ref()
            .map(|p| sanitize_text(&p.label()))
            .unwrap_or_default(),
        opt(&d.dns_name),
        opt(&d.mdns_name),
        opt(&d.smb_name),
        opt(&d.smb_domain),
        d.open_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        opt(&d.comments),
    ]
}

/// Neutralize spreadsheet formula injection: a cell starting with `=`, `+`, `-`, `@`, tab
/// or CR is evaluated as a formula by Excel / LibreOffice when the CSV is opened, so it
/// gets a leading `'` (OWASP "CSV injection" guidance).
pub fn csv_safe(cell: &str) -> std::borrow::Cow<'_, str> {
    if cell.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{cell}").into()
    } else {
        cell.into()
    }
}

/// CSV with a header row; devices sorted by VLAN, then IP.
pub fn write_csv<W: Write>(devices: &[Device], writer: W) -> Result<()> {
    let mut w = csv::Writer::from_writer(writer);
    w.write_record(COLUMNS)?;
    for d in sorted(devices) {
        w.write_record(device_row(d).iter().map(|c| csv_safe(c).into_owned()))?;
    }
    w.flush()?;
    Ok(())
}

/// Pretty-printed JSON array of the full device model (camelCase, same as the GUI sees).
pub fn write_json<W: Write>(devices: &[Device], mut writer: W) -> Result<()> {
    serde_json::to_writer_pretty(&mut writer, &sorted(devices))?;
    writer.write_all(b"\n")?;
    Ok(())
}

/// Excel workbook: bold frozen header, autofilter, fixed column widths, numeric VLAN column.
/// Cells are written as strings, so formula injection does not apply.
fn build_xlsx(devices: &[Device]) -> Result<Workbook> {
    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    ws.set_name("Devices")?;
    let header = Format::new()
        .set_bold()
        .set_font_color(Color::White)
        .set_background_color(Color::RGB(0x1F4E79))
        .set_border_bottom(FormatBorder::Thin);

    for (col, (title, width)) in COLUMNS.iter().zip(XLSX_WIDTHS).enumerate() {
        let col = u16::try_from(col)?;
        ws.write_string_with_format(0, col, *title, &header)?;
        ws.set_column_width(col, width)?;
    }
    let rows = sorted(devices);
    for (i, d) in rows.iter().enumerate() {
        let row = u32::try_from(i + 1).context("too many rows for a worksheet")?;
        for (col, value) in device_row(d).iter().enumerate() {
            let is_vlan = col == COL_VLAN;
            let col = u16::try_from(col)?;
            match (is_vlan, d.vlan_id) {
                (true, Some(v)) => ws.write_number(row, col, f64::from(v))?,
                _ if value.is_empty() => continue,
                _ => ws.write_string(row, col, value)?,
            };
        }
    }
    let last_row = u32::try_from(rows.len()).context("too many rows for a worksheet")?;
    ws.set_freeze_panes(1, 0)?;
    ws.autofilter(0, 0, last_row, u16::try_from(COLUMNS.len() - 1)?)?;
    Ok(wb)
}

/// Write an Excel workbook to `path`.
pub fn write_xlsx(devices: &[Device], path: &Path) -> Result<()> {
    build_xlsx(devices)?
        .save(path)
        .with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

/// Write `devices` to `path` in `format`.
pub fn export_to_path(devices: &[Device], format: ExportFormat, path: &Path) -> Result<()> {
    let create =
        || std::fs::File::create(path).with_context(|| format!("cannot create {}", path.display()));
    match format {
        ExportFormat::Csv => write_csv(devices, std::io::BufWriter::new(create()?)),
        ExportFormat::Json => write_json(devices, std::io::BufWriter::new(create()?)),
        ExportFormat::Xlsx => write_xlsx(devices, path),
    }
}

/// Open `path` for an export without following a symlink at the final component and only
/// if it is (or will be) a regular file. Used for paths that come from a GUI dialog.
fn open_regular_no_follow(path: &Path) -> Result<File> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            bail!(
                "refusing to write {}: it is a symbolic link",
                path.display()
            )
        }
        Ok(m) if !m.is_file() => {
            bail!("refusing to write {}: not a regular file", path.display())
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("cannot inspect {}", path.display())),
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Closes the race between the check above and the open.
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
        .with_context(|| format!("cannot create {}", path.display()))
}

/// Export to a path chosen interactively (GUI): the extension must match `format`, and
/// symbolic links or non-regular files are refused.
pub fn export_to_chosen_path(devices: &[Device], format: ExportFormat, path: &Path) -> Result<()> {
    if ExportFormat::from_path(path) != Some(format) {
        bail!(
            "file name {} does not end in .{format}",
            path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        );
    }
    let mut file = io::BufWriter::new(open_regular_no_follow(path)?);
    match format {
        ExportFormat::Csv => write_csv(devices, &mut file)?,
        ExportFormat::Json => write_json(devices, &mut file)?,
        ExportFormat::Xlsx => {
            let bytes = build_xlsx(devices)?
                .save_to_buffer()
                .context("cannot build the workbook")?;
            file.write_all(&bytes)?;
        }
    }
    file.flush()
        .with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

/// Terminal table of `devices` (sorted). Columns that are empty for every device are omitted,
/// except IP, MAC, VLAN and Role.
pub fn render_table(devices: &[Device]) -> String {
    let rows: Vec<[String; NUM_COLUMNS]> = sorted(devices).into_iter().map(device_row).collect();
    let shown: Vec<usize> = (0..COLUMNS.len())
        .filter(|c| ALWAYS_SHOWN.contains(c) || rows.iter().any(|r| !r[*c].is_empty()))
        .collect();
    let mut table = Table::new();
    table
        .load_style(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(shown.iter().map(|c| COLUMNS[*c]));
    for r in &rows {
        table.add_row(shown.iter().map(|c| {
            if r[*c].is_empty() && *c == COL_VLAN {
                "-"
            } else {
                r[*c].as_str()
            }
        }));
    }
    table.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DeviceRole, DiscoverySource};

    fn devices() -> Vec<Device> {
        let mut a = Device::new("10.0.0.20".parse().unwrap());
        a.mac = Some("00:11:22:33:44:55".into());
        a.extra_ips = vec!["fe80::1".parse().unwrap(), "2001:db8::20".parse().unwrap()];
        a.add_source(DiscoverySource::Arp);
        let mut b = Device::new("10.0.0.3".parse().unwrap());
        b.role = DeviceRole::Switch;
        b.open_ports = vec![22, 443];
        b.comments = Some("core, \"stack\"".into());
        let mut c = Device::new("10.10.0.1".parse().unwrap());
        c.vlan_id = Some(10);
        vec![a, b, c]
    }

    #[test]
    fn csv_has_header_and_sorted_rows() {
        let mut out = Vec::new();
        write_csv(&devices(), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            "IP,Other IPs,MAC,VLAN,Role,Hostname,Vendor,Switch/Port,DNS,mDNS,SMB Name,SMB Domain,TCP Ports,Comments"
        );
        assert_eq!(
            lines[1],
            "10.0.0.3,,,,Switch,,,,,,,,\"22, 443\",\"core, \"\"stack\"\"\""
        );
        assert_eq!(
            lines[2],
            "10.0.0.20,\"fe80::1, 2001:db8::20\",00:11:22:33:44:55,,Host,,,,,,,,,"
        );
        assert!(lines[3].starts_with("10.10.0.1,,,10,Host"));
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn csv_neutralizes_formulas() {
        // (Leading tab / CR / spaces are already turned into trimmed spaces by device_row.)
        for evil in [
            "=HYPERLINK(\"http://x\")",
            "+1+1",
            "-2+3",
            "@SUM(A1)",
            " \t=1",
        ] {
            let mut d = Device::new("10.0.0.1".parse().unwrap());
            d.hostname = Some(evil.to_string());
            d.comments = Some(evil.to_string());
            let mut out = Vec::new();
            write_csv(&[d], &mut out).unwrap();
            let mut r = csv::Reader::from_reader(out.as_slice());
            let row = r.records().next().unwrap().unwrap();
            let hostname = &row[5];
            assert!(hostname.starts_with('\''), "{evil:?} -> {hostname:?}");
            assert!(row[13].starts_with('\''));
        }
        assert_eq!(csv_safe("plain"), "plain");
        assert_eq!(csv_safe(""), "");
        assert_eq!(csv_safe("=1"), "'=1");
        assert_eq!(csv_safe("\tx"), "'\tx");
        assert_eq!(csv_safe("\rx"), "'\rx");
    }

    #[test]
    fn exports_strip_terminal_escapes() {
        let mut d = Device::new("10.0.0.1".parse().unwrap());
        d.hostname = Some("\u{1b}]0;pwned\u{7}\u{1b}[2Jhost".into());
        let row = device_row(&d);
        assert_eq!(row[5], "]0;pwned[2Jhost");
        assert!(!render_table(&[d]).contains('\u{1b}'));
    }

    #[test]
    fn json_round_trips() {
        let mut out = Vec::new();
        write_json(&devices(), &mut out).unwrap();
        let parsed: Vec<Device> = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].ip.to_string(), "10.0.0.3");
        assert_eq!(parsed[2].vlan_id, Some(10));
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v[1]["sources"][0], "arp");
        assert!(v[0].get("openPorts").is_some());
    }

    #[test]
    fn xlsx_is_written() {
        let dir = std::env::temp_dir().join(format!("sweepr-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("devices.xlsx");
        export_to_path(&devices(), ExportFormat::from_path(&path).unwrap(), &path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[..2], b"PK"); // zip container
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn chosen_path_export_is_guarded() {
        let dir = std::env::temp_dir().join(format!("sweepr-chosen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let xlsx = dir.join("out.xlsx");
        export_to_chosen_path(&devices(), ExportFormat::Xlsx, &xlsx).unwrap();
        assert_eq!(&std::fs::read(&xlsx).unwrap()[..2], b"PK");
        let csv_path = dir.join("out.csv");
        export_to_chosen_path(&devices(), ExportFormat::Csv, &csv_path).unwrap();
        assert!(std::fs::read_to_string(&csv_path)
            .unwrap()
            .starts_with("IP,"));
        // Extension must match the format.
        assert!(export_to_chosen_path(&devices(), ExportFormat::Json, &csv_path).is_err());
        // Directories and symlinks are refused; the symlink target is left untouched.
        assert!(export_to_chosen_path(&devices(), ExportFormat::Csv, &dir.join("sub.csv")).is_ok());
        std::fs::create_dir_all(dir.join("d.csv")).unwrap();
        assert!(export_to_chosen_path(&devices(), ExportFormat::Csv, &dir.join("d.csv")).is_err());
        #[cfg(unix)]
        {
            let target = dir.join("victim.txt");
            std::fs::write(&target, b"keep").unwrap();
            let link = dir.join("link.csv");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let err = export_to_chosen_path(&devices(), ExportFormat::Csv, &link).unwrap_err();
            assert!(err.to_string().contains("symbolic link"));
            assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn table_omits_empty_columns() {
        let t = render_table(&devices());
        assert!(t.contains("TCP Ports") && t.contains("Comments"));
        assert!(!t.contains("mDNS") && !t.contains("Vendor"));
        assert!(t.contains("10.10.0.1"));
        assert!(t.contains("Other IPs") && t.contains("2001:db8::20"));
        let mut plain = devices();
        plain[0].extra_ips.clear();
        assert!(!render_table(&plain).contains("Other IPs"));
    }

    #[test]
    fn format_parsing() {
        assert_eq!("XLSX".parse::<ExportFormat>().unwrap(), ExportFormat::Xlsx);
        assert!("pdf".parse::<ExportFormat>().is_err());
        assert_eq!(
            ExportFormat::from_path(Path::new("/tmp/a.csv")),
            Some(ExportFormat::Csv)
        );
    }
}
