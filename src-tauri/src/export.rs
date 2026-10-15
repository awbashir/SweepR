//! Device list export (CSV, JSON, XLSX) and CLI table rendering.

use std::{fmt, io::Write, path::Path, str::FromStr};

use anyhow::{bail, Context, Result};
use comfy_table::{presets::UTF8_FULL_CONDENSED, ContentArrangement, Table};
use rust_xlsxwriter::{Color, Format, FormatBorder, Workbook};
use serde::{Deserialize, Serialize};

use crate::models::Device;

/// Column headers shared by every tabular export.
pub const COLUMNS: [&str; 13] = [
    "IP",
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

/// Columns always shown by [`render_table`], even when empty.
const ALWAYS_SHOWN: [usize; 4] = [0, 1, 2, 3];

/// Excel column widths (characters), aligned with [`COLUMNS`].
const XLSX_WIDTHS: [f64; 13] = [
    16.0, 19.0, 7.0, 13.0, 22.0, 24.0, 28.0, 30.0, 26.0, 18.0, 16.0, 20.0, 36.0,
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

/// One export row, aligned with [`COLUMNS`].
pub fn device_row(d: &Device) -> [String; 13] {
    let opt = |s: &Option<String>| s.clone().unwrap_or_default();
    [
        d.ip.to_string(),
        opt(&d.mac),
        d.vlan_id.map(|v| v.to_string()).unwrap_or_default(),
        d.role.label().to_string(),
        opt(&d.hostname),
        opt(&d.vendor),
        d.switch_port
            .as_ref()
            .map(|p| p.label())
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

/// CSV with a header row; devices sorted by VLAN, then IP.
pub fn write_csv<W: Write>(devices: &[Device], writer: W) -> Result<()> {
    let mut w = csv::Writer::from_writer(writer);
    w.write_record(COLUMNS)?;
    for d in sorted(devices) {
        w.write_record(device_row(d))?;
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
pub fn write_xlsx(devices: &[Device], path: &Path) -> Result<()> {
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
            let col = u16::try_from(col)?;
            match (col, d.vlan_id) {
                (2, Some(v)) => ws.write_number(row, col, f64::from(v))?,
                _ if value.is_empty() => continue,
                _ => ws.write_string(row, col, value)?,
            };
        }
    }
    let last_row = u32::try_from(rows.len()).context("too many rows for a worksheet")?;
    ws.set_freeze_panes(1, 0)?;
    ws.autofilter(0, 0, last_row, u16::try_from(COLUMNS.len() - 1)?)?;
    wb.save(path)
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

/// Terminal table of `devices` (sorted). Columns that are empty for every device are omitted,
/// except IP, MAC, VLAN and Role.
pub fn render_table(devices: &[Device]) -> String {
    let rows: Vec<[String; 13]> = sorted(devices).into_iter().map(device_row).collect();
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
            if r[*c].is_empty() && *c == 2 {
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
            "IP,MAC,VLAN,Role,Hostname,Vendor,Switch/Port,DNS,mDNS,SMB Name,SMB Domain,TCP Ports,Comments"
        );
        assert_eq!(
            lines[1],
            "10.0.0.3,,,Switch,,,,,,,,\"22, 443\",\"core, \"\"stack\"\"\""
        );
        assert_eq!(lines[2], "10.0.0.20,00:11:22:33:44:55,,Host,,,,,,,,,");
        assert!(lines[3].starts_with("10.10.0.1,,10,Host"));
        assert_eq!(lines.len(), 4);
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
    fn table_omits_empty_columns() {
        let t = render_table(&devices());
        assert!(t.contains("TCP Ports") && t.contains("Comments"));
        assert!(!t.contains("mDNS") && !t.contains("Vendor"));
        assert!(t.contains("10.10.0.1"));
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
