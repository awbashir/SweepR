//! Branded audit report: aggregates scan data ([`ReportStats`]), runs the audit rules
//! ([`crate::audit`]) and renders a self-contained interactive HTML page
//! ([`crate::report_html`]), a PDF executive summary ([`crate::report_pdf`]) or a JSON
//! document that can be fed back into `sweepr report`.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt,
    fs::{File, OpenOptions},
    io::{self, Write},
    path::Path,
    str::FromStr,
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    audit::{
        self, compact_ports, is_uplink_name, port_mac_table, run_audit, AuditInput, AuditResult,
        AuditThresholds, Ctx, ReportMeta, SnmpMeta,
    },
    models::{
        now_ms, CdpLldpNeighbor, Device, DeviceRole, ScanConfig, ScanEvent, SnmpVersion,
        SwitchPortMapping, VlanInfo, VlanSelection,
    },
};

/// Largest logo accepted (`--logo`).
pub const MAX_LOGO_BYTES: usize = 1024 * 1024;
/// Most port mappings the CLI collector keeps (same cap as the engine's aggregate).
const MAX_COLLECTED_MAPPINGS: usize = crate::engine::MAX_AGGREGATE_MAPPINGS;
/// Default report title.
pub const DEFAULT_TITLE: &str = "SweepR Network Audit Report";

/// How the data behind the report was collected (appendix).
pub const METHODOLOGY: &[&str] = &[
    "Discovery: broadcast ARP on the local subnet, 802.1Q-tagged ARP for the requested VLANs, \
     ICMP echo for routed ranges and ICMPv6 / NDP for IPv6, from the scanning host's interface.",
    "Identification: IEEE OUI vendor lookup, DNS PTR, mDNS and NetBIOS names, CDP/LLDP \
     advertisements and a TCP connect scan of the listed ports.",
    "Infrastructure: SNMP polling of likely network devices (system MIB, VLAN tables, \
     bridge / CAM MAC-to-port tables) when SNMP credentials were supplied.",
    "Audit: the collected data is evaluated offline by SweepR's rule set; each rule has a \
     stable ID, a severity, affected devices, evidence and remediation advice.",
    "Port utilization counts ports that learned at least one MAC address in the switch's \
     forwarding table at poll time; ports learning more MACs than the uplink threshold, \
     aggregate interfaces and ports leading to other switches, routers or firewalls are \
     treated as uplinks / trunks.",
];

/// What the report cannot tell (appendix).
pub const LIMITATIONS: &[&str] = &[
    "The scan reflects one point in time from one vantage point; hosts that were offline, \
     filtered ICMP/ARP or sat behind firewalls may be missing.",
    "Services are only detected on the TCP ports that were scanned; UDP services (TFTP, \
     SNMP agents not polled, SIP over UDP) are only covered where other data exists.",
    "Findings are based on observed network behaviour, not on device configuration. Verify \
     each finding before changing production equipment.",
    "MAC-to-port tables age out (typically after 5 minutes); idle devices may not appear in \
     port utilization. Total port counts marked as estimated are derived from port names.",
    "Rules marked 'not evaluated' could not run because the scan did not collect the data \
     they need; absence of a finding there is not evidence of compliance.",
    "Reference text cites CWE identifiers and CIS Controls v8 safeguards for orientation; \
     it is not a formal compliance assessment.",
];

// ---------------------------------------------------------------------------------------------
// Format & options
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    Html,
    Pdf,
    Json,
}

impl ReportFormat {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Pdf => "pdf",
            Self::Json => "json",
        }
    }

    /// Guess the format from a file extension (`.htm` counts as HTML).
    pub fn from_path(path: &Path) -> Option<Self> {
        path.extension()?.to_str()?.parse().ok()
    }
}

impl FromStr for ReportFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "html" | "htm" => Ok(Self::Html),
            "pdf" => Ok(Self::Pdf),
            "json" => Ok(Self::Json),
            other => bail!("unsupported report format '{other}' (expected html, pdf or json)"),
        }
    }
}

impl fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.extension())
    }
}

/// An image embedded in the report header (validated PNG or JPEG).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logo {
    pub bytes: Vec<u8>,
    pub mime: &'static str,
}

impl Logo {
    /// Accept PNG or JPEG data (checked by magic bytes) up to [`MAX_LOGO_BYTES`].
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > MAX_LOGO_BYTES {
            bail!("logo is larger than {} KiB", MAX_LOGO_BYTES / 1024);
        }
        let mime = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            "image/png"
        } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
            "image/jpeg"
        } else {
            bail!("logo must be a PNG or JPEG image");
        };
        Ok(Logo { bytes, mime })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let meta =
            std::fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
        if meta.len() > MAX_LOGO_BYTES as u64 {
            bail!("logo is larger than {} KiB", MAX_LOGO_BYTES / 1024);
        }
        Self::from_bytes(
            std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?,
        )
    }
}

#[derive(Debug, Clone)]
pub struct ReportOptions {
    pub title: String,
    pub org: Option<String>,
    pub logo: Option<Logo>,
    /// Reference time (report date, certificate expiry).
    pub now_ms: u64,
    pub thresholds: AuditThresholds,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            title: DEFAULT_TITLE.into(),
            org: None,
            logo: None,
            now_ms: now_ms(),
            thresholds: AuditThresholds::default(),
        }
    }
}

impl ReportOptions {
    /// Sanitize user-supplied title / organization (they end up in HTML and PDF).
    pub fn new(title: Option<&str>, org: Option<&str>) -> Self {
        let clean = |s: &str| {
            let s = crate::models::sanitize_text(s);
            (!s.is_empty()).then_some(s)
        };
        Self {
            title: title
                .and_then(clean)
                .unwrap_or_else(|| DEFAULT_TITLE.into()),
            org: org.and_then(clean),
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NameCount {
    pub name: String,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleCount {
    pub role: DeviceRole,
    pub label: String,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VlanBucket {
    pub vlan: Option<u16>,
    pub label: String,
    pub name: Option<String>,
    pub hosts: usize,
    pub infrastructure: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceCount {
    pub port: u16,
    pub service: String,
    pub hosts: usize,
    /// Cleartext / legacy protocol.
    pub risky: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortRow {
    pub port: String,
    pub macs: u32,
    pub vlans: Vec<u16>,
    pub trunk: bool,
    /// An access point was learned on this port (its MAC count includes wireless clients).
    pub access_point: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SwitchUtil {
    pub name: String,
    pub ip: Option<String>,
    pub model: Option<String>,
    /// MAC-to-port data available (SNMP).
    pub has_data: bool,
    /// Ports that learned at least one MAC.
    pub active_ports: usize,
    pub total_ports: Option<u32>,
    /// `total_ports` is estimated from the highest port number seen.
    pub total_estimated: bool,
    pub access_ports: usize,
    pub trunk_ports: Vec<PortRow>,
    pub busiest: Vec<PortRow>,
    pub mac_total: usize,
    pub endpoints: usize,
    pub vlans: Vec<u16>,
    pub partial: bool,
    pub warnings: Vec<String>,
}

impl SwitchUtil {
    /// Fraction of ports in use, when the port count is known or estimated.
    pub fn utilization(&self) -> Option<f64> {
        self.total_ports
            .filter(|t| *t > 0)
            .map(|t| (self.active_ports as f64 / f64::from(t)).min(1.0))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportStats {
    pub total_hosts: usize,
    pub infrastructure: usize,
    pub roles: Vec<RoleCount>,
    pub vlan_count: usize,
    pub hosts_per_vlan: Vec<VlanBucket>,
    pub top_vendors: Vec<NameCount>,
    pub unknown_vendor: usize,
    pub services: Vec<ServiceCount>,
    pub switches: Vec<SwitchUtil>,
    pub neighbors: usize,
    pub ipv6_hosts: usize,
    pub port_scanned_hosts: usize,
    /// Optional per-device data present in the input (`tlsCert`, `latency`, ...).
    pub extra_fields: Vec<String>,
}

/// Well-known service name for a TCP port.
pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        69 => "TFTP",
        80 => "HTTP",
        88 => "Kerberos",
        110 => "POP3",
        111 => "RPC",
        135 => "MS-RPC",
        139 => "NetBIOS-SSN",
        143 => "IMAP",
        161 => "SNMP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        465 | 587 => "SMTP-sub",
        512 => "rexec",
        513 => "rlogin",
        514 => "rsh",
        515 => "LPD",
        548 => "AFP",
        554 => "RTSP",
        631 => "IPP",
        636 => "LDAPS",
        873 => "rsync",
        993 => "IMAPS",
        1433 => "MSSQL",
        1521 => "Oracle",
        1883 => "MQTT",
        2049 => "NFS",
        3306 => "MySQL",
        3389 => "RDP",
        5060 | 5061 => "SIP",
        5432 => "PostgreSQL",
        5800 | 5900..=5903 => "VNC",
        5985 | 5986 => "WinRM",
        6379 => "Redis",
        8000 | 8008 | 8080 | 8081 | 8888 => "HTTP-alt",
        8291 => "Winbox",
        8443 | 4443 | 10443 => "HTTPS-alt",
        9100 => "JetDirect",
        27017 => "MongoDB",
        _ => return None,
    })
}

fn is_risky_port(port: u16) -> bool {
    matches!(
        port,
        21 | 23 | 69 | 139 | 512..=514 | 3389 | 5800 | 5900..=5903 | 161
    )
}

/// Estimate a switch's port count from access-port names: per module / stack member prefix
/// (`Gi2/0/`), the highest port number rounded up to a common size (`Gi1/0/45` -> 48), summed.
fn estimate_port_count<'a>(names: impl Iterator<Item = &'a str>) -> Option<u32> {
    let mut per_prefix: BTreeMap<String, u32> = BTreeMap::new();
    for name in names.filter(|n| !is_uplink_name(n)) {
        if let Some(n) = trailing_port_number(name) {
            let prefix = name
                .trim_end_matches(|c: char| c.is_ascii_digit())
                .to_string();
            let e = per_prefix.entry(prefix).or_default();
            *e = (*e).max(n);
        }
    }
    let total: u32 = per_prefix
        .values()
        .map(|n| {
            [8, 12, 16, 24, 28, 48, 52, 96]
                .into_iter()
                .find(|s| s >= n)
                .unwrap_or(*n)
        })
        .sum();
    (total > 0).then_some(total)
}

/// Trailing number of a port name (`Gi1/0/24` -> 24), for port-count estimation.
fn trailing_port_number(name: &str) -> Option<u32> {
    let digits: String = name
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let n: u32 = digits.parse().ok()?;
    // Bare bridge-port numbers (`10101`) or ifIndexes say nothing about the port count.
    (n <= 96 && name.len() > digits.len()).then_some(n)
}

impl ReportStats {
    pub fn compute(input: &AuditInput, t: &AuditThresholds) -> Self {
        let ctx = Ctx::new(input, t, 0);
        let devices = &input.devices;

        let mut roles: BTreeMap<u8, (DeviceRole, usize)> = BTreeMap::new();
        for d in devices {
            roles.entry(5 - d.role.priority()).or_insert((d.role, 0)).1 += 1;
        }
        let roles: Vec<RoleCount> = roles
            .into_values()
            .map(|(role, count)| RoleCount {
                role,
                label: role.label().into(),
                count,
            })
            .collect();

        // Hosts per VLAN (effective VLAN; untagged last).
        let vlan_names: HashMap<u16, String> = input
            .vlans
            .iter()
            .chain(input.snmp_infos.iter().flat_map(|s| s.vlans.iter()))
            .filter_map(|v| v.name.clone().map(|n| (v.id, n)))
            .collect();
        let mut per_vlan: BTreeMap<(bool, u16), (usize, usize)> = BTreeMap::new();
        for d in devices {
            let v = ctx.effective_vlan(d);
            let e = per_vlan.entry((v.is_none(), v.unwrap_or(0))).or_default();
            e.0 += 1;
            if d.role.is_infrastructure() {
                e.1 += 1;
            }
        }
        let hosts_per_vlan: Vec<VlanBucket> = per_vlan
            .into_iter()
            .map(|((untagged, id), (hosts, infra))| {
                let vlan = (!untagged).then_some(id);
                VlanBucket {
                    vlan,
                    label: vlan.map_or_else(|| "Untagged".into(), |v| format!("VLAN {v}")),
                    name: vlan.and_then(|v| vlan_names.get(&v).cloned()),
                    hosts,
                    infrastructure: infra,
                }
            })
            .collect();
        let mut all_vlans: BTreeSet<u16> = hosts_per_vlan.iter().filter_map(|b| b.vlan).collect();
        all_vlans.extend(input.vlans.iter().map(|v| v.id));
        all_vlans.extend(
            input
                .snmp_infos
                .iter()
                .flat_map(|s| s.vlans.iter().map(|v| v.id)),
        );

        // Vendors.
        let mut vendors: HashMap<String, usize> = HashMap::new();
        let mut unknown_vendor = 0;
        for d in devices {
            match &d.vendor {
                Some(v) => *vendors.entry(short_vendor(v)).or_default() += 1,
                None => unknown_vendor += 1,
            }
        }
        let mut top_vendors: Vec<NameCount> = vendors
            .into_iter()
            .map(|(name, count)| NameCount { name, count })
            .collect();
        top_vendors.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
        if top_vendors.len() > 10 {
            let other: usize = top_vendors[9..].iter().map(|n| n.count).sum();
            top_vendors.truncate(9);
            top_vendors.push(NameCount {
                name: "Other vendors".into(),
                count: other,
            });
        }

        // Services.
        let mut ports: BTreeMap<u16, usize> = BTreeMap::new();
        for d in devices {
            for p in &d.open_ports {
                *ports.entry(*p).or_default() += 1;
            }
        }
        let mut services: Vec<ServiceCount> = ports
            .into_iter()
            .map(|(port, hosts)| ServiceCount {
                port,
                service: service_name(port).unwrap_or("").to_string(),
                hosts,
                risky: is_risky_port(port),
            })
            .collect();
        services.sort_by(|a, b| b.hosts.cmp(&a.hosts).then(a.port.cmp(&b.port)));
        services.truncate(20);

        let mut extra_fields: BTreeSet<String> = BTreeSet::new();
        for d in devices {
            extra_fields.extend(d.extra.keys().take(64).cloned());
        }

        ReportStats {
            total_hosts: devices.len(),
            infrastructure: devices
                .iter()
                .filter(|d| d.role.is_infrastructure())
                .count(),
            roles,
            vlan_count: all_vlans.len(),
            hosts_per_vlan,
            top_vendors,
            unknown_vendor,
            services,
            switches: switch_utilization(input, t),
            neighbors: input.neighbors.len(),
            ipv6_hosts: devices
                .iter()
                .filter(|d| d.ip.contains(':') || d.extra_ips.iter().any(|ip| ip.contains(':')))
                .count(),
            port_scanned_hosts: devices.iter().filter(|d| !d.open_ports.is_empty()).count(),
            extra_fields: extra_fields.into_iter().take(32).collect(),
        }
    }
}

/// `Cisco Systems, Inc` -> `Cisco Systems`; keeps charts readable.
fn short_vendor(v: &str) -> String {
    let mut s = v.trim();
    for suffix in [
        ", Inc.",
        ", Inc",
        " Inc.",
        " Inc",
        ", Ltd.",
        " Co.,Ltd.",
        " Co., Ltd.",
        " Co.,Ltd",
        " Ltd.",
        " Ltd",
        " LLC",
        " GmbH",
        " Corporation",
        " Corp.",
        " Corp",
        " AG",
        " S.A.",
        " B.V.",
    ] {
        if let Some(stripped) = s.strip_suffix(suffix) {
            s = stripped.trim_end_matches(',').trim();
        }
    }
    s.chars().take(40).collect()
}

fn switch_utilization(input: &AuditInput, t: &AuditThresholds) -> Vec<SwitchUtil> {
    let table = port_mac_table(input);
    // MACs whose port leads to other infrastructure (uplinks).
    let infra_macs: BTreeSet<&str> = input
        .devices
        .iter()
        .filter(|d| {
            matches!(
                d.role,
                DeviceRole::Switch | DeviceRole::Router | DeviceRole::Firewall
            )
        })
        .filter_map(|d| d.mac.as_deref())
        .collect();
    let ap_macs: BTreeSet<&str> = input
        .devices
        .iter()
        .filter(|d| d.role == DeviceRole::AccessPoint)
        .filter_map(|d| d.mac.as_deref())
        .collect();
    let endpoint_count: HashMap<&str, usize> =
        input.devices.iter().fold(HashMap::new(), |mut m, d| {
            if let Some(p) = &d.switch_port {
                *m.entry(p.switch_name.as_str()).or_default() += 1;
            }
            m
        });

    let mut by_switch: BTreeMap<String, Vec<(String, &audit::PortStat)>> = BTreeMap::new();
    for ((sw, port), stat) in &table {
        by_switch
            .entry(sw.clone())
            .or_default()
            .push((port.clone(), stat));
    }
    let mut out = Vec::new();
    let mut seen_ips: BTreeSet<String> = BTreeSet::new();
    for (name, ports) in by_switch {
        let info = input
            .snmp_infos
            .iter()
            .find(|s| s.name() == name || s.sys_name.as_deref() == Some(&name));
        let ip = ports
            .iter()
            .find_map(|(_, s)| s.switch_ip.clone())
            .or_else(|| info.and_then(|i| i.ip.clone()));
        if let Some(ip) = &ip {
            seen_ips.insert(ip.clone());
        }
        let mut rows: Vec<PortRow> = ports
            .iter()
            .map(|(port, stat)| PortRow {
                port: port.clone(),
                macs: stat.mac_count(),
                vlans: stat.vlans.iter().copied().collect(),
                access_point: stat.macs.iter().any(|m| ap_macs.contains(m.as_str())),
                trunk: stat.mac_count() > t.uplink_mac_threshold
                    || is_uplink_name(port)
                    || stat.macs.iter().any(|m| infra_macs.contains(m.as_str())),
            })
            .collect();
        let active_ports = rows.iter().filter(|r| r.macs > 0).count();
        let active_trunks = rows.iter().filter(|r| r.macs > 0 && r.trunk).count();
        // Distinct MACs; SNMP-only counts (no mappings kept) fall back to the sum.
        let distinct = ports
            .iter()
            .flat_map(|(_, s)| s.macs.iter())
            .collect::<HashSet<_>>()
            .len();
        let mac_total = if distinct > 0 {
            distinct
        } else {
            rows.iter().map(|r| r.macs as usize).sum()
        };
        let (total_ports, total_estimated) = match info.and_then(|i| i.total_ports) {
            Some(n) => (Some(n), false),
            None => {
                let est =
                    estimate_port_count(rows.iter().filter(|r| !r.trunk).map(|r| r.port.as_str()));
                (est.filter(|e| *e as usize >= active_ports), est.is_some())
            }
        };
        rows.sort_by(|a, b| b.macs.cmp(&a.macs).then_with(|| a.port.cmp(&b.port)));
        let trunk_ports: Vec<PortRow> = rows.iter().filter(|r| r.trunk).cloned().collect();
        let access_ports = active_ports - active_trunks;
        let mut vlans: BTreeSet<u16> = rows.iter().flat_map(|r| r.vlans.iter().copied()).collect();
        if let Some(i) = info {
            vlans.extend(i.vlans.iter().map(|v| v.id));
        }
        out.push(SwitchUtil {
            model: info.and_then(|i| i.sys_descr.as_deref().map(first_line)),
            ip,
            has_data: true,
            active_ports,
            total_ports,
            total_estimated: total_ports.is_some() && total_estimated,
            access_ports,
            busiest: rows
                .iter()
                .filter(|r| !r.trunk && r.macs > 1)
                .take(5)
                .cloned()
                .collect(),
            trunk_ports,
            mac_total,
            endpoints: endpoint_count.get(name.as_str()).copied().unwrap_or(0),
            vlans: vlans.into_iter().collect(),
            partial: info.is_some_and(|i| i.partial),
            warnings: info.map(|i| i.warnings.clone()).unwrap_or_default(),
            name,
        });
    }
    // Switches known from discovery but without SNMP data: shown as "not available".
    for d in input
        .devices
        .iter()
        .filter(|d| d.role == DeviceRole::Switch)
    {
        if seen_ips.contains(&d.ip) {
            continue;
        }
        let name = d.name().unwrap_or(&d.ip).to_string();
        if out.iter().any(|s| s.name == name) {
            continue;
        }
        out.push(SwitchUtil {
            name,
            ip: Some(d.ip.clone()),
            model: d
                .neighbor
                .as_ref()
                .and_then(|n| n.platform.clone())
                .or_else(|| d.vendor.clone()),
            has_data: false,
            active_ports: 0,
            total_ports: None,
            total_estimated: false,
            access_ports: 0,
            trunk_ports: Vec::new(),
            busiest: Vec::new(),
            mac_total: 0,
            endpoints: 0,
            vlans: Vec::new(),
            partial: false,
            warnings: Vec::new(),
        });
    }
    out
}

fn first_line(s: &str) -> String {
    let line = s.split([',', '\n']).next().unwrap_or(s).trim();
    line.chars().take(80).collect()
}

// ---------------------------------------------------------------------------------------------
// Report assembly
// ---------------------------------------------------------------------------------------------

/// Everything a renderer needs.
pub struct Report<'a> {
    pub input: &'a AuditInput,
    pub audit: AuditResult,
    pub stats: ReportStats,
    pub opts: &'a ReportOptions,
}

impl<'a> Report<'a> {
    pub fn build(input: &'a AuditInput, opts: &'a ReportOptions) -> Self {
        Report {
            audit: run_audit(input, &opts.thresholds, opts.now_ms),
            stats: ReportStats::compute(input, &opts.thresholds),
            input,
            opts,
        }
    }

    /// Short plain-text executive summary used by the HTML and PDF renderers.
    pub fn narrative(&self) -> Vec<String> {
        let s = &self.stats;
        let c = &self.audit.score.counts;
        let mut out = vec![format!(
            "SweepR discovered {} device{} ({} network infrastructure) across {} VLAN{}{}.",
            s.total_hosts,
            plural(s.total_hosts),
            s.infrastructure,
            s.vlan_count,
            plural(s.vlan_count),
            if s.neighbors > 0 {
                format!(
                    " and captured {} CDP/LLDP neighbor advertisement{}",
                    s.neighbors,
                    plural(s.neighbors)
                )
            } else {
                String::new()
            }
        )];
        let total = c.total();
        if total == 0 {
            out.push("The audit rules raised no findings on the data collected.".into());
        } else {
            out.push(format!(
                "The audit raised {total} finding{}: {} critical, {} high, {} medium, {} low and {} informational. \
                 Overall grade {} (score {}/100){}.",
                plural(total),
                c.critical,
                c.high,
                c.medium,
                c.low,
                c.info,
                self.audit.score.grade,
                self.audit.score.score,
                self.audit
                    .score
                    .capped_by
                    .as_deref()
                    .map(|w| format!(", capped because a {w}"))
                    .unwrap_or_default()
            ));
            let top: Vec<String> = self
                .audit
                .findings
                .iter()
                .filter(|f| f.severity >= audit::Severity::Medium)
                .take(3)
                .map(|f| format!("{} ({} affected)", f.title, f.affected_count))
                .collect();
            if !top.is_empty() {
                out.push(format!("Address first: {}.", top.join("; ")));
            }
        }
        let skipped = self.audit.checks.iter().filter(|c| !c.evaluated).count();
        if skipped > 0 {
            out.push(format!(
                "{skipped} of {} checks could not be evaluated because the scan did not collect the data they need (see Rule coverage).",
                self.audit.checks.len()
            ));
        }
        out
    }

    /// The JSON document (`--format json`): metadata, score, findings, statistics and the
    /// normalized input, so it can be fed back into `sweepr report`.
    pub fn to_json(&self) -> Value {
        json!({
            "format": "sweepr-audit",
            "version": 1,
            "generatedMs": self.opts.now_ms,
            "title": self.opts.title,
            "org": self.opts.org,
            "meta": self.input.meta,
            "score": self.audit.score,
            "findings": self.audit.findings,
            "checks": self.audit.checks,
            "thresholds": self.audit.thresholds,
            "stats": self.stats,
            "skippedRecords": self.input.skipped_records,
            "devices": self.input.devices,
            "vlans": self.input.vlans,
            "neighbors": self.input.neighbors,
            "portMappings": self.input.port_mappings,
            "snmpInfos": self.input.snmp_infos,
        })
    }
}

pub fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// Render `input` as `format`.
pub fn render(input: &AuditInput, opts: &ReportOptions, format: ReportFormat) -> Result<Vec<u8>> {
    let report = Report::build(input, opts);
    Ok(match format {
        ReportFormat::Html => crate::report_html::render_html(&report).into_bytes(),
        ReportFormat::Pdf => crate::report_pdf::render_pdf(&report)?,
        ReportFormat::Json => {
            let mut v = serde_json::to_vec_pretty(&report.to_json())?;
            v.push(b'\n');
            v
        }
    })
}

/// Read report input from a JSON file (`sweepr scan -o json`, `sweepr report --format json`
/// or `sweepr scan --report x.json`). Files over 512 MiB are refused.
pub fn load_input(path: &Path) -> Result<AuditInput> {
    let meta =
        std::fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    if meta.len() > 512 * 1024 * 1024 {
        bail!("{} is too large for a report input", path.display());
    }
    let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let value: Value = serde_json::from_reader(io::BufReader::new(file))
        .with_context(|| format!("{} is not valid JSON", path.display()))?;
    AuditInput::from_json_value(value)
}

// ---------------------------------------------------------------------------------------------
// Scan metadata & collection (CLI `scan --report`, GUI)
// ---------------------------------------------------------------------------------------------

/// Report metadata for a scan run with `cfg`. SNMP secrets are reduced to a classification.
pub fn meta_from_config(
    cfg: &ScanConfig,
    interface: Option<String>,
    started_ms: u64,
    finished_ms: u64,
    cancelled: bool,
) -> ReportMeta {
    let meta = ReportMeta {
        tool_version: Some(format!("SweepR {}", env!("CARGO_PKG_VERSION"))),
        interface: interface.or_else(|| cfg.interface.clone()),
        ranges: cfg
            .range
            .as_deref()
            .map(|r| r.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default(),
        vlans: Some(match &cfg.vlans {
            VlanSelection::Untagged => "untagged".into(),
            VlanSelection::AutoDetect => "auto".into(),
            VlanSelection::List(ids) => compact_ports(ids),
            VlanSelection::UntaggedAndList(ids) => format!("untagged,{}", compact_ports(ids)),
        }),
        port_spec: Some(compact_ports(&cfg.ports)),
        started_ms: Some(started_ms),
        finished_ms: Some(finished_ms),
        cancelled,
        ipv6: Some(cfg.ipv6),
        cdp_lldp: Some(cfg.cdp_lldp),
        discover_vlans: Some(cfg.discover_vlans),
        resolve_names: Some(cfg.resolve_names),
        snmp_all: Some(cfg.snmp_all),
        snmp: cfg.snmp.as_ref().map(|s| SnmpMeta {
            version: Some(
                match s.version {
                    SnmpVersion::V1 => "v1",
                    SnmpVersion::V2c => "v2c",
                    SnmpVersion::V3 => "v3",
                }
                .into(),
            ),
            community: (s.version != SnmpVersion::V3).then(|| s.community.clone()),
            community_kind: None,
        }),
        scanner_host: None,
        ..Default::default()
    };
    // Normalizes and redacts (the community never leaves this function).
    let mut input = AuditInput {
        meta,
        ..Default::default()
    };
    input.normalize();
    input.meta
}

/// Collects scan events for `sweepr scan --report`.
#[derive(Default)]
pub struct ScanCollector {
    devices: HashMap<String, Device>,
    vlans: BTreeMap<u16, VlanInfo>,
    neighbors: HashMap<String, CdpLldpNeighbor>,
    mappings: Vec<SwitchPortMapping>,
    mapping_keys: HashSet<(String, String, String, Option<u16>)>,
}

impl ScanCollector {
    pub fn observe(&mut self, ev: &ScanEvent) {
        match ev {
            ScanEvent::Device(d) => {
                self.devices.insert(d.key(), (**d).clone());
            }
            ScanEvent::Vlan(v) => {
                self.vlans.insert(v.id, v.clone());
            }
            ScanEvent::Neighbor(n) => {
                self.neighbors.insert(n.key(), n.clone());
            }
            ScanEvent::PortMapping(pm)
                if self.mappings.len() < MAX_COLLECTED_MAPPINGS
                    && self.mapping_keys.insert((
                        pm.switch_name.clone(),
                        pm.port_name.clone(),
                        pm.mac.clone(),
                        pm.vlan_id,
                    )) =>
            {
                self.mappings.push(pm.clone());
            }
            _ => {}
        }
    }

    /// Build the report input. `devices` (if given) replaces the collected device list, e.g.
    /// with the CLI's final, override-applied snapshot.
    pub fn finish(self, devices: Option<Vec<Device>>, meta: ReportMeta) -> Result<AuditInput> {
        let devices = devices.unwrap_or_else(|| self.devices.into_values().collect());
        let mut neighbors: Vec<CdpLldpNeighbor> = self.neighbors.into_values().collect();
        neighbors.sort_by_key(CdpLldpNeighbor::key);
        let v = json!({
            "devices": devices,
            "vlans": self.vlans.into_values().collect::<Vec<_>>(),
            "neighbors": neighbors,
            "portMappings": self.mappings,
            "meta": meta,
        });
        AuditInput::from_json_value(v)
    }
}

// ---------------------------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------------------------

/// Open `path` for writing without following a symlink at the final component and only if
/// it is (or will be) a regular file. Used for paths chosen in the GUI dialog.
fn open_regular_no_follow(path: &Path) -> Result<File> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            bail!(
                "refusing to write {}: it is a symbolic link",
                path.display()
            )
        }
        Ok(m) if !m.is_file() => bail!("refusing to write {}: not a regular file", path.display()),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("cannot inspect {}", path.display())),
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
        .with_context(|| format!("cannot create {}", path.display()))
}

/// Final path for a save-dialog choice: a missing extension is added (refusing to replace an
/// existing file the dialog never asked about); any other extension must match `format`.
pub fn resolve_chosen_path(
    chosen: std::path::PathBuf,
    format: ReportFormat,
) -> std::result::Result<std::path::PathBuf, String> {
    if chosen.extension().is_some() {
        return match ReportFormat::from_path(&chosen) {
            Some(f) if f == format => Ok(chosen),
            _ => Err(format!(
                "the file name must end in .{format} for a {format} report"
            )),
        };
    }
    let mut path = chosen.into_os_string();
    path.push(format!(".{format}"));
    let path = std::path::PathBuf::from(path);
    if std::fs::symlink_metadata(&path).is_ok() {
        return Err(format!(
            "{} already exists; choose it explicitly to replace it",
            path.display()
        ));
    }
    Ok(path)
}

/// Write a rendered report to a path chosen interactively (GUI): the extension must match
/// `format`; symbolic links and non-regular files are refused.
pub fn write_to_chosen_path(bytes: &[u8], format: ReportFormat, path: &Path) -> Result<()> {
    if ReportFormat::from_path(path) != Some(format) {
        bail!(
            "file name {} does not end in .{format}",
            path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        );
    }
    let mut file = io::BufWriter::new(open_regular_no_follow(path)?);
    file.write_all(bytes)?;
    file.flush()
        .with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::tests::{dev, input, NOW};
    use crate::models::{ScanSummary, SnmpConfig};

    fn opts() -> ReportOptions {
        ReportOptions {
            now_ms: NOW,
            ..ReportOptions::new(Some("Q3 audit"), Some("Acme <Corp>"))
        }
    }

    fn sample() -> AuditInput {
        let mut maps = Vec::new();
        for i in 1..=10u8 {
            maps.push(json!({ "switchName": "core-sw", "switchIp": "10.0.0.2", "portName": format!("Gi1/0/{i}"), "vlanId": 10, "mac": format!("00:11:22:33:44:{i:02x}") }));
        }
        for i in 0..60u8 {
            maps.push(json!({ "switchName": "core-sw", "switchIp": "10.0.0.2", "portName": "Gi1/0/48", "vlanId": 10, "mac": format!("00:11:22:55:00:{i:02x}") }));
        }
        input(json!({
            "meta": { "interface": "en0", "ranges": ["10.0.0.0/24"], "portSpec": "22,23,80,443,445" },
            "devices": [
                dev("10.0.0.1", "00:11:22:00:00:01", "firewall", &[443]),
                dev("10.0.0.2", "00:11:22:00:00:02", "switch", &[22, 23, 80]),
                dev("10.0.0.3", "00:11:22:00:00:03", "switch", &[22]),
                { "ip": "10.0.0.10", "mac": "00:11:22:33:44:01", "vlanId": 10, "vendor": "Dell Inc.", "openPorts": [445] },
            ],
            "portMappings": maps,
            "snmpInfos": [{ "ip": "10.0.0.2", "sysName": "core-sw", "sysDescr": "Cisco IOS Software, C2960X", "role": "switch",
                            "vlans": [{ "id": 10, "name": "users", "sources": ["snmp"] }] }]
        }))
    }

    #[test]
    fn stats_cover_vlans_roles_vendors_services_and_ports() {
        let i = sample();
        let s = ReportStats::compute(&i, &AuditThresholds::default());
        assert_eq!(s.total_hosts, 4);
        assert_eq!(s.infrastructure, 3);
        assert_eq!(s.roles[0].role, DeviceRole::Firewall);
        assert_eq!(s.hosts_per_vlan.last().unwrap().label, "Untagged");
        assert_eq!(s.hosts_per_vlan[0].name.as_deref(), Some("users"));
        assert!(s.top_vendors.iter().any(|v| v.name == "Dell"));
        assert_eq!(s.services[0].port, 22);
        let sw = &s.switches[0];
        assert_eq!(sw.name, "core-sw");
        assert_eq!(sw.active_ports, 11);
        assert_eq!(sw.total_ports, Some(12));
        assert!(sw.total_estimated);
        assert_eq!(sw.trunk_ports.len(), 1);
        assert_eq!(sw.trunk_ports[0].port, "Gi1/0/48");
        assert_eq!(sw.access_ports, 10);
        // The second switch has no SNMP data: shown as not available.
        let other = s
            .switches
            .iter()
            .find(|s| s.ip.as_deref() == Some("10.0.0.3"))
            .unwrap();
        assert!(!other.has_data);
        assert!(other.utilization().is_none());
        assert_eq!(trailing_port_number("Gi1/0/24"), Some(24));
        assert_eq!(
            estimate_port_count(["Gi1/0/3", "Gi1/0/45", "Gi2/0/30", "Po1"].into_iter()),
            Some(96)
        );
        assert_eq!(trailing_port_number("10101"), None);
        assert_eq!(short_vendor("Cisco Systems, Inc"), "Cisco Systems");
    }

    #[test]
    fn json_report_round_trips_into_input() {
        let i = sample();
        let bytes = render(&i, &opts(), ReportFormat::Json).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["format"], "sweepr-audit");
        assert!(v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "SWR-SVC-001"));
        let again = AuditInput::from_json_value(v).unwrap();
        assert_eq!(again.devices, i.devices);
        assert_eq!(again.port_mappings.len(), i.port_mappings.len());
        assert_eq!(again.meta, i.meta);
    }

    #[test]
    fn meta_from_config_redacts_community() {
        let cfg = ScanConfig {
            range: Some("10.0.0.0/24, 10.1.0.0/24".into()),
            vlans: VlanSelection::UntaggedAndList(vec![10, 11, 12, 99]),
            snmp: Some(SnmpConfig::v2c("Sup3rS3cret")),
            ports: vec![22, 23, 80],
            ..Default::default()
        };
        let m = meta_from_config(&cfg, Some("en0".into()), 1, 2, false);
        assert_eq!(m.ranges, vec!["10.0.0.0/24", "10.1.0.0/24"]);
        assert_eq!(m.vlans.as_deref(), Some("untagged,10-12,99"));
        assert_eq!(m.port_spec.as_deref(), Some("22-23,80"));
        assert_eq!(
            m.snmp.as_ref().unwrap().community_kind.as_deref(),
            Some("custom")
        );
        assert!(!serde_json::to_string(&m).unwrap().contains("Sup3rS3cret"));
        let cfg = ScanConfig {
            snmp: Some(SnmpConfig::v2c("public")),
            ..Default::default()
        };
        let m = meta_from_config(&cfg, None, 1, 2, false);
        assert_eq!(m.snmp.unwrap().community_kind.as_deref(), Some("public"));
    }

    #[test]
    fn collector_builds_input_from_events() {
        let mut c = ScanCollector::default();
        let mut d = Device::new("10.0.0.5".parse().unwrap());
        d.mac = Some("00:11:22:33:44:55".into());
        c.observe(&ScanEvent::device(d));
        let pm = SwitchPortMapping {
            switch_name: "sw".into(),
            switch_ip: None,
            port_name: "Gi1".into(),
            port_index: None,
            vlan_id: None,
            mac: "00:11:22:33:44:55".into(),
        };
        c.observe(&ScanEvent::PortMapping(pm.clone()));
        c.observe(&ScanEvent::PortMapping(pm));
        c.observe(&ScanEvent::Finished(ScanSummary {
            devices: 1,
            vlans: 0,
            neighbors: 0,
            elapsed_ms: 1,
            cancelled: false,
        }));
        let i = c.finish(None, ReportMeta::default()).unwrap();
        assert_eq!(i.devices.len(), 1);
        assert_eq!(i.port_mappings.len(), 1);
    }

    #[test]
    fn report_format_and_logo_validation() {
        assert_eq!("HTML".parse::<ReportFormat>().unwrap(), ReportFormat::Html);
        assert_eq!(
            ReportFormat::from_path(Path::new("a.pdf")),
            Some(ReportFormat::Pdf)
        );
        assert!("docx".parse::<ReportFormat>().is_err());
        assert!(Logo::from_bytes(b"<svg onload=alert(1)>".to_vec()).is_err());
        assert_eq!(
            Logo::from_bytes(b"\x89PNG\r\n\x1a\nxxxx".to_vec())
                .unwrap()
                .mime,
            "image/png"
        );
        assert!(Logo::from_bytes(vec![0xff; MAX_LOGO_BYTES + 1]).is_err());
    }

    #[test]
    fn chosen_path_is_guarded() {
        let dir = std::env::temp_dir().join(format!("sweepr-report-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ok = dir.join("r.html");
        write_to_chosen_path(b"<html>", ReportFormat::Html, &ok).unwrap();
        assert_eq!(
            resolve_chosen_path(ok.clone(), ReportFormat::Html).unwrap(),
            ok
        );
        assert!(resolve_chosen_path(dir.join("r.txt"), ReportFormat::Html).is_err());
        assert!(resolve_chosen_path(dir.join("r"), ReportFormat::Html).is_err()); // r.html exists
        assert_eq!(
            resolve_chosen_path(dir.join("new"), ReportFormat::Pdf).unwrap(),
            dir.join("new.pdf")
        );
        assert!(write_to_chosen_path(b"x", ReportFormat::Pdf, &ok).is_err());
        #[cfg(unix)]
        {
            let link = dir.join("link.html");
            std::os::unix::fs::symlink(&ok, &link).unwrap();
            assert!(write_to_chosen_path(b"x", ReportFormat::Html, &link).is_err());
            assert_eq!(std::fs::read(&ok).unwrap(), b"<html>");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn options_sanitize_title_and_org() {
        let o = ReportOptions::new(Some("  \u{1b}[31mTitle\n"), Some(""));
        assert_eq!(o.title, "[31mTitle");
        assert_eq!(o.org, None);
        assert_eq!(ReportOptions::new(None, None).title, DEFAULT_TITLE);
    }
}
