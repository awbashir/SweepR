//! Network audit: a lenient report input model and a rules engine that turns scan data into
//! security / hygiene [`Finding`]s with an overall risk score and grade.
//!
//! The input ([`AuditInput`]) is deliberately tolerant. Every field has a default, malformed
//! records are skipped (and counted) instead of failing the whole report, and each device
//! keeps the JSON fields this module does not model in [`AuditDevice::extra`]. Rules read
//! optional data from later scanner features (TLS certificates, voice VLANs, DHCP / IPv6 router
//! observations, ...) through that side channel, so the audit picks them up when present and
//! reports the rule as "not evaluated" when they are absent.
//!
//! Every string that came from the network is passed through [`sanitize_text`] when the input
//! is normalized; renderers must still escape it for their output format.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
};

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::models::{normalize_mac, parse_mac, parse_ports, sanitize_text, DeviceRole};

/// Most affected entries kept per finding (the true count is in `affected_count`).
pub const MAX_AFFECTED: usize = 500;
/// Most records of one kind accepted from an input file (bounds memory and report size).
pub const MAX_INPUT_RECORDS: usize = 250_000;

// ---------------------------------------------------------------------------------------------
// Input model
// ---------------------------------------------------------------------------------------------

/// Map any role string onto [`DeviceRole`]; unknown values become `Host`.
fn de_role<'de, D: Deserializer<'de>>(d: D) -> Result<DeviceRole, D::Error> {
    let v = Value::deserialize(d)?;
    Ok(serde_json::from_value(v).unwrap_or_default())
}

/// One discovered device. Mirrors `models::Device` (camelCase) with every field optional;
/// unknown fields land in `extra`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AuditDevice {
    pub ip: String,
    pub extra_ips: Vec<String>,
    pub mac: Option<String>,
    pub vlan_id: Option<u16>,
    #[serde(deserialize_with = "de_role")]
    pub role: DeviceRole,
    pub hostname: Option<String>,
    pub dns_name: Option<String>,
    pub mdns_name: Option<String>,
    pub smb_name: Option<String>,
    pub smb_domain: Option<String>,
    pub vendor: Option<String>,
    pub switch_port: Option<AuditPortMapping>,
    pub open_ports: Vec<u16>,
    pub comments: Option<String>,
    pub interface: Option<String>,
    pub rtt_ms: Option<f64>,
    pub sources: Vec<String>,
    pub neighbor: Option<AuditNeighbor>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    /// Fields not modelled here (added by later scanner features), kept verbatim.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AuditPortMapping {
    pub switch_name: String,
    pub switch_ip: Option<String>,
    pub port_name: String,
    pub port_index: Option<u32>,
    pub vlan_id: Option<u16>,
    pub mac: String,
}

impl AuditPortMapping {
    pub fn label(&self) -> String {
        format!("{} [{}]", self.switch_name, self.port_name)
    }

    fn normalize(&mut self) {
        self.switch_name = sanitize_text(&self.switch_name);
        self.port_name = sanitize_text(&self.port_name);
        self.switch_ip = clean_ip_opt(self.switch_ip.take());
        self.mac = normalize_mac(&self.mac).unwrap_or_else(|| sanitize_text(&self.mac));
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AuditNeighbor {
    pub protocol: String,
    pub local_interface: String,
    pub source_mac: String,
    pub device_id: String,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub port_id: Option<String>,
    pub port_description: Option<String>,
    pub platform: Option<String>,
    pub software_version: Option<String>,
    pub management_addrs: Vec<String>,
    pub native_vlan: Option<u16>,
    pub voice_vlan: Option<u16>,
    pub capabilities: Vec<String>,
    pub vtp_domain: Option<String>,
    pub last_seen_ms: u64,
}

impl AuditNeighbor {
    pub fn display_name(&self) -> &str {
        self.system_name
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.device_id)
    }

    fn has_cap(&self, cap: &str) -> bool {
        self.capabilities
            .iter()
            .any(|c| c.eq_ignore_ascii_case(cap))
    }

    /// Network gear (switch, router, firewall, access point) rather than an endpoint.
    pub fn is_infrastructure(&self) -> bool {
        ["switch", "router", "firewall", "wlan_access_point"]
            .iter()
            .any(|c| self.has_cap(c))
    }

    pub fn is_phone(&self) -> bool {
        self.has_cap("telephone")
            || self.device_id.starts_with("SEP")
            || contains_ci(self.platform.as_deref().unwrap_or(""), "phone")
    }

    fn normalize(&mut self) {
        self.protocol = sanitize_text(&self.protocol).to_ascii_lowercase();
        self.local_interface = sanitize_text(&self.local_interface);
        self.source_mac =
            normalize_mac(&self.source_mac).unwrap_or_else(|| sanitize_text(&self.source_mac));
        self.device_id = sanitize_text(&self.device_id);
        for s in [
            &mut self.system_name,
            &mut self.system_description,
            &mut self.port_id,
            &mut self.port_description,
            &mut self.platform,
            &mut self.software_version,
            &mut self.vtp_domain,
        ] {
            clean_opt(s);
        }
        self.management_addrs = clean_ips(std::mem::take(&mut self.management_addrs));
        self.capabilities = self
            .capabilities
            .iter()
            .map(|c| sanitize_text(c).to_ascii_lowercase())
            .collect();
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AuditVlan {
    pub id: u16,
    pub name: Option<String>,
    pub sources: Vec<String>,
    pub interface: Option<String>,
    pub switch_name: Option<String>,
    pub frames_seen: u64,
}

impl AuditVlan {
    fn normalize(&mut self) {
        clean_opt(&mut self.name);
        clean_opt(&mut self.interface);
        clean_opt(&mut self.switch_name);
        self.sources = self.sources.iter().map(|s| sanitize_text(s)).collect();
    }

    /// Defined in a switch configuration (SNMP / VTP), not merely seen as a tag on the wire.
    pub fn is_configured(&self) -> bool {
        self.sources.iter().any(|s| s == "snmp" || s == "vtp")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AuditPortMacCount {
    pub port_name: String,
    pub port_index: Option<u32>,
    pub mac_count: u32,
}

/// One SNMP poll result (`SnmpDeviceInfo`) plus the agent's address.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AuditSnmpInfo {
    pub ip: Option<String>,
    pub sys_name: Option<String>,
    pub sys_descr: Option<String>,
    pub sys_uptime_ticks: Option<u64>,
    pub sys_object_id: Option<String>,
    #[serde(deserialize_with = "de_role")]
    pub role: DeviceRole,
    pub vlans: Vec<AuditVlan>,
    pub port_mappings: Vec<AuditPortMapping>,
    pub port_mac_counts: Vec<AuditPortMacCount>,
    pub partial: bool,
    pub warnings: Vec<String>,
    /// Optional total physical port count (e.g. from a future ifTable walk).
    pub total_ports: Option<u32>,
}

impl AuditSnmpInfo {
    pub fn name(&self) -> String {
        self.sys_name
            .clone()
            .or_else(|| self.ip.clone())
            .unwrap_or_else(|| "SNMP agent".into())
    }

    fn normalize(&mut self) {
        self.ip = clean_ip_opt(self.ip.take());
        for s in [
            &mut self.sys_name,
            &mut self.sys_descr,
            &mut self.sys_object_id,
        ] {
            clean_opt(s);
        }
        self.vlans.iter_mut().for_each(AuditVlan::normalize);
        self.port_mappings
            .iter_mut()
            .for_each(AuditPortMapping::normalize);
        for c in &mut self.port_mac_counts {
            c.port_name = sanitize_text(&c.port_name);
        }
        self.warnings = self.warnings.iter().map(|w| sanitize_text(w)).collect();
    }
}

/// SNMP settings of the scan, with the community string reduced to a classification.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SnmpMeta {
    /// `v1`, `v2c` or `v3`.
    pub version: Option<String>,
    /// Accepted on input only so it can be classified; never serialized.
    #[serde(skip_serializing)]
    pub community: Option<String>,
    /// `public`, `private` (well-known defaults), `custom`, or `none`.
    pub community_kind: Option<String>,
}

impl SnmpMeta {
    /// Classify (and drop) the community so a report never carries a real secret.
    fn redact(&mut self) {
        if let Some(c) = self.community.take() {
            let kind = match c.trim() {
                "" => "none",
                "public" => "public",
                "private" => "private",
                _ => "custom",
            };
            self.community_kind = Some(kind.into());
        }
        clean_opt(&mut self.version);
        clean_opt(&mut self.community_kind);
        if let Some(v) = &mut self.version {
            *v = v.to_ascii_lowercase();
        }
    }

    pub fn uses_community(&self) -> bool {
        matches!(
            self.version.as_deref(),
            Some("v1" | "v2c" | "1" | "2c") | None
        )
    }
}

/// Scan metadata shown in the report header and appendix.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ReportMeta {
    pub tool_version: Option<String>,
    pub interface: Option<String>,
    pub ranges: Vec<String>,
    /// VLAN selection as typed (`10,20`, `auto`, `untagged`).
    pub vlans: Option<String>,
    /// Scanned TCP ports in compact form (`22,23,80,443,1000-2000`).
    pub port_spec: Option<String>,
    pub started_ms: Option<u64>,
    pub finished_ms: Option<u64>,
    pub cancelled: bool,
    pub ipv6: Option<bool>,
    pub cdp_lldp: Option<bool>,
    pub discover_vlans: Option<bool>,
    pub resolve_names: Option<bool>,
    pub snmp_all: Option<bool>,
    pub snmp: Option<SnmpMeta>,
    /// Default gateway of the scanning host, when known.
    pub gateway: Option<String>,
    /// DHCP servers observed answering (future passive DHCP listener).
    pub dhcp_servers: Vec<String>,
    /// Sources of IPv6 router advertisements observed.
    pub ipv6_routers: Vec<String>,
    /// Scanning host name.
    pub scanner_host: Option<String>,
}

impl ReportMeta {
    /// Ports covered by the scan, when the spec is known.
    pub fn scanned_ports(&self) -> Option<Vec<u16>> {
        self.port_spec
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .and_then(|s| parse_ports(s).ok())
    }

    fn normalize(&mut self) {
        for s in [
            &mut self.tool_version,
            &mut self.interface,
            &mut self.vlans,
            &mut self.port_spec,
            &mut self.scanner_host,
        ] {
            clean_opt(s);
        }
        self.ranges = self.ranges.iter().map(|s| sanitize_text(s)).collect();
        self.gateway = clean_ip_opt(self.gateway.take());
        self.dhcp_servers = clean_ips(std::mem::take(&mut self.dhcp_servers));
        self.ipv6_routers = clean_ips(std::mem::take(&mut self.ipv6_routers));
        if let Some(s) = &mut self.snmp {
            s.redact();
        }
    }
}

/// Compact a port list as `22,80,8000-8100`.
pub fn compact_ports(ports: &[u16]) -> String {
    let mut v: Vec<u16> = ports.to_vec();
    v.sort_unstable();
    v.dedup();
    let mut parts = Vec::new();
    let mut i = 0;
    while i < v.len() {
        let start = v[i];
        let mut end = start;
        while i + 1 < v.len() && v[i + 1] == end.saturating_add(1) {
            i += 1;
            end = v[i];
        }
        parts.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
        i += 1;
    }
    parts.join(",")
}

/// Everything the audit and the report are built from.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AuditInput {
    pub devices: Vec<AuditDevice>,
    pub vlans: Vec<AuditVlan>,
    pub neighbors: Vec<AuditNeighbor>,
    pub port_mappings: Vec<AuditPortMapping>,
    pub snmp_infos: Vec<AuditSnmpInfo>,
    pub meta: ReportMeta,
    /// Records that could not be read (wrong types, bad IP addresses) and were skipped.
    #[serde(skip_deserializing)]
    pub skipped_records: usize,
}

fn clean_opt(s: &mut Option<String>) {
    if let Some(v) = s.take() {
        let c = sanitize_text(&v);
        if !c.is_empty() {
            *s = Some(c);
        }
    }
}

fn clean_ip_opt(s: Option<String>) -> Option<String> {
    s.and_then(|v| v.trim().parse::<IpAddr>().ok())
        .map(|ip| ip.to_string())
}

fn clean_ips(v: Vec<String>) -> Vec<String> {
    v.into_iter()
        .filter_map(|s| clean_ip_opt(Some(s)))
        .collect()
}

/// Deserialize each element on its own, skipping (and counting) the ones that fail.
fn lenient_list<T: serde::de::DeserializeOwned>(v: Option<Value>, skipped: &mut usize) -> Vec<T> {
    let Some(Value::Array(items)) = v else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(items.len().min(MAX_INPUT_RECORDS));
    for item in items {
        if out.len() >= MAX_INPUT_RECORDS {
            *skipped += 1;
            continue;
        }
        match serde_json::from_value(item) {
            Ok(t) => out.push(t),
            Err(_) => *skipped += 1,
        }
    }
    out
}

impl AuditInput {
    /// Parse report input from JSON: either the full envelope
    /// (`{ devices, vlans, neighbors, portMappings, snmpInfos, meta }`, as written by
    /// `sweepr report --format json` or `sweepr scan --report x.json`) or a plain array of
    /// devices (`sweepr scan -o json`). Malformed records are skipped and counted.
    pub fn from_json_value(value: Value) -> anyhow::Result<Self> {
        let mut skipped = 0usize;
        let mut input = match value {
            Value::Array(_) => AuditInput {
                devices: lenient_list(Some(value), &mut skipped),
                ..Default::default()
            },
            Value::Object(mut obj) => {
                // `sweepr snmp -o json` output: a single SnmpDeviceInfo.
                let take = |obj: &mut Map<String, Value>, k: &str| obj.remove(k);
                let meta = match take(&mut obj, "meta") {
                    Some(m) => serde_json::from_value(m).unwrap_or_else(|_| {
                        skipped += 1;
                        ReportMeta::default()
                    }),
                    None => ReportMeta::default(),
                };
                AuditInput {
                    devices: lenient_list(take(&mut obj, "devices"), &mut skipped),
                    vlans: lenient_list(take(&mut obj, "vlans"), &mut skipped),
                    neighbors: lenient_list(take(&mut obj, "neighbors"), &mut skipped),
                    port_mappings: lenient_list(take(&mut obj, "portMappings"), &mut skipped),
                    snmp_infos: lenient_list(take(&mut obj, "snmpInfos"), &mut skipped),
                    meta,
                    skipped_records: 0,
                }
            }
            _ => anyhow::bail!("report input must be a JSON object or an array of devices"),
        };
        input.skipped_records = skipped;
        input.normalize();
        Ok(input)
    }

    /// Sanitize every string, canonicalize MACs / IPs, drop devices without a valid IP and
    /// redact secrets in the metadata. Idempotent.
    pub fn normalize(&mut self) {
        let before = self.devices.len();
        self.devices.retain_mut(|d| d.normalize());
        self.skipped_records += before - self.devices.len();
        self.vlans.iter_mut().for_each(AuditVlan::normalize);
        self.vlans.retain(|v| (1..=4094).contains(&v.id));
        self.neighbors.iter_mut().for_each(AuditNeighbor::normalize);
        self.port_mappings
            .iter_mut()
            .for_each(AuditPortMapping::normalize);
        self.snmp_infos
            .iter_mut()
            .for_each(AuditSnmpInfo::normalize);
        self.meta.normalize();
        self.devices.sort_by(|a, b| {
            (a.vlan_id, a.ip_addr())
                .cmp(&(b.vlan_id, b.ip_addr()))
                .then_with(|| a.ip.cmp(&b.ip))
        });
    }
}

impl AuditDevice {
    /// Returns `false` when the device has no usable IP address (it is then dropped).
    fn normalize(&mut self) -> bool {
        let Ok(ip) = self.ip.trim().parse::<IpAddr>() else {
            return false;
        };
        self.ip = ip.to_string();
        self.extra_ips = clean_ips(std::mem::take(&mut self.extra_ips));
        if let Some(m) = self.mac.take() {
            self.mac = normalize_mac(&m).or_else(|| {
                let s = sanitize_text(&m);
                (!s.is_empty()).then_some(s)
            });
        }
        for s in [
            &mut self.hostname,
            &mut self.dns_name,
            &mut self.mdns_name,
            &mut self.smb_name,
            &mut self.smb_domain,
            &mut self.vendor,
            &mut self.comments,
            &mut self.interface,
        ] {
            clean_opt(s);
        }
        if let Some(p) = &mut self.switch_port {
            p.normalize();
        }
        if let Some(n) = &mut self.neighbor {
            n.normalize();
        }
        self.open_ports.sort_unstable();
        self.open_ports.dedup();
        self.open_ports.retain(|p| *p != 0);
        self.sources = self.sources.iter().map(|s| sanitize_text(s)).collect();
        if self.vlan_id.is_some_and(|v| !(1..=4094).contains(&v)) {
            self.vlan_id = None;
        }
        true
    }

    pub fn ip_addr(&self) -> Option<IpAddr> {
        self.ip.parse().ok()
    }

    /// First available name: user label, DNS, mDNS, NetBIOS, CDP/LLDP system name.
    pub fn name(&self) -> Option<&str> {
        [
            &self.hostname,
            &self.dns_name,
            &self.mdns_name,
            &self.smb_name,
        ]
        .into_iter()
        .find_map(|n| n.as_deref().filter(|s| !s.is_empty()))
        .or_else(|| {
            self.neighbor
                .as_ref()
                .map(|n| n.display_name())
                .filter(|s| !s.is_empty())
        })
    }

    pub fn has_port(&self, port: u16) -> bool {
        self.open_ports.binary_search(&port).is_ok()
    }

    /// A string from `extra` (sanitized).
    pub fn extra_str(&self, key: &str) -> Option<String> {
        self.extra
            .get(key)
            .and_then(Value::as_str)
            .map(sanitize_text)
            .filter(|s| !s.is_empty())
    }

    /// A number from `extra`, accepting a nested object field via `a.b`.
    pub fn extra_f64(&self, path: &str) -> Option<f64> {
        let mut parts = path.split('.');
        let mut cur = self.extra.get(parts.next()?)?;
        for p in parts {
            cur = cur.get(p)?;
        }
        cur.as_f64()
    }

    /// TLS certificates reported for the device (`tlsCert` object or `tlsCerts` array).
    pub fn certificates(&self) -> Vec<CertView> {
        let mut out = Vec::new();
        for key in ["tlsCert", "tlsCerts", "certificates"] {
            match self.extra.get(key) {
                Some(Value::Array(a)) => out.extend(a.iter().filter_map(CertView::from_value)),
                Some(v @ Value::Object(_)) => out.extend(CertView::from_value(v)),
                _ => {}
            }
        }
        out.truncate(16);
        out
    }

    /// Voice VLAN reported for the device itself (CDP/LLDP neighbor record or `voiceVlan`).
    pub fn voice_vlan(&self) -> Option<u16> {
        self.neighbor
            .as_ref()
            .and_then(|n| n.voice_vlan)
            .or_else(|| self.extra_f64("voiceVlan").map(|v| v as u16))
    }

    /// Looks like an IP phone: SIP data, a phone vendor, or a CDP/LLDP telephone.
    pub fn is_phone(&self) -> bool {
        if self.neighbor.as_ref().is_some_and(AuditNeighbor::is_phone) {
            return true;
        }
        if self.extra.contains_key("sip") || self.extra.contains_key("sipInfo") {
            return !self
                .extra_str("sipRole")
                .is_some_and(|r| r.eq_ignore_ascii_case("pbx"));
        }
        let vendor = self.vendor.as_deref().unwrap_or("");
        PHONE_VENDORS.iter().any(|v| contains_ci(vendor, v))
    }
}

const PHONE_VENDORS: &[&str] = &[
    "yealink",
    "grandstream",
    "polycom",
    "snom",
    "avaya",
    "mitel",
    "fanvil",
    "htek",
    "aastra",
    "spectralink",
];

fn contains_ci(hay: &str, needle: &str) -> bool {
    hay.to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

/// A TLS certificate as read from the lenient device data.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertView {
    pub port: Option<u16>,
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub not_after: Option<String>,
    pub not_after_ms: Option<i64>,
    pub days_remaining: Option<i64>,
    pub self_signed: bool,
    pub expired: Option<bool>,
    pub key_type: Option<String>,
    pub key_bits: Option<u32>,
    pub signature_algorithm: Option<String>,
}

impl CertView {
    fn from_value(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let s = |k: &str| {
            o.get(k)
                .and_then(Value::as_str)
                .map(sanitize_text)
                .filter(|s| !s.is_empty())
        };
        let i = |k: &str| o.get(k).and_then(Value::as_i64);
        let not_after = s("notAfter");
        let not_after_ms = i("notAfterMs")
            .or_else(|| i("expiresMs"))
            .or_else(|| not_after.as_deref().and_then(parse_iso8601_ms));
        let subject_cn = s("subjectCn").or_else(|| s("cn"));
        let issuer_cn = s("issuerCn");
        let self_signed = o.get("selfSigned").and_then(Value::as_bool).unwrap_or_else(
            || matches!((&s("subject"), &s("issuer")), (Some(a), Some(b)) if a == b),
        );
        Some(CertView {
            port: i("port").and_then(|p| u16::try_from(p).ok()),
            subject_cn,
            issuer_cn,
            not_after,
            not_after_ms,
            days_remaining: i("daysRemaining"),
            self_signed,
            expired: o.get("expired").and_then(Value::as_bool),
            key_type: s("keyType"),
            key_bits: i("keyBits").and_then(|b| u32::try_from(b).ok()),
            signature_algorithm: s("signatureAlgorithm"),
        })
    }

    /// Days until expiry relative to `now_ms` (negative when expired).
    pub fn days_left(&self, now_ms: u64) -> Option<i64> {
        match self.not_after_ms {
            Some(ms) => Some((ms - now_ms as i64).div_euclid(86_400_000)),
            None => self.days_remaining,
        }
    }

    /// Describes why the key / signature is weak, if it is.
    pub fn weakness(&self, t: &AuditThresholds) -> Option<String> {
        let kt = self.key_type.as_deref().unwrap_or("").to_ascii_lowercase();
        let mut why = Vec::new();
        if let Some(bits) = self.key_bits {
            if (kt.contains("rsa") || kt.contains("dsa")) && bits < t.min_rsa_bits {
                why.push(format!(
                    "{bits}-bit {} key",
                    self.key_type.as_deref().unwrap_or("")
                ));
            } else if (kt.starts_with("ec") || kt.contains("ecdsa")) && bits < t.min_ec_bits {
                why.push(format!("{bits}-bit EC key"));
            }
        }
        let sig = self
            .signature_algorithm
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        if sig.contains("md5") || sig.contains("md2") {
            why.push("MD5 signature".into());
        } else if sig.contains("sha1") || sig.contains("sha-1") {
            why.push("SHA-1 signature".into());
        }
        (!why.is_empty()).then(|| why.join(", "))
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse `YYYY-MM-DD[THH:MM:SS[.fff]][Z]` (UTC) into Unix milliseconds.
pub fn parse_iso8601_ms(s: &str) -> Option<i64> {
    let s = s.trim();
    let num = |a: usize, b: usize| s.get(a..b)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    if s.get(4..5)? != "-"
        || s.get(7..8)? != "-"
        || !(1..=12).contains(&mo)
        || !(1..=31).contains(&d)
    {
        return None;
    }
    let (h, mi, se) = if s.len() >= 19 {
        (num(11, 13)?, num(14, 16)?, num(17, 19)?)
    } else {
        (0, 0, 0)
    };
    let days = days_from_civil(y, mo as u32, d as u32);
    Some(((days * 24 + h) * 60 + mi) * 60_000 + se * 1000)
}

/// Format Unix milliseconds as `YYYY-MM-DD HH:MM UTC`.
pub fn format_utc(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Inverse of days_from_civil.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60
    )
}

// ---------------------------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL_DESC: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Info",
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    /// Points per finding before the affected-count multiplier (see [`RiskScore`]).
    pub fn weight(self) -> f64 {
        match self {
            Severity::Critical => 15.0,
            Severity::High => 8.0,
            Severity::Medium => 4.0,
            Severity::Low => 1.5,
            Severity::Info => 0.0,
        }
    }
}

/// A device (or switch port) a finding applies to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Affected {
    pub ip: Option<String>,
    pub name: Option<String>,
    pub mac: Option<String>,
    pub vlan: Option<u16>,
    /// Switch port label or service port the finding refers to.
    pub port: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Stable rule id, e.g. `SWR-SVC-001`.
    pub id: String,
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub description: String,
    pub affected: Vec<Affected>,
    /// Number of affected entries before truncation to [`MAX_AFFECTED`].
    pub affected_count: usize,
    pub evidence: Vec<String>,
    pub remediation: String,
    /// Short CWE / CIS-style reference text (no links).
    pub references: Vec<String>,
    /// Points contributed to the risk score.
    pub points: f64,
}

/// Whether a rule ran and what it found.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleCheck {
    pub id: String,
    pub title: String,
    pub category: String,
    pub evaluated: bool,
    /// Why the rule could not run, or caveats about its coverage.
    pub note: Option<String>,
    pub findings: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SeverityCounts {
    pub fn get(&self, s: Severity) -> usize {
        match s {
            Severity::Critical => self.critical,
            Severity::High => self.high,
            Severity::Medium => self.medium,
            Severity::Low => self.low,
            Severity::Info => self.info,
        }
    }

    fn bump(&mut self, s: Severity) {
        match s {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
    }

    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

/// Overall risk.
///
/// Each finding contributes `weight(severity) * min(1 + log2(affected), 4)` points
/// (critical 15, high 8, medium 4, low 1.5, info 0), so breadth raises the score but one
/// noisy rule cannot dominate. `score = round(100 * exp(-points / 80))` (100 = no risk
/// found). Grades: A >= 90, B >= 80, C >= 65, D >= 50, F below. Caps: any critical
/// finding limits the grade to D, any high finding to B.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskScore {
    pub score: u8,
    pub grade: String,
    pub points: f64,
    pub counts: SeverityCounts,
    /// Set when a cap lowered the grade (e.g. "critical finding present").
    pub capped_by: Option<String>,
}

/// Human-readable statement of the scoring algorithm (shown in the report appendix).
pub const SCORING_METHOD: &str = "Each finding contributes weight x breadth points. Weights: \
critical 15, high 8, medium 4, low 1.5, informational 0. Breadth = min(1 + log2(affected \
devices), 4), so a finding on 1 device counts once and one on 8 or more devices counts at most \
four times. Score = round(100 x e^(-points/80)); 100 means no weighted risk was found. Grade: \
A >= 90, B >= 80, C >= 65, D >= 50, otherwise F. Caps: any critical finding limits the grade to \
D and any high finding limits it to B, regardless of the numeric score.";

/// Tunable thresholds for the rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AuditThresholds {
    /// Certificates expiring within this many days are flagged.
    pub cert_expiry_warn_days: i64,
    pub min_rsa_bits: u32,
    pub min_ec_bits: u32,
    /// Broad SMB exposure: at least this many hosts with TCP 445 ...
    pub smb_broad_min_hosts: usize,
    /// ... and at least this fraction of all port-scanned hosts.
    pub smb_broad_fraction: f64,
    /// VLAN 1 holding this many hosts or more is flagged.
    pub vlan1_max_hosts: usize,
    /// An access port learning at least this many MACs suggests an unmanaged switch / hub.
    pub hub_port_min_macs: u32,
    /// Ports learning more MACs than this are treated as uplinks / trunks.
    pub uplink_mac_threshold: u32,
    /// More DHCP servers than this is flagged.
    pub max_dhcp_servers: usize,
    /// More IPv6 routers (RA sources) than this is flagged.
    pub max_ipv6_routers: usize,
}

impl Default for AuditThresholds {
    fn default() -> Self {
        Self {
            cert_expiry_warn_days: 30,
            min_rsa_bits: 2048,
            min_ec_bits: 224,
            smb_broad_min_hosts: 5,
            smb_broad_fraction: 0.25,
            vlan1_max_hosts: 10,
            hub_port_min_macs: 4,
            uplink_mac_threshold: crate::engine::MAX_ACCESS_PORT_MACS as u32,
            max_dhcp_servers: 1,
            max_ipv6_routers: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditResult {
    /// Sorted by severity (highest first), then by points.
    pub findings: Vec<Finding>,
    pub checks: Vec<RuleCheck>,
    pub score: RiskScore,
    pub thresholds: AuditThresholds,
    pub evaluated_ms: u64,
}

// ---------------------------------------------------------------------------------------------
// Rule catalogue
// ---------------------------------------------------------------------------------------------

/// Static description of a rule.
pub struct RuleDef {
    pub id: &'static str,
    pub category: &'static str,
    pub title: &'static str,
    pub references: &'static [&'static str],
}

macro_rules! rules {
    ($( $konst:ident = $id:literal, $cat:literal, $title:literal, [$($r:literal),*] );+ $(;)?) => {
        $( pub const $konst: RuleDef = RuleDef { id: $id, category: $cat, title: $title, references: &[$($r),*] }; )+
        /// Every rule, in report order.
        pub const RULES: &[&RuleDef] = &[$(&$konst),+];
    };
}

rules! {
    R_TELNET = "SWR-SVC-001", "Insecure services", "Telnet service exposed",
        ["CWE-319: Cleartext Transmission of Sensitive Information", "CIS Controls v8 4.8: Uninstall or disable unnecessary services"];
    R_FTP = "SWR-SVC-002", "Insecure services", "FTP service exposed",
        ["CWE-319: Cleartext Transmission of Sensitive Information", "CIS Controls v8 4.8"];
    R_TFTP = "SWR-SVC-003", "Insecure services", "TFTP service exposed",
        ["CWE-306: Missing Authentication for Critical Function", "CIS Controls v8 4.8"];
    R_RSH = "SWR-SVC-004", "Insecure services", "Berkeley r-services (rexec/rlogin/rsh) exposed",
        ["CWE-319: Cleartext Transmission of Sensitive Information", "CWE-287: Improper Authentication"];
    R_SMB_INFRA = "SWR-SVC-005", "Insecure services", "SMB / NetBIOS on network infrastructure",
        ["CIS Controls v8 4.8", "CVE-2017-0144 class (SMBv1 remote code execution)"];
    R_NETBIOS = "SWR-SVC-006", "Insecure services", "Legacy NetBIOS session service (TCP 139) exposed",
        ["CIS Controls v8 4.8", "SMBv1-era file sharing; verify SMBv1 is disabled"];
    R_SMB_BROAD = "SWR-SVC-007", "Insecure services", "SMB file sharing exposed on many hosts",
        ["CIS Controls v8 4.4: Implement and manage a firewall on servers / end-user devices", "CIS Controls v8 13.4"];
    R_RDP = "SWR-SVC-008", "Remote access", "RDP exposed",
        ["CWE-307: Improper Restriction of Excessive Authentication Attempts", "CIS Controls v8 12.7"];
    R_VNC = "SWR-SVC-009", "Remote access", "VNC exposed",
        ["CWE-319: Cleartext Transmission of Sensitive Information", "CWE-521: Weak Password Requirements"];
    R_HTTP_MGMT = "SWR-MGT-001", "Management plane", "Infrastructure managed over HTTP only",
        ["CWE-319: Cleartext Transmission of Sensitive Information", "CIS Controls v8 12.3: Securely manage network infrastructure"];
    R_SSH_TELNET = "SWR-MGT-002", "Management plane", "SSH enabled but Telnet not disabled",
        ["CWE-757: Selection of Less-Secure Algorithm During Negotiation", "CIS Controls v8 12.3"];
    R_SNMP_DEFAULT = "SWR-SNP-001", "SNMP", "SNMP answers a default community string",
        ["CWE-1392: Use of Default Credentials", "CIS Controls v8 4.7: Manage default accounts"];
    R_SNMP_V12 = "SWR-SNP-002", "SNMP", "SNMPv1/v2c in use instead of SNMPv3",
        ["CWE-319: Cleartext Transmission of Sensitive Information", "CIS Controls v8 12.3"];
    R_SNMP_PARTIAL = "SWR-SNP-003", "SNMP", "Incomplete SNMP data",
        [];
    R_TLS_EXPIRED = "SWR-TLS-001", "TLS certificates", "Expired TLS certificate",
        ["CWE-324: Use of a Key Past its Expiration Date"];
    R_TLS_EXPIRING = "SWR-TLS-002", "TLS certificates", "TLS certificate expiring soon",
        ["CWE-324: Use of a Key Past its Expiration Date"];
    R_TLS_SELF = "SWR-TLS-003", "TLS certificates", "Self-signed TLS certificate",
        ["CWE-295: Improper Certificate Validation (trains users to accept warnings)"];
    R_TLS_WEAK = "SWR-TLS-004", "TLS certificates", "Weak certificate key or signature",
        ["CWE-326: Inadequate Encryption Strength", "CWE-328: Use of Weak Hash"];
    R_UNKNOWN = "SWR-INV-001", "Asset inventory", "Unidentified devices",
        ["CIS Controls v8 1.1: Establish and maintain a detailed enterprise asset inventory", "CIS Controls v8 1.2: Address unauthorized assets"];
    R_RANDOM_MAC = "SWR-INV-002", "Asset inventory", "Locally administered / randomized MAC addresses",
        ["CIS Controls v8 1.1"];
    R_DUP_IP = "SWR-L2-001", "Layer 2 integrity", "Duplicate IP address (different MACs)",
        ["CWE-291: Reliance on IP Address for Authentication", "Possible ARP spoofing or address conflict"];
    R_MAC_MULTI = "SWR-L2-002", "Layer 2 integrity", "One MAC address answering for several IPs",
        ["Possible ARP spoofing / proxy-ARP", "CIS Controls v8 12.2"];
    R_ROGUE_DHCP = "SWR-L2-003", "Layer 2 integrity", "Multiple DHCP servers observed",
        ["CWE-923: Improper Restriction of Communication Channel to Intended Endpoints", "Mitigation: DHCP snooping"];
    R_ROGUE_RA = "SWR-L2-004", "Layer 2 integrity", "Multiple IPv6 routers advertising (possible rogue RA)",
        ["RFC 6105: IPv6 Router Advertisement Guard", "CWE-923"];
    R_CDP_ACCESS = "SWR-L2-005", "Layer 2 integrity", "CDP/LLDP advertised on user-facing ports",
        ["CWE-200: Exposure of Sensitive Information to an Unauthorized Actor", "CIS Controls v8 4.8"];
    R_NATIVE_VLAN1 = "SWR-VLN-001", "VLAN hygiene", "VLAN 1 used as native / access VLAN",
        ["CIS Controls v8 12.2: Establish and maintain a secure network architecture", "VLAN hopping (double tagging) mitigation"];
    R_NATIVE_MISMATCH = "SWR-VLN-002", "VLAN hygiene", "Native VLAN mismatch between neighbors",
        ["CIS Controls v8 12.2"];
    R_VOICE_VLAN = "SWR-VLN-003", "VLAN hygiene", "IP phones without a voice VLAN",
        ["CIS Controls v8 12.2", "Network segmentation for voice traffic"];
    R_VLAN1_HOSTS = "SWR-VLN-004", "VLAN hygiene", "Many hosts in the default VLAN 1",
        ["CIS Controls v8 12.2"];
    R_UNUSED_VLAN = "SWR-VLN-005", "VLAN hygiene", "VLANs defined on switches with no hosts",
        ["CIS Controls v8 4.2: Establish and maintain a secure configuration process for network infrastructure"];
    R_HUB_PORT = "SWR-PRT-001", "Switch ports", "Several MACs on an access port (unmanaged switch or hub?)",
        ["CIS Controls v8 1.2: Address unauthorized assets", "Mitigation: port security / 802.1X"];
}

// ---------------------------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------------------------

/// Precomputed indexes shared by the rules.
pub struct Ctx<'a> {
    pub input: &'a AuditInput,
    pub t: &'a AuditThresholds,
    pub now_ms: u64,
    /// Ports covered by the TCP scan (`None` when unknown).
    pub scanned_ports: Option<Vec<u16>>,
    /// Any device has open-port data.
    pub has_port_data: bool,
    /// IPs of SNMP agents that answered (from snmp infos and port mappings).
    pub snmp_agents: BTreeSet<String>,
    /// Native VLAN of the scanning host's access port per local interface (from CDP/LLDP).
    pub native_vlan_by_iface: HashMap<String, u16>,
    /// The MAC addresses of infrastructure devices.
    pub infra_macs: BTreeSet<String>,
}

impl<'a> Ctx<'a> {
    pub fn new(input: &'a AuditInput, t: &'a AuditThresholds, now_ms: u64) -> Self {
        let mut snmp_agents: BTreeSet<String> = input
            .snmp_infos
            .iter()
            .filter_map(|s| s.ip.clone())
            .collect();
        snmp_agents.extend(
            input
                .port_mappings
                .iter()
                .filter_map(|p| p.switch_ip.clone()),
        );
        for d in &input.devices {
            if let Some(ip) = d.switch_port.as_ref().and_then(|p| p.switch_ip.clone()) {
                snmp_agents.insert(ip);
            }
        }
        let mut natives: HashMap<String, BTreeSet<u16>> = HashMap::new();
        for n in &input.neighbors {
            if let Some(v) = n.native_vlan.filter(|_| n.is_infrastructure()) {
                natives
                    .entry(n.local_interface.clone())
                    .or_default()
                    .insert(v);
            }
        }
        let native_vlan_by_iface = natives
            .into_iter()
            .filter(|(_, s)| s.len() == 1)
            .filter_map(|(k, s)| s.into_iter().next().map(|v| (k, v)))
            .collect();
        Ctx {
            input,
            t,
            now_ms,
            scanned_ports: input.meta.scanned_ports(),
            has_port_data: input.devices.iter().any(|d| !d.open_ports.is_empty()),
            snmp_agents,
            native_vlan_by_iface,
            infra_macs: input
                .devices
                .iter()
                .filter(|d| d.role.is_infrastructure())
                .filter_map(|d| d.mac.clone())
                .collect(),
        }
    }

    /// The VLAN a device sits in: its tag, else the native VLAN advertised to the scanner on
    /// the interface it was found on (when exactly one is known).
    pub fn effective_vlan(&self, d: &AuditDevice) -> Option<u16> {
        d.vlan_id.or_else(|| match d.interface.as_deref() {
            Some(i) => self.native_vlan_by_iface.get(i).copied(),
            None if self.native_vlan_by_iface.len() == 1 => {
                self.native_vlan_by_iface.values().next().copied()
            }
            None => None,
        })
    }

    /// `Some(note)` when `ports` were not part of the scan (so absence proves nothing).
    fn port_coverage(&self, ports: &[u16]) -> Result<(), String> {
        if !self.has_port_data && self.scanned_ports.is_none() {
            return Err("no TCP port data in the input".into());
        }
        if let Some(scanned) = &self.scanned_ports {
            if !ports.iter().any(|p| scanned.binary_search(p).is_ok()) {
                return Err(format!(
                    "port {} was not in the scanned port list",
                    ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join("/")
                ));
            }
        }
        Ok(())
    }
}

pub fn affected_device(d: &AuditDevice, ctx: &Ctx, detail: Option<String>) -> Affected {
    Affected {
        ip: Some(d.ip.clone()),
        name: d.name().map(str::to_string),
        mac: d.mac.clone(),
        vlan: ctx.effective_vlan(d),
        port: d.switch_port.as_ref().map(AuditPortMapping::label),
        detail,
    }
}

/// Builder used by the rules.
struct Draft {
    rule: &'static RuleDef,
    severity: Severity,
    title: Option<String>,
    description: String,
    affected: Vec<Affected>,
    evidence: Vec<String>,
    remediation: String,
}

impl Draft {
    fn new(rule: &'static RuleDef, severity: Severity, description: impl Into<String>) -> Self {
        Draft {
            rule,
            severity,
            title: None,
            description: description.into(),
            affected: Vec::new(),
            evidence: Vec::new(),
            remediation: String::new(),
        }
    }

    fn fix(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = remediation.into();
        self
    }

    fn evidence(mut self, e: impl Into<String>) -> Self {
        self.evidence.push(e.into());
        self
    }

    fn affected(mut self, a: Vec<Affected>) -> Self {
        self.affected = a;
        self
    }

    fn finish(self) -> Finding {
        let count = self.affected.len();
        let breadth = (1.0 + (count.max(1) as f64).log2()).min(4.0);
        let mut affected = self.affected;
        affected.truncate(MAX_AFFECTED);
        Finding {
            id: self.rule.id.to_string(),
            severity: self.severity,
            category: self.rule.category.to_string(),
            title: self.title.unwrap_or_else(|| self.rule.title.to_string()),
            description: self.description,
            affected,
            affected_count: count,
            evidence: self.evidence,
            remediation: self.remediation,
            references: self.rule.references.iter().map(|s| s.to_string()).collect(),
            points: (self.severity.weight() * breadth * 100.0).round() / 100.0,
        }
    }
}

type RuleOutcome = Result<Vec<Finding>, String>;
type RuleFn = fn(&Ctx) -> RuleOutcome;

/// Run every rule over `input`. `now_ms` is the reference time for certificate expiry.
pub fn run_audit(input: &AuditInput, t: &AuditThresholds, now_ms: u64) -> AuditResult {
    let ctx = Ctx::new(input, t, now_ms);
    let rules: [(&RuleDef, RuleFn); 31] = [
        (&R_TELNET, rule_telnet),
        (&R_FTP, rule_ftp),
        (&R_TFTP, rule_tftp),
        (&R_RSH, rule_rsh),
        (&R_SMB_INFRA, rule_smb_infra),
        (&R_NETBIOS, rule_netbios),
        (&R_SMB_BROAD, rule_smb_broad),
        (&R_RDP, rule_rdp),
        (&R_VNC, rule_vnc),
        (&R_HTTP_MGMT, rule_http_mgmt),
        (&R_SSH_TELNET, rule_ssh_telnet),
        (&R_SNMP_DEFAULT, rule_snmp_default),
        (&R_SNMP_V12, rule_snmp_v12),
        (&R_SNMP_PARTIAL, rule_snmp_partial),
        (&R_TLS_EXPIRED, rule_tls_expired),
        (&R_TLS_EXPIRING, rule_tls_expiring),
        (&R_TLS_SELF, rule_tls_self),
        (&R_TLS_WEAK, rule_tls_weak),
        (&R_UNKNOWN, rule_unknown),
        (&R_RANDOM_MAC, rule_random_mac),
        (&R_DUP_IP, rule_dup_ip),
        (&R_MAC_MULTI, rule_mac_multi),
        (&R_ROGUE_DHCP, rule_rogue_dhcp),
        (&R_ROGUE_RA, rule_rogue_ra),
        (&R_CDP_ACCESS, rule_cdp_access),
        (&R_NATIVE_VLAN1, rule_native_vlan1),
        (&R_NATIVE_MISMATCH, rule_native_mismatch),
        (&R_VOICE_VLAN, rule_voice_vlan),
        (&R_VLAN1_HOSTS, rule_vlan1_hosts),
        (&R_UNUSED_VLAN, rule_unused_vlan),
        (&R_HUB_PORT, rule_hub_port),
    ];
    debug_assert_eq!(rules.len(), RULES.len());
    let mut findings = Vec::new();
    let mut checks = Vec::new();
    for (def, f) in rules {
        let (evaluated, note, found) = match f(&ctx) {
            Ok(found) => (true, None, found),
            Err(note) => (false, Some(note), Vec::new()),
        };
        checks.push(RuleCheck {
            id: def.id.into(),
            title: def.title.into(),
            category: def.category.into(),
            evaluated,
            note,
            findings: found.len(),
        });
        findings.extend(found);
    }
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.points.total_cmp(&a.points))
            .then_with(|| a.id.cmp(&b.id))
    });
    let score = score_findings(&findings);
    AuditResult {
        findings,
        checks,
        score,
        thresholds: t.clone(),
        evaluated_ms: now_ms,
    }
}

/// Apply the documented scoring algorithm ([`SCORING_METHOD`]).
pub fn score_findings(findings: &[Finding]) -> RiskScore {
    let mut counts = SeverityCounts::default();
    let mut points = 0.0;
    for f in findings {
        counts.bump(f.severity);
        points += f.points;
    }
    let score = (100.0 * (-points / 80.0).exp()).round().clamp(0.0, 100.0) as u8;
    let numeric = match score {
        90..=100 => 'A',
        80..=89 => 'B',
        65..=79 => 'C',
        50..=64 => 'D',
        _ => 'F',
    };
    let (cap, why) = if counts.critical > 0 {
        ('D', "critical finding present")
    } else if counts.high > 0 {
        ('B', "high-severity finding present")
    } else {
        ('A', "")
    };
    // Letters sort A < B < ...: the worse grade is the larger letter.
    let grade = numeric.max(cap);
    RiskScore {
        score,
        grade: grade.to_string(),
        points: (points * 100.0).round() / 100.0,
        counts,
        capped_by: (grade != numeric).then(|| why.to_string()),
    }
}

// --- service exposure ------------------------------------------------------------------------

fn port_rule(
    ctx: &Ctx,
    def: &'static RuleDef,
    ports: &[u16],
    severity: impl Fn(&AuditDevice) -> Severity,
    describe: &str,
    fix: &str,
) -> RuleOutcome {
    ctx.port_coverage(ports)?;
    let mut by_sev: BTreeMap<Severity, Vec<Affected>> = BTreeMap::new();
    for d in &ctx.input.devices {
        let open: Vec<String> = ports
            .iter()
            .filter(|p| d.has_port(**p))
            .map(|p| format!("TCP {p}"))
            .collect();
        if !open.is_empty() {
            by_sev.entry(severity(d)).or_default().push(affected_device(
                d,
                ctx,
                Some(open.join(", ")),
            ));
        }
    }
    Ok(by_sev
        .into_iter()
        .rev()
        .map(|(sev, affected)| {
            let n = affected.len();
            Draft::new(def, sev, describe)
                .evidence(format!(
                    "{n} device(s) accept TCP connections on port {}",
                    ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join("/")
                ))
                .affected(affected)
                .fix(fix)
                .finish()
        })
        .collect())
}

fn rule_telnet(ctx: &Ctx) -> RuleOutcome {
    port_rule(
        ctx,
        &R_TELNET,
        &[23],
        |_| Severity::High,
        "Telnet sends credentials and session data in cleartext. Anyone on the path can capture \
         administrator passwords and hijack sessions.",
        "Disable Telnet (Cisco: `transport input ssh` on all VTY lines; other vendors: disable \
         the telnet service) and use SSHv2 with strong authentication. Restrict management to \
         a dedicated management VLAN or jump host.",
    )
}

fn rule_ftp(ctx: &Ctx) -> RuleOutcome {
    port_rule(
        ctx,
        &R_FTP,
        &[21],
        |_| Severity::Medium,
        "FTP transfers credentials and files in cleartext and is often left enabled on \
         printers, NAS and network gear for firmware uploads.",
        "Disable FTP where it is not needed; replace it with SFTP / FTPS or HTTPS uploads. If \
         it must stay, restrict it to known hosts and disable anonymous login.",
    )
}

fn rule_tftp(ctx: &Ctx) -> RuleOutcome {
    let has_udp = ctx
        .input
        .devices
        .iter()
        .any(|d| d.extra.contains_key("udpPorts"));
    let tcp69 = ctx.input.devices.iter().any(|d| d.has_port(69));
    if !has_udp && !tcp69 {
        return Err("TFTP runs on UDP 69; the input has no UDP port data".into());
    }
    let mut affected = Vec::new();
    for d in &ctx.input.devices {
        let udp = d
            .extra
            .get("udpPorts")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|p| p.as_u64() == Some(69)));
        if udp || d.has_port(69) {
            affected.push(affected_device(d, ctx, Some("port 69".into())));
        }
    }
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_TFTP,
        Severity::Medium,
        "TFTP has no authentication: anyone who can reach it can download (and often upload) \
         configuration files and firmware images.",
    )
    .affected(affected)
    .fix(
        "Disable TFTP servers outside maintenance windows; use SCP/SFTP for configuration \
          transfer and restrict TFTP with ACLs to the management network.",
    )
    .finish()])
}

fn rule_rsh(ctx: &Ctx) -> RuleOutcome {
    port_rule(
        ctx,
        &R_RSH,
        &[512, 513, 514],
        |_| Severity::High,
        "rexec / rlogin / rsh authenticate by source address or cleartext password and are \
         trivially abused for lateral movement.",
        "Disable the r-services (inetd/xinetd entries, `no ip rcmd ...` on Cisco) and use SSH.",
    )
}

fn rule_smb_infra(ctx: &Ctx) -> RuleOutcome {
    ctx.port_coverage(&[445, 139])?;
    let affected: Vec<Affected> = ctx
        .input
        .devices
        .iter()
        .filter(|d| d.role.is_infrastructure() && (d.has_port(445) || d.has_port(139)))
        .map(|d| {
            let ports: Vec<&str> = [(445, "TCP 445"), (139, "TCP 139")]
                .iter()
                .filter(|(p, _)| d.has_port(*p))
                .map(|(_, l)| *l)
                .collect();
            affected_device(
                d,
                ctx,
                Some(format!("{} ({})", ports.join(", "), d.role.label())),
            )
        })
        .collect();
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_SMB_INFRA,
        Severity::High,
        "Switches, routers, firewalls and access points should not offer Windows file sharing. \
         SMB on infrastructure usually means an embedded file service (often SMBv1) or a \
         misidentified server in the management network.",
    )
    .affected(affected)
    .fix(
        "Disable SMB / NetBIOS file services on network devices (USB storage sharing, \
          embedded NAS features). If SMB is required, enforce SMBv3 with signing and restrict \
          it to the management VLAN.",
    )
    .finish()])
}

fn rule_netbios(ctx: &Ctx) -> RuleOutcome {
    port_rule(
        ctx,
        &R_NETBIOS,
        &[139],
        |d| {
            if d.role.is_infrastructure() {
                Severity::High
            } else {
                Severity::Medium
            }
        },
        "SMB over the NetBIOS session service (TCP 139) is the transport of SMBv1-era file \
         sharing. Hosts offering it may still accept SMBv1, which is vulnerable to wormable \
         remote code execution and NTLM relay.",
        "Disable NetBIOS over TCP/IP where it is not needed, disable SMBv1 (Windows: \
         `Set-SmbServerConfiguration -EnableSMB1Protocol $false`) and require SMB signing.",
    )
    .map(|mut v| {
        // SMB on infrastructure is already reported by SWR-SVC-005.
        v.retain(|f| f.severity != Severity::High);
        v
    })
}

fn rule_smb_broad(ctx: &Ctx) -> RuleOutcome {
    ctx.port_coverage(&[445])?;
    let scanned = ctx
        .input
        .devices
        .iter()
        .filter(|d| !d.open_ports.is_empty())
        .count()
        .max(1);
    let hosts: Vec<&AuditDevice> = ctx
        .input
        .devices
        .iter()
        .filter(|d| !d.role.is_infrastructure() && d.has_port(445))
        .collect();
    let fraction = hosts.len() as f64 / scanned as f64;
    if hosts.len() < ctx.t.smb_broad_min_hosts || fraction < ctx.t.smb_broad_fraction {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_SMB_BROAD,
        Severity::Medium,
        "Many hosts accept SMB connections from the scanning host. Workstation-to-workstation \
         SMB is the main lateral-movement path for ransomware.",
    )
    .evidence(format!(
        "{} of {} hosts with open ports ({:.0}%) accept TCP 445",
        hosts.len(),
        scanned,
        fraction * 100.0
    ))
    .affected(
        hosts
            .iter()
            .map(|d| affected_device(d, ctx, Some("TCP 445".into())))
            .collect(),
    )
    .fix(
        "Block inbound SMB on workstations with host firewalls (allow only from file \
          servers / management hosts), disable SMBv1 everywhere and require SMB signing.",
    )
    .finish()])
}

fn rule_rdp(ctx: &Ctx) -> RuleOutcome {
    port_rule(
        ctx,
        &R_RDP,
        &[3389],
        |_| Severity::Medium,
        "Remote Desktop is a prime target for password spraying and has a history of \
         pre-authentication vulnerabilities.",
        "Restrict RDP to a jump host or VPN, require Network Level Authentication and MFA, \
         and enable account lockout.",
    )
}

fn rule_vnc(ctx: &Ctx) -> RuleOutcome {
    port_rule(
        ctx,
        &R_VNC,
        &[5800, 5900, 5901, 5902, 5903],
        |_| Severity::High,
        "VNC commonly uses weak (8-character DES) passwords or none at all and does not \
         encrypt the session by default.",
        "Disable VNC or tunnel it through SSH / VPN, set strong passwords and restrict it to \
         administrator hosts.",
    )
}

fn rule_http_mgmt(ctx: &Ctx) -> RuleOutcome {
    ctx.port_coverage(&[80])?;
    let tls_ports = [443, 4443, 8443, 10443];
    let affected: Vec<Affected> = ctx
        .input
        .devices
        .iter()
        .filter(|d| {
            d.role.is_infrastructure()
                && (d.has_port(80) || d.has_port(8080))
                && !tls_ports.iter().any(|p| d.has_port(*p))
        })
        .map(|d| {
            affected_device(
                d,
                ctx,
                Some(format!("{} with HTTP, no HTTPS", d.role.label())),
            )
        })
        .collect();
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_HTTP_MGMT,
        Severity::High,
        "Network devices expose a web management interface over plain HTTP with no HTTPS \
         alternative on the scanned ports, so administrator logins cross the network in \
         cleartext.",
    )
    .affected(affected)
    .fix(
        "Enable HTTPS management (Cisco: `ip http secure-server`, `no ip http server`) with \
          a trusted certificate, disable plain HTTP, and restrict management to a dedicated \
          VLAN / ACL.",
    )
    .finish()])
}

fn rule_ssh_telnet(ctx: &Ctx) -> RuleOutcome {
    ctx.port_coverage(&[22, 23])?;
    let affected: Vec<Affected> = ctx
        .input
        .devices
        .iter()
        .filter(|d| d.has_port(22) && d.has_port(23))
        .map(|d| affected_device(d, ctx, Some("TCP 22 and TCP 23".into())))
        .collect();
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_SSH_TELNET,
        Severity::Medium,
        "These devices already support SSH but still accept Telnet, so administrators (and \
         scripts) can silently fall back to the cleartext protocol.",
    )
    .affected(affected)
    .fix(
        "Since SSH works, remove Telnet from the allowed transports (`transport input ssh`) \
          and update any automation that still uses Telnet.",
    )
    .finish()])
}

// --- SNMP ------------------------------------------------------------------------------------

fn snmp_meta<'a>(ctx: &Ctx<'a>) -> Result<&'a SnmpMeta, String> {
    ctx.input
        .meta
        .snmp
        .as_ref()
        .ok_or_else(|| "SNMP polling was not enabled for this scan".to_string())
}

fn agent_affected(ctx: &Ctx) -> Vec<Affected> {
    ctx.snmp_agents
        .iter()
        .map(|ip| {
            let dev = ctx.input.devices.iter().find(|d| &d.ip == ip);
            let name = ctx
                .input
                .snmp_infos
                .iter()
                .find(|s| s.ip.as_deref() == Some(ip))
                .and_then(|s| s.sys_name.clone())
                .or_else(|| dev.and_then(|d| d.name().map(str::to_string)));
            Affected {
                ip: Some(ip.clone()),
                name,
                mac: dev.and_then(|d| d.mac.clone()),
                vlan: dev.and_then(|d| ctx.effective_vlan(d)),
                port: Some("UDP 161".into()),
                detail: None,
            }
        })
        .collect()
}

fn rule_snmp_default(ctx: &Ctx) -> RuleOutcome {
    let meta = snmp_meta(ctx)?;
    if !meta.uses_community() {
        return Ok(Vec::new());
    }
    let kind = match meta.community_kind.as_deref() {
        Some(k @ ("public" | "private")) => k,
        Some(_) => return Ok(Vec::new()),
        None => return Err("the SNMP community used is not recorded".into()),
    };
    let affected = agent_affected(ctx);
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    let severity = if kind == "private" {
        Severity::Critical
    } else {
        Severity::High
    };
    let mut d = Draft::new(
        &R_SNMP_DEFAULT,
        severity,
        format!(
            "These agents answered SNMP requests using the factory-default community \
             `{kind}`. Anyone on the network can read the full configuration inventory \
             (interfaces, ARP / MAC tables, routes){}.",
            if kind == "private" {
                " and the `private` community is commonly read-write, allowing configuration \
                 changes"
            } else {
                ""
            }
        ),
    )
    .evidence(format!(
        "{} agent(s) returned data for community `{kind}`",
        affected.len()
    ))
    .affected(affected)
    .fix(
        "Remove the default communities, migrate to SNMPv3 authPriv (SHA-2 + AES), and \
          restrict SNMP with an ACL to the monitoring servers.",
    );
    d.title = Some(format!("SNMP answers the default community \"{kind}\""));
    Ok(vec![d.finish()])
}

fn rule_snmp_v12(ctx: &Ctx) -> RuleOutcome {
    let meta = snmp_meta(ctx)?;
    if !meta.uses_community() {
        return Ok(Vec::new());
    }
    let affected = agent_affected(ctx);
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    let version = meta.version.clone().unwrap_or_else(|| "v2c".into());
    Ok(vec![Draft::new(
        &R_SNMP_V12,
        Severity::Medium,
        format!(
            "Infrastructure is polled with SNMP{version}, whose community string travels in \
             cleartext and provides no integrity protection."
        ),
    )
    .evidence(format!(
        "{} agent(s) answered SNMP{version}",
        affected.len()
    ))
    .affected(affected)
    .fix(
        "Configure SNMPv3 users with authPriv (SHA-256 / AES-128 or better), disable v1/v2c \
          communities once monitoring has migrated, and restrict SNMP to the NMS addresses.",
    )
    .finish()])
}

fn rule_snmp_partial(ctx: &Ctx) -> RuleOutcome {
    if ctx.input.snmp_infos.is_empty() {
        return Err("no per-device SNMP results in the input".into());
    }
    let affected: Vec<Affected> = ctx
        .input
        .snmp_infos
        .iter()
        .filter(|s| s.partial || !s.warnings.is_empty())
        .map(|s| Affected {
            ip: s.ip.clone(),
            name: s.sys_name.clone(),
            detail: Some(
                s.warnings
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
            ..Default::default()
        })
        .collect();
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_SNMP_PARTIAL,
        Severity::Info,
        "Some SNMP table walks failed or were truncated; port utilization and switch-port \
         mapping for these devices may be incomplete.",
    )
    .affected(affected)
    .fix(
        "Check SNMP views / ACLs on these devices, raise the timeout, or poll them \
          individually with `sweepr snmp <ip>`.",
    )
    .finish()])
}

// --- TLS -------------------------------------------------------------------------------------

fn cert_rule(
    ctx: &Ctx,
    pick: impl Fn(&CertView) -> Option<String>,
) -> Result<Vec<Affected>, String> {
    let mut any = false;
    let mut affected = Vec::new();
    for d in &ctx.input.devices {
        for c in d.certificates() {
            any = true;
            if let Some(detail) = pick(&c) {
                let mut a = affected_device(d, ctx, Some(detail));
                if let Some(p) = c.port {
                    a.port = Some(format!("TCP {p}"));
                }
                affected.push(a);
            }
        }
    }
    if any {
        Ok(affected)
    } else {
        Err("no TLS certificate data in the input".into())
    }
}

fn cert_name(c: &CertView) -> String {
    c.subject_cn.clone().unwrap_or_else(|| "certificate".into())
}

fn rule_tls_expired(ctx: &Ctx) -> RuleOutcome {
    let now = ctx.now_ms;
    let affected = cert_rule(ctx, |c| {
        let days = c.days_left(now);
        let expired = days.map(|d| d < 0).or(c.expired).unwrap_or(false);
        expired.then(|| {
            format!(
                "{} expired {}",
                cert_name(c),
                c.not_after
                    .clone()
                    .or_else(|| days.map(|d| format!("{} days ago", -d)))
                    .unwrap_or_default()
            )
        })
    })?;
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_TLS_EXPIRED,
        Severity::Medium,
        "These HTTPS interfaces present an expired certificate. Browsers show errors, and \
         users learn to click through certificate warnings, which defeats protection against \
         man-in-the-middle attacks.",
    )
    .affected(affected)
    .fix(
        "Renew the certificates (ideally from an internal CA or ACME) and track expiry \
          dates in monitoring.",
    )
    .finish()])
}

fn rule_tls_expiring(ctx: &Ctx) -> RuleOutcome {
    let (now, warn) = (ctx.now_ms, ctx.t.cert_expiry_warn_days);
    let affected = cert_rule(ctx, |c| {
        let days = c.days_left(now)?;
        (0..=warn)
            .contains(&days)
            .then(|| format!("{} expires in {days} day(s)", cert_name(c)))
    })?;
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_TLS_EXPIRING,
        Severity::Low,
        format!("These certificates expire within {warn} days."),
    )
    .affected(affected)
    .fix("Schedule renewal now and automate it (ACME / internal CA auto-enrollment).")
    .finish()])
}

fn rule_tls_self(ctx: &Ctx) -> RuleOutcome {
    let affected = cert_rule(ctx, |c| {
        c.self_signed
            .then(|| format!("{} (self-signed)", cert_name(c)))
    })?;
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_TLS_SELF,
        Severity::Low,
        "Self-signed certificates cannot be validated, so every connection starts with a \
         browser warning and impersonation goes unnoticed.",
    )
    .affected(affected)
    .fix(
        "Issue certificates from an internal CA trusted by managed clients (or ACME for \
          public names) and replace factory self-signed certificates.",
    )
    .finish()])
}

fn rule_tls_weak(ctx: &Ctx) -> RuleOutcome {
    let t = ctx.t;
    let affected = cert_rule(ctx, |c| c.weakness(t))?;
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_TLS_WEAK,
        Severity::Medium,
        format!(
            "Certificates use keys or signatures below current minimums (RSA {} bits, EC {} \
             bits, SHA-256 signatures).",
            t.min_rsa_bits, t.min_ec_bits
        ),
    )
    .affected(affected)
    .fix(
        "Re-issue the certificates with RSA-2048+ or ECDSA P-256 keys and SHA-256 \
          signatures; upgrade firmware that cannot generate them.",
    )
    .finish()])
}

// --- inventory -------------------------------------------------------------------------------

fn rule_unknown(ctx: &Ctx) -> RuleOutcome {
    if ctx.input.devices.is_empty() {
        return Err("no devices in the input".into());
    }
    let affected: Vec<Affected> = ctx
        .input
        .devices
        .iter()
        .filter(|d| d.name().is_none() && d.vendor.is_none() && !d.role.is_infrastructure())
        .map(|d| affected_device(d, ctx, Some("no host name, no vendor".into())))
        .collect();
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_UNKNOWN,
        Severity::Low,
        "These devices have neither a resolvable name nor a recognized hardware vendor. They \
         may be unmanaged, personal or rogue equipment.",
    )
    .evidence(format!(
        "{} of {} devices unidentified",
        affected.len(),
        ctx.input.devices.len()
    ))
    .affected(affected)
    .fix(
        "Identify the owners (switch port, DHCP lease, physical check), register them in \
          the asset inventory and DNS, and enforce 802.1X / NAC for unknown devices.",
    )
    .finish()])
}

/// Locally administered (bit 1) unicast MAC.
pub fn is_local_admin_mac(mac: &str) -> bool {
    parse_mac(mac).is_some_and(|m| m[0] & 0x02 != 0 && m[0] & 0x01 == 0)
}

fn rule_random_mac(ctx: &Ctx) -> RuleOutcome {
    if !ctx.input.devices.iter().any(|d| d.mac.is_some()) {
        return Err("no MAC addresses in the input (routed scan)".into());
    }
    let affected: Vec<Affected> = ctx
        .input
        .devices
        .iter()
        .filter(|d| d.mac.as_deref().is_some_and(is_local_admin_mac))
        .map(|d| affected_device(d, ctx, Some("locally administered MAC".into())))
        .collect();
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_RANDOM_MAC,
        Severity::Info,
        "These devices use locally administered MAC addresses: phones and laptops with \
         Wi-Fi privacy addresses, virtual machines or containers. Vendor identification and \
         MAC-based policies do not work for them.",
    )
    .affected(affected)
    .fix(
        "Expected for BYOD Wi-Fi. On corporate SSIDs, prefer 802.1X identity over MAC-based \
          controls; investigate randomized MACs on wired ports.",
    )
    .finish()])
}

// --- layer 2 ---------------------------------------------------------------------------------

fn rule_dup_ip(ctx: &Ctx) -> RuleOutcome {
    let mut map: BTreeMap<(String, Option<u16>), BTreeMap<String, &AuditDevice>> = BTreeMap::new();
    let mut any_mac = false;
    for d in &ctx.input.devices {
        let Some(mac) = &d.mac else { continue };
        any_mac = true;
        let vlan = ctx.effective_vlan(d);
        for ip in std::iter::once(&d.ip).chain(d.extra_ips.iter()) {
            map.entry((ip.clone(), vlan))
                .or_default()
                .insert(mac.clone(), d);
        }
    }
    if !any_mac {
        return Err("no MAC addresses in the input (routed scan)".into());
    }
    let mut affected = Vec::new();
    for ((ip, vlan), macs) in map.iter().filter(|(_, m)| m.len() > 1) {
        let list: Vec<&str> = macs.keys().map(String::as_str).collect();
        for d in macs.values() {
            let mut a =
                affected_device(d, ctx, Some(format!("{ip} claimed by {}", list.join(", "))));
            a.ip = Some(ip.clone());
            a.vlan = *vlan;
            affected.push(a);
        }
    }
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_DUP_IP,
        Severity::High,
        "The same IP address was answered by different MAC addresses in the same VLAN. This \
         is either an address conflict or an ARP spoofing / man-in-the-middle attempt.",
    )
    .affected(affected)
    .fix(
        "Locate both MACs via the switch CAM table, fix the static / DHCP conflict, and \
          enable DHCP snooping with Dynamic ARP Inspection on access switches.",
    )
    .finish()])
}

fn rule_mac_multi(ctx: &Ctx) -> RuleOutcome {
    let mut map: BTreeMap<(String, Option<u16>), Vec<&AuditDevice>> = BTreeMap::new();
    for d in &ctx.input.devices {
        if let (Some(mac), Some(IpAddr::V4(_))) = (&d.mac, d.ip_addr()) {
            map.entry((mac.clone(), ctx.effective_vlan(d)))
                .or_default()
                .push(d);
        }
    }
    if map.is_empty() {
        return Err("no MAC addresses in the input (routed scan)".into());
    }
    let mut hosts = Vec::new();
    let mut gateways = Vec::new();
    for ((mac, _), devs) in map.iter().filter(|(_, v)| v.len() > 1) {
        let ips: Vec<&str> = devs.iter().map(|d| d.ip.as_str()).collect();
        let infra = ctx.infra_macs.contains(mac)
            || devs
                .iter()
                .any(|d| matches!(d.role, DeviceRole::Router | DeviceRole::Firewall));
        for d in devs {
            let a = affected_device(
                d,
                ctx,
                Some(format!("{mac} answers for {}", ips.join(", "))),
            );
            if infra {
                gateways.push(a);
            } else {
                hosts.push(a);
            }
        }
    }
    let mut out = Vec::new();
    if !hosts.is_empty() {
        out.push(
            Draft::new(
                &R_MAC_MULTI,
                Severity::Medium,
                "A single non-router MAC address answered ARP for several IPv4 addresses in the \
                 same VLAN. Unless the host deliberately carries several addresses, this \
                 indicates ARP spoofing or an unexpected proxy-ARP device.",
            )
            .affected(hosts)
            .fix(
                "Confirm whether the host is multi-homed; otherwise trace the MAC to its switch \
                  port and enable Dynamic ARP Inspection.",
            )
            .finish(),
        );
    }
    if !gateways.is_empty() {
        let mut d = Draft::new(
            &R_MAC_MULTI,
            Severity::Info,
            "A router / firewall MAC answers for several IPv4 addresses (secondary addresses or \
             proxy-ARP). Usually intentional; confirm proxy-ARP is required.",
        )
        .affected(gateways)
        .fix(
            "Disable proxy-ARP on router interfaces where it is not required (`no ip \
              proxy-arp`).",
        );
        d.title = Some("Router / firewall MAC answering for several IPs (proxy-ARP)".into());
        out.push(d.finish());
    }
    Ok(out)
}

fn rule_rogue_dhcp(ctx: &Ctx) -> RuleOutcome {
    let mut servers: BTreeSet<String> = ctx.input.meta.dhcp_servers.iter().cloned().collect();
    let mut any = !servers.is_empty();
    for d in &ctx.input.devices {
        if let Some(b) = d.extra.get("dhcpServer").and_then(Value::as_bool) {
            any = true;
            if b {
                servers.insert(d.ip.clone());
            }
        }
    }
    if !any {
        return Err("no DHCP server observations in the input".into());
    }
    if servers.len() <= ctx.t.max_dhcp_servers {
        return Ok(Vec::new());
    }
    let affected = servers
        .iter()
        .map(|ip| {
            let d = ctx.input.devices.iter().find(|d| &d.ip == ip);
            match d {
                Some(d) => affected_device(d, ctx, Some("DHCP server".into())),
                None => Affected {
                    ip: Some(ip.clone()),
                    detail: Some("DHCP server".into()),
                    ..Default::default()
                },
            }
        })
        .collect();
    Ok(vec![Draft::new(
        &R_ROGUE_DHCP,
        Severity::Critical,
        "More DHCP servers answered than expected. A rogue DHCP server can hand out its own \
         gateway / DNS and intercept all traffic of new clients.",
    )
    .evidence(format!("{} DHCP servers observed", servers.len()))
    .affected(affected)
    .fix(
        "Identify the unauthorized server, enable DHCP snooping (trusted ports only on \
          uplinks / the real server) on all access switches.",
    )
    .finish()])
}

fn rule_rogue_ra(ctx: &Ctx) -> RuleOutcome {
    let mut routers: BTreeSet<String> = ctx.input.meta.ipv6_routers.iter().cloned().collect();
    let mut any = !routers.is_empty();
    for d in &ctx.input.devices {
        if let Some(b) = d.extra.get("ipv6Router").and_then(Value::as_bool) {
            any = true;
            if b {
                routers.insert(d.ip.clone());
            }
        }
    }
    if !any {
        return Err("no IPv6 router advertisement observations in the input".into());
    }
    if routers.len() <= ctx.t.max_ipv6_routers {
        return Ok(Vec::new());
    }
    let affected = routers
        .iter()
        .map(|ip| Affected {
            ip: Some(ip.clone()),
            detail: Some("sends IPv6 router advertisements".into()),
            ..Default::default()
        })
        .collect();
    Ok(vec![Draft::new(
        &R_ROGUE_RA,
        Severity::High,
        "Several hosts send IPv6 router advertisements. Clients auto-configure a default \
         route through any of them, so a rogue RA silently redirects IPv6 traffic, even on \
         networks that do not use IPv6.",
    )
    .evidence(format!("{} RA sources observed", routers.len()))
    .affected(affected)
    .fix(
        "Enable RA Guard (RFC 6105) on access ports, and disable IPv6 router functions on \
          hosts that should not route.",
    )
    .finish()])
}

fn rule_cdp_access(ctx: &Ctx) -> RuleOutcome {
    if ctx.input.neighbors.is_empty() {
        return Err("no CDP/LLDP advertisements captured".into());
    }
    // Interfaces where the scanner saw 802.1Q tags are trunks; CDP/LLDP is expected there.
    let trunk_ifaces: BTreeSet<&str> = ctx
        .input
        .vlans
        .iter()
        .filter(|v| v.sources.iter().any(|s| s == "tagged8021q"))
        .filter_map(|v| v.interface.as_deref())
        .collect();
    let affected: Vec<Affected> = ctx
        .input
        .neighbors
        .iter()
        .filter(|n| n.is_infrastructure() && !trunk_ifaces.contains(n.local_interface.as_str()))
        .map(|n| Affected {
            ip: n.management_addrs.first().cloned(),
            name: Some(n.display_name().to_string()),
            mac: Some(n.source_mac.clone()),
            vlan: n.native_vlan,
            port: n.port_id.clone(),
            detail: Some(format!(
                "{} heard on {}{}",
                n.protocol.to_ascii_uppercase(),
                n.local_interface,
                n.software_version
                    .as_deref()
                    .map(|v| format!("; reveals version: {}", truncate(v, 60)))
                    .unwrap_or_default()
            )),
        })
        .collect();
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_CDP_ACCESS,
        Severity::Low,
        "The scanning host (an endpoint) received CDP/LLDP advertisements from network \
         devices. Any user on these ports learns device names, models, software versions, \
         management addresses and VLAN IDs, which helps attackers pick exploits and VLAN-hop.",
    )
    .affected(affected)
    .fix(
        "Disable CDP/LLDP transmit on user-facing access ports (`no cdp enable`, `no lldp \
          transmit`); keep it on uplinks and on ports with IP phones that need LLDP-MED.",
    )
    .finish()])
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(max).collect::<String>())
    }
}

// --- VLAN hygiene ----------------------------------------------------------------------------

fn rule_native_vlan1(ctx: &Ctx) -> RuleOutcome {
    let with_native: Vec<&AuditNeighbor> = ctx
        .input
        .neighbors
        .iter()
        .filter(|n| n.native_vlan.is_some())
        .collect();
    if with_native.is_empty() {
        return Err("no native VLAN information (CDP/LLDP) captured".into());
    }
    let affected: Vec<Affected> = with_native
        .iter()
        .filter(|n| n.native_vlan == Some(1) && n.is_infrastructure())
        .map(|n| Affected {
            ip: n.management_addrs.first().cloned(),
            name: Some(n.display_name().to_string()),
            mac: Some(n.source_mac.clone()),
            vlan: Some(1),
            port: n.port_id.clone(),
            detail: Some("native / access VLAN 1".into()),
        })
        .collect();
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_NATIVE_VLAN1,
        Severity::Medium,
        "Switch ports use VLAN 1 as their native (untagged) VLAN. VLAN 1 also carries control \
         protocols (CDP, VTP, DTP, STP) and is the default for every unconfigured port, which \
         enables double-tagging VLAN-hopping attacks on trunks.",
    )
    .affected(affected)
    .fix(
        "Move access ports to dedicated user VLANs, set an unused 'black-hole' native VLAN \
          on trunks (`switchport trunk native vlan 999`) or tag the native VLAN, and shut \
          unused ports into an unused VLAN.",
    )
    .finish()])
}

fn rule_native_mismatch(ctx: &Ctx) -> RuleOutcome {
    let mut by_iface: BTreeMap<&str, BTreeMap<u16, Vec<&AuditNeighbor>>> = BTreeMap::new();
    for n in &ctx.input.neighbors {
        if let Some(v) = n.native_vlan {
            by_iface
                .entry(n.local_interface.as_str())
                .or_default()
                .entry(v)
                .or_default()
                .push(n);
        }
    }
    if by_iface.is_empty() {
        return Err("no native VLAN information (CDP/LLDP) captured".into());
    }
    let mut affected = Vec::new();
    for (iface, vlans) in by_iface.iter().filter(|(_, v)| v.len() > 1) {
        let list: Vec<String> = vlans.keys().map(u16::to_string).collect();
        for (vlan, ns) in vlans {
            for n in ns {
                affected.push(Affected {
                    ip: n.management_addrs.first().cloned(),
                    name: Some(n.display_name().to_string()),
                    mac: Some(n.source_mac.clone()),
                    vlan: Some(*vlan),
                    port: n.port_id.clone(),
                    detail: Some(format!(
                        "native VLANs {} advertised on the same segment ({iface})",
                        list.join(" vs ")
                    )),
                });
            }
        }
    }
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_NATIVE_MISMATCH,
        Severity::Medium,
        "Devices on the same link advertise different native VLANs. Untagged traffic leaks \
         between the two VLANs (a classic segmentation bypass) and spanning tree may block or \
         loop unexpectedly.",
    )
    .affected(affected)
    .fix(
        "Make the native VLAN identical on both ends of every trunk (or tag it everywhere) \
          and resolve CDP 'native VLAN mismatch' log messages.",
    )
    .finish()])
}

fn rule_voice_vlan(ctx: &Ctx) -> RuleOutcome {
    let phones: Vec<&AuditDevice> = ctx.input.devices.iter().filter(|d| d.is_phone()).collect();
    if phones.is_empty() {
        return Err("no IP phones identified".into());
    }
    let advertised: BTreeSet<u16> = ctx
        .input
        .neighbors
        .iter()
        .filter_map(|n| n.voice_vlan)
        .chain(ctx.input.devices.iter().filter_map(AuditDevice::voice_vlan))
        .collect();
    // Data VLANs: where the non-phone hosts live.
    let mut data_vlans: BTreeMap<Option<u16>, usize> = BTreeMap::new();
    for d in ctx.input.devices.iter().filter(|d| !d.is_phone()) {
        *data_vlans.entry(ctx.effective_vlan(d)).or_default() += 1;
    }
    let affected: Vec<Affected> = phones
        .iter()
        .filter(|p| {
            let v = ctx.effective_vlan(p);
            let in_voice = v.is_some_and(|v| advertised.contains(&v));
            !in_voice
                && (v.is_none() || v == Some(1) || data_vlans.get(&v).copied().unwrap_or(0) > 0)
        })
        .map(|p| {
            let v = ctx.effective_vlan(p);
            affected_device(
                p,
                ctx,
                Some(match v {
                    Some(v) => format!("phone in data VLAN {v}"),
                    None => "phone on the untagged / native network".into(),
                }),
            )
        })
        .collect();
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_VOICE_VLAN,
        Severity::Low,
        "IP phones share a VLAN with ordinary hosts instead of a dedicated voice VLAN. Voice \
         traffic loses QoS separation and phones (often with weak web interfaces and SIP \
         credentials) are directly reachable from workstations.",
    )
    .evidence(if advertised.is_empty() {
        "no voice VLAN is advertised by CDP / LLDP-MED".to_string()
    } else {
        format!(
            "voice VLAN(s) advertised: {}",
            advertised
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
    .affected(affected)
    .fix(
        "Configure a voice VLAN on access ports (`switchport voice vlan <id>`, LLDP-MED \
          network policy) and restrict SIP / phone management to the PBX and admin hosts.",
    )
    .finish()])
}

fn rule_vlan1_hosts(ctx: &Ctx) -> RuleOutcome {
    if ctx.input.devices.is_empty() {
        return Err("no devices in the input".into());
    }
    let hosts: Vec<&AuditDevice> = ctx
        .input
        .devices
        .iter()
        .filter(|d| ctx.effective_vlan(d) == Some(1))
        .collect();
    if hosts.is_empty()
        && !ctx
            .input
            .devices
            .iter()
            .any(|d| ctx.effective_vlan(d).is_some())
    {
        return Err(
            "VLAN membership unknown (no tagged scan and no native VLAN advertised)".into(),
        );
    }
    if hosts.len() < ctx.t.vlan1_max_hosts {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_VLAN1_HOSTS,
        Severity::Medium,
        format!(
            "{} devices live in VLAN 1, the default VLAN every unconfigured switch port joins. \
             Users, servers and management share one broadcast domain with no segmentation.",
            hosts.len()
        ),
    )
    .evidence(format!("threshold: {} hosts", ctx.t.vlan1_max_hosts))
    .affected(
        hosts
            .iter()
            .map(|d| affected_device(d, ctx, Some("VLAN 1".into())))
            .collect(),
    )
    .fix(
        "Create purpose-specific VLANs (users, servers, voice, management, IoT), move access \
          ports out of VLAN 1 and filter traffic between VLANs on the firewall.",
    )
    .finish()])
}

fn rule_unused_vlan(ctx: &Ctx) -> RuleOutcome {
    let mut defined: BTreeMap<u16, String> = BTreeMap::new();
    for v in ctx
        .input
        .vlans
        .iter()
        .chain(ctx.input.snmp_infos.iter().flat_map(|s| s.vlans.iter()))
        .filter(|v| v.is_configured())
    {
        defined
            .entry(v.id)
            .or_insert_with(|| v.name.clone().unwrap_or_default());
    }
    if defined.is_empty() {
        return Err("no VLAN definitions from switch configuration (SNMP / VTP)".into());
    }
    let mut used: BTreeSet<u16> = ctx
        .input
        .devices
        .iter()
        .filter_map(|d| ctx.effective_vlan(d))
        .collect();
    used.extend(ctx.input.port_mappings.iter().filter_map(|p| p.vlan_id));
    used.extend(
        ctx.input
            .snmp_infos
            .iter()
            .flat_map(|s| s.port_mappings.iter().filter_map(|p| p.vlan_id)),
    );
    used.extend(ctx.input.neighbors.iter().filter_map(|n| n.native_vlan));
    used.extend(ctx.input.neighbors.iter().filter_map(|n| n.voice_vlan));
    let affected: Vec<Affected> = defined
        .iter()
        .filter(|(id, _)| !used.contains(id) && !(1002..=1005).contains(*id) && **id != 1)
        .map(|(id, name)| Affected {
            vlan: Some(*id),
            name: (!name.is_empty()).then(|| name.clone()),
            detail: Some("no hosts or learned MACs".into()),
            ..Default::default()
        })
        .collect();
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_UNUSED_VLAN,
        Severity::Info,
        "These VLANs are defined on switches but no host, learned MAC or CDP/LLDP neighbor was \
         seen in them. Stale VLANs complicate audits and may still be allowed on trunks.",
    )
    .affected(affected)
    .fix(
        "Confirm the VLANs are obsolete, remove them, and prune them from trunk allowed \
          lists (`switchport trunk allowed vlan remove <id>`).",
    )
    .finish()])
}

// --- switch ports ----------------------------------------------------------------------------

/// MACs learned per (switch, port), from SNMP counts when available, else port mappings.
pub fn port_mac_table(input: &AuditInput) -> BTreeMap<(String, String), PortStat> {
    let mut out: BTreeMap<(String, String), PortStat> = BTreeMap::new();
    let mut add = |pm: &AuditPortMapping| {
        let e = out
            .entry((pm.switch_name.clone(), pm.port_name.clone()))
            .or_default();
        if e.switch_ip.is_none() {
            e.switch_ip = pm.switch_ip.clone();
        }
        e.macs.insert(pm.mac.clone());
        if let Some(v) = pm.vlan_id {
            e.vlans.insert(v);
        }
    };
    for pm in &input.port_mappings {
        add(pm);
    }
    for s in &input.snmp_infos {
        s.port_mappings.iter().for_each(&mut add);
    }
    for s in &input.snmp_infos {
        let name = s.name();
        for c in &s.port_mac_counts {
            let e = out.entry((name.clone(), c.port_name.clone())).or_default();
            if e.switch_ip.is_none() {
                e.switch_ip = s.ip.clone();
            }
            e.reported_count = Some(e.reported_count.unwrap_or(0).max(c.mac_count));
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct PortStat {
    pub switch_ip: Option<String>,
    pub macs: BTreeSet<String>,
    pub vlans: BTreeSet<u16>,
    /// Count reported by the SNMP poll (may exceed the mappings kept).
    pub reported_count: Option<u32>,
}

impl PortStat {
    pub fn mac_count(&self) -> u32 {
        self.reported_count.unwrap_or(0).max(self.macs.len() as u32)
    }
}

/// Port names that are aggregates / uplinks by convention.
pub fn is_uplink_name(port: &str) -> bool {
    let p = port.to_ascii_lowercase();
    [
        "po",
        "port-channel",
        "ae",
        "bond",
        "lag",
        "trk",
        "vlan",
        "cpu",
    ]
    .iter()
    .any(|pre| {
        p.starts_with(pre)
            && p[pre.len()..].starts_with(|c: char| c.is_ascii_digit() || c == '-' || c == ' ')
    })
}

fn rule_hub_port(ctx: &Ctx) -> RuleOutcome {
    let table = port_mac_table(ctx.input);
    if table.is_empty() {
        return Err("no switch MAC-to-port data (SNMP bridge tables)".into());
    }
    // MACs of devices that legitimately front many clients (APs, switches, routers, hypervisors).
    let fronting: BTreeSet<&str> = ctx
        .input
        .devices
        .iter()
        .filter(|d| d.role.is_infrastructure())
        .filter_map(|d| d.mac.as_deref())
        .chain(ctx.input.neighbors.iter().map(|n| n.source_mac.as_str()))
        .collect();
    let mut affected = Vec::new();
    for ((switch, port), stat) in &table {
        let n = stat.mac_count();
        if n < ctx.t.hub_port_min_macs
            || n > ctx.t.uplink_mac_threshold
            || is_uplink_name(port)
            || stat.macs.iter().any(|m| fronting.contains(m.as_str()))
        {
            continue;
        }
        affected.push(Affected {
            ip: stat.switch_ip.clone(),
            name: Some(switch.clone()),
            port: Some(port.clone()),
            vlan: (stat.vlans.len() == 1)
                .then(|| stat.vlans.iter().next().copied())
                .flatten(),
            detail: Some(format!("{n} MACs learned")),
            ..Default::default()
        });
    }
    if affected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![Draft::new(
        &R_HUB_PORT,
        Severity::Low,
        format!(
            "These access ports learned between {} and {} MAC addresses without a known \
             switch, AP or router behind them, which suggests an unmanaged switch, hub, \
             hypervisor or docking station extending the network outside IT control.",
            ctx.t.hub_port_min_macs, ctx.t.uplink_mac_threshold
        ),
    )
    .affected(affected)
    .fix(
        "Inspect the ports physically, document legitimate hypervisors / docks, and limit \
          MACs per port with port security or 802.1X multi-auth.",
    )
    .finish()])
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub const NOW: u64 = 1_790_000_000_000; // 2026-09-21

    pub fn dev(ip: &str, mac: &str, role: &str, ports: &[u16]) -> Value {
        json!({ "ip": ip, "mac": mac, "role": role, "openPorts": ports, "vendor": "Acme" })
    }

    pub fn input(v: Value) -> AuditInput {
        AuditInput::from_json_value(v).unwrap()
    }

    fn base_meta() -> Value {
        json!({ "portSpec": "21,22,23,69,80,139,443,445,512-514,3389,5900,8443" })
    }

    fn run(v: Value) -> AuditResult {
        run_audit(&input(v), &AuditThresholds::default(), NOW)
    }

    fn find<'a>(r: &'a AuditResult, id: &str) -> Vec<&'a Finding> {
        r.findings.iter().filter(|f| f.id == id).collect()
    }

    fn check<'a>(r: &'a AuditResult, id: &str) -> &'a RuleCheck {
        r.checks.iter().find(|c| c.id == id).unwrap()
    }

    #[test]
    fn rule_ids_are_unique_and_complete() {
        let ids: BTreeSet<&str> = RULES.iter().map(|r| r.id).collect();
        assert_eq!(ids.len(), RULES.len());
        let r = run(json!({ "devices": [] }));
        assert_eq!(r.checks.len(), RULES.len());
        for (c, def) in r.checks.iter().zip(RULES) {
            assert_eq!(c.id, def.id);
        }
    }

    #[test]
    fn lenient_input_accepts_arrays_unknown_fields_and_skips_garbage() {
        let v = json!([
            { "ip": "10.0.0.1", "role": "quantum_router", "futureField": { "x": 1 },
              "tlsCert": { "subjectCn": "a" } },
            { "ip": "not-an-ip" },
            { "ip": "10.0.0.2", "vlanId": "ten" },
            "garbage"
        ]);
        let i = input(v);
        assert_eq!(i.devices.len(), 1);
        assert_eq!(i.skipped_records, 3);
        assert_eq!(i.devices[0].role, DeviceRole::Host);
        assert!(i.devices[0].extra.contains_key("futureField"));
        assert_eq!(i.devices[0].certificates().len(), 1);
        assert!(AuditInput::from_json_value(json!("x")).is_err());
    }

    #[test]
    fn snmp_community_is_redacted() {
        let i = input(json!({ "meta": { "snmp": { "version": "v2c", "community": "s3cr3t!" } } }));
        let s = i.meta.snmp.as_ref().unwrap();
        assert_eq!(s.community_kind.as_deref(), Some("custom"));
        let text = serde_json::to_string(&i).unwrap();
        assert!(!text.contains("s3cr3t"));
    }

    #[test]
    fn telnet_ftp_rsh_vnc_rdp() {
        let r = run(json!({ "meta": base_meta(), "devices": [
            dev("10.0.0.1", "00:11:22:00:00:01", "switch", &[22, 23]),
            dev("10.0.0.2", "00:11:22:00:00:02", "host", &[21]),
            dev("10.0.0.3", "00:11:22:00:00:03", "host", &[514]),
            dev("10.0.0.4", "00:11:22:00:00:04", "host", &[5900]),
            dev("10.0.0.5", "00:11:22:00:00:05", "host", &[3389]),
        ]}));
        assert_eq!(find(&r, "SWR-SVC-001")[0].severity, Severity::High);
        assert_eq!(
            find(&r, "SWR-SVC-001")[0].affected[0].ip.as_deref(),
            Some("10.0.0.1")
        );
        assert_eq!(find(&r, "SWR-SVC-002")[0].severity, Severity::Medium);
        assert_eq!(find(&r, "SWR-SVC-004")[0].affected_count, 1);
        assert_eq!(find(&r, "SWR-SVC-009")[0].severity, Severity::High);
        assert_eq!(find(&r, "SWR-SVC-008")[0].severity, Severity::Medium);
        assert_eq!(find(&r, "SWR-MGT-002").len(), 1);
    }

    #[test]
    fn port_rules_not_evaluated_without_coverage() {
        let r = run(json!({ "meta": { "portSpec": "22,80" }, "devices": [
            dev("10.0.0.1", "00:11:22:00:00:01", "host", &[22]),
        ]}));
        let c = check(&r, "SWR-SVC-008");
        assert!(!c.evaluated);
        assert!(c.note.as_deref().unwrap().contains("3389"));
        assert!(check(&r, "SWR-SVC-003")
            .note
            .as_deref()
            .unwrap()
            .contains("UDP"));
        let r = run(json!({ "devices": [{ "ip": "10.0.0.1" }] }));
        assert!(!check(&r, "SWR-SVC-001").evaluated);
    }

    #[test]
    fn tftp_from_udp_extra() {
        let mut d = dev("10.0.0.9", "00:11:22:00:00:09", "host", &[]);
        d["udpPorts"] = json!([69, 161]);
        let r = run(json!({ "devices": [d] }));
        assert_eq!(find(&r, "SWR-SVC-003").len(), 1);
    }

    #[test]
    fn smb_rules() {
        let mut devices = vec![dev("10.0.0.1", "00:11:22:00:00:01", "switch", &[445])];
        for i in 2..10 {
            devices.push(dev(
                &format!("10.0.0.{i}"),
                &format!("00:11:22:00:00:{i:02x}"),
                "host",
                &[445, 139],
            ));
        }
        devices.push(dev("10.0.0.20", "00:11:22:00:00:20", "host", &[22]));
        let r = run(json!({ "meta": base_meta(), "devices": devices }));
        assert_eq!(find(&r, "SWR-SVC-005")[0].affected_count, 1);
        assert_eq!(find(&r, "SWR-SVC-006")[0].affected_count, 8);
        assert_eq!(find(&r, "SWR-SVC-007")[0].affected_count, 8);
        // Few SMB hosts: not "broad".
        let r = run(json!({ "meta": base_meta(), "devices": [
            dev("10.0.0.2", "00:11:22:00:00:02", "host", &[445]),
            dev("10.0.0.3", "00:11:22:00:00:03", "host", &[22]),
        ]}));
        assert!(find(&r, "SWR-SVC-007").is_empty());
    }

    #[test]
    fn http_only_management() {
        let r = run(json!({ "meta": base_meta(), "devices": [
            dev("10.0.0.1", "00:11:22:00:00:01", "switch", &[80]),
            dev("10.0.0.2", "00:11:22:00:00:02", "firewall", &[80, 443]),
            dev("10.0.0.3", "00:11:22:00:00:03", "host", &[80]),
        ]}));
        let f = find(&r, "SWR-MGT-001");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].affected_count, 1);
        assert_eq!(f[0].affected[0].ip.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn snmp_default_community_and_version() {
        let mk = |community: &str, version: &str| {
            json!({
                "meta": { "snmp": { "version": version, "community": community } },
                "devices": [dev("10.0.0.1", "00:11:22:00:00:01", "switch", &[])],
                "portMappings": [{ "switchName": "sw1", "switchIp": "10.0.0.1", "portName": "Gi1/0/1", "mac": "00:11:22:00:00:99" }]
            })
        };
        let r = run(mk("public", "v2c"));
        assert_eq!(find(&r, "SWR-SNP-001")[0].severity, Severity::High);
        assert_eq!(find(&r, "SWR-SNP-002").len(), 1);
        let r = run(mk("private", "v1"));
        assert_eq!(find(&r, "SWR-SNP-001")[0].severity, Severity::Critical);
        let r = run(mk("corp-ro-7", "v2c"));
        assert!(find(&r, "SWR-SNP-001").is_empty());
        assert_eq!(find(&r, "SWR-SNP-002").len(), 1);
        let r = run(mk("", "v3"));
        assert!(find(&r, "SWR-SNP-002").is_empty());
        let r = run(json!({ "devices": [] }));
        assert!(!check(&r, "SWR-SNP-001").evaluated);
    }

    #[test]
    fn snmp_partial_is_info() {
        let r = run(json!({ "snmpInfos": [
            { "ip": "10.0.0.1", "sysName": "sw1", "role": "switch", "partial": true, "warnings": ["dot1dTpFdb timed out"] },
            { "ip": "10.0.0.2", "sysName": "sw2", "role": "switch" }
        ]}));
        let f = find(&r, "SWR-SNP-003");
        assert_eq!(f[0].severity, Severity::Info);
        assert_eq!(f[0].affected_count, 1);
    }

    fn cert_dev(ip: &str, cert: Value) -> Value {
        let mut d = dev(ip, "00:11:22:00:00:01", "host", &[443]);
        d["tlsCert"] = cert;
        d
    }

    #[test]
    fn tls_rules() {
        let day = 86_400_000i64;
        let now = NOW as i64;
        let r = run(json!({ "devices": [
            cert_dev("10.0.0.1", json!({ "port": 443, "subjectCn": "old", "notAfterMs": now - 3 * day })),
            cert_dev("10.0.0.2", json!({ "port": 8443, "subjectCn": "soon", "notAfterMs": now + 10 * day })),
            cert_dev("10.0.0.3", json!({ "subjectCn": "self", "notAfter": "2030-01-01T00:00:00Z", "selfSigned": true })),
            cert_dev("10.0.0.4", json!({ "subjectCn": "weak", "notAfterMs": now + 400 * day, "keyType": "RSA", "keyBits": 1024, "signatureAlgorithm": "sha1WithRSAEncryption" })),
            cert_dev("10.0.0.5", json!({ "subjectCn": "ok", "notAfterMs": now + 400 * day, "keyType": "EC P-256", "keyBits": 256, "signatureAlgorithm": "ecdsa-with-SHA256" })),
        ]}));
        let expired = find(&r, "SWR-TLS-001");
        assert_eq!(expired[0].affected_count, 1);
        assert_eq!(expired[0].affected[0].port.as_deref(), Some("TCP 443"));
        assert_eq!(
            find(&r, "SWR-TLS-002")[0].affected[0].ip.as_deref(),
            Some("10.0.0.2")
        );
        assert_eq!(
            find(&r, "SWR-TLS-003")[0].affected[0].ip.as_deref(),
            Some("10.0.0.3")
        );
        let weak = find(&r, "SWR-TLS-004");
        assert_eq!(weak[0].affected_count, 1);
        let detail = weak[0].affected[0].detail.as_deref().unwrap();
        assert!(
            detail.contains("1024") && detail.contains("SHA-1"),
            "{detail}"
        );
        // No certificate data at all: not evaluated.
        let r = run(json!({ "devices": [dev("10.0.0.1", "00:11:22:00:00:01", "host", &[443])] }));
        assert!(!check(&r, "SWR-TLS-001").evaluated);
    }

    #[test]
    fn iso_dates() {
        assert_eq!(parse_iso8601_ms("1970-01-02T00:00:00Z"), Some(86_400_000));
        assert_eq!(parse_iso8601_ms("2000-03-01"), Some(951_868_800_000));
        assert_eq!(parse_iso8601_ms("garbage"), None);
        assert_eq!(
            format_utc(951_868_800_000 + 3_660_000),
            "2000-03-01 01:01 UTC"
        );
    }

    #[test]
    fn unknown_and_random_macs() {
        let r = run(json!({ "devices": [
            { "ip": "10.0.0.1", "mac": "00:11:22:33:44:55" },
            { "ip": "10.0.0.2", "mac": "00:11:22:33:44:56", "dnsName": "pc.lan" },
            { "ip": "10.0.0.3", "mac": "da:a1:19:00:00:01", "vendor": "Apple" },
        ]}));
        let u = find(&r, "SWR-INV-001");
        assert_eq!(u[0].affected_count, 1);
        assert_eq!(u[0].affected[0].ip.as_deref(), Some("10.0.0.1"));
        assert!(is_local_admin_mac("da:a1:19:00:00:01"));
        assert!(!is_local_admin_mac("00:11:22:33:44:55"));
        assert!(!is_local_admin_mac("01:00:5e:00:00:01"));
        assert_eq!(find(&r, "SWR-INV-002")[0].affected_count, 1);
    }

    #[test]
    fn duplicate_ip_and_mac_on_many_ips() {
        let r = run(json!({ "devices": [
            { "ip": "10.0.0.5", "mac": "00:11:22:00:00:01", "vlanId": 10 },
            { "ip": "10.0.0.6", "mac": "00:11:22:00:00:02", "vlanId": 10, "extraIps": ["10.0.0.5"] },
            // Same IP in another VLAN is not a duplicate.
            { "ip": "10.0.0.5", "mac": "00:11:22:00:00:03", "vlanId": 20 },
            { "ip": "10.0.0.7", "mac": "00:11:22:00:00:aa", "vlanId": 10 },
            { "ip": "10.0.0.8", "mac": "00:11:22:00:00:aa", "vlanId": 10 },
            { "ip": "10.0.0.1", "mac": "00:11:22:00:00:fe", "vlanId": 10, "role": "router" },
            { "ip": "10.0.0.2", "mac": "00:11:22:00:00:fe", "vlanId": 10 },
        ]}));
        let dup = find(&r, "SWR-L2-001");
        assert_eq!(dup[0].affected_count, 2);
        assert!(dup[0].affected.iter().all(|a| a.vlan == Some(10)));
        let multi = find(&r, "SWR-L2-002");
        assert_eq!(multi.len(), 2);
        assert_eq!(multi[0].severity, Severity::Medium);
        assert_eq!(multi[0].affected_count, 2);
        assert_eq!(multi[1].severity, Severity::Info);
    }

    #[test]
    fn rogue_dhcp_and_ra_only_with_data() {
        let r = run(json!({ "devices": [dev("10.0.0.1", "00:11:22:00:00:01", "host", &[])] }));
        assert!(!check(&r, "SWR-L2-003").evaluated);
        assert!(!check(&r, "SWR-L2-004").evaluated);
        let r = run(json!({
            "meta": { "dhcpServers": ["10.0.0.1", "10.0.0.66"], "ipv6Routers": ["fe80::1"] },
            "devices": [dev("10.0.0.1", "00:11:22:00:00:01", "router", &[])]
        }));
        assert_eq!(find(&r, "SWR-L2-003")[0].severity, Severity::Critical);
        assert!(check(&r, "SWR-L2-004").evaluated);
        assert!(find(&r, "SWR-L2-004").is_empty());
        let mut d = dev("10.0.0.9", "00:11:22:00:00:09", "host", &[]);
        d["ipv6Router"] = json!(true);
        let r = run(json!({ "meta": { "ipv6Routers": ["fe80::1"] }, "devices": [d] }));
        assert_eq!(find(&r, "SWR-L2-004")[0].affected_count, 2);
    }

    fn nb(dev_id: &str, iface: &str, native: Option<u16>, caps: &[&str]) -> Value {
        json!({ "protocol": "cdp", "localInterface": iface, "sourceMac": "00:aa:00:00:00:01",
                "deviceId": dev_id, "portId": "Gi1/0/7", "nativeVlan": native,
                "capabilities": caps, "softwareVersion": "IOS 15.2(7)E" })
    }

    #[test]
    fn cdp_on_access_port() {
        let r = run(
            json!({ "neighbors": [nb("sw1", "en0", Some(10), &["switch"]), nb("phone", "en0", None, &["telephone"])] }),
        );
        let f = find(&r, "SWR-L2-005");
        assert_eq!(f[0].affected_count, 1);
        assert!(f[0].affected[0].detail.as_deref().unwrap().contains("IOS"));
        // A trunk (tags seen) is not user-facing.
        let r = run(json!({
            "neighbors": [nb("sw1", "en0", Some(10), &["switch"])],
            "vlans": [{ "id": 20, "sources": ["tagged8021q"], "interface": "en0" }]
        }));
        assert!(find(&r, "SWR-L2-005").is_empty());
    }

    #[test]
    fn native_vlan1_and_mismatch() {
        let r = run(json!({ "neighbors": [
            nb("sw1", "en0", Some(1), &["switch"]),
            nb("sw2", "en0", Some(10), &["switch"]),
        ]}));
        assert_eq!(find(&r, "SWR-VLN-001")[0].affected_count, 1);
        assert_eq!(find(&r, "SWR-VLN-002")[0].affected_count, 2);
        let r = run(json!({ "neighbors": [nb("sw1", "en0", Some(10), &["switch"])] }));
        assert!(find(&r, "SWR-VLN-001").is_empty());
        assert!(find(&r, "SWR-VLN-002").is_empty());
    }

    #[test]
    fn voice_vlan_for_phones() {
        let phone = |ip: &str, vlan: u16| json!({ "ip": ip, "mac": "80:5e:c0:00:00:01", "vendor": "Yealink Network Technology", "vlanId": vlan });
        let pc = |ip: &str, vlan: u16| json!({ "ip": ip, "mac": "00:11:22:00:00:01", "vendor": "Dell", "vlanId": vlan });
        let r = run(json!({ "devices": [phone("10.0.10.5", 10), pc("10.0.10.6", 10)] }));
        let f = find(&r, "SWR-VLN-003");
        assert_eq!(f[0].affected_count, 1);
        assert!(f[0].evidence[0].contains("no voice VLAN"));
        // Phones in their own advertised voice VLAN are fine.
        let mut n = nb("sw1", "en0", Some(10), &["switch"]);
        n["voiceVlan"] = json!(20);
        let r = run(
            json!({ "devices": [phone("10.0.20.5", 20), pc("10.0.10.6", 10)], "neighbors": [n] }),
        );
        assert!(find(&r, "SWR-VLN-003").is_empty());
        let r = run(json!({ "devices": [pc("10.0.10.6", 10)] }));
        assert!(!check(&r, "SWR-VLN-003").evaluated);
    }

    #[test]
    fn many_hosts_in_vlan1_including_native_inference() {
        let devices: Vec<Value> = (1..=12)
            .map(|i| json!({ "ip": format!("10.0.0.{i}"), "interface": "en0" }))
            .collect();
        // Untagged hosts on en0, whose switch advertises native VLAN 1.
        let r = run(
            json!({ "devices": devices, "neighbors": [nb("sw1", "en0", Some(1), &["switch"])] }),
        );
        assert_eq!(find(&r, "SWR-VLN-004")[0].affected_count, 12);
        let r = run(json!({ "devices": devices }));
        assert!(!check(&r, "SWR-VLN-004").evaluated);
    }

    #[test]
    fn unused_vlans() {
        let r = run(json!({
            "devices": [{ "ip": "10.0.10.5", "vlanId": 10 }],
            "snmpInfos": [{ "ip": "10.0.0.2", "role": "switch", "vlans": [
                { "id": 1, "sources": ["snmp"] }, { "id": 10, "sources": ["snmp"] },
                { "id": 30, "name": "old-guest", "sources": ["snmp"] }, { "id": 1002, "sources": ["vtp"] }
            ]}]
        }));
        let f = find(&r, "SWR-VLN-005");
        assert_eq!(f[0].affected_count, 1);
        assert_eq!(f[0].affected[0].vlan, Some(30));
        assert_eq!(f[0].affected[0].name.as_deref(), Some("old-guest"));
    }

    #[test]
    fn hub_ports() {
        let mut maps = Vec::new();
        for i in 0..6 {
            maps.push(json!({ "switchName": "sw1", "switchIp": "10.0.0.2", "portName": "Gi1/0/5", "mac": format!("00:11:22:33:00:{i:02x}") }));
        }
        for i in 0..60 {
            maps.push(json!({ "switchName": "sw1", "portName": "Gi1/0/48", "mac": format!("00:11:22:44:00:{i:02x}") }));
        }
        for i in 0..6 {
            maps.push(json!({ "switchName": "sw1", "portName": "Po1", "mac": format!("00:11:22:55:00:{i:02x}") }));
        }
        let r = run(json!({ "portMappings": maps }));
        let f = find(&r, "SWR-PRT-001");
        assert_eq!(f[0].affected_count, 1);
        assert_eq!(f[0].affected[0].port.as_deref(), Some("Gi1/0/5"));
        assert!(
            is_uplink_name("Port-channel1") && is_uplink_name("ae0") && !is_uplink_name("Gi1/0/1")
        );
    }

    #[test]
    fn scoring_weights_breadth_and_caps() {
        let empty = score_findings(&[]);
        assert_eq!((empty.score, empty.grade.as_str()), (100, "A"));
        let mk = |sev: Severity, n: usize| {
            let mut d = Draft::new(&R_TELNET, sev, "");
            d.affected = vec![Affected::default(); n];
            d.finish()
        };
        // Breadth: 1 device = 1x, 8 devices = 4x, 1000 devices still 4x.
        assert_eq!(mk(Severity::Medium, 1).points, 4.0);
        assert_eq!(mk(Severity::Medium, 8).points, 16.0);
        assert_eq!(mk(Severity::Medium, 1000).points, 16.0);
        assert_eq!(mk(Severity::Medium, 1000).affected.len(), MAX_AFFECTED);
        // One high finding: numeric A, capped to B.
        let s = score_findings(&[mk(Severity::High, 1)]);
        assert_eq!(s.score, 90);
        assert_eq!(s.grade, "B");
        assert!(s.capped_by.is_some());
        let s = score_findings(&[mk(Severity::Critical, 1)]);
        assert_eq!(s.grade, "D");
        let s = score_findings(&[mk(Severity::Low, 1), mk(Severity::Info, 50)]);
        assert_eq!(s.grade, "A");
        assert_eq!(s.counts.info, 1);
        let many: Vec<Finding> = (0..10).map(|_| mk(Severity::Medium, 8)).collect();
        assert_eq!(score_findings(&many).grade, "F");
    }

    #[test]
    fn findings_sorted_by_severity() {
        let r = run(json!({ "meta": base_meta(), "devices": [
            dev("10.0.0.2", "00:11:22:00:00:02", "host", &[21]),
            dev("10.0.0.1", "00:11:22:00:00:01", "switch", &[23]),
            { "ip": "10.0.0.3", "mac": "da:00:00:00:00:01" },
        ]}));
        let sevs: Vec<Severity> = r.findings.iter().map(|f| f.severity).collect();
        let mut sorted = sevs.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(sevs, sorted);
    }

    #[test]
    fn compact_port_spec() {
        assert_eq!(compact_ports(&[443, 22, 23, 24, 80, 22]), "22-24,80,443");
        let i = input(json!({ "meta": { "portSpec": "22-24,80" } }));
        assert_eq!(i.meta.scanned_ports(), Some(vec![22, 23, 24, 80]));
    }
}
