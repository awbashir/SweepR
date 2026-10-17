//! Shared data models for SweepR.
//!
//! Every type here is serialized with `serde` using `camelCase` field names so the exact same
//! structures flow to the React frontend (Tauri events / commands) and to the CLI's JSON output.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default TCP ports probed for management-plane fingerprinting.
/// Includes SIP (5060, so PBXes / phones become SIP OPTIONS candidates) and the common
/// alternate web ports 8000 / 8080 (web identity, HTTP-only management checks).
pub const DEFAULT_PORTS: &[u16] = &[
    22, 23, 80, 161, 443, 445, 5060, 8000, 8080, 8291, 8443, 10443,
];

/// Highest usable IEEE 802.1Q VLAN ID (4095 is reserved, 0 means "priority tag only").
pub const MAX_VLAN_ID: u16 = 4094;

// ---------------------------------------------------------------------------------------------
// Errors & small helpers
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ModelError {
    #[error("invalid IP range or CIDR: {0}")]
    InvalidRange(String),
    #[error("invalid VLAN specification: {0}")]
    InvalidVlan(String),
    #[error("invalid port specification: {0}")]
    InvalidPort(String),
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Longest string kept from any network-supplied text field (CDP/LLDP/VTP, names).
pub const MAX_TEXT_LEN: usize = 256;
/// Longest URL kept from network-supplied data (SSDP `LOCATION`, WSD `XAddrs`, ONVIF URIs).
pub const MAX_URL_LEN: usize = 2048;

/// `true` for Unicode bidirectional / zero-width format characters that can make text
/// display differently from its content ("Trojan Source" style spoofing).
fn is_bidi_or_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}'
    )
}

/// Make untrusted text safe to print on a terminal or show in a UI.
///
/// Whitespace control characters (tab, newline, CR, VT, FF) become a single space; every
/// other control character (C0 including ESC and BEL, DEL, C1 such as CSI `\u{9b}`) and
/// bidi/zero-width format characters are removed. Leading/trailing whitespace and NULs are
/// trimmed and the result is capped at [`MAX_TEXT_LEN`] characters.
pub fn sanitize_text(s: &str) -> String {
    sanitize_text_max(s, MAX_TEXT_LEN)
}

/// [`sanitize_text`] with a custom length cap (in characters), for fields that are
/// legitimately longer than a name, e.g. URLs (see [`MAX_URL_LEN`]).
pub fn sanitize_text_max(s: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_chars));
    let mut chars = 0usize;
    for c in s.chars() {
        let c = match c {
            '\t' | '\n' | '\r' | '\u{0b}' | '\u{0c}' => ' ',
            c if c.is_control() || is_bidi_or_invisible(c) => continue,
            c => c,
        };
        if chars == max_chars {
            break;
        }
        out.push(c);
        chars += 1;
    }
    let trimmed = out.trim();
    if trimmed.len() == out.len() {
        out
    } else {
        trimmed.to_string()
    }
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// Format a MAC address as lowercase `aa:bb:cc:dd:ee:ff`.
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Parse a MAC address in any common notation (`aa:bb:..`, `aa-bb-..`, `aabb.ccdd.eeff`,
/// or the zero-stripped form printed by macOS `arp`, e.g. `0:1a:2b:3:4:5`).
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let s = s.trim();
    let mut out = [0u8; 6];

    if s.contains(':') || s.contains('-') {
        let parts: Vec<&str> = s.split([':', '-']).collect();
        if parts.len() != 6 {
            return None;
        }
        for (i, p) in parts.iter().enumerate() {
            if p.is_empty() || p.len() > 2 {
                return None;
            }
            out[i] = u8::from_str_radix(p, 16).ok()?;
        }
        return Some(out);
    }

    // Cisco dotted notation or bare hex.
    let hex: String = s.chars().filter(|c| *c != '.').collect();
    if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Normalize a MAC string to the canonical lowercase colon form.
pub fn normalize_mac(s: &str) -> Option<String> {
    parse_mac(s).map(|m| format_mac(&m))
}

// ---------------------------------------------------------------------------------------------
// Device role & discovery provenance
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRole {
    Switch,
    Firewall,
    AccessPoint,
    Router,
    #[default]
    Host,
}

impl DeviceRole {
    pub fn label(self) -> &'static str {
        match self {
            DeviceRole::Switch => "Switch",
            DeviceRole::Firewall => "Firewall",
            DeviceRole::AccessPoint => "Access Point",
            DeviceRole::Router => "Router",
            DeviceRole::Host => "Host",
        }
    }

    /// `true` for network infrastructure (everything except plain hosts).
    pub fn is_infrastructure(self) -> bool {
        self != DeviceRole::Host
    }

    /// Merge precedence: when two observations disagree, the higher value wins.
    pub fn priority(self) -> u8 {
        match self {
            DeviceRole::Host => 0,
            DeviceRole::Router => 1,
            DeviceRole::AccessPoint => 2,
            DeviceRole::Switch => 3,
            DeviceRole::Firewall => 4,
        }
    }
}

impl fmt::Display for DeviceRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Where a device's [`DeviceRole`] came from (`Device::role_source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleSource {
    /// Set by the user (reserved: the GUI does not edit roles yet).
    User,
    /// The device's own CDP advertisement.
    Cdp,
    /// The device's own LLDP advertisement.
    Lldp,
    /// SNMP sysObjectID / sysDescr / sysServices / BRIDGE-MIB.
    Snmp,
    /// Web interface identity (title, `Server` header, certificate).
    Web,
    /// DNS-SD service types advertised over mDNS.
    MdnsService,
    /// Host name tokens (DNS PTR, mDNS, NetBIOS, user label) with the vendor OUI.
    Name,
    /// OUI vendor plus the open management ports.
    OuiPorts,
}

impl RoleSource {
    /// Short human label ("CDP", "mDNS service", ...).
    pub fn label(self) -> &'static str {
        match self {
            RoleSource::User => "user",
            RoleSource::Cdp => "CDP",
            RoleSource::Lldp => "LLDP",
            RoleSource::Snmp => "SNMP",
            RoleSource::Web => "web identity",
            RoleSource::MdnsService => "mDNS service",
            RoleSource::Name => "host name",
            RoleSource::OuiPorts => "OUI + ports",
        }
    }
}

/// How sure a role is (`Device::role_confidence`). Ordered: `Low < Medium < High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleConfidence {
    /// A guess from weak hints (host name tokens, OUI + ports): treat as "probably".
    Low,
    /// A product identification (web UI, vendor-specific management port).
    Medium,
    /// The device described itself (CDP / LLDP / SNMP) or the user set it.
    High,
}

impl RoleConfidence {
    pub fn label(self) -> &'static str {
        match self {
            RoleConfidence::Low => "low",
            RoleConfidence::Medium => "medium",
            RoleConfidence::High => "high",
        }
    }
}

/// Most `role_evidence` entries kept on one device.
pub const MAX_ROLE_EVIDENCE: usize = 8;

/// How a device (or piece of its data) was learned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    Arp,
    Ndp,
    Icmp,
    Tcp,
    NeighborCache,
    Cdp,
    Lldp,
    Snmp,
    Dns,
    Mdns,
    Netbios,
    Ssdp,
    Wsd,
    Sip,
    Dhcp,
}

// ---------------------------------------------------------------------------------------------
// VLANs
// ---------------------------------------------------------------------------------------------

/// Where a VLAN ID was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VlanSource {
    /// An OS-level 802.1Q sub-interface (`vlan0`, `en0.100`, `eth0.10`).
    OsInterface,
    /// An 802.1Q tag seen on the wire by the passive sniffer.
    Tagged8021q,
    Cdp,
    Lldp,
    Vtp,
    Snmp,
    /// Explicitly requested by the user.
    UserConfigured,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VlanInfo {
    pub id: u16,
    pub name: Option<String>,
    pub sources: Vec<VlanSource>,
    /// Local interface the VLAN was seen on / is configured on.
    pub interface: Option<String>,
    /// Switch that advertised or owns the VLAN (CDP/LLDP/SNMP/VTP).
    pub switch_name: Option<String>,
    pub frames_seen: u64,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

impl VlanInfo {
    pub fn new(id: u16, source: VlanSource) -> Self {
        let now = now_ms();
        Self {
            id,
            name: None,
            sources: vec![source],
            interface: None,
            switch_name: None,
            frames_seen: 0,
            first_seen_ms: now,
            last_seen_ms: now,
        }
    }

    /// Fold another observation of the same VLAN into this one.
    pub fn merge(&mut self, other: &VlanInfo) {
        if self.name.is_none() {
            self.name = other.name.clone();
        }
        if self.interface.is_none() {
            self.interface = other.interface.clone();
        }
        if self.switch_name.is_none() {
            self.switch_name = other.switch_name.clone();
        }
        for s in &other.sources {
            if !self.sources.contains(s) {
                self.sources.push(*s);
            }
        }
        self.frames_seen += other.frames_seen;
        self.first_seen_ms = self.first_seen_ms.min(other.first_seen_ms);
        self.last_seen_ms = self.last_seen_ms.max(other.last_seen_ms);
    }

    /// Fold a *cumulative snapshot* of the same VLAN into this one.
    ///
    /// [`ScanEvent::Vlan`] events carry the running totals of the observer that emitted them
    /// (a passive listener re-announces a VLAN with its total frame count so far), so
    /// summing them would double count. Concurrent listeners on one interface see the same
    /// frames, so the largest count is the true one.
    pub fn merge_snapshot(&mut self, other: &VlanInfo) {
        let frames = self.frames_seen.max(other.frames_seen);
        self.merge(other);
        self.frames_seen = frames;
    }
}

/// Which VLANs a scan should tag its probes with.
///
/// Serialized as `{"mode": "...", "ids": [...]}`; the `untagged_and_list` mode was added
/// later, so older `untagged` / `list` / `auto_detect` documents keep their meaning.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "mode", content = "ids", rename_all = "snake_case")]
pub enum VlanSelection {
    /// Plain (untagged) probes on the interface's native network.
    #[default]
    Untagged,
    /// Explicit VLAN IDs, e.g. `10,20,99` or `1-100`.
    List(Vec<u16>),
    /// OS VLAN interfaces + a short passive sniff for tags/CDP/LLDP/VTP.
    AutoDetect,
    /// The native (untagged) network plus explicit VLAN IDs, e.g. `untagged,10,20`.
    UntaggedAndList(Vec<u16>),
}

impl VlanSelection {
    pub fn is_untagged(&self) -> bool {
        matches!(self, VlanSelection::Untagged)
    }

    /// Explicit VLAN IDs of a list selection (empty for `Untagged` / `AutoDetect`).
    pub fn ids(&self) -> &[u16] {
        match self {
            VlanSelection::List(ids) | VlanSelection::UntaggedAndList(ids) => ids,
            VlanSelection::Untagged | VlanSelection::AutoDetect => &[],
        }
    }

    /// `true` when the native (untagged) network is probed.
    pub fn includes_untagged(&self) -> bool {
        !matches!(self, VlanSelection::List(_))
    }
}

fn is_untagged_keyword(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "untagged" | "none" | "native"
    )
}

impl FromStr for VlanSelection {
    type Err = ModelError;

    /// Accepts `untagged`/`none`/empty, `auto`, or a list such as `10,20,30` / `1-100` /
    /// `10,20-25`. A list may include `untagged` (`untagged,10,20`) to also probe the native
    /// network.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        match s.to_ascii_lowercase().as_str() {
            "" | "untagged" | "none" | "native" => return Ok(VlanSelection::Untagged),
            "auto" | "auto-detect" | "autodetect" => return Ok(VlanSelection::AutoDetect),
            _ => {}
        }

        let mut ids: Vec<u16> = Vec::new();
        let mut untagged = false;
        for part in s
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|p| !p.is_empty())
        {
            if is_untagged_keyword(part) {
                untagged = true;
                continue;
            }
            if part.eq_ignore_ascii_case("auto") {
                return Err(ModelError::InvalidVlan(
                    "'auto' cannot be combined with other VLAN IDs".into(),
                ));
            }
            // Tolerate a leading "VLAN"/"vlan" label ("VLAN 10, 20").
            let part = part.trim_start_matches(|c: char| c.is_ascii_alphabetic());
            if part.is_empty() {
                continue;
            }
            let parse_id = |t: &str| -> Result<u16, ModelError> {
                let id: u16 = t
                    .trim()
                    .parse()
                    .map_err(|_| ModelError::InvalidVlan(format!("'{t}' is not a number")))?;
                if !(1..=MAX_VLAN_ID).contains(&id) {
                    return Err(ModelError::InvalidVlan(format!(
                        "VLAN ID {id} out of range (1-{MAX_VLAN_ID})"
                    )));
                }
                Ok(id)
            };
            if let Some((a, b)) = part.split_once('-') {
                let (lo, hi) = (parse_id(a)?, parse_id(b)?);
                if lo > hi {
                    return Err(ModelError::InvalidVlan(format!(
                        "descending range '{part}'"
                    )));
                }
                ids.extend(lo..=hi);
            } else {
                ids.push(parse_id(part)?);
            }
        }
        ids.sort_unstable();
        ids.dedup();
        match (ids.is_empty(), untagged) {
            (true, true) => Ok(VlanSelection::Untagged),
            (true, false) => Err(ModelError::InvalidVlan(format!("no VLAN IDs in '{s}'"))),
            (false, true) => Ok(VlanSelection::UntaggedAndList(ids)),
            (false, false) => Ok(VlanSelection::List(ids)),
        }
    }
}

impl fmt::Display for VlanSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let list = |ids: &[u16]| ids.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
        match self {
            VlanSelection::Untagged => f.write_str("untagged"),
            VlanSelection::AutoDetect => f.write_str("auto"),
            VlanSelection::List(ids) => f.write_str(&list(ids)),
            VlanSelection::UntaggedAndList(ids) => write!(f, "untagged,{}", list(ids)),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// CDP / LLDP neighbors
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NeighborProtocol {
    Cdp,
    Lldp,
}

/// Device capability advertised in CDP/LLDP (superset of both protocols).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Router,
    Switch,
    WlanAccessPoint,
    Firewall,
    Repeater,
    Telephone,
    DocsisCable,
    Host,
    Other,
}

impl Capability {
    pub fn label(self) -> &'static str {
        match self {
            Capability::Router => "Router",
            Capability::Switch => "Switch",
            Capability::WlanAccessPoint => "WLAN Access Point",
            Capability::Firewall => "Firewall",
            Capability::Repeater => "Repeater",
            Capability::Telephone => "Telephone",
            Capability::DocsisCable => "DOCSIS Cable Device",
            Capability::Host => "Host",
            Capability::Other => "Other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CdpLldpNeighbor {
    pub protocol: NeighborProtocol,
    /// Local interface the advertisement was received on.
    pub local_interface: String,
    /// Source MAC address of the advertisement frame.
    pub source_mac: String,
    /// CDP Device ID / LLDP Chassis ID (rendered as text).
    pub device_id: String,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    /// Remote port, e.g. `GigabitEthernet1/0/12` (CDP Port ID / LLDP Port ID).
    pub port_id: Option<String>,
    pub port_description: Option<String>,
    /// Hardware platform / model (CDP Platform TLV).
    pub platform: Option<String>,
    /// OS / IOS version string (CDP Software Version TLV).
    pub software_version: Option<String>,
    pub management_addrs: Vec<IpAddr>,
    pub native_vlan: Option<u16>,
    pub voice_vlan: Option<u16>,
    pub capabilities: Vec<Capability>,
    /// CDP VTP management domain.
    pub vtp_domain: Option<String>,
    /// PoE power the neighbor reported it draws / supplies, in watts (CDP Power Consumption /
    /// Power Available, LLDP 802.3 MDI power / LLDP-MED Extended Power-via-MDI).
    #[serde(default)]
    pub poe_watts: Option<f32>,
    /// Full PoE detail parsed from the power TLVs (class, source, priority, status). Boxed to
    /// keep `ScanEvent::Neighbor` small; serializes exactly like an inline `PoeInfo`.
    #[serde(default)]
    pub poe_info: Option<Box<PoeInfo>>,
    pub ttl_secs: u16,
    pub last_seen_ms: u64,
}

impl CdpLldpNeighbor {
    /// Stable identity of the advertising port (chassis + port).
    pub fn key(&self) -> String {
        format!(
            "{:?}|{}|{}",
            self.protocol,
            self.device_id,
            self.port_id.as_deref().unwrap_or("")
        )
    }

    /// Best human-readable name for the neighbor.
    pub fn display_name(&self) -> &str {
        self.system_name
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.device_id)
    }

    /// Classify the neighbor from its advertised capabilities and platform/description strings.
    pub fn infer_role(&self) -> DeviceRole {
        let text = [
            self.platform.as_deref(),
            self.software_version.as_deref(),
            self.system_description.as_deref(),
            self.system_name.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();

        let has = |c: Capability| self.capabilities.contains(&c);
        let any = |needles: &[&str]| needles.iter().any(|n| text.contains(n));

        if has(Capability::Firewall)
            || any(&[
                "fortigate",
                "fortinet",
                "palo alto",
                "pan-os",
                "firepower",
                "pfsense",
                "sophos",
                "sonicwall",
                "checkpoint",
                "check point",
                "netscreen",
                "juniper srx",
                " srx",
                "cisco asa",
                "adaptive security",
                "meraki mx",
                "watchguard",
                "opnsense",
            ])
        {
            return DeviceRole::Firewall;
        }
        // Access points are checked before switches: many APs (e.g. Cisco Catalyst 91xx,
        // Aironet) advertise only the CDP "transparent bridge" capability, which maps to
        // Switch, so an AP model/software string must win over that capability.
        let ap_keyword = any(&[
            "access point",
            "aironet",
            "air-",
            "cisco ap software",
            "ap3g",
            "ap1g",
            "c9105",
            "c9115",
            "c9117",
            "c9120",
            "c9124",
            "c9130",
            "c9136",
            "cw91",
            "unifi",
            "uap-",
            "u6-",
            "u7-",
            "meraki mr",
            "aruba ap",
            "instant ap",
            "ruckus zoneflex",
            "mikrotik cap",
        ]);
        // Controllers and non-AP gear whose strings overlap the AP keywords above.
        let not_ap = any(&[
            "air-ct",
            "wireless lan controller",
            "unifi switch",
            "usw-",
            "udm",
            "usg",
            "uxg",
        ]);
        if has(Capability::WlanAccessPoint) || (ap_keyword && !not_ap) {
            return DeviceRole::AccessPoint;
        }
        // IP phones with a PC port advertise Bridge (+ Telephone): they are endpoints, not
        // switches. Telephone together with Router is a voice gateway / router.
        if has(Capability::Telephone) && !has(Capability::Router) {
            return DeviceRole::Host;
        }
        // L3 switches advertise Router + Switch: treat them as switches.
        if has(Capability::Switch)
            || any(&[
                "catalyst",
                "switch",
                "ws-c",
                "c9200",
                "c9300",
                "c9500",
                "nexus",
                "meraki ms",
                "arubaos-cx",
                "aruba 29",
                "aruba 25",
                "procurve",
                "ex2300",
                "ex3400",
                "ex4300",
                "fortiswitch",
                "unifi switch",
                "usw-",
                "crs3",
            ])
        {
            return DeviceRole::Switch;
        }
        if has(Capability::Router)
            || any(&["router", "isr", "asr", "routeros", "edgerouter", "ubnt er"])
        {
            return DeviceRole::Router;
        }
        DeviceRole::Host
    }
}

// ---------------------------------------------------------------------------------------------
// Switch port mapping (CAM table)
// ---------------------------------------------------------------------------------------------

/// A MAC address learned on a physical switch port (from SNMP bridge MIB or CDP/LLDP).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SwitchPortMapping {
    pub switch_name: String,
    pub switch_ip: Option<IpAddr>,
    /// Interface name such as `Gi1/0/24` (falls back to the bridge port number).
    pub port_name: String,
    pub port_index: Option<u32>,
    pub vlan_id: Option<u16>,
    pub mac: String,
    /// PoE delivered on this port, when the switch reported POWER-ETHERNET-MIB data for it.
    #[serde(default)]
    pub poe: Option<PoeInfo>,
    /// Voice VLAN configured on this port (Cisco `vmVoiceVlanId`), when reported.
    #[serde(default)]
    pub voice_vlan: Option<u16>,
}

impl SwitchPortMapping {
    /// `Cisco-SW01 [Gi1/0/24]`
    pub fn label(&self) -> String {
        format!("{} [{}]", self.switch_name, self.port_name)
    }
}

// ---------------------------------------------------------------------------------------------
// Deeper discovery: service / identity info (SSDP/UPnP, WSD/ONVIF, SIP, PoE, DHCP)
// ---------------------------------------------------------------------------------------------

/// Longest service-type / header list kept from a single device.
pub const MAX_SERVICE_LIST: usize = 64;

/// What an SSDP/UPnP device advertised and what its description XML reported. Only filled
/// when the description was fetched from the responder's own IP (no SSRF through LOCATION).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SsdpInfo {
    /// The `LOCATION` URL of the device description (as advertised).
    pub location: Option<String>,
    /// SSDP `SERVER` header (OS / product / UPnP version).
    pub server: Option<String>,
    /// Search target / notification type (`ST` / `NT`).
    pub search_target: Option<String>,
    /// Unique service name (`USN`).
    pub usn: Option<String>,
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_number: Option<String>,
    pub model_description: Option<String>,
    pub serial_number: Option<String>,
    /// UPnP `deviceType` URN, e.g. `urn:schemas-upnp-org:device:MediaServer:1`.
    pub device_type: Option<String>,
    /// Unique device name (`UDN`, usually `uuid:...`).
    pub udn: Option<String>,
    pub presentation_url: Option<String>,
    /// Advertised UPnP service types (capped at [`MAX_SERVICE_LIST`]).
    pub services: Vec<String>,
}

/// WS-Discovery / ONVIF data learned over UDP 3702 and (for cameras) the device's own HTTP
/// `GetDeviceInformation` service. No credentials are ever sent; RTSP URLs are only reported
/// when the device itself returned one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OnvifInfo {
    /// Transport addresses (`XAddrs`) the device published (capped).
    pub xaddrs: Vec<String>,
    /// WS-Discovery `Types` (e.g. `dn:NetworkVideoTransmitter`, `wsdp:Computer`).
    pub types: Option<String>,
    /// WS-Discovery `Scopes` (onvif://www.onvif.org/name/…, hardware/…, location/…), capped.
    pub scopes: Vec<String>,
    pub name: Option<String>,
    pub location: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
    pub serial_number: Option<String>,
    pub hardware_id: Option<String>,
    /// `true` for an ONVIF Network Video Transmitter (IP camera).
    pub is_camera: bool,
    /// `true` for a Windows host that answered WSD (`wsdp:Device`/`pub:Computer`).
    pub is_windows: bool,
    /// RTSP stream URL the device itself reported (unauthenticated `GetStreamUri`); never a
    /// guess.
    pub rtsp_url: Option<String>,
    /// Common vendor RTSP URL templates, clearly labelled as guesses (never credentials).
    pub rtsp_hints: Vec<String>,
}

/// SIP endpoint role hint (stored as a string field, not a [`DeviceRole`] variant).
pub const DEVICE_KIND_VOIP_PHONE: &str = "voip_phone";
pub const DEVICE_KIND_PBX: &str = "pbx";

/// What a SIP OPTIONS probe revealed about a VoIP endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SipInfo {
    /// Status line text, e.g. `200 OK` or `405 Method Not Allowed` (still identifies a device).
    pub status: Option<String>,
    pub server: Option<String>,
    pub user_agent: Option<String>,
    pub allow: Option<String>,
    pub supported: Option<String>,
    /// Transport the response came over (`udp` or `tcp`).
    pub transport: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware: Option<String>,
    /// `voip_phone` or `pbx` when identified (mirrors [`Device::device_kind`]).
    pub kind: Option<String>,
}

/// Power-over-Ethernet delivery to one port / endpoint, from CDP/LLDP power TLVs or SNMP
/// POWER-ETHERNET-MIB. Watts are real values; `max_watts` is the allocated / classified budget.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PoeInfo {
    pub watts: Option<f32>,
    pub max_watts: Option<f32>,
    /// IEEE PoE class (0-4, or 5-8 for 802.3bt).
    pub class: Option<u8>,
    /// `delivering` / `searching` / `disabled` / `fault` / `test` (POWER-ETHERNET-MIB
    /// detection status).
    pub status: Option<String>,
    /// Power source from the PD's point of view (`pse` / `local` / `pse+local`), from the
    /// LLDP-MED / 802.3at power TLVs.
    pub source: Option<String>,
    /// Power priority (`critical` / `high` / `low`) from LLDP-MED / CDP.
    pub priority: Option<String>,
    pub switch_name: Option<String>,
    pub port: Option<String>,
}

impl PoeInfo {
    pub fn is_empty(&self) -> bool {
        self.watts.is_none()
            && self.max_watts.is_none()
            && self.class.is_none()
            && self.status.is_none()
            && self.source.is_none()
            && self.priority.is_none()
    }
}

/// Switch-wide PoE budget (POWER-ETHERNET-MIB `pethMainPse`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PoeBudget {
    /// Nominal power of the PSE in watts (summed over groups).
    pub nominal_watts: Option<f32>,
    /// Measured power currently consumed in watts (summed over groups).
    pub consumed_watts: Option<f32>,
    /// Usage threshold percentage at which the PSE warns.
    pub usage_threshold_pct: Option<u8>,
    /// Ports currently delivering power.
    pub ports_delivering: u32,
}

/// Result of a single-host service probe (the GUI `discover_services` command): unicast SSDP
/// `M-SEARCH`, unicast WS-Discovery `Probe` (+ ONVIF / WSD metadata) and SIP OPTIONS.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ServiceDiscovery {
    pub ip: Option<IpAddr>,
    pub device_kind: Option<String>,
    pub ssdp: Option<SsdpInfo>,
    pub onvif: Option<OnvifInfo>,
    pub sip: Option<SipInfo>,
}

/// Passive DHCP fingerprint attributed to a client from its DISCOVER / REQUEST options.
/// Best-effort heuristic (see the signature table in `data/dhcp_fingerprints.tsv`), never
/// authoritative.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DhcpFingerprint {
    /// Guessed OS family / version, when a signature matched.
    pub os: Option<String>,
    /// `high` / `medium` / `low`.
    pub confidence: Option<String>,
    /// DHCP option 60 vendor class identifier.
    pub vendor_class: Option<String>,
    /// DHCP option 12 hostname.
    pub hostname: Option<String>,
    /// DHCP option 55 parameter request list (the ordered option codes).
    pub param_list: Vec<u8>,
}

// ---------------------------------------------------------------------------------------------
// Device
// ---------------------------------------------------------------------------------------------

impl DhcpFingerprint {
    /// How much a fingerprint says: confidence of the OS match first, then the raw evidence.
    pub fn evidence_rank(&self) -> (u8, bool, usize, bool, bool) {
        let confidence = match self.confidence.as_deref() {
            Some("high") => 3,
            Some("medium") => 2,
            Some("low") => 1,
            _ => 0,
        };
        (
            confidence,
            self.os.is_some(),
            self.param_list.len(),
            self.vendor_class.is_some(),
            self.hostname.is_some(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub ip: IpAddr,
    /// Additional addresses of the same host (e.g. IPv6 link-local / global for an IPv4 key).
    pub extra_ips: Vec<IpAddr>,
    pub mac: Option<String>,
    pub vlan_id: Option<u16>,
    pub role: DeviceRole,
    /// User-assigned label (persisted locally by the GUI).
    pub hostname: Option<String>,
    pub dns_name: Option<String>,
    pub mdns_name: Option<String>,
    pub smb_name: Option<String>,
    pub smb_domain: Option<String>,
    pub vendor: Option<String>,
    pub switch_port: Option<SwitchPortMapping>,
    pub open_ports: Vec<u16>,
    pub comments: Option<String>,
    pub interface: Option<String>,
    pub rtt_ms: Option<f32>,
    /// Voice VLAN the port serves (CDP voice VLAN / LLDP-MED network policy / SNMP).
    #[serde(default)]
    pub voice_vlan: Option<u16>,
    /// A finer device category than [`DeviceRole`] (e.g. `voip_phone`, `pbx`, `tv`, `printer`,
    /// `nas`, `media_server`, `camera`, `igd_router`). Set from service discovery; additive.
    #[serde(default)]
    pub device_kind: Option<String>,
    /// SSDP/UPnP identity (model, serial, services).
    #[serde(default)]
    pub ssdp: Option<SsdpInfo>,
    /// WS-Discovery / ONVIF identity (cameras, Windows hosts).
    #[serde(default)]
    pub onvif: Option<OnvifInfo>,
    /// SIP OPTIONS identity (VoIP phones / PBXes).
    #[serde(default)]
    pub sip: Option<SipInfo>,
    /// Power-over-Ethernet drawn by this endpoint (from its switch port).
    #[serde(default)]
    pub poe: Option<PoeInfo>,
    /// Passive DHCP OS fingerprint.
    #[serde(default)]
    pub dhcp_fingerprint: Option<DhcpFingerprint>,
    pub sources: Vec<DiscoverySource>,
    pub neighbor: Option<CdpLldpNeighbor>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    /// Rolling latency statistics (latency monitor). The engine never fills this during a
    /// scan; the GUI copies it from `latency-update` events (like overrides) so exports
    /// carry it.
    #[serde(default)]
    pub latency: Option<LatencyStats>,
    /// HTML `<title>` of the device's web interface (sanitized, entity-decoded).
    #[serde(default)]
    pub web_title: Option<String>,
    /// HTTP `Server` header of the device's web interface.
    #[serde(default)]
    pub web_server: Option<String>,
    /// TLS certificate presented by the device's HTTPS interface.
    #[serde(default)]
    pub tls_cert: Option<TlsCertInfo>,
    /// Appliance / product recognized from the web title, server header or certificate
    /// (e.g. "Proxmox VE", "Dell iDRAC").
    #[serde(default)]
    pub web_identity: Option<String>,
    /// Problems worth flagging (expired / expiring / self-signed certificates, ...).
    #[serde(default)]
    pub warnings: Vec<String>,
    /// `true` when the passive DHCP capture saw this host answer as a DHCP server
    /// (OFFER / ACK). Feeds the rogue-DHCP audit rule. Additive.
    #[serde(default)]
    pub dhcp_server: Option<bool>,
    /// `true` when this host sent an IPv6 router advertisement during the scan. Feeds the
    /// rogue-RA audit rule. Additive.
    #[serde(default)]
    pub ipv6_router: Option<bool>,
    /// Where `role` came from; `None` for a plain host (or a role from an older save).
    /// Additive.
    #[serde(default)]
    pub role_source: Option<RoleSource>,
    /// How sure `role` is; `None` for a plain host. An infrastructure role without one (older
    /// saves) is treated as `medium`. Additive.
    #[serde(default)]
    pub role_confidence: Option<RoleConfidence>,
    /// Human-readable reasons behind `role` (e.g. "mDNS name 'switch375bc6.local' is a Cisco
    /// Business default host name", "Cisco OUI"). A host can carry hints too ("possible
    /// network device: Ruijie OUI"). At most [`MAX_ROLE_EVIDENCE`]. Additive.
    #[serde(default)]
    pub role_evidence: Vec<String>,
    /// DNS-SD service types the device advertised over mDNS (e.g. `_http._tcp`,
    /// `_csco-sb._tcp`). At most [`MAX_MDNS_SERVICES`]. Additive.
    #[serde(default)]
    pub mdns_services: Vec<String>,
}

/// Most mDNS service types kept on one device.
pub const MAX_MDNS_SERVICES: usize = 16;

/// Most warnings kept on one device (hostile-input bound).
pub const MAX_DEVICE_WARNINGS: usize = 32;

impl Device {
    pub fn new(ip: IpAddr) -> Self {
        let now = now_ms();
        Self {
            ip,
            extra_ips: Vec::new(),
            mac: None,
            vlan_id: None,
            role: DeviceRole::Host,
            hostname: None,
            dns_name: None,
            mdns_name: None,
            smb_name: None,
            smb_domain: None,
            vendor: None,
            switch_port: None,
            open_ports: Vec::new(),
            comments: None,
            interface: None,
            rtt_ms: None,
            voice_vlan: None,
            device_kind: None,
            ssdp: None,
            onvif: None,
            sip: None,
            poe: None,
            dhcp_fingerprint: None,
            sources: Vec::new(),
            neighbor: None,
            first_seen_ms: now,
            last_seen_ms: now,
            latency: None,
            web_title: None,
            web_server: None,
            tls_cert: None,
            web_identity: None,
            warnings: Vec::new(),
            dhcp_server: None,
            ipv6_router: None,
            role_source: None,
            role_confidence: None,
            role_evidence: Vec::new(),
            mdns_services: Vec::new(),
        }
    }

    /// Set an infrastructure role with its provenance (replacing the previous evidence).
    pub fn set_role(
        &mut self,
        role: DeviceRole,
        source: RoleSource,
        confidence: RoleConfidence,
        evidence: Vec<String>,
    ) {
        self.role = role;
        self.role_source = Some(source);
        self.role_confidence = Some(confidence);
        self.role_evidence = evidence;
        self.role_evidence.truncate(MAX_ROLE_EVIDENCE);
    }

    /// Effective confidence of `role`: `None` for a plain host, `medium` for an
    /// infrastructure role recorded without one (older saves, legacy code paths).
    pub fn effective_role_confidence(&self) -> Option<RoleConfidence> {
        if self.role.is_infrastructure() {
            Some(self.role_confidence.unwrap_or(RoleConfidence::Medium))
        } else {
            None
        }
    }

    /// `true` for an infrastructure role better than a low-confidence guess.
    pub fn is_confident_infrastructure(&self) -> bool {
        self.effective_role_confidence() > Some(RoleConfidence::Low)
    }

    /// Add one role-evidence line unless present (bounded by [`MAX_ROLE_EVIDENCE`]).
    pub fn add_role_evidence(&mut self, line: impl Into<String>) {
        let line = line.into();
        if self.role_evidence.len() < MAX_ROLE_EVIDENCE && !self.role_evidence.contains(&line) {
            self.role_evidence.push(line);
        }
    }

    /// Fold `other`'s role observation into this one:
    ///
    /// * a plain-host observation never replaces an infrastructure role (no downgrade);
    /// * otherwise the more confident observation wins, and between equally confident ones
    ///   the higher [`DeviceRole::priority`] wins (the historical rule);
    /// * the winner's source / confidence / evidence come with it; a same-role observation
    ///   adds its evidence, and host-level hints ("possible network device") accumulate.
    pub fn merge_role(&mut self, other: &Device) {
        let (mine, theirs) = (
            self.effective_role_confidence(),
            other.effective_role_confidence(),
        );
        let take = other.role.is_infrastructure()
            && (theirs > mine || (theirs == mine && other.role.priority() > self.role.priority()));
        if take {
            self.role = other.role;
            self.role_source = other.role_source;
            self.role_confidence = other.role_confidence;
            self.role_evidence = other.role_evidence.clone();
            self.role_evidence.truncate(MAX_ROLE_EVIDENCE);
            return;
        }
        if other.role == self.role {
            if self.role_source.is_none() {
                self.role_source = other.role_source;
            }
            if self.role_confidence.is_none() {
                self.role_confidence = other.role_confidence;
            }
            for e in &other.role_evidence {
                self.add_role_evidence(e.clone());
            }
        }
    }

    /// Add a warning unless it is already present (bounded by [`MAX_DEVICE_WARNINGS`]).
    pub fn add_warning(&mut self, warning: impl Into<String>) {
        let warning = warning.into();
        if self.warnings.len() < MAX_DEVICE_WARNINGS && !self.warnings.contains(&warning) {
            self.warnings.push(warning);
        }
    }

    /// Identity used for de-duplication: the same IP seen on different VLANs is a different row.
    pub fn key(&self) -> String {
        match self.vlan_id {
            Some(v) => format!("{}@{}", self.ip, v),
            None => self.ip.to_string(),
        }
    }

    /// First available name, preferring the user label.
    pub fn display_name(&self) -> Option<&str> {
        [
            &self.hostname,
            &self.dns_name,
            &self.mdns_name,
            &self.smb_name,
        ]
        .into_iter()
        .find_map(|n| n.as_deref().filter(|s| !s.is_empty()))
    }

    pub fn add_source(&mut self, source: DiscoverySource) {
        if !self.sources.contains(&source) {
            self.sources.push(source);
        }
    }

    /// Fold a newer observation of the same device into this one. Existing values are kept;
    /// gaps are filled from `other`; port/IP/source sets are unioned.
    pub fn merge(&mut self, other: &Device) {
        macro_rules! fill {
            ($($f:ident),+ $(,)?) => {
                $( if self.$f.is_none() { self.$f = other.$f.clone(); } )+
            };
        }
        fill!(
            mac,
            vlan_id,
            hostname,
            dns_name,
            mdns_name,
            smb_name,
            smb_domain,
            vendor,
            switch_port,
            comments,
            interface,
            rtt_ms,
            neighbor,
            web_title,
            web_server,
            tls_cert,
            web_identity,
            voice_vlan,
            device_kind,
            ssdp,
            onvif,
            sip,
            poe
        );
        // Role observations: once seen, they stick.
        for (mine, theirs) in [
            (&mut self.dhcp_server, other.dhcp_server),
            (&mut self.ipv6_router, other.ipv6_router),
        ] {
            if theirs == Some(true) || mine.is_none() {
                *mine = mine.filter(|v| *v).or(theirs);
            }
        }
        // DHCP fingerprint: the observation with more evidence wins (an early DISCOVER with
        // nothing matched must not shadow a later, identified REQUEST).
        if let Some(o) = &other.dhcp_fingerprint {
            if self
                .dhcp_fingerprint
                .as_ref()
                .is_none_or(|s| o.evidence_rank() > s.evidence_rank())
            {
                self.dhcp_fingerprint = Some(o.clone());
            }
        }
        // Live statistics: the newest snapshot wins.
        match (&mut self.latency, &other.latency) {
            (None, Some(o)) => self.latency = Some(o.clone()),
            (Some(s), Some(o)) if o.updated_ms >= s.updated_ms => *s = o.clone(),
            _ => {}
        }
        for w in &other.warnings {
            self.add_warning(w.clone());
        }
        self.merge_role(other);
        for s in &other.mdns_services {
            if self.mdns_services.len() < MAX_MDNS_SERVICES && !self.mdns_services.contains(s) {
                self.mdns_services.push(s.clone());
            }
        }
        for ip in other.extra_ips.iter().chain(std::iter::once(&other.ip)) {
            if *ip != self.ip && !self.extra_ips.contains(ip) {
                self.extra_ips.push(*ip);
            }
        }
        for p in &other.open_ports {
            if !self.open_ports.contains(p) {
                self.open_ports.push(*p);
            }
        }
        self.open_ports.sort_unstable();
        for s in &other.sources {
            self.add_source(*s);
        }
        self.first_seen_ms = self.first_seen_ms.min(other.first_seen_ms);
        self.last_seen_ms = self.last_seen_ms.max(other.last_seen_ms);
    }
}

// ---------------------------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceKind {
    Ethernet,
    Wifi,
    /// 802.1Q sub-interface (`vlan0`, `en0.100`, `eth0.10`).
    Vlan,
    Bridge,
    Vpn,
    Virtual,
    Loopback,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IfAddr {
    pub ip: IpAddr,
    pub prefix: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceInfo {
    pub name: String,
    pub index: u32,
    pub description: Option<String>,
    pub mac: Option<String>,
    pub addrs: Vec<IfAddr>,
    pub is_up: bool,
    pub kind: InterfaceKind,
    /// VLAN ID when this is an 802.1Q sub-interface.
    pub vlan_id: Option<u16>,
    /// Parent interface of a VLAN sub-interface.
    pub parent: Option<String>,
    /// `true` for the interface carrying the default route.
    pub is_default: bool,
}

impl InterfaceInfo {
    pub fn ipv4_addrs(&self) -> impl Iterator<Item = (Ipv4Addr, u8)> + '_ {
        self.addrs.iter().filter_map(|a| match a.ip {
            IpAddr::V4(v4) => Some((v4, a.prefix)),
            _ => None,
        })
    }

    pub fn primary_ipv4(&self) -> Option<(Ipv4Addr, u8)> {
        self.ipv4_addrs().next()
    }

    /// The fe80::/10 address of the interface, used as the source for NDP probes.
    pub fn link_local_v6(&self) -> Option<Ipv6Addr> {
        self.addrs.iter().find_map(|a| match a.ip {
            IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80 => Some(v6),
            _ => None,
        })
    }

    /// Global unicast and ULA (fc00::/7) addresses of the interface with their prefix length.
    pub fn routable_v6(&self) -> impl Iterator<Item = (Ipv6Addr, u8)> + '_ {
        self.addrs.iter().filter_map(|a| match a.ip {
            IpAddr::V6(v6) if is_routable_v6(v6) => Some((v6, a.prefix)),
            _ => None,
        })
    }

    /// `true` when `ip` is link-local or inside one of this interface's IPv6 prefixes.
    pub fn is_on_link_v6(&self, ip: Ipv6Addr) -> bool {
        is_link_local_v6(ip)
            || self
                .routable_v6()
                .any(|(net, prefix)| same_v6_prefix(ip, net, prefix))
    }

    /// The directly connected IPv4 subnet (host range), e.g. `10.177.134.1-10.177.134.254`.
    pub fn local_subnet(&self) -> Option<Ipv4Range> {
        let (ip, prefix) = self.primary_ipv4()?;
        Ipv4Range::from_cidr(ip, prefix).ok()
    }
}

/// `true` for fe80::/10.
pub fn is_link_local_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// `true` for global unicast (2000::/3) and unique-local (fc00::/7) addresses.
pub fn is_routable_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    (first & 0xe000) == 0x2000 || (first & 0xfe00) == 0xfc00
}

/// `true` when `a` and `b` share their first `prefix` bits.
pub fn same_v6_prefix(a: Ipv6Addr, b: Ipv6Addr, prefix: u8) -> bool {
    let prefix = u32::from(prefix.min(128));
    if prefix == 0 {
        return true;
    }
    let mask = u128::MAX << (128 - prefix);
    (u128::from(a) & mask) == (u128::from(b) & mask)
}

// ---------------------------------------------------------------------------------------------
// IPv4 target ranges
// ---------------------------------------------------------------------------------------------

/// An inclusive range of IPv4 addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv4Range {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
}

impl Ipv4Range {
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Result<Self, ModelError> {
        if u32::from(start) > u32::from(end) {
            return Err(ModelError::InvalidRange(format!(
                "{start}-{end} is descending"
            )));
        }
        Ok(Self { start, end })
    }

    /// Host range of `addr/prefix`. Network and broadcast addresses are excluded for prefixes
    /// up to /30; /31 and /32 return every address.
    pub fn from_cidr(addr: Ipv4Addr, prefix: u8) -> Result<Self, ModelError> {
        if prefix > 32 {
            return Err(ModelError::InvalidRange(format!(
                "{addr}/{prefix}: prefix > 32"
            )));
        }
        let mask: u32 = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let net = u32::from(addr) & mask;
        let bcast = net | !mask;
        if prefix >= 31 {
            Self::new(Ipv4Addr::from(net), Ipv4Addr::from(bcast))
        } else {
            Self::new(Ipv4Addr::from(net + 1), Ipv4Addr::from(bcast - 1))
        }
    }

    /// Number of addresses in the range (up to 2^32).
    pub fn count(&self) -> u64 {
        u64::from(u32::from(self.end)) - u64::from(u32::from(self.start)) + 1
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let v = u32::from(ip);
        v >= u32::from(self.start) && v <= u32::from(self.end)
    }

    pub fn iter(&self) -> impl Iterator<Item = Ipv4Addr> {
        (u32::from(self.start)..=u32::from(self.end)).map(Ipv4Addr::from)
    }
}

impl FromStr for Ipv4Range {
    type Err = ModelError;

    /// Accepts `10.0.0.0/24`, `10.0.0.1-10.0.0.50`, `10.0.0.1-50` (last-octet shorthand) and `10.0.0.5`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let bad = |why: &str| ModelError::InvalidRange(format!("'{s}': {why}"));

        if let Some((ip, prefix)) = s.split_once('/') {
            let ip: Ipv4Addr = ip.parse().map_err(|_| bad("bad address"))?;
            let prefix: u8 = prefix.parse().map_err(|_| bad("bad prefix length"))?;
            return Self::from_cidr(ip, prefix);
        }
        if let Some((a, b)) = s.split_once('-') {
            let start: Ipv4Addr = a.trim().parse().map_err(|_| bad("bad start address"))?;
            let b = b.trim();
            let end: Ipv4Addr = match b.parse::<Ipv4Addr>() {
                Ok(ip) => ip,
                Err(_) => {
                    let last: u8 = b.parse().map_err(|_| bad("bad end address"))?;
                    let o = start.octets();
                    Ipv4Addr::new(o[0], o[1], o[2], last)
                }
            };
            return Self::new(start, end);
        }
        let ip: Ipv4Addr = s
            .parse()
            .map_err(|_| bad("not an IPv4 address, range or CIDR"))?;
        Self::new(ip, ip)
    }
}

impl fmt::Display for Ipv4Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

/// Parse a comma/whitespace separated list of targets (`10.0.0.0/24, 10.1.0.5-20`).
pub fn parse_targets(spec: &str) -> Result<Vec<Ipv4Range>, ModelError> {
    let ranges = spec
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|p| !p.is_empty())
        .map(str::parse)
        .collect::<Result<Vec<Ipv4Range>, _>>()?;
    if ranges.is_empty() {
        return Err(ModelError::InvalidRange("empty target list".into()));
    }
    Ok(ranges)
}

/// Parse a port list such as `22,80,443` or `1-1024,8443`.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, ModelError> {
    let mut ports = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let parse = |t: &str| -> Result<u16, ModelError> {
            t.trim()
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| ModelError::InvalidPort(format!("'{t}'")))
        };
        if let Some((a, b)) = part.split_once('-') {
            let (lo, hi) = (parse(a)?, parse(b)?);
            if lo > hi {
                return Err(ModelError::InvalidPort(format!(
                    "descending range '{part}'"
                )));
            }
            ports.extend(lo..=hi);
        } else {
            ports.push(parse(part)?);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Err(ModelError::InvalidPort(format!("no ports in '{spec}'")));
    }
    Ok(ports)
}

// ---------------------------------------------------------------------------------------------
// SNMP & scan configuration
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnmpVersion {
    V1,
    #[default]
    V2c,
    V3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnmpAuthProtocol {
    Md5,
    #[default]
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnmpPrivProtocol {
    Des,
    #[default]
    Aes128,
    Aes192,
    Aes256,
}

#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SnmpV3Credentials {
    pub username: String,
    pub auth_protocol: SnmpAuthProtocol,
    pub auth_password: Option<String>,
    pub priv_protocol: SnmpPrivProtocol,
    pub priv_password: Option<String>,
}

// Secrets must never end up in logs.
impl fmt::Debug for SnmpV3Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnmpV3Credentials")
            .field("username", &self.username)
            .field("auth_protocol", &self.auth_protocol)
            .field(
                "auth_password",
                &self.auth_password.as_ref().map(|_| "<redacted>"),
            )
            .field("priv_protocol", &self.priv_protocol)
            .field(
                "priv_password",
                &self.priv_password.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SnmpConfig {
    pub version: SnmpVersion,
    pub community: String,
    pub v3: Option<SnmpV3Credentials>,
    pub port: u16,
    pub timeout_ms: u64,
    pub retries: u8,
}

// The community string is a shared secret: never print it.
impl fmt::Debug for SnmpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnmpConfig")
            .field("version", &self.version)
            .field("community", &"<redacted>")
            .field("v3", &self.v3)
            .field("port", &self.port)
            .field("timeout_ms", &self.timeout_ms)
            .field("retries", &self.retries)
            .finish()
    }
}

/// RFC 3414 (section 11.2) requires SNMPv3 passwords of at least 8 characters; the key
/// localization of shorter (and especially empty) passwords is undefined.
pub const MIN_SNMPV3_PASSWORD_LEN: usize = 8;

impl Default for SnmpConfig {
    fn default() -> Self {
        Self {
            version: SnmpVersion::V2c,
            community: "public".into(),
            v3: None,
            port: 161,
            timeout_ms: 2000,
            retries: 1,
        }
    }
}

impl SnmpConfig {
    pub fn v2c(community: impl Into<String>) -> Self {
        Self {
            community: community.into(),
            ..Self::default()
        }
    }

    /// Validate the SNMP settings in isolation. Used by [`ScanConfig::validate`], the CLI and
    /// the GUI `query_snmp` command.
    ///
    /// * The UDP port must not be 0; timeout and retries are bounded.
    /// * SNMPv3 needs a username; any password given must be at least
    ///   [`MIN_SNMPV3_PASSWORD_LEN`] characters (RFC 3414), and a privacy password needs an
    ///   authentication password (there is no noAuthPriv security level).
    pub fn validate(&self) -> Result<(), ModelError> {
        let invalid = |m: &str| Err(ModelError::InvalidConfig(m.into()));
        if self.port == 0 {
            return invalid("snmp.port must be between 1 and 65535");
        }
        if self.version == SnmpVersion::V3 {
            let Some(creds) = self.v3.as_ref().filter(|c| !c.username.is_empty()) else {
                return invalid("SNMPv3 requires a username");
            };
            for (name, pw) in [
                ("authentication", &creds.auth_password),
                ("privacy", &creds.priv_password),
            ] {
                if let Some(pw) = pw {
                    if pw.chars().count() < MIN_SNMPV3_PASSWORD_LEN {
                        return Err(ModelError::InvalidConfig(format!(
                            "the SNMPv3 {name} password must be at least \
                             {MIN_SNMPV3_PASSWORD_LEN} characters (RFC 3414)"
                        )));
                    }
                }
            }
            if creds.auth_password.is_none() && creds.priv_password.is_some() {
                return invalid(
                    "SNMPv3 privacy requires an authentication password (there is no \
                     noAuthPriv security level)",
                );
            }
        }
        if !(1..=MAX_TIMEOUT_MS).contains(&self.timeout_ms) {
            return Err(ModelError::InvalidConfig(format!(
                "snmp.timeout_ms must be between 1 and {MAX_TIMEOUT_MS}"
            )));
        }
        if u64::from(self.retries) > MAX_RETRIES {
            return Err(ModelError::InvalidConfig(format!(
                "snmp.retries must be at most {MAX_RETRIES}"
            )));
        }
        Ok(())
    }
}

/// Upper bounds enforced by [`ScanConfig::validate`]. They keep arithmetic (deadlines,
/// pacing intervals, semaphore permits) far from overflow and reject nonsense input early.
pub const MAX_RATE_PPS: u64 = 1_000_000;
/// Maximum in-flight async probes (well below `tokio::sync::Semaphore::MAX_PERMITS`).
pub const MAX_CONCURRENCY: usize = 65_535;
/// Reply timeout / grace period ceiling (10 minutes).
pub const MAX_TIMEOUT_MS: u64 = 600_000;
pub const MAX_RETRIES: u64 = 10;
/// Passive listening ceiling (one day).
pub const MAX_LISTEN_SECS: u64 = 86_400;

/// serde default for boolean fields that default to `true` when absent from GUI JSON.
fn default_true() -> bool {
    true
}

/// Everything a scan needs. Missing fields in JSON (from the GUI) fall back to [`Default`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ScanConfig {
    /// Interface name (`en0`, `eth0`). `None` auto-selects the default-route interface.
    pub interface: Option<String>,
    /// Targets: CIDR, `a-b` range or comma-separated list. `None` scans the interface's subnet.
    pub range: Option<String>,
    pub vlans: VlanSelection,
    /// Passively sniff 802.1Q tags, CDP, LLDP, VTP and DTP while scanning.
    pub discover_vlans: bool,
    /// Listen for CDP/LLDP advertisements while scanning.
    pub cdp_lldp: bool,
    pub snmp: Option<SnmpConfig>,
    /// Poll every discovered host over SNMP instead of only likely infrastructure (gateway,
    /// CDP/LLDP neighbors, hosts with management ports open, network-vendor MACs, devices
    /// already classified as infrastructure). Slow on large ranges.
    pub snmp_all: bool,
    /// Discover IPv6 link-local / global addresses via ICMPv6 NDP.
    pub ipv6: bool,
    pub ports: Vec<u16>,
    /// Resolve DNS PTR / mDNS / NetBIOS names for each device.
    pub resolve_names: bool,
    /// Probe discovered hosts for services during enrichment: SSDP/UPnP (model/serial),
    /// WS-Discovery + ONVIF (cameras, Windows hosts) and SIP OPTIONS (VoIP phones / PBXes).
    /// On by default (the CLI `--no-services` disables it).
    #[serde(default = "default_true")]
    pub discover_services: bool,
    /// Also probe every candidate with SIP OPTIONS, not only hosts with 5060 open or a VoIP
    /// vendor MAC (the CLI `--sip-all`). Only has effect when `discover_services` is on.
    #[serde(default)]
    pub sip_all: bool,
    /// Passively capture and fingerprint DHCP DISCOVER/REQUEST options to guess client OSes.
    /// Off by default: it needs raw packet capture (root / BPF), like the other sniffers.
    #[serde(default)]
    pub dhcp_fingerprint: bool,
    /// How long to wait for late replies after the last probe, in milliseconds.
    pub timeout_ms: u64,
    /// Extra probe passes over unanswered addresses.
    pub retries: u8,
    /// Raw-frame transmit rate limit (packets per second).
    pub rate_pps: u32,
    /// Max in-flight async probes (ICMP / TCP) for routed scans.
    pub concurrency: usize,
    /// Duration of the passive CDP/LLDP/VLAN listener in seconds.
    pub listen_secs: u64,
    /// Fetch the HTTP `<title>`, `Server` header and TLS certificate of devices with a web
    /// port open (needs the port scan, i.e. a non-empty `ports`).
    pub web_identity: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            interface: None,
            range: None,
            vlans: VlanSelection::Untagged,
            discover_vlans: false,
            cdp_lldp: false,
            snmp: None,
            snmp_all: false,
            ipv6: false,
            ports: DEFAULT_PORTS.to_vec(),
            resolve_names: true,
            discover_services: true,
            sip_all: false,
            dhcp_fingerprint: false,
            timeout_ms: 1500,
            retries: 1,
            rate_pps: 2000,
            concurrency: 512,
            listen_secs: 10,
            web_identity: true,
        }
    }
}

impl ScanConfig {
    /// Parse `range` (if set) into concrete IPv4 ranges.
    pub fn parse_ranges(&self) -> Result<Option<Vec<Ipv4Range>>, ModelError> {
        self.range.as_deref().map(parse_targets).transpose()
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.parse_ranges()?;
        if let VlanSelection::List(ids) | VlanSelection::UntaggedAndList(ids) = &self.vlans {
            if ids.is_empty() || ids.iter().any(|v| !(1..=MAX_VLAN_ID).contains(v)) {
                return Err(ModelError::InvalidVlan(format!(
                    "VLAN IDs must be 1-{MAX_VLAN_ID}"
                )));
            }
        }
        let bound = |name: &str, value: u64, min: u64, max: u64| {
            if (min..=max).contains(&value) {
                Ok(())
            } else {
                Err(ModelError::InvalidConfig(format!(
                    "{name} must be between {min} and {max} (got {value})"
                )))
            }
        };
        bound("rate_pps", u64::from(self.rate_pps), 1, MAX_RATE_PPS)?;
        bound(
            "concurrency",
            u64::try_from(self.concurrency).unwrap_or(u64::MAX),
            1,
            MAX_CONCURRENCY as u64,
        )?;
        bound("timeout_ms", self.timeout_ms, 0, MAX_TIMEOUT_MS)?;
        bound("retries", u64::from(self.retries), 0, MAX_RETRIES)?;
        bound("listen_secs", self.listen_secs, 0, MAX_LISTEN_SECS)?;
        if self.ports.contains(&0) {
            return Err(ModelError::InvalidPort("port 0".into()));
        }
        if let Some(snmp) = &self.snmp {
            snmp.validate()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// SNMP infrastructure poll result & device overrides
// ---------------------------------------------------------------------------------------------

/// MAC addresses learned on one switch port (used to flag uplink/trunk ports, which learn
/// far more MACs than an access port with a single endpoint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortMacCount {
    pub port_name: String,
    pub port_index: Option<u32>,
    pub mac_count: u32,
}

/// Everything a single SNMP poll of one infrastructure device yields. Serialized camelCase
/// for the GUI's `query_snmp` command and the CLI `snmp` subcommand.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnmpDeviceInfo {
    pub sys_name: Option<String>,
    pub sys_descr: Option<String>,
    pub sys_uptime_ticks: Option<u32>,
    pub sys_object_id: Option<String>,
    pub role: DeviceRole,
    pub vlans: Vec<VlanInfo>,
    pub port_mappings: Vec<SwitchPortMapping>,
    pub port_mac_counts: Vec<PortMacCount>,
    /// Switch-wide PoE budget (POWER-ETHERNET-MIB `pethMainPse`), when the device answered it.
    #[serde(default)]
    pub poe_budget: Option<PoeBudget>,
    /// `true` when some table walks failed or were cut short (timeout, device budget, row
    /// cap): the data above is what was collected before that happened.
    #[serde(default)]
    pub partial: bool,
    /// Why the result is partial (one line per failed or truncated walk).
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Longest override text kept (hostname / comments the user types in the GUI).
pub const MAX_OVERRIDE_LEN: usize = 1024;

/// A user-assigned label and free-form note for one device, persisted locally by the GUI.
/// The GUI applies overrides itself; the CLI scan path copies them into emitted [`Device`]s
/// (see `engine::ScanOptions`). Keyed by [`Device::key`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeviceOverride {
    pub hostname: Option<String>,
    pub comments: Option<String>,
}

impl DeviceOverride {
    /// Sanitize and length-cap both fields; empty strings become `None`. Returns `None` when
    /// nothing is left (so a cleared override can be dropped from the store).
    pub fn sanitized(hostname: Option<String>, comments: Option<String>) -> Option<Self> {
        let clean = |s: Option<String>| s.map(|t| sanitize_override(&t)).filter(|t| !t.is_empty());
        let o = DeviceOverride {
            hostname: clean(hostname),
            comments: clean(comments),
        };
        (o.hostname.is_some() || o.comments.is_some()).then_some(o)
    }
}

/// Like [`sanitize_text`] but with the larger [`MAX_OVERRIDE_LEN`] cap for user notes.
pub fn sanitize_override(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_OVERRIDE_LEN));
    let mut chars = 0usize;
    for c in s.chars() {
        let c = match c {
            '\t' | '\n' | '\r' | '\u{0b}' | '\u{0c}' => ' ',
            c if c.is_control() || is_bidi_or_invisible(c) => continue,
            c => c,
        };
        if chars == MAX_OVERRIDE_LEN {
            break;
        }
        out.push(c);
        chars += 1;
    }
    out.trim().to_string()
}

// ---------------------------------------------------------------------------------------------
// Streaming events (Tokio channel → CLI renderer / Tauri emitter)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanPhase {
    Preparing,
    Discovering,
    Enriching,
    Listening,
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub phase: ScanPhase,
    pub probes_sent: u64,
    pub probes_total: u64,
    pub devices_found: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub devices: u64,
    pub vlans: u64,
    pub neighbors: u64,
    pub elapsed_ms: u64,
    pub cancelled: bool,
    /// Interface the scan ran on (full scans only; additive, for report metadata).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// The scanning host's IPv4 default gateway, when known (full scans only; additive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<IpAddr>,
    /// The scanning host's name (full scans only; additive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanner_host: Option<String>,
    /// The job ended with an error or crashed (GUI jobs; an `error` log precedes the event).
    /// Additive: only serialized when `true`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub failed: bool,
}

/// This machine's host name (sanitized), for report metadata.
#[cfg(windows)]
pub fn local_hostname() -> Option<String> {
    crate::win::computer_name()
        .map(|n| sanitize_text(&n))
        .filter(|n| !n.is_empty())
}

/// This machine's host name (sanitized), for report metadata.
#[cfg(not(windows))]
pub fn local_hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is valid for `buf.len()` bytes; gethostname NUL-terminates on success
    // (or truncates; we stop at the first NUL or the end of the buffer).
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    let name = sanitize_text(&String::from_utf8_lossy(&buf[..end]));
    (!name.is_empty()).then_some(name)
}

/// The outcome of polling one SNMP agent during a scan (`snmp_agent` event). Carries the
/// community *class* only (`public` / `private` / `custom` / `none`, or `v3`), never the
/// community or SNMPv3 credentials. Additive: consumers that do not know the event ignore it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SnmpAgentStatus {
    pub ip: Option<IpAddr>,
    /// `v1`, `v2c` or `v3`.
    pub version: String,
    /// `public`, `private`, `custom`, `none` (v1/v2c) or `v3`.
    pub community_class: String,
    /// The agent returned data.
    pub answered: bool,
    /// Some table walks failed or were cut short.
    pub partial: bool,
    pub sys_name: Option<String>,
    pub sys_descr: Option<String>,
    pub role: Option<DeviceRole>,
    /// Switch-wide PoE budget, when the agent answered POWER-ETHERNET-MIB.
    pub poe_budget: Option<PoeBudget>,
    /// Why the result is partial (at most a few lines).
    pub warnings: Vec<String>,
}

impl SnmpConfig {
    /// The community class of this configuration (never the community itself).
    pub fn community_class(&self) -> &'static str {
        if self.version == SnmpVersion::V3 {
            return "v3";
        }
        match self.community.trim() {
            "" => "none",
            "public" => "public",
            "private" => "private",
            _ => "custom",
        }
    }

    pub fn version_label(&self) -> &'static str {
        match self.version {
            SnmpVersion::V1 => "v1",
            SnmpVersion::V2c => "v2c",
            SnmpVersion::V3 => "v3",
        }
    }
}

/// Messages streamed while a scan runs. Serialized as `{ "type": "...", "data": ... }`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ScanEvent {
    /// Boxed to keep the enum small; serializes exactly like an inline `Device`.
    Device(Box<Device>),
    Vlan(VlanInfo),
    Neighbor(CdpLldpNeighbor),
    PortMapping(SwitchPortMapping),
    /// One SNMP agent polled (answered or not), with its PoE budget. Added in the roadmap
    /// review; older consumers ignore it.
    SnmpAgent(Box<SnmpAgentStatus>),
    Progress(ScanProgress),
    Log {
        level: LogLevel,
        message: String,
    },
    Finished(ScanSummary),
}

impl ScanEvent {
    pub fn device(device: Device) -> Self {
        ScanEvent::Device(Box::new(device))
    }

    pub fn info(message: impl Into<String>) -> Self {
        ScanEvent::Log {
            level: LogLevel::Info,
            message: message.into(),
        }
    }

    pub fn warn(message: impl Into<String>) -> Self {
        ScanEvent::Log {
            level: LogLevel::Warn,
            message: message.into(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        ScanEvent::Log {
            level: LogLevel::Error,
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Network utilities: latency monitor, traceroute, web identity, iPerf3, Wake-on-LAN
// ---------------------------------------------------------------------------------------------

/// How a latency sample was measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeMethod {
    /// ICMP / ICMPv6 echo.
    #[default]
    Icmp,
    /// TCP connect round trip (SYN → SYN-ACK or RST), used when the host ignores ICMP.
    Tcp,
}

/// Rolling latency statistics of one host over the monitor window (its last
/// `latency::HISTORY_LEN` samples). Times are milliseconds; they stay `None` until a reply
/// arrives.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LatencyStats {
    pub last_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub min_ms: Option<f64>,
    pub max_ms: Option<f64>,
    /// Mean absolute difference between consecutive replies.
    pub jitter_ms: Option<f64>,
    /// Lost probes in the window, 0-100.
    pub loss_pct: f64,
    /// Probes in the window and replies among them.
    pub sent: u32,
    pub received: u32,
    pub method: ProbeMethod,
    /// When the newest sample was taken (Unix ms).
    pub updated_ms: u64,
}

/// One host's newest sample plus its rolling statistics (element of a `latency-update`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LatencySample {
    pub ip: IpAddr,
    /// Round trip of the newest probe; `None` when it was lost.
    pub rtt_ms: Option<f64>,
    /// When the newest probe was sent (Unix ms).
    pub ts: u64,
    pub method: ProbeMethod,
    pub loss_pct: f64,
    pub avg_ms: Option<f64>,
    pub min_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub sent: u32,
    pub received: u32,
    /// The whole window, oldest first (`null` = lost), for sparklines. In `latency-update`
    /// events it is sent on a host's first update and then at most every
    /// `latency::HISTORY_RESEND` (absent in between; consumers keep their own history from
    /// `newSamples`). Always present in final / CLI results.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<Option<f64>>>,
    /// Live updates only: every sample taken since the host's previous update, oldest first
    /// (`null` = lost; usually one).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub new_samples: Vec<Option<f64>>,
}

impl LatencySample {
    /// The statistics part, as stored on [`Device::latency`].
    pub fn stats(&self) -> LatencyStats {
        LatencyStats {
            last_ms: self.rtt_ms,
            avg_ms: self.avg_ms,
            min_ms: self.min_ms,
            max_ms: self.max_ms,
            jitter_ms: self.jitter_ms,
            loss_pct: self.loss_pct,
            sent: self.sent,
            received: self.received,
            method: self.method,
            updated_ms: self.ts,
        }
    }
}

/// Payload of the `latency-update` Tauri event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LatencyUpdate {
    pub monitor_id: u64,
    pub samples: Vec<LatencySample>,
}

/// How a traceroute was run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceMethod {
    /// Raw ICMP echo probes with increasing TTL (needs root / CAP_NET_RAW; not on Windows).
    Raw,
    /// The system `traceroute` / `traceroute6` / `tracepath` binary (Windows: `tracert`), run
    /// once per round.
    System,
}

/// MTR-style statistics of one hop.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceHop {
    pub ttl: u8,
    /// The address that answered most recently (`None` while the hop never answered).
    pub ip: Option<IpAddr>,
    /// Reverse-DNS name of `ip`.
    pub hostname: Option<String>,
    /// Other addresses that answered for this TTL (load-balanced paths), at most 4.
    #[serde(default)]
    pub other_ips: Vec<IpAddr>,
    pub sent: u32,
    pub received: u32,
    pub loss_pct: f64,
    pub last_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub best_ms: Option<f64>,
    pub worst_ms: Option<f64>,
}

/// Payload of the `trace-update` Tauri event (also the CLI's JSON output).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceUpdate {
    pub trace_id: u64,
    pub target: IpAddr,
    pub method: TraceMethod,
    /// Rounds completed so far / requested.
    pub round: u32,
    pub rounds: u32,
    /// Hops 1..=N, where N is the destination's TTL once it answered.
    pub hops: Vec<TraceHop>,
    /// `true` once the destination itself answered.
    pub reached: bool,
    /// `true` on the last update of the trace (finished, stopped or failed).
    pub done: bool,
    /// Why the trace failed (only on the final update).
    pub error: Option<String>,
}

/// Details of a server's TLS certificate (read without validating it).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TlsCertInfo {
    /// Port the certificate was read from.
    pub port: u16,
    pub subject_cn: Option<String>,
    /// Full subject DN, e.g. `CN=pve.lan, O=Proxmox`.
    pub subject: Option<String>,
    /// Subject alternative names (DNS names and IPs), at most 8.
    pub sans: Vec<String>,
    /// Total number of SANs in the certificate.
    pub san_count: u32,
    pub issuer_cn: Option<String>,
    pub issuer: Option<String>,
    /// Validity bounds, ISO 8601 UTC (`2026-01-31T12:00:00Z`).
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    /// Validity bounds as Unix milliseconds.
    pub not_before_ms: Option<i64>,
    pub not_after_ms: Option<i64>,
    /// Whole days until `notAfter` (negative once expired).
    pub days_remaining: Option<i64>,
    /// Issuer equals subject and the certificate verifies with its own key.
    pub self_signed: bool,
    pub expired: bool,
    /// `"RSA"`, `"EC P-256"`, `"Ed25519"`, ...
    pub key_type: Option<String>,
    pub key_bits: Option<u32>,
    pub signature_algorithm: Option<String>,
    /// SHA-256 fingerprint of the DER certificate, `AB:CD:...`.
    pub sha256: Option<String>,
}

/// Plain HTTP or HTTPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebScheme {
    Http,
    Https,
}

/// What one web port of a device answered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebService {
    pub port: u16,
    /// Scheme that answered on `port` (TLS is tried first on HTTPS-style ports).
    pub scheme: WebScheme,
    /// URL of the final response (after redirects).
    pub url: String,
    pub status: Option<u16>,
    pub title: Option<String>,
    pub server: Option<String>,
    /// Redirects followed (at most 2, same host only).
    pub redirects: u8,
    /// Where an unfollowed redirect pointed (other host, or the redirect limit was hit).
    pub redirect_to: Option<String>,
    pub tls_cert: Option<TlsCertInfo>,
    /// Why nothing (or only part) could be read.
    pub error: Option<String>,
}

/// Result of `grab_web_identity` / `sweepr web`, and what the scan copies onto a device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebIdentity {
    pub ip: IpAddr,
    /// One entry per probed port that accepted a connection.
    pub services: Vec<WebService>,
    /// Best title / server / certificate across the services (HTTPS first).
    pub title: Option<String>,
    pub server: Option<String>,
    pub tls_cert: Option<TlsCertInfo>,
    /// Recognized appliance, e.g. "Proxmox VE", "Synology DSM", "Fortinet FortiGate".
    pub identity: Option<String>,
    /// Role suggested by the identity (only ever applied to devices still classified as a
    /// plain host).
    pub role_hint: Option<DeviceRole>,
    /// Certificate problems (expired, expiring within 30 days, self-signed, not yet valid).
    pub warnings: Vec<String>,
}

/// Bounds of [`IperfOptions`].
pub const IPERF_MAX_DURATION_SECS: u32 = 60;
pub const IPERF_MAX_STREAMS: u8 = 16;

/// Options of one iPerf3 client run. Missing JSON fields use the defaults (TCP, port 5201,
/// 10 s, one stream, client → server).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct IperfOptions {
    pub port: u16,
    pub duration_secs: u32,
    /// Server sends, client receives (`-R`).
    pub reverse: bool,
    /// Parallel streams (`-P`), 1-16.
    pub streams: u8,
    pub udp: bool,
    /// Target bitrate (`-b`), e.g. `"100M"`, `"1G"`, `"500K"`, `"0"` (unlimited). UDP
    /// defaults to iperf3's 1 Mbit/s when omitted.
    pub bitrate: Option<String>,
}

impl Default for IperfOptions {
    fn default() -> Self {
        Self {
            port: 5201,
            duration_secs: 10,
            reverse: false,
            streams: 1,
            udp: false,
            bitrate: None,
        }
    }
}

/// `true` for `"0"`, `"100"`, `"100M"`, `"2.5G"`, `"500k"` (no other characters).
pub fn is_valid_bitrate(s: &str) -> bool {
    let s = s.trim();
    let digits = s
        .strip_suffix(['K', 'M', 'G', 'T', 'k', 'm', 'g', 't'])
        .unwrap_or(s);
    if digits.is_empty() || digits.len() > 12 {
        return false;
    }
    let mut dots = 0;
    for c in digits.chars() {
        match c {
            '0'..='9' => {}
            '.' => dots += 1,
            _ => return false,
        }
    }
    dots <= 1 && !digits.starts_with('.') && !digits.ends_with('.')
}

impl IperfOptions {
    pub fn validate(&self) -> Result<(), ModelError> {
        let invalid = |m: String| Err(ModelError::InvalidConfig(m));
        if self.port == 0 {
            return invalid("iperf port must be between 1 and 65535".into());
        }
        if !(1..=IPERF_MAX_DURATION_SECS).contains(&self.duration_secs) {
            return invalid(format!(
                "iperf duration must be 1-{IPERF_MAX_DURATION_SECS} seconds"
            ));
        }
        if !(1..=IPERF_MAX_STREAMS).contains(&self.streams) {
            return invalid(format!(
                "iperf parallel streams must be 1-{IPERF_MAX_STREAMS}"
            ));
        }
        if let Some(b) = &self.bitrate {
            if !is_valid_bitrate(b) {
                return invalid(format!(
                    "invalid bitrate '{}': use a number with an optional K/M/G/T suffix, e.g. 100M",
                    sanitize_text(b)
                ));
            }
        }
        Ok(())
    }
}

/// Whether the `iperf3` binary can be used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IperfAvailability {
    pub available: bool,
    pub path: Option<String>,
    /// e.g. `"3.17.1"`.
    pub version: Option<String>,
    /// `true` when the version streams per-interval results live (`--json-stream`, 3.17+);
    /// older versions report every interval at the end of the run.
    pub streaming: bool,
    /// How to install iperf3 when it is missing.
    pub install_hint: Option<String>,
}

/// One per-second (summed over streams) iPerf3 measurement.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct IperfInterval {
    /// Seconds since the test started.
    pub start: f64,
    pub end: f64,
    pub bytes: u64,
    pub bits_per_second: f64,
    /// TCP sender only.
    pub retransmits: Option<u64>,
    /// UDP only.
    pub jitter_ms: Option<f64>,
    pub lost_packets: Option<u64>,
    pub packets: Option<u64>,
    pub lost_percent: Option<f64>,
    /// Inside the `--omit` warm-up window.
    pub omitted: bool,
}

/// End-of-test iPerf3 totals.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct IperfSummary {
    /// `"tcp"` or `"udp"`.
    pub protocol: String,
    pub reverse: bool,
    pub streams: u32,
    pub duration_secs: f64,
    pub sent_bytes: Option<u64>,
    pub sent_bps: Option<f64>,
    pub received_bytes: Option<u64>,
    pub received_bps: Option<f64>,
    pub retransmits: Option<u64>,
    pub jitter_ms: Option<f64>,
    pub lost_packets: Option<u64>,
    pub packets: Option<u64>,
    pub lost_percent: Option<f64>,
    pub cpu_local_pct: Option<f64>,
    pub cpu_remote_pct: Option<f64>,
    /// `host:port` the client connected to, and the local iperf3 version (sanitized).
    pub remote_host: Option<String>,
    pub version: Option<String>,
}

/// Payload of the `iperf-update` Tauri event: one interval, or the final summary / error
/// (`done: true`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IperfUpdate {
    pub run_id: u64,
    pub interval: Option<IperfInterval>,
    pub summary: Option<IperfSummary>,
    pub done: bool,
    pub error: Option<String>,
}

/// What a Wake-on-LAN request sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WakeResult {
    /// Target MAC, canonical `aa:bb:cc:dd:ee:ff`.
    pub mac: String,
    /// Destinations as `addr:port`.
    pub targets: Vec<String>,
    pub packets_sent: u32,
    /// Interface the packets were sent from (when one was chosen).
    pub interface: Option<String>,
    pub source_ip: Option<IpAddr>,
    /// Destinations that could not be sent to, as `addr:port: error` (additive; empty when
    /// every send succeeded).
    #[serde(default)]
    pub failures: Vec<String>,
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// An early, unmatched DHCP fingerprint must not shadow a later identified one (review
    /// M2), whichever order they merge in.
    #[test]
    fn merge_prefers_the_dhcp_fingerprint_with_more_evidence() {
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        let mut early = Device::new(ip);
        early.dhcp_fingerprint = Some(DhcpFingerprint::default());
        let mut later = Device::new(ip);
        later.dhcp_fingerprint = Some(DhcpFingerprint {
            os: Some("Windows".into()),
            confidence: Some("high".into()),
            param_list: vec![1, 3, 6],
            ..Default::default()
        });
        let mut a = early.clone();
        a.merge(&later);
        assert_eq!(
            a.dhcp_fingerprint.as_ref().unwrap().os.as_deref(),
            Some("Windows")
        );
        let mut b = later.clone();
        b.merge(&early);
        assert_eq!(
            b.dhcp_fingerprint.as_ref().unwrap().os.as_deref(),
            Some("Windows")
        );
    }

    fn ip4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_excludes_network_and_broadcast() {
        let r: Ipv4Range = "10.177.134.0/24".parse().unwrap();
        assert_eq!(r.start, ip4("10.177.134.1"));
        assert_eq!(r.end, ip4("10.177.134.254"));
        assert_eq!(r.count(), 254);
        assert!(r.contains(ip4("10.177.134.77")));
        assert!(!r.contains(ip4("10.177.135.1")));
    }

    #[test]
    fn small_cidrs_keep_all_addresses() {
        assert_eq!("10.0.0.5/32".parse::<Ipv4Range>().unwrap().count(), 1);
        assert_eq!("10.0.0.4/31".parse::<Ipv4Range>().unwrap().count(), 2);
    }

    #[test]
    fn whole_ipv4_space_does_not_overflow() {
        let r: Ipv4Range = "0.0.0.0/0".parse().unwrap();
        assert_eq!(r.count(), (1u64 << 32) - 2);
        let all = Ipv4Range::new(ip4("0.0.0.0"), ip4("255.255.255.255")).unwrap();
        assert_eq!(all.count(), 1u64 << 32);
    }

    #[test]
    fn range_forms() {
        let r: Ipv4Range = "10.177.134.1-10.177.140.254".parse().unwrap();
        assert_eq!(r.count(), 6 * 256 + 254);
        let short: Ipv4Range = "192.168.1.10-20".parse().unwrap();
        assert_eq!(
            (short.start, short.end),
            (ip4("192.168.1.10"), ip4("192.168.1.20"))
        );
        assert_eq!("1.2.3.4".parse::<Ipv4Range>().unwrap().count(), 1);
        assert!("10.0.0.9-10.0.0.1".parse::<Ipv4Range>().is_err());
        assert!("10.0.0.0/33".parse::<Ipv4Range>().is_err());
        assert!("nonsense".parse::<Ipv4Range>().is_err());
    }

    #[test]
    fn target_list() {
        let t = parse_targets("10.0.0.0/30, 192.168.0.5-9").unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].count(), 2);
        assert_eq!(t[1].count(), 5);
        assert!(parse_targets("  ").is_err());
    }

    #[test]
    fn vlan_selection_parsing() {
        assert_eq!(
            "".parse::<VlanSelection>().unwrap(),
            VlanSelection::Untagged
        );
        assert_eq!(
            "auto".parse::<VlanSelection>().unwrap(),
            VlanSelection::AutoDetect
        );
        assert_eq!(
            "30,10,20,10".parse::<VlanSelection>().unwrap(),
            VlanSelection::List(vec![10, 20, 30])
        );
        assert_eq!(
            "VLAN 10, 20-22".parse::<VlanSelection>().unwrap(),
            VlanSelection::List(vec![10, 20, 21, 22])
        );
        assert!("0".parse::<VlanSelection>().is_err());
        assert!("4095".parse::<VlanSelection>().is_err());
        assert!("20-10".parse::<VlanSelection>().is_err());
        assert!("abc".parse::<VlanSelection>().is_err());
        assert_eq!(VlanSelection::List(vec![10, 20]).to_string(), "10,20");
    }

    #[test]
    fn vlan_selection_with_untagged() {
        assert_eq!(
            "untagged,10,20".parse::<VlanSelection>().unwrap(),
            VlanSelection::UntaggedAndList(vec![10, 20])
        );
        assert_eq!(
            "20, native, 10-11".parse::<VlanSelection>().unwrap(),
            VlanSelection::UntaggedAndList(vec![10, 11, 20])
        );
        assert_eq!(
            "untagged, none".parse::<VlanSelection>().unwrap(),
            VlanSelection::Untagged
        );
        assert!("auto,10".parse::<VlanSelection>().is_err());
        let sel = VlanSelection::UntaggedAndList(vec![10, 20]);
        assert_eq!(sel.to_string(), "untagged,10,20");
        assert_eq!(sel.to_string().parse::<VlanSelection>().unwrap(), sel);
        assert!(sel.includes_untagged() && !VlanSelection::List(vec![1]).includes_untagged());
        assert_eq!(sel.ids(), &[10, 20]);

        // Serde: new variant round-trips, old documents keep their meaning.
        let v = serde_json::to_value(&sel).unwrap();
        assert_eq!(v["mode"], "untagged_and_list");
        assert_eq!(v["ids"], serde_json::json!([10, 20]));
        assert_eq!(serde_json::from_value::<VlanSelection>(v).unwrap(), sel);
        for (json, want) in [
            (r#"{"mode":"untagged"}"#, VlanSelection::Untagged),
            (r#"{"mode":"auto_detect"}"#, VlanSelection::AutoDetect),
            (r#"{"mode":"list","ids":[5]}"#, VlanSelection::List(vec![5])),
        ] {
            assert_eq!(serde_json::from_str::<VlanSelection>(json).unwrap(), want);
        }
        let mut cfg = ScanConfig {
            vlans: VlanSelection::UntaggedAndList(vec![4095]),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
        cfg.vlans = VlanSelection::UntaggedAndList(vec![10]);
        cfg.validate().unwrap();
    }

    #[test]
    fn sanitize_strips_control_and_escape_sequences() {
        assert_eq!(
            sanitize_text("\u{1b}]0;pwned\u{7}\u{1b}[2Jsw01"),
            "]0;pwned[2Jsw01"
        );
        assert_eq!(sanitize_text("a\u{9b}31mb\u{7f}c"), "a31mbc"); // C1 CSI and DEL
        assert_eq!(sanitize_text("  IOS\nVersion 17\r\n\0\0"), "IOS Version 17");
        assert_eq!(sanitize_text("evil\u{202e}txt.exe"), "eviltxt.exe");
        assert_eq!(sanitize_text("Zürich-SW"), "Zürich-SW");
        let long = "x".repeat(MAX_TEXT_LEN * 4);
        assert_eq!(sanitize_text(&long).chars().count(), MAX_TEXT_LEN);
        assert!(sanitize_text(&"é".repeat(1000)).chars().count() == MAX_TEXT_LEN);
    }

    #[test]
    fn numeric_config_is_bounded() {
        let ok = ScanConfig::default();
        ok.validate().unwrap();
        let bad = [
            ScanConfig {
                concurrency: usize::MAX,
                ..Default::default()
            },
            ScanConfig {
                concurrency: MAX_CONCURRENCY + 1,
                ..Default::default()
            },
            ScanConfig {
                concurrency: 0,
                ..Default::default()
            },
            ScanConfig {
                listen_secs: u64::MAX,
                ..Default::default()
            },
            ScanConfig {
                timeout_ms: u64::MAX,
                ..Default::default()
            },
            ScanConfig {
                retries: 200,
                ..Default::default()
            },
            ScanConfig {
                rate_pps: 0,
                ..Default::default()
            },
            ScanConfig {
                rate_pps: u32::MAX,
                ..Default::default()
            },
            ScanConfig {
                ports: vec![0],
                ..Default::default()
            },
            ScanConfig {
                snmp: Some(SnmpConfig {
                    timeout_ms: u64::MAX,
                    ..Default::default()
                }),
                ..Default::default()
            },
        ];
        for cfg in bad {
            assert!(cfg.validate().is_err(), "{cfg:?}");
        }
        ScanConfig {
            concurrency: MAX_CONCURRENCY,
            listen_secs: MAX_LISTEN_SECS,
            timeout_ms: MAX_TIMEOUT_MS,
            retries: MAX_RETRIES as u8,
            rate_pps: MAX_RATE_PPS as u32,
            ..Default::default()
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn vlan_snapshot_merge_does_not_double_count() {
        let mut a = VlanInfo::new(30, VlanSource::Tagged8021q);
        a.frames_seen = 2;
        let mut later = a.clone();
        later.frames_seen = 6;
        a.merge_snapshot(&later);
        a.merge_snapshot(&later);
        assert_eq!(a.frames_seen, 6);
        let mut cdp = VlanInfo::new(30, VlanSource::Cdp);
        cdp.name = Some("USERS".into());
        a.merge_snapshot(&cdp);
        assert_eq!(a.frames_seen, 6);
        assert_eq!(a.name.as_deref(), Some("USERS"));
        assert_eq!(a.sources, vec![VlanSource::Tagged8021q, VlanSource::Cdp]);
    }

    #[test]
    fn ipv6_on_link_helpers() {
        let iface = InterfaceInfo {
            name: "en0".into(),
            index: 4,
            description: None,
            mac: None,
            addrs: vec![
                IfAddr {
                    ip: "fe80::1".parse().unwrap(),
                    prefix: 64,
                },
                IfAddr {
                    ip: "2001:db8:1::5".parse().unwrap(),
                    prefix: 64,
                },
                IfAddr {
                    ip: "fd00:1::5".parse().unwrap(),
                    prefix: 48,
                },
            ],
            is_up: true,
            kind: InterfaceKind::Ethernet,
            vlan_id: None,
            parent: None,
            is_default: true,
        };
        let routable: Vec<Ipv6Addr> = iface.routable_v6().map(|(ip, _)| ip).collect();
        assert_eq!(
            routable,
            vec![
                "2001:db8:1::5".parse::<Ipv6Addr>().unwrap(),
                "fd00:1::5".parse().unwrap()
            ]
        );
        for on in ["fe80::abcd", "2001:db8:1::99", "fd00:1:0:ffff::1"] {
            assert!(iface.is_on_link_v6(on.parse().unwrap()), "{on}");
        }
        for off in ["2001:db8:2::1", "fd00:2::1", "2600::1"] {
            assert!(!iface.is_on_link_v6(off.parse().unwrap()), "{off}");
        }
        assert!(same_v6_prefix(
            "::1".parse().unwrap(),
            "ffff::".parse().unwrap(),
            0
        ));
        assert!(!same_v6_prefix(
            "::1".parse().unwrap(),
            "::2".parse().unwrap(),
            128
        ));
    }

    #[test]
    fn port_parsing() {
        assert_eq!(parse_ports("443, 22,80,22").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("1-3,8443").unwrap(), vec![1, 2, 3, 8443]);
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("70000").is_err());
        assert!(parse_ports(",").is_err());
    }

    #[test]
    fn mac_parsing() {
        let want = [0x00, 0x1a, 0x2b, 0x03, 0x04, 0x05];
        assert_eq!(parse_mac("00:1a:2b:03:04:05"), Some(want));
        assert_eq!(parse_mac("0:1a:2b:3:4:5"), Some(want)); // macOS `arp` style
        assert_eq!(parse_mac("00-1A-2B-03-04-05"), Some(want));
        assert_eq!(parse_mac("001a.2b03.0405"), Some(want));
        assert_eq!(parse_mac("zz:1a:2b:03:04:05"), None);
        assert_eq!(parse_mac("00:1a:2b:03:04"), None);
        assert_eq!(
            normalize_mac("00-1A-2B-03-04-05").as_deref(),
            Some("00:1a:2b:03:04:05")
        );
    }

    #[test]
    fn scan_config_accepts_partial_json() {
        let cfg: ScanConfig = serde_json::from_str(
            r#"{"interface":"en0","vlans":{"mode":"list","ids":[10,20]},"ipv6":true}"#,
        )
        .unwrap();
        assert_eq!(cfg.interface.as_deref(), Some("en0"));
        assert_eq!(cfg.vlans, VlanSelection::List(vec![10, 20]));
        assert!(cfg.ipv6);
        assert_eq!(cfg.ports, DEFAULT_PORTS);
        cfg.validate().unwrap();
    }

    #[test]
    fn scan_config_validation() {
        let mut cfg = ScanConfig {
            range: Some("bogus".into()),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
        cfg.range = Some("10.0.0.0/24".into());
        cfg.snmp = Some(SnmpConfig {
            version: SnmpVersion::V3,
            ..Default::default()
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn snmp_secrets_are_redacted_in_debug() {
        let c = SnmpV3Credentials {
            username: "admin".into(),
            auth_password: Some("hunter2".into()),
            priv_password: Some("hunter3".into()),
            ..Default::default()
        };
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("hunter"));
        assert!(dbg.contains("admin"));
        // The v1/v2c community is a secret too.
        let cfg = SnmpConfig::v2c("s3cr3t-community");
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("s3cr3t"), "{dbg}");
        assert!(dbg.contains("<redacted>"));
        let scan = ScanConfig {
            snmp: Some(cfg),
            ..Default::default()
        };
        assert!(!format!("{scan:?}").contains("s3cr3t"));
    }

    #[test]
    fn snmp_validation_rejects_unusable_credentials() {
        let v3 = |auth: Option<&str>, privacy: Option<&str>| SnmpConfig {
            version: SnmpVersion::V3,
            v3: Some(SnmpV3Credentials {
                username: "monitor".into(),
                auth_password: auth.map(String::from),
                priv_password: privacy.map(String::from),
                ..Default::default()
            }),
            ..Default::default()
        };
        // Valid security levels: noAuthNoPriv, authNoPriv, authPriv.
        assert!(v3(None, None).validate().is_ok());
        assert!(v3(Some("authpass1"), None).validate().is_ok());
        assert!(v3(Some("authpass1"), Some("privpass1")).validate().is_ok());
        // Empty / short passwords would make the key localization panic or be insecure.
        assert!(v3(Some(""), None).validate().is_err());
        assert!(v3(Some("short"), None).validate().is_err());
        assert!(v3(Some("authpass1"), Some("")).validate().is_err());
        assert!(v3(Some("authpass1"), Some("1234567")).validate().is_err());
        // Privacy without authentication does not exist.
        assert!(v3(None, Some("privpass1")).validate().is_err());
        // Missing username.
        let mut no_user = v3(None, None);
        no_user.v3.as_mut().unwrap().username.clear();
        assert!(no_user.validate().is_err());
        // Port 0.
        let port0 = SnmpConfig {
            port: 0,
            ..SnmpConfig::v2c("public")
        };
        assert!(port0.validate().is_err());
        // ScanConfig validation delegates to the SNMP rules.
        let scan = ScanConfig {
            snmp: Some(v3(Some("short"), None)),
            ..Default::default()
        };
        assert!(scan.validate().is_err());
    }

    #[test]
    fn snmp_device_info_partial_fields_default_when_absent() {
        let json = r#"{"sysName":null,"sysDescr":null,"sysUptimeTicks":null,"sysObjectId":null,
            "role":"switch","vlans":[],"portMappings":[],"portMacCounts":[]}"#;
        let info: SnmpDeviceInfo = serde_json::from_str(json).unwrap();
        assert!(!info.partial && info.warnings.is_empty());
        let v = serde_json::to_value(&info).unwrap();
        assert_eq!(v["partial"], false);
        assert!(v["warnings"].as_array().unwrap().is_empty());
        // `snmpAll` is optional on the wire and defaults to off.
        let cfg: ScanConfig = serde_json::from_str("{}").unwrap();
        assert!(!cfg.snmp_all);
        let cfg: ScanConfig = serde_json::from_str(r#"{"snmpAll":true}"#).unwrap();
        assert!(cfg.snmp_all);
        // Service discovery defaults ON when absent; DHCP fingerprinting defaults OFF.
        let cfg: ScanConfig = serde_json::from_str("{}").unwrap();
        assert!(cfg.discover_services && !cfg.sip_all && !cfg.dhcp_fingerprint);
        let cfg: ScanConfig = serde_json::from_str(r#"{"discoverServices":false}"#).unwrap();
        assert!(!cfg.discover_services);
    }

    #[test]
    fn role_merge_respects_confidence_and_never_downgrades() {
        use RoleConfidence::{High, Low, Medium};
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        let obs = |role, source, conf, why: &str| {
            let mut d = Device::new(ip);
            d.set_role(role, source, conf, vec![why.to_string()]);
            d
        };
        // A low-confidence name guess lands on a plain host.
        let mut d = Device::new(ip);
        d.merge(&obs(DeviceRole::Switch, RoleSource::Name, Low, "name"));
        assert_eq!(d.role, DeviceRole::Switch);
        assert_eq!(d.role_confidence, Some(Low));
        assert!(!d.is_confident_infrastructure());
        // A plain-host observation (e.g. a later sparse update) never downgrades it.
        d.merge(&Device::new(ip));
        assert_eq!(d.role, DeviceRole::Switch);
        assert_eq!(d.role_source, Some(RoleSource::Name));
        // A higher-priority role at LOWER confidence does not win any more...
        let mut snmp = Device::new(ip);
        snmp.merge(&obs(DeviceRole::Switch, RoleSource::Snmp, High, "snmp"));
        snmp.merge(&obs(DeviceRole::Firewall, RoleSource::Name, Low, "fw name"));
        assert_eq!(snmp.role, DeviceRole::Switch);
        assert_eq!(snmp.role_source, Some(RoleSource::Snmp));
        assert_eq!(snmp.role_evidence, vec!["snmp".to_string()]);
        // ...but more confident evidence replaces a guess, even with a lower priority.
        d.merge(&obs(
            DeviceRole::Router,
            RoleSource::Snmp,
            High,
            "snmp router",
        ));
        assert_eq!(d.role, DeviceRole::Router);
        assert_eq!(d.role_source, Some(RoleSource::Snmp));
        assert_eq!(d.role_confidence, Some(High));
        assert_eq!(d.role_evidence, vec!["snmp router".to_string()]);
        // Equal confidence: the historical priority rule.
        let mut e = obs(DeviceRole::Router, RoleSource::Web, Medium, "a");
        e.merge(&obs(DeviceRole::Firewall, RoleSource::Web, Medium, "b"));
        assert_eq!(e.role, DeviceRole::Firewall);
        // Same role, same confidence: evidence accumulates.
        e.merge(&obs(
            DeviceRole::Firewall,
            RoleSource::OuiPorts,
            Medium,
            "c",
        ));
        assert_eq!(e.role_source, Some(RoleSource::Web));
        assert_eq!(e.role_evidence, vec!["b".to_string(), "c".to_string()]);
        // A legacy infrastructure role without provenance counts as medium.
        let mut legacy = Device::new(ip);
        legacy.role = DeviceRole::Switch;
        legacy.merge(&obs(DeviceRole::Firewall, RoleSource::Name, Low, "x"));
        assert_eq!(legacy.role, DeviceRole::Switch);
        assert!(legacy.is_confident_infrastructure());
        // Host-level hints accumulate on a host.
        let mut h = Device::new(ip);
        let mut hint = Device::new(ip);
        hint.add_role_evidence("possible network device: Ruijie OUI");
        h.merge(&hint);
        assert_eq!(h.role, DeviceRole::Host);
        assert_eq!(h.role_evidence.len(), 1);
        assert_eq!(h.role_confidence, None);
        // Wire format.
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["roleSource"], "snmp");
        assert_eq!(v["roleConfidence"], "high");
        assert_eq!(
            serde_json::to_value(RoleSource::MdnsService).unwrap(),
            "mdns_service"
        );
        assert_eq!(
            serde_json::to_value(RoleSource::OuiPorts).unwrap(),
            "oui_ports"
        );
    }

    #[test]
    fn device_merge_fills_gaps_and_unions() {
        let mut a = Device::new("10.0.0.1".parse().unwrap());
        a.add_source(DiscoverySource::Arp);
        a.open_ports = vec![443];
        let mut b = Device::new("10.0.0.1".parse().unwrap());
        b.mac = Some("aa:bb:cc:dd:ee:ff".into());
        b.role = DeviceRole::Firewall;
        b.open_ports = vec![22, 443];
        b.extra_ips.push("fe80::1".parse().unwrap());
        b.add_source(DiscoverySource::Snmp);
        a.merge(&b);
        assert_eq!(a.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(a.role, DeviceRole::Firewall);
        assert_eq!(a.open_ports, vec![22, 443]);
        assert_eq!(a.extra_ips.len(), 1);
        assert_eq!(a.sources, vec![DiscoverySource::Arp, DiscoverySource::Snmp]);
        assert_eq!(a.key(), "10.0.0.1");
        a.vlan_id = Some(20);
        assert_eq!(a.key(), "10.0.0.1@20");
    }

    fn neighbor(platform: &str, caps: &[Capability]) -> CdpLldpNeighbor {
        CdpLldpNeighbor {
            protocol: NeighborProtocol::Cdp,
            local_interface: "en0".into(),
            source_mac: "00:00:00:00:00:01".into(),
            device_id: "sw01".into(),
            system_name: None,
            system_description: None,
            port_id: Some("Gi1/0/1".into()),
            port_description: None,
            platform: Some(platform.into()),
            software_version: None,
            management_addrs: vec![],
            native_vlan: None,
            voice_vlan: None,
            capabilities: caps.to_vec(),
            vtp_domain: None,
            poe_watts: None,
            poe_info: None,
            ttl_secs: 180,
            last_seen_ms: 0,
        }
    }

    #[test]
    fn neighbor_role_inference() {
        use Capability::*;
        assert_eq!(
            neighbor("cisco WS-C3850-48P", &[Router, Switch]).infer_role(),
            DeviceRole::Switch
        );
        assert_eq!(
            neighbor("cisco ISR4331", &[Router]).infer_role(),
            DeviceRole::Router
        );
        assert_eq!(
            neighbor("FortiGate-60F", &[Router]).infer_role(),
            DeviceRole::Firewall
        );
        assert_eq!(
            neighbor("UAP-AC-Pro", &[WlanAccessPoint]).infer_role(),
            DeviceRole::AccessPoint
        );
        assert_eq!(
            neighbor("Cisco IP Phone 8845", &[Telephone]).infer_role(),
            DeviceRole::Host
        );
    }

    #[test]
    fn modern_access_points_beat_bridge_capability() {
        use Capability::*;
        // Catalyst 91xx / CW91xx APs advertise CDP "transparent bridge" (→ Switch).
        for platform in [
            "cisco C9120AXI-B",
            "cisco C9130AXE-B",
            "cisco C9105AXW-B",
            "cisco CW9164I-ROW",
            "cisco AIR-AP2802I-B-K9",
            "cisco AIR-CAP3702I-A-K9",
            "Aruba AP-515",
            "UniFi U6-Pro",
            "Meraki MR46",
        ] {
            assert_eq!(
                neighbor(platform, &[Switch]).infer_role(),
                DeviceRole::AccessPoint,
                "{platform}"
            );
        }
        let mut sw = neighbor("cisco WS-C2960X", &[Switch]);
        sw.software_version = Some("Cisco AP Software, ap3g3-k9w8 Version: 17.9".into());
        assert_eq!(sw.infer_role(), DeviceRole::AccessPoint);
        // Gear that shares keywords but is not an AP.
        assert_eq!(
            neighbor("cisco AIR-CT5520-K9", &[Router, Switch]).infer_role(),
            DeviceRole::Switch
        );
        assert_eq!(
            neighbor("UniFi Switch USW-24-POE", &[Switch]).infer_role(),
            DeviceRole::Switch
        );
        assert_eq!(
            neighbor("cisco C9300-48P", &[Router, Switch]).infer_role(),
            DeviceRole::Switch
        );
    }

    #[test]
    fn local_subnet_from_interface() {
        let iface = InterfaceInfo {
            name: "en0".into(),
            index: 4,
            description: None,
            mac: None,
            addrs: vec![IfAddr {
                ip: "10.177.134.23".parse().unwrap(),
                prefix: 24,
            }],
            is_up: true,
            kind: InterfaceKind::Ethernet,
            vlan_id: None,
            parent: None,
            is_default: true,
        };
        let r = iface.local_subnet().unwrap();
        assert_eq!(r.to_string(), "10.177.134.1-10.177.134.254");
    }

    #[test]
    fn events_serialize_with_type_tag() {
        let v = serde_json::to_value(ScanEvent::info("hello")).unwrap();
        assert_eq!(v["type"], "log");
        assert_eq!(v["data"]["level"], "info");
        let role = serde_json::to_value(DeviceRole::AccessPoint).unwrap();
        assert_eq!(role, "access_point");
    }

    /// Regression: the GUI passes devices back to `export_devices`; a frontend that does not
    /// know the utility fields yet must still deserialize.
    #[test]
    fn devices_without_utility_fields_still_deserialize() {
        let json = r#"{"ip":"10.0.0.1","extraIps":[],"mac":null,"vlanId":null,"role":"host",
            "hostname":null,"dnsName":null,"mdnsName":null,"smbName":null,"smbDomain":null,
            "vendor":null,"switchPort":null,"openPorts":[443],"comments":null,"interface":null,
            "rttMs":null,"sources":[],"neighbor":null,"firstSeenMs":1,"lastSeenMs":2}"#;
        let d: Device = serde_json::from_str(json).unwrap();
        assert!(d.latency.is_none() && d.tls_cert.is_none() && d.warnings.is_empty());
        let v = serde_json::to_value(&d).unwrap();
        for key in [
            "latency",
            "webTitle",
            "webServer",
            "tlsCert",
            "webIdentity",
            "warnings",
            "roleSource",
            "roleConfidence",
            "roleEvidence",
            "mdnsServices",
        ] {
            assert!(v.get(key).is_some(), "{key} is always serialized");
        }
        // Partial nested objects use their defaults.
        let mut v = v;
        v["latency"] = serde_json::json!({ "avgMs": 3.5 });
        v["tlsCert"] = serde_json::json!({ "subjectCn": "fw.lan", "port": 443 });
        let d: Device = serde_json::from_value(v).unwrap();
        assert_eq!(d.latency.unwrap().avg_ms, Some(3.5));
        assert_eq!(d.tls_cert.unwrap().subject_cn.as_deref(), Some("fw.lan"));
    }

    #[test]
    fn device_merge_of_utility_fields() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let mut a = Device::new(ip);
        a.web_title = Some("first".into());
        a.latency = Some(LatencyStats {
            avg_ms: Some(1.0),
            updated_ms: 100,
            ..LatencyStats::default()
        });
        a.add_warning("w1");
        let mut b = Device::new(ip);
        b.web_title = Some("second".into());
        b.web_server = Some("nginx".into());
        b.web_identity = Some("pfSense".into());
        b.tls_cert = Some(TlsCertInfo {
            port: 443,
            ..TlsCertInfo::default()
        });
        b.latency = Some(LatencyStats {
            avg_ms: Some(2.0),
            updated_ms: 200,
            ..LatencyStats::default()
        });
        b.add_warning("w1");
        b.add_warning("w2");
        a.merge(&b);
        assert_eq!(
            a.web_title.as_deref(),
            Some("first"),
            "gaps are filled, values kept"
        );
        assert_eq!(a.web_server.as_deref(), Some("nginx"));
        assert_eq!(a.web_identity.as_deref(), Some("pfSense"));
        assert_eq!(a.tls_cert.as_ref().map(|c| c.port), Some(443));
        assert_eq!(
            a.latency.as_ref().unwrap().avg_ms,
            Some(2.0),
            "newest stats win"
        );
        assert_eq!(a.warnings, vec!["w1", "w2"]);
        // Older latency snapshots never replace newer ones.
        let mut old = Device::new(ip);
        old.latency = Some(LatencyStats {
            avg_ms: Some(9.0),
            updated_ms: 50,
            ..LatencyStats::default()
        });
        a.merge(&old);
        assert_eq!(a.latency.as_ref().unwrap().avg_ms, Some(2.0));
        for i in 0..100 {
            a.add_warning(format!("x{i}"));
        }
        assert_eq!(a.warnings.len(), MAX_DEVICE_WARNINGS);
    }

    #[test]
    fn web_identity_defaults_on_and_utility_options_validate() {
        let cfg: ScanConfig = serde_json::from_str("{}").unwrap();
        assert!(cfg.web_identity);
        let cfg: ScanConfig = serde_json::from_str(r#"{"webIdentity":false}"#).unwrap();
        assert!(!cfg.web_identity);
        for ok in ["0", "100", "100M", "2.5G", "500k", " 10M "] {
            assert!(is_valid_bitrate(ok), "{ok}");
        }
        for bad in ["", "M", "1.2.3M", ".5M", "5.M", "10MB", "-b", "1e9", "1M 2"] {
            assert!(!is_valid_bitrate(bad), "{bad}");
        }
        let o: IperfOptions = serde_json::from_str(r#"{"udp":true,"bitrate":"10M"}"#).unwrap();
        assert_eq!((o.port, o.duration_secs, o.streams), (5201, 10, 1));
        o.validate().unwrap();
        let sample = LatencySample {
            ip: "10.0.0.1".parse().unwrap(),
            rtt_ms: None,
            ts: 5,
            method: ProbeMethod::Tcp,
            loss_pct: 50.0,
            avg_ms: Some(1.0),
            min_ms: Some(1.0),
            max_ms: Some(1.0),
            jitter_ms: None,
            sent: 2,
            received: 1,
            history: Some(vec![Some(1.0), None]),
            new_samples: vec![None],
        };
        let v = serde_json::to_value(LatencyUpdate {
            monitor_id: 3,
            samples: vec![sample.clone()],
        })
        .unwrap();
        assert_eq!(v["monitorId"], 3);
        assert_eq!(v["samples"][0]["rttMs"], serde_json::Value::Null);
        assert_eq!(v["samples"][0]["method"], "tcp");
        assert_eq!(v["samples"][0]["history"][1], serde_json::Value::Null);
        assert_eq!(v["samples"][0]["newSamples"][0], serde_json::Value::Null);
        // Without a history (live update in between resends) the key is absent.
        let mut delta = sample.clone();
        delta.history = None;
        let v = serde_json::to_value(&delta).unwrap();
        assert!(v.get("history").is_none());
        let stats = sample.stats();
        assert_eq!((stats.updated_ms, stats.sent, stats.last_ms), (5, 2, None));
    }
}
