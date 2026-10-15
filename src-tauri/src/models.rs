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
pub const DEFAULT_PORTS: &[u16] = &[22, 23, 80, 161, 443, 445, 8291, 8443, 10443];

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
}

/// Which VLANs a scan should tag its probes with.
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
}

impl VlanSelection {
    pub fn is_untagged(&self) -> bool {
        matches!(self, VlanSelection::Untagged)
    }
}

impl FromStr for VlanSelection {
    type Err = ModelError;

    /// Accepts `untagged`/`none`/empty, `auto`, or a list such as `10,20,30` / `1-100` / `10,20-25`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        match s.to_ascii_lowercase().as_str() {
            "" | "untagged" | "none" | "native" => return Ok(VlanSelection::Untagged),
            "auto" | "auto-detect" | "autodetect" => return Ok(VlanSelection::AutoDetect),
            _ => {}
        }

        let mut ids: Vec<u16> = Vec::new();
        for part in s
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|p| !p.is_empty())
        {
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
        if ids.is_empty() {
            return Err(ModelError::InvalidVlan(format!("no VLAN IDs in '{s}'")));
        }
        Ok(VlanSelection::List(ids))
    }
}

impl fmt::Display for VlanSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VlanSelection::Untagged => f.write_str("untagged"),
            VlanSelection::AutoDetect => f.write_str("auto"),
            VlanSelection::List(ids) => {
                let s: Vec<String> = ids.iter().map(u16::to_string).collect();
                f.write_str(&s.join(","))
            }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        if has(Capability::WlanAccessPoint)
            || any(&[
                "access point",
                "aironet",
                "air-ap",
                "air-cap",
                "unifi ap",
                "uap-",
                "u6-",
                "meraki mr",
                "aruba ap",
                "instant ap",
                "ruckus zoneflex",
                "mikrotik cap",
            ])
        {
            return DeviceRole::AccessPoint;
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SwitchPortMapping {
    pub switch_name: String,
    pub switch_ip: Option<IpAddr>,
    /// Interface name such as `Gi1/0/24` (falls back to the bridge port number).
    pub port_name: String,
    pub port_index: Option<u32>,
    pub vlan_id: Option<u16>,
    pub mac: String,
}

impl SwitchPortMapping {
    /// `Cisco-SW01 [Gi1/0/24]`
    pub fn label(&self) -> String {
        format!("{} [{}]", self.switch_name, self.port_name)
    }
}

// ---------------------------------------------------------------------------------------------
// Device
// ---------------------------------------------------------------------------------------------

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
    pub sources: Vec<DiscoverySource>,
    pub neighbor: Option<CdpLldpNeighbor>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

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
            sources: Vec::new(),
            neighbor: None,
            first_seen_ms: now,
            last_seen_ms: now,
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
            neighbor
        );
        if other.role.priority() > self.role.priority() {
            self.role = other.role;
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

    /// The directly connected IPv4 subnet (host range), e.g. `10.177.134.1-10.177.134.254`.
    pub fn local_subnet(&self) -> Option<Ipv4Range> {
        let (ip, prefix) = self.primary_ipv4()?;
        Ipv4Range::from_cidr(ip, prefix).ok()
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SnmpConfig {
    pub version: SnmpVersion,
    pub community: String,
    pub v3: Option<SnmpV3Credentials>,
    pub port: u16,
    pub timeout_ms: u64,
    pub retries: u8,
}

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
    /// Discover IPv6 link-local / global addresses via ICMPv6 NDP.
    pub ipv6: bool,
    pub ports: Vec<u16>,
    /// Resolve DNS PTR / mDNS / NetBIOS names for each device.
    pub resolve_names: bool,
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
            ipv6: false,
            ports: DEFAULT_PORTS.to_vec(),
            resolve_names: true,
            timeout_ms: 1500,
            retries: 1,
            rate_pps: 2000,
            concurrency: 512,
            listen_secs: 10,
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
        if let VlanSelection::List(ids) = &self.vlans {
            if ids.is_empty() || ids.iter().any(|v| !(1..=MAX_VLAN_ID).contains(v)) {
                return Err(ModelError::InvalidVlan(format!(
                    "VLAN IDs must be 1-{MAX_VLAN_ID}"
                )));
            }
        }
        if self.rate_pps == 0 {
            return Err(ModelError::InvalidConfig("rate_pps must be > 0".into()));
        }
        if self.concurrency == 0 {
            return Err(ModelError::InvalidConfig("concurrency must be > 0".into()));
        }
        if let Some(snmp) = &self.snmp {
            if snmp.version == SnmpVersion::V3
                && snmp.v3.as_ref().map_or(true, |c| c.username.is_empty())
            {
                return Err(ModelError::InvalidConfig(
                    "SNMPv3 requires a username".into(),
                ));
            }
        }
        Ok(())
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub devices: u64,
    pub vlans: u64,
    pub neighbors: u64,
    pub elapsed_ms: u64,
    pub cancelled: bool,
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
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
}
