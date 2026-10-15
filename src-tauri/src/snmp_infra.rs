//! Asynchronous SNMP infrastructure discovery (v1 / v2c / v3).
//!
//! Polls a device's system group, VLAN tables (Q-BRIDGE and Cisco VTP) and bridge/CAM tables
//! (802.1D and Q-BRIDGE forwarding databases) to turn switches into structured
//! [`SnmpDeviceInfo`]: a role, the VLANs it owns and a MAC-to-port map.
//!
//! The crate's [`snmp2::AsyncSession`] drives UDP over tokio. Every request is wrapped in a
//! timeout and retried, and every table walk is bounded by an overall per-device deadline, a
//! row cap, a byte budget, an index-length cap and strict end-of-MIB / subtree / loop
//! detection, so a hostile or buggy agent can neither hang the poller nor exhaust its memory.
//! A walk that fails part-way keeps the rows it already has and the result is flagged
//! `partial`. All strings coming off the wire pass through [`sanitize_text`]. Each poll runs
//! in its own task, so a panic inside the SNMP library becomes an error, never a crash.
//!
//! OID / index parsing and role classification are pure functions (unit tested below), and a
//! hand-encoded in-process SNMPv2c responder exercises the walk end to end.

use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::Result;
use snmp2::{AsyncSession, Oid, Value};
use tokio::sync::{mpsc::Sender, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::{
    limits::SocketBudget,
    models::{
        now_ms, sanitize_text, DeviceRole, DiscoverySource, PortMacCount, ScanEvent, SnmpConfig,
        SnmpDeviceInfo, SnmpVersion, SwitchPortMapping, VlanInfo, VlanSource, MAX_VLAN_ID,
    },
    progress::ProgressScope,
};

// ---------------------------------------------------------------------------------------------
// OIDs (as sub-identifier slices; `Oid` is rebuilt per request)
// ---------------------------------------------------------------------------------------------

const SYS_DESCR: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
const SYS_OBJECT_ID: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 2, 0];
const SYS_UPTIME: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];
const SYS_NAME: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];
const SYS_SERVICES: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 7, 0];

/// dot1qVlanStaticName (Q-BRIDGE-MIB): index = VLAN id.
const DOT1Q_VLAN_STATIC_NAME: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 3, 1, 1];
/// vtpVlanName (CISCO-VTP-MIB): index = domain index . VLAN id.
const VTP_VLAN_NAME: &[u64] = &[1, 3, 6, 1, 4, 1, 9, 9, 46, 1, 3, 1, 1, 4];
/// dot1dTpFdbPort (BRIDGE-MIB): index = 6 MAC octets, value = bridge port number.
const DOT1D_TP_FDB_PORT: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2];
/// dot1qTpFdbPort (Q-BRIDGE-MIB): index = VLAN id + 6 MAC octets, value = bridge port number.
const DOT1Q_TP_FDB_PORT: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2];
/// dot1dBasePortIfIndex (BRIDGE-MIB): index = bridge port number, value = ifIndex.
const DOT1D_BASE_PORT_IFINDEX: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2];
/// ifName (IF-MIB): index = ifIndex, value = short interface name (e.g. `Gi1/0/24`).
const IF_NAME: &[u64] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1];
/// ifDescr (IF-MIB): index = ifIndex, value = long interface description.
const IF_DESCR: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 2];

/// POWER-ETHERNET-MIB pethPsePortDetectionStatus: index = group.port, value = status enum
/// (1 disabled, 2 searching, 3 deliveringPower, 4 fault, 5 test, 6 otherFault).
const PETH_PSE_PORT_DETECTION: &[u64] = &[1, 3, 6, 1, 2, 1, 105, 1, 1, 1, 1, 6];
/// POWER-ETHERNET-MIB pethPsePortPowerClassifications: index = group.port, value = class enum
/// (class0(1) .. class4(5)).
const PETH_PSE_PORT_CLASS: &[u64] = &[1, 3, 6, 1, 2, 1, 105, 1, 1, 1, 1, 11];
/// POWER-ETHERNET-MIB pethMainPsePower: index = group, value = nominal PSE power (watts).
const PETH_MAIN_PSE_POWER: &[u64] = &[1, 3, 6, 1, 2, 1, 105, 1, 3, 1, 1, 2];
/// POWER-ETHERNET-MIB pethMainPseConsumptionPower: index = group, value = watts in use.
const PETH_MAIN_PSE_CONSUMPTION: &[u64] = &[1, 3, 6, 1, 2, 1, 105, 1, 3, 1, 1, 4];
/// POWER-ETHERNET-MIB pethMainPseUsageThreshold: index = group, value = percent.
const PETH_MAIN_PSE_THRESHOLD: &[u64] = &[1, 3, 6, 1, 2, 1, 105, 1, 3, 1, 1, 5];
/// CISCO-POWER-ETHERNET-EXT-MIB cpeExtPsePortPwrConsumption: index = group.port, value = mW.
const CISCO_CPE_EXT_PSE_PORT_PWR: &[u64] = &[1, 3, 6, 1, 4, 1, 9, 9, 402, 1, 2, 1, 7];
/// CISCO-VLAN-MEMBERSHIP-MIB vmVoiceVlanId: index = ifIndex, value = voice VLAN (4096 = none,
/// 4095 = untagged 802.1p).
const CISCO_VM_VOICE_VLAN: &[u64] = &[1, 3, 6, 1, 4, 1, 9, 9, 68, 1, 5, 1, 1, 1];

// ---------------------------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------------------------

/// Hard cap on rows returned by any one table walk (hostile-agent memory bound).
const MAX_WALK_ROWS: usize = 50_000;
/// Hard cap on MAC-to-port mappings kept per device, across every VLAN / community context.
pub const MAX_DEVICE_MAPPINGS: usize = 50_000;
/// Longest table index accepted (sub-identifiers after the column OID). The tables walked here
/// use at most 7 (Q-BRIDGE FDB: VLAN + MAC); anything far longer is malformed.
const MAX_INDEX_SUBIDS: usize = 32;
/// Octet-string values are truncated to this many bytes when copied out of the session (every
/// value we keep is a short name; text is further capped by [`sanitize_text`]).
const MAX_VALUE_BYTES: usize = 1024;
/// OID-valued varbinds keep at most this many sub-identifiers.
const MAX_OID_VALUE_SUBIDS: usize = 128;
/// Approximate memory budget of one walk (index sub-ids + value bytes).
const MAX_WALK_BYTES: usize = 8 * 1024 * 1024;
/// GETBULK max-repetitions (v2c/v3). Kept modest so a reply fits one datagram comfortably.
const BULK_REPETITIONS: u32 = 20;
/// Overall wall-clock budget for one device poll, independent of per-request timeouts.
const DEVICE_BUDGET: Duration = Duration::from_secs(25);
/// Attempts (initial + retries) are taken from [`SnmpConfig::retries`]; this caps the v3
/// engine-discovery (`AuthUpdated`) retries so a misbehaving agent cannot loop forever.
const MAX_AUTH_UPDATES: u8 = 4;
/// Per-VLAN community-string CAM polling (Cisco Catalyst) is bounded to this many VLANs.
const MAX_COMMUNITY_VLANS: usize = 128;
/// Max concurrent device polls in [`probe_candidates`] (each also holds a socket permit from
/// the global [`SocketBudget`]).
const MAX_CONCURRENT_POLLS: usize = 64;
/// Timeout of the cheap reachability probe sent before any heavy walk.
const PROBE_TIMEOUT: Duration = Duration::from_millis(1000);
/// Attempts of the reachability probe.
const PROBE_ATTEMPTS: u8 = 2;
/// Warnings kept per poll result.
const MAX_POLL_WARNINGS: usize = 16;
/// Per-device failure lines streamed to the scan log (the rest only go to `tracing`).
const MAX_FAILURE_LOGS: usize = 20;

/// A `(index-suffix, value)` row returned by a table walk / GET.
type OidRow = (Vec<u64>, SnmpValue);
/// Forwarding database: `(vlan, mac)` → `(bridge port, vlan)`.
type FdbMap = BTreeMap<(Option<u16>, [u8; 6]), (u32, Option<u16>)>;

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// Coarse reason a poll failed, for per-scan statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollFailure {
    /// No answer (timeout, ICMP unreachable): usually "no SNMP agent" or a wrong v1/v2c
    /// community (agents silently drop those).
    NoResponse,
    /// The agent answered but rejected or could not decrypt our credentials (v3 USM errors).
    Auth,
    /// Anything else (malformed replies, invalid configuration, library failure).
    Other,
}

/// A failed SNMP poll / request with its [`PollFailure`] class.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct SnmpPollError {
    pub kind: PollFailure,
    pub message: String,
}

impl SnmpPollError {
    fn new(kind: PollFailure, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

/// Classify an `anyhow` error from [`SnmpClient::poll_device`].
pub fn failure_kind(err: &anyhow::Error) -> PollFailure {
    err.chain()
        .find_map(|c| c.downcast_ref::<SnmpPollError>().map(|e| e.kind))
        .unwrap_or(PollFailure::Other)
}

fn classify_snmp_error(e: &snmp2::Error) -> PollFailure {
    match e {
        snmp2::Error::AuthFailure(_)
        | snmp2::Error::CommunityMismatch
        | snmp2::Error::Crypto(_) => PollFailure::Auth,
        snmp2::Error::Send | snmp2::Error::Receive => PollFailure::NoResponse,
        _ => PollFailure::Other,
    }
}

// ---------------------------------------------------------------------------------------------
// Owned SNMP value (decoupled from the session's borrowed receive buffer)
// ---------------------------------------------------------------------------------------------

/// A varbind value copied out of the session buffer so the borrow ends before the next request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SnmpValue {
    Int(i64),
    Bytes(Vec<u8>),
    Oid(Vec<u64>),
    Counter32(u32),
    Counter64(u64),
    Unsigned32(u32),
    Timeticks(u32),
    Ip([u8; 4]),
    EndOfMibView,
    NoSuchObject,
    NoSuchInstance,
    Null,
    Unsupported,
}

impl SnmpValue {
    fn from_value(v: &Value<'_>) -> Self {
        match v {
            Value::Integer(i) => SnmpValue::Int(*i),
            Value::OctetString(b) => SnmpValue::Bytes(b[..b.len().min(MAX_VALUE_BYTES)].to_vec()),
            Value::ObjectIdentifier(o) => SnmpValue::Oid(
                o.iter()
                    .map(|it| it.take(MAX_OID_VALUE_SUBIDS).collect())
                    .unwrap_or_default(),
            ),
            Value::Counter32(n) => SnmpValue::Counter32(*n),
            Value::Counter64(n) => SnmpValue::Counter64(*n),
            Value::Unsigned32(n) => SnmpValue::Unsigned32(*n),
            Value::Timeticks(n) => SnmpValue::Timeticks(*n),
            Value::IpAddress(ip) => SnmpValue::Ip(*ip),
            Value::Null => SnmpValue::Null,
            Value::EndOfMibView => SnmpValue::EndOfMibView,
            Value::NoSuchObject => SnmpValue::NoSuchObject,
            Value::NoSuchInstance => SnmpValue::NoSuchInstance,
            _ => SnmpValue::Unsupported,
        }
    }

    /// `true` for the SNMP exception markers that terminate a walk.
    fn is_end_marker(&self) -> bool {
        matches!(
            self,
            SnmpValue::EndOfMibView | SnmpValue::NoSuchObject | SnmpValue::NoSuchInstance
        )
    }

    fn as_u32(&self) -> Option<u32> {
        match self {
            SnmpValue::Int(i) => u32::try_from(*i).ok(),
            SnmpValue::Counter32(n) | SnmpValue::Unsigned32(n) | SnmpValue::Timeticks(n) => {
                Some(*n)
            }
            SnmpValue::Counter64(n) => u32::try_from(*n).ok(),
            _ => None,
        }
    }

    /// Approximate bytes this value occupies once stored.
    fn approx_size(&self) -> usize {
        match self {
            SnmpValue::Bytes(b) => b.len(),
            SnmpValue::Oid(o) => o.len() * 8,
            _ => 8,
        }
    }

    fn octets(&self) -> Option<&[u8]> {
        match self {
            SnmpValue::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Sanitized UTF-8 (lossy) text, or `None` when the value is empty / not a string.
    fn text(&self) -> Option<String> {
        let b = self.octets()?;
        let s = sanitize_text(&String::from_utf8_lossy(b));
        (!s.is_empty()).then_some(s)
    }
}

// ---------------------------------------------------------------------------------------------
// OID helpers (pure)
// ---------------------------------------------------------------------------------------------

/// Build an owning [`Oid`] from sub-identifiers. The slices here are compile-time constants, so
/// this never fails in practice; a bad slice yields the empty OID rather than panicking.
fn oid(parts: &[u64]) -> Oid<'static> {
    Oid::from(parts).unwrap_or_else(|_| Oid::from(&[0, 0]).expect("0.0 is a valid OID"))
}

/// Sub-identifiers of `full` after the `base` prefix, or `None` when `full` is not a strict,
/// deeper descendant of `base` (so it has left the table/subtree).
fn suffix_of<'a>(base: &[u64], full: &'a [u64]) -> Option<&'a [u64]> {
    (full.len() > base.len() && full.starts_with(base)).then(|| &full[base.len()..])
}

/// The trailing 6 sub-identifiers of a FDB OID index read as a MAC address.
pub fn mac_from_suffix(suffix: &[u64]) -> Option<[u8; 6]> {
    if suffix.len() < 6 {
        return None;
    }
    let tail = &suffix[suffix.len() - 6..];
    let mut mac = [0u8; 6];
    for (slot, v) in mac.iter_mut().zip(tail) {
        *slot = u8::try_from(*v).ok()?;
    }
    Some(mac)
}

/// A Q-BRIDGE FDB index `vlan . mac[0..6]`: the first sub-id is the VLAN, the last six the MAC.
pub fn vlan_and_mac_from_suffix(suffix: &[u64]) -> Option<(u16, [u8; 6])> {
    if suffix.len() < 7 {
        return None;
    }
    let vlan = u16::try_from(suffix[0])
        .ok()
        .filter(|v| *v <= MAX_VLAN_ID)?;
    let mac = mac_from_suffix(suffix)?;
    Some((vlan, mac))
}

/// Resolve a bridge port number to an interface name via the two IF-MIB maps. Falls back to a
/// synthetic `port <n>` label (and no ifIndex) when the maps do not cover the port.
pub fn resolve_port_name(
    bridge_port: u32,
    base_port_ifindex: &HashMap<u32, u32>,
    if_names: &HashMap<u32, String>,
) -> (String, Option<u32>) {
    if let Some(&ifindex) = base_port_ifindex.get(&bridge_port) {
        if let Some(name) = if_names.get(&ifindex) {
            return (name.clone(), Some(ifindex));
        }
        return (format!("ifIndex {ifindex}"), Some(ifindex));
    }
    (format!("port {bridge_port}"), None)
}

/// The IANA/SMI private-enterprise number of a `1.3.6.1.4.1.<N>...` sysObjectID string.
pub fn enterprise_number(sys_object_id: &str) -> Option<u64> {
    let rest = sys_object_id.trim().strip_prefix("1.3.6.1.4.1.")?;
    rest.split('.').next()?.parse().ok()
}

// ---------------------------------------------------------------------------------------------
// Power-over-Ethernet (pure helpers)
// ---------------------------------------------------------------------------------------------

/// PoE delivery state of one PSE port, keyed by `(group, port)` from the table index.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PoePortData {
    pub status: Option<String>,
    pub class: Option<u8>,
    pub watts: Option<f32>,
}

/// Per-port PoE collected from the POWER-ETHERNET-MIB (and Cisco extension), keyed by the
/// `(pethPsePortGroupIndex, pethPsePortIndex)` table index.
pub type PoePortMap = BTreeMap<(u32, u32), PoePortData>;

/// Human label for a POWER-ETHERNET-MIB pethPsePortDetectionStatus value.
pub fn poe_detection_label(v: u32) -> Option<&'static str> {
    Some(match v {
        1 => "disabled",
        2 => "searching",
        3 => "delivering",
        4 => "fault",
        5 => "test",
        6 => "fault",
        _ => return None,
    })
}

/// IEEE class (0-4) from a pethPsePortPowerClassifications enum (`class0(1)..class4(5)`).
pub fn poe_class_from_enum(v: u32) -> Option<u8> {
    (1..=5).contains(&v).then(|| (v - 1) as u8)
}

/// A usable voice VLAN from a `vmVoiceVlanId` value (4096 = none and 4095 = untagged 802.1p
/// priority are not VLANs).
pub fn voice_vlan_value(v: u32) -> Option<u16> {
    u16::try_from(v)
        .ok()
        .filter(|id| (1..=crate::models::MAX_VLAN_ID).contains(id))
}

/// The last two sub-identifiers of a `group.port` PoE index.
fn group_port(suffix: &[u64]) -> Option<(u32, u32)> {
    if suffix.len() < 2 {
        return None;
    }
    let group = u32::try_from(suffix[suffix.len() - 2]).ok()?;
    let port = u32::try_from(suffix[suffix.len() - 1]).ok()?;
    Some((group, port))
}

/// Trailing integers of an interface name, e.g. `Gi1/0/24` → `[1, 0, 24]`, `Fa0/5` → `[0, 5]`.
/// Used to match a resolved switch-port name back to a PoE `(group, port)` index, since no MIB
/// links PoE ports to ifIndex and vendors index PoE by module/port.
fn port_name_numbers(port_name: &str) -> Vec<u32> {
    let mut nums = Vec::new();
    let mut cur = String::new();
    for c in port_name.chars() {
        if c.is_ascii_digit() {
            cur.push(c);
        } else if !cur.is_empty() {
            if let Ok(n) = cur.parse() {
                nums.push(n);
            }
            cur.clear();
        }
    }
    if let Ok(n) = cur.parse() {
        nums.push(n);
    }
    nums
}

/// Best-effort match of a resolved switch port to a collected PoE `(group, port)` entry.
/// Heuristic (documented as such): the PoE port index equals the last number of the port name,
/// and either there is only one PSE group or the group equals the name's first number. When
/// matched, returns a [`PoeInfo`] tagged with the switch and port names.
pub fn lookup_port_poe(
    poe: &PoePortMap,
    port_name: &str,
    _port_index: Option<u32>,
    switch_name: &str,
) -> Option<crate::models::PoeInfo> {
    let nums = port_name_numbers(port_name);
    let last = *nums.last()?;
    let first = nums.first().copied();
    let single_group = poe
        .keys()
        .map(|(g, _)| *g)
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        <= 1;
    let (_, data) = poe
        .iter()
        .find(|((g, p), _)| *p == last && (single_group || Some(*g) == first))?;
    if data.status.is_none() && data.class.is_none() && data.watts.is_none() {
        return None;
    }
    Some(crate::models::PoeInfo {
        watts: data.watts,
        max_watts: None,
        class: data.class,
        status: data.status.clone(),
        source: None,
        priority: None,
        switch_name: Some(switch_name.to_string()),
        port: Some(port_name.to_string()),
    })
}

// ---------------------------------------------------------------------------------------------
// Role classification (pure)
// ---------------------------------------------------------------------------------------------

/// `true` when `sys_object_id` lies in the subtree `prefix` (dotted, no trailing dot).
fn oid_in(sys_object_id: Option<&str>, prefix: &str) -> bool {
    sys_object_id.is_some_and(|o| {
        let o = o.trim();
        o == prefix || o.strip_prefix(prefix).is_some_and(|r| r.starts_with('.'))
    })
}

/// Enterprises whose agents are (practically) only network infrastructure: with no better
/// evidence they default to `Switch`.
const NETWORK_ONLY_ENTERPRISES: &[u64] = &[
    9,     // Cisco
    2636,  // Juniper
    14988, // MikroTik
    25506, // H3C
    30065, // Arista
    1916,  // Extreme Networks
];

/// Classify a device from its sysObjectID, sysDescr text, sysServices bit field and whether
/// it answered the BRIDGE-MIB port table (`bridge_ports`). Keyword evidence wins; the
/// services bits, bridge evidence and enterprise number are tie-breakers.
///
/// Vendors that also make non-network products (HP / HPE: printers and servers, Aruba: APs
/// and controllers, Ubiquiti: cameras and APs, Fortinet: phones and APs) are never assumed to
/// be switches from the enterprise number alone: that needs bridge evidence (a BRIDGE-MIB port
/// table or the datalink sysServices bit) or a known switch sysObjectID subtree.
pub fn classify_role(
    sys_object_id: Option<&str>,
    sys_descr: &str,
    sys_services: Option<i64>,
    bridge_ports: bool,
) -> DeviceRole {
    let text = sys_descr.to_ascii_lowercase();
    let any = |needles: &[&str]| needles.iter().any(|n| text.contains(n));
    let ent = sys_object_id.and_then(enterprise_number);

    // Printers first: JetDirect & co. advertise HP's enterprise number and often bridging bits.
    if oid_in(sys_object_id, "1.3.6.1.4.1.11.2.3.9")
        || any(&[
            "jetdirect",
            "laserjet",
            "officejet",
            "designjet",
            "printer",
            "print server",
        ])
    {
        return DeviceRole::Host;
    }
    // Firewalls: the strongest signal, and several overlap switch/router keywords.
    if any(&[
        "fortigate",
        "fortios",
        "palo alto",
        "pan-os",
        "firepower",
        "pfsense",
        "opnsense",
        "sophos",
        "sonicwall",
        "checkpoint",
        "check point",
        "netscreen",
        "cisco asa",
        "adaptive security",
        "srx",
        "meraki mx",
        "watchguard",
        "firewall",
    ]) || matches!(ent, Some(12356) | Some(25461) | Some(3401) | Some(2620) | Some(74) if any(&["firewall", "security", "fortigate", "pan-os", "asa", "srx"]))
    {
        return DeviceRole::Firewall;
    }
    // Access points before switches (many APs advertise bridging).
    if any(&[
        "access point",
        "aironet",
        "air-",
        "ap software",
        "wireless ap",
        "unifi ap",
        "uap-",
        " u6-",
        " u7-",
        "meraki mr",
        "aruba ap",
        "instant ap",
        "arubaos (ap",
        "fortiap",
        "ruckus",
        "mikrotik cap",
        "wifi access",
    ]) && !any(&["wireless lan controller", "wlc", "switch", "router"])
    {
        return DeviceRole::AccessPoint;
    }
    if any(&[
        "switch",
        "catalyst",
        "ws-c",
        "nexus",
        "procurve",
        "aruba 2",
        "aruba 3",
        "arubaos-cx",
        "fortiswitch",
        "powerconnect",
        "ex2300",
        "ex3400",
        "ex4300",
        "qfx",
        "meraki ms",
        "usw-",
        "unifi switch",
        "edgeswitch",
    ]) || oid_in(sys_object_id, "1.3.6.1.4.1.11.2.3.7.11")
    // HP ProCurve / Aruba switch products
    {
        return DeviceRole::Switch;
    }
    if any(&[
        "router",
        "routeros",
        "ios xe software",
        "ios-xr",
        " isr",
        " asr",
        "edgerouter",
        "edgeos",
        "vyos",
        "mx240",
        "mx480",
        "gateway",
    ]) {
        return DeviceRole::Router;
    }

    // No keyword hit: lean on sysServices (bit L set => offers OSI layer L), bridge evidence
    // and the vendor.
    let offers = |layer: u32| sys_services.is_some_and(|bits| bits & (1 << (layer - 1)) != 0);
    if sys_services.is_some() {
        if offers(2) && !offers(4) && !offers(7) {
            return DeviceRole::Switch; // datalink only
        }
        if offers(3) && !offers(7) {
            return DeviceRole::Router; // internet layer, not an application host
        }
    }
    let network_only = ent.is_some_and(|e| NETWORK_ONLY_ENTERPRISES.contains(&e));
    if network_only || bridge_ports {
        return DeviceRole::Switch;
    }
    DeviceRole::Host
}

// ---------------------------------------------------------------------------------------------
// Session construction
// ---------------------------------------------------------------------------------------------

/// Map our auth-protocol enum onto the crate's. Every variant is supported by `crypto-rust`.
fn auth_protocol(p: crate::models::SnmpAuthProtocol) -> snmp2::v3::AuthProtocol {
    use crate::models::SnmpAuthProtocol as A;
    use snmp2::v3::AuthProtocol as P;
    match p {
        A::Md5 => P::Md5,
        A::Sha1 => P::Sha1,
        A::Sha224 => P::Sha224,
        A::Sha256 => P::Sha256,
        A::Sha384 => P::Sha384,
        A::Sha512 => P::Sha512,
    }
}

fn priv_cipher(p: crate::models::SnmpPrivProtocol) -> snmp2::v3::Cipher {
    use crate::models::SnmpPrivProtocol as S;
    use snmp2::v3::Cipher as C;
    match p {
        S::Des => C::Des,
        S::Aes128 => C::Aes128,
        S::Aes192 => C::Aes192,
        S::Aes256 => C::Aes256,
    }
}

/// A configured SNMP poller. Cheap to clone/share; opens a fresh UDP session per device.
#[derive(Debug, Clone)]
pub struct SnmpClient {
    cfg: SnmpConfig,
}

/// Rows of one table walk plus, when it ended early, why.
#[derive(Debug, Default)]
struct Walk {
    rows: Vec<OidRow>,
    /// `Some(reason)` when the walk failed or was cut short; `rows` holds what was collected.
    issue: Option<String>,
}

impl Walk {
    fn cut(rows: Vec<OidRow>, issue: impl Into<String>) -> Self {
        Self {
            rows,
            issue: Some(issue.into()),
        }
    }
}

/// Bounded list of per-poll warnings.
#[derive(Debug, Default)]
struct Warnings {
    lines: Vec<String>,
    omitted: usize,
}

impl Warnings {
    fn push(&mut self, line: String) {
        if self.lines.len() < MAX_POLL_WARNINGS {
            self.lines.push(line);
        } else {
            self.omitted += 1;
        }
    }

    fn note(&mut self, table: &str, walk: &Walk) {
        if let Some(issue) = &walk.issue {
            self.push(format!("{table}: {issue}"));
        }
    }

    fn into_lines(mut self) -> Vec<String> {
        if self.omitted > 0 {
            self.lines
                .push(format!("... and {} more warning(s)", self.omitted));
        }
        self.lines
    }
}

/// Run `fut` on its own task so that a panic inside it (e.g. in a dependency) becomes
/// `Err(message)` instead of unwinding through the caller. The task is aborted when the
/// returned future is dropped, so cancellation still works.
pub async fn run_isolated<T, F>(fut: F) -> std::result::Result<T, String>
where
    T: Send + 'static,
    F: std::future::Future<Output = T> + Send + 'static,
{
    struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);
    impl<T> Drop for AbortOnDrop<T> {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let mut task = AbortOnDrop(tokio::spawn(fut));
    match (&mut task.0).await {
        Ok(v) => Ok(v),
        Err(e) if e.is_panic() => {
            let payload = e.into_panic();
            Err(payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic".into()))
        }
        Err(e) => Err(e.to_string()),
    }
}

impl SnmpClient {
    pub fn new(cfg: SnmpConfig) -> Self {
        Self { cfg }
    }

    pub fn config(&self) -> &SnmpConfig {
        &self.cfg
    }

    fn per_request_timeout(&self) -> Duration {
        Duration::from_millis(self.cfg.timeout_ms.clamp(1, 600_000))
    }

    /// Timeout of the cheap reachability probe (never longer than the configured timeout).
    fn probe_timeout(&self) -> Duration {
        self.per_request_timeout().min(PROBE_TIMEOUT)
    }

    fn attempts(&self) -> u8 {
        self.cfg.retries.saturating_add(1)
    }

    fn uses_bulk(&self) -> bool {
        self.cfg.version != SnmpVersion::V1
    }

    /// `true` when the configured SNMPv3 auth/priv pair needs a privacy-key extension
    /// (AES-192/256 with MD5 or SHA-1, AES-256 with SHA-224). Agents implement either the
    /// Reeder or the Blumenthal method for it.
    fn needs_key_extension(&self) -> bool {
        self.cfg.version == SnmpVersion::V3
            && self.cfg.v3.as_ref().is_some_and(|c| {
                c.auth_password.is_some()
                    && c.priv_password.is_some()
                    && priv_cipher(c.priv_protocol)
                        .priv_key_needs_extension(&auth_protocol(c.auth_protocol))
            })
    }

    /// Open a session to `addr` using `community` (community-string polling can override the
    /// configured community for Cisco per-VLAN `community@vlan` indexing). For SNMPv3 this
    /// also runs engine discovery, which doubles as the reachability probe.
    async fn open(
        &self,
        addr: SocketAddr,
        community: &str,
    ) -> std::result::Result<AsyncSession, SnmpPollError> {
        let start_id = ((now_ms() as i32) ^ (std::process::id() as i32)) & 0x7fff_ffff;
        let other = |e: String| SnmpPollError::new(PollFailure::Other, e);
        match self.cfg.version {
            SnmpVersion::V1 => AsyncSession::new_v1(addr, community.as_bytes(), start_id)
                .await
                .map_err(|e| other(format!("SNMPv1 session to {addr}: {e}"))),
            SnmpVersion::V2c => AsyncSession::new_v2c(addr, community.as_bytes(), start_id)
                .await
                .map_err(|e| other(format!("SNMPv2c session to {addr}: {e}"))),
            SnmpVersion::V3 => {
                let creds = self
                    .cfg
                    .v3
                    .as_ref()
                    .ok_or_else(|| other("SNMPv3 requires credentials".into()))?;
                let mut security = snmp2::v3::Security::new(
                    creds.username.as_bytes(),
                    creds.auth_password.as_deref().unwrap_or("").as_bytes(),
                )
                .with_auth_protocol(auth_protocol(creds.auth_protocol));
                security = match (&creds.auth_password, &creds.priv_password) {
                    (Some(_), Some(pw)) => security.with_auth(snmp2::v3::Auth::AuthPriv {
                        cipher: priv_cipher(creds.priv_protocol),
                        privacy_password: pw.as_bytes().to_vec(),
                    }),
                    (Some(_), None) => security.with_auth(snmp2::v3::Auth::AuthNoPriv),
                    (None, Some(_)) => {
                        return Err(other(
                            "SNMPv3 privacy requires an authentication password (there is no \
                             noAuthPriv security level)"
                                .into(),
                        ))
                    }
                    (None, None) => security.with_auth(snmp2::v3::Auth::NoAuthNoPriv),
                };
                // AES-192/256 with MD5/SHA-1 (and AES-256 with SHA-224) need a key-extension
                // method. Start with Reeder; `poll_device` retries the first encrypted request
                // with Blumenthal when the agent cannot decrypt it.
                if self.needs_key_extension() {
                    security = security.with_key_extension_method(snmp2::v3::KeyExtension::Reeder);
                }
                let mut session = AsyncSession::new_v3(addr, start_id, security)
                    .await
                    .map_err(|e| other(format!("SNMPv3 session to {addr}: {e}")))?;
                // Engine-ID / boots-time discovery (unauthenticated, so it cannot detect a
                // wrong key-extension method). AuthUpdated just means "state learned, retry".
                let mut timeouts = 0u8;
                for _ in 0..MAX_AUTH_UPDATES + PROBE_ATTEMPTS {
                    match tokio::time::timeout(self.probe_timeout(), session.init()).await {
                        Ok(Ok(())) => return Ok(session),
                        Ok(Err(snmp2::Error::AuthUpdated)) => continue,
                        Ok(Err(e)) => {
                            return Err(SnmpPollError::new(
                                classify_snmp_error(&e),
                                format!("SNMPv3 engine discovery with {addr} failed: {e}"),
                            ))
                        }
                        Err(_) => {
                            timeouts += 1;
                            if timeouts >= PROBE_ATTEMPTS {
                                return Err(SnmpPollError::new(
                                    PollFailure::NoResponse,
                                    format!("no SNMPv3 response from {addr} (timeout)"),
                                ));
                            }
                        }
                    }
                }
                Err(other(format!(
                    "SNMPv3 engine discovery did not converge for {addr}"
                )))
            }
        }
    }

    // ----- one-shot requests (each copies results out before returning) ----------------------

    /// GET several scalar OIDs in one request; returns `(oid, value)` pairs. Timeouts and
    /// malformed replies are retried up to `attempts` times; authentication errors and ICMP
    /// unreachables are not (retrying cannot fix them).
    async fn get_many_with(
        &self,
        session: &mut AsyncSession,
        oids: &[Oid<'static>],
        timeout: Duration,
        attempts: u8,
    ) -> std::result::Result<Vec<OidRow>, SnmpPollError> {
        let refs: Vec<&Oid> = oids.iter().collect();
        let mut last: Option<SnmpPollError> = None;
        for _ in 0..attempts.max(1) {
            let mut auth_rounds = 0u8;
            loop {
                match tokio::time::timeout(timeout, session.get_many(&refs)).await {
                    Ok(Ok(pdu)) => {
                        let out = pdu
                            .varbinds
                            .map(|(o, v)| {
                                (
                                    o.iter().map(|it| it.collect()).unwrap_or_default(),
                                    SnmpValue::from_value(&v),
                                )
                            })
                            .collect();
                        return Ok(out);
                    }
                    Ok(Err(snmp2::Error::AuthUpdated)) if auth_rounds < MAX_AUTH_UPDATES => {
                        auth_rounds += 1;
                        continue;
                    }
                    Ok(Err(e)) => {
                        let err = SnmpPollError::new(
                            classify_snmp_error(&e),
                            format!("SNMP GET failed: {e}"),
                        );
                        if err.kind != PollFailure::Other {
                            return Err(err);
                        }
                        last = Some(err);
                        break;
                    }
                    Err(_) => {
                        last = Some(SnmpPollError::new(
                            PollFailure::NoResponse,
                            "SNMP GET timed out",
                        ));
                        break;
                    }
                }
            }
        }
        Err(last.unwrap_or_else(|| SnmpPollError::new(PollFailure::NoResponse, "no response")))
    }

    async fn get_many(
        &self,
        session: &mut AsyncSession,
        oids: &[Oid<'static>],
    ) -> std::result::Result<Vec<OidRow>, SnmpPollError> {
        self.get_many_with(session, oids, self.per_request_timeout(), self.attempts())
            .await
    }

    /// One GETBULK (v2c/v3) or GETNEXT (v1) step from `from`. Returns `(oid, value)` pairs in
    /// order plus the response error-status (non-zero on v1 end-of-table `noSuchName`).
    async fn step(
        &self,
        session: &mut AsyncSession,
        from: &Oid<'static>,
    ) -> std::result::Result<(Vec<OidRow>, u32), SnmpPollError> {
        let timeout = self.per_request_timeout();
        let bulk = self.uses_bulk();
        let mut last: Option<SnmpPollError> = None;
        for _ in 0..self.attempts() {
            let mut auth_rounds = 0u8;
            loop {
                let fut = async {
                    if bulk {
                        session.getbulk(&[from], 0, BULK_REPETITIONS).await
                    } else {
                        session.getnext(from).await
                    }
                };
                match tokio::time::timeout(timeout, fut).await {
                    Ok(Ok(pdu)) => {
                        let err_status = pdu.error_status;
                        let rows = pdu
                            .varbinds
                            .map(|(o, v)| {
                                (
                                    o.iter().map(|it| it.collect()).unwrap_or_default(),
                                    SnmpValue::from_value(&v),
                                )
                            })
                            .collect();
                        return Ok((rows, err_status));
                    }
                    Ok(Err(snmp2::Error::AuthUpdated)) if auth_rounds < MAX_AUTH_UPDATES => {
                        auth_rounds += 1;
                        continue;
                    }
                    Ok(Err(e)) => {
                        let err = SnmpPollError::new(
                            classify_snmp_error(&e),
                            format!("walk step failed: {e}"),
                        );
                        if err.kind != PollFailure::Other {
                            return Err(err);
                        }
                        last = Some(err);
                        break;
                    }
                    Err(_) => {
                        last = Some(SnmpPollError::new(
                            PollFailure::NoResponse,
                            "request timed out",
                        ));
                        break;
                    }
                }
            }
        }
        Err(last.unwrap_or_else(|| SnmpPollError::new(PollFailure::NoResponse, "no response")))
    }

    /// Walk the subtree rooted at `base`, returning `(index-suffix, value)` rows. Stops at the
    /// end of the subtree, on an SNMP end marker or when the agent fails to advance (loop).
    /// Stops early, keeping the rows collected so far and reporting why, on a request failure,
    /// at `row_cap` rows, when the byte budget is spent, on an over-long index, or when the
    /// device deadline passes.
    async fn walk(
        &self,
        session: &mut AsyncSession,
        base: &[u64],
        deadline: Instant,
        row_cap: usize,
    ) -> Walk {
        let row_cap = row_cap.min(MAX_WALK_ROWS);
        let mut rows: Vec<OidRow> = Vec::new();
        let mut bytes = 0usize;
        let mut cursor: Vec<u64> = base.to_vec();
        if row_cap == 0 {
            return Walk::cut(rows, "mapping cap reached; not walked");
        }
        loop {
            if Instant::now() >= deadline {
                return Walk::cut(
                    rows,
                    format!(
                        "device time budget ({} s) exhausted",
                        DEVICE_BUDGET.as_secs()
                    ),
                );
            }
            let (batch, err_status) = match self.step(session, &oid(&cursor)).await {
                Ok(v) => v,
                Err(e) => return Walk::cut(rows, e.message),
            };
            // v1 signals the end of a table with noSuchName (error-status 2).
            if !self.uses_bulk() && err_status != 0 {
                break;
            }
            if batch.is_empty() {
                break;
            }
            let mut advanced = false;
            let mut done = false;
            let mut last_full: Option<Vec<u64>> = None;
            for (full, value) in batch {
                let Some(suffix) = suffix_of(base, &full) else {
                    done = true; // left the subtree
                    break;
                };
                if value.is_end_marker() {
                    done = true;
                    break;
                }
                // Loop / non-advance protection: each OID must be strictly greater than the
                // cursor we asked from.
                if oid_le(&full, &cursor) {
                    done = true;
                    break;
                }
                if suffix.len() > MAX_INDEX_SUBIDS {
                    return Walk::cut(rows, "agent returned an over-long table index");
                }
                bytes = bytes.saturating_add(suffix.len() * 8 + value.approx_size() + 32);
                if bytes > MAX_WALK_BYTES {
                    return Walk::cut(rows, "walk exceeded its memory budget");
                }
                rows.push((suffix.to_vec(), value));
                last_full = Some(full);
                advanced = true;
                if rows.len() >= row_cap {
                    return Walk::cut(rows, format!("row cap ({row_cap}) reached"));
                }
            }
            if done || !advanced {
                break;
            }
            match last_full {
                Some(full) => cursor = full,
                None => break,
            }
        }
        Walk { rows, issue: None }
    }

    /// Walk the POWER-ETHERNET-MIB (`pethPsePortTable`, `pethMainPse`) and the Cisco
    /// `cpeExtPsePortPwrConsumption` extension. Returns per-port PoE state (keyed by the
    /// `group.port` index) and the switch-wide budget. Both are `None` when the device does
    /// not implement the MIB (the common case for non-PoE gear). Failed / truncated walks are
    /// noted in `warnings` but never fail the whole poll.
    async fn collect_poe(
        &self,
        session: &mut AsyncSession,
        deadline: Instant,
        warnings: &mut Warnings,
    ) -> (Option<PoePortMap>, Option<crate::models::PoeBudget>) {
        let mut ports: PoePortMap = PoePortMap::new();

        let walk = self
            .walk(session, PETH_PSE_PORT_DETECTION, deadline, MAX_WALK_ROWS)
            .await;
        warnings.note("PoE port status", &walk);
        for (suffix, value) in walk.rows {
            if let (Some(idx), Some(v)) = (group_port(&suffix), value.as_u32()) {
                if let Some(label) = poe_detection_label(v) {
                    ports.entry(idx).or_default().status = Some(label.to_string());
                }
            }
        }
        let walk = self
            .walk(session, PETH_PSE_PORT_CLASS, deadline, MAX_WALK_ROWS)
            .await;
        warnings.note("PoE port class", &walk);
        for (suffix, value) in walk.rows {
            if let (Some(idx), Some(v)) = (group_port(&suffix), value.as_u32()) {
                if let Some(class) = poe_class_from_enum(v) {
                    ports.entry(idx).or_default().class = Some(class);
                }
            }
        }
        let walk = self
            .walk(session, CISCO_CPE_EXT_PSE_PORT_PWR, deadline, MAX_WALK_ROWS)
            .await;
        // Cisco-only: absence is normal, so do not flag it as a partial result.
        for (suffix, value) in walk.rows {
            if let (Some(idx), Some(mw)) = (group_port(&suffix), value.as_u32()) {
                if mw > 0 {
                    ports.entry(idx).or_default().watts = Some(mw as f32 / 1000.0);
                }
            }
        }

        // Switch-wide budget (summed over PSE groups).
        let mut nominal = 0.0f32;
        let mut consumed = 0.0f32;
        let mut have_nominal = false;
        let mut have_consumed = false;
        let mut threshold = None;
        let walk = self
            .walk(session, PETH_MAIN_PSE_POWER, deadline, MAX_WALK_ROWS)
            .await;
        for (_, value) in walk.rows {
            if let Some(w) = value.as_u32() {
                nominal += w as f32;
                have_nominal = true;
            }
        }
        let walk = self
            .walk(session, PETH_MAIN_PSE_CONSUMPTION, deadline, MAX_WALK_ROWS)
            .await;
        for (_, value) in walk.rows {
            if let Some(w) = value.as_u32() {
                consumed += w as f32;
                have_consumed = true;
            }
        }
        let walk = self
            .walk(session, PETH_MAIN_PSE_THRESHOLD, deadline, MAX_WALK_ROWS)
            .await;
        for (_, value) in walk.rows {
            if let Some(pct) = value.as_u32() {
                threshold = u8::try_from(pct).ok();
                break;
            }
        }

        let ports_delivering = ports
            .values()
            .filter(|p| p.status.as_deref() == Some("delivering"))
            .count() as u32;
        let budget = if have_nominal || have_consumed || threshold.is_some() {
            Some(crate::models::PoeBudget {
                nominal_watts: have_nominal.then_some(nominal),
                consumed_watts: have_consumed.then_some(consumed),
                usage_threshold_pct: threshold,
                ports_delivering,
            })
        } else {
            None
        };
        let ports = (!ports.is_empty()).then_some(ports);
        (ports, budget)
    }

    /// Poll one device and return its structured SNMP view. Fails (rather than returning an
    /// empty record) when the device does not answer or the system group cannot be read, so
    /// callers can treat the device as not SNMP-reachable. Table walks that fail part-way
    /// yield a `partial` result with the rows collected so far.
    ///
    /// The configuration is validated first, the poll holds one permit of the global
    /// [`SocketBudget`], and the session work runs on its own task: a panic inside the SNMP
    /// library becomes an error instead of tearing down the caller.
    pub async fn poll_device(&self, ip: IpAddr) -> Result<SnmpDeviceInfo> {
        self.cfg
            .validate()
            .map_err(|e| SnmpPollError::new(PollFailure::Other, e.to_string()))?;
        let _permit = SocketBudget::global().acquire().await;
        let client = self.clone();
        match run_isolated(async move { client.poll_device_inner(ip).await }).await {
            Ok(res) => res,
            Err(panic) => Err(SnmpPollError::new(
                PollFailure::Other,
                format!("SNMP poll of {ip} failed inside the SNMP library: {panic}"),
            )
            .into()),
        }
    }

    async fn poll_device_inner(&self, ip: IpAddr) -> Result<SnmpDeviceInfo> {
        let deadline = Instant::now() + DEVICE_BUDGET;
        let addr = SocketAddr::new(ip, self.cfg.port);
        let community = self.cfg.community.clone();
        let mut session = self.open(addr, &community).await?;

        // Cheap reachability probe before anything heavy (v3 engine discovery in `open`
        // already was one): silent hosts cost one short timeout, not a full retry cycle.
        if self.cfg.version != SnmpVersion::V3 {
            self.get_many_with(
                &mut session,
                &[oid(SYS_OBJECT_ID)],
                self.probe_timeout(),
                PROBE_ATTEMPTS.min(self.attempts()),
            )
            .await
            .map_err(|e| {
                let hint = if e.kind == PollFailure::NoResponse {
                    " (no agent, filtered, or wrong community)"
                } else {
                    ""
                };
                SnmpPollError::new(
                    e.kind,
                    format!("no SNMP response from {ip}: {}{hint}", e.message),
                )
            })?;
        }

        // --- system group (first authenticated / encrypted request for v3) ---
        let sys_oids = [
            oid(SYS_DESCR),
            oid(SYS_OBJECT_ID),
            oid(SYS_UPTIME),
            oid(SYS_NAME),
            oid(SYS_SERVICES),
        ];
        let sys = match self.get_many(&mut session, &sys_oids).await {
            Ok(rows) => rows,
            Err(first) if self.needs_key_extension() => {
                // snmp2's engine discovery succeeds whichever key-extension method we picked;
                // a mismatch only shows on the first encrypted request (a decryption report,
                // or silence). Retry it once with the other method (Blumenthal).
                let switched = tokio::time::timeout(
                    self.per_request_timeout(),
                    session.try_another_key_extension_method(),
                )
                .await;
                match switched {
                    Ok(Ok(Some(method))) => {
                        tracing::debug!("SNMPv3 {ip}: retrying with key extension {method:?}");
                        self.get_many(&mut session, &sys_oids).await.map_err(|e| {
                            SnmpPollError::new(
                                e.kind,
                                format!(
                                    "SNMP system group unreadable with either AES key-extension \
                                     method (Reeder: {}; Blumenthal: {})",
                                    first.message, e.message
                                ),
                            )
                        })?
                    }
                    _ => {
                        return Err(SnmpPollError::new(
                            first.kind,
                            format!("SNMP system group unreadable: {}", first.message),
                        )
                        .into())
                    }
                }
            }
            Err(e) => {
                return Err(SnmpPollError::new(
                    e.kind,
                    format!("SNMP system group unreadable: {}", e.message),
                )
                .into())
            }
        };

        let mut sys_descr = None;
        let mut sys_object_id = None;
        let mut sys_uptime_ticks = None;
        let mut sys_name = None;
        let mut sys_services = None;
        for (o, v) in &sys {
            if o == SYS_DESCR {
                sys_descr = v.text();
            } else if o == SYS_OBJECT_ID {
                if let SnmpValue::Oid(parts) = v {
                    sys_object_id = Some(oid_to_string(parts));
                }
            } else if o == SYS_UPTIME {
                sys_uptime_ticks = v.as_u32();
            } else if o == SYS_NAME {
                sys_name = v.text();
            } else if o == SYS_SERVICES {
                sys_services = match v {
                    SnmpValue::Int(i) => Some(*i),
                    _ => v.as_u32().map(i64::from),
                };
            }
        }
        // A device that answers nothing of the system group is not really SNMP-reachable.
        if sys_descr.is_none() && sys_name.is_none() && sys_object_id.is_none() {
            return Err(SnmpPollError::new(
                PollFailure::Other,
                format!("{ip} did not return any system MIB values"),
            )
            .into());
        }
        let switch_name = sys_name.clone().unwrap_or_else(|| ip.to_string());
        let mut warnings = Warnings::default();

        // --- VLANs (Q-BRIDGE static names, then Cisco VTP) ---
        let mut vlans: BTreeMap<u16, VlanInfo> = BTreeMap::new();
        let walk = self
            .walk(
                &mut session,
                DOT1Q_VLAN_STATIC_NAME,
                deadline,
                MAX_WALK_ROWS,
            )
            .await;
        warnings.note("Q-BRIDGE VLAN names", &walk);
        for (suffix, value) in walk.rows {
            if let Some(id) = vlan_index(&suffix) {
                let v = vlans
                    .entry(id)
                    .or_insert_with(|| new_snmp_vlan(id, &switch_name));
                v.name = value.text().or_else(|| v.name.clone());
            }
        }
        let walk = self
            .walk(&mut session, VTP_VLAN_NAME, deadline, MAX_WALK_ROWS)
            .await;
        warnings.note("Cisco VTP VLAN names", &walk);
        for (suffix, value) in walk.rows {
            if let Some(id) = vlan_index(&suffix) {
                let v = vlans
                    .entry(id)
                    .or_insert_with(|| new_snmp_vlan(id, &switch_name));
                if v.name.is_none() {
                    v.name = value.text();
                }
            }
        }

        // --- interface-name maps ---
        let mut base_port_ifindex: HashMap<u32, u32> = HashMap::new();
        let walk = self
            .walk(
                &mut session,
                DOT1D_BASE_PORT_IFINDEX,
                deadline,
                MAX_WALK_ROWS,
            )
            .await;
        warnings.note("BRIDGE-MIB port table", &walk);
        for (suffix, value) in walk.rows {
            if let (Some(&port), Some(ifindex)) = (suffix.last(), value.as_u32()) {
                if let Ok(port) = u32::try_from(port) {
                    base_port_ifindex.insert(port, ifindex);
                }
            }
        }
        let mut if_names: HashMap<u32, String> = HashMap::new();
        let walk = self
            .walk(&mut session, IF_NAME, deadline, MAX_WALK_ROWS)
            .await;
        warnings.note("ifName", &walk);
        for (suffix, value) in walk.rows {
            if let (Some(&ifindex), Some(name)) = (suffix.last(), value.text()) {
                if let Ok(ifindex) = u32::try_from(ifindex) {
                    if_names.insert(ifindex, name);
                }
            }
        }
        let walk = self
            .walk(&mut session, IF_DESCR, deadline, MAX_WALK_ROWS)
            .await;
        warnings.note("ifDescr", &walk);
        for (suffix, value) in walk.rows {
            if let (Some(&ifindex), Some(name)) = (suffix.last(), value.text()) {
                if let Ok(ifindex) = u32::try_from(ifindex) {
                    if_names.entry(ifindex).or_insert(name);
                }
            }
        }

        // --- Power-over-Ethernet (POWER-ETHERNET-MIB + Cisco extension) ---
        let (poe_ports, poe_budget) = self
            .collect_poe(&mut session, deadline, &mut warnings)
            .await;
        // --- Per-port voice VLAN (Cisco; absence is normal and not a partial result) ---
        let mut voice_vlans: HashMap<u32, u16> = HashMap::new();
        let walk = self
            .walk(&mut session, CISCO_VM_VOICE_VLAN, deadline, MAX_WALK_ROWS)
            .await;
        for (suffix, value) in walk.rows {
            if let (Some(&ifindex), Some(vid)) = (suffix.last(), value.as_u32()) {
                if let (Ok(ifindex), Some(vid)) = (u32::try_from(ifindex), voice_vlan_value(vid)) {
                    voice_vlans.insert(ifindex, vid);
                }
            }
        }

        // --- forwarding database → MAC-to-port ---
        // Keyed by (vlan, mac) so the same MAC on two VLANs is two mappings. At most
        // MAX_DEVICE_MAPPINGS across every table and VLAN context.
        let mut mappings: FdbMap = FdbMap::new();

        // Preferred: Q-BRIDGE per-VLAN FDB (also yields the VLAN id).
        let walk = self
            .walk(
                &mut session,
                DOT1Q_TP_FDB_PORT,
                deadline,
                MAX_DEVICE_MAPPINGS,
            )
            .await;
        warnings.note("Q-BRIDGE FDB", &walk);
        for (suffix, value) in walk.rows {
            if let (Some((vlan, mac)), Some(port)) =
                (vlan_and_mac_from_suffix(&suffix), value.as_u32())
            {
                if port != 0 {
                    mappings.insert((Some(vlan), mac), (port, Some(vlan)));
                }
            }
        }
        // Fallback: classic 802.1D FDB (no VLAN in the index).
        if mappings.is_empty() {
            let walk = self
                .walk(
                    &mut session,
                    DOT1D_TP_FDB_PORT,
                    deadline,
                    MAX_DEVICE_MAPPINGS,
                )
                .await;
            warnings.note("BRIDGE-MIB FDB", &walk);
            for (suffix, value) in walk.rows {
                if let (Some(mac), Some(port)) = (mac_from_suffix(&suffix), value.as_u32()) {
                    if port != 0 {
                        mappings.insert((None, mac), (port, None));
                    }
                }
            }
        }
        // The per-VLAN loop opens its own sessions; release this socket first.
        drop(session);
        // Cisco Catalyst per-VLAN community indexing when the bridge tables came back empty.
        if mappings.is_empty() && self.cfg.version != SnmpVersion::V3 && !vlans.is_empty() {
            for &vid in vlans
                .keys()
                .filter(|v| !CISCO_RESERVED_VLANS.contains(v))
                .take(MAX_COMMUNITY_VLANS)
            {
                if Instant::now() >= deadline {
                    warnings.push(format!(
                        "per-VLAN FDB: device time budget ({} s) exhausted at VLAN {vid}",
                        DEVICE_BUDGET.as_secs()
                    ));
                    break;
                }
                let remaining = MAX_DEVICE_MAPPINGS.saturating_sub(mappings.len());
                if remaining == 0 {
                    warnings.push(format!(
                        "per-VLAN FDB: mapping cap ({MAX_DEVICE_MAPPINGS}) reached at VLAN {vid}"
                    ));
                    break;
                }
                let vcommunity = format!("{community}@{vid}");
                let Ok(mut vsession) = self.open(addr, &vcommunity).await else {
                    continue;
                };
                let walk = self
                    .walk(&mut vsession, DOT1D_TP_FDB_PORT, deadline, remaining)
                    .await;
                warnings.note(&format!("BRIDGE-MIB FDB (VLAN {vid})"), &walk);
                for (suffix, value) in walk.rows {
                    if let (Some(mac), Some(port)) = (mac_from_suffix(&suffix), value.as_u32()) {
                        if port != 0 && mappings.len() < MAX_DEVICE_MAPPINGS {
                            mappings.insert((Some(vid), mac), (port, Some(vid)));
                        }
                    }
                }
            }
        }

        // Role, now that we know whether the agent has a bridge (BRIDGE-MIB port table).
        let role = classify_role(
            sys_object_id.as_deref(),
            sys_descr.as_deref().unwrap_or(""),
            sys_services,
            !base_port_ifindex.is_empty(),
        );

        // Count MACs per resolved port name, then build the mapping list.
        let mut counts: HashMap<(String, Option<u32>), u32> = HashMap::new();
        let mut port_mappings = Vec::with_capacity(mappings.len());
        for ((_, mac), (bridge_port, vlan_id)) in mappings {
            let (port_name, port_index) =
                resolve_port_name(bridge_port, &base_port_ifindex, &if_names);
            *counts.entry((port_name.clone(), port_index)).or_insert(0) += 1;
            let poe = poe_ports
                .as_ref()
                .and_then(|p| lookup_port_poe(p, &port_name, port_index, &switch_name));
            port_mappings.push(SwitchPortMapping {
                switch_name: switch_name.clone(),
                switch_ip: Some(ip),
                port_name,
                port_index,
                vlan_id,
                mac: crate::models::format_mac(&mac),
                poe,
                voice_vlan: port_index.and_then(|i| voice_vlans.get(&i).copied()),
            });
        }
        let mut port_mac_counts: Vec<PortMacCount> = counts
            .into_iter()
            .map(|((port_name, port_index), mac_count)| PortMacCount {
                port_name,
                port_index,
                mac_count,
            })
            .collect();
        port_mac_counts.sort_by(|a, b| {
            b.mac_count
                .cmp(&a.mac_count)
                .then(a.port_name.cmp(&b.port_name))
        });

        let warnings = warnings.into_lines();
        Ok(SnmpDeviceInfo {
            sys_name,
            sys_descr,
            sys_uptime_ticks,
            sys_object_id,
            role,
            vlans: vlans.into_values().collect(),
            port_mappings,
            port_mac_counts,
            poe_budget,
            partial: !warnings.is_empty(),
            warnings,
        })
    }
}

/// Cisco's default FDDI / Token Ring VLANs: never carry Ethernet MACs, and their
/// `community@vlan` contexts usually do not answer (each would cost a full timeout).
const CISCO_RESERVED_VLANS: [u16; 4] = [1002, 1003, 1004, 1005];

/// The VLAN id at the end of a VLAN-table index, when it is a valid 802.1Q id.
fn vlan_index(suffix: &[u64]) -> Option<u16> {
    let id = u16::try_from(*suffix.last()?).ok()?;
    (1..=MAX_VLAN_ID).contains(&id).then_some(id)
}

fn new_snmp_vlan(id: u16, switch_name: &str) -> VlanInfo {
    let mut v = VlanInfo::new(id, VlanSource::Snmp);
    v.switch_name = Some(switch_name.to_string());
    v
}

/// Render OID sub-identifiers as a dotted string.
fn oid_to_string(parts: &[u64]) -> String {
    parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// `a <= b` by SNMP lexicographic OID order.
fn oid_le(a: &[u64], b: &[u64]) -> bool {
    use std::cmp::Ordering;
    for (x, y) in a.iter().zip(b) {
        match x.cmp(y) {
            Ordering::Less => return true,
            Ordering::Greater => return false,
            Ordering::Equal => {}
        }
    }
    a.len() <= b.len()
}

// ---------------------------------------------------------------------------------------------
// Concurrent candidate probing
// ---------------------------------------------------------------------------------------------

/// Outcome counts of one [`probe_candidates`] run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SnmpPollStats {
    pub polled: usize,
    pub ok: usize,
    /// Of `ok`: results with failed / truncated table walks.
    pub partial: usize,
    pub no_response: usize,
    pub auth_failures: usize,
    pub errors: usize,
}

impl SnmpPollStats {
    /// The per-scan summary log line.
    pub fn summary(&self) -> String {
        format!(
            "SNMP: polled {} host(s): {} answered ({} partial), {} no response / timeout, {} \
             authentication failure(s), {} other error(s)",
            self.polled, self.ok, self.partial, self.no_response, self.auth_failures, self.errors
        )
    }

    fn record(&mut self, outcome: PollOutcome) {
        match outcome {
            PollOutcome::Skipped => return,
            PollOutcome::Ok { partial } => {
                self.ok += 1;
                if partial {
                    self.partial += 1;
                }
            }
            PollOutcome::Failed(PollFailure::NoResponse) => self.no_response += 1,
            PollOutcome::Failed(PollFailure::Auth) => self.auth_failures += 1,
            PollOutcome::Failed(PollFailure::Other) => self.errors += 1,
        }
        self.polled += 1;
    }
}

#[derive(Debug, Clone, Copy)]
enum PollOutcome {
    Skipped,
    Ok { partial: bool },
    Failed(PollFailure),
}

/// Poll every candidate in `ips` with bounded concurrency, emitting a [`ScanEvent::Device`]
/// (role + SNMP evidence), one [`ScanEvent::Vlan`] per discovered VLAN and one
/// [`ScanEvent::PortMapping`] per learned MAC (at most [`MAX_DEVICE_MAPPINGS`] per device).
/// Cancellation stops dispatch promptly. One unit of `progress` is counted per candidate.
///
/// Partial results and non-timeout failures are logged per device (the first
/// [`MAX_FAILURE_LOGS`] to the scan log, all of them to `tracing`), and a summary line with
/// the outcome counts ends the run.
pub async fn probe_candidates(
    ips: Vec<IpAddr>,
    cfg: &SnmpConfig,
    tx: Sender<ScanEvent>,
    cancel: CancellationToken,
    progress: ProgressScope,
) -> SnmpPollStats {
    let client = SnmpClient::new(cfg.clone());
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_POLLS));
    let logged = Arc::new(AtomicUsize::new(0));
    let mut tasks = tokio::task::JoinSet::new();
    let mut stats = SnmpPollStats::default();
    let record = |stats: &mut SnmpPollStats, res: Result<PollOutcome, tokio::task::JoinError>| {
        stats.record(res.unwrap_or(PollOutcome::Failed(PollFailure::Other)));
    };

    for ip in ips {
        if cancel.is_cancelled() {
            break;
        }
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        let (client, tx, cancel, logged, progress) = (
            client.clone(),
            tx.clone(),
            cancel.clone(),
            logged.clone(),
            progress.clone(),
        );
        tasks.spawn(async move {
            let _permit = permit;
            let res = if cancel.is_cancelled() {
                None
            } else {
                tokio::select! {
                    _ = cancel.cancelled() => None,
                    res = client.poll_device(ip) => Some(res),
                }
            };
            progress.add(1);
            let may_log = || logged.fetch_add(1, Ordering::Relaxed) < MAX_FAILURE_LOGS;
            match res {
                None => PollOutcome::Skipped,
                Some(Ok(info)) => {
                    if info.partial {
                        tracing::info!("SNMP {ip}: partial result: {}", info.warnings.join("; "));
                        if may_log() {
                            let _ = tx
                                .send(ScanEvent::warn(format!(
                                    "SNMP {ip}: partial result ({})",
                                    info.warnings.join("; ")
                                )))
                                .await;
                        }
                    }
                    emit_device_info(ip, &info, &tx).await;
                    PollOutcome::Ok {
                        partial: info.partial,
                    }
                }
                Some(Err(e)) => {
                    let kind = failure_kind(&e);
                    tracing::debug!("SNMP poll of {ip} failed: {e:#}");
                    // Silent hosts are the common case on a mixed network: count them only.
                    if kind != PollFailure::NoResponse && may_log() {
                        let _ = tx.send(ScanEvent::warn(format!("SNMP {ip}: {e:#}"))).await;
                    }
                    PollOutcome::Failed(kind)
                }
            }
        });
        while let Some(res) = tasks.try_join_next() {
            record(&mut stats, res);
        }
    }
    while let Some(res) = tasks.join_next().await {
        record(&mut stats, res);
    }
    let _ = tx.send(ScanEvent::info(stats.summary())).await;
    stats
}

/// Turn one [`SnmpDeviceInfo`] into stream events for `ip`.
async fn emit_device_info(ip: IpAddr, info: &SnmpDeviceInfo, tx: &Sender<ScanEvent>) {
    // The infrastructure device itself: role plus a vendor guess from sysDescr.
    let mut dev = crate::models::Device::new(ip);
    dev.role = info.role;
    dev.vendor = info
        .sys_descr
        .as_deref()
        .map(vendor_hint)
        .filter(|s| !s.is_empty());
    dev.add_source(DiscoverySource::Snmp);
    let _ = tx.send(ScanEvent::device(dev)).await;

    for v in &info.vlans {
        let _ = tx.send(ScanEvent::Vlan(v.clone())).await;
    }
    for pm in info.port_mappings.iter().take(MAX_DEVICE_MAPPINGS) {
        let _ = tx.send(ScanEvent::PortMapping(pm.clone())).await;
    }
}

/// A coarse vendor label from a sysDescr: its first word, trimmed (e.g. "Cisco").
fn vendor_hint(sys_descr: &str) -> String {
    sys_descr
        .split_whitespace()
        .next()
        .map(sanitize_text)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_parsed_from_oid_suffix() {
        // dot1dTpFdbAddress / dot1dTpFdbPort index: 6 MAC octets.
        assert_eq!(
            mac_from_suffix(&[0x00, 0x1a, 0x2b, 0x03, 0x04, 0x05]),
            Some([0x00, 0x1a, 0x2b, 0x03, 0x04, 0x05])
        );
        // A byte out of range rejects the whole index.
        assert_eq!(mac_from_suffix(&[0, 0, 0, 0, 0, 256]), None);
        assert_eq!(mac_from_suffix(&[1, 2, 3]), None);
    }

    #[test]
    fn vlan_and_mac_parsed_from_qbridge_index() {
        // dot1qTpFdbPort index: vlan . mac[0..6].
        assert_eq!(
            vlan_and_mac_from_suffix(&[20, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            Some((20, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))
        );
        assert_eq!(vlan_and_mac_from_suffix(&[4095, 1, 2, 3, 4, 5, 6]), None); // vlan out of range
        assert_eq!(vlan_and_mac_from_suffix(&[10, 1, 2, 3]), None);
    }

    #[test]
    fn bridge_port_resolves_to_ifname() {
        let base: HashMap<u32, u32> = [(1, 10001), (2, 10002)].into_iter().collect();
        let names: HashMap<u32, String> = [
            (10001, "Gi1/0/1".to_string()),
            (10002, "Gi1/0/24".to_string()),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            resolve_port_name(1, &base, &names),
            ("Gi1/0/1".into(), Some(10001))
        );
        assert_eq!(
            resolve_port_name(2, &base, &names),
            ("Gi1/0/24".into(), Some(10002))
        );
        // No ifName for the ifIndex: fall back to the ifIndex label.
        let base2: HashMap<u32, u32> = [(3, 99)].into_iter().collect();
        assert_eq!(
            resolve_port_name(3, &base2, &names),
            ("ifIndex 99".into(), Some(99))
        );
        // Unknown bridge port: synthetic label, no ifIndex.
        assert_eq!(resolve_port_name(7, &base, &names), ("port 7".into(), None));
    }

    #[test]
    fn enterprise_numbers_parse() {
        assert_eq!(enterprise_number("1.3.6.1.4.1.9.1.516"), Some(9));
        assert_eq!(enterprise_number("1.3.6.1.4.1.12356.101.1"), Some(12356));
        assert_eq!(enterprise_number("1.3.6.1.2.1.1"), None);
        assert_eq!(enterprise_number("garbage"), None);
    }

    #[test]
    fn role_classification() {
        assert_eq!(
            classify_role(
                Some("1.3.6.1.4.1.9.1.516"),
                "Cisco IOS Software, Catalyst L3 Switch",
                None,
                true
            ),
            DeviceRole::Switch
        );
        assert_eq!(
            classify_role(
                Some("1.3.6.1.4.1.12356.101.1"),
                "FortiGate-60F",
                None,
                false
            ),
            DeviceRole::Firewall
        );
        assert_eq!(
            classify_role(
                Some("1.3.6.1.4.1.25461.2.3"),
                "Palo Alto Networks PA-220",
                None,
                false
            ),
            DeviceRole::Firewall
        );
        assert_eq!(
            classify_role(None, "Cisco Aironet 2800 Series AP Software", None, false),
            DeviceRole::AccessPoint
        );
        assert_eq!(
            classify_role(Some("1.3.6.1.4.1.14988.1"), "RouterOS RB750", None, false),
            DeviceRole::Router
        );
        // No keywords: sysServices datalink-only => switch; network-only vendor => switch.
        assert_eq!(
            classify_role(None, "some device", Some(0b10), false),
            DeviceRole::Switch
        );
        assert_eq!(
            classify_role(Some("1.3.6.1.4.1.2636.1.1"), "junos box", None, false),
            DeviceRole::Switch
        );
        assert_eq!(
            classify_role(None, "Linux server 5.15", Some(0b1001110), false),
            DeviceRole::Host
        );
    }

    /// M6: vendors that also make printers, servers, APs or cameras are not switches by
    /// enterprise number alone.
    #[test]
    fn role_classification_avoids_vendor_only_false_positives() {
        // HP JetDirect printer: enterprise 11, sysServices 72 (L4 + L7).
        assert_eq!(
            classify_role(
                Some("1.3.6.1.4.1.11.2.3.9.1"),
                "HP ETHERNET MULTI-ENVIRONMENT,ROM none,JETDIRECT,JD153,EEPROM JSI24",
                Some(72),
                false
            ),
            DeviceRole::Host
        );
        // ... even when it happens to expose a bridge table.
        assert_eq!(
            classify_role(
                Some("1.3.6.1.4.1.11.2.3.9.1"),
                "HP LaserJet",
                Some(72),
                true
            ),
            DeviceRole::Host
        );
        // An HP/HPE server with an agent: enterprise 11, no bridge evidence.
        assert_eq!(
            classify_role(
                Some("1.3.6.1.4.1.11.5.7"),
                "Linux ilo 5.10",
                Some(72),
                false
            ),
            DeviceRole::Host
        );
        // HP ProCurve switch subtree, or bridge evidence, is a switch.
        assert_eq!(
            classify_role(
                Some("1.3.6.1.4.1.11.2.3.7.11.181"),
                "2930F-24G",
                Some(72),
                false
            ),
            DeviceRole::Switch
        );
        assert_eq!(
            classify_role(Some("1.3.6.1.4.1.11.2.14.11.5"), "ArubaOS", Some(72), true),
            DeviceRole::Switch
        );
        // Aruba (14823) and Ubiquiti (41112) without evidence: not assumed to be switches.
        assert_eq!(
            classify_role(
                Some("1.3.6.1.4.1.14823.1.1.36"),
                "ArubaOS 8.10",
                Some(72),
                false
            ),
            DeviceRole::Host
        );
        assert_eq!(
            classify_role(
                Some("1.3.6.1.4.1.41112.1.4"),
                "Linux 4.4.153",
                Some(72),
                false
            ),
            DeviceRole::Host
        );
        // UniFi switch: keyword (or bridge evidence) makes it a switch.
        assert_eq!(
            classify_role(
                Some("1.3.6.1.4.1.41112.1.6"),
                "USW-24-PoE, 6.5.59",
                Some(72),
                false
            ),
            DeviceRole::Switch
        );
        assert_eq!(
            classify_role(Some("1.3.6.1.4.1.41112.1.6"), "Linux 3.6.5", Some(72), true),
            DeviceRole::Switch
        );
        // UniFi AP.
        assert_eq!(
            classify_role(
                Some("1.3.6.1.4.1.41112.1.6"),
                "UAP-AC-Pro 6.5.62",
                Some(72),
                true
            ),
            DeviceRole::AccessPoint
        );
        // FortiSwitch / FortiAP are not firewalls.
        assert_eq!(
            classify_role(
                Some("1.3.6.1.4.1.12356.106.1"),
                "FortiSwitch-148F-FPOE",
                None,
                true
            ),
            DeviceRole::Switch
        );
        assert_eq!(
            classify_role(Some("1.3.6.1.4.1.12356.120.1"), "FortiAP-231F", None, false),
            DeviceRole::AccessPoint
        );
    }

    #[test]
    fn poe_helpers_decode_and_match_ports() {
        assert_eq!(poe_detection_label(3), Some("delivering"));
        assert_eq!(poe_detection_label(2), Some("searching"));
        assert_eq!(poe_detection_label(6), Some("fault"));
        assert_eq!(poe_detection_label(0), None);
        assert_eq!(poe_class_from_enum(1), Some(0));
        assert_eq!(poe_class_from_enum(5), Some(4));
        assert_eq!(poe_class_from_enum(9), None);
        assert_eq!(voice_vlan_value(110), Some(110));
        assert_eq!(voice_vlan_value(4096), None); // none
        assert_eq!(voice_vlan_value(4095), None); // untagged 802.1p
        assert_eq!(voice_vlan_value(0), None);
        assert_eq!(group_port(&[1, 24]), Some((1, 24)));
        assert_eq!(group_port(&[24]), None);
        assert_eq!(port_name_numbers("Gi1/0/24"), vec![1, 0, 24]);
        assert_eq!(port_name_numbers("port 7"), vec![7]);

        let mut map = PoePortMap::new();
        map.insert(
            (1, 24),
            PoePortData {
                status: Some("delivering".into()),
                class: Some(2),
                watts: Some(6.1),
            },
        );
        map.insert(
            (2, 24),
            PoePortData {
                status: Some("searching".into()),
                ..PoePortData::default()
            },
        );
        // Stack member 1 port 24 ↔ Gi1/0/24; member 2 port 24 ↔ Gi2/0/24.
        let poe = lookup_port_poe(&map, "Gi1/0/24", Some(10024), "sw1").unwrap();
        assert_eq!(
            (poe.watts, poe.class, poe.status.as_deref()),
            (Some(6.1), Some(2), Some("delivering"))
        );
        assert_eq!(poe.switch_name.as_deref(), Some("sw1"));
        assert_eq!(poe.port.as_deref(), Some("Gi1/0/24"));
        let poe = lookup_port_poe(&map, "Gi2/0/24", None, "sw1").unwrap();
        assert_eq!(poe.status.as_deref(), Some("searching"));
        assert!(lookup_port_poe(&map, "Gi3/0/24", None, "sw1").is_none());
        assert!(lookup_port_poe(&map, "Gi1/0/23", None, "sw1").is_none());
        // Single PSE group: the port number alone matches (e.g. "port 24", "ge-0/0/24").
        let mut single = PoePortMap::new();
        single.insert(
            (1, 24),
            PoePortData {
                watts: Some(4.0),
                ..PoePortData::default()
            },
        );
        assert!(lookup_port_poe(&single, "ge-0/0/24", None, "ex").is_some());
    }

    #[test]
    fn walk_cursor_ordering() {
        assert!(oid_le(&[1, 3, 6, 1], &[1, 3, 6, 1]));
        assert!(oid_le(&[1, 3, 6, 1], &[1, 3, 6, 2]));
        assert!(!oid_le(&[1, 3, 6, 2], &[1, 3, 6, 1]));
        assert!(oid_le(&[1, 3, 6], &[1, 3, 6, 1])); // prefix is "<="
        assert!(!oid_le(&[1, 3, 6, 1], &[1, 3, 6]));
    }

    #[test]
    fn suffix_extraction() {
        assert_eq!(
            suffix_of(&[1, 3, 6, 1], &[1, 3, 6, 1, 10, 20]),
            Some(&[10u64, 20][..])
        );
        assert_eq!(suffix_of(&[1, 3, 6, 1], &[1, 3, 6, 1]), None); // not deeper
        assert_eq!(suffix_of(&[1, 3, 6, 1], &[1, 3, 7, 1, 1]), None); // different subtree
    }

    // --- integration-style walk test against a hand-encoded SNMPv2c responder ---------------

    mod ber {
        //! Minimal BER encoder for building canned SNMP responses in-test.

        pub fn len(n: usize) -> Vec<u8> {
            if n < 0x80 {
                vec![n as u8]
            } else {
                let mut bytes = Vec::new();
                let mut v = n;
                while v > 0 {
                    bytes.insert(0, (v & 0xff) as u8);
                    v >>= 8;
                }
                let mut out = vec![0x80 | bytes.len() as u8];
                out.extend(bytes);
                out
            }
        }

        pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            out.extend(len(content.len()));
            out.extend_from_slice(content);
            out
        }

        pub fn int(mut v: i64) -> Vec<u8> {
            // Minimal two's-complement encoding.
            let mut bytes = Vec::new();
            loop {
                bytes.insert(0, (v & 0xff) as u8);
                v >>= 8;
                if (v == 0 && bytes[0] & 0x80 == 0) || (v == -1 && bytes[0] & 0x80 != 0) {
                    break;
                }
            }
            tlv(0x02, &bytes)
        }

        pub fn octet(s: &[u8]) -> Vec<u8> {
            tlv(0x04, s)
        }

        pub fn oid(parts: &[u64]) -> Vec<u8> {
            let mut body = vec![(parts[0] * 40 + parts[1]) as u8];
            for &sub in &parts[2..] {
                let mut stack = Vec::new();
                let mut v = sub;
                stack.push((v & 0x7f) as u8);
                v >>= 7;
                while v > 0 {
                    stack.push((v & 0x7f) as u8 | 0x80);
                    v >>= 7;
                }
                stack.reverse();
                body.extend(stack);
            }
            tlv(0x06, &body)
        }

        pub fn end_of_mib() -> Vec<u8> {
            vec![0x82, 0x00]
        }

        /// SNMP Timeticks (application tag 0x43), minimal unsigned big-endian content.
        pub fn timeticks(mut v: u32) -> Vec<u8> {
            let mut bytes = Vec::new();
            loop {
                bytes.insert(0, (v & 0xff) as u8);
                v >>= 8;
                if v == 0 {
                    break;
                }
            }
            if bytes[0] & 0x80 != 0 {
                bytes.insert(0, 0);
            }
            tlv(0x43, &bytes)
        }

        pub fn varbind(oid_parts: &[u64], value: &[u8]) -> Vec<u8> {
            let mut inner = oid(oid_parts);
            inner.extend_from_slice(value);
            tlv(0x30, &inner)
        }
    }

    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::UdpSocket;

    /// A tiny fixed SNMPv2c agent: answers the system group GET and the two table walks the
    /// poller performs, returning end-of-MIB markers to terminate.
    async fn fake_agent(sock: UdpSocket, cancel: CancellationToken) {
        fake_agent_with(sock, cancel, false).await
    }

    /// `stall_vlan_continuation`: never answer the VLAN-name walk's second request (a walk
    /// that breaks part-way).
    async fn fake_agent_with(
        sock: UdpSocket,
        cancel: CancellationToken,
        stall_vlan_continuation: bool,
    ) {
        let mut buf = [0u8; 65535];
        loop {
            let (n, peer) = tokio::select! {
                _ = cancel.cancelled() => return,
                r = sock.recv_from(&mut buf) => match r { Ok(v) => v, Err(_) => return },
            };
            let Ok(req) = snmp2::Pdu::from_bytes(&buf[..n]) else {
                continue;
            };
            let req_id = req.req_id;
            let community = req.community.to_vec();
            let is_bulk = req.message_type == snmp2::MessageType::GetBulkRequest;
            // First requested OID.
            let mut vb = req.varbinds.clone();
            let first = vb.next().map(|(o, _)| {
                o.iter()
                    .map(|it| it.collect::<Vec<u64>>())
                    .unwrap_or_default()
            });

            let vlan_base: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 3, 1, 1];
            if stall_vlan_continuation
                && is_bulk
                && first
                    .as_deref()
                    .is_some_and(|f| f.starts_with(vlan_base) && f != vlan_base)
            {
                continue;
            }
            let varbinds = build_reply(first.as_deref(), is_bulk, &mut vb);
            let pdu = ber::tlv(
                0xa2,
                &[
                    ber::int(i64::from(req_id)),
                    ber::int(0),
                    ber::int(0),
                    ber::tlv(0x30, &varbinds),
                ]
                .concat(),
            );
            let msg = ber::tlv(0x30, &[ber::int(1), ber::octet(&community), pdu].concat());
            let _ = sock.send_to(&msg, peer).await;
        }
    }

    fn build_reply(
        first: Option<&[u64]>,
        is_bulk: bool,
        rest: &mut snmp2::Varbinds<'_>,
    ) -> Vec<u8> {
        let sys_descr: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
        let sys_object_id: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 2, 0];
        let sys_uptime: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];
        let sys_name: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];
        let sys_services: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 7, 0];
        let vlan_base: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 3, 1, 1];

        let value_for = |o: &[u64]| -> Vec<u8> {
            if o == sys_descr {
                ber::octet(b"Cisco IOS Software, Catalyst 3850")
            } else if o == sys_object_id {
                // 1.3.6.1.4.1.9.1.516 (a Cisco enterprise OID value, tag 0x06).
                ber::oid(&[1, 3, 6, 1, 4, 1, 9, 1, 516])
            } else if o == sys_uptime {
                ber::timeticks(123456)
            } else if o == sys_name {
                ber::octet(b"core-sw-01")
            } else if o == sys_services {
                ber::int(0b10) // datalink
            } else {
                vec![0x05, 0x00] // NULL
            }
        };

        if !is_bulk {
            // System group GET (get_many): echo each requested OID with its canned value.
            let mut out = Vec::new();
            if let Some(o) = first {
                out.extend(ber::varbind(o, &value_for(o)));
            }
            for (o, _) in rest.by_ref() {
                let o = o
                    .iter()
                    .map(|it| it.collect::<Vec<u64>>())
                    .unwrap_or_default();
                out.extend(ber::varbind(&o, &value_for(&o)));
            }
            return out;
        }

        // GETBULK: this fake only populates the Q-BRIDGE static VLAN-name table, returning two
        // rows then end-of-MIB; every other walk gets an immediate end-of-MIB so it terminates.
        let Some(start) = first else {
            return ber::varbind(&[0, 0], &ber::end_of_mib());
        };
        if start.starts_with(vlan_base) || start == vlan_base {
            // Determine where we are: fresh walk (== base) returns the two rows; a continuation
            // (cursor at the last row) returns end-of-MIB.
            let row1: Vec<u64> = [vlan_base, &[1]].concat();
            let row2: Vec<u64> = [vlan_base, &[20]].concat();
            if start == vlan_base {
                let mut out = ber::varbind(&row1, &ber::octet(b"default"));
                out.extend(ber::varbind(&row2, &ber::octet(b"USERS")));
                return out;
            }
            // Past the first batch: signal the end.
            return ber::varbind(&row2, &ber::end_of_mib());
        }
        ber::varbind(start, &ber::end_of_mib())
    }

    #[tokio::test]
    async fn polls_fake_v2c_agent_and_terminates_walks() {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = sock.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let agent = tokio::spawn(fake_agent(sock, cancel.clone()));

        let cfg = SnmpConfig {
            port: addr.port(),
            timeout_ms: 400,
            retries: 1,
            ..SnmpConfig::v2c("public")
        };
        let client = SnmpClient::new(cfg);
        let info = client
            .poll_device(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .await
            .expect("poll should succeed against the fake agent");

        assert_eq!(info.sys_name.as_deref(), Some("core-sw-01"));
        assert!(info.sys_descr.as_deref().unwrap().contains("Catalyst"));
        assert_eq!(info.sys_object_id.as_deref(), Some("1.3.6.1.4.1.9.1.516"));
        assert_eq!(info.role, DeviceRole::Switch);
        // The VLAN walk returned two rows and then terminated cleanly.
        let ids: Vec<u16> = info.vlans.iter().map(|v| v.id).collect();
        assert_eq!(ids, vec![1, 20]);
        assert_eq!(info.vlans[1].name.as_deref(), Some("USERS"));
        assert_eq!(info.vlans[0].switch_name.as_deref(), Some("core-sw-01"));

        cancel.cancel();
        let _ = agent.await;
    }

    /// M4: a walk that stops answering part-way keeps the rows it already collected, and the
    /// device result is flagged partial instead of losing everything.
    #[tokio::test]
    async fn failing_walk_returns_partial_rows() {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = sock.local_addr().unwrap();
        let cancel = CancellationToken::new();
        // The fake answers the VLAN table's first batch but never its continuation.
        let agent = tokio::spawn(fake_agent_with(sock, cancel.clone(), true));
        let cfg = SnmpConfig {
            port: addr.port(),
            timeout_ms: 300,
            retries: 1,
            ..SnmpConfig::v2c("public")
        };
        let client = SnmpClient::new(cfg);
        let info = client
            .poll_device(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .await
            .expect("a partial poll still succeeds");
        let ids: Vec<u16> = info.vlans.iter().map(|v| v.id).collect();
        assert_eq!(ids, vec![1, 20], "rows before the failure are kept");
        assert!(info.partial);
        assert!(
            info.warnings
                .iter()
                .any(|w| w.contains("Q-BRIDGE VLAN names")),
            "{:?}",
            info.warnings
        );
        cancel.cancel();
        let _ = agent.await;
    }

    /// M3: a panic inside the session work (e.g. snmp2's key localization on an empty
    /// password) must surface as an error, not kill the caller.
    #[tokio::test]
    async fn panics_in_session_work_become_errors() {
        let res: std::result::Result<(), String> =
            run_isolated(async { panic!("index out of bounds") }).await;
        assert_eq!(res.unwrap_err(), "index out of bounds");
        assert_eq!(run_isolated(async { 7 }).await, Ok(7));
        // Invalid credentials are rejected before any session is opened.
        let cfg = SnmpConfig {
            version: SnmpVersion::V3,
            v3: Some(crate::models::SnmpV3Credentials {
                username: "u".into(),
                auth_password: Some(String::new()),
                ..Default::default()
            }),
            ..SnmpConfig::default()
        };
        let err = SnmpClient::new(cfg)
            .poll_device(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("at least 8"), "{err}");
    }

    #[test]
    fn values_and_walk_rows_are_bounded() {
        let big = vec![b'x'; 10_000];
        let v = SnmpValue::from_value(&Value::OctetString(&big));
        assert_eq!(v.octets().unwrap().len(), MAX_VALUE_BYTES);
        let mut w = Warnings::default();
        for i in 0..MAX_POLL_WARNINGS + 3 {
            w.push(format!("w{i}"));
        }
        let lines = w.into_lines();
        assert_eq!(lines.len(), MAX_POLL_WARNINGS + 1);
        assert!(lines.last().unwrap().contains("3 more"));
        assert_eq!(vlan_index(&[1, 20]), Some(20));
        assert_eq!(vlan_index(&[0]), None);
        assert_eq!(vlan_index(&[4095]), None);
    }

    #[test]
    fn poll_stats_summary_counts_outcomes() {
        let mut s = SnmpPollStats::default();
        s.record(PollOutcome::Ok { partial: false });
        s.record(PollOutcome::Ok { partial: true });
        s.record(PollOutcome::Failed(PollFailure::NoResponse));
        s.record(PollOutcome::Failed(PollFailure::Auth));
        s.record(PollOutcome::Failed(PollFailure::Other));
        s.record(PollOutcome::Skipped);
        assert_eq!(
            s,
            SnmpPollStats {
                polled: 5,
                ok: 2,
                partial: 1,
                no_response: 1,
                auth_failures: 1,
                errors: 1
            }
        );
        let line = s.summary();
        assert!(
            line.contains("polled 5") && line.contains("1 authentication"),
            "{line}"
        );
        let e: anyhow::Error = SnmpPollError::new(PollFailure::Auth, "nope").into();
        assert_eq!(failure_kind(&e.context("outer")), PollFailure::Auth);
        assert_eq!(failure_kind(&anyhow::anyhow!("x")), PollFailure::Other);
    }

    #[tokio::test]
    async fn poll_times_out_cleanly_against_dead_port() {
        // Nothing is listening: the poll must fail (not hang) within a bounded time.
        let cfg = SnmpConfig {
            port: 1,
            timeout_ms: 200,
            retries: 0,
            ..SnmpConfig::v2c("public")
        };
        let client = SnmpClient::new(cfg);
        let res = tokio::time::timeout(
            Duration::from_secs(5),
            client.poll_device(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await
        .expect("poll_device must return promptly");
        assert!(res.is_err());
    }
}
