//! Raw layer-2 packet engine.
//!
//! * Interface discovery and classification (Wi-Fi / Ethernet / 802.1Q sub-interface / VPN / ...).
//! * Frame builders for untagged and IEEE 802.1Q-tagged ARP requests and ICMPv6 probes.
//! * Active L2 sweep ([`run_l2_scan`]): paced transmit through a `pnet` datalink channel and
//!   reply capture through libpcap (which re-inserts VLAN tags the Linux kernel strips into
//!   packet metadata, so tagged replies stay attributable to their VLAN).
//! * Passive discovery ([`run_passive_sniffer`]): 802.1Q tag census, CDP, LLDP, VTP and DTP.
//!
//! Frame builders and parsers are pure functions over byte slices so they are unit tested
//! without privileges. Every parser is bounds-checked and returns `None` on malformed input
//! instead of panicking: these bytes come straight off the wire.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    thread,
    time::{Duration, Instant},
};
#[cfg(not(windows))]
use std::{fs, path::Path};

use anyhow::{anyhow, bail, Context, Result};
use pnet::datalink::{self, Channel, DataLinkSender};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;

use crate::{
    models::{
        format_mac, is_link_local_v6, now_ms, parse_mac, sanitize_text, Capability,
        CdpLldpNeighbor, Device, DeviceRole, DiscoverySource, IfAddr, InterfaceInfo, InterfaceKind,
        Ipv4Range, NeighborProtocol, PoeInfo, ScanConfig, ScanEvent, VlanInfo, VlanSelection,
        VlanSource, MAX_VLAN_ID,
    },
    progress::ProgressScope,
};

// ---------------------------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------------------------

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
/// IEEE 802.1Q customer tag.
pub const ETHERTYPE_VLAN: u16 = 0x8100;
/// IEEE 802.1ad service tag (QinQ).
pub const ETHERTYPE_QINQ: u16 = 0x88a8;
/// Pre-standard QinQ service tag still emitted by some vendors.
pub const ETHERTYPE_QINQ_LEGACY: u16 = 0x9100;
pub const ETHERTYPE_LLDP: u16 = 0x88cc;

pub const BROADCAST_MAC: [u8; 6] = [0xff; 6];
pub const CDP_MULTICAST: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc];
pub const LLDP_MULTICAST: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e];
/// `ff02::1`, the IPv6 all-nodes link-local multicast group.
pub const ALL_NODES_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// Minimum Ethernet frame length without FCS; shorter frames are zero padded.
const MIN_FRAME_LEN: usize = 60;
/// Largest value of the EtherType/length field that denotes an IEEE 802.3 length.
const MAX_8023_LENGTH: u16 = 1500;
/// Stacked tags beyond this are treated as malformed.
const MAX_VLAN_TAGS: usize = 4;

const LLC_SNAP: [u8; 3] = [0xaa, 0xaa, 0x03];
const OUI_CISCO: [u8; 3] = [0x00, 0x00, 0x0c];
const SNAP_PID_CDP: u16 = 0x2000;
const SNAP_PID_VTP: u16 = 0x2003;
const SNAP_PID_DTP: u16 = 0x2004;

const OUI_IEEE_8021: [u8; 3] = [0x00, 0x80, 0xc2];
/// IEEE 802.3 organizationally-specific LLDP TLVs (MAC/PHY, power-via-MDI, ...).
const OUI_IEEE_8023: [u8; 3] = [0x00, 0x12, 0x0f];
const OUI_TIA: [u8; 3] = [0x00, 0x12, 0xbb];

const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
const ICMPV6_ROUTER_ADVERT: u8 = 134;
const ICMPV6_NEIGHBOR_SOLICIT: u8 = 135;
const ICMPV6_NEIGHBOR_ADVERT: u8 = 136;
const IPPROTO_ICMPV6: u8 = 58;

/// Identifier carried in our ICMPv6 echo requests ("SW").
pub const ECHO_IDENT: u16 = 0x5357;
const ECHO_PAYLOAD: &[u8; 8] = b"SweepR\0\0";

/// libpcap filter for active scans. `vlan` must come last: it shifts the offsets of every
/// primitive that follows it.
const ACTIVE_FILTER: &str = "arp or icmp6 or (vlan and (arp or icmp6))";
/// libpcap filter for the passive listener (`vlan` last for the same reason).
const PASSIVE_FILTER: &str =
    "ether dst 01:00:0c:cc:cc:cc or ether dst 01:80:c2:00:00:0e or ether proto 0x88cc or vlan";

/// Poll interval of blocking capture loops (bounds cancellation latency).
const CAPTURE_POLL_MS: i32 = 100;

/// Bytes of a binary LLDP ID rendered as hex (longer IDs are truncated).
const MAX_HEX_ID_BYTES: usize = 64;
/// Management addresses kept per neighbor.
const MAX_MGMT_ADDRS: usize = 16;
/// Distinct CDP/LLDP neighbors a passive listener tracks; frames from further neighbors
/// are ignored so a flood of spoofed advertisements cannot exhaust memory.
pub const MAX_NEIGHBORS: usize = 2048;
/// Distinct VTP domains / DTP speakers remembered (for de-duplication).
const MAX_VTP_DOMAINS: usize = 2048;
const MAX_DTP_SOURCES: usize = 2048;
/// Distinct VTP domain / DTP speaker log lines per listener; the rest are summarized.
const MAX_PROTOCOL_LOGS: usize = 16;
/// Minimum interval between re-announcements of a changed neighbor.
const NEIGHBOR_UPDATE_INTERVAL_MS: u64 = 5_000;

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// Errors the engine reacts to (e.g. by falling back to unprivileged ICMP probing).
#[derive(Debug, thiserror::Error)]
pub enum L2Error {
    #[error("raw packet access requires {req} ({0})", req = crate::platform::RAW_ACCESS_REQUIREMENT)]
    PermissionDenied(String),
    #[error("interface {0} has no Ethernet link layer; layer-2 probing is not possible on it")]
    NoLinkLayer(String),
    #[error("interface '{name}' not found (available: {available})")]
    InterfaceNotFound { name: String, available: String },
}

impl L2Error {
    /// `true` when `err` (or anything in its chain) means raw L2 access is unavailable.
    pub fn is_l2_unavailable(err: &anyhow::Error) -> bool {
        matches!(
            err.downcast_ref::<L2Error>(),
            Some(L2Error::PermissionDenied(_) | L2Error::NoLinkLayer(_))
        )
    }

    /// `true` when `err` is specifically a privilege problem.
    pub fn is_permission(err: &anyhow::Error) -> bool {
        matches!(
            err.downcast_ref::<L2Error>(),
            Some(L2Error::PermissionDenied(_))
        )
    }
}

/// Root on Unix, an elevated token on Windows.
fn is_root() -> bool {
    crate::platform::is_privileged()
}

/// Map an OS error from opening a raw channel to [`L2Error::PermissionDenied`] when appropriate.
///
/// pnet probes `/dev/bpf0..N` on macOS and reports the errno of the *last* attempt, which is
/// usually `ENOENT` rather than `EACCES`, so "not found" counts as a permission problem too
/// when we are not root.
fn map_open_error(err: io::Error, what: &str) -> anyhow::Error {
    let denied = err.kind() == io::ErrorKind::PermissionDenied
        || matches!(err.raw_os_error(), Some(libc::EACCES | libc::EPERM))
        || (!is_root() && err.kind() == io::ErrorKind::NotFound);
    if denied {
        L2Error::PermissionDenied(format!("{what}: {err}")).into()
    } else {
        anyhow!("{what}: {err}")
    }
}

fn map_pcap_error(err: pcap::Error, what: &str) -> anyhow::Error {
    let text = err.to_string();
    let lower = text.to_ascii_lowercase();
    if lower.contains("permission")
        || lower.contains("not permitted")
        || lower.contains("bpf device")
        || lower.contains("access is denied")
    {
        L2Error::PermissionDenied(format!("{what}: {text}")).into()
    } else {
        anyhow!("{what}: {text}")
    }
}

// ---------------------------------------------------------------------------------------------
// Byte helpers (all bounds-checked)
// ---------------------------------------------------------------------------------------------

fn be16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off.checked_add(2)?)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

fn be32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn mac_at(b: &[u8], off: usize) -> Option<[u8; 6]> {
    b.get(off..off.checked_add(6)?)?.try_into().ok()
}

fn ipv4_at(b: &[u8], off: usize) -> Option<Ipv4Addr> {
    let o: [u8; 4] = b.get(off..off.checked_add(4)?)?.try_into().ok()?;
    Some(Ipv4Addr::from(o))
}

fn ipv6_at(b: &[u8], off: usize) -> Option<Ipv6Addr> {
    let o: [u8; 16] = b.get(off..off.checked_add(16)?)?.try_into().ok()?;
    Some(Ipv6Addr::from(o))
}

/// Decode a protocol string field: lossy UTF-8, then [`sanitize_text`] (control and
/// escape characters removed, whitespace trimmed, length capped). These bytes come from
/// any host on the segment and end up on terminals and in exports.
fn text(v: &[u8]) -> String {
    sanitize_text(&String::from_utf8_lossy(v))
}

fn opt_text(v: &[u8]) -> Option<String> {
    Some(text(v)).filter(|s| !s.is_empty())
}

fn hex_string(v: &[u8]) -> String {
    v.iter()
        .take(MAX_HEX_ID_BYTES)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn push_unique<T: PartialEq>(v: &mut Vec<T>, item: T) {
    if !v.contains(&item) {
        v.push(item);
    }
}

/// Add a management address, de-duplicated and capped at [`MAX_MGMT_ADDRS`].
fn push_addr(v: &mut Vec<IpAddr>, ip: IpAddr) {
    if v.len() < MAX_MGMT_ADDRS {
        push_unique(v, ip);
    }
}

// ---------------------------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------------------------

/// Enumerate local interfaces, classified and annotated with OS VLAN configuration.
/// The default-route interface sorts first.
pub fn list_interfaces() -> Vec<InterfaceInfo> {
    let mut out = os_interfaces();
    if !out.iter().any(|i| i.is_default) {
        if let Some(idx) = heuristic_default(&out) {
            out[idx].is_default = true;
        }
    }
    out.sort_by(|a, b| {
        b.is_default
            .cmp(&a.is_default)
            .then(b.is_up.cmp(&a.is_up))
            .then(kind_rank(a.kind).cmp(&kind_rank(b.kind)))
            .then(a.name.cmp(&b.name))
    });
    out
}

/// macOS / Linux: `getifaddrs` (through pnet) plus `ifconfig` / `/proc` / `networksetup`.
#[cfg(not(windows))]
fn os_interfaces() -> Vec<InterfaceInfo> {
    let raw = datalink::interfaces();
    let default = default_interface_name();
    let link = os_link_info();
    let hw_ports = if cfg!(target_os = "macos") {
        command_stdout("/usr/sbin/networksetup", &["-listallhardwareports"])
            .map(|t| parse_networksetup_ports(&t))
            .unwrap_or_default()
    } else {
        HashMap::new()
    };

    raw.into_iter()
        .map(|ni| {
            let vlan = link
                .vlans
                .get(&ni.name)
                .cloned()
                .or_else(|| parse_dotted_vlan_name(&ni.name).map(|(p, v)| (v, Some(p))));
            let hw_port = hw_ports.get(&ni.name).cloned();
            let wifi = is_wireless(&ni.name, hw_port.as_deref());
            let kind = classify_interface(&ni.name, ni.is_loopback(), wifi, vlan.is_some());
            let mac = ni
                .mac
                .map(|m| m.octets())
                .filter(is_real_mac)
                .or_else(|| link.ethers.get(&ni.name).copied().filter(is_real_mac))
                .map(|m| format_mac(&m));
            let addrs = ni
                .ips
                .iter()
                .map(|n| IfAddr {
                    ip: n.ip(),
                    prefix: n.prefix(),
                })
                .collect();
            let description =
                hw_port.or_else(|| Some(ni.description.clone()).filter(|d| !d.is_empty()));
            InterfaceInfo {
                is_default: default.as_deref() == Some(ni.name.as_str()),
                index: ni.index,
                description,
                mac,
                addrs,
                is_up: ni.is_up(),
                kind,
                vlan_id: vlan.as_ref().map(|v| v.0),
                parent: vlan.and_then(|v| v.1),
                name: ni.name,
            }
        })
        .collect()
}

/// Windows: `GetAdaptersAddresses` (no Npcap needed). Interfaces are named by their
/// connection name ("Ethernet", "Wi-Fi"); [`capture_device`] maps that to the Npcap device
/// (`\Device\NPF_{GUID}`) when raw access is needed. A NIC-level `VlanID` driver setting
/// makes the adapter a VLAN interface (the NIC tags everything it sends).
#[cfg(windows)]
fn os_interfaces() -> Vec<InterfaceInfo> {
    let adapters = crate::win::adapters();
    let vlans: HashMap<String, u16> = crate::win::nic_vlan_ids().into_iter().collect();
    let default = windows_default_route(&adapters).map(|(name, _)| name);
    adapters
        .into_iter()
        .filter(|a| !a.friendly_name.is_empty())
        .map(|a| {
            let vlan = vlans.get(&a.guid).copied();
            let kind = classify_windows_adapter(
                a.if_type,
                &a.description,
                &a.friendly_name,
                vlan.is_some(),
            );
            InterfaceInfo {
                is_default: default.as_deref() == Some(a.friendly_name.as_str()),
                index: a.index,
                description: Some(a.description.clone()).filter(|d| !d.is_empty()),
                mac: a.mac.filter(is_real_mac).map(|m| format_mac(&m)),
                addrs: a
                    .addrs
                    .iter()
                    .map(|(ip, prefix)| IfAddr {
                        ip: *ip,
                        prefix: *prefix,
                    })
                    .collect(),
                is_up: a.up,
                kind,
                vlan_id: vlan,
                parent: None,
                name: a.friendly_name,
            }
        })
        .collect()
}

/// The Windows default route as `(adapter name, gateway)`: the lowest-metric active
/// `0.0.0.0/0` row of `route print -4 0.0.0.0`, matched to the adapter owning its interface
/// address; failing that, the up adapter with an IPv4 gateway and the lowest metric.
#[cfg(windows)]
fn windows_default_route(adapters: &[crate::win::Adapter]) -> Option<(String, Option<Ipv4Addr>)> {
    let route = command_stdout(
        crate::platform::system32_tool("ROUTE.EXE"),
        &["print", "-4", "0.0.0.0"],
    )
    .and_then(|t| parse_route_print_default(&t));
    if let Some(r) = route {
        let owner = adapters
            .iter()
            .find(|a| a.addrs.iter().any(|(ip, _)| *ip == IpAddr::V4(r.interface)));
        if let Some(a) = owner {
            return Some((a.friendly_name.clone(), r.gateway));
        }
    }
    adapters
        .iter()
        .filter(|a| a.up)
        .filter_map(|a| {
            let gw = a.gateways.iter().find_map(|g| match g {
                IpAddr::V4(v4) if !v4.is_unspecified() => Some(*v4),
                _ => None,
            })?;
            Some((a.ipv4_metric, a.friendly_name.clone(), gw))
        })
        .min()
        .map(|(_, name, gw)| (name, Some(gw)))
}

/// Name of the interface carrying the default IPv4 route, if it can be determined.
pub fn default_interface_name() -> Option<String> {
    #[cfg(windows)]
    {
        windows_default_route(&crate::win::adapters()).map(|(name, _)| name)
    }
    #[cfg(not(windows))]
    {
        if cfg!(target_os = "linux") {
            fs::read_to_string("/proc/net/route")
                .ok()
                .and_then(|t| parse_proc_net_route(&t))
        } else {
            command_stdout("/sbin/route", &["-n", "get", "default"])
                .and_then(|t| parse_route_get(&t))
        }
    }
}

/// The default IPv4 gateway, if it can be determined (used to prioritize SNMP polling).
pub fn default_gateway_v4() -> Option<Ipv4Addr> {
    #[cfg(windows)]
    {
        windows_default_route(&crate::win::adapters()).and_then(|(_, gw)| gw)
    }
    #[cfg(not(windows))]
    {
        if cfg!(target_os = "linux") {
            fs::read_to_string("/proc/net/route")
                .ok()
                .and_then(|t| parse_proc_net_route_gateway(&t))
        } else {
            command_stdout("/sbin/route", &["-n", "get", "default"])
                .and_then(|t| parse_route_get_gateway(&t))
        }
    }
}

/// The `gateway:` of macOS/BSD `route -n get default` output.
pub fn parse_route_get_gateway(text: &str) -> Option<Ipv4Addr> {
    text.lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("gateway:"))
        .and_then(|s| s.trim().parse().ok())
}

/// The gateway of the lowest-metric default route in Linux `/proc/net/route` (the gateway
/// column is a little-endian hex IPv4 address).
pub fn parse_proc_net_route_gateway(text: &str) -> Option<Ipv4Addr> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (dest, gw, metric, mask) = (f.get(1)?, f.get(2)?, f.get(6)?, f.get(7)?);
            if *dest != "00000000" || *mask != "00000000" {
                return None;
            }
            let raw = u32::from_str_radix(gw, 16).ok().filter(|v| *v != 0)?;
            Some((
                metric.parse::<u32>().unwrap_or(u32::MAX),
                Ipv4Addr::from(raw.swap_bytes()),
            ))
        })
        .min()
        .map(|(_, gw)| gw)
}

/// Choose an interface by name, or the best default when `name` is `None`.
pub fn select_interface(all: &[InterfaceInfo], name: Option<&str>) -> Result<InterfaceInfo> {
    match name {
        // Windows connection names are case-insensitive ("ethernet" = "Ethernet").
        Some(n) => all
            .iter()
            .find(|i| i.name == n || (cfg!(windows) && i.name.eq_ignore_ascii_case(n)))
            .cloned()
            .ok_or_else(|| {
                L2Error::InterfaceNotFound {
                    name: n.to_string(),
                    available: all
                        .iter()
                        .map(|i| i.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                }
                .into()
            }),
        None => all
            .iter()
            .find(|i| i.is_default && i.is_up && i.primary_ipv4().is_some())
            .cloned()
            .or_else(|| heuristic_default(all).map(|i| all[i].clone()))
            .ok_or_else(|| {
                anyhow!("no usable network interface (up, non-loopback, with IPv4) found")
            }),
    }
}

/// `true` when the OS hides link-layer addresses from this process: on recent macOS,
/// unprivileged processes get a placeholder MAC for every interface (filtered out by
/// [`list_interfaces`], so Ethernet / Wi-Fi interfaces end up without a MAC).
pub fn macs_hidden(all: &[InterfaceInfo]) -> bool {
    // Windows always reports adapter MACs.
    !cfg!(windows)
        && !is_root()
        && all.iter().any(|i| {
            matches!(i.kind, InterfaceKind::Ethernet | InterfaceKind::Wifi) && i.mac.is_none()
        })
}

/// [`select_interface`] over a fresh [`list_interfaces`].
pub fn pick_interface(name: Option<&str>) -> Result<InterfaceInfo> {
    select_interface(&list_interfaces(), name)
}

/// OS VLAN sub-interfaces whose parent is `parent`.
pub fn vlan_children<'a>(
    parent: &str,
    all: &'a [InterfaceInfo],
) -> impl Iterator<Item = &'a InterfaceInfo> + 'a {
    let parent = parent.to_string();
    all.iter()
        .filter(move |i| i.vlan_id.is_some() && i.parent.as_deref() == Some(parent.as_str()))
}

fn heuristic_default(all: &[InterfaceInfo]) -> Option<usize> {
    all.iter()
        .enumerate()
        .filter(|(_, i)| {
            i.is_up
                && i.kind != InterfaceKind::Loopback
                && i.mac.is_some()
                && i.primary_ipv4().is_some()
        })
        .min_by_key(|(_, i)| kind_rank(i.kind))
        .map(|(idx, _)| idx)
}

fn kind_rank(kind: InterfaceKind) -> u8 {
    match kind {
        InterfaceKind::Ethernet => 0,
        InterfaceKind::Wifi => 1,
        InterfaceKind::Vlan => 2,
        InterfaceKind::Bridge => 3,
        InterfaceKind::Vpn => 4,
        InterfaceKind::Virtual => 5,
        InterfaceKind::Unknown => 6,
        InterfaceKind::Loopback => 7,
    }
}

fn command_stdout(cmd: impl AsRef<std::ffi::OsStr>, args: &[&str]) -> Option<String> {
    let out = crate::platform::hide_console_std(&mut Command::new(cmd))
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(not(windows))]
fn is_wireless(name: &str, hw_port: Option<&str>) -> bool {
    if let Some(port) = hw_port {
        let p = port.to_ascii_lowercase();
        if p.contains("wi-fi") || p.contains("airport") || p.contains("wlan") {
            return true;
        }
    }
    if cfg!(target_os = "linux") {
        let sys = Path::new("/sys/class/net").join(name);
        if sys.join("wireless").exists() || sys.join("phy80211").exists() {
            return true;
        }
    }
    name.starts_with("wl")
}

/// Classify an interface from its name and a few facts. Pure; see tests.
pub fn classify_interface(name: &str, loopback: bool, wireless: bool, vlan: bool) -> InterfaceKind {
    if loopback {
        return InterfaceKind::Loopback;
    }
    if vlan {
        return InterfaceKind::Vlan;
    }
    if wireless {
        return InterfaceKind::Wifi;
    }
    let n = name.to_ascii_lowercase();
    let starts = |prefixes: &[&str]| prefixes.iter().any(|p| n.starts_with(p));
    let digits_after = |prefix: &str| {
        n.strip_prefix(prefix)
            .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
    };

    if starts(&[
        "utun",
        "tun",
        "tap",
        "ppp",
        "wg",
        "ipsec",
        "tailscale",
        "zt",
        "nordlynx",
        "gpd",
    ]) {
        InterfaceKind::Vpn
    } else if starts(&["bridge", "br-", "virbr", "docker", "cni", "lxcbr"]) || digits_after("br") {
        InterfaceKind::Bridge
    } else if starts(&[
        "veth", "vmnet", "vboxnet", "awdl", "llw", "anpi", "gif", "stf", "xhc", "lxc", "vnic",
        "dummy", "nan", "anri", "ifb", "vxlan", "genev", "macvlan", "macvtap", "ipvlan", "kube",
        "flannel", "cali",
    ]) || digits_after("ap")
    {
        InterfaceKind::Virtual
    } else if starts(&[
        "en", "eth", "em", "p1p", "p2p", "igb", "ixgbe", "bond", "team",
    ]) {
        InterfaceKind::Ethernet
    } else {
        InterfaceKind::Unknown
    }
}

/// `en0.100` / `eth0.10` / `wlan0.20` → `(parent, vid)`.
pub fn parse_dotted_vlan_name(name: &str) -> Option<(String, u16)> {
    let (parent, vid) = name.rsplit_once('.')?;
    if parent.is_empty() || vid.is_empty() || !vid.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let vid: u16 = vid.parse().ok()?;
    (1..=MAX_VLAN_ID)
        .contains(&vid)
        .then(|| (parent.to_string(), vid))
}

/// Parse Linux `/proc/net/vlan/config` (`eth0.10 | 10 | eth0`) → `(name, vid, parent)`.
pub fn parse_proc_vlan_config(text: &str) -> Vec<(String, u16, String)> {
    text.lines()
        .filter_map(|line| {
            let mut f = line.split('|').map(str::trim);
            let (name, vid, parent) = (f.next()?, f.next()?, f.next()?);
            let vid: u16 = vid.parse().ok()?;
            (!name.is_empty() && !parent.is_empty() && (1..=MAX_VLAN_ID).contains(&vid))
                .then(|| (name.to_string(), vid, parent.to_string()))
        })
        .collect()
}

/// Parse macOS `ifconfig vlanN` output (`vlan: 100 parent interface: en0`).
pub fn parse_ifconfig_vlan(text: &str) -> Option<(u16, Option<String>)> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("vlan:"))?;
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let vid: u16 = tokens.get(1)?.parse().ok()?;
    if !(1..=MAX_VLAN_ID).contains(&vid) {
        return None;
    }
    let parent = tokens
        .iter()
        .position(|t| *t == "interface:")
        .and_then(|i| tokens.get(i + 1))
        .filter(|p| !p.starts_with('<'))
        .map(|p| p.to_string());
    Some((vid, parent))
}

/// Parse `networksetup -listallhardwareports` → device name → hardware port label.
pub fn parse_networksetup_ports(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut port: Option<String> = None;
    for line in text.lines().map(str::trim) {
        if let Some(p) = line.strip_prefix("Hardware Port:") {
            port = Some(p.trim().to_string());
        } else if let Some(dev) = line.strip_prefix("Device:") {
            if let Some(p) = port.take() {
                map.insert(dev.trim().to_string(), p);
            }
        }
    }
    map
}

/// Parse macOS/BSD `route -n get default` output.
pub fn parse_route_get(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("interface:"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Parse Linux `/proc/net/route`; returns the default-route interface with the lowest metric.
pub fn parse_proc_net_route(text: &str) -> Option<String> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (iface, dest, metric, mask) = (f.first()?, f.get(1)?, f.get(6)?, f.get(7)?);
            (*dest == "00000000" && *mask == "00000000")
                .then(|| (metric.parse::<u32>().unwrap_or(u32::MAX), iface.to_string()))
        })
        .min()
        .map(|(_, iface)| iface)
}

/// The active IPv4 default route of Windows `route print -4 0.0.0.0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsDefaultRoute {
    /// `None` for an on-link default route.
    pub gateway: Option<Ipv4Addr>,
    /// The address of the interface the route leaves through.
    pub interface: Ipv4Addr,
    pub metric: u32,
}

/// Parse Windows `route print -4 0.0.0.0` and return the lowest-metric active default route.
/// Rows look like `0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.23  25`. Headers and the
/// "On-link" gateway label are localized (and may be several words), so rows are recognized
/// by shape only: destination and mask `0.0.0.0`, an IPv4 interface address and a numeric
/// metric at the end. Persistent-route rows (no interface column) never match.
pub fn parse_route_print_default(text: &str) -> Option<WindowsDefaultRoute> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 5 || f.len() > 8 || f[0] != "0.0.0.0" || f[1] != "0.0.0.0" {
                return None;
            }
            let metric: u32 = f[f.len() - 1].parse().ok()?;
            let interface: Ipv4Addr = f[f.len() - 2].parse().ok()?;
            let gateway = match &f[2..f.len() - 2] {
                [one] => one.parse::<Ipv4Addr>().ok().filter(|g| !g.is_unspecified()),
                _ => None,
            };
            Some(WindowsDefaultRoute {
                gateway,
                interface,
                metric,
            })
        })
        .min_by_key(|r| r.metric)
}

/// Classify a Windows adapter from its IANA ifType, driver description and connection name.
/// Pure; see tests.
pub fn classify_windows_adapter(
    if_type: u32,
    description: &str,
    friendly_name: &str,
    vlan: bool,
) -> InterfaceKind {
    const ETHERNET: u32 = 6;
    const PPP: u32 = 23;
    const LOOPBACK: u32 = 24;
    const PROP_VIRTUAL: u32 = 53;
    const IEEE80211: u32 = 71;
    const TUNNEL: u32 = 131;
    const IEEE1394: u32 = 144;

    if if_type == LOOPBACK {
        return InterfaceKind::Loopback;
    }
    if vlan {
        return InterfaceKind::Vlan;
    }
    let text = format!("{description} {friendly_name}").to_ascii_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| text.contains(w));
    // IPv6 transition pseudo-interfaces and debug / Wi-Fi Direct adapters.
    if has(&[
        "teredo",
        "isatap",
        "6to4",
        "ip-https",
        "kernel debug",
        "wi-fi direct",
        "wan miniport",
    ]) {
        return InterfaceKind::Virtual;
    }
    if matches!(if_type, PPP | TUNNEL)
        || has(&[
            "wireguard",
            "wintun",
            "tap-windows",
            "openvpn",
            "tailscale",
            "zerotier",
            "anyconnect",
            "secure client",
            "globalprotect",
            "pangp",
            "fortinet",
            "forticlient",
            "juniper",
            "pulse secure",
            "nordlynx",
            "vpn",
        ])
    {
        return InterfaceKind::Vpn;
    }
    if if_type == IEEE80211 {
        return InterfaceKind::Wifi;
    }
    // Hyper-V virtual switch host adapters ("vEthernet (...)") and network bridges.
    if has(&[
        "hyper-v virtual ethernet",
        "vethernet",
        "network bridge",
        "mac bridge",
    ]) {
        return InterfaceKind::Bridge;
    }
    if matches!(if_type, PROP_VIRTUAL | IEEE1394)
        || has(&[
            "virtualbox",
            "vmware",
            "virtual",
            "loopback",
            "bluetooth",
            "docker",
            "npcap",
        ])
    {
        return InterfaceKind::Virtual;
    }
    if if_type == ETHERNET {
        InterfaceKind::Ethernet
    } else {
        InterfaceKind::Unknown
    }
}

/// The placeholder macOS reports to unentitled processes instead of the real link address.
const MASKED_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0];

fn is_real_mac(mac: &[u8; 6]) -> bool {
    *mac != [0; 6] && *mac != MASKED_MAC
}

/// Link-layer facts the portable interface API does not provide.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OsLinkInfo {
    /// Interface → `(vid, parent)` for OS 802.1Q sub-interfaces.
    pub vlans: HashMap<String, (u16, Option<String>)>,
    /// Interface → Ethernet address as reported by `ifconfig` (macOS masks the address
    /// returned by `getifaddrs` for unentitled processes).
    pub ethers: HashMap<String, [u8; 6]>,
}

#[cfg(not(windows))]
fn os_link_info() -> OsLinkInfo {
    if cfg!(target_os = "linux") {
        let vlans = fs::read_to_string("/proc/net/vlan/config")
            .map(|t| {
                parse_proc_vlan_config(&t)
                    .into_iter()
                    .map(|(name, vid, parent)| (name, (vid, Some(parent))))
                    .collect()
            })
            .unwrap_or_default();
        OsLinkInfo {
            vlans,
            ethers: HashMap::new(),
        }
    } else {
        command_stdout("/sbin/ifconfig", &["-a"])
            .map(|t| parse_ifconfig_all(&t))
            .unwrap_or_default()
    }
}

/// Parse BSD/macOS `ifconfig -a`: per-interface `ether` address and `vlan:` configuration.
pub fn parse_ifconfig_all(text: &str) -> OsLinkInfo {
    let mut info = OsLinkInfo::default();
    let mut current: Option<String> = None;
    let mut block = String::new();
    let flush = |name: Option<String>, block: &str, info: &mut OsLinkInfo| {
        let Some(name) = name else { return };
        if let Some(v) = parse_ifconfig_vlan(block) {
            info.vlans.insert(name.clone(), v);
        }
        let ether = block
            .lines()
            .map(str::trim)
            .find_map(|l| l.strip_prefix("ether "))
            .and_then(|m| parse_mac(m.split_whitespace().next().unwrap_or("")));
        if let Some(mac) = ether {
            info.ethers.insert(name, mac);
        }
    };
    for line in text.lines() {
        let is_header = !line.starts_with(char::is_whitespace) && line.contains(": flags=");
        if is_header {
            flush(current.take(), &block, &mut info);
            block.clear();
            current = line.split(':').next().map(str::to_string);
        } else {
            block.push_str(line);
            block.push('\n');
        }
    }
    flush(current, &block, &mut info);
    info
}

// ---------------------------------------------------------------------------------------------
// Frame builders
// ---------------------------------------------------------------------------------------------

/// An IEEE 802.1Q tag to insert into an outgoing frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VlanTag {
    /// 12-bit VLAN identifier.
    pub vid: u16,
    /// 3-bit priority code point.
    pub pcp: u8,
}

impl VlanTag {
    pub const fn new(vid: u16) -> Self {
        Self { vid, pcp: 0 }
    }

    /// Tag control information: `PCP(3) | DEI(1)=0 | VID(12)`.
    pub const fn tci(self) -> u16 {
        (((self.pcp & 0x7) as u16) << 13) | (self.vid & 0x0fff)
    }
}

fn push_eth_header(
    buf: &mut Vec<u8>,
    dst: [u8; 6],
    src: [u8; 6],
    vlan: Option<VlanTag>,
    ethertype: u16,
) {
    buf.extend_from_slice(&dst);
    buf.extend_from_slice(&src);
    if let Some(tag) = vlan {
        buf.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        buf.extend_from_slice(&tag.tci().to_be_bytes());
    }
    buf.extend_from_slice(&ethertype.to_be_bytes());
}

fn pad_frame(buf: &mut Vec<u8>) {
    if buf.len() < MIN_FRAME_LEN {
        buf.resize(MIN_FRAME_LEN, 0);
    }
}

/// Broadcast ARP who-has `target_ip`, optionally 802.1Q-tagged, padded to 60 bytes.
pub fn build_arp_request(
    src_mac: [u8; 6],
    src_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    vlan: Option<VlanTag>,
) -> Vec<u8> {
    let mut f = Vec::with_capacity(MIN_FRAME_LEN);
    push_eth_header(&mut f, BROADCAST_MAC, src_mac, vlan, ETHERTYPE_ARP);
    f.extend_from_slice(&1u16.to_be_bytes()); // HTYPE: Ethernet
    f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes()); // PTYPE: IPv4
    f.push(6); // HLEN
    f.push(4); // PLEN
    f.extend_from_slice(&1u16.to_be_bytes()); // OPER: request
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&src_ip.octets());
    f.extend_from_slice(&[0u8; 6]);
    f.extend_from_slice(&target_ip.octets());
    pad_frame(&mut f);
    f
}

/// RFC 4443 ICMPv6 checksum over the IPv6 pseudo-header and `icmp` (checksum field zeroed).
pub fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, icmp: &[u8]) -> u16 {
    fn sum_words(bytes: &[u8]) -> u64 {
        bytes
            .chunks(2)
            .map(|c| u64::from(u16::from_be_bytes([c[0], c.get(1).copied().unwrap_or(0)])))
            .sum()
    }
    let len = u32::try_from(icmp.len()).unwrap_or(u32::MAX);
    let mut sum = sum_words(&src.octets())
        + sum_words(&dst.octets())
        + sum_words(&len.to_be_bytes())
        + u64::from(IPPROTO_ICMPV6)
        + sum_words(icmp);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Multicast MAC (`33:33:xx:xx:xx:xx`) for an IPv6 multicast group.
pub fn ipv6_multicast_mac(group: Ipv6Addr) -> [u8; 6] {
    let o = group.octets();
    [0x33, 0x33, o[12], o[13], o[14], o[15]]
}

/// Solicited-node multicast group `ff02::1:ffXX:XXXX` of `addr`.
pub fn solicited_node(addr: Ipv6Addr) -> Ipv6Addr {
    let s = addr.segments();
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00 | (s[6] & 0x00ff), s[7])
}

/// Wrap an ICMPv6 message (checksum bytes 2..4 are filled in here) into IPv6 + Ethernet.
fn build_icmpv6_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    vlan: Option<VlanTag>,
    mut icmp: Vec<u8>,
) -> Vec<u8> {
    if icmp.len() >= 4 {
        icmp[2] = 0;
        icmp[3] = 0;
        let ck = icmpv6_checksum(src, dst, &icmp);
        icmp[2..4].copy_from_slice(&ck.to_be_bytes());
    }
    let mut f = Vec::with_capacity(18 + 40 + icmp.len());
    push_eth_header(&mut f, dst_mac, src_mac, vlan, ETHERTYPE_IPV6);
    f.extend_from_slice(&[0x60, 0, 0, 0]); // version 6, traffic class 0, flow label 0
    f.extend_from_slice(&u16::try_from(icmp.len()).unwrap_or(u16::MAX).to_be_bytes());
    f.push(IPPROTO_ICMPV6);
    f.push(255); // hop limit (mandatory for NDP, harmless for echo)
    f.extend_from_slice(&src.octets());
    f.extend_from_slice(&dst.octets());
    f.extend_from_slice(&icmp);
    pad_frame(&mut f);
    f
}

/// ICMPv6 echo request to `ff02::1` (all nodes) from `src` (one of our link-local, global
/// or unique-local addresses). Carries [`ECHO_IDENT`].
pub fn build_icmpv6_echo_multicast(
    src_mac: [u8; 6],
    src: Ipv6Addr,
    vlan: Option<VlanTag>,
) -> Vec<u8> {
    let mut icmp = vec![ICMPV6_ECHO_REQUEST, 0, 0, 0];
    icmp.extend_from_slice(&ECHO_IDENT.to_be_bytes());
    icmp.extend_from_slice(&1u16.to_be_bytes()); // sequence
    icmp.extend_from_slice(ECHO_PAYLOAD);
    build_icmpv6_frame(
        src_mac,
        ipv6_multicast_mac(ALL_NODES_V6),
        src,
        ALL_NODES_V6,
        vlan,
        icmp,
    )
}

/// ICMPv6 neighbor solicitation for `target` (to its solicited-node group) with our
/// source link-layer address option.
pub fn build_neighbor_solicitation(
    src_mac: [u8; 6],
    src_ip: Ipv6Addr,
    target: Ipv6Addr,
    vlan: Option<VlanTag>,
) -> Vec<u8> {
    let group = solicited_node(target);
    let mut icmp = vec![ICMPV6_NEIGHBOR_SOLICIT, 0, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&target.octets());
    icmp.extend_from_slice(&[1, 1]); // option: source link-layer address, length 1 (8 bytes)
    icmp.extend_from_slice(&src_mac);
    build_icmpv6_frame(
        src_mac,
        ipv6_multicast_mac(group),
        src_ip,
        group,
        vlan,
        icmp,
    )
}

// ---------------------------------------------------------------------------------------------
// Frame parsing
// ---------------------------------------------------------------------------------------------

/// A decoded Ethernet II / 802.3 header with any stacked VLAN tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    /// VLAN IDs from outermost to innermost (802.1Q `0x8100` and 802.1ad `0x88a8`/`0x9100`).
    /// A VID of 0 is a priority-only tag.
    pub vlans: Vec<u16>,
    /// EtherType after all tags. Values <= 1500 are 802.3 length fields (LLC follows).
    pub ethertype: u16,
    /// Offset of the payload within the frame.
    pub payload_offset: usize,
    /// Payload (for 802.3 frames trimmed to the declared length, i.e. without padding).
    pub payload: &'a [u8],
}

impl EthernetFrame<'_> {
    /// The outermost non-zero VLAN ID. Our probes carry a single tag, so for replies this is
    /// the VLAN that was probed.
    pub fn vlan_id(&self) -> Option<u16> {
        self.vlans.iter().copied().find(|v| *v != 0)
    }

    pub fn is_8023(&self) -> bool {
        self.ethertype <= MAX_8023_LENGTH
    }
}

/// Decode the Ethernet header of `frame`, walking stacked 802.1Q / QinQ tags.
pub fn parse_frame(frame: &[u8]) -> Option<EthernetFrame<'_>> {
    let dst = mac_at(frame, 0)?;
    let src = mac_at(frame, 6)?;
    let mut off = 12;
    let mut ethertype = be16(frame, off)?;
    off += 2;
    let mut vlans = Vec::new();
    while matches!(
        ethertype,
        ETHERTYPE_VLAN | ETHERTYPE_QINQ | ETHERTYPE_QINQ_LEGACY
    ) {
        if vlans.len() >= MAX_VLAN_TAGS {
            return None;
        }
        vlans.push(be16(frame, off)? & 0x0fff);
        ethertype = be16(frame, off + 2)?;
        off += 4;
    }
    let mut payload = frame.get(off..)?;
    if ethertype <= MAX_8023_LENGTH {
        payload = payload.get(..usize::from(ethertype)).unwrap_or(payload);
    }
    Some(EthernetFrame {
        dst,
        src,
        vlans,
        ethertype,
        payload_offset: off,
        payload,
    })
}

/// An ARP reply observed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpReply {
    /// Sender protocol address (the host that answered).
    pub ip: Ipv4Addr,
    /// Sender hardware address.
    pub mac: [u8; 6],
    /// VLAN tag the reply arrived with.
    pub vlan: Option<u16>,
    /// Target protocol address (who the reply was for).
    pub target_ip: Ipv4Addr,
}

/// Decode an ARP reply (operation 2) for Ethernet/IPv4.
pub fn parse_arp_reply(frame: &[u8]) -> Option<ArpReply> {
    let eth = parse_frame(frame)?;
    if eth.ethertype != ETHERTYPE_ARP {
        return None;
    }
    let p = eth.payload;
    let valid = be16(p, 0)? == 1
        && be16(p, 2)? == ETHERTYPE_IPV4
        && *p.get(4)? == 6
        && *p.get(5)? == 4
        && be16(p, 6)? == 2;
    if !valid {
        return None;
    }
    let ip = ipv4_at(p, 14)?;
    if ip.is_unspecified() {
        return None;
    }
    Some(ArpReply {
        ip,
        mac: mac_at(p, 8)?,
        vlan: eth.vlan_id(),
        target_ip: ipv4_at(p, 24)?,
    })
}

/// An IPv6 neighbor learned from ICMPv6 (echo reply, router/neighbor advertisement,
/// or neighbor solicitation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Observation {
    pub ip: Ipv6Addr,
    pub mac: [u8; 6],
    pub vlan: Option<u16>,
    /// ICMPv6 type the observation came from.
    pub icmp_type: u8,
}

/// Find an NDP option (`kind` 1 = source LL address, 2 = target LL address) holding a MAC.
fn ndp_lladdr_option(opts: &[u8], kind: u8) -> Option<[u8; 6]> {
    let mut off = 0;
    while let (Some(&t), Some(&len)) = (opts.get(off), opts.get(off + 1)) {
        if len == 0 {
            return None;
        }
        if t == kind {
            return mac_at(opts, off + 2);
        }
        off += usize::from(len) * 8;
    }
    None
}

/// Decode ICMPv6 messages that reveal a live neighbor: echo reply (129), router
/// advertisement (134), neighbor solicitation (135) and neighbor advertisement (136).
pub fn parse_icmpv6_discovery(frame: &[u8]) -> Option<Ipv6Observation> {
    let eth = parse_frame(frame)?;
    if eth.ethertype != ETHERTYPE_IPV6 {
        return None;
    }
    let p = eth.payload;
    if p.first()? >> 4 != 6 || *p.get(6)? != IPPROTO_ICMPV6 {
        return None;
    }
    let src = ipv6_at(p, 8)?;
    let icmp = p.get(40..)?;
    let icmp_type = *icmp.first()?;
    let (ip, mac) = match icmp_type {
        // Only replies to our own probes (other pingers' replies are not ours to report).
        ICMPV6_ECHO_REPLY if be16(icmp, 4)? == ECHO_IDENT => (src, eth.src),
        ICMPV6_ROUTER_ADVERT => (
            src,
            icmp.get(16..)
                .and_then(|o| ndp_lladdr_option(o, 1))
                .unwrap_or(eth.src),
        ),
        ICMPV6_NEIGHBOR_SOLICIT => (
            src,
            icmp.get(24..)
                .and_then(|o| ndp_lladdr_option(o, 1))
                .unwrap_or(eth.src),
        ),
        ICMPV6_NEIGHBOR_ADVERT => {
            let target = ipv6_at(icmp, 8)?;
            (
                target,
                icmp.get(24..)
                    .and_then(|o| ndp_lladdr_option(o, 2))
                    .unwrap_or(eth.src),
            )
        }
        _ => return None,
    };
    if ip.is_unspecified() || ip.is_multicast() {
        return None;
    }
    Some(Ipv6Observation {
        ip,
        mac,
        vlan: eth.vlan_id(),
        icmp_type,
    })
}

/// LLC/SNAP header of an 802.3 frame → `(OUI, protocol id, SNAP payload)`.
fn snap<'a>(eth: &EthernetFrame<'a>) -> Option<([u8; 3], u16, &'a [u8])> {
    if !eth.is_8023() || eth.payload.get(0..3)? != LLC_SNAP {
        return None;
    }
    let oui: [u8; 3] = eth.payload.get(3..6)?.try_into().ok()?;
    Some((oui, be16(eth.payload, 6)?, eth.payload.get(8..)?))
}

fn cisco_snap<'a>(frame: &'a [u8], pid: u16) -> Option<(EthernetFrame<'a>, &'a [u8])> {
    let eth = parse_frame(frame)?;
    if eth.dst != CDP_MULTICAST {
        return None;
    }
    let (oui, p, body) = snap(&eth)?;
    (oui == OUI_CISCO && p == pid).then_some((eth, body))
}

// ---------------------------------------------------------------------------------------------
// CDP
// ---------------------------------------------------------------------------------------------

/// Decode CDP address lists (Addresses / Management Addresses TLVs).
fn parse_cdp_addresses(v: &[u8]) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let Some(count) = be32(v, 0) else { return out };
    let mut off = 4;
    for _ in 0..count.min(64) {
        let (Some(&ptype), Some(&plen)) = (v.get(off), v.get(off + 1)) else {
            break;
        };
        let plen = usize::from(plen);
        let Some(proto) = v.get(off + 2..off + 2 + plen) else {
            break;
        };
        off += 2 + plen;
        let Some(alen) = be16(v, off) else { break };
        let alen = usize::from(alen);
        let Some(addr) = v.get(off + 2..off + 2 + alen) else {
            break;
        };
        off += 2 + alen;
        match (ptype, proto, alen) {
            (1, [0xcc], 4) => out.extend(ipv4_at(addr, 0).map(IpAddr::V4)),
            (2, [.., 0x86, 0xdd], 16) => out.extend(ipv6_at(addr, 0).map(IpAddr::V6)),
            _ => {}
        }
    }
    out
}

fn cdp_capabilities(bits: u32) -> Vec<Capability> {
    let mut caps = Vec::new();
    for (bit, cap) in [
        (0x01, Capability::Router),
        (0x02, Capability::Switch), // transparent bridge
        (0x04, Capability::Switch), // source-route bridge
        (0x08, Capability::Switch),
        (0x10, Capability::Host),
        (0x40, Capability::Repeater),
        (0x80, Capability::Telephone),
    ] {
        if bits & bit != 0 {
            push_unique(&mut caps, cap);
        }
    }
    if bits & 0x20 != 0 && caps.is_empty() {
        caps.push(Capability::Other); // IGMP-capable only
    }
    caps
}

/// Decode a Cisco Discovery Protocol frame (v1/v2) received on `local_if`.
pub fn parse_cdp(frame: &[u8], local_if: &str) -> Option<CdpLldpNeighbor> {
    let (eth, body) = cisco_snap(frame, SNAP_PID_CDP)?;
    let version = *body.first()?;
    if !(1..=2).contains(&version) {
        return None;
    }
    let mut n = empty_neighbor(NeighborProtocol::Cdp, local_if, &eth.src);
    n.ttl_secs = u16::from(*body.get(1)?);

    let mut device_id = None;
    let mut off = 4;
    while let (Some(t), Some(len)) = (be16(body, off), be16(body, off + 2)) {
        let len = usize::from(len);
        if len < 4 {
            break;
        }
        let Some(v) = body.get(off + 4..off + len) else {
            break;
        };
        off += len;
        match t {
            0x0001 => device_id = opt_text(v),
            0x0002 => {
                for ip in parse_cdp_addresses(v) {
                    push_addr(&mut n.management_addrs, ip);
                }
            }
            0x0003 => n.port_id = opt_text(v),
            0x0004 => n.capabilities = be32(v, 0).map(cdp_capabilities).unwrap_or_default(),
            0x0005 => n.software_version = opt_text(v),
            0x0006 => n.platform = opt_text(v),
            0x0009 => n.vtp_domain = opt_text(v),
            0x000a => n.native_vlan = be16(v, 0).filter(|id| (1..=MAX_VLAN_ID).contains(id)),
            0x000e => n.voice_vlan = be16(v, 1).filter(|id| (1..=MAX_VLAN_ID).contains(id)),
            0x0010 => {
                if let Some(watts) = parse_cdp_power_consumption(v) {
                    apply_poe(
                        &mut n,
                        PoeInfo {
                            watts: Some(watts),
                            ..PoeInfo::default()
                        },
                    );
                }
            }
            0x0016 => {
                for ip in parse_cdp_addresses(v) {
                    push_addr(&mut n.management_addrs, ip);
                }
            }
            0x001a => {
                if let Some(watts) = parse_cdp_power_available(v) {
                    apply_poe(
                        &mut n,
                        PoeInfo {
                            max_watts: Some(watts),
                            ..PoeInfo::default()
                        },
                    );
                }
            }
            _ => {}
        }
    }
    let mut seen = HashSet::new();
    n.management_addrs.retain(|ip| seen.insert(*ip));
    n.device_id = device_id.unwrap_or_else(|| n.source_mac.clone());
    n.system_name = Some(n.device_id.clone());
    Some(n)
}

fn empty_neighbor(protocol: NeighborProtocol, local_if: &str, src: &[u8; 6]) -> CdpLldpNeighbor {
    CdpLldpNeighbor {
        protocol,
        local_interface: local_if.to_string(),
        source_mac: format_mac(src),
        device_id: String::new(),
        system_name: None,
        system_description: None,
        port_id: None,
        port_description: None,
        platform: None,
        software_version: None,
        management_addrs: Vec::new(),
        native_vlan: None,
        voice_vlan: None,
        capabilities: Vec::new(),
        vtp_domain: None,
        poe_watts: None,
        poe_info: None,
        ttl_secs: 0,
        last_seen_ms: now_ms(),
    }
}

// ---------------------------------------------------------------------------------------------
// LLDP
// ---------------------------------------------------------------------------------------------

/// Render an LLDP Chassis ID / Port ID value. `mac_subtype` / `addr_subtype` differ between
/// the two TLVs (chassis: 4 / 5, port: 3 / 4).
fn render_lldp_id(v: &[u8], mac_subtype: u8, addr_subtype: u8) -> Option<String> {
    let (&subtype, val) = v.split_first()?;
    if val.is_empty() {
        return None;
    }
    if subtype == mac_subtype && val.len() == 6 {
        return mac_at(val, 0).map(|m| format_mac(&m));
    }
    if subtype == addr_subtype {
        return match (val.first(), val.len()) {
            (Some(1), 5) => ipv4_at(val, 1).map(|ip| ip.to_string()),
            (Some(2), 17) => ipv6_at(val, 1).map(|ip| ip.to_string()),
            _ => Some(hex_string(val)),
        };
    }
    let printable = val
        .iter()
        .all(|b| b.is_ascii_graphic() || *b == b' ' || *b == 0);
    if printable {
        opt_text(val)
    } else {
        Some(hex_string(val))
    }
}

fn lldp_capabilities(bits: u16) -> Vec<Capability> {
    let mut caps = Vec::new();
    for (bit, cap) in [
        (0x0001, Capability::Other),
        (0x0002, Capability::Repeater),
        (0x0004, Capability::Switch), // MAC bridge
        (0x0008, Capability::WlanAccessPoint),
        (0x0010, Capability::Router),
        (0x0020, Capability::Telephone),
        (0x0040, Capability::DocsisCable),
        (0x0080, Capability::Host),   // station only
        (0x0100, Capability::Switch), // C-VLAN component
        (0x0200, Capability::Switch), // S-VLAN component
        (0x0400, Capability::Other),  // two-port MAC relay
    ] {
        if bits & bit != 0 {
            push_unique(&mut caps, cap);
        }
    }
    caps
}

/// Decoded ANSI/TIA-1057 (LLDP-MED) Network Policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub app_type: u8,
    pub unknown: bool,
    pub tagged: bool,
    pub vlan_id: u16,
    pub l2_priority: u8,
    pub dscp: u8,
}

/// Decode the 4-byte LLDP-MED Network Policy body: app type, then
/// `U(1) T(1) X(1) VLAN(12) L2 priority(3) DSCP(6)`.
pub fn parse_network_policy(v: &[u8]) -> Option<NetworkPolicy> {
    let app_type = *v.first()?;
    let b: [u8; 3] = v.get(1..4)?.try_into().ok()?;
    let bits = u32::from_be_bytes([0, b[0], b[1], b[2]]);
    Some(NetworkPolicy {
        app_type,
        unknown: bits & (1 << 23) != 0,
        tagged: bits & (1 << 22) != 0,
        vlan_id: ((bits >> 9) & 0x0fff) as u16,
        l2_priority: ((bits >> 6) & 0x7) as u8,
        dscp: (bits & 0x3f) as u8,
    })
}

/// Power priority label from a 2-bit LLDP-MED / 802.3at priority field (1 critical, 2 high,
/// 3 low).
fn poe_priority_label(bits: u8) -> Option<String> {
    Some(
        match bits & 0x3 {
            1 => "critical",
            2 => "high",
            3 => "low",
            _ => return None,
        }
        .to_string(),
    )
}

/// PoE power source label from a 2-bit field (PD perspective: 1 PSE, 2 local, 3 PSE+local).
fn poe_source_label(bits: u8) -> Option<String> {
    Some(
        match bits & 0x3 {
            1 => "pse",
            2 => "local",
            3 => "pse+local",
            _ => return None,
        }
        .to_string(),
    )
}

/// Decode an IEEE 802.3 Power-via-MDI TLV body (OUI 00-12-0F, subtype 2). The base TLV carries
/// the PoE class; the 802.3at/bt extension adds the PD-requested and PSE-allocated power in
/// 0.1 W units, plus a type/source/priority octet. Returns `None` when nothing useful is set.
pub fn parse_dot3_power_mdi(v: &[u8]) -> Option<PoeInfo> {
    // v[0] MDI power support, v[1] PSE power pair, v[2] power class.
    let mut info = PoeInfo::default();
    if let Some(&class_byte) = v.get(2) {
        // power class enum: class0(1) .. class4(5); 0 = unknown.
        if (1..=5).contains(&class_byte) {
            info.class = Some(class_byte - 1);
        }
    }
    // 802.3at extension: v[3] type/source/priority, v[4..6] PD requested, v[6..8] PSE allocated.
    if let Some(&tsp) = v.get(3) {
        info.source = poe_source_label((tsp >> 4) & 0x3);
        info.priority = poe_priority_label(tsp & 0x3);
    }
    if let Some(req) = be16(v, 4) {
        if req != 0 {
            info.watts = Some(f32::from(req) / 10.0);
        }
    }
    if let Some(alloc) = be16(v, 6) {
        if alloc != 0 {
            info.max_watts = Some(f32::from(alloc) / 10.0);
        }
    }
    (!info.is_empty()).then_some(info)
}

/// Decode an LLDP-MED Extended Power-via-MDI TLV body (OUI 00-12-BB, subtype 4):
/// `type/source/priority(1) power-value(2)` where the value is in 0.1 W units.
pub fn parse_med_ext_power(v: &[u8]) -> Option<PoeInfo> {
    let tsp = *v.first()?;
    let value = be16(v, 1)?;
    let mut info = PoeInfo {
        source: poe_source_label((tsp >> 4) & 0x3),
        priority: poe_priority_label(tsp & 0x3),
        ..PoeInfo::default()
    };
    if value != 0 {
        info.watts = Some(f32::from(value) / 10.0);
    }
    (!info.is_empty()).then_some(info)
}

/// Decode the two CDP power TLVs. `0x0010` Power Consumption is a 16-bit milliwatt value the
/// device draws; `0x001a` Power Available is request-id(2) + management-id(2) + 32-bit
/// milliwatt values the PSE can supply.
fn parse_cdp_power_consumption(v: &[u8]) -> Option<f32> {
    let mw = be16(v, 0)?;
    (mw != 0).then(|| f32::from(mw) / 1000.0)
}

fn parse_cdp_power_available(v: &[u8]) -> Option<f32> {
    let mw = be32(v, 4)?;
    (mw != 0).then_some(mw as f32 / 1000.0)
}

/// Merge a freshly parsed PoE observation into the neighbor (the first value of each field in
/// an advert wins). `poe_watts`, the headline value, is the drawn power, else the budget.
fn apply_poe(n: &mut CdpLldpNeighbor, poe: PoeInfo) {
    let info = n.poe_info.get_or_insert_with(Box::default);
    info.watts = info.watts.or(poe.watts);
    info.max_watts = info.max_watts.or(poe.max_watts);
    info.class = info.class.or(poe.class);
    info.status = info.status.take().or(poe.status);
    info.source = info.source.take().or(poe.source);
    info.priority = info.priority.take().or(poe.priority);
    n.poe_watts = info.watts.or(info.max_watts);
}

/// Decode an LLDPDU (EtherType `0x88cc`, optionally VLAN-tagged) received on `local_if`.
pub fn parse_lldp(frame: &[u8], local_if: &str) -> Option<CdpLldpNeighbor> {
    let eth = parse_frame(frame)?;
    if eth.ethertype != ETHERTYPE_LLDP {
        return None;
    }
    let p = eth.payload;
    let mut n = empty_neighbor(NeighborProtocol::Lldp, local_if, &eth.src);
    let mut chassis = None;
    let mut off = 0;
    while let Some(header) = be16(p, off) {
        let tlv_type = header >> 9;
        let len = usize::from(header & 0x01ff);
        let Some(v) = p.get(off + 2..off + 2 + len) else {
            break;
        };
        off += 2 + len;
        match tlv_type {
            0 => break, // End of LLDPDU
            1 => chassis = render_lldp_id(v, 4, 5),
            2 => n.port_id = render_lldp_id(v, 3, 4),
            3 => n.ttl_secs = be16(v, 0).unwrap_or(0),
            4 => n.port_description = opt_text(v),
            5 => n.system_name = opt_text(v),
            6 => n.system_description = opt_text(v),
            7 => n.capabilities = be16(v, 2).map(lldp_capabilities).unwrap_or_default(),
            8 => {
                // addr string length (subtype + address), subtype, address, ...
                let alen = usize::from(*v.first().unwrap_or(&0));
                let addr = v.get(2..1 + alen).unwrap_or(&[]);
                let ip = match (v.get(1), addr.len()) {
                    (Some(1), 4) => ipv4_at(addr, 0).map(IpAddr::V4),
                    (Some(2), 16) => ipv6_at(addr, 0).map(IpAddr::V6),
                    _ => None,
                };
                if let Some(ip) = ip {
                    push_addr(&mut n.management_addrs, ip);
                }
            }
            127 => parse_lldp_org_tlv(v, &mut n),
            _ => {}
        }
    }
    n.device_id = chassis?;
    Some(n)
}

fn parse_lldp_org_tlv(v: &[u8], n: &mut CdpLldpNeighbor) {
    let (Some(oui), Some(&subtype)) = (v.get(0..3), v.get(3)) else {
        return;
    };
    let data = v.get(4..).unwrap_or(&[]);
    match (oui, subtype) {
        // IEEE 802.1 Port VLAN ID (native / untagged VLAN).
        (o, 1) if o == OUI_IEEE_8021 => {
            n.native_vlan = be16(data, 0).filter(|id| (1..=MAX_VLAN_ID).contains(id));
        }
        // LLDP-MED Network Policy: application type 1 = voice.
        (o, 2) if o == OUI_TIA => {
            if let Some(p) = parse_network_policy(data) {
                if p.app_type == 1
                    && !p.unknown
                    && p.tagged
                    && (1..=MAX_VLAN_ID).contains(&p.vlan_id)
                {
                    n.voice_vlan = Some(p.vlan_id);
                }
            }
        }
        // LLDP-MED inventory: software revision, model name.
        (o, 7) if o == OUI_TIA => n.software_version = opt_text(data),
        (o, 10) if o == OUI_TIA => n.platform = opt_text(data),
        // IEEE 802.3 Power Via MDI (PoE class / 802.3at power negotiation).
        (o, 2) if o == OUI_IEEE_8023 => {
            if let Some(poe) = parse_dot3_power_mdi(data) {
                apply_poe(n, poe);
            }
        }
        // LLDP-MED Extended Power-via-MDI (power value, source, priority).
        (o, 4) if o == OUI_TIA => {
            if let Some(poe) = parse_med_ext_power(data) {
                apply_poe(n, poe);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------------------------
// VTP / DTP
// ---------------------------------------------------------------------------------------------

/// A decoded VTP summary or subset advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtpAdvert {
    pub version: u8,
    /// 1 = summary, 2 = subset.
    pub code: u8,
    pub domain: String,
    pub revision: u32,
    /// Ethernet VLANs `(id, name)` from a subset advertisement.
    pub vlans: Vec<(u16, String)>,
    pub source_mac: [u8; 6],
}

/// Decode a VTP v1/v2 summary (code 1) or subset (code 2) advertisement.
/// Only Ethernet VLANs (type 1) are reported; FDDI / Token Ring defaults are skipped.
pub fn parse_vtp(frame: &[u8]) -> Option<VtpAdvert> {
    let (eth, body) = cisco_snap(frame, SNAP_PID_VTP)?;
    let version = *body.first()?;
    let code = *body.get(1)?;
    if !(1..=2).contains(&version) || !(1..=2).contains(&code) {
        return None;
    }
    let dom_len = usize::from(*body.get(3)?).min(32);
    let domain = text(body.get(4..4 + dom_len)?);
    let revision = be32(body, 36)?;
    let mut vlans = Vec::new();
    if code == 2 {
        let mut off = 40;
        while let Some(&info_len) = body.get(off) {
            let info_len = usize::from(info_len);
            if info_len < 12 {
                break;
            }
            let Some(entry) = body.get(off..off + info_len) else {
                break;
            };
            off += info_len;
            let (Some(&vlan_type), Some(&name_len), Some(id)) =
                (entry.get(2), entry.get(3), be16(entry, 4))
            else {
                continue;
            };
            let name = entry
                .get(12..12 + usize::from(name_len))
                .map(text)
                .unwrap_or_default();
            if vlan_type == 1 && (1..=MAX_VLAN_ID).contains(&id) {
                vlans.push((id, name));
            }
        }
    }
    Some(VtpAdvert {
        version,
        code,
        domain,
        revision,
        vlans,
        source_mac: eth.src,
    })
}

/// `true` for a Cisco Dynamic Trunking Protocol frame.
pub fn is_dtp(frame: &[u8]) -> bool {
    cisco_snap(frame, SNAP_PID_DTP).is_some()
}

// ---------------------------------------------------------------------------------------------
// Passive discovery
// ---------------------------------------------------------------------------------------------

/// Everything the passive listener learned.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassiveResults {
    pub vlans: Vec<VlanInfo>,
    pub neighbors: Vec<CdpLldpNeighbor>,
    pub frames_seen: u64,
}

/// Source MACs our active probes are transmitted with, across every L2 job of this process.
fn transmit_macs() -> &'static Mutex<HashSet<[u8; 6]>> {
    static MACS: OnceLock<Mutex<HashSet<[u8; 6]>>> = OnceLock::new();
    MACS.get_or_init(Mutex::default)
}

/// Remember `mac` as one of ours so passive listeners never report our own probes
/// (e.g. our 802.1Q-tagged ARP requests) as discovered VLANs or neighbors.
pub fn register_transmit_mac(mac: [u8; 6]) {
    if let Ok(mut set) = transmit_macs().lock() {
        set.insert(mac);
    }
}

fn is_transmit_mac(mac: &[u8; 6]) -> bool {
    transmit_macs()
        .lock()
        .map(|set| set.contains(mac))
        .unwrap_or(false)
}

/// Real (unmasked) MAC addresses of all local interfaces.
pub fn local_macs(all: &[InterfaceInfo]) -> Vec<[u8; 6]> {
    let mut macs: Vec<[u8; 6]> = all
        .iter()
        .filter_map(|i| i.mac.as_deref().and_then(parse_mac))
        .collect();
    macs.sort_unstable();
    macs.dedup();
    macs
}

/// Per-neighbor state of the passive listener.
#[derive(Debug)]
struct NeighborState {
    neighbor: CdpLldpNeighbor,
    last_emit_ms: u64,
    /// Changed since it was last announced.
    dirty: bool,
}

/// `true` when two advertisements carry the same information (timestamps aside).
fn same_advert(a: &CdpLldpNeighbor, b: &CdpLldpNeighbor) -> bool {
    CdpLldpNeighbor {
        last_seen_ms: a.last_seen_ms,
        ..b.clone()
    } == *a
}

/// Folds captured frames into VLAN / neighbor state. Pure (no I/O) so it is unit testable;
/// [`PassiveAggregator::ingest`] returns the events to stream for each frame.
///
/// Frames sent by this host (any local interface MAC, or a MAC registered with
/// [`register_transmit_mac`]) are ignored. All state is bounded ([`MAX_NEIGHBORS`] etc.) and
/// log events are de-duplicated and capped, since any host on the segment can send these
/// frames.
#[derive(Debug, Default)]
pub struct PassiveAggregator {
    if_name: String,
    own_macs: HashSet<[u8; 6]>,
    vlans: BTreeMap<u16, VlanInfo>,
    neighbors: HashMap<String, NeighborState>,
    neighbor_limit_warned: bool,
    dtp_sources: HashSet<[u8; 6]>,
    vtp_domains: HashSet<String>,
    vtp_logs: usize,
    dtp_logs: usize,
    frames: u64,
    own_frames: u64,
}

impl PassiveAggregator {
    pub fn new(if_name: &str) -> Self {
        Self {
            if_name: if_name.to_string(),
            // macOS' placeholder for hidden link addresses is never a real neighbor.
            own_macs: HashSet::from([MASKED_MAC]),
            ..Self::default()
        }
    }

    /// Also ignore frames sent from `macs` (this host's interface addresses).
    pub fn with_own_macs(mut self, macs: impl IntoIterator<Item = [u8; 6]>) -> Self {
        self.own_macs.extend(macs);
        self
    }

    /// Frames ignored because this host sent them.
    pub fn own_frames(&self) -> u64 {
        self.own_frames
    }

    /// Record a VLAN observation; returns an event when the VLAN is new or gained a new
    /// source / name.
    fn observe_vlan(
        &mut self,
        id: u16,
        source: VlanSource,
        name: Option<String>,
        switch: Option<&str>,
        frames: u64,
    ) -> Option<ScanEvent> {
        if !(1..=MAX_VLAN_ID).contains(&id) {
            return None;
        }
        let mut obs = VlanInfo::new(id, source);
        obs.name = name.filter(|n| !n.is_empty());
        obs.interface = Some(self.if_name.clone());
        obs.switch_name = switch.map(str::to_string);
        obs.frames_seen = frames;
        match self.vlans.get_mut(&id) {
            Some(existing) => {
                let changed = !existing.sources.contains(&source)
                    || (existing.name.is_none() && obs.name.is_some());
                existing.merge(&obs);
                changed.then(|| ScanEvent::Vlan(existing.clone()))
            }
            None => {
                self.vlans.insert(id, obs.clone());
                Some(ScanEvent::Vlan(obs))
            }
        }
    }

    fn observe_neighbor(&mut self, n: CdpLldpNeighbor, now: u64, events: &mut Vec<ScanEvent>) {
        let source = match n.protocol {
            NeighborProtocol::Cdp => VlanSource::Cdp,
            NeighborProtocol::Lldp => VlanSource::Lldp,
        };
        let switch = n.display_name().to_string();
        for id in [n.native_vlan, n.voice_vlan].into_iter().flatten() {
            events.extend(self.observe_vlan(id, source, None, Some(&switch), 0));
        }
        let key = n.key();
        let full = self.neighbors.len() >= MAX_NEIGHBORS;
        match self.neighbors.get_mut(&key) {
            Some(state) => {
                if !same_advert(&state.neighbor, &n) {
                    state.dirty = true;
                }
                state.neighbor = n;
                // Re-announce changes, but at most once per interval per neighbor.
                if state.dirty
                    && now.saturating_sub(state.last_emit_ms) >= NEIGHBOR_UPDATE_INTERVAL_MS
                {
                    state.dirty = false;
                    state.last_emit_ms = now;
                    events.push(ScanEvent::Neighbor(state.neighbor.clone()));
                }
            }
            None if full => {
                if !self.neighbor_limit_warned {
                    self.neighbor_limit_warned = true;
                    events.push(ScanEvent::warn(format!(
                        "more than {MAX_NEIGHBORS} CDP/LLDP neighbors on {}; ignoring further \
                         neighbors (possible advertisement flood)",
                        self.if_name
                    )));
                }
            }
            None => {
                events.push(ScanEvent::Neighbor(n.clone()));
                self.neighbors.insert(
                    key,
                    NeighborState {
                        neighbor: n,
                        last_emit_ms: now,
                        dirty: false,
                    },
                );
            }
        }
    }

    /// Process one captured frame.
    pub fn ingest(&mut self, frame: &[u8]) -> Vec<ScanEvent> {
        self.ingest_at(frame, now_ms())
    }

    fn ingest_at(&mut self, frame: &[u8], now: u64) -> Vec<ScanEvent> {
        let mut events = Vec::new();
        let Some(eth) = parse_frame(frame) else {
            return events;
        };
        // Our own probes (tagged ARP / NDP) must never count as observed VLANs.
        if self.own_macs.contains(&eth.src) || is_transmit_mac(&eth.src) {
            self.own_frames += 1;
            return events;
        }
        self.frames += 1;

        for vid in eth.vlans.iter().copied().filter(|v| *v != 0) {
            events.extend(self.observe_vlan(vid, VlanSource::Tagged8021q, None, None, 1));
        }

        if eth.dst == CDP_MULTICAST {
            if let Some(n) = parse_cdp(frame, &self.if_name) {
                self.observe_neighbor(n, now, &mut events);
            } else if let Some(vtp) = parse_vtp(frame) {
                let new_domain = self.vtp_domains.len() < MAX_VTP_DOMAINS
                    && self.vtp_domains.insert(vtp.domain.clone());
                if new_domain {
                    self.vtp_logs += 1;
                    if self.vtp_logs <= MAX_PROTOCOL_LOGS {
                        events.push(ScanEvent::info(format!(
                            "VTP v{} domain '{}' (revision {}) advertised by {}",
                            vtp.version,
                            vtp.domain,
                            vtp.revision,
                            format_mac(&vtp.source_mac)
                        )));
                    } else if self.vtp_logs == MAX_PROTOCOL_LOGS + 1 {
                        events.push(ScanEvent::warn(format!(
                            "more than {MAX_PROTOCOL_LOGS} VTP domains on {}; not logging further \
                             domains",
                            self.if_name
                        )));
                    }
                }
                let domain = (!vtp.domain.is_empty()).then(|| format!("VTP {}", vtp.domain));
                for (id, name) in vtp.vlans {
                    events.extend(self.observe_vlan(
                        id,
                        VlanSource::Vtp,
                        Some(name),
                        domain.as_deref(),
                        0,
                    ));
                }
            } else if is_dtp(frame)
                && self.dtp_sources.len() < MAX_DTP_SOURCES
                && self.dtp_sources.insert(eth.src)
            {
                self.dtp_logs += 1;
                if self.dtp_logs <= MAX_PROTOCOL_LOGS {
                    events.push(ScanEvent::info(format!(
                        "trunk negotiation (DTP) from {} on {}",
                        format_mac(&eth.src),
                        self.if_name
                    )));
                } else if self.dtp_logs == MAX_PROTOCOL_LOGS + 1 {
                    events.push(ScanEvent::warn(format!(
                        "more than {MAX_PROTOCOL_LOGS} DTP speakers on {}; not logging further \
                         speakers",
                        self.if_name
                    )));
                }
            }
        } else if eth.ethertype == ETHERTYPE_LLDP {
            if let Some(n) = parse_lldp(frame, &self.if_name) {
                self.observe_neighbor(n, now, &mut events);
            }
        }
        events
    }

    pub fn finish(self) -> PassiveResults {
        let mut neighbors: Vec<CdpLldpNeighbor> =
            self.neighbors.into_values().map(|s| s.neighbor).collect();
        neighbors.sort_by(|a, b| {
            a.display_name()
                .cmp(b.display_name())
                .then(a.port_id.cmp(&b.port_id))
        });
        PassiveResults {
            vlans: self.vlans.into_values().collect(),
            neighbors,
            frames_seen: self.frames,
        }
    }
}

/// The libpcap device for `if_name`: the name itself on macOS / Linux; on Windows the Npcap
/// device (`\Device\NPF_{GUID}`) of the adapter with that connection name. Fails with
/// [`L2Error::PermissionDenied`] when the capture driver is missing (Windows without Npcap),
/// before any libpcap / Packet.dll function is called.
pub fn capture_device(if_name: &str) -> Result<String> {
    crate::platform::capture_driver_status().map_err(L2Error::PermissionDenied)?;
    #[cfg(windows)]
    let device = if if_name.starts_with(r"\Device\") {
        Some(if_name.to_string())
    } else {
        crate::win::adapters()
            .into_iter()
            .find(|a| {
                a.friendly_name.eq_ignore_ascii_case(if_name)
                    || a.guid.eq_ignore_ascii_case(if_name)
            })
            .map(|a| a.npf_name())
    };
    #[cfg(not(windows))]
    let device = Some(if_name.to_string());
    device.ok_or_else(|| anyhow!("interface {if_name} disappeared"))
}

/// The pnet datalink interface used to transmit on `if_name` (whose MAC is `src_mac`).
fn datalink_interface(if_name: &str, src_mac: [u8; 6]) -> Result<datalink::NetworkInterface> {
    #[cfg(windows)]
    {
        // pnet's Windows backend only needs the Npcap device name to open the adapter.
        let [a, b, c, d, e, f] = src_mac;
        Ok(datalink::NetworkInterface {
            name: capture_device(if_name)?,
            description: String::new(),
            index: 0,
            mac: Some(datalink::MacAddr::new(a, b, c, d, e, f)),
            ips: Vec::new(),
            flags: 0,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = src_mac;
        datalink::interfaces()
            .into_iter()
            .find(|i| i.name == if_name)
            .ok_or_else(|| anyhow!("interface {if_name} disappeared"))
    }
}

fn open_capture(if_name: &str, promisc: bool) -> Result<pcap::Capture<pcap::Active>> {
    let device = capture_device(if_name)?;
    let cap = pcap::Capture::from_device(device.as_str())
        .map_err(|e| map_pcap_error(e, &format!("cannot open {if_name} for capture")))?
        .promisc(promisc)
        .immediate_mode(true)
        .snaplen(65_535)
        .buffer_size(4 << 20)
        .timeout(CAPTURE_POLL_MS)
        .open()
        .map_err(|e| map_pcap_error(e, &format!("cannot capture on {if_name}")))?;
    if cap.get_datalink() != pcap::Linktype::ETHERNET {
        bail!(L2Error::NoLinkLayer(if_name.to_string()));
    }
    // Only received frames: our own transmitted probes must not be captured. Not every
    // platform supports this; source-MAC filtering in the consumers covers the rest.
    if let Err(e) = cap.direction(pcap::Direction::In) {
        tracing::debug!("cannot restrict capture on {if_name} to inbound frames: {e}");
    }
    Ok(cap)
}

/// Passively listen on `if_name` for `duration`: 802.1Q tags, CDP, LLDP, VTP and DTP.
/// Streams [`ScanEvent::Vlan`] / [`ScanEvent::Neighbor`] / log events as they are learned.
/// Frames sent from `own_macs` (this host) are ignored.
pub async fn run_passive_sniffer(
    if_name: &str,
    own_macs: Vec<[u8; 6]>,
    duration: Duration,
    tx: Sender<ScanEvent>,
    cancel: CancellationToken,
) -> Result<PassiveResults> {
    let if_name = if_name.to_string();
    tokio::task::spawn_blocking(move || -> Result<PassiveResults> {
        let mut cap = open_capture(&if_name, true)?;
        if let Err(e) = cap.filter(PASSIVE_FILTER, true) {
            let _ = tx.blocking_send(ScanEvent::warn(format!(
                "kernel capture filter rejected ({e}); filtering in user space"
            )));
        }
        // `None` (an absurdly long duration) means "until cancelled".
        let deadline = Instant::now().checked_add(duration);
        let mut agg = PassiveAggregator::new(&if_name).with_own_macs(own_macs);
        while deadline.is_none_or(|d| Instant::now() < d) && !cancel.is_cancelled() {
            match cap.next_packet() {
                Ok(pkt) => {
                    for ev in agg.ingest(pkt.data) {
                        if tx.blocking_send(ev).is_err() {
                            return Ok(agg.finish());
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {}
                Err(e) => return Err(map_pcap_error(e, &format!("capture on {if_name} failed"))),
            }
        }
        Ok(agg.finish())
    })
    .await
    .context("passive listener task failed")?
}

/// Turn the configured VLAN selection into the list of tags to probe (`None` = untagged).
///
/// `AutoDetect` combines OS VLAN sub-interfaces of `iface` with a short passive sniff
/// (`cfg.listen_secs`, capped at 5 s) and always includes the untagged native network.
pub async fn resolve_vlans(
    cfg: &ScanConfig,
    iface: &InterfaceInfo,
    all_ifaces: &[InterfaceInfo],
    tx: &Sender<ScanEvent>,
    cancel: &CancellationToken,
) -> Vec<Option<u16>> {
    match &cfg.vlans {
        VlanSelection::Untagged => vec![None],
        VlanSelection::List(ids) => ids.iter().copied().map(Some).collect(),
        VlanSelection::UntaggedAndList(ids) => std::iter::once(None)
            .chain(ids.iter().copied().map(Some))
            .collect(),
        VlanSelection::AutoDetect => {
            let mut ids: Vec<u16> = vlan_children(&iface.name, all_ifaces)
                .filter_map(|i| i.vlan_id)
                .collect();
            let secs = cfg.listen_secs.clamp(1, 5);
            let _ = tx
                .send(ScanEvent::info(format!(
                    "auto-detecting VLANs on {} ({secs} s passive listen)",
                    iface.name
                )))
                .await;
            match run_passive_sniffer(
                &iface.name,
                local_macs(all_ifaces),
                Duration::from_secs(secs),
                tx.clone(),
                cancel.clone(),
            )
            .await
            {
                Ok(res) => {
                    ids.extend(res.vlans.iter().map(|v| v.id));
                    // Final cumulative counts (the live events only carry early snapshots).
                    for v in res.vlans {
                        let _ = tx.send(ScanEvent::Vlan(v)).await;
                    }
                }
                Err(e) => {
                    let _ = tx
                        .send(ScanEvent::warn(format!(
                            "VLAN auto-detection sniff skipped: {e:#}"
                        )))
                        .await;
                }
            }
            ids.sort_unstable();
            ids.dedup();
            let _ = tx
                .send(ScanEvent::info(if ids.is_empty() {
                    "auto-detect found no VLANs; scanning untagged only".to_string()
                } else {
                    format!("auto-detected VLANs: {}", VlanSelection::List(ids.clone()))
                }))
                .await;
            std::iter::once(None)
                .chain(ids.into_iter().map(Some))
                .collect()
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Active L2 scan
// ---------------------------------------------------------------------------------------------

/// Counters returned by [`run_l2_scan`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct L2ScanReport {
    pub probes_sent: u64,
    pub devices_found: u64,
    /// Frames the OS refused to queue (ENOBUFS / EAGAIN) even after backing off.
    pub frames_dropped: u64,
}

/// One probing pass: which tag to send and which VLAN to report replies under.
#[derive(Debug, Clone)]
struct ProbeGroup {
    tag: Option<VlanTag>,
    /// VLAN reported on devices (the tag, or the VLAN of an OS sub-interface).
    report_vlan: Option<u16>,
    sender_ip: Ipv4Addr,
    targets: Vec<Ipv4Range>,
}

/// Intersection of two inclusive ranges.
pub fn intersect(a: &Ipv4Range, b: &Ipv4Range) -> Option<Ipv4Range> {
    let start = u32::from(a.start).max(u32::from(b.start));
    let end = u32::from(a.end).min(u32::from(b.end));
    (start <= end).then(|| Ipv4Range {
        start: Ipv4Addr::from(start),
        end: Ipv4Addr::from(end),
    })
}

/// Split `targets` into the part inside `subnet` (L2-reachable) and the routed remainder.
pub fn split_targets(
    targets: &[Ipv4Range],
    subnet: Option<&Ipv4Range>,
) -> (Vec<Ipv4Range>, Vec<Ipv4Range>) {
    let Some(subnet) = subnet else {
        return (Vec::new(), targets.to_vec());
    };
    let (mut local, mut routed) = (Vec::new(), Vec::new());
    for t in targets {
        match intersect(t, subnet) {
            None => routed.push(*t),
            Some(i) => {
                local.push(i);
                if t.start < i.start {
                    routed.push(Ipv4Range {
                        start: t.start,
                        end: Ipv4Addr::from(u32::from(i.start) - 1),
                    });
                }
                if t.end > i.end {
                    routed.push(Ipv4Range {
                        start: Ipv4Addr::from(u32::from(i.end) + 1),
                        end: t.end,
                    });
                }
            }
        }
    }
    (local, routed)
}

fn range_count(r: &[Ipv4Range]) -> u64 {
    r.iter().map(Ipv4Range::count).sum()
}

fn build_probe_groups(
    iface: &InterfaceInfo,
    targets: &[Ipv4Range],
    vlans: &[Option<u16>],
    tx: &Sender<ScanEvent>,
) -> Vec<ProbeGroup> {
    let mut groups = Vec::new();
    for vlan in vlans {
        match vlan {
            None => {
                let subnet = iface.local_subnet();
                let (local, routed) = split_targets(targets, subnet.as_ref());
                if !routed.is_empty() {
                    let _ = tx.try_send(ScanEvent::warn(format!(
                        "{} target address(es) are outside {}'s connected subnet; routed targets are \
                         handled by the ICMP sweeper",
                        range_count(&routed),
                        iface.name
                    )));
                }
                if !local.is_empty() {
                    groups.push(ProbeGroup {
                        tag: None,
                        report_vlan: iface.vlan_id,
                        sender_ip: iface
                            .primary_ipv4()
                            .map_or(Ipv4Addr::UNSPECIFIED, |(ip, _)| ip),
                        targets: local,
                    });
                }
            }
            Some(vid) => groups.push(ProbeGroup {
                tag: Some(VlanTag::new(*vid)),
                report_vlan: Some(*vid),
                // We own no address on a foreign VLAN: send RFC 5227-style probes.
                sender_ip: Ipv4Addr::UNSPECIFIED,
                targets: targets.to_vec(),
            }),
        }
    }
    groups
}

/// Decide which VLAN an incoming reply belongs to. Replies without a tag are attributed to
/// the untagged group when one was probed, or to the only tagged group (NIC tag stripping);
/// otherwise they are ambiguous and reported untagged.
fn attribute_vlan(groups: &[ProbeGroup], tag: Option<u16>) -> Option<u16> {
    if let Some(t) = tag {
        return Some(t);
    }
    if let Some(g) = groups.iter().find(|g| g.tag.is_none()) {
        return g.report_vlan;
    }
    match groups {
        [only] => only.report_vlan,
        _ => None,
    }
}

/// Slowest pace the transmitter backs off to under sustained back-pressure (50 pps).
const MAX_PACE_INTERVAL: Duration = Duration::from_millis(20);
/// Successful sends at a reduced pace before the pace is doubled again.
const PACE_RECOVERY_SENDS: u32 = 64;
/// First and largest single back-off sleep when the OS transmit queue is full.
const BACKOFF_START: Duration = Duration::from_millis(1);
const BACKOFF_MAX_STEP: Duration = Duration::from_millis(64);
/// Total time spent retrying one frame before it is counted as dropped.
const BACKOFF_BUDGET: Duration = Duration::from_millis(500);

/// Paced transmit through a pnet datalink sender. Back-pressure from the OS temporarily
/// lowers the rate (down to [`MAX_PACE_INTERVAL`]); it recovers after a run of good sends.
#[derive(Debug)]
struct Pacer {
    base: Duration,
    interval: Duration,
    next: Instant,
    good_streak: u32,
}

impl Pacer {
    fn new(rate_pps: u32) -> Self {
        let base = Duration::from_secs_f64(1.0 / f64::from(rate_pps.max(1)));
        Self {
            base,
            interval: base,
            next: Instant::now(),
            good_streak: 0,
        }
    }

    fn wait(&mut self) {
        let now = Instant::now();
        if self.next > now {
            thread::sleep(self.next - now);
        } else if now - self.next > Duration::from_millis(100) {
            // We fell far behind (e.g. the sender blocked): don't burst to catch up.
            self.next = now;
        }
        self.next += self.interval;
    }

    /// The OS transmit queue is full: halve the effective rate.
    fn on_backpressure(&mut self) {
        self.good_streak = 0;
        self.interval = (self.interval * 2).min(MAX_PACE_INTERVAL.max(self.base));
    }

    /// A frame was queued: after enough of them, step back towards the configured rate.
    fn on_sent(&mut self) {
        if self.interval > self.base {
            self.good_streak += 1;
            if self.good_streak >= PACE_RECOVERY_SENDS {
                self.good_streak = 0;
                self.interval = (self.interval / 2).max(self.base);
            }
        }
    }
}

/// Outcome of [`send_frame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendOutcome {
    Sent,
    /// The OS kept refusing the frame (transmit queue full) or the scan was cancelled
    /// while backing off.
    Dropped,
}

/// `true` for "transmit queue full" errors, which are back-pressure, not failures. On Windows
/// (Npcap's `PacketSendPacket`) that is `ERROR_NO_SYSTEM_RESOURCES` or Winsock's `WSAENOBUFS`.
fn is_backpressure(e: &io::Error) -> bool {
    const ERROR_NO_SYSTEM_RESOURCES: i32 = 1450;
    const WSAENOBUFS: i32 = 10055;
    let code = e.raw_os_error();
    code == Some(libc::ENOBUFS)
        || (cfg!(windows) && matches!(code, Some(ERROR_NO_SYSTEM_RESOURCES | WSAENOBUFS)))
        || matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        )
}

/// Send one frame. Back-pressure (ENOBUFS / EAGAIN) is retried with exponential back-off
/// for up to [`BACKOFF_BUDGET`] and slows the pacer; a frame that still cannot be queued is
/// dropped rather than failing the scan. Other errors are returned.
fn send_frame(
    sender: &mut dyn DataLinkSender,
    frame: &[u8],
    pacer: &mut Pacer,
    cancel: &CancellationToken,
) -> io::Result<SendOutcome> {
    let mut delay = BACKOFF_START;
    let mut waited = Duration::ZERO;
    loop {
        match sender.send_to(frame, None) {
            None | Some(Ok(())) => {
                pacer.on_sent();
                return Ok(SendOutcome::Sent);
            }
            Some(Err(e)) if is_backpressure(&e) => {
                pacer.on_backpressure();
                if waited >= BACKOFF_BUDGET || cancel.is_cancelled() {
                    return Ok(SendOutcome::Dropped);
                }
                sleep_cancellable(delay, cancel);
                waited += delay;
                delay = (delay * 2).min(BACKOFF_MAX_STEP);
            }
            Some(Err(e)) => return Err(e),
        }
    }
}

/// Sleep for `d`, waking early on cancellation.
fn sleep_cancellable(d: Duration, cancel: &CancellationToken) {
    let start = Instant::now();
    while !cancel.is_cancelled() {
        let elapsed = start.elapsed();
        if elapsed >= d {
            break;
        }
        thread::sleep((d - elapsed).min(Duration::from_millis(50)));
    }
}

/// `(ip, vlan)` pairs that have answered, shared between the RX and TX threads.
type AnsweredSet = Arc<Mutex<HashSet<(IpAddr, Option<u16>)>>>;
/// MACs that answered untagged ARP (candidates for EUI-64 neighbor solicitation).
type LearnedMacs = Arc<Mutex<Vec<[u8; 6]>>>;

/// IPv6 sources used for active NDP discovery on one interface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Ipv6Plan {
    link_local: Option<Ipv6Addr>,
    /// Global / ULA addresses with their prefix length.
    routable: Vec<(Ipv6Addr, u8)>,
}

impl Ipv6Plan {
    fn for_iface(iface: &InterfaceInfo) -> Option<Self> {
        let plan = Self {
            link_local: iface.link_local_v6(),
            routable: iface.routable_v6().collect(),
        };
        (plan.link_local.is_some() || !plan.routable.is_empty()).then_some(plan)
    }

    /// Source addresses of the all-nodes echo for a probe group. Every address of the
    /// interface is used on the native network (hosts answer an echo from the same scope,
    /// so a global source finds global addresses); tagged VLANs only get the link-local
    /// source since our routable prefixes do not exist there.
    fn echo_sources(&self, tag: Option<VlanTag>) -> Vec<Ipv6Addr> {
        let mut out: Vec<Ipv6Addr> = self.link_local.into_iter().collect();
        if tag.is_none() {
            out.extend(self.routable.iter().map(|(ip, _)| *ip));
        }
        out
    }

    /// Source address for neighbor solicitations.
    fn ns_source(&self) -> Option<Ipv6Addr> {
        self.link_local
            .or_else(|| self.routable.first().map(|(ip, _)| *ip))
    }

    /// EUI-64 SLAAC candidates of `mac` in each routable /64 of the interface.
    fn eui64_candidates(&self, mac: [u8; 6]) -> Vec<Ipv6Addr> {
        let mut out: Vec<Ipv6Addr> = self
            .routable
            .iter()
            .filter(|(_, prefix)| *prefix == 64)
            .map(|(net, _)| eui64_address(*net, mac))
            .collect();
        out.dedup();
        out
    }
}

/// The modified EUI-64 address of `mac` inside the /64 of `prefix` (RFC 4291 appendix A).
pub fn eui64_address(prefix: Ipv6Addr, mac: [u8; 6]) -> Ipv6Addr {
    let p = prefix.octets();
    let mut o = [0u8; 16];
    o[..8].copy_from_slice(&p[..8]);
    o[8..].copy_from_slice(&[
        mac[0] ^ 0x02,
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ]);
    Ipv6Addr::from(o)
}

/// Should an IPv6 observation from the active capture become a device? Echo replies must
/// come from an on-link source: link-local, or (on the native network) inside one of the
/// interface's prefixes. Other NDP messages are accepted as before.
fn accept_ipv6_observation(o: &Ipv6Observation, iface: &InterfaceInfo) -> bool {
    if o.icmp_type != ICMPV6_ECHO_REPLY {
        return true;
    }
    match o.vlan {
        Some(_) if o.vlan != iface.vlan_id => is_link_local_v6(o.ip),
        _ => iface.is_on_link_v6(o.ip),
    }
}

/// Shared state of the transmit thread.
struct TxContext {
    groups: Arc<Vec<ProbeGroup>>,
    answered: AnsweredSet,
    learned_macs: LearnedMacs,
    cancel: CancellationToken,
    progress: ProgressScope,
    dropped: Arc<AtomicU64>,
    rate_pps: u32,
    retries: u8,
    grace: Duration,
    src_mac: [u8; 6],
    ipv6: Option<Ipv6Plan>,
}

impl TxContext {
    fn is_answered(&self, ip: Ipv4Addr, vlan: Option<u16>) -> bool {
        self.answered
            .lock()
            .map(|s| s.contains(&(IpAddr::V4(ip), vlan)))
            .unwrap_or(false)
    }

    fn send(
        &self,
        sender: &mut dyn DataLinkSender,
        pacer: &mut Pacer,
        frame: &[u8],
    ) -> io::Result<()> {
        pacer.wait();
        if send_frame(sender, frame, pacer, &self.cancel)? == SendOutcome::Dropped {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
}

/// Paced probe transmission: `retries + 1` passes (later passes skip answered targets),
/// then a `grace` period for late replies.
fn transmit(ctx: &TxContext, sender: &mut dyn DataLinkSender) -> Result<()> {
    let mut pacer = Pacer::new(ctx.rate_pps);
    let mut solicited: HashSet<[u8; 6]> = HashSet::new();
    let untagged_probed = ctx.groups.iter().any(|g| g.tag.is_none());
    for pass in 0..=ctx.retries {
        if ctx.cancel.is_cancelled() {
            return Ok(());
        }
        if pass > 0 {
            sleep_cancellable(ctx.grace.min(Duration::from_secs(1)), &ctx.cancel);
        }
        if let Some(v6) = &ctx.ipv6 {
            let mut tags: Vec<Option<VlanTag>> = ctx.groups.iter().map(|g| g.tag).collect();
            if tags.is_empty() {
                tags.push(None);
            }
            tags.dedup();
            for tag in tags {
                for src in v6.echo_sources(tag) {
                    ctx.send(
                        sender,
                        &mut pacer,
                        &build_icmpv6_echo_multicast(ctx.src_mac, src, tag),
                    )
                    .map_err(|e| map_open_error(e, "ICMPv6 send failed"))?;
                }
            }
        }
        for g in ctx.groups.iter() {
            for ip in g.targets.iter().flat_map(Ipv4Range::iter) {
                if ctx.cancel.is_cancelled() {
                    return Ok(());
                }
                if pass == 0 || !ctx.is_answered(ip, g.report_vlan) {
                    ctx.send(
                        sender,
                        &mut pacer,
                        &build_arp_request(ctx.src_mac, g.sender_ip, ip, g.tag),
                    )
                    .map_err(|e| map_open_error(e, &format!("ARP send to {ip} failed")))?;
                }
                if pass == 0 {
                    ctx.progress.add(1);
                }
            }
        }
        // Hosts using EUI-64 SLAAC addresses often ignore multicast echo: solicit the
        // global address derived from each MAC that answered ARP on the native network.
        if let (Some(v6), true) = (&ctx.ipv6, untagged_probed) {
            if let Some(src) = v6.ns_source() {
                let macs: Vec<[u8; 6]> = ctx
                    .learned_macs
                    .lock()
                    .map(|m| m.clone())
                    .unwrap_or_default();
                for mac in macs.into_iter().filter(|m| solicited.insert(*m)) {
                    for target in v6.eui64_candidates(mac) {
                        if ctx.cancel.is_cancelled() {
                            return Ok(());
                        }
                        ctx.send(
                            sender,
                            &mut pacer,
                            &build_neighbor_solicitation(ctx.src_mac, src, target, None),
                        )
                        .map_err(|e| map_open_error(e, "ICMPv6 send failed"))?;
                    }
                }
            }
        }
    }
    sleep_cancellable(ctx.grace, &ctx.cancel);
    Ok(())
}

/// Active L2 discovery on `iface`: broadcast ARP (and with `cfg.ipv6` an ICMPv6 all-nodes
/// echo from each of the interface's IPv6 addresses, plus neighbor solicitations for the
/// EUI-64 addresses of ARP responders) for every target, once per entry of `vlans`
/// (`None` = untagged, `Some(id)` = 802.1Q-tagged). Untagged probing is restricted to the
/// interface's connected subnet.
///
/// Probes are paced at `cfg.rate_pps`; `cfg.retries` extra passes re-probe unanswered
/// addresses; replies are collected for a further `cfg.timeout_ms`. Each first-pass probe
/// is counted in `progress`. Each new `(ip, vlan)` is streamed as a [`ScanEvent::Device`].
/// Fails with [`L2Error::PermissionDenied`] when raw access is not available so callers
/// can fall back to ICMP. A full OS transmit queue slows the scan down but never fails it.
pub async fn run_l2_scan(
    iface: &InterfaceInfo,
    targets: Vec<Ipv4Range>,
    vlans: Vec<Option<u16>>,
    cfg: &ScanConfig,
    progress: ProgressScope,
    tx: Sender<ScanEvent>,
    cancel: CancellationToken,
) -> Result<L2ScanReport> {
    if iface.kind == InterfaceKind::Loopback {
        bail!(L2Error::NoLinkLayer(iface.name.clone()));
    }
    let src_mac = match iface.mac.as_deref().and_then(parse_mac) {
        Some(mac) => mac,
        // macOS hides link addresses from unprivileged processes; raw access needs root anyway.
        None if !is_root() && iface.kind != InterfaceKind::Vpn => {
            bail!(L2Error::PermissionDenied(format!(
                "the MAC address of {} is hidden from unprivileged processes; active layer-2 \
                 probes need it, so BPF device access alone is not enough",
                iface.name
            )))
        }
        None => bail!(L2Error::NoLinkLayer(iface.name.clone())),
    };
    let groups = Arc::new(build_probe_groups(iface, &targets, &vlans, &tx));
    let ipv6 = if cfg.ipv6 {
        Ipv6Plan::for_iface(iface)
    } else {
        None
    };
    if cfg.ipv6 && ipv6.is_none() {
        let _ = tx.try_send(ScanEvent::warn(format!(
            "{} has no IPv6 address; skipping NDP discovery",
            iface.name
        )));
    }
    if groups.is_empty() && ipv6.is_none() {
        return Ok(L2ScanReport::default());
    }
    let total: u64 = groups.iter().map(|g| range_count(&g.targets)).sum();

    // Open both handles up front so permission problems surface before anything is sent.
    let name = iface.name.clone();
    let (mut sender, mut capture) = tokio::task::spawn_blocking(move || -> Result<_> {
        let ni = datalink_interface(&name, src_mac)?;
        let config = datalink::Config {
            read_buffer_size: 1 << 16,
            write_buffer_size: 1 << 12,
            read_timeout: Some(Duration::from_millis(100)),
            write_timeout: Some(Duration::from_millis(500)),
            promiscuous: false,
            ..Default::default()
        };
        let sender = match datalink::channel(&ni, config) {
            Ok(Channel::Ethernet(tx, _rx)) => tx,
            Ok(_) => bail!("unsupported datalink channel type on {name}"),
            Err(e) => {
                return Err(map_open_error(
                    e,
                    &format!("cannot open raw channel on {name}"),
                ))
            }
        };
        // Promiscuous so NIC VLAN filtering does not drop tagged replies.
        let mut cap = open_capture(&name, true)?;
        cap.filter(ACTIVE_FILTER, true)
            .map_err(|e| map_pcap_error(e, "cannot install capture filter"))?;
        Ok((sender, cap))
    })
    .await
    .context("raw channel setup task failed")??;
    // Passive listeners on this host must not mistake our tagged probes for live VLANs.
    register_transmit_mac(src_mac);

    let _ = tx.try_send(ScanEvent::info(format!(
        "L2 scan on {}: {} address(es) across {} probe group(s){}",
        iface.name,
        total,
        groups.len(),
        if ipv6.is_some() { " + IPv6 NDP" } else { "" }
    )));

    let answered: AnsweredSet = Arc::default();
    let learned_macs: LearnedMacs = Arc::default();
    let done = Arc::new(AtomicBool::new(false));
    // Lets a failing receiver stop the transmitter without cancelling the whole scan.
    let cancel = cancel.child_token();
    let found = Arc::new(AtomicU64::new(0));
    let dropped = Arc::new(AtomicU64::new(0));
    let sent_before = progress.used();

    // --- RX -----------------------------------------------------------------------------
    let rx_task = {
        let (groups, answered, learned_macs, done, found, tx, cancel) = (
            groups.clone(),
            answered.clone(),
            learned_macs.clone(),
            done.clone(),
            found.clone(),
            tx.clone(),
            cancel.clone(),
        );
        let iface = iface.clone();
        let want_v6 = ipv6.is_some();
        let untagged_vlan = groups
            .iter()
            .find(|g| g.tag.is_none())
            .map(|g| g.report_vlan);
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut warned_untagged = false;
            let mut routers_seen: std::collections::HashSet<(IpAddr, Option<u16>)> =
                std::collections::HashSet::new();
            while !done.load(Ordering::Acquire) && !cancel.is_cancelled() {
                let data = match capture.next_packet() {
                    Ok(pkt) => pkt.data,
                    Err(pcap::Error::TimeoutExpired) => continue,
                    Err(e) => {
                        cancel.cancel();
                        return Err(map_pcap_error(
                            e,
                            &format!("capture on {} failed", iface.name),
                        ));
                    }
                };
                let observed = if let Some(r) = parse_arp_reply(data) {
                    let vlan = attribute_vlan(&groups, r.vlan);
                    let ambiguous = r.vlan.is_none()
                        && vlan.is_none()
                        && !groups.iter().any(|g| g.tag.is_none());
                    if ambiguous && !warned_untagged {
                        warned_untagged = true;
                        let _ = tx.try_send(ScanEvent::warn(
                            "ARP replies are arriving without 802.1Q tags (NIC VLAN stripping?); \
                             they cannot be attributed to a VLAN",
                        ));
                    }
                    // Only report hosts inside the requested ranges (other ARP chatter is ignored).
                    let in_scope = groups
                        .iter()
                        .any(|g| g.targets.iter().any(|t| t.contains(r.ip)));
                    in_scope.then_some((IpAddr::V4(r.ip), r.mac, vlan, DiscoverySource::Arp, false))
                } else if want_v6 {
                    parse_icmpv6_discovery(data)
                        .filter(|o| accept_ipv6_observation(o, &iface))
                        .map(|o| {
                            (
                                IpAddr::V6(o.ip),
                                o.mac,
                                attribute_vlan(&groups, o.vlan),
                                DiscoverySource::Ndp,
                                o.icmp_type == ICMPV6_ROUTER_ADVERT,
                            )
                        })
                } else {
                    None
                };
                let Some((ip, mac, vlan, source, router)) = observed else {
                    continue;
                };
                if mac == src_mac {
                    continue;
                }
                let is_new = answered
                    .lock()
                    .map(|mut set| set.insert((ip, vlan)))
                    .unwrap_or(false);
                // A router advertisement from an already-seen host still marks it as a router
                // (once).
                let new_router =
                    router && routers_seen.len() < 4096 && routers_seen.insert((ip, vlan));
                if !is_new && !new_router {
                    continue;
                }
                if want_v6 && ip.is_ipv4() && untagged_vlan == Some(vlan) {
                    if let Ok(mut macs) = learned_macs.lock() {
                        if !macs.contains(&mac) {
                            macs.push(mac);
                        }
                    }
                }
                if is_new {
                    found.fetch_add(1, Ordering::Relaxed);
                }
                let mut dev = Device::new(ip);
                dev.mac = Some(format_mac(&mac));
                dev.vlan_id = vlan;
                dev.role = DeviceRole::Host;
                dev.interface = Some(iface.name.clone());
                dev.add_source(source);
                if router {
                    dev.ipv6_router = Some(true);
                }
                if tx.blocking_send(ScanEvent::device(dev)).is_err() {
                    break;
                }
            }
            Ok(())
        })
    };

    // --- TX -----------------------------------------------------------------------------
    let tx_task = {
        let ctx = TxContext {
            groups,
            answered,
            learned_macs,
            cancel,
            progress: progress.clone(),
            dropped: dropped.clone(),
            rate_pps: cfg.rate_pps,
            retries: cfg.retries,
            grace: Duration::from_millis(cfg.timeout_ms),
            src_mac,
            ipv6,
        };
        tokio::task::spawn_blocking(move || -> Result<()> {
            let result = transmit(&ctx, sender.as_mut());
            done.store(true, Ordering::Release);
            result
        })
    };

    let (tx_res, rx_res) = tokio::join!(tx_task, rx_task);
    tx_res.context("transmit task panicked")??;
    rx_res.context("receive task panicked")??;
    let report = L2ScanReport {
        probes_sent: progress.used().saturating_sub(sent_before),
        devices_found: found.load(Ordering::Relaxed),
        frames_dropped: dropped.load(Ordering::Relaxed),
    };
    if report.frames_dropped > 0 {
        let _ = tx
            .send(ScanEvent::warn(format!(
                "{}: {} probe frame(s) dropped because the OS transmit queue stayed full; \
                 consider a lower --rate-pps",
                iface.name, report.frames_dropped
            )))
            .await;
    }
    Ok(report)
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const MAC_A: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const MAC_B: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];

    fn ip4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    // --- builders ---------------------------------------------------------------------------

    #[test]
    fn untagged_arp_request_bytes() {
        let f = build_arp_request(MAC_A, ip4("10.0.0.5"), ip4("10.0.0.77"), None);
        assert_eq!(f.len(), 60);
        assert_eq!(&f[0..6], &BROADCAST_MAC);
        assert_eq!(&f[6..12], &MAC_A);
        assert_eq!(&f[12..14], &[0x08, 0x06]);
        assert_eq!(&f[14..22], &[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]);
        assert_eq!(&f[22..28], &MAC_A);
        assert_eq!(&f[28..32], &[10, 0, 0, 5]);
        assert_eq!(&f[32..38], &[0; 6]);
        assert_eq!(&f[38..42], &[10, 0, 0, 77]);
        assert!(f[42..].iter().all(|b| *b == 0));
    }

    #[test]
    fn tagged_arp_request_bytes() {
        let tag = VlanTag { vid: 100, pcp: 5 };
        assert_eq!(tag.tci(), (5 << 13) | 100);
        let f = build_arp_request(
            MAC_A,
            Ipv4Addr::UNSPECIFIED,
            ip4("192.168.100.1"),
            Some(tag),
        );
        assert_eq!(f.len(), 60);
        assert_eq!(&f[12..14], &[0x81, 0x00]);
        assert_eq!(&f[14..16], &[0xa0, 0x64]); // PCP 5, VID 100
        assert_eq!(&f[16..18], &[0x08, 0x06]);
        assert_eq!(&f[18..20], &[0x00, 0x01]);
        assert_eq!(&f[32..36], &[0, 0, 0, 0]);
        assert_eq!(&f[42..46], &[192, 168, 100, 1]);
        // Round trip through the parser.
        let eth = parse_frame(&f).unwrap();
        assert_eq!(eth.vlans, vec![100]);
        assert_eq!(eth.ethertype, ETHERTYPE_ARP);
        assert_eq!(eth.payload_offset, 18);
    }

    fn checksum_ok(frame: &[u8], ip_off: usize) -> bool {
        let src = ipv6_at(frame, ip_off + 8).unwrap();
        let dst = ipv6_at(frame, ip_off + 24).unwrap();
        let plen = usize::from(be16(frame, ip_off + 4).unwrap());
        let icmp = &frame[ip_off + 40..ip_off + 40 + plen];
        // Summing a message including a correct checksum yields 0xffff → complement 0.
        icmpv6_checksum(src, dst, icmp) == 0
    }

    #[test]
    fn icmpv6_echo_multicast_frame() {
        let ll: Ipv6Addr = "fe80::211:22ff:fe33:4455".parse().unwrap();
        let f = build_icmpv6_echo_multicast(MAC_A, ll, None);
        assert_eq!(&f[0..6], &[0x33, 0x33, 0, 0, 0, 1]);
        assert_eq!(&f[12..14], &[0x86, 0xdd]);
        assert_eq!(f[14] >> 4, 6);
        assert_eq!(f[20], 58); // next header
        assert_eq!(f[21], 255); // hop limit
        assert_eq!(ipv6_at(&f, 38).unwrap(), ALL_NODES_V6);
        assert_eq!(f[54], ICMPV6_ECHO_REQUEST);
        assert!(checksum_ok(&f, 14));

        // Cross-check against pnet's independent implementation.
        use pnet::packet::icmpv6::{checksum, Icmpv6Packet};
        let icmp = &f[54..54 + usize::from(be16(&f, 18).unwrap())];
        let pkt = Icmpv6Packet::new(icmp).unwrap();
        assert_eq!(checksum(&pkt, &ll, &ALL_NODES_V6), be16(icmp, 2).unwrap());

        let tagged = build_icmpv6_echo_multicast(MAC_A, ll, Some(VlanTag::new(30)));
        assert_eq!(&tagged[12..16], &[0x81, 0x00, 0x00, 30]);
        assert!(checksum_ok(&tagged, 18));
    }

    #[test]
    fn neighbor_solicitation_frame() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let target: Ipv6Addr = "2001:db8::abcd:1234".parse().unwrap();
        let f = build_neighbor_solicitation(MAC_A, src, target, None);
        assert_eq!(
            solicited_node(target),
            "ff02::1:ffcd:1234".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(&f[0..6], &[0x33, 0x33, 0xff, 0xcd, 0x12, 0x34]);
        assert_eq!(f[54], ICMPV6_NEIGHBOR_SOLICIT);
        assert_eq!(ipv6_at(&f, 62).unwrap(), target);
        assert_eq!(&f[78..80], &[1, 1]);
        assert_eq!(&f[80..86], &MAC_A);
        assert!(checksum_ok(&f, 14));
    }

    // --- parsers ----------------------------------------------------------------------------

    fn arp_reply_frame(vlans: &[(u16, u16)]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&MAC_A);
        f.extend_from_slice(&MAC_B);
        for (tpid, vid) in vlans {
            f.extend_from_slice(&tpid.to_be_bytes());
            f.extend_from_slice(&vid.to_be_bytes());
        }
        f.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        f.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 2]);
        f.extend_from_slice(&MAC_B);
        f.extend_from_slice(&[10, 20, 0, 9]);
        f.extend_from_slice(&MAC_A);
        f.extend_from_slice(&[10, 20, 0, 1]);
        f
    }

    #[test]
    fn parses_stacked_tags_and_arp_reply() {
        let f = arp_reply_frame(&[(ETHERTYPE_QINQ, 0x2000 | 300), (ETHERTYPE_VLAN, 20)]);
        let eth = parse_frame(&f).unwrap();
        assert_eq!(eth.vlans, vec![300, 20]);
        assert_eq!(eth.ethertype, ETHERTYPE_ARP);
        assert_eq!(eth.payload_offset, 22);
        let r = parse_arp_reply(&f).unwrap();
        assert_eq!(r.ip, ip4("10.20.0.9"));
        assert_eq!(r.mac, MAC_B);
        assert_eq!(r.target_ip, ip4("10.20.0.1"));
        assert_eq!(r.vlan, Some(300));

        // Priority-tagged (VID 0) frames are untagged for VLAN purposes.
        let prio = arp_reply_frame(&[(ETHERTYPE_VLAN, 0xa000)]);
        assert_eq!(parse_arp_reply(&prio).unwrap().vlan, None);

        // A request is not a reply.
        let req = build_arp_request(MAC_A, ip4("10.0.0.1"), ip4("10.0.0.2"), None);
        assert!(parse_arp_reply(&req).is_none());
    }

    #[test]
    fn rejects_truncated_and_overtagged_frames() {
        let f = arp_reply_frame(&[(ETHERTYPE_VLAN, 10)]);
        for len in 0..f.len() {
            let _ = parse_frame(&f[..len]);
            let _ = parse_arp_reply(&f[..len]);
        }
        assert!(parse_frame(&f[..13]).is_none());
        let deep = arp_reply_frame(&[(ETHERTYPE_VLAN, 1); 5]);
        assert!(parse_frame(&deep).is_none());
    }

    #[test]
    fn parses_icmpv6_echo_reply_and_na() {
        let ll: Ipv6Addr = "fe80::aabb:ccff:fedd:ee01".parse().unwrap();
        let mut f = build_icmpv6_echo_multicast(MAC_B, ll, Some(VlanTag::new(40)));
        f[58] = ICMPV6_ECHO_REPLY; // icmp type sits after 18-byte tagged header + 40-byte IPv6
        let o = parse_icmpv6_discovery(&f).unwrap();
        assert_eq!(
            (o.ip, o.mac, o.vlan, o.icmp_type),
            (ll, MAC_B, Some(40), ICMPV6_ECHO_REPLY)
        );

        // Neighbor advertisement with target link-layer option.
        let target: Ipv6Addr = "2001:db8::9".parse().unwrap();
        let mut icmp = vec![ICMPV6_NEIGHBOR_ADVERT, 0, 0, 0, 0x60, 0, 0, 0];
        icmp.extend_from_slice(&target.octets());
        icmp.extend_from_slice(&[2, 1]);
        icmp.extend_from_slice(&MAC_B);
        let na = build_icmpv6_frame(MAC_A, MAC_B, ll, "fe80::1".parse().unwrap(), None, icmp);
        let o = parse_icmpv6_discovery(&na).unwrap();
        assert_eq!((o.ip, o.mac, o.vlan), (target, MAC_B, None));

        // Our own echo request is ignored.
        let req = build_icmpv6_echo_multicast(MAC_A, ll, None);
        assert!(parse_icmpv6_discovery(&req).is_none());
        for len in 0..na.len() {
            let _ = parse_icmpv6_discovery(&na[..len]);
        }
    }

    // --- CDP --------------------------------------------------------------------------------

    fn cdp_tlv(t: u16, v: &[u8]) -> Vec<u8> {
        let mut out = t.to_be_bytes().to_vec();
        out.extend_from_slice(&u16::try_from(v.len() + 4).unwrap().to_be_bytes());
        out.extend_from_slice(v);
        out
    }

    fn cdp_ipv4_addrs(ips: &[[u8; 4]]) -> Vec<u8> {
        let mut v = u32::try_from(ips.len()).unwrap().to_be_bytes().to_vec();
        for ip in ips {
            v.extend_from_slice(&[1, 1, 0xcc, 0, 4]);
            v.extend_from_slice(ip);
        }
        v
    }

    fn snap_frame(src: [u8; 6], dst: [u8; 6], tag: Option<u16>, pid: u16, body: &[u8]) -> Vec<u8> {
        let mut llc = LLC_SNAP.to_vec();
        llc.extend_from_slice(&OUI_CISCO);
        llc.extend_from_slice(&pid.to_be_bytes());
        llc.extend_from_slice(body);
        let mut f = dst.to_vec();
        f.extend_from_slice(&src);
        if let Some(vid) = tag {
            f.extend_from_slice(&[0x81, 0x00]);
            f.extend_from_slice(&vid.to_be_bytes());
        }
        f.extend_from_slice(&u16::try_from(llc.len()).unwrap().to_be_bytes());
        f.extend_from_slice(&llc);
        f
    }

    fn cdp_frame(tag: Option<u16>) -> Vec<u8> {
        let mut body = vec![2, 180, 0xbe, 0xef];
        body.extend(cdp_tlv(0x0001, b"CORE-SW01.example.com"));
        body.extend(cdp_tlv(0x0002, &cdp_ipv4_addrs(&[[10, 0, 0, 2]])));
        body.extend(cdp_tlv(0x0003, b"GigabitEthernet1/0/24"));
        body.extend(cdp_tlv(0x0004, &0x28u32.to_be_bytes()));
        body.extend(cdp_tlv(0x0005, b"Cisco IOS Software, Version 17.9.4\n"));
        body.extend(cdp_tlv(0x0006, b"cisco C9300-48P"));
        body.extend(cdp_tlv(0x0009, b"CAMPUS"));
        body.extend(cdp_tlv(0x000a, &10u16.to_be_bytes()));
        body.extend(cdp_tlv(0x000e, &[1, 0, 100]));
        body.extend(cdp_tlv(
            0x0016,
            &cdp_ipv4_addrs(&[[10, 0, 0, 2], [192, 168, 255, 1]]),
        ));
        body.extend(cdp_tlv(0x7777, b"unknown tlv"));
        let mut f = snap_frame(MAC_B, CDP_MULTICAST, tag, SNAP_PID_CDP, &body);
        f.extend_from_slice(&[0; 4]); // trailing padding beyond the 802.3 length is ignored
        f
    }

    #[test]
    fn parses_cdp_frame() {
        for tag in [None, Some(1)] {
            let n = parse_cdp(&cdp_frame(tag), "en0").unwrap();
            assert_eq!(n.protocol, NeighborProtocol::Cdp);
            assert_eq!(n.local_interface, "en0");
            assert_eq!(n.source_mac, "aa:bb:cc:dd:ee:01");
            assert_eq!(n.device_id, "CORE-SW01.example.com");
            assert_eq!(n.port_id.as_deref(), Some("GigabitEthernet1/0/24"));
            assert_eq!(n.capabilities, vec![Capability::Switch]);
            assert_eq!(
                n.software_version.as_deref(),
                Some("Cisco IOS Software, Version 17.9.4")
            );
            assert_eq!(n.platform.as_deref(), Some("cisco C9300-48P"));
            assert_eq!(n.vtp_domain.as_deref(), Some("CAMPUS"));
            assert_eq!(n.native_vlan, Some(10));
            assert_eq!(n.voice_vlan, Some(100));
            assert_eq!(n.ttl_secs, 180);
            assert_eq!(
                n.management_addrs,
                vec![
                    IpAddr::V4(ip4("10.0.0.2")),
                    IpAddr::V4(ip4("192.168.255.1"))
                ]
            );
            assert_eq!(n.infer_role(), DeviceRole::Switch);
        }
    }

    #[test]
    fn cdp_capability_bits() {
        assert_eq!(cdp_capabilities(0x01), vec![Capability::Router]);
        assert_eq!(
            cdp_capabilities(0x29),
            vec![Capability::Router, Capability::Switch]
        );
        assert_eq!(
            cdp_capabilities(0x90),
            vec![Capability::Host, Capability::Telephone]
        );
        assert_eq!(cdp_capabilities(0x20), vec![Capability::Other]);
    }

    #[test]
    fn cdp_ipv6_address_and_rejections() {
        let mut v = 1u32.to_be_bytes().to_vec();
        v.extend_from_slice(&[2, 8, 0xaa, 0xaa, 0x03, 0, 0, 0, 0x86, 0xdd, 0, 16]);
        v.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(
            parse_cdp_addresses(&v),
            vec!["2001:db8::1".parse::<IpAddr>().unwrap()]
        );
        // Count larger than the data: stops cleanly.
        assert!(parse_cdp_addresses(&[0, 0, 0, 9, 1]).is_empty());

        let mut f = cdp_frame(None);
        f[0] = 0x02; // wrong destination
        assert!(parse_cdp(&f, "en0").is_none());
        assert!(parse_lldp(&cdp_frame(None), "en0").is_none());
    }

    #[test]
    fn cdp_never_panics_on_malformed_input() {
        let f = cdp_frame(Some(5));
        for len in 0..f.len() {
            let _ = parse_cdp(&f[..len], "en0");
        }
        // Corrupt every byte position in turn.
        for i in 0..f.len() {
            let mut g = f.clone();
            g[i] ^= 0xff;
            let _ = parse_cdp(&g, "en0");
            let _ = parse_vtp(&g);
        }
        // Pseudo-random bodies behind a valid header.
        let mut seed: u32 = 0x1234_5678;
        for _ in 0..500 {
            let mut body = vec![2, 180, 0, 0];
            for _ in 0..64 {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                body.push((seed >> 16) as u8);
            }
            let _ = parse_cdp(
                &snap_frame(MAC_B, CDP_MULTICAST, None, SNAP_PID_CDP, &body),
                "en0",
            );
        }
    }

    // --- PoE TLVs ---------------------------------------------------------------------------

    /// A Cisco IP phone's CDP advert: Telephone capability, voice VLAN, Power Consumption
    /// (0x0010, mW) and Power Available (0x001a: request-id, mgmt-id, mW).
    #[test]
    fn parses_cdp_power_tlvs() {
        let mut body = vec![2, 180, 0, 0];
        body.extend(cdp_tlv(0x0001, b"SEP001122334455"));
        body.extend(cdp_tlv(0x0004, &0x90u32.to_be_bytes())); // host + phone
        body.extend(cdp_tlv(0x0006, b"Cisco IP Phone 8841"));
        body.extend(cdp_tlv(0x000e, &[1, 0, 110]));
        body.extend(cdp_tlv(0x0010, &6300u16.to_be_bytes())); // 6.3 W drawn
        let mut avail = vec![0, 1, 0, 2];
        avail.extend_from_slice(&15_400u32.to_be_bytes()); // 15.4 W available
        body.extend(cdp_tlv(0x001a, &avail));
        let f = snap_frame(MAC_B, CDP_MULTICAST, None, SNAP_PID_CDP, &body);
        let n = parse_cdp(&f, "en0").unwrap();
        assert!(n.capabilities.contains(&Capability::Telephone));
        assert_eq!(n.voice_vlan, Some(110));
        assert_eq!(n.poe_watts, Some(6.3));
        let poe = n.poe_info.unwrap();
        assert_eq!(poe.watts, Some(6.3));
        assert_eq!(poe.max_watts, Some(15.4));
        // Zero / truncated power values carry no data.
        assert_eq!(parse_cdp_power_consumption(&[0, 0]), None);
        assert_eq!(parse_cdp_power_consumption(&[1]), None);
        assert_eq!(parse_cdp_power_available(&[0, 1, 0, 2, 0]), None);
    }

    /// LLDP from a PoE endpoint: IEEE 802.3 Power-via-MDI (class + 802.3at requested /
    /// allocated power) and LLDP-MED Extended Power-via-MDI (priority, 0.1 W value).
    #[test]
    fn parses_lldp_power_tlvs() {
        let mut f = LLDP_MULTICAST.to_vec();
        f.extend_from_slice(&MAC_B);
        f.extend_from_slice(&ETHERTYPE_LLDP.to_be_bytes());
        let mut chassis = vec![4];
        chassis.extend_from_slice(&MAC_B);
        f.extend(lldp_tlv(1, &chassis));
        f.extend(lldp_tlv(2, b"\x03\xaa\xbb\xcc\xdd\xee\x01"));
        f.extend(lldp_tlv(3, &120u16.to_be_bytes()));
        // 802.3 PoE: support 0x0f, pair 1, power class enum 5 (= class 4), then the 802.3at
        // type/source/priority octet 0x51 (source PSE, priority critical), PD requested 25.5 W
        // and PSE allocated 30.0 W (0.1 W units).
        let mut dot3 = vec![0x00, 0x12, 0x0f, 2, 0x0f, 0x01, 0x05, 0x51];
        dot3.extend_from_slice(&255u16.to_be_bytes());
        dot3.extend_from_slice(&300u16.to_be_bytes());
        f.extend(lldp_tlv(127, &dot3));
        // LLDP-MED extended power: PD(01) source PSE(01) priority high(2) → 0b0101_0010.
        let mut med = vec![0x00, 0x12, 0xbb, 4, 0x52];
        med.extend_from_slice(&120u16.to_be_bytes()); // 12.0 W (802.3 value wins)
        f.extend(lldp_tlv(127, &med));
        f.extend(lldp_tlv(0, &[]));
        let n = parse_lldp(&f, "en0").unwrap();
        let poe = n.poe_info.clone().unwrap();
        assert_eq!(poe.class, Some(4));
        assert_eq!(poe.watts, Some(25.5));
        assert_eq!(poe.max_watts, Some(30.0));
        assert_eq!(poe.priority.as_deref(), Some("critical"));
        assert_eq!(poe.source.as_deref(), Some("pse"));
        assert_eq!(n.poe_watts, Some(25.5));

        // MED-only advert.
        let med = parse_med_ext_power(&[0x53, 0x00, 0x46]).unwrap();
        assert_eq!(med.watts, Some(7.0));
        assert_eq!(med.priority.as_deref(), Some("low"));
        // Base 802.3 TLV (no at-extension): class only.
        let base = parse_dot3_power_mdi(&[0x0f, 0x01, 0x03]).unwrap();
        assert_eq!((base.class, base.watts), (Some(2), None));
        // Hostile / empty input.
        assert!(parse_dot3_power_mdi(&[]).is_none());
        assert!(parse_dot3_power_mdi(&[0x0f, 0x01, 0x00]).is_none());
        assert!(parse_med_ext_power(&[0x50]).is_none());
        for len in 0..f.len() {
            let _ = parse_lldp(&f[..len], "en0");
        }
    }

    // --- LLDP -------------------------------------------------------------------------------

    fn lldp_tlv(t: u16, v: &[u8]) -> Vec<u8> {
        let header = (t << 9) | u16::try_from(v.len()).unwrap();
        let mut out = header.to_be_bytes().to_vec();
        out.extend_from_slice(v);
        out
    }

    fn lldp_frame(tag: Option<u16>) -> Vec<u8> {
        let mut f = LLDP_MULTICAST.to_vec();
        f.extend_from_slice(&MAC_B);
        if let Some(vid) = tag {
            f.extend_from_slice(&[0x81, 0x00]);
            f.extend_from_slice(&vid.to_be_bytes());
        }
        f.extend_from_slice(&ETHERTYPE_LLDP.to_be_bytes());
        let mut chassis = vec![4];
        chassis.extend_from_slice(&MAC_B);
        f.extend(lldp_tlv(1, &chassis));
        f.extend(lldp_tlv(2, b"\x05ge-0/0/12"));
        f.extend(lldp_tlv(3, &120u16.to_be_bytes()));
        f.extend(lldp_tlv(4, b"uplink to IDF-2"));
        f.extend(lldp_tlv(5, b"idf2-ex3400"));
        f.extend(lldp_tlv(
            6,
            b"Juniper Networks, Inc. ex3400-48p Ethernet Switch, JUNOS 22.4R3",
        ));
        f.extend(lldp_tlv(7, &[0x00, 0x14, 0x00, 0x14])); // bridge + router
        f.extend(lldp_tlv(8, &[5, 1, 10, 1, 2, 3, 2, 0, 0, 0, 1, 0]));
        f.extend(lldp_tlv(127, &[0x00, 0x80, 0xc2, 1, 0, 20]));
        let policy: u32 = (1 << 22) | (200 << 9) | (5 << 6) | 46;
        let pb = policy.to_be_bytes();
        f.extend(lldp_tlv(
            127,
            &[0x00, 0x12, 0xbb, 2, 1, pb[1], pb[2], pb[3]],
        ));
        f.extend(lldp_tlv(127, b"\x00\x12\xbb\x0aEX3400-48P"));
        f.extend(lldp_tlv(0, &[]));
        f.extend(lldp_tlv(5, b"ignored-after-end"));
        f
    }

    #[test]
    fn parses_lldp_frame() {
        for tag in [None, Some(99)] {
            let n = parse_lldp(&lldp_frame(tag), "eth0").unwrap();
            assert_eq!(n.protocol, NeighborProtocol::Lldp);
            assert_eq!(n.device_id, "aa:bb:cc:dd:ee:01");
            assert_eq!(n.port_id.as_deref(), Some("ge-0/0/12"));
            assert_eq!(n.ttl_secs, 120);
            assert_eq!(n.port_description.as_deref(), Some("uplink to IDF-2"));
            assert_eq!(n.system_name.as_deref(), Some("idf2-ex3400"));
            assert!(n.system_description.as_deref().unwrap().contains("JUNOS"));
            assert_eq!(n.capabilities, vec![Capability::Switch, Capability::Router]);
            assert_eq!(n.management_addrs, vec![IpAddr::V4(ip4("10.1.2.3"))]);
            assert_eq!(n.native_vlan, Some(20));
            assert_eq!(n.voice_vlan, Some(200));
            assert_eq!(n.platform.as_deref(), Some("EX3400-48P"));
            assert_eq!(n.infer_role(), DeviceRole::Switch);
        }
    }

    #[test]
    fn network_policy_bits() {
        let bits: u32 = (1 << 22) | (200 << 9) | (5 << 6) | 46;
        let b = bits.to_be_bytes();
        let p = parse_network_policy(&[1, b[1], b[2], b[3]]).unwrap();
        assert_eq!(
            p,
            NetworkPolicy {
                app_type: 1,
                unknown: false,
                tagged: true,
                vlan_id: 200,
                l2_priority: 5,
                dscp: 46
            }
        );
        assert!(parse_network_policy(&[1, 2]).is_none());
    }

    #[test]
    fn lldp_ids_render_by_subtype() {
        assert_eq!(
            render_lldp_id(&[5, 1, 192, 0, 2, 1], 4, 5).as_deref(),
            Some("192.0.2.1")
        );
        assert_eq!(
            render_lldp_id(b"\x07local-id", 4, 5).as_deref(),
            Some("local-id")
        );
        assert_eq!(
            render_lldp_id(&[1, 0x01, 0x02], 4, 5).as_deref(),
            Some("01:02")
        );
        assert_eq!(render_lldp_id(&[4], 4, 5), None);
    }

    #[test]
    fn lldp_never_panics_on_malformed_input() {
        let f = lldp_frame(None);
        for len in 0..f.len() {
            let _ = parse_lldp(&f[..len], "eth0");
        }
        for i in 14..f.len() {
            let mut g = f.clone();
            g[i] ^= 0xa5;
            let _ = parse_lldp(&g, "eth0");
        }
        // Missing chassis id → invalid LLDPDU.
        let mut bare = LLDP_MULTICAST.to_vec();
        bare.extend_from_slice(&MAC_B);
        bare.extend_from_slice(&ETHERTYPE_LLDP.to_be_bytes());
        bare.extend(lldp_tlv(3, &[0, 120]));
        assert!(parse_lldp(&bare, "eth0").is_none());
    }

    // --- VTP / DTP / passive aggregation ----------------------------------------------------

    fn vtp_vlan_entry(id: u16, vlan_type: u8, name: &str) -> Vec<u8> {
        let padded = name.len().div_ceil(4) * 4;
        let info_len = 12 + padded;
        let mut e = vec![
            u8::try_from(info_len).unwrap(),
            0,
            vlan_type,
            u8::try_from(name.len()).unwrap(),
        ];
        e.extend_from_slice(&id.to_be_bytes());
        e.extend_from_slice(&1500u16.to_be_bytes());
        e.extend_from_slice(&(100_000 + u32::from(id)).to_be_bytes());
        e.extend_from_slice(name.as_bytes());
        e.resize(info_len, 0);
        e
    }

    fn vtp_subset_frame() -> Vec<u8> {
        let mut body = vec![2, 2, 1, 6];
        let mut domain = b"CAMPUS".to_vec();
        domain.resize(32, 0);
        body.extend_from_slice(&domain);
        body.extend_from_slice(&42u32.to_be_bytes());
        body.extend(vtp_vlan_entry(10, 1, "USERS"));
        body.extend(vtp_vlan_entry(20, 1, "VOICE-PHONES"));
        body.extend(vtp_vlan_entry(1002, 2, "fddi-default"));
        snap_frame(MAC_B, CDP_MULTICAST, None, SNAP_PID_VTP, &body)
    }

    #[test]
    fn parses_vtp_subset_advert() {
        let v = parse_vtp(&vtp_subset_frame()).unwrap();
        assert_eq!((v.version, v.code, v.revision), (2, 2, 42));
        assert_eq!(v.domain, "CAMPUS");
        assert_eq!(
            v.vlans,
            vec![(10, "USERS".to_string()), (20, "VOICE-PHONES".to_string())]
        );
        assert!(parse_cdp(&vtp_subset_frame(), "en0").is_none());
        let f = vtp_subset_frame();
        for len in 0..f.len() {
            let _ = parse_vtp(&f[..len]);
        }
    }

    #[test]
    fn detects_dtp() {
        let dtp = snap_frame(MAC_B, CDP_MULTICAST, None, SNAP_PID_DTP, &[1, 0, 1, 0, 5]);
        assert!(is_dtp(&dtp));
        assert!(!is_dtp(&cdp_frame(None)));
    }

    #[test]
    fn passive_aggregator_collects_vlans_and_neighbors() {
        let mut agg = PassiveAggregator::new("en0");
        let tagged = arp_reply_frame(&[(ETHERTYPE_VLAN, 30)]);
        let ev = agg.ingest(&tagged);
        assert!(matches!(&ev[..], [ScanEvent::Vlan(v)] if v.id == 30));
        assert!(
            agg.ingest(&tagged).is_empty(),
            "repeat sightings are not re-announced"
        );

        let ev = agg.ingest(&cdp_frame(None));
        assert!(ev.iter().any(|e| matches!(e, ScanEvent::Neighbor(_))));
        assert!(ev
            .iter()
            .any(|e| matches!(e, ScanEvent::Vlan(v) if v.id == 100)));
        assert!(agg.ingest(&cdp_frame(None)).is_empty());

        agg.ingest(&vtp_subset_frame());
        let dtp = snap_frame(MAC_B, CDP_MULTICAST, None, SNAP_PID_DTP, &[1]);
        assert!(matches!(&agg.ingest(&dtp)[..], [ScanEvent::Log { .. }]));
        assert!(agg.ingest(&dtp).is_empty());
        agg.ingest(&lldp_frame(Some(30)));

        let res = agg.finish();
        let ids: Vec<u16> = res.vlans.iter().map(|v| v.id).collect();
        assert_eq!(ids, vec![10, 20, 30, 100, 200]);
        let v30 = &res.vlans[2];
        assert_eq!(v30.frames_seen, 3);
        assert_eq!(v30.sources, vec![VlanSource::Tagged8021q]);
        let v10 = &res.vlans[0];
        assert_eq!(v10.name.as_deref(), Some("USERS"));
        assert!(v10.sources.contains(&VlanSource::Cdp) && v10.sources.contains(&VlanSource::Vtp));
        assert_eq!(res.neighbors.len(), 2);
        assert_eq!(res.frames_seen, 8);
    }

    #[test]
    fn passive_listener_ignores_own_tagged_probes() {
        // Our own 802.1Q-tagged ARP probe, as captured on the wire.
        let probe = build_arp_request(
            MAC_A,
            Ipv4Addr::UNSPECIFIED,
            ip4("10.0.0.1"),
            Some(VlanTag::new(777)),
        );
        let mut agg = PassiveAggregator::new("en0").with_own_macs([MAC_A]);
        assert!(agg.ingest(&probe).is_empty());
        assert_eq!(agg.own_frames(), 1);
        // Same frame from another host is a real observation.
        let mut foreign = probe.clone();
        foreign[6..12].copy_from_slice(&MAC_B);
        assert!(matches!(&agg.ingest(&foreign)[..], [ScanEvent::Vlan(v)] if v.id == 777));
        let res = agg.finish();
        assert_eq!(res.frames_seen, 1);
        assert_eq!(res.vlans[0].frames_seen, 1);

        // Unknown / masked interface MAC: the placeholder and every MAC registered by an
        // active scan are still filtered.
        let masked = build_arp_request(
            MASKED_MAC,
            Ipv4Addr::UNSPECIFIED,
            ip4("10.0.0.1"),
            Some(VlanTag::new(778)),
        );
        let mut agg = PassiveAggregator::new("en0");
        assert!(agg.ingest(&masked).is_empty());
        let tx_mac = [0x02, 0x5e, 0x10, 0x00, 0x00, 0x99];
        let probe = build_arp_request(
            tx_mac,
            Ipv4Addr::UNSPECIFIED,
            ip4("10.0.0.1"),
            Some(VlanTag::new(779)),
        );
        assert!(!agg.ingest(&probe).is_empty(), "not registered yet");
        register_transmit_mac(tx_mac);
        let probe = build_arp_request(
            tx_mac,
            Ipv4Addr::UNSPECIFIED,
            ip4("10.0.0.1"),
            Some(VlanTag::new(780)),
        );
        assert!(agg.ingest(&probe).is_empty());
        assert!(agg.finish().vlans.iter().all(|v| v.id == 779));
    }

    #[test]
    fn vlan_frame_counts_are_exact() {
        let mut agg = PassiveAggregator::new("en0");
        let tagged = arp_reply_frame(&[(ETHERTYPE_VLAN, 30)]);
        let mut events = Vec::new();
        for _ in 0..6 {
            events.extend(agg.ingest(&tagged));
        }
        let res = agg.finish();
        assert_eq!(res.vlans[0].frames_seen, 6);
        // Folding the live snapshot(s) and the final snapshot reports the true count.
        let mut v = match &events[..] {
            [ScanEvent::Vlan(v)] => v.clone(),
            other => panic!("{other:?}"),
        };
        v.merge_snapshot(&res.vlans[0]);
        v.merge_snapshot(&res.vlans[0]);
        assert_eq!(v.frames_seen, 6);
    }

    #[test]
    fn passive_state_is_bounded() {
        let mut agg = PassiveAggregator::new("en0");
        let mut warned = 0;
        for i in 0..(MAX_NEIGHBORS + 50) {
            let mut body = vec![2, 180, 0, 0];
            body.extend(cdp_tlv(0x0001, format!("spoof-{i}").as_bytes()));
            let f = snap_frame(MAC_B, CDP_MULTICAST, None, SNAP_PID_CDP, &body);
            for ev in agg.ingest(&f) {
                if matches!(ev, ScanEvent::Log { .. }) {
                    warned += 1;
                }
            }
        }
        assert_eq!(warned, 1);
        assert_eq!(agg.neighbors.len(), MAX_NEIGHBORS);

        // DTP / VTP log lines are capped (sets stay bounded too).
        let mut logs = 0;
        for i in 0..(MAX_PROTOCOL_LOGS * 3) {
            let src = [0x00, 0x11, 0x00, 0x00, (i >> 8) as u8, i as u8];
            let dtp = snap_frame(src, CDP_MULTICAST, None, SNAP_PID_DTP, &[1]);
            logs += agg.ingest(&dtp).len();
        }
        assert_eq!(logs, MAX_PROTOCOL_LOGS + 1);
        assert_eq!(agg.dtp_sources.len(), MAX_PROTOCOL_LOGS * 3);
        let mut logs = 0;
        for i in 0..(MAX_PROTOCOL_LOGS * 2) {
            let mut body = vec![2, 1, 1, 4];
            let mut domain = format!("D{i:03}").into_bytes();
            domain.resize(32, 0);
            body.extend_from_slice(&domain);
            body.extend_from_slice(&1u32.to_be_bytes());
            let vtp = snap_frame(MAC_B, CDP_MULTICAST, None, SNAP_PID_VTP, &body);
            logs += agg.ingest(&vtp).len();
        }
        assert_eq!(logs, MAX_PROTOCOL_LOGS + 1);
    }

    #[test]
    fn changed_neighbors_are_reannounced_with_rate_limit() {
        let mut agg = PassiveAggregator::new("en0");
        let base = cdp_frame(None);
        assert!(agg
            .ingest_at(&base, 1_000)
            .iter()
            .any(|e| matches!(e, ScanEvent::Neighbor(_))));
        // Same key (device + port), new platform string.
        let mut body = vec![2, 180, 0, 0];
        body.extend(cdp_tlv(0x0001, b"CORE-SW01.example.com"));
        body.extend(cdp_tlv(0x0003, b"GigabitEthernet1/0/24"));
        body.extend(cdp_tlv(0x0006, b"cisco C9300-24P"));
        let changed = snap_frame(MAC_B, CDP_MULTICAST, None, SNAP_PID_CDP, &body);
        let neighbor_events = |evs: Vec<ScanEvent>| {
            evs.into_iter()
                .filter(|e| matches!(e, ScanEvent::Neighbor(_)))
                .count()
        };
        assert_eq!(
            neighbor_events(agg.ingest_at(&changed, 2_000)),
            0,
            "rate limited"
        );
        assert_eq!(neighbor_events(agg.ingest_at(&changed, 3_000)), 0);
        assert_eq!(
            neighbor_events(agg.ingest_at(&changed, 1_000 + NEIGHBOR_UPDATE_INTERVAL_MS)),
            1,
            "pending change announced once the interval passed"
        );
        assert_eq!(
            neighbor_events(agg.ingest_at(&changed, 99_000)),
            0,
            "unchanged"
        );
        let res = agg.finish();
        assert_eq!(
            res.neighbors[0].platform.as_deref(),
            Some("cisco C9300-24P")
        );
    }

    #[test]
    fn cdp_strings_cannot_inject_terminal_escapes() {
        let mut body = vec![2, 180, 0, 0];
        body.extend(cdp_tlv(0x0001, b"\x1b]0;pwned\x07\x1b[2Jsw01"));
        body.extend(cdp_tlv(0x0003, b"Gi1/0/1\x1b[31m"));
        body.extend(cdp_tlv(0x0006, &[b'x'; 900]));
        let f = snap_frame(MAC_B, CDP_MULTICAST, None, SNAP_PID_CDP, &body);
        let n = parse_cdp(&f, "en0").unwrap();
        assert_eq!(n.device_id, "]0;pwned[2Jsw01");
        assert_eq!(n.port_id.as_deref(), Some("Gi1/0/1[31m"));
        assert_eq!(
            n.platform.as_deref().map(str::len),
            Some(crate::models::MAX_TEXT_LEN)
        );
        for s in [&n.device_id, n.port_id.as_ref().unwrap()] {
            assert!(!s.chars().any(char::is_control), "{s:?}");
        }
        // LLDP system name and VTP VLAN names go through the same decoder.
        let mut f = LLDP_MULTICAST.to_vec();
        f.extend_from_slice(&MAC_B);
        f.extend_from_slice(&ETHERTYPE_LLDP.to_be_bytes());
        f.extend(lldp_tlv(1, b"\x07chassis\x1b[0m"));
        f.extend(lldp_tlv(5, b"name\xc2\x9b\x07")); // U+009B (C1 CSI) + BEL
        let n = parse_lldp(&f, "en0").unwrap();
        assert!(!n.device_id.chars().any(char::is_control));
        assert_eq!(n.system_name.as_deref(), Some("name"));
    }

    #[test]
    fn management_addresses_are_capped() {
        let ips: Vec<[u8; 4]> = (0..60).map(|i| [10, 0, 0, i]).collect();
        let mut body = vec![2, 180, 0, 0];
        body.extend(cdp_tlv(0x0001, b"sw"));
        body.extend(cdp_tlv(0x0002, &cdp_ipv4_addrs(&ips)));
        body.extend(cdp_tlv(0x0016, &cdp_ipv4_addrs(&ips)));
        let n = parse_cdp(
            &snap_frame(MAC_B, CDP_MULTICAST, None, SNAP_PID_CDP, &body),
            "en0",
        )
        .unwrap();
        assert_eq!(n.management_addrs.len(), MAX_MGMT_ADDRS);
    }

    // --- transmit back-pressure -------------------------------------------------------------

    /// Fails `fail_first` sends with `errno`, then accepts everything.
    struct MockSender {
        fail_first: usize,
        errno: i32,
        calls: usize,
        sent: usize,
    }

    impl DataLinkSender for MockSender {
        fn build_and_send(
            &mut self,
            _num_packets: usize,
            _packet_size: usize,
            _func: &mut dyn FnMut(&mut [u8]),
        ) -> Option<io::Result<()>> {
            None
        }

        fn send_to(
            &mut self,
            _packet: &[u8],
            _dst: Option<datalink::NetworkInterface>,
        ) -> Option<io::Result<()>> {
            self.calls += 1;
            if self.calls <= self.fail_first {
                Some(Err(io::Error::from_raw_os_error(self.errno)))
            } else {
                self.sent += 1;
                Some(Ok(()))
            }
        }
    }

    #[test]
    fn enobufs_is_backpressure_not_failure() {
        let cancel = CancellationToken::new();
        let mut pacer = Pacer::new(10_000);
        let base = pacer.interval;
        let mut s = MockSender {
            fail_first: 5,
            errno: libc::ENOBUFS,
            calls: 0,
            sent: 0,
        };
        assert_eq!(
            send_frame(&mut s, &[0; 60], &mut pacer, &cancel).unwrap(),
            SendOutcome::Sent
        );
        assert_eq!((s.calls, s.sent), (6, 1));
        assert!(pacer.interval > base, "rate lowered under back-pressure");
        for _ in 0..(PACE_RECOVERY_SENDS * 16) {
            send_frame(&mut s, &[0; 60], &mut pacer, &cancel).unwrap();
        }
        assert_eq!(pacer.interval, base, "rate recovers");

        // EAGAIN (Windows: WSAEWOULDBLOCK) behaves the same.
        let mut s = MockSender {
            fail_first: 2,
            errno: if cfg!(windows) { 10035 } else { libc::EAGAIN },
            calls: 0,
            sent: 0,
        };
        assert_eq!(
            send_frame(&mut s, &[0; 60], &mut pacer, &cancel).unwrap(),
            SendOutcome::Sent
        );

        // A queue that never drains: the frame is dropped, not an error.
        let mut s = MockSender {
            fail_first: usize::MAX,
            errno: libc::ENOBUFS,
            calls: 0,
            sent: 0,
        };
        let started = Instant::now();
        assert_eq!(
            send_frame(&mut s, &[0; 60], &mut pacer, &cancel).unwrap(),
            SendOutcome::Dropped
        );
        // The budget counts the nominal back-off steps; the bound only proves the drop ends
        // (generous: loaded CI runners overshoot every one of those sleeps).
        assert!(started.elapsed() < BACKOFF_BUDGET * 20);
        assert_eq!(pacer.interval, MAX_PACE_INTERVAL);

        // Cancellation ends the back-off immediately.
        cancel.cancel();
        let started = Instant::now();
        assert_eq!(
            send_frame(&mut s, &[0; 60], &mut pacer, &cancel).unwrap(),
            SendOutcome::Dropped
        );
        assert!(started.elapsed() < Duration::from_millis(100));

        // Real errors still fail.
        let mut s = MockSender {
            fail_first: 1,
            errno: libc::ENETDOWN,
            calls: 0,
            sent: 0,
        };
        let cancel = CancellationToken::new();
        assert!(send_frame(&mut s, &[0; 60], &mut pacer, &cancel).is_err());
    }

    // --- IPv6 discovery ---------------------------------------------------------------------

    fn v6_iface() -> InterfaceInfo {
        InterfaceInfo {
            name: "en0".into(),
            index: 4,
            description: None,
            mac: Some("00:11:22:33:44:55".into()),
            addrs: vec![
                IfAddr {
                    ip: "10.0.0.5".parse().unwrap(),
                    prefix: 24,
                },
                IfAddr {
                    ip: "fe80::211:22ff:fe33:4455".parse().unwrap(),
                    prefix: 64,
                },
                IfAddr {
                    ip: "2001:db8:1::5".parse().unwrap(),
                    prefix: 64,
                },
                IfAddr {
                    ip: "fd12:3456::5".parse().unwrap(),
                    prefix: 64,
                },
            ],
            is_up: true,
            kind: InterfaceKind::Ethernet,
            vlan_id: None,
            parent: None,
            is_default: true,
        }
    }

    #[test]
    fn ipv6_echo_is_sent_from_every_address_on_the_native_network() {
        let plan = Ipv6Plan::for_iface(&v6_iface()).unwrap();
        let ll: Ipv6Addr = "fe80::211:22ff:fe33:4455".parse().unwrap();
        assert_eq!(
            plan.echo_sources(None),
            vec![
                ll,
                "2001:db8:1::5".parse().unwrap(),
                "fd12:3456::5".parse().unwrap()
            ]
        );
        // Our routable prefixes do not exist on foreign VLANs.
        assert_eq!(plan.echo_sources(Some(VlanTag::new(20))), vec![ll]);
        assert_eq!(plan.ns_source(), Some(ll));
        for src in plan.echo_sources(None) {
            let f = build_icmpv6_echo_multicast(MAC_A, src, None);
            assert_eq!(ipv6_at(&f, 22).unwrap(), src);
            assert!(checksum_ok(&f, 14));
        }
        // Global-only interface still gets an echo.
        let mut iface = v6_iface();
        iface
            .addrs
            .retain(|a| !matches!(a.ip, IpAddr::V6(v) if is_link_local_v6(v)));
        let plan = Ipv6Plan::for_iface(&iface).unwrap();
        assert_eq!(plan.echo_sources(None).len(), 2);
        assert!(plan.echo_sources(Some(VlanTag::new(5))).is_empty());
        iface.addrs.truncate(1);
        assert!(Ipv6Plan::for_iface(&iface).is_none());
    }

    #[test]
    fn eui64_solicitation_targets() {
        let mac = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
        assert_eq!(
            eui64_address("2001:db8:1::5".parse().unwrap(), mac),
            "2001:db8:1:0:21a:2bff:fe3c:4d5e"
                .parse::<Ipv6Addr>()
                .unwrap()
        );
        let plan = Ipv6Plan::for_iface(&v6_iface()).unwrap();
        let targets = plan.eui64_candidates(mac);
        assert_eq!(targets.len(), 2);
        let ns = build_neighbor_solicitation(MAC_A, plan.ns_source().unwrap(), targets[0], None);
        assert_eq!(ipv6_at(&ns, 62).unwrap(), targets[0]);
        assert!(checksum_ok(&ns, 14));
    }

    #[test]
    fn icmpv6_echo_replies_need_our_ident_and_an_on_link_source() {
        let iface = v6_iface();
        let reply_from = |src: Ipv6Addr, ident: u16, tag: Option<VlanTag>| {
            let mut f = build_icmpv6_echo_multicast(MAC_B, src, tag);
            let off = if tag.is_some() { 58 } else { 54 };
            f[off] = ICMPV6_ECHO_REPLY;
            f[off + 4..off + 6].copy_from_slice(&ident.to_be_bytes());
            f
        };
        let on_link: Ipv6Addr = "2001:db8:1::77".parse().unwrap();
        let o = parse_icmpv6_discovery(&reply_from(on_link, ECHO_IDENT, None)).unwrap();
        assert!(accept_ipv6_observation(&o, &iface));
        // Someone else's echo reply (wrong identifier) is not a discovery.
        assert!(parse_icmpv6_discovery(&reply_from(on_link, 0x1234, None)).is_none());
        // Off-link / spoofed sources are rejected.
        let o = parse_icmpv6_discovery(&reply_from("2600::1".parse().unwrap(), ECHO_IDENT, None))
            .unwrap();
        assert!(!accept_ipv6_observation(&o, &iface));
        // On a probed foreign VLAN only link-local replies count.
        let tag = Some(VlanTag::new(20));
        let o = parse_icmpv6_discovery(&reply_from("fe80::9".parse().unwrap(), ECHO_IDENT, tag))
            .unwrap();
        assert!(accept_ipv6_observation(&o, &iface));
        let o = parse_icmpv6_discovery(&reply_from(on_link, ECHO_IDENT, tag)).unwrap();
        assert!(!accept_ipv6_observation(&o, &iface));
    }

    // --- interface helpers --------------------------------------------------------------------

    #[test]
    fn os_vlan_parsers() {
        let proc = "VLAN Dev name\t | VLAN ID\nName-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\n\
                    eth0.10        | 10  | eth0\nvoice          | 200  | bond0\n";
        assert_eq!(
            parse_proc_vlan_config(proc),
            vec![
                ("eth0.10".into(), 10, "eth0".into()),
                ("voice".into(), 200, "bond0".into())
            ]
        );
        let ifc = "vlan0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
                   \tether 00:11:22:33:44:55\n\tvlan: 100 parent interface: en0\n";
        assert_eq!(parse_ifconfig_vlan(ifc), Some((100, Some("en0".into()))));
        assert_eq!(
            parse_ifconfig_vlan("\tvlan: 0 parent interface: <none>\n"),
            None
        );
        assert_eq!(
            parse_ifconfig_vlan("\tvlan: 7 parent interface: <none>\n"),
            Some((7, None))
        );
        assert_eq!(parse_dotted_vlan_name("en0.100"), Some(("en0".into(), 100)));
        assert_eq!(
            parse_dotted_vlan_name("wlan0.20"),
            Some(("wlan0".into(), 20))
        );
        assert_eq!(parse_dotted_vlan_name("en0.5000"), None);
        assert_eq!(parse_dotted_vlan_name("en0"), None);
        assert_eq!(parse_dotted_vlan_name(".10"), None);
    }

    #[test]
    fn parses_ifconfig_all() {
        let text = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\
                    \tinet 127.0.0.1 netmask 0xff000000\n\
                    en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
                    \tether 8a:1c:6a:c5:76:2d\n\
                    \tinet 172.20.10.2 netmask 0xfffffff0 broadcast 172.20.10.15\n\
                    vlan0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
                    \tether 8a:1c:6a:c5:76:2d\n\
                    \tvlan: 100 parent interface: en0\n";
        let info = parse_ifconfig_all(text);
        assert_eq!(
            info.ethers.get("en0"),
            Some(&[0x8a, 0x1c, 0x6a, 0xc5, 0x76, 0x2d])
        );
        assert!(!info.ethers.contains_key("lo0"));
        assert_eq!(
            info.vlans.get("vlan0"),
            Some(&(100, Some("en0".to_string())))
        );
        assert_eq!(info.vlans.len(), 1);
        assert!(!is_real_mac(&MASKED_MAC) && is_real_mac(&MAC_A));
    }

    #[test]
    fn route_and_hardware_port_parsers() {
        let route = "   route to: default\ndestination: default\n       mask: default\n    \
                     gateway: 192.168.1.1\n  interface: en7\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n";
        assert_eq!(parse_route_get(route).as_deref(), Some("en7"));
        let proc =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                    wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
                    eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                    eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(parse_proc_net_route(proc).as_deref(), Some("eth0"));
        // Gateways: the lowest-metric default route, little-endian hex on Linux.
        assert_eq!(
            parse_route_get_gateway(route),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(
            parse_proc_net_route_gateway(proc),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(parse_route_get_gateway("interface: en0\n"), None);
        let ns = "\nHardware Port: Ethernet\nDevice: en0\nEthernet Address: 00:11:22:33:44:55\n\n\
                  Hardware Port: Wi-Fi\nDevice: en1\nEthernet Address: 00:11:22:33:44:66\n";
        let ports = parse_networksetup_ports(ns);
        assert_eq!(ports.get("en1").map(String::as_str), Some("Wi-Fi"));
        #[cfg(not(windows))]
        assert!(is_wireless("en1", ports.get("en1").map(String::as_str)));
    }

    /// `route print -4 0.0.0.0` from Windows 11 (English), with a second, higher-metric
    /// default route (VPN) and a persistent route.
    const ROUTE_PRINT_EN: &str = "\
===========================================================================
Interface List
 18...00 15 5d 2a 81 07 ......Hyper-V Virtual Ethernet Adapter
  7...a4 bb 6d 11 22 33 ......Intel(R) Ethernet Connection (7) I219-LM
 23...........................WireGuard Tunnel
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.23     25
          0.0.0.0          0.0.0.0         On-link        10.66.0.2      5281
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0      192.168.1.254  Default
===========================================================================
";

    #[test]
    fn windows_route_print_default_route() {
        assert_eq!(
            parse_route_print_default(ROUTE_PRINT_EN),
            Some(WindowsDefaultRoute {
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                interface: Ipv4Addr::new(192, 168, 1, 23),
                metric: 25,
            })
        );
        // German: localized headers and a two-word "On-link"; only the on-link route exists.
        let de = "Aktive Routen:\n     Netzwerkziel    Netzwerkmaske          Gateway    Schnittstelle Metrik\n\
                  \x20         0.0.0.0          0.0.0.0   Auf Verbindung      172.20.10.4     35\n\
                  Ständige Routen:\n  Keine\n";
        assert_eq!(
            parse_route_print_default(de),
            Some(WindowsDefaultRoute {
                gateway: None,
                interface: Ipv4Addr::new(172, 20, 10, 4),
                metric: 35,
            })
        );
        // No default route at all (only the persistent table), or garbage.
        let none = "Active Routes:\n  None\nPersistent Routes:\n  0.0.0.0  0.0.0.0  10.0.0.1  1\n";
        assert_eq!(parse_route_print_default(none), None);
        assert_eq!(parse_route_print_default(""), None);
        assert_eq!(
            parse_route_print_default("0.0.0.0 0.0.0.0 10.0.0.1 not-an-ip 25\n"),
            None
        );
    }

    #[test]
    fn windows_adapter_classification() {
        use InterfaceKind::*;
        let c = classify_windows_adapter;
        assert_eq!(
            c(
                6,
                "Intel(R) Ethernet Connection (7) I219-LM",
                "Ethernet",
                false
            ),
            Ethernet
        );
        assert_eq!(c(71, "Intel(R) Wi-Fi 6 AX201 160MHz", "Wi-Fi", false), Wifi);
        assert_eq!(
            c(
                71,
                "Microsoft Wi-Fi Direct Virtual Adapter #2",
                "Local Area Connection* 2",
                false
            ),
            Virtual
        );
        assert_eq!(
            c(
                24,
                "Software Loopback Interface 1",
                "Loopback Pseudo-Interface 1",
                false
            ),
            Loopback
        );
        assert_eq!(
            c(
                6,
                "Hyper-V Virtual Ethernet Adapter",
                "vEthernet (WSL)",
                false
            ),
            Bridge
        );
        assert_eq!(c(53, "WireGuard Tunnel", "wg0", false), Vpn);
        assert_eq!(c(6, "TAP-Windows Adapter V9", "OpenVPN TAP", false), Vpn);
        assert_eq!(
            c(131, "Teredo Tunneling Pseudo-Interface", "Teredo", false),
            Virtual
        );
        assert_eq!(
            c(
                6,
                "VirtualBox Host-Only Ethernet Adapter",
                "Ethernet 3",
                false
            ),
            Virtual
        );
        assert_eq!(
            c(
                6,
                "Bluetooth Device (Personal Area Network)",
                "Bluetooth Network Connection",
                false
            ),
            Virtual
        );
        assert_eq!(
            c(6, "Intel(R) Ethernet Connection I219-LM", "Ethernet", true),
            Vlan
        );
        assert_eq!(
            c(243, "Generic Mobile Broadband Adapter", "Cellular", false),
            Unknown
        );
    }

    /// On Windows interfaces carry connection names, a description and real MACs; nothing in
    /// the listing needs Npcap.
    #[cfg(windows)]
    #[test]
    fn windows_interfaces_use_connection_names() {
        let all = list_interfaces();
        assert!(!all.is_empty());
        assert!(
            all.iter().all(|i| !i.name.starts_with(r"\Device\")),
            "{all:?}"
        );
        assert!(
            all.iter().any(|i| i.kind == InterfaceKind::Loopback),
            "{all:?}"
        );
        assert!(!macs_hidden(&all));
        let first = &all[0].name;
        let upper = first.to_uppercase();
        assert_eq!(&select_interface(&all, Some(&upper)).unwrap().name, first);
    }

    /// Without Npcap, raw capture fails cleanly as "raw access unavailable" (the engine then
    /// falls back to the ICMP sweep) instead of crashing on a missing DLL.
    #[cfg(windows)]
    #[test]
    fn windows_capture_without_npcap_is_a_clean_l2_error() {
        let all = list_interfaces();
        let name = &all[0].name;
        match crate::platform::capture_driver_status() {
            Err(_) => {
                let e = capture_device(name).unwrap_err();
                assert!(L2Error::is_l2_unavailable(&e), "{e:#}");
                assert!(format!("{e:#}").contains("Npcap"), "{e:#}");
            }
            Ok(()) => assert!(capture_device(name).unwrap().starts_with(r"\Device\NPF_")),
        }
    }

    #[test]
    fn interface_classification() {
        use InterfaceKind::*;
        assert_eq!(classify_interface("lo0", true, false, false), Loopback);
        assert_eq!(classify_interface("en0", false, true, false), Wifi);
        assert_eq!(classify_interface("en0.100", false, false, true), Vlan);
        assert_eq!(classify_interface("en5", false, false, false), Ethernet);
        assert_eq!(classify_interface("enp3s0", false, false, false), Ethernet);
        assert_eq!(classify_interface("utun3", false, false, false), Vpn);
        assert_eq!(classify_interface("wg0", false, false, false), Vpn);
        assert_eq!(classify_interface("bridge100", false, false, false), Bridge);
        assert_eq!(classify_interface("br0", false, false, false), Bridge);
        assert_eq!(classify_interface("br-1a2b3c", false, false, false), Bridge);
        assert_eq!(classify_interface("docker0", false, false, false), Bridge);
        assert_eq!(classify_interface("veth12ab", false, false, false), Virtual);
        assert_eq!(classify_interface("awdl0", false, false, false), Virtual);
        assert_eq!(classify_interface("llw0", false, false, false), Virtual);
        assert_eq!(classify_interface("vmnet8", false, false, false), Virtual);
        assert_eq!(classify_interface("ap1", false, false, false), Virtual);
        assert_eq!(classify_interface("nan0", false, false, false), Virtual);
        assert_eq!(classify_interface("xyz", false, false, false), Unknown);
    }

    fn iface(name: &str, addr: &str, prefix: u8) -> InterfaceInfo {
        InterfaceInfo {
            name: name.into(),
            index: 1,
            description: None,
            mac: Some("00:11:22:33:44:55".into()),
            addrs: vec![IfAddr {
                ip: addr.parse().unwrap(),
                prefix,
            }],
            is_up: true,
            kind: InterfaceKind::Ethernet,
            vlan_id: None,
            parent: None,
            is_default: false,
        }
    }

    #[test]
    fn interface_selection() {
        let mut lo = iface("lo0", "127.0.0.1", 8);
        lo.kind = InterfaceKind::Loopback;
        let mut wifi = iface("en1", "192.168.1.20", 24);
        wifi.kind = InterfaceKind::Wifi;
        let eth = iface("en0", "10.0.0.5", 24);
        let all = vec![lo, wifi, eth];
        assert_eq!(select_interface(&all, None).unwrap().name, "en0");
        assert_eq!(select_interface(&all, Some("en1")).unwrap().name, "en1");
        let err = select_interface(&all, Some("nope")).unwrap_err();
        assert!(err.to_string().contains("available: lo0, en1, en0"));
    }

    #[test]
    fn target_splitting() {
        let subnet: Ipv4Range = "10.0.0.0/24".parse().unwrap();
        let targets = vec![
            "9.255.255.250-10.0.1.5".parse().unwrap(),
            "10.0.0.10-20".parse().unwrap(),
        ];
        let (local, routed) = split_targets(&targets, Some(&subnet));
        assert_eq!(
            local.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["10.0.0.1-10.0.0.254", "10.0.0.10-10.0.0.20"]
        );
        assert_eq!(
            routed.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["9.255.255.250-10.0.0.0", "10.0.0.255-10.0.1.5"]
        );
        let (l, r) = split_targets(&targets, None);
        assert!(l.is_empty());
        assert_eq!(r, targets);
    }

    #[test]
    fn vlan_attribution() {
        let g = |tag: Option<u16>, report: Option<u16>| ProbeGroup {
            tag: tag.map(VlanTag::new),
            report_vlan: report,
            sender_ip: Ipv4Addr::UNSPECIFIED,
            targets: vec![],
        };
        assert_eq!(
            attribute_vlan(&[g(None, None), g(Some(10), Some(10))], Some(10)),
            Some(10)
        );
        assert_eq!(
            attribute_vlan(&[g(None, None), g(Some(10), Some(10))], None),
            None
        );
        assert_eq!(attribute_vlan(&[g(Some(10), Some(10))], None), Some(10));
        assert_eq!(
            attribute_vlan(&[g(Some(10), Some(10)), g(Some(20), Some(20))], None),
            None
        );
        assert_eq!(attribute_vlan(&[g(None, Some(100))], None), Some(100));
    }
}
