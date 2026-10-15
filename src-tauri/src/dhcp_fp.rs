//! Passive DHCP fingerprinting (UDP 67/68).
//!
//! Captures inbound DHCP `DISCOVER` / `REQUEST` / `INFORM` packets (BPF filter
//! `udp and (port 67 or port 68)`), parses their options with a bounds-checked parser (option
//! 53 message type, 55 parameter request list, 60 vendor class, 12 hostname, 61 client id, 77
//! user class, 57 max message size, 50 requested IP, 82 relay agent), attributes each to the
//! client MAC / IP, and matches the option-55 list plus vendor-class / hostname hints against
//! an embedded signature table (`data/dhcp_fingerprints.tsv`).
//!
//! The signatures are **best-effort heuristics with a confidence level, not authoritative**
//! (the Fingerbank API is deliberately not used). VLAN-tagged frames are handled via
//! [`arp_vlan::parse_frame`]. Capture needs raw packet access (root / BPF) like the other
//! sniffers; the pure parser and matcher are unit tested with hand-built packets.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr},
    sync::OnceLock,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;

use crate::{
    arp_vlan::{self, ETHERTYPE_IPV4},
    models::{now_ms, sanitize_text, Device, DhcpFingerprint, DiscoverySource, ScanEvent},
};

/// BOOTP magic cookie that precedes the DHCP options.
const DHCP_MAGIC: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
const IPPROTO_UDP: u8 = 17;
/// Longest parameter-request list kept (hostile-input bound; real lists are < 64).
const MAX_PARAM_LIST: usize = 64;
/// Longest option value kept.
const MAX_OPTION_VALUE: usize = 255;
/// Distinct clients a capture run reports (bounds a hostile flood).
const MAX_CLIENTS: usize = 8192;
/// Capture poll interval (bounds cancellation latency), ms.
const CAPTURE_POLL_MS: i32 = 100;

// ---------------------------------------------------------------------------------------------
// Parsing (pure, bounds-checked)
// ---------------------------------------------------------------------------------------------

/// A parsed DHCP client packet (only the fields we fingerprint on).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DhcpPacket {
    /// Option 53 message type (1 DISCOVER, 3 REQUEST, 8 INFORM, …).
    pub msg_type: Option<u8>,
    /// Client hardware address (`chaddr`, 6 octets for Ethernet).
    pub mac: Option<[u8; 6]>,
    /// Client IP: `ciaddr` if set, else option 50 (requested IP).
    pub client_ip: Option<Ipv4Addr>,
    /// Option 55 parameter request list.
    pub param_list: Vec<u8>,
    /// Option 60 vendor class identifier.
    pub vendor_class: Option<String>,
    /// Option 12 host name.
    pub hostname: Option<String>,
    /// Option 61 client identifier (rendered as text/hex).
    pub client_id: Option<String>,
    /// Option 77 user class.
    pub user_class: Option<String>,
    /// Option 57 maximum DHCP message size.
    pub max_message_size: Option<u16>,
    /// Option 82 relay agent info present.
    pub relay_agent: bool,
    /// `giaddr` relay IP, when non-zero.
    pub giaddr: Option<Ipv4Addr>,
}

fn be16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off.checked_add(2)?)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

fn ipv4_at(b: &[u8], off: usize) -> Option<Ipv4Addr> {
    let o: [u8; 4] = b.get(off..off.checked_add(4)?)?.try_into().ok()?;
    Some(Ipv4Addr::from(o))
}

/// Extract the DHCP payload (BOOTP bytes after the UDP header) from an Ethernet frame, honouring
/// 802.1Q tags. Returns `(dhcp_bytes, vlan_id)` for a UDP 67/68 datagram, else `None`.
pub fn dhcp_payload(frame: &[u8]) -> Option<(&[u8], Option<u16>)> {
    let eth = arp_vlan::parse_frame(frame)?;
    if eth.ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = eth.payload;
    // IPv4 header: version/IHL, ... protocol at offset 9.
    if (ip.first()? >> 4) != 4 {
        return None;
    }
    let ihl = usize::from(ip.first()? & 0x0f) * 4;
    if ihl < 20 || *ip.get(9)? != IPPROTO_UDP {
        return None;
    }
    let udp = ip.get(ihl..)?;
    let sport = be16(udp, 0)?;
    let dport = be16(udp, 2)?;
    if !matches!((sport, dport), (67, 68) | (68, 67) | (67, 67) | (68, 68)) {
        return None;
    }
    let dhcp = udp.get(8..)?;
    Some((dhcp, eth.vlan_id()))
}

/// Parse a BOOTP/DHCP message. Bounds-checked throughout; returns `None` when it is not a DHCP
/// message (no magic cookie) or is truncated past the fixed header.
pub fn parse_dhcp(dhcp: &[u8]) -> Option<DhcpPacket> {
    // Fixed BOOTP header is 236 bytes, then the 4-byte magic cookie, then options.
    if dhcp.len() < 240 || dhcp[236..240] != DHCP_MAGIC {
        return None;
    }
    let hlen = usize::from(dhcp[2]).min(6);
    let mut pkt = DhcpPacket::default();
    if hlen == 6 {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&dhcp[28..34]);
        if mac != [0u8; 6] {
            pkt.mac = Some(mac);
        }
    }
    // ciaddr (offset 12) and giaddr (offset 24).
    if let Some(ci) = ipv4_at(dhcp, 12).filter(|ip| !ip.is_unspecified()) {
        pkt.client_ip = Some(ci);
    }
    if let Some(gi) = ipv4_at(dhcp, 24).filter(|ip| !ip.is_unspecified()) {
        pkt.giaddr = Some(gi);
    }

    // Options (TLV from offset 240; 0 = pad, 255 = end).
    let mut off = 240;
    let mut requested_ip = None;
    while let Some(&code) = dhcp.get(off) {
        match code {
            0 => {
                off += 1;
                continue;
            }
            255 => break,
            _ => {}
        }
        let Some(&len) = dhcp.get(off + 1) else { break };
        let len = usize::from(len);
        let Some(value) = dhcp.get(off + 2..off + 2 + len) else {
            break;
        };
        off += 2 + len;
        match code {
            53 => pkt.msg_type = value.first().copied(),
            55 => {
                pkt.param_list = value.iter().take(MAX_PARAM_LIST).copied().collect();
            }
            60 => pkt.vendor_class = opt_text(value),
            12 => pkt.hostname = opt_text(value),
            61 => pkt.client_id = render_client_id(value),
            77 => pkt.user_class = opt_text(value),
            57 => pkt.max_message_size = be16(value, 0),
            50 => requested_ip = ipv4_at(value, 0),
            82 => pkt.relay_agent = true,
            _ => {}
        }
    }
    if pkt.client_ip.is_none() {
        pkt.client_ip = requested_ip.filter(|ip| !ip.is_unspecified());
    }
    // A packet with neither a MAC nor a message type is not useful.
    (pkt.mac.is_some() || pkt.msg_type.is_some()).then_some(pkt)
}

fn opt_text(v: &[u8]) -> Option<String> {
    let v = &v[..v.len().min(MAX_OPTION_VALUE)];
    let s = sanitize_text(&String::from_utf8_lossy(v));
    (!s.is_empty()).then_some(s)
}

/// Render an option-61 client identifier: type 1 (Ethernet) as a MAC, else printable text, else
/// hex.
fn render_client_id(v: &[u8]) -> Option<String> {
    if v.len() == 7 && v[0] == 0x01 {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&v[1..7]);
        return Some(crate::models::format_mac(&mac));
    }
    if v.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        return opt_text(v);
    }
    Some(
        v.iter()
            .take(32)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

// ---------------------------------------------------------------------------------------------
// Signature table
// ---------------------------------------------------------------------------------------------

/// The embedded best-effort signature table.
static DHCP_FP_TSV: &str = include_str!("../data/dhcp_fingerprints.tsv");

#[derive(Debug, Clone, PartialEq, Eq)]
enum MatchKind {
    /// Exact option-55 list.
    ParamList(Vec<u8>),
    /// Case-insensitive option-60 substring.
    VendorClass(String),
}

#[derive(Debug, Clone)]
struct Signature {
    kind: MatchKind,
    os: String,
    confidence: String,
}

/// Lazily parse the embedded TSV into signatures.
fn signatures() -> &'static Vec<Signature> {
    static SIGS: OnceLock<Vec<Signature>> = OnceLock::new();
    SIGS.get_or_init(|| parse_signature_table(DHCP_FP_TSV))
}

/// Parse a signature table (comments and blank lines ignored).
fn parse_signature_table(tsv: &str) -> Vec<Signature> {
    let mut out = Vec::new();
    for line in tsv.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 4 {
            continue;
        }
        let (kind, pattern, os, confidence) = (cols[0], cols[1], cols[2], cols[3]);
        let kind = match kind {
            "paramlist" => {
                let list: Vec<u8> = pattern
                    .split(',')
                    .filter_map(|n| n.trim().parse::<u8>().ok())
                    .collect();
                if list.is_empty() {
                    continue;
                }
                MatchKind::ParamList(list)
            }
            "vendorclass" => {
                if pattern.is_empty() {
                    continue;
                }
                MatchKind::VendorClass(pattern.to_ascii_lowercase())
            }
            _ => continue,
        };
        out.push(Signature {
            kind,
            os: os.to_string(),
            confidence: confidence.to_string(),
        });
    }
    out
}

/// Build a [`DhcpFingerprint`] for a parsed packet by matching the signature table and the
/// hostname hints. Confidence order: vendor class (high) > parameter list (table value) >
/// hostname hint (low).
pub fn fingerprint(pkt: &DhcpPacket) -> DhcpFingerprint {
    let mut fp = DhcpFingerprint {
        vendor_class: pkt.vendor_class.clone(),
        hostname: pkt.hostname.clone(),
        param_list: pkt.param_list.clone(),
        ..DhcpFingerprint::default()
    };
    match_signatures(signatures(), pkt, &mut fp);
    fp
}

/// Match `pkt` against `sigs`, filling `fp.os` / `fp.confidence`. Separated from the embedded
/// table so it can be unit tested with a known table.
fn match_signatures(sigs: &[Signature], pkt: &DhcpPacket, fp: &mut DhcpFingerprint) {
    // 1. Vendor class (option 60): the strongest signal, incl. `android-dhcp-NN` versioning.
    if let Some(vc) = &pkt.vendor_class {
        let lower = vc.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("android-dhcp-") {
            let version: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            fp.os = Some(if version.is_empty() {
                "Android".to_string()
            } else {
                format!("Android {version}")
            });
            fp.confidence = Some("high".to_string());
            return;
        }
        for sig in sigs {
            if let MatchKind::VendorClass(pat) = &sig.kind {
                if lower.contains(pat.as_str()) {
                    fp.os = Some(sig.os.clone());
                    fp.confidence = Some(sig.confidence.clone());
                    return;
                }
            }
        }
    }
    // 2. Exact parameter request list.
    if !pkt.param_list.is_empty() {
        for sig in sigs {
            if let MatchKind::ParamList(list) = &sig.kind {
                if list.as_slice() == pkt.param_list.as_slice() {
                    fp.os = Some(sig.os.clone());
                    fp.confidence = Some(sig.confidence.clone());
                    return;
                }
            }
        }
    }
    // 3. Hostname hints (lowest confidence).
    if let Some(os) = hostname_hint(pkt.hostname.as_deref()) {
        fp.os = Some(os);
        fp.confidence = Some("low".to_string());
    }
}

/// Coarse OS guess from a DHCP hostname (option 12).
fn hostname_hint(hostname: Option<&str>) -> Option<String> {
    let h = hostname?.to_ascii_lowercase();
    let os = if h.starts_with("android-") {
        "Android"
    } else if h.starts_with("iphone") {
        "iOS"
    } else if h.starts_with("ipad") {
        "iPadOS"
    } else if h.contains("macbook") || h.contains("-mbp") || h.contains("imac") {
        "macOS"
    } else if h.starts_with("desktop-") || h.starts_with("laptop-") || h.starts_with("win-") {
        "Windows"
    } else if h.contains("ubuntu") || h.contains("debian") || h.contains("fedora") {
        "Linux"
    } else if h.contains("chromebook") {
        "Chrome OS"
    } else {
        return None;
    };
    Some(os.to_string())
}

// ---------------------------------------------------------------------------------------------
// Passive capture
// ---------------------------------------------------------------------------------------------

/// Open a bounded, inbound-only pcap capture on `if_name` with the DHCP BPF filter installed.
fn open_dhcp_capture(if_name: &str) -> Result<pcap::Capture<pcap::Active>> {
    let mut cap = pcap::Capture::from_device(if_name)
        .map_err(|e| anyhow::anyhow!("cannot open {if_name} for DHCP capture: {e}"))?
        .promisc(true)
        .immediate_mode(true)
        .snaplen(2048)
        .buffer_size(2 << 20)
        .timeout(CAPTURE_POLL_MS)
        .open()
        .map_err(|e| map_capture_error(e, if_name))?;
    if cap.get_datalink() != pcap::Linktype::ETHERNET {
        bail!(
            "interface {if_name} has no Ethernet link layer; DHCP fingerprinting is not possible"
        );
    }
    // Inbound only: our own renewals must not be fingerprinted as remote clients.
    if let Err(e) = cap.direction(pcap::Direction::In) {
        tracing::debug!("cannot restrict DHCP capture on {if_name} to inbound: {e}");
    }
    // Kernel BPF filter; verified before the capture loop runs.
    cap.filter("udp and (port 67 or port 68)", true)
        .with_context(|| format!("DHCP BPF filter rejected on {if_name}"))?;
    Ok(cap)
}

fn map_capture_error(err: pcap::Error, if_name: &str) -> anyhow::Error {
    let lower = err.to_string().to_ascii_lowercase();
    if lower.contains("permission") || lower.contains("not permitted") || lower.contains("bpf") {
        anyhow::anyhow!(
            "DHCP fingerprinting needs raw packet access (root / BPF) on {if_name}: {err}"
        )
    } else {
        anyhow::anyhow!("cannot capture DHCP on {if_name}: {err}")
    }
}

/// Passively capture and fingerprint DHCP clients on `if_name` for `duration`, streaming a
/// [`ScanEvent::Device`] snapshot (carrying `dhcpFingerprint`) per client. Frames sent by this
/// host (`own_macs`) are ignored. Needs raw packet access; errors clearly say so.
pub async fn run_dhcp_fingerprint(
    if_name: &str,
    own_macs: Vec<[u8; 6]>,
    duration: Duration,
    tx: Sender<ScanEvent>,
    cancel: CancellationToken,
) -> Result<u64> {
    let if_name = if_name.to_string();
    tokio::task::spawn_blocking(move || -> Result<u64> {
        let mut cap = open_dhcp_capture(&if_name)?;
        let own: HashSet<[u8; 6]> = own_macs.into_iter().collect();
        let deadline = Instant::now().checked_add(duration);
        // Last fingerprint emitted per client, so we only re-emit on change.
        let mut seen: HashMap<[u8; 6], DhcpFingerprint> = HashMap::new();
        let mut count = 0u64;
        while deadline.is_none_or(|d| Instant::now() < d) && !cancel.is_cancelled() {
            match cap.next_packet() {
                Ok(pkt) => {
                    let Some((dhcp, vlan)) = dhcp_payload(pkt.data) else {
                        continue;
                    };
                    let Some(parsed) = parse_dhcp(dhcp) else {
                        continue;
                    };
                    let Some(mac) = parsed.mac else { continue };
                    if own.contains(&mac) {
                        continue;
                    }
                    if seen.len() >= MAX_CLIENTS && !seen.contains_key(&mac) {
                        continue;
                    }
                    let fp = fingerprint(&parsed);
                    if seen.get(&mac) == Some(&fp) {
                        continue; // unchanged: do not re-emit
                    }
                    seen.insert(mac, fp.clone());
                    count += 1;
                    let mut dev = device_for(&parsed, vlan, fp);
                    dev.add_source(DiscoverySource::Dhcp);
                    if tx.blocking_send(ScanEvent::device(dev)).is_err() {
                        break;
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {}
                Err(e) => return Err(map_capture_error(e, &if_name)),
            }
        }
        Ok(count)
    })
    .await
    .context("DHCP fingerprint task failed")?
}

/// Build a [`Device`] snapshot for a fingerprinted DHCP client. A client that has no address
/// yet (a bare DISCOVER) gets the unspecified IP `0.0.0.0`: the engine then attributes the
/// fingerprint by MAC to the matching row instead of creating one. The DHCP hostname stays in
/// `dhcpFingerprint.hostname` (it is client-chosen, not a DNS name or a user label).
fn device_for(pkt: &DhcpPacket, vlan: Option<u16>, fp: DhcpFingerprint) -> Device {
    let ip = pkt
        .client_ip
        .map(IpAddr::V4)
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let mut dev = Device::new(ip);
    dev.vlan_id = vlan;
    dev.mac = pkt.mac.map(|m| crate::models::format_mac(&m));
    dev.dhcp_fingerprint = Some(fp);
    dev.last_seen_ms = now_ms();
    dev
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an Ethernet + IPv4 + UDP + BOOTP DHCP packet with the given options.
    fn build_dhcp_frame(
        client_mac: [u8; 6],
        msg_type: u8,
        options: &[(u8, Vec<u8>)],
        vlan: Option<u16>,
    ) -> Vec<u8> {
        // BOOTP body.
        let mut bootp = vec![0u8; 240];
        bootp[0] = 1; // op = BOOTREQUEST
        bootp[1] = 1; // htype = Ethernet
        bootp[2] = 6; // hlen
        bootp[28..34].copy_from_slice(&client_mac);
        bootp[236..240].copy_from_slice(&DHCP_MAGIC);
        // Option 53 message type first.
        bootp.extend_from_slice(&[53, 1, msg_type]);
        for (code, value) in options {
            bootp.push(*code);
            bootp.push(value.len() as u8);
            bootp.extend_from_slice(value);
        }
        bootp.push(255); // end

        // UDP header (src 68 -> dst 67).
        let udp_len = 8 + bootp.len();
        let mut udp = Vec::new();
        udp.extend_from_slice(&68u16.to_be_bytes());
        udp.extend_from_slice(&67u16.to_be_bytes());
        udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]); // checksum 0 (optional for IPv4/UDP)
        udp.extend_from_slice(&bootp);

        // IPv4 header (20 bytes), proto UDP.
        let total = 20 + udp.len();
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        ip[8] = 64; // ttl
        ip[9] = IPPROTO_UDP;
        ip[12..16].copy_from_slice(&[0, 0, 0, 0]); // src 0.0.0.0
        ip[16..20].copy_from_slice(&[255, 255, 255, 255]); // dst broadcast
        ip.extend_from_slice(&udp);

        // Ethernet header, optionally 802.1Q-tagged.
        let mut eth = Vec::new();
        eth.extend_from_slice(&[0xff; 6]); // dst broadcast
        eth.extend_from_slice(&client_mac); // src
        if let Some(vid) = vlan {
            eth.extend_from_slice(&0x8100u16.to_be_bytes());
            eth.extend_from_slice(&vid.to_be_bytes());
        }
        eth.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        eth.extend_from_slice(&ip);
        eth
    }

    #[test]
    fn parses_dhcp_discover_options() {
        let mac = [0x00, 0x1a, 0x2b, 0x03, 0x04, 0x05];
        let frame = build_dhcp_frame(
            mac,
            1,
            &[
                (
                    55,
                    vec![1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252],
                ),
                (60, b"MSFT 5.0".to_vec()),
                (12, b"DESKTOP-ABC123".to_vec()),
                (57, vec![0x05, 0xdc]),
            ],
            None,
        );
        let (dhcp, vlan) = dhcp_payload(&frame).expect("should recognise DHCP");
        assert_eq!(vlan, None);
        let pkt = parse_dhcp(dhcp).expect("should parse");
        assert_eq!(pkt.msg_type, Some(1));
        assert_eq!(pkt.mac, Some(mac));
        assert_eq!(pkt.vendor_class.as_deref(), Some("MSFT 5.0"));
        assert_eq!(pkt.hostname.as_deref(), Some("DESKTOP-ABC123"));
        assert_eq!(pkt.max_message_size, Some(1500));
        assert_eq!(
            pkt.param_list,
            vec![1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]
        );
    }

    #[test]
    fn handles_vlan_tagged_dhcp() {
        let mac = [0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33];
        let frame = build_dhcp_frame(mac, 3, &[(55, vec![1, 3, 6, 15])], Some(20));
        let (dhcp, vlan) = dhcp_payload(&frame).expect("tagged DHCP");
        assert_eq!(vlan, Some(20));
        let pkt = parse_dhcp(dhcp).unwrap();
        assert_eq!(pkt.msg_type, Some(3));
        assert_eq!(pkt.mac, Some(mac));
    }

    #[test]
    fn parser_is_hostile_input_safe() {
        assert!(parse_dhcp(&[]).is_none());
        assert!(parse_dhcp(&[0u8; 100]).is_none()); // no magic cookie
                                                    // Magic cookie but an option claiming a huge length past the buffer must not panic.
        let mut p = vec![0u8; 240];
        p[2] = 6;
        p[236..240].copy_from_slice(&DHCP_MAGIC);
        p.extend_from_slice(&[55, 200, 1, 2, 3]); // len 200, only 3 bytes present
        assert!(parse_dhcp(&p).is_none_or(|pkt| pkt.param_list.len() <= 3));
        // Truncated UDP/IP frames must be rejected cleanly.
        assert!(dhcp_payload(&[0u8; 20]).is_none());
    }

    #[test]
    fn signature_table_loads_and_matches() {
        let sigs = signatures();
        assert!(sigs.len() > 20, "embedded table should have many rows");
        // Windows via vendor class.
        let mut pkt = DhcpPacket {
            vendor_class: Some("MSFT 5.0".into()),
            param_list: vec![1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252],
            ..DhcpPacket::default()
        };
        let fp = fingerprint(&pkt);
        assert_eq!(fp.os.as_deref(), Some("Windows"));
        assert_eq!(fp.confidence.as_deref(), Some("high"));
        // android-dhcp-14 → Android 14, versioned, high confidence.
        pkt.vendor_class = Some("android-dhcp-14".into());
        let fp = fingerprint(&pkt);
        assert_eq!(fp.os.as_deref(), Some("Android 14"));
        assert_eq!(fp.confidence.as_deref(), Some("high"));
        // Parameter list only (no vendor class) → medium macOS.
        let pkt = DhcpPacket {
            param_list: vec![1, 121, 3, 6, 15, 119, 252, 95, 44, 46],
            ..DhcpPacket::default()
        };
        let fp = fingerprint(&pkt);
        assert_eq!(fp.os.as_deref(), Some("macOS"));
        assert_eq!(fp.confidence.as_deref(), Some("medium"));
        // Hostname hint only → low.
        let pkt = DhcpPacket {
            hostname: Some("iPhone-of-Sam".into()),
            ..DhcpPacket::default()
        };
        let fp = fingerprint(&pkt);
        assert_eq!(fp.os.as_deref(), Some("iOS"));
        assert_eq!(fp.confidence.as_deref(), Some("low"));
        // No match: os None but the raw param list / vendor class are still carried.
        let pkt = DhcpPacket {
            param_list: vec![200, 201, 202],
            vendor_class: Some("something-unknown".into()),
            ..DhcpPacket::default()
        };
        let fp = fingerprint(&pkt);
        assert!(fp.os.is_none());
        assert_eq!(fp.param_list, vec![200, 201, 202]);
        assert_eq!(fp.vendor_class.as_deref(), Some("something-unknown"));
    }

    #[test]
    fn client_id_renders_mac_and_text() {
        assert_eq!(
            render_client_id(&[0x01, 0x00, 0x1a, 0x2b, 0x03, 0x04, 0x05]).as_deref(),
            Some("00:1a:2b:03:04:05")
        );
        assert_eq!(render_client_id(b"myclient").as_deref(), Some("myclient"));
        assert!(render_client_id(&[0xff, 0x00, 0xde])
            .as_deref()
            .unwrap()
            .contains(':'));
    }

    #[test]
    fn builds_device_snapshot() {
        let mac = [0x00, 0x1a, 0x2b, 0x03, 0x04, 0x05];
        let frame = build_dhcp_frame(
            mac,
            1,
            &[(55, vec![1, 3, 6, 15]), (12, b"my-laptop".to_vec())],
            Some(30),
        );
        let (dhcp, vlan) = dhcp_payload(&frame).unwrap();
        let pkt = parse_dhcp(dhcp).unwrap();
        let dev = device_for(&pkt, vlan, fingerprint(&pkt));
        assert_eq!(dev.vlan_id, Some(30));
        assert_eq!(dev.mac.as_deref(), Some("00:1a:2b:03:04:05"));
        // No address yet (DISCOVER): unspecified IP, attributed by MAC downstream.
        assert!(dev.ip.is_unspecified());
        assert!(dev.dns_name.is_none());
        let fp = dev.dhcp_fingerprint.unwrap();
        assert_eq!(fp.hostname.as_deref(), Some("my-laptop"));
        // A REQUEST carrying option 50 (requested IP) keys the row by that address.
        let frame = build_dhcp_frame(mac, 3, &[(50, vec![10, 0, 0, 42])], None);
        let (dhcp, vlan) = dhcp_payload(&frame).unwrap();
        let pkt = parse_dhcp(dhcp).unwrap();
        let dev = device_for(&pkt, vlan, fingerprint(&pkt));
        assert_eq!(dev.ip.to_string(), "10.0.0.42");
    }
}
