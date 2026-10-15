//! Wake-on-LAN: build and broadcast AMD "Magic Packets".
//!
//! A magic packet is 6 bytes of `0xFF` followed by the target MAC repeated 16 times (102
//! bytes), optionally followed by a 6-byte SecureOn password. It is sent as a UDP datagram
//! (port 9 by default, port 7 on request) to the directed broadcast address of the chosen
//! interface's subnet and to the limited broadcast `255.255.255.255`, from a socket bound to
//! that interface's address with `SO_BROADCAST` set. An explicit `--broadcast` address
//! (directed broadcast of a remote subnet, or a unicast relay) replaces both.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};

use crate::{
    arp_vlan,
    limits::SocketBudget,
    models::{format_mac, parse_mac, InterfaceInfo, WakeResult},
};

/// Default destination port (discard). Port 7 (echo) is the other common choice.
pub const WOL_PORT: u16 = 9;
/// Default and maximum number of times the packet is sent to each destination.
pub const DEFAULT_REPEAT: u8 = 3;
pub const MAX_REPEAT: u8 = 20;
/// Most distinct destination ports per request.
pub const MAX_PORTS: usize = 4;
/// Pause between repetitions.
const REPEAT_GAP: Duration = Duration::from_millis(100);

/// What to send and where.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WakeOptions {
    /// Interface to send from. `None` = the default-route interface (or, with an explicit
    /// `broadcast`, whatever the routing table picks).
    pub interface: Option<String>,
    /// Destination address instead of the interface's subnet broadcast + 255.255.255.255.
    pub broadcast: Option<Ipv4Addr>,
    /// Destination UDP ports (empty = [`WOL_PORT`]).
    pub ports: Vec<u16>,
    /// Repetitions per destination (0 = [`DEFAULT_REPEAT`]).
    pub repeat: u8,
    /// Optional 6-byte SecureOn password appended to the packet.
    pub password: Option<[u8; 6]>,
}

/// Parse a target MAC (any notation [`parse_mac`] accepts) and reject addresses no NIC
/// could own: all-zero, broadcast and multicast (I/G bit set).
pub fn parse_wol_mac(s: &str) -> Result<[u8; 6]> {
    let mac = parse_mac(s).ok_or_else(|| {
        anyhow!(
            "'{}' is not a MAC address (expected e.g. aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff \
             or aabb.ccdd.eeff)",
            crate::models::sanitize_text(s)
        )
    })?;
    if mac == [0; 6] {
        bail!("00:00:00:00:00:00 is not a device MAC address");
    }
    if mac[0] & 0x01 != 0 {
        bail!(
            "{} is a broadcast/multicast address, not a device MAC address",
            format_mac(&mac)
        );
    }
    Ok(mac)
}

/// Parse a SecureOn password: 6 bytes written like a MAC address (`01:02:03:04:05:06`).
pub fn parse_secureon(s: &str) -> Result<[u8; 6]> {
    parse_mac(s).ok_or_else(|| {
        anyhow!("the SecureOn password must be 6 bytes written like a MAC address, e.g. 01:02:03:04:05:06")
    })
}

/// The magic packet for `mac` (102 bytes, or 108 with a SecureOn password).
pub fn magic_packet(mac: &[u8; 6], password: Option<&[u8; 6]>) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(108);
    pkt.extend_from_slice(&[0xff; 6]);
    for _ in 0..16 {
        pkt.extend_from_slice(mac);
    }
    if let Some(pw) = password {
        pkt.extend_from_slice(pw);
    }
    pkt
}

/// Directed broadcast address of `ip/prefix`, or `None` for /31 and /32 (no broadcast).
pub fn directed_broadcast(ip: Ipv4Addr, prefix: u8) -> Option<Ipv4Addr> {
    if prefix >= 31 {
        return None;
    }
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    Some(Ipv4Addr::from(u32::from(ip) | !mask))
}

/// Reject destinations a magic packet can never usefully go to.
pub fn validate_destination(addr: Ipv4Addr) -> Result<()> {
    if addr.is_unspecified() {
        bail!("0.0.0.0 is not a valid broadcast address");
    }
    if addr.is_multicast() {
        bail!("{addr} is a multicast address; use a broadcast or unicast address");
    }
    Ok(())
}

/// Destination addresses for `iface` (its subnet's directed broadcast, then
/// 255.255.255.255), or just `broadcast` when given.
pub fn plan_destinations(
    iface: Option<&InterfaceInfo>,
    broadcast: Option<Ipv4Addr>,
) -> Vec<Ipv4Addr> {
    if let Some(b) = broadcast {
        return vec![b];
    }
    let mut out = Vec::new();
    if let Some((ip, prefix)) = iface.and_then(InterfaceInfo::primary_ipv4) {
        if let Some(b) = directed_broadcast(ip, prefix) {
            out.push(b);
        }
    }
    if !out.contains(&Ipv4Addr::BROADCAST) {
        out.push(Ipv4Addr::BROADCAST);
    }
    out
}

/// Distinct, non-zero destination ports (default [`WOL_PORT`]), at most [`MAX_PORTS`].
fn plan_ports(ports: &[u16]) -> Result<Vec<u16>> {
    let mut out: Vec<u16> = Vec::new();
    for p in ports {
        if *p == 0 {
            bail!("port 0 is not a valid Wake-on-LAN port");
        }
        if !out.contains(p) {
            out.push(*p);
        }
    }
    if out.len() > MAX_PORTS {
        bail!("at most {MAX_PORTS} destination ports");
    }
    if out.is_empty() {
        out.push(WOL_PORT);
    }
    Ok(out)
}

/// UDP socket with `SO_BROADCAST`, bound to `source` (and, on macOS, pinned to the interface
/// so even 255.255.255.255 leaves through it).
fn broadcast_socket(source: Ipv4Addr, iface: Option<&InterfaceInfo>) -> Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("cannot open a UDP socket")?;
    sock.set_broadcast(true)
        .context("cannot enable SO_BROADCAST")?;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    if let Some(index) = iface.and_then(|i| std::num::NonZeroU32::new(i.index)) {
        // IP_BOUND_IF: no privileges needed. Best effort.
        if let Err(e) = sock.bind_device_by_index_v4(Some(index)) {
            tracing::debug!("IP_BOUND_IF failed: {e}");
        }
    }
    #[cfg(target_os = "linux")]
    if let Some(i) = iface {
        // SO_BINDTODEVICE needs CAP_NET_RAW; binding to the address below is the fallback.
        if let Err(e) = sock.bind_device(Some(i.name.as_bytes())) {
            tracing::debug!("SO_BINDTODEVICE failed: {e}");
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
    let _ = iface;
    sock.bind(&SocketAddr::V4(SocketAddrV4::new(source, 0)).into())
        .with_context(|| format!("cannot bind a UDP socket to {source}"))?;
    Ok(sock)
}

/// Send the magic packet for `mac` as described by `opts`.
pub async fn wake(mac: [u8; 6], opts: &WakeOptions) -> Result<WakeResult> {
    wake_with(mac, opts, SocketBudget::global()).await
}

/// [`wake`] with an explicit socket budget.
pub async fn wake_with(
    mac: [u8; 6],
    opts: &WakeOptions,
    budget: &SocketBudget,
) -> Result<WakeResult> {
    if mac == [0; 6] || mac[0] & 0x01 != 0 {
        bail!("{} is not a device MAC address", format_mac(&mac));
    }
    if let Some(b) = opts.broadcast {
        validate_destination(b)?;
    }
    let ports = plan_ports(&opts.ports)?;
    let repeat = match opts.repeat {
        0 => DEFAULT_REPEAT,
        n => n.min(MAX_REPEAT),
    };

    // An explicit broadcast without an interface needs no interface lookup (and works for
    // unicast relays / loopback). Otherwise resolve the interface for its subnet + address.
    let iface = if opts.interface.is_some() || opts.broadcast.is_none() {
        let name = opts.interface.clone();
        let iface = tokio::task::spawn_blocking(move || {
            arp_vlan::select_interface(&arp_vlan::list_interfaces(), name.as_deref())
        })
        .await
        .context("interface lookup failed")??;
        Some(iface)
    } else {
        None
    };
    let source = match &iface {
        Some(i) => i
            .primary_ipv4()
            .map(|(ip, _)| ip)
            .ok_or_else(|| anyhow!("interface {} has no IPv4 address", i.name))?,
        None => Ipv4Addr::UNSPECIFIED,
    };
    let destinations = plan_destinations(iface.as_ref(), opts.broadcast);
    let packet = magic_packet(&mac, opts.password.as_ref());

    let _permit = budget.acquire().await;
    let sock = broadcast_socket(source, iface.as_ref())?;
    sock.set_nonblocking(true)?;
    let sock = tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(sock))
        .context("cannot register the UDP socket")?;

    let mut sent = 0u32;
    let mut reached: Vec<String> = Vec::new();
    let mut last_err: Option<std::io::Error> = None;
    for round in 0..repeat {
        if round > 0 {
            tokio::time::sleep(REPEAT_GAP).await;
        }
        for dst in &destinations {
            for port in &ports {
                let to = SocketAddr::V4(SocketAddrV4::new(*dst, *port));
                match sock.send_to(&packet, to).await {
                    Ok(_) => {
                        sent += 1;
                        let label = to.to_string();
                        if !reached.contains(&label) {
                            reached.push(label);
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Wake-on-LAN send to {to} failed: {e}");
                        last_err = Some(e);
                    }
                }
            }
        }
    }
    if sent == 0 {
        let e = last_err.map(|e| e.to_string()).unwrap_or_default();
        bail!("could not send the magic packet to any destination: {e}");
    }
    Ok(WakeResult {
        mac: format_mac(&mac),
        targets: reached,
        packets_sent: sent,
        interface: iface.as_ref().map(|i| i.name.clone()),
        source_ip: (!source.is_unspecified()).then_some(IpAddr::V4(source)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{IfAddr, InterfaceKind};

    #[test]
    fn magic_packet_layout() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let pkt = magic_packet(&mac, None);
        assert_eq!(pkt.len(), 102);
        assert_eq!(&pkt[..6], &[0xff; 6]);
        for i in 0..16 {
            assert_eq!(&pkt[6 + i * 6..12 + i * 6], &mac);
        }
        let pw = [1, 2, 3, 4, 5, 6];
        let pkt = magic_packet(&mac, Some(&pw));
        assert_eq!(pkt.len(), 108);
        assert_eq!(&pkt[102..], &pw);
        assert_eq!(&pkt[..102], magic_packet(&mac, None).as_slice());
    }

    #[test]
    fn mac_notations_and_rejections() {
        let want = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        for s in [
            "aa:bb:cc:dd:ee:ff",
            "AA-BB-CC-DD-EE-FF",
            "aabb.ccdd.eeff",
            "AABBCCDDEEFF",
            " aa:bb:cc:dd:ee:ff ",
        ] {
            assert_eq!(parse_wol_mac(s).unwrap(), want, "{s}");
        }
        assert_eq!(parse_wol_mac("0:1a:2b:3:4:5").unwrap()[5], 5);
        for bad in [
            "",
            "aa:bb:cc:dd:ee",
            "zz:bb:cc:dd:ee:ff",
            "ff:ff:ff:ff:ff:ff",
            "01:00:5e:00:00:01",
            "00:00:00:00:00:00",
            "--gui",
        ] {
            assert!(parse_wol_mac(bad).is_err(), "{bad}");
        }
        assert_eq!(
            parse_secureon("01-02-03-04-05-06").unwrap(),
            [1, 2, 3, 4, 5, 6]
        );
        assert!(parse_secureon("1234").is_err());
    }

    #[test]
    fn destinations_and_ports() {
        assert_eq!(
            directed_broadcast(Ipv4Addr::new(192, 168, 1, 10), 24),
            Some(Ipv4Addr::new(192, 168, 1, 255))
        );
        assert_eq!(
            directed_broadcast(Ipv4Addr::new(10, 177, 134, 9), 21),
            Some(Ipv4Addr::new(10, 177, 135, 255))
        );
        assert_eq!(directed_broadcast(Ipv4Addr::new(10, 0, 0, 1), 31), None);
        assert_eq!(directed_broadcast(Ipv4Addr::new(10, 0, 0, 1), 32), None);
        let iface = InterfaceInfo {
            name: "en0".into(),
            index: 4,
            description: None,
            mac: None,
            addrs: vec![IfAddr {
                ip: "192.168.7.20".parse().unwrap(),
                prefix: 24,
            }],
            is_up: true,
            kind: InterfaceKind::Ethernet,
            vlan_id: None,
            parent: None,
            is_default: true,
        };
        assert_eq!(
            plan_destinations(Some(&iface), None),
            vec![Ipv4Addr::new(192, 168, 7, 255), Ipv4Addr::BROADCAST]
        );
        assert_eq!(plan_destinations(None, None), vec![Ipv4Addr::BROADCAST]);
        let b = Ipv4Addr::new(10, 9, 9, 255);
        assert_eq!(plan_destinations(Some(&iface), Some(b)), vec![b]);
        assert!(validate_destination(Ipv4Addr::UNSPECIFIED).is_err());
        assert!(validate_destination(Ipv4Addr::new(224, 0, 0, 1)).is_err());
        assert!(validate_destination(Ipv4Addr::LOCALHOST).is_ok());
        assert_eq!(plan_ports(&[]).unwrap(), vec![9]);
        assert_eq!(plan_ports(&[9, 7, 9]).unwrap(), vec![9, 7]);
        assert!(plan_ports(&[0]).is_err());
        assert!(plan_ports(&[1, 2, 3, 4, 5]).is_err());
    }

    /// Happy path end to end: the packet arrives intact at a local UDP listener.
    #[tokio::test]
    async fn magic_packet_reaches_a_loopback_listener() {
        let rx = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = rx.local_addr().unwrap().port();
        let mac = parse_wol_mac("00:11:22:33:44:55").unwrap();
        let opts = WakeOptions {
            broadcast: Some(Ipv4Addr::LOCALHOST),
            ports: vec![port],
            repeat: 2,
            password: Some([9, 8, 7, 6, 5, 4]),
            ..WakeOptions::default()
        };
        let res = wake_with(mac, &opts, &SocketBudget::new(1)).await.unwrap();
        assert_eq!(res.packets_sent, 2);
        assert_eq!(res.targets, vec![format!("127.0.0.1:{port}")]);
        assert_eq!(res.mac, "00:11:22:33:44:55");
        let want = magic_packet(&mac, Some(&[9, 8, 7, 6, 5, 4]));
        let mut buf = [0u8; 256];
        for _ in 0..2 {
            let n = tokio::time::timeout(Duration::from_secs(2), rx.recv(&mut buf))
                .await
                .expect("magic packet not received")
                .unwrap();
            assert_eq!(&buf[..n], want.as_slice());
        }
        // Bad inputs fail before anything is sent.
        let bad = WakeOptions {
            broadcast: Some(Ipv4Addr::new(239, 1, 1, 1)),
            ..WakeOptions::default()
        };
        assert!(wake_with(mac, &bad, &SocketBudget::new(1)).await.is_err());
        assert!(wake_with([0xff; 6], &opts, &SocketBudget::new(1))
            .await
            .is_err());
    }
}
