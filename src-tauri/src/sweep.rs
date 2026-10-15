//! Routed / unprivileged discovery: concurrent async ICMPv4 echo sweeps plus the OS neighbor
//! (ARP) cache.
//!
//! Used for targets outside the interface's connected subnet and as the fallback when raw
//! layer-2 access is denied. `surge-ping` opens an unprivileged `SOCK_DGRAM` ICMP socket where
//! the OS allows it (macOS, Linux with `net.ipv4.ping_group_range`) and a raw socket otherwise.

use std::{
    collections::HashSet,
    fs,
    net::{IpAddr, Ipv4Addr},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use surge_ping::{Client, Config, PingIdentifier, PingSequence};
use tokio::{
    sync::{mpsc::Sender, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use crate::{
    models::{
        format_mac, now_ms, parse_mac, Device, DiscoverySource, Ipv4Range, ScanConfig, ScanEvent,
        MAX_CONCURRENCY,
    },
    progress::ProgressScope,
};

const PING_PAYLOAD: &[u8; 16] = b"SweepR-ICMP-v4\0\0";

/// Counters returned by [`run_icmp_sweep`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    pub probes_sent: u64,
    pub alive: u64,
    /// Hosts that only showed up in the neighbor cache (answered ARP but not ICMP).
    pub cache_only: u64,
}

/// One complete entry from the OS neighbor (ARP) cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborEntry {
    pub ip: Ipv4Addr,
    /// Canonical lowercase `aa:bb:cc:dd:ee:ff`.
    pub mac: String,
    pub interface: Option<String>,
}

/// ICMPv4 echo sweep over `targets` with at most `cfg.concurrency` probes in flight, each
/// waiting `cfg.timeout_ms` and retried `cfg.retries` times. Responsive hosts are streamed as
/// [`ScanEvent::Device`] (source [`DiscoverySource::Icmp`], with RTT) tagged with `vlan_id`
/// (set when sweeping through an OS VLAN sub-interface). Each dispatched probe is counted in
/// `progress`.
///
/// Afterwards the OS neighbor cache is read to attach MAC addresses. Entries are trusted
/// only when the IP answered the sweep or the entry did not exist before it (the sweep's
/// ARP resolution created it, so the host answered ARP but filters ICMP); stale entries
/// that were already cached are ignored. See [`select_cache_entries`].
pub async fn run_icmp_sweep(
    targets: Vec<Ipv4Range>,
    cfg: &ScanConfig,
    iface_name: Option<&str>,
    vlan_id: Option<u16>,
    progress: ProgressScope,
    tx: Sender<ScanEvent>,
    cancel: CancellationToken,
) -> Result<SweepReport> {
    let client = Client::new(&Config::default()).context(
        "cannot open an ICMP socket (unprivileged ICMP may be disabled: on Linux check \
         net.ipv4.ping_group_range, or run with sudo)",
    )?;
    let total: u64 = targets.iter().map(Ipv4Range::count).sum();
    let semaphore = Arc::new(Semaphore::new(cfg.concurrency.clamp(1, MAX_CONCURRENCY)));
    let alive: Arc<Mutex<HashSet<Ipv4Addr>>> = Arc::default();
    let timeout = Duration::from_millis(cfg.timeout_ms.max(1));
    let retries = u16::from(cfg.retries);
    let iface: Option<String> = iface_name.map(str::to_string);
    // The identifier only needs to distinguish us from other pingers on this host.
    let ident = PingIdentifier((std::process::id() as u16) ^ (now_ms() as u16));
    // What the cache held before we probed: those entries may be stale.
    let cache_before: HashSet<(Ipv4Addr, String)> =
        tokio::task::spawn_blocking(read_neighbor_cache)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|e| (e.ip, e.mac))
            .collect();

    let _ = tx
        .send(ScanEvent::info(format!(
            "ICMP sweep: {total} address(es), {} in flight",
            cfg.concurrency
        )))
        .await;

    let mut tasks = JoinSet::new();
    let mut sent = 0u64;
    'dispatch: for range in &targets {
        for ip in range.iter() {
            let permit = tokio::select! {
                _ = cancel.cancelled() => break 'dispatch,
                permit = semaphore.clone().acquire_owned() => permit.context("probe semaphore closed")?,
            };
            let (task_client, task_tx, task_alive, task_iface) =
                (client.clone(), tx.clone(), alive.clone(), iface.clone());
            tasks.spawn(async move {
                let _permit = permit;
                if let Some(rtt) = ping_host(&task_client, ip, ident, timeout, retries).await {
                    if let Ok(mut set) = task_alive.lock() {
                        set.insert(ip);
                    }
                    let mut dev = Device::new(IpAddr::V4(ip));
                    dev.rtt_ms = Some(rtt.as_secs_f32() * 1000.0);
                    dev.interface = task_iface;
                    dev.vlan_id = vlan_id;
                    dev.add_source(DiscoverySource::Icmp);
                    let _ = task_tx.send(ScanEvent::device(dev)).await;
                }
            });
            sent += 1;
            progress.add(1);
            // Reap finished probes so the JoinSet stays bounded on huge ranges.
            while tasks.try_join_next().is_some() {}
        }
    }

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tasks.abort_all();
                break;
            }
            next = tasks.join_next() => if next.is_none() { break },
        }
    }

    // Pull MACs (and ICMP-silent hosts) from the neighbor cache the sweep just populated.
    let mut cache_only = 0;
    if !cancel.is_cancelled() {
        let cache = tokio::task::spawn_blocking(read_neighbor_cache)
            .await
            .unwrap_or_default();
        let responders = alive.lock().map(|s| s.clone()).unwrap_or_default();
        for (entry, replied) in select_cache_entries(cache, &cache_before, &responders, &targets) {
            if !replied {
                cache_only += 1;
            }
            let mut dev = Device::new(IpAddr::V4(entry.ip));
            dev.mac = Some(entry.mac);
            dev.interface = entry.interface.or_else(|| iface.clone());
            dev.vlan_id = vlan_id;
            dev.add_source(DiscoverySource::NeighborCache);
            let _ = tx.send(ScanEvent::device(dev)).await;
        }
    }
    Ok(SweepReport {
        probes_sent: sent,
        alive: count(&alive),
        cache_only,
    })
}

/// Neighbor-cache entries worth reporting after a sweep, with `true` when the IP also
/// answered ICMP. An entry inside `targets` qualifies when its IP replied to the sweep, or
/// when the `(ip, mac)` pair was not cached before the sweep (resolving it is evidence the
/// host answered ARP just now). Pre-existing entries for silent IPs may be stale and are
/// dropped. Incomplete / failed entries never reach this point (see the parsers).
pub fn select_cache_entries(
    after: Vec<NeighborEntry>,
    before: &HashSet<(Ipv4Addr, String)>,
    responders: &HashSet<Ipv4Addr>,
    targets: &[Ipv4Range],
) -> Vec<(NeighborEntry, bool)> {
    after
        .into_iter()
        .filter(|e| targets.iter().any(|r| r.contains(e.ip)))
        .filter_map(|e| {
            let replied = responders.contains(&e.ip);
            let fresh = !before.contains(&(e.ip, e.mac.clone()));
            (replied || fresh).then_some((e, replied))
        })
        .collect()
}

fn count(set: &Mutex<HashSet<Ipv4Addr>>) -> u64 {
    set.lock().map(|s| s.len() as u64).unwrap_or(0)
}

/// Ping `ip` up to `retries + 1` times; returns the first round-trip time.
async fn ping_host(
    client: &Client,
    ip: Ipv4Addr,
    ident: PingIdentifier,
    timeout: Duration,
    retries: u16,
) -> Option<Duration> {
    let mut pinger = client.pinger(IpAddr::V4(ip), ident).await;
    pinger.timeout(timeout);
    for seq in 0..=retries {
        if let Ok((_, rtt)) = pinger.ping(PingSequence(seq), PING_PAYLOAD).await {
            return Some(rtt);
        }
    }
    None
}

/// Read the OS IPv4 neighbor cache (`/proc/net/arp` on Linux, `arp -an` elsewhere).
/// Incomplete, broadcast and multicast entries are skipped.
pub fn read_neighbor_cache() -> Vec<NeighborEntry> {
    if cfg!(target_os = "linux") {
        fs::read_to_string("/proc/net/arp")
            .map(|t| parse_proc_net_arp(&t))
            .unwrap_or_default()
    } else {
        Command::new("/usr/sbin/arp")
            .arg("-an")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| parse_arp_an(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default()
    }
}

/// Canonicalize a cache MAC, rejecting zero, broadcast and multicast addresses.
fn usable_mac(s: &str) -> Option<String> {
    let mac = parse_mac(s)?;
    let unusable = mac == [0; 6] || mac[0] & 0x01 != 0;
    (!unusable).then(|| format_mac(&mac))
}

/// Parse BSD/macOS `arp -an` output, e.g.
/// `? (192.168.1.1) at 0:1a:2b:3:4:5 on en0 ifscope [ethernet]`.
/// macOS prints MAC octets without leading zeros, which [`parse_mac`] accepts.
pub fn parse_arp_an(text: &str) -> Vec<NeighborEntry> {
    text.lines()
        .filter_map(|line| {
            let open = line.find('(')?;
            let close = open + line.get(open..)?.find(')')?;
            let ip: Ipv4Addr = line.get(open + 1..close)?.parse().ok()?;
            let tokens: Vec<&str> = line.get(close + 1..)?.split_whitespace().collect();
            let after = |key: &str| {
                tokens
                    .iter()
                    .position(|t| *t == key)
                    .and_then(|i| tokens.get(i + 1))
            };
            let mac = usable_mac(after("at")?)?;
            Some(NeighborEntry {
                ip,
                mac,
                interface: after("on").map(|s| s.to_string()),
            })
        })
        .collect()
}

/// Parse Linux `/proc/net/arp`. Only complete entries (`ATF_COM`, flag 0x2) are returned.
pub fn parse_proc_net_arp(text: &str) -> Vec<NeighborEntry> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let ip: Ipv4Addr = f.first()?.parse().ok()?;
            let flags = u32::from_str_radix(f.get(2)?.trim_start_matches("0x"), 16).ok()?;
            if flags & 0x2 == 0 {
                return None;
            }
            Some(NeighborEntry {
                ip,
                mac: usable_mac(f.get(3)?)?,
                interface: f.get(5).map(|s| s.to_string()),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_macos_arp_output() {
        let text = "? (192.168.1.1) at 0:1a:2b:3:4:5 on en0 ifscope [ethernet]\n\
                    ? (192.168.1.7) at (incomplete) on en0 ifscope [ethernet]\n\
                    ? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n\
                    ? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n\
                    router.lan (10.0.0.1) at a4:91:b1:c:d:e on en7 ifscope [ethernet]\n\
                    garbage line\n";
        let e = parse_arp_an(text);
        assert_eq!(
            e,
            vec![
                NeighborEntry {
                    ip: "192.168.1.1".parse().unwrap(),
                    mac: "00:1a:2b:03:04:05".into(),
                    interface: Some("en0".into())
                },
                NeighborEntry {
                    ip: "10.0.0.1".parse().unwrap(),
                    mac: "a4:91:b1:0c:0d:0e".into(),
                    interface: Some("en7".into())
                },
            ]
        );
    }

    #[test]
    fn parses_linux_proc_net_arp() {
        let text = "IP address       HW type     Flags       HW address            Mask     Device\n\
                    192.168.1.1      0x1         0x2         00:1a:2b:03:04:05     *        eth0\n\
                    192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n\
                    10.10.0.20       0x1         0x6         de:ad:be:ef:00:01     *        eth0.10\n";
        let e = parse_proc_net_arp(text);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].mac, "00:1a:2b:03:04:05");
        assert_eq!(e[1].interface.as_deref(), Some("eth0.10"));
    }

    #[test]
    fn stale_cache_entries_are_ignored() {
        let entry = |ip: &str, mac: &str| NeighborEntry {
            ip: ip.parse().unwrap(),
            mac: mac.into(),
            interface: Some("en0".into()),
        };
        let before: HashSet<(Ipv4Addr, String)> = [
            ("10.0.0.2", "00:00:00:00:00:02"), // stale: cached before, silent now
            ("10.0.0.3", "00:00:00:00:00:03"), // cached before, answered ICMP
            ("10.0.0.4", "00:00:00:00:00:04"), // MAC changed since
        ]
        .into_iter()
        .map(|(ip, mac)| (ip.parse().unwrap(), mac.to_string()))
        .collect();
        let after = vec![
            entry("10.0.0.2", "00:00:00:00:00:02"),
            entry("10.0.0.3", "00:00:00:00:00:03"),
            entry("10.0.0.4", "00:00:00:00:00:44"),
            entry("10.0.0.5", "00:00:00:00:00:05"), // new: answered ARP, filters ICMP
            entry("192.168.9.9", "00:00:00:00:00:99"), // outside the targets
        ];
        let responders: HashSet<Ipv4Addr> = ["10.0.0.3".parse().unwrap()].into();
        let targets = vec!["10.0.0.0/24".parse().unwrap()];
        let got: Vec<(String, bool)> = select_cache_entries(after, &before, &responders, &targets)
            .into_iter()
            .map(|(e, replied)| (e.ip.to_string(), replied))
            .collect();
        assert_eq!(
            got,
            vec![
                ("10.0.0.3".to_string(), true),
                ("10.0.0.4".to_string(), false),
                ("10.0.0.5".to_string(), false)
            ]
        );
    }
}
