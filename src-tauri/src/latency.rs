//! Continuous latency monitor (ping with rolling statistics and sparkline history).
//!
//! [`run_monitor`] pings every host of a [`MonitorConfig`] on a fixed interval (0.5-10 s)
//! with unprivileged ICMP / ICMPv6 echo (`surge-ping`, one shared socket per address family,
//! as the scan's ICMP sweep does). A host that never answers ICMP falls back to TCP connect
//! round trips (SYN → SYN-ACK or RST) on a known open port, or on a short list of common
//! ports. Each host keeps a ring buffer of its last [`HISTORY_LEN`] samples, from which
//! last / avg / min / max / jitter / loss are computed.
//!
//! Samples are batched: at most one batch per [`FLUSH_INTERVAL`] (≤ 4 per second), carrying
//! only the hosts that got a new sample since the previous batch. Every socket draws from
//! the process-wide [`SocketBudget`], and the number of monitored hosts is capped across all
//! monitors at [`MAX_MONITORED_HOSTS`].

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    net::IpAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use surge_ping::{Client, Config, PingIdentifier, PingSequence, ICMP};
use tokio::{net::TcpStream, sync::mpsc, task::JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{
    limits::SocketBudget,
    models::{now_ms, LatencySample, LatencyStats, ProbeMethod},
};

pub const DEFAULT_INTERVAL_MS: u64 = 1_000;
pub const MIN_INTERVAL_MS: u64 = 500;
pub const MAX_INTERVAL_MS: u64 = 10_000;
/// Samples kept per host (statistics window and sparkline length).
pub const HISTORY_LEN: usize = 120;
/// Hosts monitored at once, across every monitor in the process.
pub const MAX_MONITORED_HOSTS: usize = 2_000;
/// Minimum spacing of sample batches (≤ 4 per second).
pub const FLUSH_INTERVAL: Duration = Duration::from_millis(250);
/// Ports tried for the TCP fallback when no open port is known.
pub const FALLBACK_TCP_PORTS: &[u16] = &[443, 80, 22, 445];
/// Most ports tried per host for the TCP fallback.
const MAX_TCP_PORTS_PER_HOST: usize = 4;
/// Consecutive ICMP losses (with no ICMP reply so far) before the TCP fallback is tried.
const ICMP_MISSES_BEFORE_TCP: u32 = 3;
/// After an unsuccessful TCP port search, search again every this many lost probes.
const TCP_SEARCH_EVERY: u32 = 10;
const PING_PAYLOAD: &[u8; 16] = b"SweepR-latency\0\0";

// ---------------------------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------------------------

/// Statistics of a window of samples.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Summary {
    pub avg: Option<f64>,
    pub min: Option<f64>,
    pub max: Option<f64>,
    /// Mean absolute difference between consecutive replies.
    pub jitter: Option<f64>,
    pub loss_pct: f64,
    pub sent: u32,
    pub received: u32,
}

/// Summarize a window (`None` = lost probe).
pub fn summarize(samples: &[Option<f64>]) -> Summary {
    let sent = samples.len();
    let replies: Vec<f64> = samples.iter().flatten().copied().collect();
    let received = replies.len();
    let loss_pct = if sent == 0 {
        0.0
    } else {
        (sent - received) as f64 * 100.0 / sent as f64
    };
    let (avg, min, max) = if replies.is_empty() {
        (None, None, None)
    } else {
        let sum: f64 = replies.iter().sum();
        let min = replies.iter().copied().fold(f64::INFINITY, f64::min);
        let max = replies.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        (Some(sum / received as f64), Some(min), Some(max))
    };
    let jitter = (replies.len() >= 2).then(|| {
        let diffs: f64 = replies.windows(2).map(|w| (w[1] - w[0]).abs()).sum();
        diffs / (replies.len() - 1) as f64
    });
    let clamp = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    Summary {
        avg,
        min,
        max,
        jitter,
        loss_pct,
        sent: clamp(sent),
        received: clamp(received),
    }
}

/// Round to 3 decimals (microsecond resolution) so events stay compact.
fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

/// Ring buffer of one host's samples.
#[derive(Debug, Clone, Default)]
pub struct Window {
    samples: VecDeque<Option<f64>>,
    last_ts: u64,
    method: ProbeMethod,
}

impl Window {
    /// Record one probe (`None` = lost) taken at `ts` (Unix ms).
    pub fn push(&mut self, rtt_ms: Option<f64>, ts: u64, method: ProbeMethod) {
        if self.samples.len() == HISTORY_LEN {
            self.samples.pop_front();
        }
        self.samples
            .push_back(rtt_ms.filter(|v| v.is_finite() && *v >= 0.0).map(round3));
        self.last_ts = ts;
        self.method = method;
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Rolling statistics of the window.
    pub fn stats(&self) -> LatencyStats {
        self.sample_for(None).stats()
    }

    /// The newest sample of `ip` with the window's statistics and history.
    pub fn sample(&self, ip: IpAddr) -> LatencySample {
        self.sample_for(Some(ip))
    }

    fn sample_for(&self, ip: Option<IpAddr>) -> LatencySample {
        let history: Vec<Option<f64>> = self.samples.iter().copied().collect();
        let s = summarize(&history);
        LatencySample {
            ip: ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            rtt_ms: self.samples.back().copied().flatten(),
            ts: self.last_ts,
            method: self.method,
            loss_pct: round3(s.loss_pct),
            avg_ms: s.avg.map(round3),
            min_ms: s.min,
            max_ms: s.max,
            jitter_ms: s.jitter.map(round3),
            sent: s.sent,
            received: s.received,
            history,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Configuration & host reservation
// ---------------------------------------------------------------------------------------------

/// What to monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorConfig {
    /// Distinct hosts (at most [`MAX_MONITORED_HOSTS`]).
    pub ips: Vec<IpAddr>,
    pub interval: Duration,
    /// Known open TCP ports per host for the TCP fallback.
    pub tcp_ports: HashMap<IpAddr, Vec<u16>>,
    /// Stop each host after this many probes (`None` = until cancelled).
    pub count: Option<u32>,
    /// Use ICMP (tests turn it off to exercise the TCP fallback).
    pub icmp: bool,
}

impl MonitorConfig {
    /// Validate and normalize: de-duplicates `ips`, checks the host cap and the interval
    /// (`None` = [`DEFAULT_INTERVAL_MS`]).
    pub fn new(ips: Vec<IpAddr>, interval_ms: Option<u64>) -> Result<Self> {
        let mut seen = BTreeSet::new();
        let ips: Vec<IpAddr> = ips.into_iter().filter(|ip| seen.insert(*ip)).collect();
        if ips.is_empty() {
            bail!("no hosts to monitor");
        }
        if ips.len() > MAX_MONITORED_HOSTS {
            bail!(
                "too many hosts ({}); at most {MAX_MONITORED_HOSTS} can be monitored",
                ips.len()
            );
        }
        if let Some(ip) = ips
            .iter()
            .find(|ip| ip.is_unspecified() || ip.is_multicast())
        {
            bail!("{ip} cannot be pinged");
        }
        let interval_ms = interval_ms.unwrap_or(DEFAULT_INTERVAL_MS);
        if !(MIN_INTERVAL_MS..=MAX_INTERVAL_MS).contains(&interval_ms) {
            bail!(
                "the interval must be {MIN_INTERVAL_MS}-{MAX_INTERVAL_MS} ms (got {interval_ms})"
            );
        }
        Ok(Self {
            ips,
            interval: Duration::from_millis(interval_ms),
            tcp_ports: HashMap::new(),
            count: None,
            icmp: true,
        })
    }

    /// Per-probe timeout: the interval, clamped to 1-2 s.
    pub fn probe_timeout(&self) -> Duration {
        self.interval
            .clamp(Duration::from_secs(1), Duration::from_secs(2))
    }

    /// Candidate TCP fallback ports of `ip`: its known open ports, else the common list.
    fn fallback_ports(&self, ip: &IpAddr) -> Vec<u16> {
        let mut ports: Vec<u16> = Vec::new();
        for p in self
            .tcp_ports
            .get(ip)
            .map(Vec::as_slice)
            .filter(|p| !p.is_empty())
            .unwrap_or(FALLBACK_TCP_PORTS)
        {
            if *p != 0 && !ports.contains(p) {
                ports.push(*p);
            }
            if ports.len() == MAX_TCP_PORTS_PER_HOST {
                break;
            }
        }
        ports
    }
}

static MONITORED_HOSTS: AtomicUsize = AtomicUsize::new(0);

/// A share of the process-wide host cap, released on drop.
#[derive(Debug)]
pub struct HostReservation(usize);

impl Drop for HostReservation {
    fn drop(&mut self) {
        MONITORED_HOSTS.fetch_sub(self.0, Ordering::AcqRel);
    }
}

/// Reserve `n` of the [`MAX_MONITORED_HOSTS`] slots.
pub fn reserve_hosts(n: usize) -> Result<HostReservation> {
    let mut cur = MONITORED_HOSTS.load(Ordering::Acquire);
    loop {
        if cur.saturating_add(n) > MAX_MONITORED_HOSTS {
            bail!(
                "{n} more host(s) would exceed the limit of {MAX_MONITORED_HOSTS} monitored \
                 hosts ({cur} already monitored); stop a monitor first"
            );
        }
        match MONITORED_HOSTS.compare_exchange_weak(
            cur,
            cur + n,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(HostReservation(n)),
            Err(actual) => cur = actual,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Probing
// ---------------------------------------------------------------------------------------------

/// TCP connect round trip to `ip:port` in milliseconds. A refused connection (RST) is an
/// answer too; only a timeout or an unreachable error counts as lost.
pub async fn tcp_rtt(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    budget: &SocketBudget,
) -> Option<f64> {
    let _permit = budget.acquire().await?;
    let start = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect((ip, port))).await {
        Ok(Ok(_stream)) => Some(start.elapsed().as_secs_f64() * 1000.0),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            Some(start.elapsed().as_secs_f64() * 1000.0)
        }
        _ => None,
    }
}

/// First port among `ports` that answers, with its round trip (probed concurrently).
async fn find_tcp_port(
    ip: IpAddr,
    ports: &[u16],
    timeout: Duration,
    budget: &SocketBudget,
) -> Option<(u16, f64)> {
    let mut probes: FuturesUnordered<_> = ports
        .iter()
        .map(|p| async move { tcp_rtt(ip, *p, timeout, budget).await.map(|r| (*p, r)) })
        .collect();
    while let Some(res) = probes.next().await {
        if res.is_some() {
            return res;
        }
    }
    None
}

/// Shared, per-monitor probing resources.
#[derive(Clone)]
struct Probe {
    v4: Option<Client>,
    v6: Option<Client>,
    ident: PingIdentifier,
    timeout: Duration,
    interval: Duration,
    count: Option<u32>,
    budget: SocketBudget,
}

type RawSample = (IpAddr, Option<f64>, u64, ProbeMethod);

/// Probe one host on every tick until `count` probes were sent or `cancel` fires.
async fn host_loop(
    ip: IpAddr,
    probe: Probe,
    fallback_ports: Vec<u16>,
    tx: mpsc::Sender<RawSample>,
    cancel: CancellationToken,
) {
    let client = match ip {
        IpAddr::V4(_) => probe.v4.as_ref(),
        IpAddr::V6(_) => probe.v6.as_ref(),
    };
    let mut pinger = match client {
        Some(c) => {
            let mut p = c.pinger(ip, probe.ident).await;
            p.timeout(probe.timeout);
            Some(p)
        }
        None => None,
    };
    let mut ticker = tokio::time::interval(probe.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut seq: u16 = 0;
    let mut icmp_seen = false;
    let mut misses = 0u32;
    let mut tcp_port: Option<u16> = None;
    let mut done = 0u32;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = ticker.tick() => {}
        }
        if probe.count.is_some_and(|c| done >= c) {
            return;
        }
        let ts = now_ms();
        let sample = match (&mut pinger, tcp_port) {
            (Some(p), None) => {
                let rtt = tokio::select! {
                    _ = cancel.cancelled() => return,
                    r = p.ping(PingSequence(seq), PING_PAYLOAD) => r.ok().map(|(_, d)| d.as_secs_f64() * 1000.0),
                };
                seq = seq.wrapping_add(1);
                match rtt {
                    Some(r) => {
                        icmp_seen = true;
                        misses = 0;
                        (Some(r), ProbeMethod::Icmp)
                    }
                    None => {
                        misses += 1;
                        // Search after a few misses, then only every few probes so dead
                        // hosts do not keep a burst of connects in flight on every tick.
                        let try_tcp = !icmp_seen
                            && !fallback_ports.is_empty()
                            && (misses == ICMP_MISSES_BEFORE_TCP
                                || (misses > ICMP_MISSES_BEFORE_TCP
                                    && misses.is_multiple_of(TCP_SEARCH_EVERY)));
                        let found = if try_tcp {
                            find_tcp_port(ip, &fallback_ports, probe.timeout, &probe.budget).await
                        } else {
                            None
                        };
                        match found {
                            Some((port, r)) => {
                                tcp_port = Some(port);
                                (Some(r), ProbeMethod::Tcp)
                            }
                            None => (None, ProbeMethod::Icmp),
                        }
                    }
                }
            }
            (_, Some(port)) => (
                tcp_rtt(ip, port, probe.timeout, &probe.budget).await,
                ProbeMethod::Tcp,
            ),
            // ICMP unavailable: TCP only, searching for an answering port (on the first probe,
            // then every few probes) until one is found.
            (None, None) => {
                misses += 1;
                let found = if misses == 1 || misses.is_multiple_of(TCP_SEARCH_EVERY) {
                    find_tcp_port(ip, &fallback_ports, probe.timeout, &probe.budget).await
                } else {
                    None
                };
                match found {
                    Some((port, r)) => {
                        tcp_port = Some(port);
                        (Some(r), ProbeMethod::Tcp)
                    }
                    None => (None, ProbeMethod::Tcp),
                }
            }
        };
        done += 1;
        if tx.send((ip, sample.0, ts, sample.1)).await.is_err() {
            return;
        }
    }
}

/// An ICMP client for one address family, holding a socket permit for its lifetime.
async fn icmp_client(
    kind: ICMP,
    budget: &SocketBudget,
) -> Option<(Client, tokio::sync::OwnedSemaphorePermit)> {
    let permit = budget.acquire().await?;
    let config = Config::builder().kind(kind).build();
    match Client::new(&config) {
        Ok(c) => Some((c, permit)),
        Err(e) => {
            tracing::debug!("ICMP socket unavailable ({kind:?}): {e}; using TCP round trips");
            None
        }
    }
}

/// Run a monitor until every host sent `cfg.count` probes or `cancel` fires. Sample batches
/// (hosts with a new sample since the previous batch, sorted by IP) go to `out` at most every
/// [`FLUSH_INTERVAL`]. Returns the final sample of every host.
pub async fn run_monitor(
    cfg: MonitorConfig,
    out: mpsc::Sender<Vec<LatencySample>>,
    cancel: CancellationToken,
) -> Result<Vec<LatencySample>> {
    run_monitor_with(cfg, out, cancel, SocketBudget::global()).await
}

/// [`run_monitor`] with an explicit socket budget.
pub async fn run_monitor_with(
    cfg: MonitorConfig,
    out: mpsc::Sender<Vec<LatencySample>>,
    cancel: CancellationToken,
    budget: &SocketBudget,
) -> Result<Vec<LatencySample>> {
    let reservation = reserve_hosts(cfg.ips.len())?;
    run_monitor_reserved(cfg, reservation, out, cancel, budget).await
}

/// [`run_monitor_with`] for a caller that already reserved the hosts (so a GUI command can
/// reject an over-limit request synchronously). The reservation is released on return.
pub async fn run_monitor_reserved(
    cfg: MonitorConfig,
    reservation: HostReservation,
    out: mpsc::Sender<Vec<LatencySample>>,
    cancel: CancellationToken,
    budget: &SocketBudget,
) -> Result<Vec<LatencySample>> {
    let _reservation = reservation;
    let want_v4 = cfg.icmp && cfg.ips.iter().any(IpAddr::is_ipv4);
    let want_v6 = cfg.icmp && cfg.ips.iter().any(IpAddr::is_ipv6);
    let v4 = if want_v4 {
        icmp_client(ICMP::V4, budget).await
    } else {
        None
    };
    let v6 = if want_v6 {
        icmp_client(ICMP::V6, budget).await
    } else {
        None
    };
    let probe = Probe {
        v4: v4.as_ref().map(|(c, _)| c.clone()),
        v6: v6.as_ref().map(|(c, _)| c.clone()),
        ident: PingIdentifier((std::process::id() as u16) ^ (now_ms() as u16).rotate_left(5)),
        timeout: cfg.probe_timeout(),
        interval: cfg.interval,
        count: cfg.count,
        budget: budget.clone(),
    };

    let (stx, mut srx) = mpsc::channel::<RawSample>(cfg.ips.len().clamp(64, 4096));
    let hosts_cancel = cancel.child_token();
    let mut tasks = JoinSet::new();
    for ip in &cfg.ips {
        tasks.spawn(host_loop(
            *ip,
            probe.clone(),
            cfg.fallback_ports(ip),
            stx.clone(),
            hosts_cancel.clone(),
        ));
    }
    drop(stx);

    let mut windows: BTreeMap<IpAddr, Window> = BTreeMap::new();
    let mut dirty: BTreeSet<IpAddr> = BTreeSet::new();
    let mut flush = tokio::time::interval(FLUSH_INTERVAL);
    flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let batch = |windows: &BTreeMap<IpAddr, Window>, dirty: &mut BTreeSet<IpAddr>| {
        let samples: Vec<LatencySample> = dirty
            .iter()
            .filter_map(|ip| windows.get(ip).map(|w| w.sample(*ip)))
            .collect();
        dirty.clear();
        samples
    };
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            next = srx.recv() => match next {
                Some((ip, rtt, ts, method)) => {
                    windows.entry(ip).or_default().push(rtt, ts, method);
                    dirty.insert(ip);
                }
                None => break, // every host finished its count
            },
            _ = flush.tick() => {
                if !dirty.is_empty() {
                    let samples = batch(&windows, &mut dirty);
                    if out.send(samples).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
    hosts_cancel.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    // Samples that arrived after the last flush.
    while let Ok((ip, rtt, ts, method)) = srx.try_recv() {
        windows.entry(ip).or_default().push(rtt, ts, method);
        dirty.insert(ip);
    }
    if !dirty.is_empty() {
        let samples = batch(&windows, &mut dirty);
        let _ = out.send(samples).await;
    }
    drop((v4, v6));
    Ok(windows.iter().map(|(ip, w)| w.sample(*ip)).collect())
}

/// Terminal sparkline of the last `width` samples (`·` = lost).
pub fn sparkline(history: &[Option<f64>], width: usize) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let tail = &history[history.len().saturating_sub(width)..];
    let replies = tail.iter().flatten().copied();
    let (lo, hi) = replies.fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), v| {
        (lo.min(v), hi.max(v))
    });
    tail.iter()
        .map(|s| match s {
            None => '·',
            Some(v) if hi > lo => {
                let idx = ((v - lo) / (hi - lo) * 7.0).round() as usize;
                BARS[idx.min(7)]
            }
            Some(_) => BARS[0],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn sparklines() {
        assert_eq!(
            sparkline(&[Some(1.0), None, Some(8.0), Some(4.5)], 10),
            "▁·█▅"
        );
        assert_eq!(sparkline(&[Some(2.0), Some(2.0)], 10), "▁▁");
        assert_eq!(sparkline(&[Some(1.0), Some(2.0), Some(3.0)], 2), "▁█");
        assert_eq!(sparkline(&[], 5), "");
    }

    #[test]
    fn statistics_over_a_window() {
        let s = summarize(&[Some(10.0), None, Some(20.0), Some(15.0), None]);
        assert_eq!((s.sent, s.received), (5, 3));
        assert!((s.loss_pct - 40.0).abs() < 1e-9);
        assert_eq!(s.avg, Some(15.0));
        assert_eq!((s.min, s.max), (Some(10.0), Some(20.0)));
        // |20-10| + |15-20| over 2 pairs.
        assert_eq!(s.jitter, Some(7.5));
        let empty = summarize(&[]);
        assert_eq!((empty.avg, empty.loss_pct, empty.sent), (None, 0.0, 0));
        let lost = summarize(&[None, None]);
        assert_eq!((lost.avg, lost.jitter, lost.loss_pct), (None, None, 100.0));
        assert_eq!(
            summarize(&[Some(3.0)]).jitter,
            None,
            "one reply has no jitter"
        );
    }

    #[test]
    fn window_is_a_bounded_ring() {
        let mut w = Window::default();
        for i in 0..(HISTORY_LEN + 30) {
            w.push(Some(i as f64), i as u64, ProbeMethod::Icmp);
        }
        w.push(None, 9_999, ProbeMethod::Tcp);
        w.push(Some(f64::NAN), 10_000, ProbeMethod::Tcp); // garbage is a loss
        assert_eq!(w.len(), HISTORY_LEN);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let s = w.sample(ip);
        assert_eq!(s.ip, ip);
        assert_eq!(s.history.len(), HISTORY_LEN);
        assert_eq!(s.rtt_ms, None);
        assert_eq!(s.ts, 10_000);
        assert_eq!(s.method, ProbeMethod::Tcp);
        assert_eq!(
            (s.sent, s.received),
            (HISTORY_LEN as u32, HISTORY_LEN as u32 - 2)
        );
        assert_eq!(s.history.first().copied().flatten(), Some(32.0));
        let stats = w.stats();
        assert_eq!(stats.updated_ms, 10_000);
        assert_eq!(stats.max_ms, Some((HISTORY_LEN + 29) as f64));
    }

    #[test]
    fn config_validation() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let cfg = MonitorConfig::new(vec![ip, ip], None).unwrap();
        assert_eq!(cfg.ips, vec![ip]);
        assert_eq!(cfg.interval, Duration::from_secs(1));
        assert_eq!(cfg.probe_timeout(), Duration::from_secs(1));
        assert!(MonitorConfig::new(vec![], None).is_err());
        assert!(MonitorConfig::new(vec![ip], Some(100)).is_err());
        assert!(MonitorConfig::new(vec![ip], Some(60_000)).is_err());
        assert!(MonitorConfig::new(vec!["0.0.0.0".parse().unwrap()], None).is_err());
        assert!(MonitorConfig::new(vec!["224.0.0.1".parse().unwrap()], None).is_err());
        let many: Vec<IpAddr> = (0..=MAX_MONITORED_HOSTS as u32)
            .map(|i| IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)))
            .collect();
        assert!(MonitorConfig::new(many, None).is_err());
        let slow = MonitorConfig::new(vec![ip], Some(10_000)).unwrap();
        assert_eq!(slow.probe_timeout(), Duration::from_secs(2));
        let mut c = cfg.clone();
        assert_eq!(c.fallback_ports(&ip), FALLBACK_TCP_PORTS);
        c.tcp_ports.insert(ip, vec![8080, 0, 8080, 22, 1, 2, 3]);
        assert_eq!(c.fallback_ports(&ip), vec![8080, 22, 1, 2]);
    }

    #[test]
    fn host_reservations_are_capped_and_released() {
        let a = reserve_hosts(MAX_MONITORED_HOSTS - 10).unwrap();
        assert!(reserve_hosts(MAX_MONITORED_HOSTS).is_err());
        drop(a);
        let b = reserve_hosts(5).unwrap();
        drop(b);
    }

    /// TCP fallback end to end: with ICMP off, a local listener's port gives round trips.
    #[tokio::test]
    async fn tcp_fallback_measures_a_local_listener() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                drop(s);
            }
        });
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut cfg = MonitorConfig::new(vec![ip], Some(MIN_INTERVAL_MS)).unwrap();
        cfg.icmp = false;
        cfg.count = Some(3);
        cfg.tcp_ports.insert(ip, vec![port]);
        let (tx, mut rx) = mpsc::channel(64);
        let fin = run_monitor_with(cfg, tx, CancellationToken::new(), &SocketBudget::new(4))
            .await
            .unwrap();
        accept.abort();
        assert_eq!(fin.len(), 1);
        let s = &fin[0];
        assert_eq!(s.method, ProbeMethod::Tcp);
        assert_eq!((s.sent, s.received), (3, 3));
        assert!(s.avg_ms.is_some() && s.loss_pct == 0.0);
        assert_eq!(s.history.len(), 3);
        let mut batches = 0;
        while let Ok(b) = rx.try_recv() {
            assert!(b.iter().all(|x| x.ip == ip));
            batches += 1;
        }
        assert!(batches >= 1);
    }

    /// Loopback ping: ICMP where the OS allows unprivileged echo sockets, otherwise the TCP
    /// fallback (RST from a closed loopback port also counts). Either way the host answers.
    #[tokio::test]
    async fn loopback_answers_and_monitor_stops_on_cancel() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut cfg = MonitorConfig::new(vec![ip], Some(MIN_INTERVAL_MS)).unwrap();
        cfg.count = Some(2);
        let (tx, _rx) = mpsc::channel(64);
        let fin = run_monitor_with(cfg, tx, CancellationToken::new(), &SocketBudget::new(4))
            .await
            .unwrap();
        assert_eq!(fin.len(), 1);
        assert!(fin[0].received >= 1, "{:?}", fin[0]);

        // Without a count the monitor runs until cancelled.
        let cfg = MonitorConfig::new(vec![ip], Some(MIN_INTERVAL_MS)).unwrap();
        let (tx, _rx) = mpsc::channel(64);
        let cancel = CancellationToken::new();
        let stopper = {
            let c = cancel.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(700)).await;
                c.cancel();
            })
        };
        let fin = tokio::time::timeout(
            Duration::from_secs(5),
            run_monitor_with(cfg, tx, cancel, &SocketBudget::new(4)),
        )
        .await
        .expect("monitor must stop when cancelled")
        .unwrap();
        stopper.await.unwrap();
        assert!(fin.len() <= 1);
    }
}
