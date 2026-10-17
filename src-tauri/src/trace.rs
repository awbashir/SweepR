//! MTR-style traceroute: hop-by-hop path with per-hop loss / last / avg / best / worst over
//! several rounds, streamed as [`TraceUpdate`] snapshots.
//!
//! Two probe engines:
//!
//! * **Raw** ([`TraceMethod::Raw`]): ICMP / ICMPv6 echo requests with increasing TTL on a raw
//!   socket, matching the Time Exceeded / Destination Unreachable / Echo Reply messages that
//!   come back. Opening a raw socket needs root (or `CAP_NET_RAW` on Linux).
//! * **System** ([`TraceMethod::System`]): without that privilege, an unprivileged socket
//!   never sees ICMP Time Exceeded, so the system tool runs once per round:
//!   `traceroute -n -q 1 -w 1 -m <max> <ip>` (macOS ships a setuid `/usr/sbin/traceroute`
//!   and `traceroute6`; Linux uses `traceroute` or, failing that, `tracepath`). On Windows
//!   this is always the engine: `tracert -d -h <max> -w 1000 <ip>` (`System32\tracert.exe`,
//!   no Administrator rights needed; it sends three probes per hop, so each round adds three
//!   samples per hop). The target is always a validated IP literal and arguments are passed
//!   as a vector, never through a shell, so nothing can be injected. The output parsers are
//!   bounded and hostile-input safe.
//!
//! Hop names come from reverse DNS through the system resolver ([`PtrResolver`]).

use std::{
    collections::{BTreeMap, HashSet},
    ffi::OsString,
    io,
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::Command,
    sync::mpsc,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use crate::{
    enricher::PtrResolver,
    models::{sanitize_text, TraceHop, TraceMethod, TraceUpdate},
};

pub const DEFAULT_MAX_HOPS: u8 = 30;
pub const MAX_HOPS_CAP: u8 = 64;
pub const DEFAULT_ROUNDS: u32 = 5;
pub const MAX_ROUNDS: u32 = 100;
/// How long each probe waits for its answer.
const PROBE_WAIT: Duration = Duration::from_secs(1);
/// Minimum spacing of rounds (one probe per hop per second, like `mtr`).
const ROUND_SPACING: Duration = Duration::from_secs(1);
/// Minimum spacing of streamed updates (≤ 4 per second).
const UPDATE_INTERVAL: Duration = Duration::from_millis(250);
/// Parser bounds for the system tool's output.
const MAX_LINE_LEN: usize = 1024;
const MAX_TOKENS: usize = 64;
const MAX_OUTPUT_BYTES: u64 = 256 * 1024;
const MAX_RTT_MS: f64 = 60_000.0;
/// Extra addresses remembered per hop (load-balanced paths).
const MAX_OTHER_IPS: usize = 4;
/// Reverse lookups per trace.
const MAX_LOOKUPS: usize = 128;

// ---------------------------------------------------------------------------------------------
// Options & validation
// ---------------------------------------------------------------------------------------------

/// What to trace and how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceOptions {
    pub max_hops: u8,
    pub rounds: u32,
    /// Reverse-resolve hop addresses.
    pub resolve: bool,
}

impl TraceOptions {
    /// Validated options (`None` = defaults: 30 hops, 5 rounds).
    pub fn new(max_hops: Option<u8>, rounds: Option<u32>) -> Result<Self> {
        let max_hops = max_hops.unwrap_or(DEFAULT_MAX_HOPS);
        if !(1..=MAX_HOPS_CAP).contains(&max_hops) {
            bail!("max hops must be 1-{MAX_HOPS_CAP} (got {max_hops})");
        }
        let rounds = rounds.unwrap_or(DEFAULT_ROUNDS);
        if !(1..=MAX_ROUNDS).contains(&rounds) {
            bail!("rounds must be 1-{MAX_ROUNDS} (got {rounds})");
        }
        Ok(Self {
            max_hops,
            rounds,
            resolve: true,
        })
    }
}

/// Parse a trace target: an IP literal only (no host names, no flags), and one that can be
/// traced to (not unspecified, multicast or broadcast).
pub fn parse_target(s: &str) -> Result<IpAddr> {
    let ip: IpAddr = s.trim().parse().map_err(|_| {
        anyhow::anyhow!(
            "'{}' is not an IP address (host names are not accepted)",
            sanitize_text(s)
        )
    })?;
    let bad = match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_multicast(),
    };
    if bad {
        bail!("{ip} cannot be traced");
    }
    Ok(ip)
}

// ---------------------------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------------------------

/// One probe result: the probe with `ttl` was answered by `ip` after `rtt_ms`, or lost
/// (`ip` and `rtt_ms` both `None`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HopObservation {
    pub ttl: u8,
    pub ip: Option<IpAddr>,
    pub rtt_ms: Option<f64>,
}

#[derive(Debug, Clone, Default)]
struct HopAcc {
    ip: Option<IpAddr>,
    other_ips: Vec<IpAddr>,
    hostname: Option<String>,
    sent: u32,
    received: u32,
    last: Option<f64>,
    sum: f64,
    timed: u32,
    best: Option<f64>,
    worst: Option<f64>,
}

/// MTR-style per-hop accumulator.
#[derive(Debug, Clone)]
pub struct TraceStats {
    target: IpAddr,
    max_hops: u8,
    hops: BTreeMap<u8, HopAcc>,
    dest_ttl: Option<u8>,
}

impl TraceStats {
    pub fn new(target: IpAddr, max_hops: u8) -> Self {
        Self {
            target,
            max_hops,
            hops: BTreeMap::new(),
            dest_ttl: None,
        }
    }

    /// Fold one probe result in. Returns the responding address when it is new to the trace
    /// (so its name can be looked up).
    pub fn record(&mut self, obs: HopObservation) -> Option<IpAddr> {
        if obs.ttl == 0 || obs.ttl > self.max_hops {
            return None;
        }
        let rtt = obs
            .rtt_ms
            .filter(|r| r.is_finite() && (0.0..=MAX_RTT_MS).contains(r));
        let known_before = obs.ip.is_some_and(|ip| {
            self.hops
                .values()
                .any(|h| h.ip == Some(ip) || h.other_ips.contains(&ip))
        });
        let hop = self.hops.entry(obs.ttl).or_default();
        hop.sent = hop.sent.saturating_add(1);
        if let Some(ip) = obs.ip {
            hop.received = hop.received.saturating_add(1);
            match hop.ip {
                Some(cur) if cur != ip => {
                    if !hop.other_ips.contains(&cur) && hop.other_ips.len() < MAX_OTHER_IPS {
                        hop.other_ips.push(cur);
                    }
                    hop.other_ips.retain(|o| *o != ip);
                    hop.ip = Some(ip);
                    hop.hostname = None;
                }
                Some(_) => {}
                None => hop.ip = Some(ip),
            }
            if let Some(r) = rtt {
                hop.last = Some(r);
                hop.sum += r;
                hop.timed += 1;
                hop.best = Some(hop.best.map_or(r, |b| b.min(r)));
                hop.worst = Some(hop.worst.map_or(r, |w| w.max(r)));
            }
            if ip == self.target {
                self.dest_ttl = Some(self.dest_ttl.map_or(obs.ttl, |d| d.min(obs.ttl)));
            }
        }
        obs.ip.filter(|_| !known_before)
    }

    /// Attach a reverse-DNS name to every hop currently answering from `ip`.
    pub fn set_hostname(&mut self, ip: IpAddr, name: &str) {
        for hop in self.hops.values_mut() {
            if hop.ip == Some(ip) {
                hop.hostname = Some(name.to_string());
            }
        }
    }

    /// `true` once the destination answered.
    pub fn reached(&self) -> bool {
        self.dest_ttl.is_some()
    }

    /// TTL of the destination (once reached).
    pub fn dest_ttl(&self) -> Option<u8> {
        self.dest_ttl
    }

    /// Hops 1..=N (N = the destination's TTL, or the highest TTL probed so far).
    pub fn hops(&self) -> Vec<TraceHop> {
        let last = self
            .dest_ttl
            .or_else(|| self.hops.keys().next_back().copied())
            .unwrap_or(0);
        (1..=last)
            .map(|ttl| {
                let h = self.hops.get(&ttl).cloned().unwrap_or_default();
                let loss = if h.sent == 0 {
                    0.0
                } else {
                    f64::from(h.sent - h.received.min(h.sent)) * 100.0 / f64::from(h.sent)
                };
                let r3 = |v: f64| (v * 1000.0).round() / 1000.0;
                TraceHop {
                    ttl,
                    ip: h.ip,
                    hostname: h.hostname,
                    other_ips: h.other_ips,
                    sent: h.sent,
                    received: h.received,
                    loss_pct: r3(loss),
                    last_ms: h.last,
                    avg_ms: (h.timed > 0).then(|| r3(h.sum / f64::from(h.timed))),
                    best_ms: h.best,
                    worst_ms: h.worst,
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------------------------
// System traceroute output parsers (hostile-input safe)
// ---------------------------------------------------------------------------------------------

fn parse_rtt(s: &str) -> Option<f64> {
    if s.is_empty() || s.len() > 16 || !s.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }
    s.parse::<f64>()
        .ok()
        .filter(|v| v.is_finite() && (0.0..=MAX_RTT_MS).contains(v))
}

fn parse_ip_token(s: &str) -> Option<IpAddr> {
    let s = s.trim_start_matches('(').trim_end_matches(')');
    // IPv6 link-local hops can carry a zone (`fe80::1%en0`).
    let s = s.split('%').next().unwrap_or(s);
    if s.len() > 45 {
        return None;
    }
    s.parse().ok()
}

fn parse_ttl(s: &str, max_hops: u8) -> Option<u8> {
    if s.is_empty() || s.len() > 3 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u8>().ok().filter(|t| (1..=max_hops).contains(t))
}

/// Parse one hop line of BSD / macOS or Linux `traceroute` (`-n`, any `-q`):
///
/// ```text
///  1  192.168.1.1  0.512 ms
///  2  *
///  3  10.0.0.1  4.2 ms !H
///  4  10.1.1.1  5.1 ms  10.1.1.2  5.3 ms
///  5  router.example (10.2.2.2)  6.0 ms
/// ```
///
/// Returns one observation per probe on the line, or `None` for anything else (the header
/// line, blank lines, garbage, TTLs outside `1..=max_hops`).
pub fn parse_traceroute_line(line: &str, max_hops: u8) -> Option<Vec<HopObservation>> {
    if line.len() > MAX_LINE_LEN {
        return None;
    }
    let tokens: Vec<&str> = line.split_whitespace().take(MAX_TOKENS + 1).collect();
    if tokens.len() > MAX_TOKENS || tokens.len() < 2 {
        return None;
    }
    let ttl = parse_ttl(tokens[0], max_hops)?;
    let mut out = Vec::new();
    let mut current: Option<IpAddr> = None;
    let mut i = 1;
    while i < tokens.len() {
        let t = tokens[i];
        if t == "*" {
            out.push(HopObservation {
                ttl,
                ip: None,
                rtt_ms: None,
            });
        } else if let Some(ip) = parse_ip_token(t) {
            current = Some(ip);
        } else if let Some(num) = t.strip_suffix("ms").filter(|n| !n.is_empty()) {
            // "0.512ms" (no space).
            if let (Some(rtt), Some(ip)) = (parse_rtt(num), current) {
                out.push(HopObservation {
                    ttl,
                    ip: Some(ip),
                    rtt_ms: Some(rtt),
                });
            }
        } else if let Some(rtt) = parse_rtt(t) {
            if tokens.get(i + 1) == Some(&"ms") {
                i += 1;
                if let Some(ip) = current {
                    out.push(HopObservation {
                        ttl,
                        ip: Some(ip),
                        rtt_ms: Some(rtt),
                    });
                }
            }
        }
        // Anything else (host names, `!H` / `!N` / `!X` annotations, `<syn,ack>`) is skipped.
        i += 1;
    }
    (!out.is_empty()).then_some(out)
}

/// One probe column of Windows `tracert`: `<1` / `12` followed by a unit token (`ms`, or a
/// localized one). `<1 ms` is recorded as 0.5 ms (tracert's resolution is 1 ms).
fn parse_tracert_rtt(value: &str, unit: Option<&&str>) -> Option<f64> {
    let unit = unit?;
    let is_unit = !unit.is_empty()
        && *unit != "*"
        && !unit.bytes().all(|b| b.is_ascii_digit())
        && !unit.starts_with('<')
        && parse_ip_token(unit).is_none();
    if !is_unit {
        return None;
    }
    if value == "<1" {
        return Some(0.5);
    }
    if value.is_empty() || value.len() > 6 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    parse_rtt(value)
}

/// Parse one hop line of Windows `tracert -d` (any language: only the shape is used):
///
/// ```text
///   1    <1 ms    <1 ms    <1 ms  192.168.1.1
///   2     9 ms     8 ms     *     100.64.0.1
///   3     *        *        *     Request timed out.
///   4  192.168.1.1  reports: Destination host unreachable.
/// ```
///
/// Returns one observation per probe column (`*` = lost); a "reports: ... unreachable" line
/// is one answered probe without a round-trip time. Header, footer and error lines
/// ("Transmit error: code 1231.") give `None`.
pub fn parse_tracert_line(line: &str, max_hops: u8) -> Option<Vec<HopObservation>> {
    if line.len() > MAX_LINE_LEN {
        return None;
    }
    let tokens: Vec<&str> = line.split_whitespace().take(MAX_TOKENS + 1).collect();
    if tokens.len() > MAX_TOKENS || tokens.len() < 2 {
        return None;
    }
    let ttl = parse_ttl(tokens[0], max_hops)?;
    let mut probes: Vec<Option<f64>> = Vec::new();
    let mut ip: Option<IpAddr> = None;
    let mut i = 1;
    while i < tokens.len() {
        let t = tokens[i];
        if t == "*" {
            probes.push(None);
        } else if let Some(rtt) = parse_tracert_rtt(t, tokens.get(i + 1)) {
            probes.push(Some(rtt));
            i += 1; // the unit
        } else if ip.is_none() {
            ip = parse_ip_token(t);
        }
        i += 1;
    }
    let lost = HopObservation {
        ttl,
        ip: None,
        rtt_ms: None,
    };
    let out: Vec<HopObservation> = match ip {
        Some(ip) if probes.is_empty() => vec![HopObservation {
            ttl,
            ip: Some(ip),
            rtt_ms: None,
        }],
        Some(ip) => probes
            .iter()
            .map(|p| match p {
                Some(rtt) => HopObservation {
                    ttl,
                    ip: Some(ip),
                    rtt_ms: Some(*rtt),
                },
                None => lost,
            })
            .collect(),
        // Without an address only losses can be attributed.
        None => probes
            .iter()
            .filter(|p| p.is_none())
            .map(|_| lost)
            .collect(),
    };
    (!out.is_empty()).then_some(out)
}

/// Parse one line of Linux `tracepath -n`:
///
/// ```text
///  1?: [LOCALHOST]                      pmtu 1500
///  1:  192.168.1.1                                           0.512ms
///  2:  no reply
///  4:  8.8.8.8                                              12.345ms reached
///      Resume: pmtu 1500 hops 4 back 4
/// ```
pub fn parse_tracepath_line(line: &str, max_hops: u8) -> Option<HopObservation> {
    if line.len() > MAX_LINE_LEN {
        return None;
    }
    let tokens: Vec<&str> = line.split_whitespace().take(MAX_TOKENS + 1).collect();
    if tokens.len() > MAX_TOKENS || tokens.len() < 2 {
        return None;
    }
    let ttl_token = tokens[0].strip_suffix(':')?.trim_end_matches('?');
    let ttl = parse_ttl(ttl_token, max_hops)?;
    if tokens[1] == "[LOCALHOST]" {
        return None;
    }
    if tokens[1] == "no" && tokens.get(2) == Some(&"reply") {
        return Some(HopObservation {
            ttl,
            ip: None,
            rtt_ms: None,
        });
    }
    let ip = tokens[1..].iter().take(2).find_map(|t| parse_ip_token(t))?;
    let rtt = tokens
        .iter()
        .skip(2)
        .find_map(|t| t.strip_suffix("ms").and_then(parse_rtt));
    Some(HopObservation {
        ttl,
        ip: Some(ip),
        rtt_ms: rtt,
    })
}

// ---------------------------------------------------------------------------------------------
// System tool discovery & execution
// ---------------------------------------------------------------------------------------------

/// Output format of the system tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Traceroute,
    Tracepath,
    /// Windows `tracert`.
    Tracert,
}

/// A system traceroute program and the arguments for one round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemTracer {
    pub program: PathBuf,
    pub flavor: Flavor,
    /// Leading arguments (e.g. `-6`).
    pub extra: Vec<&'static str>,
}

impl SystemTracer {
    /// Full argument vector for one round towards `target` (never via a shell).
    pub fn args(&self, target: IpAddr, max_hops: u8) -> Vec<OsString> {
        let mut args: Vec<OsString> = self.extra.iter().map(OsString::from).collect();
        match self.flavor {
            Flavor::Traceroute => {
                for a in ["-n", "-q", "1", "-w", "1", "-m"] {
                    args.push(a.into());
                }
            }
            Flavor::Tracepath => {
                for a in ["-n", "-m"] {
                    args.push(a.into());
                }
            }
            Flavor::Tracert => {
                // -d: no reverse DNS (hop names come from our resolver); -w: ms per probe.
                for a in ["-d", "-w", "1000", "-h"] {
                    args.push(a.into());
                }
            }
        }
        args.push(max_hops.to_string().into());
        args.push(target.to_string().into());
        args
    }
}

fn find_program(name: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
        .iter()
        .map(PathBuf::from)
        .collect();
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path).filter(|p| p.is_absolute()));
    }
    dirs.into_iter()
        .map(|d| d.join(name))
        .find(|p| is_executable(p))
}

fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

/// The system traceroute for `v6` targets, if one is installed.
pub fn find_system_tracer(v6: bool) -> Option<SystemTracer> {
    let tracer = |program, flavor, extra| SystemTracer {
        program,
        flavor,
        extra,
    };
    if cfg!(windows) {
        let program = crate::platform::system32_tool("TRACERT.EXE");
        let family = if v6 { "-6" } else { "-4" };
        return is_executable(&program).then(|| tracer(program, Flavor::Tracert, vec![family]));
    }
    if v6 {
        if let Some(p) = find_program("traceroute6") {
            return Some(tracer(p, Flavor::Traceroute, vec![]));
        }
        if cfg!(target_os = "linux") {
            if let Some(p) = find_program("traceroute") {
                return Some(tracer(p, Flavor::Traceroute, vec!["-6"]));
            }
            if let Some(p) = find_program("tracepath6") {
                return Some(tracer(p, Flavor::Tracepath, vec![]));
            }
            if let Some(p) = find_program("tracepath") {
                return Some(tracer(p, Flavor::Tracepath, vec!["-6"]));
            }
        }
        return None;
    }
    if let Some(p) = find_program("traceroute") {
        return Some(tracer(p, Flavor::Traceroute, vec![]));
    }
    find_program("tracepath").map(|p| tracer(p, Flavor::Tracepath, vec![]))
}

/// Messages from a probe engine to the trace loop.
#[derive(Debug)]
enum Msg {
    Obs(HopObservation),
    RoundDone(u32),
    Failed(String),
}

/// Run one round of the system tool, forwarding every parsed probe. Returns the number of
/// probes seen.
async fn system_round(
    tracer: &SystemTracer,
    target: IpAddr,
    max_hops: u8,
    tx: &mpsc::Sender<Msg>,
    cancel: &CancellationToken,
) -> Result<usize> {
    let mut cmd = Command::new(&tracer.program);
    let mut child = crate::platform::hide_console(&mut cmd)
        .args(tracer.args(target, max_hops))
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| anyhow::anyhow!("cannot run {}: {e}", tracer.program.display()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("no stdout"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("no stderr"))?;
    let err_reader = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = (&mut stderr).take(16 * 1024).read_to_end(&mut buf).await;
        buf
    });
    let mut lines = BufReader::new(stdout.take(MAX_OUTPUT_BYTES)).lines();
    // tracert sends three probes per hop, each waiting up to PROBE_WAIT.
    let per_hop = match tracer.flavor {
        Flavor::Tracert => 3.2,
        Flavor::Traceroute | Flavor::Tracepath => 1.5,
    };
    let deadline = tokio::time::Instant::now()
        + PROBE_WAIT.mul_f64(f64::from(max_hops) * per_hop)
        + Duration::from_secs(5);
    let mut seen = 0usize;
    loop {
        let line = tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep_until(deadline) => break,
            l = lines.next_line() => l,
        };
        let line = match line {
            Ok(Some(l)) => l,
            Ok(None) => break,
            // Invalid UTF-8 or I/O error: stop reading this round.
            Err(_) => break,
        };
        let obs: Vec<HopObservation> = match tracer.flavor {
            Flavor::Traceroute => parse_traceroute_line(&line, max_hops).unwrap_or_default(),
            Flavor::Tracepath => parse_tracepath_line(&line, max_hops).into_iter().collect(),
            Flavor::Tracert => parse_tracert_line(&line, max_hops).unwrap_or_default(),
        };
        for o in obs {
            seen += 1;
            if tx.send(Msg::Obs(o)).await.is_err() {
                return Ok(seen);
            }
        }
    }
    let _ = child.start_kill();
    let status = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    let stderr = tokio::time::timeout(Duration::from_secs(1), err_reader)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    if seen == 0 && !cancel.is_cancelled() {
        let msg = sanitize_text(&String::from_utf8_lossy(&stderr));
        let failed = !matches!(status, Ok(Ok(s)) if s.success());
        if failed || !msg.is_empty() {
            bail!(
                "{} failed{}",
                tracer.program.display(),
                if msg.is_empty() {
                    String::new()
                } else {
                    format!(": {msg}")
                }
            );
        }
    }
    Ok(seen)
}

async fn system_worker(
    tracer: SystemTracer,
    target: IpAddr,
    opts: TraceOptions,
    tx: mpsc::Sender<Msg>,
    cancel: CancellationToken,
) {
    for round in 1..=opts.rounds {
        if cancel.is_cancelled() {
            return;
        }
        let started = tokio::time::Instant::now();
        match system_round(&tracer, target, opts.max_hops, &tx, &cancel).await {
            Ok(_) => {}
            Err(e) => {
                let _ = tx.send(Msg::Failed(format!("{e:#}"))).await;
                return;
            }
        }
        if cancel.is_cancelled() {
            return;
        }
        let _ = tx.send(Msg::RoundDone(round)).await;
        if round < opts.rounds {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep_until(started + ROUND_SPACING) => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Raw ICMP engine (root / CAP_NET_RAW)
// ---------------------------------------------------------------------------------------------

/// What an ICMP message says about one of our probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpKind {
    /// The destination answered.
    EchoReply,
    /// A router on the path dropped the probe (TTL expired).
    TimeExceeded,
    /// Destination / route unreachable.
    Unreachable,
}

/// Internet checksum (RFC 1071).
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
        sum = sum.wrapping_add(u32::from(word));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

const PROBE_PAYLOAD: &[u8; 16] = b"SweepR-trace\0\0\0\0";

/// ICMPv4 echo request with checksum.
pub fn build_echo_v4(ident: u16, seq: u16) -> Vec<u8> {
    let mut pkt = vec![8, 0, 0, 0];
    pkt.extend_from_slice(&ident.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(PROBE_PAYLOAD);
    let c = checksum(&pkt);
    pkt[2..4].copy_from_slice(&c.to_be_bytes());
    pkt
}

/// ICMPv6 echo request (the kernel fills in the checksum on raw ICMPv6 sockets).
pub fn build_echo_v6(ident: u16, seq: u16) -> Vec<u8> {
    let mut pkt = vec![128, 0, 0, 0];
    pkt.extend_from_slice(&ident.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(PROBE_PAYLOAD);
    pkt
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

/// Parse a packet read from a raw IPv4 ICMP socket (starts with the IPv4 header), received
/// from `from`. Returns what it says about our probe `seq`: an Echo Reply counts only when it
/// comes from `target` with our `ident`; errors must quote a probe of ours to `target`.
pub fn parse_icmp_v4(
    buf: &[u8],
    ident: u16,
    target: Ipv4Addr,
    from: Ipv4Addr,
) -> Option<(IcmpKind, u16)> {
    let first = *buf.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(first & 0x0f) * 4;
    if ihl < 20 {
        return None;
    }
    let icmp = buf.get(ihl..)?;
    match *icmp.first()? {
        0 => {
            // Echo reply: id / seq follow type, code and checksum.
            (from == target && be16(icmp, 4)? == ident)
                .then_some((IcmpKind::EchoReply, be16(icmp, 6)?))
        }
        t @ (3 | 11) => {
            // Quoted original datagram: IPv4 header + the first 8 bytes of our echo.
            let inner = icmp.get(8..)?;
            let ifirst = *inner.first()?;
            if ifirst >> 4 != 4 {
                return None;
            }
            let iihl = usize::from(ifirst & 0x0f) * 4;
            if iihl < 20 || *inner.get(9)? != 1 {
                return None; // not ICMP
            }
            let dst = Ipv4Addr::new(
                *inner.get(16)?,
                *inner.get(17)?,
                *inner.get(18)?,
                *inner.get(19)?,
            );
            let orig = inner.get(iihl..)?;
            if dst != target || *orig.first()? != 8 || be16(orig, 4)? != ident {
                return None;
            }
            let kind = if t == 11 {
                IcmpKind::TimeExceeded
            } else {
                IcmpKind::Unreachable
            };
            Some((kind, be16(orig, 6)?))
        }
        _ => None,
    }
}

/// Parse a packet read from a raw ICMPv6 socket (no IPv6 header), received from `from`
/// (same rules as [`parse_icmp_v4`]).
pub fn parse_icmp_v6(
    buf: &[u8],
    ident: u16,
    target: Ipv6Addr,
    from: Ipv6Addr,
) -> Option<(IcmpKind, u16)> {
    match *buf.first()? {
        129 => (from == target && be16(buf, 4)? == ident)
            .then_some((IcmpKind::EchoReply, be16(buf, 6)?)),
        t @ (1 | 3) => {
            // Quoted packet: IPv6 header (40 bytes) + our echo request.
            let inner = buf.get(8..)?;
            if *inner.first()? >> 4 != 6 || *inner.get(6)? != 58 {
                return None;
            }
            let dst: [u8; 16] = inner.get(24..40)?.try_into().ok()?;
            let orig = inner.get(40..)?;
            if Ipv6Addr::from(dst) != target || *orig.first()? != 128 || be16(orig, 4)? != ident {
                return None;
            }
            let kind = if t == 3 {
                IcmpKind::TimeExceeded
            } else {
                IcmpKind::Unreachable
            };
            Some((kind, be16(orig, 6)?))
        }
        _ => None,
    }
}

/// Sequence number of the probe for `round` (0-based) and `ttl`.
fn encode_seq(round: u32, ttl: u8) -> u16 {
    ((round % 1000) * u32::from(MAX_HOPS_CAP) + u32::from(ttl - 1)) as u16
}

fn decode_ttl(seq: u16) -> u8 {
    (seq % u16::from(MAX_HOPS_CAP)) as u8 + 1
}

/// Open the raw ICMP socket for `target`. Fails with `EPERM` / `EACCES` without privileges.
pub fn open_raw(target: IpAddr) -> io::Result<Socket> {
    let sock = match target {
        IpAddr::V4(_) => Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?,
        IpAddr::V6(_) => Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?,
    };
    sock.set_read_timeout(Some(Duration::from_millis(50)))?;
    Ok(sock)
}

/// A distinct ICMP identifier per trace (concurrent traces in one process must not take each
/// other's replies).
fn next_ident() -> u16 {
    static NEXT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    ((std::process::id() as u16) ^ 0x5357).wrapping_add(n.wrapping_mul(0x9e37))
}

/// Raw engine: one echo probe per TTL per round on a blocking thread.
fn raw_worker(
    sock: Socket,
    target: IpAddr,
    opts: TraceOptions,
    tx: mpsc::Sender<Msg>,
    cancel: CancellationToken,
) {
    let ident = next_ident();
    let dest: SockAddr = SocketAddr::new(target, 0).into();
    let mut dest_ttl: Option<u8> = None;
    let mut buf = vec![0u8; 2048];
    for round in 0..opts.rounds {
        if cancel.is_cancelled() {
            return;
        }
        let started = Instant::now();
        let limit = dest_ttl.unwrap_or(opts.max_hops);
        let mut pending: BTreeMap<u16, Instant> = BTreeMap::new();
        for ttl in 1..=limit {
            let set = match target {
                IpAddr::V4(_) => sock.set_ttl_v4(u32::from(ttl)),
                IpAddr::V6(_) => sock.set_unicast_hops_v6(u32::from(ttl)),
            };
            let seq = encode_seq(round, ttl);
            let pkt = match target {
                IpAddr::V4(_) => build_echo_v4(ident, seq),
                IpAddr::V6(_) => build_echo_v6(ident, seq),
            };
            if let Err(e) = set.and_then(|_| sock.send_to(&pkt, &dest)) {
                let _ = tx.blocking_send(Msg::Failed(format!("raw ICMP send failed: {e}")));
                return;
            }
            pending.insert(seq, Instant::now());
            std::thread::sleep(Duration::from_millis(5));
        }
        let deadline = Instant::now() + PROBE_WAIT;
        while !pending.is_empty() && Instant::now() < deadline && !cancel.is_cancelled() {
            // SAFETY: `buf` is fully initialized; viewing it as `MaybeUninit<u8>` only
            // allows `recv_from` to overwrite bytes, never to de-initialize them.
            let uninit =
                unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
            let (n, from) = match sock.recv_from(uninit) {
                Ok(r) => r,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                Err(e) => {
                    let _ = tx.blocking_send(Msg::Failed(format!("raw ICMP receive failed: {e}")));
                    return;
                }
            };
            let received_at = Instant::now();
            let data = &buf[..n.min(buf.len())];
            let Some(from) = from.as_socket().map(|s| s.ip()) else {
                continue;
            };
            let parsed = match (target, from) {
                (IpAddr::V4(t), IpAddr::V4(f)) => parse_icmp_v4(data, ident, t, f),
                (IpAddr::V6(t), IpAddr::V6(f)) => parse_icmp_v6(data, ident, t, f),
                _ => None,
            };
            let Some((kind, seq)) = parsed else { continue };
            let Some(sent_at) = pending.remove(&seq) else {
                continue;
            };
            let ttl = decode_ttl(seq);
            if kind != IcmpKind::TimeExceeded && from == target {
                dest_ttl = Some(dest_ttl.map_or(ttl, |d| d.min(ttl)));
            }
            let rtt = received_at.saturating_duration_since(sent_at).as_secs_f64() * 1000.0;
            let obs = HopObservation {
                ttl,
                ip: Some(from),
                rtt_ms: Some(rtt),
            };
            if tx.blocking_send(Msg::Obs(obs)).is_err() {
                return;
            }
        }
        for seq in pending.into_keys() {
            let ttl = decode_ttl(seq);
            if dest_ttl.is_some_and(|d| ttl > d) {
                continue; // beyond the destination: not a loss
            }
            let obs = HopObservation {
                ttl,
                ip: None,
                rtt_ms: None,
            };
            if tx.blocking_send(Msg::Obs(obs)).is_err() {
                return;
            }
        }
        if tx.blocking_send(Msg::RoundDone(round + 1)).is_err() {
            return;
        }
        if round + 1 < opts.rounds {
            while started.elapsed() < ROUND_SPACING && !cancel.is_cancelled() {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Trace loop
// ---------------------------------------------------------------------------------------------

fn snapshot(
    trace_id: u64,
    target: IpAddr,
    method: TraceMethod,
    stats: &TraceStats,
    round: u32,
    rounds: u32,
) -> TraceUpdate {
    TraceUpdate {
        trace_id,
        target,
        method,
        round,
        rounds,
        hops: stats.hops(),
        reached: stats.reached(),
        done: false,
        error: None,
    }
}

/// Run a trace to `target`, sending throttled snapshots to `tx` and always finishing with
/// one `done: true` update (carrying `error` when the trace could not run). Returns that
/// final update.
pub async fn run_trace(
    target: IpAddr,
    opts: TraceOptions,
    trace_id: u64,
    tx: mpsc::Sender<TraceUpdate>,
    cancel: CancellationToken,
) -> TraceUpdate {
    let mut stats = TraceStats::new(target, opts.max_hops);
    let (mtx, mut mrx) = mpsc::channel::<Msg>(1024);
    let worker_cancel = cancel.child_token();

    // Raw sockets when privileged, else the system tool. Windows always uses tracert: raw
    // ICMP sockets there need Administrator rights, an explicit bind and a firewall rule
    // before Time Exceeded messages arrive.
    let raw = if cfg!(windows) {
        Err(io::Error::other("raw ICMP sockets are not used on Windows"))
    } else {
        open_raw(target)
    };
    let (method, worker) = match raw {
        Ok(sock) => {
            let (o, c, m) = (opts, worker_cancel.clone(), mtx.clone());
            let h = tokio::task::spawn_blocking(move || raw_worker(sock, target, o, m, c));
            (TraceMethod::Raw, Some(h))
        }
        Err(e) => {
            tracing::debug!("raw ICMP socket unavailable ({e}); using the system traceroute");
            match find_system_tracer(target.is_ipv6()) {
                Some(tracer) => {
                    let (c, m) = (worker_cancel.clone(), mtx.clone());
                    let h = tokio::spawn(system_worker(tracer, target, opts, m, c));
                    (TraceMethod::System, Some(h))
                }
                None => (TraceMethod::System, None),
            }
        }
    };
    drop(mtx);
    let mut error = worker.is_none().then(|| {
        if cfg!(windows) {
            "tracert.exe was not found in the Windows system directory".to_string()
        } else if cfg!(target_os = "linux") {
            "no traceroute tool found: install `traceroute` (or `iputils-tracepath`), or run \
             SweepR as root / with CAP_NET_RAW"
                .to_string()
        } else {
            "no traceroute tool found (/usr/sbin/traceroute); run SweepR as root to use raw \
             sockets"
                .to_string()
        }
    });

    let resolver = if opts.resolve && worker.is_some() {
        PtrResolver::system(Duration::from_millis(1500))
    } else {
        None
    };
    let mut lookups: JoinSet<(IpAddr, Option<String>)> = JoinSet::new();
    let mut looked_up: HashSet<IpAddr> = HashSet::new();
    let mut names: BTreeMap<IpAddr, String> = BTreeMap::new();
    let mut round = 0u32;
    let mut dirty = false;
    let mut last_sent = tokio::time::Instant::now() - UPDATE_INTERVAL;
    let mut tick = tokio::time::interval(UPDATE_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    if worker.is_some() {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                msg = mrx.recv() => match msg {
                    Some(Msg::Obs(o)) => {
                        if let Some(ip) = stats.record(o) {
                            if let Some(name) = names.get(&ip) {
                                stats.set_hostname(ip, &name.clone());
                            } else if let Some(r) = resolver.clone() {
                                if looked_up.len() < MAX_LOOKUPS && looked_up.insert(ip) {
                                    lookups.spawn(async move { (ip, r.lookup(ip).await) });
                                }
                            }
                        }
                        dirty = true;
                    }
                    Some(Msg::RoundDone(r)) => {
                        round = r;
                        // Round boundaries are always reported.
                        if tx.send(snapshot(trace_id, target, method, &stats, round, opts.rounds)).await.is_err() {
                            break;
                        }
                        last_sent = tokio::time::Instant::now();
                        dirty = false;
                    }
                    Some(Msg::Failed(e)) => {
                        error = Some(e);
                    }
                    None => break,
                },
                Some(res) = lookups.join_next(), if !lookups.is_empty() => {
                    if let Ok((ip, Some(name))) = res {
                        stats.set_hostname(ip, &name);
                        names.insert(ip, name);
                        dirty = true;
                    }
                }
                _ = tick.tick() => {
                    if dirty && last_sent.elapsed() >= UPDATE_INTERVAL {
                        if tx.send(snapshot(trace_id, target, method, &stats, round, opts.rounds)).await.is_err() {
                            break;
                        }
                        last_sent = tokio::time::Instant::now();
                        dirty = false;
                    }
                }
            }
        }
    }
    worker_cancel.cancel();
    if let Some(h) = worker {
        // The system worker kills its child on drop; the raw worker polls the token.
        let _ = tokio::time::timeout(Duration::from_secs(3), h).await;
    }
    // Late names (short grace period so the final table has them).
    let grace = tokio::time::Instant::now() + Duration::from_millis(1500);
    while !lookups.is_empty() && !cancel.is_cancelled() {
        match tokio::time::timeout_at(grace, lookups.join_next()).await {
            Ok(Some(Ok((ip, Some(name))))) => stats.set_hostname(ip, &name),
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    lookups.abort_all();
    let mut fin = snapshot(trace_id, target, method, &stats, round, opts.rounds);
    fin.done = true;
    fin.error = error;
    let _ = tx.send(fin.clone()).await;
    fin
}

#[cfg(test)]
mod tests {
    use super::*;

    const MACOS_OUTPUT: &str = "\
 1  10.10.20.1  0.408 ms
 2  192.168.10.1  0.786 ms
 3  *
 4  10.78.131.19  4.904 ms !H
";

    const LINUX_OUTPUT: &str = "\
traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  192.168.1.1  0.384 ms
 2  100.64.0.1  8.210 ms
 3  *
 4  72.14.215.85  9.917 ms  72.14.215.86  10.101 ms
 5  8.8.8.8  10.442 ms
";

    const TRACEPATH_OUTPUT: &str = "\
 1?: [LOCALHOST]                      pmtu 1500
 1:  192.168.1.1                                           0.512ms
 1:  192.168.1.1                                           0.402ms
 2:  no reply
 3:  10.0.0.1                                              5.123ms asymm  4
 4:  8.8.8.8                                              12.345ms reached
     Resume: pmtu 1500 hops 4 back 4
";

    fn obs(line: &str) -> Vec<HopObservation> {
        parse_traceroute_line(line, 30).unwrap_or_default()
    }

    #[test]
    fn parses_macos_traceroute() {
        let all: Vec<HopObservation> = MACOS_OUTPUT.lines().flat_map(obs).collect();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].ttl, 1);
        assert_eq!(all[0].ip, Some("10.10.20.1".parse().unwrap()));
        assert_eq!(all[0].rtt_ms, Some(0.408));
        assert_eq!((all[2].ttl, all[2].ip, all[2].rtt_ms), (3, None, None));
        // Annotations (`!H`) do not hide the reply.
        assert_eq!(all[3].ip, Some("10.78.131.19".parse().unwrap()));
        assert_eq!(all[3].rtt_ms, Some(4.904));
        // The header (macOS prints it on stderr, Linux on stdout) is not a hop.
        assert!(parse_traceroute_line(
            "traceroute to 1.1.1.1 (1.1.1.1), 4 hops max, 40 byte packets",
            30
        )
        .is_none());
        // IPv6 (traceroute6).
        let v6 = obs(" 1  ::1  0.090 ms");
        assert_eq!(v6[0].ip, Some("::1".parse().unwrap()));
        let zoned = obs(" 1  fe80::1%en0  1.5 ms");
        assert_eq!(zoned[0].ip, Some("fe80::1".parse().unwrap()));
    }

    #[test]
    fn parses_linux_traceroute_and_tracepath() {
        let all: Vec<HopObservation> = LINUX_OUTPUT.lines().flat_map(obs).collect();
        assert_eq!(all.len(), 6);
        assert_eq!(all[2].ip, None);
        // Two probes answered by different routers on one line (ECMP).
        assert_eq!(all[3].ip, Some("72.14.215.85".parse().unwrap()));
        assert_eq!(all[4].ip, Some("72.14.215.86".parse().unwrap()));
        assert_eq!(all[4].rtt_ms, Some(10.101));
        // Named hops ("host (ip)") and "0.5ms" without a space.
        let named = obs(" 5  router.example.net (10.2.2.2)  6.0 ms");
        assert_eq!(named[0].ip, Some("10.2.2.2".parse().unwrap()));
        assert_eq!(obs(" 6  10.3.3.3  0.5ms")[0].rtt_ms, Some(0.5));

        let tp: Vec<HopObservation> = TRACEPATH_OUTPUT
            .lines()
            .filter_map(|l| parse_tracepath_line(l, 30))
            .collect();
        assert_eq!(tp.len(), 5);
        assert_eq!(tp[0].ip, Some("192.168.1.1".parse().unwrap()));
        assert_eq!(tp[0].rtt_ms, Some(0.512));
        assert_eq!((tp[2].ttl, tp[2].ip), (2, None));
        assert_eq!(tp[3].rtt_ms, Some(5.123));
        assert_eq!(tp[4].ip, Some("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn parsers_reject_hostile_input() {
        for line in [
            "",
            "   ",
            "0  10.0.0.1  1 ms",
            "31  10.0.0.1  1 ms", // beyond max hops (30)
            "999999999999  10.0.0.1  1 ms",
            "-1  10.0.0.1  1 ms",
            " 1  10.0.0.1  1e309 ms",
            " 1  10.0.0.1  NaN ms",
            " 1  10.0.0.1  99999999 ms",
            " 1  not-an-ip",
            " 1  \u{1b}[2J  1 ms",
            "x  10.0.0.1  1 ms",
        ] {
            assert!(parse_traceroute_line(line, 30).is_none(), "{line:?}");
            assert!(parse_tracepath_line(line, 30).is_none(), "{line:?}");
        }
        let long = format!(" 1  10.0.0.1  1 ms {}", "x ".repeat(2000));
        assert!(parse_traceroute_line(&long, 30).is_none());
        let many = format!(" 1 {}", " 10.0.0.1 1 ms".repeat(40));
        assert!(parse_traceroute_line(&many, 30).is_none());
        // An RTT before any address is ignored rather than attributed to nobody.
        assert!(parse_traceroute_line(" 1  1.0 ms", 30).is_none());
    }

    #[test]
    fn mtr_statistics() {
        let target: IpAddr = "8.8.8.8".parse().unwrap();
        let mut s = TraceStats::new(target, 30);
        let hop = |ttl, ip: &str, rtt| HopObservation {
            ttl,
            ip: Some(ip.parse().unwrap()),
            rtt_ms: Some(rtt),
        };
        let lost = |ttl| HopObservation {
            ttl,
            ip: None,
            rtt_ms: None,
        };
        assert_eq!(
            s.record(hop(1, "10.0.0.1", 1.0)),
            Some("10.0.0.1".parse().unwrap())
        );
        assert_eq!(s.record(hop(1, "10.0.0.1", 3.0)), None, "already known");
        s.record(lost(1));
        s.record(lost(2));
        s.record(hop(3, "8.8.8.8", 10.0));
        s.record(hop(4, "8.8.8.8", 11.0)); // beyond the destination: not listed
        s.record(hop(99, "1.2.3.4", 1.0)); // beyond max hops: ignored
        s.set_hostname("10.0.0.1".parse().unwrap(), "gw.lan");
        let hops = s.hops();
        assert_eq!(hops.len(), 3);
        assert!(s.reached());
        assert_eq!(s.dest_ttl(), Some(3));
        let h1 = &hops[0];
        assert_eq!((h1.sent, h1.received), (3, 2));
        assert!((h1.loss_pct - 33.333).abs() < 0.01);
        assert_eq!((h1.last_ms, h1.avg_ms), (Some(3.0), Some(2.0)));
        assert_eq!((h1.best_ms, h1.worst_ms), (Some(1.0), Some(3.0)));
        assert_eq!(h1.hostname.as_deref(), Some("gw.lan"));
        assert_eq!((hops[1].ip, hops[1].loss_pct), (None, 100.0));
        assert_eq!(hops[2].ip, Some(target));
        // Load-balanced hop: the newest responder is shown, the other one remembered.
        s.record(hop(2, "10.9.9.1", 2.0));
        s.record(hop(2, "10.9.9.2", 2.5));
        let h2 = &s.hops()[1];
        assert_eq!(h2.ip, Some("10.9.9.2".parse().unwrap()));
        assert_eq!(h2.other_ips, vec!["10.9.9.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn options_and_targets_are_validated() {
        assert!(TraceOptions::new(None, None).is_ok());
        assert!(TraceOptions::new(Some(0), None).is_err());
        assert!(TraceOptions::new(Some(65), None).is_err());
        assert!(TraceOptions::new(Some(64), Some(100)).is_ok());
        assert!(TraceOptions::new(None, Some(0)).is_err());
        assert!(TraceOptions::new(None, Some(101)).is_err());
        assert!(parse_target("10.0.0.1").is_ok());
        assert!(parse_target("2001:db8::1").is_ok());
        for bad in [
            "example.com",
            "-m 1 10.0.0.1",
            "--help",
            "10.0.0.1; rm -rf /",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "::",
            "ff02::1",
        ] {
            assert!(parse_target(bad).is_err(), "{bad}");
        }
        let t = SystemTracer {
            program: "/usr/sbin/traceroute".into(),
            flavor: Flavor::Traceroute,
            extra: vec![],
        };
        let args: Vec<String> = t
            .args("10.0.0.1".parse().unwrap(), 30)
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        assert_eq!(args, ["-n", "-q", "1", "-w", "1", "-m", "30", "10.0.0.1"]);
        let tp = SystemTracer {
            program: "/usr/bin/tracepath".into(),
            flavor: Flavor::Tracepath,
            extra: vec!["-6"],
        };
        let args: Vec<String> = tp
            .args("2001:db8::1".parse().unwrap(), 8)
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        assert_eq!(args, ["-6", "-n", "-m", "8", "2001:db8::1"]);
        let tr = SystemTracer {
            program: r"C:\Windows\System32\TRACERT.EXE".into(),
            flavor: Flavor::Tracert,
            extra: vec!["-4"],
        };
        let args: Vec<String> = tr
            .args("8.8.8.8".parse().unwrap(), 30)
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        assert_eq!(args, ["-4", "-d", "-w", "1000", "-h", "30", "8.8.8.8"]);
    }

    /// `tracert -d -h 30 -w 1000 8.8.8.8` on Windows 11 (English), CRLF line ends.
    const TRACERT_OUTPUT: &str = "\r
Tracing route to 8.8.8.8 over a maximum of 30 hops\r
\r
  1    <1 ms    <1 ms    <1 ms  192.168.1.1 \r
  2     9 ms     8 ms     *     100.64.0.1 \r
  3     *        *        *     Request timed out.\r
  4    11 ms    12 ms    10 ms  72.14.215.85 \r
  5    12 ms    11 ms    11 ms  8.8.8.8 \r
\r
Trace complete.\r
";

    fn tr(line: &str) -> Vec<HopObservation> {
        parse_tracert_line(line, 30).unwrap_or_default()
    }

    #[test]
    fn parses_windows_tracert() {
        let all: Vec<HopObservation> = TRACERT_OUTPUT.lines().flat_map(tr).collect();
        assert_eq!(all.len(), 15, "three probes per hop");
        let gw: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(
            (all[0].ttl, all[0].ip, all[0].rtt_ms),
            (1, Some(gw), Some(0.5))
        );
        let cgn: IpAddr = "100.64.0.1".parse().unwrap();
        assert_eq!(all[3].rtt_ms, Some(9.0));
        assert_eq!((all[4].ip, all[4].rtt_ms), (Some(cgn), Some(8.0)));
        assert_eq!((all[5].ttl, all[5].ip, all[5].rtt_ms), (2, None, None));
        assert!(all[6..9].iter().all(|o| o.ttl == 3 && o.ip.is_none()));
        assert_eq!(all[14].ip, Some("8.8.8.8".parse().unwrap()));
        assert_eq!(all[14].rtt_ms, Some(11.0));
        // Header, footer, blank lines and transmit errors are not hops.
        for line in [
            "Tracing route to 8.8.8.8 over a maximum of 30 hops",
            "over a maximum of 30 hops:",
            "Trace complete.",
            "",
            "  1  Transmit error: code 1231.",
            "  1  General failure.",
        ] {
            assert!(parse_tracert_line(line, 30).is_none(), "{line:?}");
        }
        // "reports: Destination host unreachable": answered, no round-trip time.
        let unreach = tr("  2  192.168.1.1  reports: Destination host unreachable.");
        assert_eq!(
            unreach,
            vec![HopObservation {
                ttl: 2,
                ip: Some(gw),
                rtt_ms: None
            }]
        );
        // IPv6 hops and a localized unit / timeout text (German, Russian).
        let v6 = tr("  1     1 ms    <1 ms    <1 ms  2001:db8:1::1 ");
        assert_eq!(v6.len(), 3);
        assert_eq!(v6[0].ip, Some("2001:db8:1::1".parse().unwrap()));
        assert_eq!(v6[0].rtt_ms, Some(1.0));
        let de = tr("  3     *        *        *     Zeitüberschreitung der Anforderung.");
        assert_eq!(de.len(), 3);
        let ru = tr("  2    10 мс     9 мс    11 мс  10.0.0.1");
        assert_eq!(ru.len(), 3);
        assert_eq!(ru[2].rtt_ms, Some(11.0));
        // TTLs out of range and hostile input.
        assert!(parse_tracert_line("  31    1 ms  1 ms  1 ms  10.0.0.1", 30).is_none());
        assert!(parse_tracert_line(&format!("  1 {}", "1 ms ".repeat(100)), 30).is_none());
        assert!(parse_tracert_line(&"9".repeat(4096), 30).is_none());
    }

    #[test]
    fn icmp_probe_packets_round_trip() {
        let ident = 0x1234;
        let seq = encode_seq(7, 13);
        assert_eq!(decode_ttl(seq), 13);
        assert_eq!(decode_ttl(encode_seq(99, 64)), 64);
        let echo = build_echo_v4(ident, seq);
        assert_eq!(checksum(&echo), 0, "a valid checksum sums to zero");
        let target = Ipv4Addr::new(8, 8, 8, 8);
        let router = Ipv4Addr::new(10, 0, 0, 1);
        let r6_router: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_ne!(next_ident(), next_ident(), "each trace gets its own ident");

        // Echo reply from the destination: IPv4 header + ICMP type 0.
        let mut ip = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0, 8, 8, 8, 8, 10, 0, 0, 2,
        ];
        let mut reply = echo.clone();
        reply[0] = 0;
        ip.extend_from_slice(&reply);
        assert_eq!(
            parse_icmp_v4(&ip, ident, target, target),
            Some((IcmpKind::EchoReply, seq))
        );
        assert_eq!(
            parse_icmp_v4(&ip, ident ^ 1, target, target),
            None,
            "other process"
        );
        // An echo reply with our ident from anyone but the target is not ours (another
        // trace's destination, or a spoofed reply).
        assert_eq!(
            parse_icmp_v4(&ip, ident, target, Ipv4Addr::new(10, 0, 0, 9)),
            None,
            "reply from a different host"
        );

        // Time exceeded from a router quoting our probe.
        let mut te = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        te.extend_from_slice(&[11, 0, 0, 0, 0, 0, 0, 0]);
        te.extend_from_slice(&[
            0x45, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 10, 0, 0, 2, 8, 8, 8, 8,
        ]);
        te.extend_from_slice(&echo[..8]);
        assert_eq!(
            parse_icmp_v4(&te, ident, target, router),
            Some((IcmpKind::TimeExceeded, seq))
        );
        assert_eq!(
            parse_icmp_v4(&te, ident, Ipv4Addr::new(1, 1, 1, 1), router),
            None,
            "other target"
        );
        // Truncated / garbage packets never panic.
        for n in 0..te.len() {
            let _ = parse_icmp_v4(&te[..n], ident, target, router);
        }
        assert_eq!(parse_icmp_v4(&[0x4f; 3], ident, target, target), None);
        assert_eq!(
            parse_icmp_v4(&[0x41, 0, 0], ident, target, target),
            None,
            "IHL < 20"
        );

        // ICMPv6.
        let t6: Ipv6Addr = "2001:db8::8".parse().unwrap();
        let e6 = build_echo_v6(ident, seq);
        let mut r6 = e6.clone();
        r6[0] = 129;
        assert_eq!(
            parse_icmp_v6(&r6, ident, t6, t6),
            Some((IcmpKind::EchoReply, seq))
        );
        assert_eq!(
            parse_icmp_v6(&r6, ident, t6, "2001:db8::99".parse().unwrap()),
            None
        );
        let mut te6 = vec![3, 0, 0, 0, 0, 0, 0, 0];
        let mut hdr = vec![0x60, 0, 0, 0, 0, 24, 58, 1];
        hdr.extend_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        hdr.extend_from_slice(&t6.octets());
        te6.extend_from_slice(&hdr);
        te6.extend_from_slice(&e6);
        assert_eq!(
            parse_icmp_v6(&te6, ident, t6, r6_router),
            Some((IcmpKind::TimeExceeded, seq))
        );
        for n in 0..te6.len() {
            let _ = parse_icmp_v6(&te6[..n], ident, t6, r6_router);
        }
    }

    /// Loopback trace end to end with whatever engine this process may use (the system
    /// traceroute when unprivileged). Skipped when no engine exists on this machine.
    #[tokio::test]
    async fn loopback_trace_reaches_the_target() {
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        if open_raw(target).is_err() && find_system_tracer(false).is_none() {
            eprintln!("skipping: no traceroute engine on this machine");
            return;
        }
        let mut opts = TraceOptions::new(Some(4), Some(2)).unwrap();
        opts.resolve = false;
        let (tx, mut rx) = mpsc::channel(64);
        let fin = run_trace(target, opts, 7, tx, CancellationToken::new()).await;
        assert!(fin.done && fin.error.is_none(), "{fin:?}");
        assert_eq!(fin.trace_id, 7);
        assert!(fin.reached);
        assert_eq!(fin.hops.last().and_then(|h| h.ip), Some(target));
        assert_eq!(fin.round, 2);
        let mut updates = 0;
        while rx.try_recv().is_ok() {
            updates += 1;
        }
        assert!(
            updates >= 2,
            "round updates and the final update are streamed"
        );
    }
}
