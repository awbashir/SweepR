//! iPerf3 throughput tests through the system `iperf3` binary.
//!
//! The binary is looked up on `PATH` and in the usual Homebrew / system locations. Each run
//! is `iperf3 -c <ip> -p <port> -t <secs> -J [-R] [-P n] [-u -b rate]`, with every argument
//! validated (IP literal, port 1-65535, 1-60 s, 1-16 streams, numeric bitrate) and passed as
//! a vector (never through a shell). iperf3 3.17+ streams one JSON object per interval
//! (`--json-stream`), which is forwarded live; older versions print one JSON document at the
//! end, whose intervals are then reported together. The child is killed when the run is
//! cancelled, dropped or overruns its deadline.

use std::{
    ffi::OsString,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::Command,
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;

use crate::models::{sanitize_text, IperfAvailability, IperfInterval, IperfOptions, IperfSummary};

/// Largest iperf3 output read (JSON of a 60 s, 16-stream run is far smaller).
const MAX_OUTPUT_BYTES: u64 = 8 * 1024 * 1024;
/// Longest single `--json-stream` line.
const MAX_LINE_BYTES: usize = 1024 * 1024;
/// Most intervals kept from one report.
const MAX_INTERVALS: usize = 3_600;
/// Time allowed beyond the test duration (connect, setup, final exchange).
const DEADLINE_SLACK: Duration = Duration::from_secs(20);

// ---------------------------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------------------------

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

/// Path of the `iperf3` binary: `PATH` first, then Homebrew (`/opt/homebrew/bin`,
/// `/usr/local/bin`) and system directories. GUI apps launched from Finder get a minimal
/// `PATH`, hence the explicit locations.
pub fn find_iperf3() -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p)
                .filter(|d| d.is_absolute())
                .collect()
        })
        .unwrap_or_default();
    for d in [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/snap/bin",
    ] {
        dirs.push(PathBuf::from(d));
    }
    dirs.into_iter()
        .map(|d| d.join("iperf3"))
        .find(|p| is_executable(p))
}

/// How to install iperf3 on this OS.
pub fn install_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "install it with `brew install iperf3`"
    } else {
        "install it with your package manager, e.g. `sudo apt install iperf3` or `sudo dnf install iperf3`"
    }
}

/// `("3.17.1", (3, 17, 1))` from `iperf3 --version` output (`iperf 3.17.1 (cJSON 1.7.15)`).
pub fn parse_version(text: &str) -> Option<(String, (u32, u32, u32))> {
    let first = text.lines().next()?;
    let mut tokens = first.split_whitespace();
    if tokens.next()? != "iperf" {
        return None;
    }
    let raw = tokens.next()?;
    let clean: String = raw
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .take(16)
        .collect();
    let mut parts = clean.split('.').map(|p| p.parse::<u32>().ok());
    let major = parts.next()??;
    let minor = parts.next().flatten().unwrap_or(0);
    let patch = parts.next().flatten().unwrap_or(0);
    Some((clean, (major, minor, patch)))
}

/// Locate iperf3 and read its version.
pub async fn availability() -> IperfAvailability {
    let Some(path) = find_iperf3() else {
        return IperfAvailability {
            available: false,
            path: None,
            version: None,
            streaming: false,
            install_hint: Some(format!("iperf3 was not found; {}", install_hint())),
        };
    };
    let out = tokio::time::timeout(
        Duration::from_secs(3),
        Command::new(&path)
            .arg("--version")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let version = match out {
        Ok(Ok(o)) => parse_version(&String::from_utf8_lossy(
            &o.stdout[..o.stdout.len().min(4096)],
        )),
        _ => None,
    };
    let Some((version, (major, minor, _))) = version else {
        return IperfAvailability {
            available: false,
            path: Some(path.display().to_string()),
            version: None,
            streaming: false,
            install_hint: Some(format!(
                "{} did not report an iperf 3 version; {}",
                path.display(),
                install_hint()
            )),
        };
    };
    IperfAvailability {
        available: major == 3,
        path: Some(path.display().to_string()),
        version: Some(version),
        streaming: (major, minor) >= (3, 17),
        install_hint: (major != 3)
            .then(|| format!("iperf3 major version 3 required; {}", install_hint())),
    }
}

// ---------------------------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------------------------

/// Validate the server address: an IP literal that can be connected to.
pub fn parse_server(s: &str) -> Result<IpAddr> {
    let ip: IpAddr = s
        .trim()
        .parse()
        .map_err(|_| anyhow!("'{}' is not an IP address", sanitize_text(s)))?;
    if ip.is_unspecified() || ip.is_multicast() {
        bail!("{ip} cannot be an iperf3 server");
    }
    Ok(ip)
}

/// The client argument vector (`streaming`: use `--json-stream`, iperf3 3.17+).
pub fn build_args(ip: IpAddr, opts: &IperfOptions, streaming: bool) -> Vec<OsString> {
    let mut a: Vec<String> = vec![
        "-c".into(),
        ip.to_string(),
        "-p".into(),
        opts.port.to_string(),
        "-t".into(),
        opts.duration_secs.to_string(),
        "-i".into(),
        "1".into(),
        "--connect-timeout".into(),
        "5000".into(),
    ];
    if streaming {
        a.push("--json-stream".into());
        a.push("--forceflush".into());
    } else {
        a.push("-J".into());
    }
    if opts.reverse {
        a.push("-R".into());
    }
    if opts.streams > 1 {
        a.push("-P".into());
        a.push(opts.streams.to_string());
    }
    if opts.udp {
        a.push("-u".into());
    }
    if let Some(b) = &opts.bitrate {
        a.push("-b".into());
        a.push(b.trim().to_string());
    }
    a.into_iter().map(OsString::from).collect()
}

// ---------------------------------------------------------------------------------------------
// JSON parsing
// ---------------------------------------------------------------------------------------------

fn f64_at(v: &Value, key: &str) -> Option<f64> {
    v.get(key)?.as_f64().filter(|x| x.is_finite())
}

fn u64_at(v: &Value, key: &str) -> Option<u64> {
    let x = v.get(key)?;
    x.as_u64().or_else(|| {
        x.as_f64()
            .filter(|f| f.is_finite() && *f >= 0.0)
            .map(|f| f as u64)
    })
}

/// One interval from an `intervals[]` entry (or a `--json-stream` interval event's data):
/// its `sum` over all streams.
pub fn parse_interval(v: &Value) -> Option<IperfInterval> {
    let sum = v.get("sum")?;
    Some(IperfInterval {
        start: f64_at(sum, "start")?,
        end: f64_at(sum, "end")?,
        bytes: u64_at(sum, "bytes").unwrap_or(0),
        bits_per_second: f64_at(sum, "bits_per_second").unwrap_or(0.0),
        retransmits: u64_at(sum, "retransmits"),
        jitter_ms: f64_at(sum, "jitter_ms"),
        lost_packets: u64_at(sum, "lost_packets"),
        packets: u64_at(sum, "packets"),
        lost_percent: f64_at(sum, "lost_percent"),
        omitted: sum.get("omitted").and_then(Value::as_bool).unwrap_or(false),
    })
}

/// End-of-test summary from the `start` and `end` objects.
pub fn parse_summary(start: Option<&Value>, end: &Value) -> Option<IperfSummary> {
    let test = start.and_then(|s| s.get("test_start"));
    let protocol = test
        .and_then(|t| t.get("protocol"))
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .filter(|p| p == "tcp" || p == "udp")
        .unwrap_or_else(|| {
            if end.get("sum").is_some() && end.get("sum_sent").is_none() {
                "udp".into()
            } else {
                "tcp".into()
            }
        });
    let sent = end.get("sum_sent");
    let received = end.get("sum_received");
    let sum = end.get("sum");
    if sent.is_none() && received.is_none() && sum.is_none() {
        return None;
    }
    // UDP: loss and jitter are in `sum` (older) or `sum_received` (newer).
    let udp_stats = if protocol == "udp" {
        received.or(sum)
    } else {
        None
    };
    let cpu = end.get("cpu_utilization_percent");
    let connecting = start.and_then(|s| s.get("connecting_to"));
    Some(IperfSummary {
        reverse: test
            .and_then(|t| u64_at(t, "reverse"))
            .is_some_and(|r| r != 0),
        streams: test
            .and_then(|t| u64_at(t, "num_streams"))
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(1),
        duration_secs: sent
            .or(sum)
            .or(received)
            .and_then(|s| f64_at(s, "seconds"))
            .unwrap_or(0.0),
        sent_bytes: sent.or(sum).and_then(|s| u64_at(s, "bytes")),
        sent_bps: sent.or(sum).and_then(|s| f64_at(s, "bits_per_second")),
        received_bytes: received.or(sum).and_then(|s| u64_at(s, "bytes")),
        received_bps: received.or(sum).and_then(|s| f64_at(s, "bits_per_second")),
        retransmits: sent.and_then(|s| u64_at(s, "retransmits")),
        jitter_ms: udp_stats.and_then(|s| f64_at(s, "jitter_ms")),
        lost_packets: udp_stats.and_then(|s| u64_at(s, "lost_packets")),
        packets: udp_stats.and_then(|s| u64_at(s, "packets")),
        lost_percent: udp_stats.and_then(|s| f64_at(s, "lost_percent")),
        cpu_local_pct: cpu.and_then(|c| f64_at(c, "host_total")),
        cpu_remote_pct: cpu.and_then(|c| f64_at(c, "remote_total")),
        remote_host: connecting.and_then(|c| {
            let host = sanitize_text(c.get("host")?.as_str()?);
            let port = u64_at(c, "port")?;
            Some(format!("{host}:{port}"))
        }),
        version: start
            .and_then(|s| s.get("version"))
            .and_then(Value::as_str)
            .map(sanitize_text),
        protocol,
    })
}

/// A whole `-J` report.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IperfReport {
    pub intervals: Vec<IperfInterval>,
    pub summary: Option<IperfSummary>,
    /// iperf3's own error message (`"error": "..."`).
    pub error: Option<String>,
}

/// Parse the single JSON document printed by `iperf3 -J`.
pub fn parse_json_report(text: &str) -> Result<IperfReport> {
    let v: Value = serde_json::from_str(text.trim())
        .map_err(|e| anyhow!("iperf3 printed invalid JSON: {e}"))?;
    let intervals = v
        .get("intervals")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .take(MAX_INTERVALS)
                .filter_map(parse_interval)
                .collect()
        })
        .unwrap_or_default();
    let summary = v
        .get("end")
        .and_then(|end| parse_summary(v.get("start"), end));
    let error = v
        .get("error")
        .and_then(Value::as_str)
        .map(sanitize_text)
        .filter(|e| !e.is_empty());
    Ok(IperfReport {
        intervals,
        summary,
        error,
    })
}

/// One `--json-stream` event.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamEvent {
    Start(Value),
    Interval(IperfInterval),
    End(Value),
    Error(String),
    Other,
}

/// Parse one `--json-stream` line (`{"event": "...", "data": ...}`).
pub fn parse_stream_line(line: &str) -> Option<StreamEvent> {
    let line = line.trim();
    if line.is_empty() || line.len() > MAX_LINE_BYTES {
        return None;
    }
    let v: Value = serde_json::from_str(line).ok()?;
    let data = v.get("data")?;
    Some(match v.get("event")?.as_str()? {
        "start" => StreamEvent::Start(data.clone()),
        "interval" => StreamEvent::Interval(parse_interval(data)?),
        "end" => StreamEvent::End(data.clone()),
        "error" => StreamEvent::Error(sanitize_text(
            data.as_str()
                .map(str::to_string)
                .unwrap_or_else(|| data.to_string())
                .as_str(),
        )),
        _ => StreamEvent::Other,
    })
}

// ---------------------------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------------------------

/// Run one iperf3 client test against `ip`, streaming intervals to `intervals` and returning
/// the summary. Fails with a clear message (and an install hint) when iperf3 is missing, and
/// with iperf3's own message when the test fails (e.g. no server listening).
pub async fn run_iperf(
    ip: IpAddr,
    opts: &IperfOptions,
    intervals: mpsc::Sender<IperfInterval>,
    cancel: CancellationToken,
) -> Result<IperfSummary> {
    opts.validate()?;
    if ip.is_unspecified() || ip.is_multicast() {
        bail!("{ip} cannot be an iperf3 server");
    }
    let avail = availability().await;
    let Some(path) = avail.path.as_ref().filter(|_| avail.available) else {
        bail!(
            "{}",
            avail
                .install_hint
                .unwrap_or_else(|| format!("iperf3 is not available; {}", install_hint()))
        );
    };
    let mut child = Command::new(path)
        .args(build_args(ip, opts, avail.streaming))
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| anyhow!("cannot run {path}: {e}"))?;
    let stdout = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
    let mut stderr = child.stderr.take().ok_or_else(|| anyhow!("no stderr"))?;
    let err_reader = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = (&mut stderr).take(64 * 1024).read_to_end(&mut buf).await;
        buf
    });
    let deadline = tokio::time::Instant::now()
        + Duration::from_secs(u64::from(opts.duration_secs))
        + DEADLINE_SLACK;

    let mut summary: Option<IperfSummary> = None;
    let mut error: Option<String> = None;
    let mut timed_out = false;
    // Output that was not valid JSON (older iperf3 prints plain-text errors): reported only
    // when stderr does not say more.
    let mut json_error: Option<String> = None;
    let mut reader = BufReader::new(stdout.take(MAX_OUTPUT_BYTES));
    if avail.streaming {
        let mut start: Option<Value> = None;
        let mut line = Vec::new();
        loop {
            line.clear();
            let mut limited = (&mut reader).take(MAX_LINE_BYTES as u64);
            let read = tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep_until(deadline) => { timed_out = true; break }
                r = limited.read_until(b'\n', &mut line) => r,
            };
            match read {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            match parse_stream_line(&String::from_utf8_lossy(&line)) {
                Some(StreamEvent::Start(s)) => start = Some(s),
                Some(StreamEvent::Interval(i)) => {
                    let _ = intervals.send(i).await;
                }
                Some(StreamEvent::End(end)) => summary = parse_summary(start.as_ref(), &end),
                Some(StreamEvent::Error(e)) => {
                    error.get_or_insert(e);
                }
                Some(StreamEvent::Other) | None => {}
            }
        }
    } else {
        let mut text = Vec::new();
        let read = tokio::select! {
            _ = cancel.cancelled() => None,
            _ = tokio::time::sleep_until(deadline) => { timed_out = true; None }
            r = reader.read_to_end(&mut text) => Some(r),
        };
        if let Some(Ok(_)) = read {
            if !text.is_empty() {
                match parse_json_report(&String::from_utf8_lossy(&text)) {
                    Ok(report) => {
                        for i in report.intervals {
                            let _ = intervals.send(i).await;
                        }
                        summary = report.summary;
                        error = report.error;
                    }
                    Err(e) => json_error = Some(format!("{e:#}")),
                }
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
    if cancel.is_cancelled() {
        bail!("iperf3 test stopped");
    }
    if timed_out {
        bail!(
            "iperf3 did not finish within {} s",
            opts.duration_secs + DEADLINE_SLACK.as_secs() as u32
        );
    }
    if let Some(e) = error {
        bail!("iperf3: {e}");
    }
    match summary {
        Some(s) => Ok(s),
        None => {
            let msg = sanitize_text(&String::from_utf8_lossy(&stderr));
            if msg.is_empty() {
                if let Some(e) = json_error {
                    bail!("{e}");
                }
            }
            let code = match status {
                Ok(Ok(s)) => s
                    .code()
                    .map(|c| format!(" (exit status {c})"))
                    .unwrap_or_default(),
                _ => String::new(),
            };
            bail!(
                "iperf3 produced no result{code}{}",
                if msg.is_empty() {
                    String::new()
                } else {
                    format!(": {msg}")
                }
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trimmed real `iperf3 -c 127.0.0.1 -t 2 -J` (3.17.1, macOS) output: TCP.
    const TCP_REPORT: &str = r#"{
	"start":	{
		"connected":	[{"socket": 5, "local_host": "127.0.0.1", "local_port": 50432, "remote_host": "127.0.0.1", "remote_port": 5201}],
		"version":	"iperf 3.17.1",
		"system_info":	"Darwin host 24.0.0 Darwin Kernel Version 24.0.0 arm64",
		"timestamp":	{"time": "Thu, 15 Oct 2026 10:00:00 GMT", "timesecs": 1792058400},
		"connecting_to":	{"host": "127.0.0.1", "port": 5201},
		"cookie":	"abcdefghijklmnopqrstuvwxyz234567abcd",
		"tcp_mss_default":	16332,
		"target_bitrate":	0,
		"fq_rate":	0,
		"sock_bufsize":	0,
		"sndbuf_actual":	146988,
		"rcvbuf_actual":	408300,
		"test_start":	{"protocol": "TCP", "num_streams": 1, "blksize": 131072, "omit": 0, "duration": 2, "bytes": 0, "blocks": 0, "reverse": 0, "tos": 0, "target_bitrate": 0, "bidir": 0, "fqrate": 0, "interval": 1}
	},
	"intervals":	[{
			"streams":	[{"socket": 5, "start": 0, "end": 1.000123, "seconds": 1.000123, "bytes": 7516192768, "bits_per_second": 60122147560.4, "retransmits": 0, "snd_cwnd": 3196608, "snd_wnd": 3197248, "rtt": 1095, "rttvar": 133, "pmtu": 16384, "omitted": false, "sender": true}],
			"sum":	{"start": 0, "end": 1.000123, "seconds": 1.000123, "bytes": 7516192768, "bits_per_second": 60122147560.4, "retransmits": 0, "omitted": false, "sender": true}
		}, {
			"streams":	[{"socket": 5, "start": 1.000123, "end": 2.000214, "seconds": 1.000091, "bytes": 7650410496, "bits_per_second": 61197718790.2, "retransmits": 2, "omitted": false, "sender": true}],
			"sum":	{"start": 1.000123, "end": 2.000214, "seconds": 1.000091, "bytes": 7650410496, "bits_per_second": 61197718790.2, "retransmits": 2, "omitted": false, "sender": true}
		}],
	"end":	{
		"streams":	[{"sender": {"socket": 5, "start": 0, "end": 2.000214, "seconds": 2.000214, "bytes": 15166603264, "bits_per_second": 60659936394.1, "retransmits": 2, "sender": true}, "receiver": {"socket": 5, "start": 0, "end": 2.000401, "seconds": 2.000214, "bytes": 15165030400, "bits_per_second": 60648068101.5, "sender": true}}],
		"sum_sent":	{"start": 0, "end": 2.000214, "seconds": 2.000214, "bytes": 15166603264, "bits_per_second": 60659936394.1, "retransmits": 2, "sender": true},
		"sum_received":	{"start": 0, "end": 2.000401, "seconds": 2.000401, "bytes": 15165030400, "bits_per_second": 60648068101.5, "sender": true},
		"cpu_utilization_percent":	{"host_total": 98.97, "host_user": 2.41, "host_system": 96.56, "remote_total": 61.53, "remote_user": 3.83, "remote_system": 57.7},
		"sender_tcp_congestion":	"cubic",
		"receiver_tcp_congestion":	"cubic"
	}
}"#;

    /// Trimmed real `iperf3 -c ... -u -b 10M -J` output (3.9, Linux): UDP with `end.sum`.
    const UDP_REPORT: &str = r#"{
	"start": {"connecting_to": {"host": "192.168.1.10", "port": 5201}, "version": "iperf 3.9",
		"test_start": {"protocol": "UDP", "num_streams": 1, "blksize": 1460, "omit": 0, "duration": 1, "bytes": 0, "blocks": 0, "reverse": 0, "tos": 0}},
	"intervals": [{"streams": [{"socket": 5, "start": 0, "end": 1.000052, "seconds": 1.000052, "bytes": 1250120, "bits_per_second": 10000440.9, "packets": 856, "omitted": false, "sender": true}],
		"sum": {"start": 0, "end": 1.000052, "seconds": 1.000052, "bytes": 1250120, "bits_per_second": 10000440.9, "packets": 856, "omitted": false, "sender": true}}],
	"end": {"streams": [{"udp": {"socket": 5, "start": 0, "end": 1.000052, "seconds": 1.000052, "bytes": 1250120, "bits_per_second": 10000440.9, "jitter_ms": 0.021, "lost_packets": 3, "packets": 856, "lost_percent": 0.35, "out_of_order": 0, "sender": true}}],
		"sum": {"start": 0, "end": 1.000052, "seconds": 1.000052, "bytes": 1250120, "bits_per_second": 10000440.9, "jitter_ms": 0.021, "lost_packets": 3, "packets": 856, "lost_percent": 0.35, "sender": true},
		"cpu_utilization_percent": {"host_total": 1.2, "host_user": 0.3, "host_system": 0.9, "remote_total": 0.4, "remote_user": 0.1, "remote_system": 0.3}}
}"#;

    /// What iperf3 prints with -J when no server listens.
    const ERROR_REPORT: &str = r#"{
	"start":	{"connected": [], "version": "iperf 3.17.1", "system_info": "Darwin", "connecting_to": {"host": "127.0.0.1", "port": 5999}},
	"intervals":	[],
	"end":	{},
	"error":	"unable to connect to server - server may have stopped running or use a different port, firewall issue, etc.: Connection refused"
}"#;

    #[test]
    fn tcp_report() {
        let r = parse_json_report(TCP_REPORT).unwrap();
        assert!(r.error.is_none());
        assert_eq!(r.intervals.len(), 2);
        assert_eq!(r.intervals[1].retransmits, Some(2));
        assert_eq!(r.intervals[1].bytes, 7_650_410_496);
        assert!((r.intervals[0].bits_per_second - 60_122_147_560.4).abs() < 1.0);
        let s = r.summary.unwrap();
        assert_eq!(s.protocol, "tcp");
        assert_eq!((s.streams, s.reverse), (1, false));
        assert_eq!(s.retransmits, Some(2));
        assert_eq!(s.sent_bytes, Some(15_166_603_264));
        assert!((s.received_bps.unwrap() - 60_648_068_101.5).abs() < 1.0);
        assert_eq!(s.cpu_local_pct, Some(98.97));
        assert_eq!(s.cpu_remote_pct, Some(61.53));
        assert_eq!(s.remote_host.as_deref(), Some("127.0.0.1:5201"));
        assert_eq!(s.version.as_deref(), Some("iperf 3.17.1"));
        assert!(s.jitter_ms.is_none());
        assert!((s.duration_secs - 2.000214).abs() < 1e-9);
    }

    #[test]
    fn udp_and_error_reports() {
        let r = parse_json_report(UDP_REPORT).unwrap();
        assert_eq!(r.intervals[0].packets, Some(856));
        let s = r.summary.unwrap();
        assert_eq!(s.protocol, "udp");
        assert_eq!(s.jitter_ms, Some(0.021));
        assert_eq!((s.lost_packets, s.packets), (Some(3), Some(856)));
        assert_eq!(s.lost_percent, Some(0.35));
        assert!(s.retransmits.is_none());
        let e = parse_json_report(ERROR_REPORT).unwrap();
        assert!(e.summary.is_none() && e.intervals.is_empty());
        assert!(e.error.unwrap().contains("Connection refused"));
        assert!(parse_json_report("not json").is_err());
        assert!(parse_json_report("{}").unwrap().summary.is_none());
        // Hostile values are bounded / sanitized, never panics.
        let evil = r#"{"start":{"version":"iperf \u001b[2J3"},"intervals":[{"sum":{"start":"x"}}, 5],
            "end":{"sum_sent":{"bytes":-5,"bits_per_second":"fast"}},"error":""}"#;
        let r = parse_json_report(evil).unwrap();
        assert!(r.intervals.is_empty() && r.error.is_none());
        let s = r.summary.unwrap();
        assert_eq!(s.version.as_deref(), Some("iperf [2J3"));
        assert_eq!(s.sent_bytes, None);
    }

    #[test]
    fn json_stream_lines() {
        let start = r#"{"event":"start","data":{"version":"iperf 3.17.1","test_start":{"protocol":"TCP","num_streams":2,"reverse":1}}}"#;
        let interval = r#"{"event":"interval","data":{"streams":[],"sum":{"start":0,"end":1.0,"seconds":1.0,"bytes":1000,"bits_per_second":8000,"retransmits":0,"omitted":false,"sender":false}}}"#;
        let end = r#"{"event":"end","data":{"sum_sent":{"seconds":1.0,"bytes":1000,"bits_per_second":8000,"retransmits":1},"sum_received":{"seconds":1.0,"bytes":990,"bits_per_second":7920}}}"#;
        let err =
            r#"{"event":"error","data":"error - unable to connect to server: Connection refused"}"#;
        let Some(StreamEvent::Start(s)) = parse_stream_line(start) else {
            panic!("start")
        };
        let Some(StreamEvent::Interval(i)) = parse_stream_line(interval) else {
            panic!("interval")
        };
        assert_eq!((i.bytes, i.bits_per_second), (1000, 8000.0));
        let Some(StreamEvent::End(e)) = parse_stream_line(end) else {
            panic!("end")
        };
        let sum = parse_summary(Some(&s), &e).unwrap();
        assert_eq!((sum.streams, sum.reverse), (2, true));
        assert_eq!(sum.received_bytes, Some(990));
        assert!(
            matches!(parse_stream_line(err), Some(StreamEvent::Error(m)) if m.contains("refused"))
        );
        assert_eq!(parse_stream_line(""), None);
        assert_eq!(parse_stream_line("garbage"), None);
        assert_eq!(
            parse_stream_line(r#"{"event":"server_output_text","data":"x"}"#),
            Some(StreamEvent::Other)
        );
    }

    #[test]
    fn versions_and_arguments() {
        assert_eq!(
            parse_version("iperf 3.17.1 (cJSON 1.7.15)\nDarwin x 24.0.0\n"),
            Some(("3.17.1".into(), (3, 17, 1)))
        );
        assert_eq!(
            parse_version("iperf 3.9 (cJSON 1.7.13)").unwrap().1,
            (3, 9, 0)
        );
        assert_eq!(
            parse_version("iperf 3.12+ (cJSON 1.7.15)").unwrap().1,
            (3, 12, 0)
        );
        assert!(parse_version("iperf version 2.0.13").is_none());
        assert!(parse_version("").is_none());

        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        let opts = IperfOptions {
            port: 5202,
            duration_secs: 5,
            reverse: true,
            streams: 4,
            udp: true,
            bitrate: Some("100M".into()),
        };
        let args: Vec<String> = build_args(ip, &opts, false)
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        assert_eq!(
            args,
            [
                "-c",
                "10.0.0.9",
                "-p",
                "5202",
                "-t",
                "5",
                "-i",
                "1",
                "--connect-timeout",
                "5000",
                "-J",
                "-R",
                "-P",
                "4",
                "-u",
                "-b",
                "100M"
            ]
        );
        let stream: Vec<String> = build_args(ip, &IperfOptions::default(), true)
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        assert!(
            stream.contains(&"--json-stream".to_string()) && !stream.contains(&"-J".to_string())
        );
        assert!(!stream.contains(&"-P".to_string()));

        // Validation: everything that reaches argv is checked first.
        let bad = |f: fn(&mut IperfOptions)| {
            let mut o = IperfOptions::default();
            f(&mut o);
            o.validate().is_err()
        };
        assert!(bad(|o| o.port = 0));
        assert!(bad(|o| o.duration_secs = 0));
        assert!(bad(|o| o.duration_secs = 61));
        assert!(bad(|o| o.streams = 0));
        assert!(bad(|o| o.streams = 17));
        assert!(bad(|o| o.bitrate = Some("--help".into())));
        assert!(bad(|o| o.bitrate = Some("1M; rm".into())));
        assert!(bad(|o| o.bitrate = Some("".into())));
        assert!(IperfOptions::default().validate().is_ok());
        assert!(parse_server("10.0.0.1").is_ok());
        assert!(parse_server("-s").is_err());
        assert!(parse_server("host.example").is_err());
        assert!(parse_server("0.0.0.0").is_err());
    }

    /// Missing binary → clear error with an install hint. Runs only when iperf3 is absent.
    #[tokio::test]
    async fn missing_iperf3_is_reported_clearly() {
        if find_iperf3().is_some() {
            eprintln!("skipping: iperf3 is installed");
            return;
        }
        let a = availability().await;
        assert!(!a.available && a.path.is_none());
        assert!(a.install_hint.unwrap().contains("install"));
        let (tx, _rx) = mpsc::channel(4);
        let err = run_iperf(
            "127.0.0.1".parse().unwrap(),
            &IperfOptions::default(),
            tx,
            CancellationToken::new(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("iperf3") && err.contains("install"), "{err}");
    }

    /// End to end against a local `iperf3 -s`, only when iperf3 is installed (skipped
    /// otherwise; never fails for lack of the binary).
    #[tokio::test]
    async fn local_iperf3_server_round_trip() {
        let Some(bin) = find_iperf3() else {
            eprintln!("skipping: iperf3 is not installed");
            return;
        };
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let mut server = Command::new(bin)
            .args(["-s", "-1", "-B", "127.0.0.1", "-p", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let opts = IperfOptions {
            port,
            duration_secs: 1,
            ..IperfOptions::default()
        };
        let (tx, mut rx) = mpsc::channel(64);
        let summary = run_iperf(
            "127.0.0.1".parse().unwrap(),
            &opts,
            tx,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(summary.sent_bps.unwrap_or(0.0) > 0.0, "{summary:?}");
        assert!(rx.try_recv().is_ok(), "at least one interval");
        let _ = server.kill().await;
    }
}
