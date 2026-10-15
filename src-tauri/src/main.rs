//! `sweepr`: one binary, two front-ends.
//!
//! * No arguments (double-click, `.app` launch, or `--gui`) → the Tauri desktop GUI.
//! * A subcommand (`scan`, `vlans`, `interfaces`) → headless CLI that prints and exits.
//!
//! The mode is decided before clap parses anything so a Finder launch (which passes
//! `-psn_*` on macOS) never trips the argument parser.

use std::{
    collections::{BTreeMap, HashMap},
    ffi::OsString,
    fmt::Display,
    future::Future,
    io::{self, IsTerminal, Write},
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Mutex, PoisonError,
    },
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use comfy_table::{presets::UTF8_FULL_CONDENSED, ContentArrangement, Table};
use serde::Serialize;
use sweepr_core::{
    arp_vlan::{self, L2Error, PassiveResults},
    engine::{self, ScanOptions},
    enricher,
    export::{self, ExportFormat},
    iperf,
    jobs::JobRegistry,
    latency::{self, MonitorConfig},
    limits::{self, SocketBudget},
    models::{
        parse_ports, sanitize_text, CdpLldpNeighbor, Device, DeviceOverride, InterfaceInfo,
        IperfAvailability, IperfInterval, IperfOptions, IperfSummary, IperfUpdate, LatencySample,
        LatencyUpdate, LogLevel, ProbeMethod, ScanConfig, ScanEvent, ScanPhase, ScanSummary,
        SnmpAuthProtocol, SnmpConfig, SnmpDeviceInfo, SnmpPrivProtocol, SnmpV3Credentials,
        SnmpVersion, TraceMethod, TraceUpdate, VlanInfo, VlanSelection, VlanSource, WakeResult,
        WebIdentity, WebScheme, DEFAULT_PORTS, MAX_LISTEN_SECS, MAX_TIMEOUT_MS,
    },
    report::{self, ReportFormat, ReportOptions},
    snmp_infra::SnmpClient,
    trace::{self, TraceOptions},
    webid, wol,
};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

/// Tauri event name carrying every [`ScanEvent`] to the frontend, wrapped in a
/// [`GuiScanEvent`] (`{ scanId, event }`).
const SCAN_EVENT: &str = "scan-event";
/// Utility events: [`LatencyUpdate`], [`TraceUpdate`] and [`IperfUpdate`] payloads.
const LATENCY_EVENT: &str = "latency-update";
const TRACE_EVENT: &str = "trace-update";
const IPERF_EVENT: &str = "iperf-update";

const ROOT_HINT: &str = "hint: active layer-2 scanning (ARP, 802.1Q, NDP) and CDP/LLDP capture \
     need root: run `sudo sweepr ...`. On macOS, BPF device access (e.g. Wireshark's ChmodBPF) \
     is enough for passive capture only; active probes also need the interface MAC address, \
     which macOS hides from non-root processes.";

/// Write a diagnostic line to stderr. Failures are ignored: a closed stderr (e.g.
/// `sweepr ... 2>&1 | head -1`) must not panic like `eprintln!` would.
macro_rules! diag {
    ($($arg:tt)*) => {{
        let _ = writeln!(io::stderr().lock(), $($arg)*);
    }};
}

/// Write `text` (plus a newline) to stdout. Unlike `println!` this returns an error instead
/// of panicking when stdout is closed (`sweepr ... | head -1`).
fn write_stdout(text: impl Display) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{text}")?;
    out.flush()
}

/// stdout was closed by the reader; the CLI stops quietly.
#[derive(Debug, thiserror::Error)]
#[error("stdout closed")]
struct StdoutClosed;

/// `true` when `err` comes from writing to a closed pipe.
fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        if cause.downcast_ref::<StdoutClosed>().is_some() {
            return true;
        }
        if let Some(e) = cause.downcast_ref::<io::Error>() {
            return e.kind() == io::ErrorKind::BrokenPipe;
        }
        if let Some(e) = cause.downcast_ref::<serde_json::Error>() {
            return e.io_error_kind() == Some(io::ErrorKind::BrokenPipe);
        }
        if let Some(e) = cause.downcast_ref::<csv::Error>() {
            return matches!(e.kind(), csv::ErrorKind::Io(io) if io.kind() == io::ErrorKind::BrokenPipe);
        }
        false
    })
}

// ---------------------------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "sweepr",
    version,
    about = "SweepR - IPv4/IPv6 enterprise network scanner with 802.1Q VLAN and CDP/LLDP discovery",
    after_help = "Run without arguments (or with --gui) to open the desktop app."
)]
struct Cli {
    /// Launch the graphical interface (default when run without arguments)
    #[arg(long, global = true)]
    gui: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Discover devices on IPv4 ranges, 802.1Q VLANs and IPv6 (ARP / NDP / ICMP)
    Scan(ScanArgs),
    /// Passively discover VLANs and CDP/LLDP neighbors (switches, APs, firewalls)
    Vlans(VlansArgs),
    /// Poll one device over SNMP: system info, VLAN table and MAC-to-port table
    Snmp(SnmpArgs),
    /// List network interfaces with their kind, VLAN and addresses
    Interfaces,
    /// Build an audit report (HTML, PDF or JSON) from a saved scan
    Report(ReportArgs),
    /// Wake a device with a Wake-on-LAN magic packet
    Wake(WakeArgs),
    /// Ping hosts continuously with rolling latency, loss and jitter statistics
    Ping(PingArgs),
    /// MTR-style traceroute: per-hop loss and latency over several rounds
    Trace(TraceArgs),
    /// Read a host's web page titles, Server headers and TLS certificates
    Web(WebArgs),
    /// Measure throughput to an iperf3 server (needs the iperf3 binary)
    Iperf(IperfArgs),
}

/// Output of the utility subcommands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ToolOutput {
    Table,
    Json,
}

#[derive(Args, Debug)]
struct WakeArgs {
    /// Target MAC address: aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff or aabb.ccdd.eeff
    #[arg(value_name = "MAC")]
    mac: String,

    /// Interface to send from [default: the default-route interface]
    #[arg(short, long, value_name = "IFACE")]
    interface: Option<String>,

    /// Send to this address instead of the interface's subnet broadcast and 255.255.255.255
    /// (e.g. the directed broadcast of a remote subnet)
    #[arg(long, value_name = "ADDR")]
    broadcast: Option<Ipv4Addr>,

    /// UDP destination port; repeat to send to several (e.g. --port 9 --port 7)
    #[arg(long = "port", value_name = "PORT", default_values_t = [wol::WOL_PORT],
          value_parser = clap::value_parser!(u16).range(1..))]
    ports: Vec<u16>,

    /// How many times to send the packet to each destination
    #[arg(long, value_name = "N", default_value_t = wol::DEFAULT_REPEAT,
          value_parser = clap::value_parser!(u8).range(1..=i64::from(wol::MAX_REPEAT)))]
    repeat: u8,

    /// SecureOn password (6 bytes written like a MAC address). Prefer the environment
    /// variable: command-line arguments are visible to other local users
    #[arg(
        long,
        value_name = "PASS",
        env = "SWEEPR_WOL_PASSWORD",
        hide_env_values = true
    )]
    password: Option<String>,
}

#[derive(Args, Debug)]
struct PingArgs {
    /// Hosts to ping (IP addresses)
    #[arg(value_name = "IP", required = true, num_args = 1..)]
    ips: Vec<String>,

    /// Stop after N probes per host [default: run until Ctrl-C]
    #[arg(short = 'c', long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    count: Option<u32>,

    /// Probe interval in milliseconds (500-10000)
    #[arg(long, value_name = "MS", default_value_t = latency::DEFAULT_INTERVAL_MS)]
    interval_ms: u64,

    /// TCP port for the fallback when a host ignores ICMP (repeatable) [default: 443, 80, 22, 445]
    #[arg(long = "tcp-port", value_name = "PORT", value_parser = clap::value_parser!(u16).range(1..))]
    tcp_ports: Vec<u16>,

    /// Output format (json prints the final statistics)
    #[arg(short, long, value_enum, default_value_t = ToolOutput::Table)]
    output: ToolOutput,
}

#[derive(Args, Debug)]
struct TraceArgs {
    /// Destination IP address
    #[arg(value_name = "IP")]
    ip: String,

    /// Maximum hops (1-64)
    #[arg(long, value_name = "N", default_value_t = trace::DEFAULT_MAX_HOPS)]
    max_hops: u8,

    /// Probe rounds (1-100); statistics accumulate over all rounds
    #[arg(long, value_name = "N", default_value_t = trace::DEFAULT_ROUNDS)]
    rounds: u32,

    /// Do not reverse-resolve hop addresses
    #[arg(long)]
    no_resolve: bool,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = ToolOutput::Table)]
    output: ToolOutput,
}

#[derive(Args, Debug)]
struct WebArgs {
    /// Host IP address
    #[arg(value_name = "IP")]
    ip: String,

    /// Ports to probe [default: 80,443,8443,8080,8000,10443]
    #[arg(short, long, value_name = "PORTS", value_parser = parse_ports_arg)]
    ports: Option<PortList>,

    /// Per-request timeout in milliseconds (100-30000)
    #[arg(long, value_name = "MS", default_value_t = 3000)]
    timeout_ms: u64,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = ToolOutput::Table)]
    output: ToolOutput,
}

#[derive(Args, Debug)]
struct IperfArgs {
    /// iperf3 server IP address
    #[arg(value_name = "IP")]
    ip: String,

    /// Server port
    #[arg(short, long, value_name = "PORT", default_value_t = 5201)]
    port: u16,

    /// Test duration in seconds (1-60)
    #[arg(short = 't', long = "time", value_name = "SECS", default_value_t = 10)]
    duration: u32,

    /// Reverse: the server sends, this host receives
    #[arg(short = 'R', long)]
    reverse: bool,

    /// Parallel streams (1-16)
    #[arg(short = 'P', long = "parallel", value_name = "N", default_value_t = 1)]
    streams: u8,

    /// UDP instead of TCP
    #[arg(short = 'u', long)]
    udp: bool,

    /// Target bitrate, e.g. 100M or 1G (UDP defaults to 1M)
    #[arg(short = 'b', long, value_name = "RATE")]
    bitrate: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = ToolOutput::Table)]
    output: ToolOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// Live rows while scanning, then a sorted table
    Table,
    Json,
    Csv,
    Xlsx,
}

/// A parsed `--ports` list (newtype so clap treats it as a single value).
#[derive(Debug, Clone)]
struct PortList(Vec<u16>);

#[derive(Args, Debug)]
struct ScanArgs {
    /// Interface to scan from [default: the default-route interface]
    #[arg(short, long, value_name = "IFACE")]
    interface: Option<String>,

    /// Targets: CIDR, range or comma list, e.g. 10.0.0.0/24, 10.0.0.1-10.0.3.254, 10.0.0.1-50
    /// [default: the interface's subnet]
    #[arg(short, long, value_name = "RANGE")]
    range: Option<String>,

    /// 802.1Q VLAN IDs to probe with tagged frames: 10,20,30 | 1-100 | untagged,10,20 | auto
    #[arg(long, value_name = "IDS", value_parser = parse_vlan_arg)]
    vlan: Option<VlanSelection>,

    /// Passively sniff 802.1Q tags, VTP and DTP while scanning
    #[arg(long)]
    discover_vlans: bool,

    /// Listen for CDP/LLDP advertisements while scanning
    #[arg(long)]
    cdp_lldp: bool,

    /// SNMP settings; giving a community, version or user enables infrastructure polling
    #[command(flatten)]
    snmp: SnmpCliArgs,

    /// Poll every discovered host over SNMP, not only likely infrastructure (slow)
    #[arg(long)]
    snmp_all: bool,

    /// Also discover IPv6 neighbors (ICMPv6 all-nodes echo / NDP)
    #[arg(short = '6', long)]
    ipv6: bool,

    /// TCP ports to probe, e.g. 22,80,443 or 1-1024
    #[arg(short, long, value_name = "PORTS", value_parser = parse_ports_arg)]
    ports: Option<PortList>,

    /// Do not resolve DNS / mDNS / NetBIOS names
    #[arg(long)]
    no_resolve: bool,

    /// Do not read web page titles / TLS certificates of devices with web ports open
    #[arg(long)]
    no_web: bool,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
    output: OutputFormat,

    /// Write the output to a file (required for xlsx)
    #[arg(short, long, value_name = "PATH")]
    file: Option<PathBuf>,

    /// Reply timeout per probe and grace period for late replies, in milliseconds
    #[arg(long, value_name = "MS", default_value_t = 1500)]
    timeout_ms: u64,

    /// Raw frame transmit rate in packets per second
    #[arg(long, value_name = "PPS", default_value_t = 2000)]
    rate_pps: u32,

    /// Passive listener duration in seconds (--cdp-lldp, --discover-vlans, --vlan auto)
    #[arg(long, value_name = "SECS", default_value_t = 10)]
    listen_secs: u64,

    /// Extra probe passes over unanswered addresses
    #[arg(long, value_name = "N", default_value_t = 1)]
    retries: u8,

    /// Maximum concurrent ICMP probes for routed ranges
    #[arg(long, value_name = "N", default_value_t = 512)]
    concurrency: usize,

    /// After the scan, write an audit report (format from the extension: .html, .pdf, .json)
    #[arg(long, value_name = "PATH")]
    report: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct ReportArgs {
    /// Scan data: the JSON written by `sweepr scan -o json`, `sweepr scan --report x.json`
    /// or `sweepr report --format json`
    #[arg(short, long, value_name = "PATH")]
    input: PathBuf,

    /// Report format [default: from the output extension, else html]
    #[arg(long, value_enum)]
    format: Option<CliReportFormat>,

    /// Output file
    #[arg(short, long, value_name = "PATH")]
    output: PathBuf,

    /// Report title
    #[arg(long, value_name = "TEXT")]
    title: Option<String>,

    /// Customer / organization name shown on the report
    #[arg(long, value_name = "NAME")]
    org: Option<String>,

    /// PNG or JPEG logo shown in the report header (max 1 MiB)
    #[arg(long, value_name = "PATH")]
    logo: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliReportFormat {
    Html,
    Pdf,
    Json,
}

impl From<CliReportFormat> for ReportFormat {
    fn from(f: CliReportFormat) -> Self {
        match f {
            CliReportFormat::Html => ReportFormat::Html,
            CliReportFormat::Pdf => ReportFormat::Pdf,
            CliReportFormat::Json => ReportFormat::Json,
        }
    }
}

#[derive(Args, Debug)]
struct VlansArgs {
    /// Interface to listen on [default: the default-route interface]
    #[arg(short, long, value_name = "IFACE")]
    interface: Option<String>,

    /// How long to listen, in seconds (CDP is sent every 60 s, LLDP every 30 s)
    #[arg(short, long, value_name = "SECS", default_value_t = 30)]
    timeout: u64,

    /// Print the results as JSON instead of tables
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SnmpOutput {
    Table,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliSnmpVersion {
    #[value(name = "1", alias = "v1")]
    V1,
    #[value(name = "2c", alias = "v2c")]
    V2c,
    #[value(name = "3", alias = "v3")]
    V3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliAuthProto {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliPrivProto {
    Des,
    Aes128,
    Aes192,
    Aes256,
}

/// SNMP version / credential flags shared by `scan` and `snmp`.
#[derive(Args, Debug, Clone, Default)]
struct SnmpCliArgs {
    /// SNMP v1/v2c community string
    #[arg(long, value_name = "COMMUNITY")]
    snmp_community: Option<String>,

    /// SNMP version [default: 3 when --snmp-user is given, else 2c]
    #[arg(long, value_enum, value_name = "VERSION")]
    snmp_version: Option<CliSnmpVersion>,

    /// SNMPv3 user name
    #[arg(long, value_name = "USER")]
    snmp_user: Option<String>,

    /// SNMPv3 authentication protocol [default: sha1]
    #[arg(long, value_enum, value_name = "PROTO")]
    snmp_auth_proto: Option<CliAuthProto>,

    /// SNMPv3 authentication password (8+ characters). Prefer the environment variable:
    /// command-line arguments are visible to other local users
    #[arg(
        long,
        value_name = "PASS",
        env = "SWEEPR_SNMP_AUTH_PASS",
        hide_env_values = true
    )]
    snmp_auth_pass: Option<String>,

    /// SNMPv3 privacy protocol [default: aes128]
    #[arg(long, value_enum, value_name = "PROTO")]
    snmp_priv_proto: Option<CliPrivProto>,

    /// SNMPv3 privacy password (8+ characters; needs an authentication password). Prefer the
    /// environment variable: command-line arguments are visible to other local users
    #[arg(
        long,
        value_name = "PASS",
        env = "SWEEPR_SNMP_PRIV_PASS",
        hide_env_values = true
    )]
    snmp_priv_pass: Option<String>,
}

impl SnmpCliArgs {
    /// `true` when the user asked for SNMP (the password environment variables alone do not
    /// count, so having them exported does not turn polling on for every scan).
    fn requested(&self) -> bool {
        self.snmp_community.is_some() || self.snmp_version.is_some() || self.snmp_user.is_some()
    }

    /// Build and validate the SNMP configuration. `None` when SNMP was not requested and
    /// `always` is false.
    fn to_config(&self, always: bool) -> Result<Option<SnmpConfig>> {
        if !always && !self.requested() {
            return Ok(None);
        }
        let version = match self.snmp_version {
            Some(CliSnmpVersion::V1) => SnmpVersion::V1,
            Some(CliSnmpVersion::V2c) => SnmpVersion::V2c,
            Some(CliSnmpVersion::V3) => SnmpVersion::V3,
            None if self.snmp_user.is_some() => SnmpVersion::V3,
            None => SnmpVersion::V2c,
        };
        let mut cfg = SnmpConfig {
            version,
            ..SnmpConfig::default()
        };
        if let Some(c) = &self.snmp_community {
            cfg.community = c.clone();
        }
        if version == SnmpVersion::V3 {
            let username = self
                .snmp_user
                .clone()
                .filter(|u| !u.is_empty())
                .context("SNMPv3 needs --snmp-user")?;
            cfg.v3 = Some(SnmpV3Credentials {
                username,
                auth_protocol: match self.snmp_auth_proto.unwrap_or(CliAuthProto::Sha1) {
                    CliAuthProto::Md5 => SnmpAuthProtocol::Md5,
                    CliAuthProto::Sha1 => SnmpAuthProtocol::Sha1,
                    CliAuthProto::Sha224 => SnmpAuthProtocol::Sha224,
                    CliAuthProto::Sha256 => SnmpAuthProtocol::Sha256,
                    CliAuthProto::Sha384 => SnmpAuthProtocol::Sha384,
                    CliAuthProto::Sha512 => SnmpAuthProtocol::Sha512,
                },
                auth_password: self.snmp_auth_pass.clone(),
                priv_protocol: match self.snmp_priv_proto.unwrap_or(CliPrivProto::Aes128) {
                    CliPrivProto::Des => SnmpPrivProtocol::Des,
                    CliPrivProto::Aes128 => SnmpPrivProtocol::Aes128,
                    CliPrivProto::Aes192 => SnmpPrivProtocol::Aes192,
                    CliPrivProto::Aes256 => SnmpPrivProtocol::Aes256,
                },
                priv_password: self.snmp_priv_pass.clone(),
            });
        } else if self.snmp_user.is_some() {
            bail!("--snmp-user is an SNMPv3 setting; use --snmp-version 3");
        }
        cfg.validate()?;
        Ok(Some(cfg))
    }
}

#[derive(Args, Debug)]
struct SnmpArgs {
    /// Device IP address to poll
    #[arg(value_name = "IP")]
    ip: String,

    /// SNMP settings (v1/v2c community defaults to "public")
    #[command(flatten)]
    snmp: SnmpCliArgs,

    /// UDP port
    #[arg(long, value_name = "PORT", default_value_t = 161)]
    snmp_port: u16,

    /// Per-request timeout in milliseconds
    #[arg(long, value_name = "MS", default_value_t = 2000)]
    timeout_ms: u64,

    /// Retries per request
    #[arg(long, value_name = "N", default_value_t = 1)]
    retries: u8,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = SnmpOutput::Table)]
    output: SnmpOutput,
}

fn parse_vlan_arg(s: &str) -> Result<VlanSelection, String> {
    s.parse()
        .map_err(|e: sweepr_core::models::ModelError| e.to_string())
}

fn parse_ports_arg(s: &str) -> Result<PortList, String> {
    parse_ports(s).map(PortList).map_err(|e| e.to_string())
}

impl ScanArgs {
    fn to_config(&self) -> Result<ScanConfig> {
        let snmp = self.snmp.to_config(false)?;
        if self.snmp_all && snmp.is_none() {
            bail!("--snmp-all needs SNMP settings (e.g. --snmp-community or --snmp-user)");
        }
        Ok(ScanConfig {
            interface: self.interface.clone(),
            range: self.range.clone(),
            vlans: self.vlan.clone().unwrap_or_default(),
            discover_vlans: self.discover_vlans,
            cdp_lldp: self.cdp_lldp,
            snmp,
            snmp_all: self.snmp_all,
            ipv6: self.ipv6,
            ports: self
                .ports
                .clone()
                .map_or_else(|| DEFAULT_PORTS.to_vec(), |p| p.0),
            resolve_names: !self.no_resolve,
            timeout_ms: self.timeout_ms,
            retries: self.retries,
            rate_pps: self.rate_pps,
            concurrency: self.concurrency,
            listen_secs: self.listen_secs,
            web_identity: !self.no_web,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------------------------

fn main() -> ExitCode {
    // macOS starts processes with 256 descriptors; enrichment and SNMP need more. Raise the
    // soft limit before anything sizes the shared socket budget from it.
    let _ = limits::raise_nofile_limit();
    // Finder launches pass `-psn_0_12345` on older macOS; ignore it.
    let args: Vec<OsString> = std::env::args_os()
        .filter(|a| !a.to_string_lossy().starts_with("-psn_"))
        .collect();
    if args.len() <= 1 {
        return run_gui();
    }
    let cli = Cli::parse_from(args);
    let command = match cli.command {
        Some(command) if !cli.gui => command,
        _ => return run_gui(),
    };

    sweepr_core::init_tracing();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("sweepr")
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            diag!("error: cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let code = runtime.block_on(run_cli(command));
    runtime.shutdown_timeout(Duration::from_millis(500));
    code
}

async fn run_cli(command: Command) -> ExitCode {
    let cancel = CancellationToken::new();
    {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                diag!("\nstopping... (Ctrl-C again to abort immediately)");
                cancel.cancel();
            }
            if tokio::signal::ctrl_c().await.is_ok() {
                std::process::exit(130);
            }
        });
    }

    let result = match command {
        Command::Scan(args) => cmd_scan(args, cancel.clone()).await,
        Command::Vlans(args) => cmd_vlans(args, cancel.clone()).await,
        Command::Snmp(args) => cmd_snmp(args, cancel.clone()).await,
        Command::Interfaces => cmd_interfaces().await,
        Command::Report(args) => cmd_report(args),
        Command::Wake(args) => cmd_wake(args).await,
        Command::Ping(args) => cmd_ping(args, cancel.clone()).await,
        Command::Trace(args) => cmd_trace(args, cancel.clone()).await,
        Command::Web(args) => cmd_web(args, cancel.clone()).await,
        Command::Iperf(args) => cmd_iperf(args, cancel.clone()).await,
    };
    match result {
        // The reader went away (`| head`): stop quietly, like other Unix filters.
        Err(e) if is_broken_pipe(&e) => ExitCode::SUCCESS,
        Ok(()) if cancel.is_cancelled() => ExitCode::from(130),
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            diag!("error: {e:#}");
            if L2Error::is_permission(&e) {
                diag!("{ROOT_HINT}");
            }
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------------------------
// CLI commands
// ---------------------------------------------------------------------------------------------

/// Renders streamed events: device rows on stdout (table mode), everything else on stderr.
/// Every network-derived string is sanitized before it reaches the terminal.
struct LiveRenderer {
    stream_rows: bool,
    progress_tty: bool,
    progress_visible: bool,
    header_printed: bool,
    devices: HashMap<String, Device>,
    vlans: BTreeMap<u16, VlanInfo>,
    neighbors: HashMap<String, CdpLldpNeighbor>,
    l2_permission_warned: bool,
    /// Cancelled when stdout is closed so the scan stops early.
    cancel: CancellationToken,
    stdout_closed: bool,
}

impl LiveRenderer {
    fn new(stream_rows: bool, cancel: CancellationToken) -> Self {
        Self {
            stream_rows,
            progress_tty: io::stderr().is_terminal(),
            progress_visible: false,
            header_printed: false,
            devices: HashMap::new(),
            vlans: BTreeMap::new(),
            neighbors: HashMap::new(),
            l2_permission_warned: false,
            cancel,
            stdout_closed: false,
        }
    }

    fn clear_progress(&mut self) {
        if self.progress_visible {
            let mut err = io::stderr().lock();
            let _ = write!(err, "\r\x1b[2K");
            let _ = err.flush();
            self.progress_visible = false;
        }
    }

    /// Print a live device row; a closed stdout stops the scan.
    fn print_row(&mut self, text: &str) {
        if self.stdout_closed {
            return;
        }
        if let Err(e) = write_stdout(text) {
            self.stdout_closed = true;
            self.cancel.cancel();
            if e.kind() != io::ErrorKind::BrokenPipe {
                diag!("error: cannot write to stdout: {e}");
            }
        }
    }

    fn handle(&mut self, ev: ScanEvent) {
        match ev {
            ScanEvent::Device(d) => {
                let key = d.key();
                let is_new = !self.devices.contains_key(&key);
                if is_new && self.stream_rows {
                    self.clear_progress();
                    if !self.header_printed {
                        self.header_printed = true;
                        self.print_row(&format!(
                            "{:<39} {:<17} {:>5} {:<12} SOURCE",
                            "IP", "MAC", "VLAN", "ROLE"
                        ));
                    }
                    self.print_row(&live_row(&d));
                }
                self.devices.insert(key, *d);
            }
            ScanEvent::Vlan(v) => {
                if !self.vlans.contains_key(&v.id) {
                    self.clear_progress();
                    diag!(
                        "vlan: {} {}({})",
                        v.id,
                        v.name
                            .as_deref()
                            .map(|n| format!("'{}' ", sanitize_text(n)))
                            .unwrap_or_default(),
                        sources_label(&v.sources)
                    );
                }
                self.vlans.insert(v.id, v);
            }
            ScanEvent::Neighbor(n) => {
                if !self.neighbors.contains_key(&n.key()) {
                    self.clear_progress();
                    diag!(
                        "neighbor: {:?} {} {} port {}{}",
                        n.protocol,
                        sanitize_text(n.display_name()),
                        sanitize_text(n.platform.as_deref().unwrap_or("")),
                        sanitize_text(n.port_id.as_deref().unwrap_or("?")),
                        n.management_addrs
                            .first()
                            .map(|ip| format!(" mgmt {ip}"))
                            .unwrap_or_default()
                    );
                }
                self.neighbors.insert(n.key(), n);
            }
            ScanEvent::Progress(p) => {
                if self.progress_tty && p.phase != ScanPhase::Done {
                    let detail = if p.probes_total > 0 {
                        format!("{}/{} probes, ", p.probes_sent, p.probes_total)
                    } else {
                        String::new()
                    };
                    let mut err = io::stderr().lock();
                    let _ = write!(
                        err,
                        "\r\x1b[2K[{:?}] {detail}{} device(s)",
                        p.phase,
                        self.devices.len()
                    );
                    let _ = err.flush();
                    self.progress_visible = true;
                }
            }
            ScanEvent::Log { level, message } => {
                self.clear_progress();
                let tag = match level {
                    LogLevel::Info => "info",
                    LogLevel::Warn => "warning",
                    LogLevel::Error => "error",
                };
                diag!("{tag}: {}", sanitize_log(&message));
                if level == LogLevel::Warn
                    && message.contains("requires root")
                    && !self.l2_permission_warned
                {
                    self.l2_permission_warned = true;
                    diag!("{ROOT_HINT}");
                }
            }
            ScanEvent::PortMapping(_) | ScanEvent::Finished(_) => {}
        }
    }

    fn sorted_devices(&self) -> Vec<Device> {
        let mut v: Vec<Device> = self.devices.values().cloned().collect();
        v.sort_by_key(|d| (d.vlan_id, d.ip));
        v
    }
}

/// Log messages may embed network-derived text: strip control characters, keep newlines
/// out, but do not apply the per-field length cap.
fn sanitize_log(message: &str) -> String {
    message
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .filter(|c| !c.is_control())
        .collect()
}

fn live_row(d: &Device) -> String {
    format!(
        "{:<39} {:<17} {:>5} {:<12} {}",
        d.ip,
        sanitize_text(d.mac.as_deref().unwrap_or("-")),
        d.vlan_id
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into()),
        d.role.label(),
        d.sources
            .iter()
            .map(|s| format!("{s:?}").to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn sources_label(sources: &[VlanSource]) -> String {
    sources
        .iter()
        .map(|s| match s {
            VlanSource::OsInterface => "os-interface",
            VlanSource::Tagged8021q => "802.1q",
            VlanSource::Cdp => "cdp",
            VlanSource::Lldp => "lldp",
            VlanSource::Vtp => "vtp",
            VlanSource::Snmp => "snmp",
            VlanSource::UserConfigured => "user",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn new_table<I: IntoIterator<Item = &'static str>>(header: I) -> Table {
    let mut t = Table::new();
    t.load_style(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(header);
    t
}

fn render_vlan_table(vlans: &[VlanInfo]) -> String {
    let mut t = new_table(["VLAN", "Name", "Sources", "Frames", "Switch", "Interface"]);
    for v in vlans {
        let text = |s: &Option<String>| s.as_deref().map(sanitize_text).unwrap_or_default();
        t.add_row([
            v.id.to_string(),
            text(&v.name),
            sources_label(&v.sources),
            v.frames_seen.to_string(),
            text(&v.switch_name),
            text(&v.interface),
        ]);
    }
    t.to_string()
}

fn render_neighbor_table(neighbors: &[CdpLldpNeighbor]) -> String {
    let mut t = new_table([
        "Proto",
        "Device",
        "Role",
        "Platform",
        "Remote Port",
        "Mgmt IP",
        "Native",
        "Voice",
        "Capabilities",
        "Local If",
    ]);
    for n in neighbors {
        let text = |s: &Option<String>| s.as_deref().map(sanitize_text).unwrap_or_default();
        t.add_row([
            format!("{:?}", n.protocol).to_ascii_uppercase(),
            sanitize_text(n.display_name()),
            n.infer_role().label().to_string(),
            text(&n.platform),
            text(&n.port_id),
            n.management_addrs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            n.native_vlan.map(|v| v.to_string()).unwrap_or_default(),
            n.voice_vlan.map(|v| v.to_string()).unwrap_or_default(),
            n.capabilities
                .iter()
                .map(|c| c.label())
                .collect::<Vec<_>>()
                .join(", "),
            sanitize_text(&n.local_interface),
        ]);
    }
    t.to_string()
}

async fn cmd_scan(args: ScanArgs, cancel: CancellationToken) -> Result<()> {
    if args.output == OutputFormat::Xlsx && args.file.is_none() {
        bail!("xlsx output requires --file <PATH>");
    }
    let cfg = args.to_config()?;
    cfg.validate()?;
    let report_format = match &args.report {
        Some(path) => Some(ReportFormat::from_path(path).with_context(|| {
            format!(
                "--report {}: use a .html, .pdf or .json file name",
                path.display()
            )
        })?),
        None => None,
    };
    let started_ms = sweepr_core::models::now_ms();
    let report_cfg = report_format.map(|_| cfg.clone());

    let (tx, mut rx) = mpsc::channel(1024);
    let scan = tokio::spawn(engine::run_scan(cfg, tx, cancel.clone()));
    let mut ui = LiveRenderer::new(args.output == OutputFormat::Table, cancel.clone());
    let mut collector = report_format.map(|_| report::ScanCollector::default());
    while let Some(ev) = rx.recv().await {
        if let Some(c) = &mut collector {
            c.observe(&ev);
        }
        ui.handle(ev);
    }
    ui.clear_progress();
    let summary = scan.await.context("scan task crashed")??;
    if ui.stdout_closed {
        return Err(StdoutClosed.into());
    }
    let devices = ui.sorted_devices();

    match (args.output, &args.file) {
        (OutputFormat::Table, file) => {
            let mut text = format!("\n{}\n", export::render_table(&devices));
            let vlans: Vec<VlanInfo> = ui.vlans.values().cloned().collect();
            if !vlans.is_empty() {
                text.push_str(&format!("\nVLANs\n{}\n", render_vlan_table(&vlans)));
            }
            let mut neighbors: Vec<CdpLldpNeighbor> = ui.neighbors.values().cloned().collect();
            neighbors.sort_by(|a, b| a.display_name().cmp(b.display_name()));
            if !neighbors.is_empty() {
                text.push_str(&format!(
                    "\nCDP/LLDP neighbors\n{}\n",
                    render_neighbor_table(&neighbors)
                ));
            }
            match file {
                Some(path) => std::fs::write(path, text.trim_start())
                    .with_context(|| format!("cannot write {}", path.display()))?,
                None => {
                    let mut out = io::stdout().lock();
                    out.write_all(text.as_bytes())?;
                    out.flush()?;
                }
            }
        }
        (OutputFormat::Json, None) => export::write_json(&devices, io::stdout().lock())?,
        (OutputFormat::Csv, None) => export::write_csv(&devices, io::stdout().lock())?,
        (format, Some(path)) => {
            let format = match format {
                OutputFormat::Csv => ExportFormat::Csv,
                OutputFormat::Xlsx => ExportFormat::Xlsx,
                _ => ExportFormat::Json,
            };
            export::export_to_path(&devices, format, path)?;
            diag!("wrote {} device(s) to {}", devices.len(), path.display());
        }
        (OutputFormat::Xlsx, None) => bail!("xlsx output requires --file <PATH>"),
    }
    print_summary(&summary);
    if let (Some(collector), Some(format), Some(path), Some(cfg)) =
        (collector, report_format, &args.report, report_cfg)
    {
        let meta = report::meta_from_config(
            &cfg,
            None,
            started_ms,
            sweepr_core::models::now_ms(),
            summary.cancelled,
        );
        let input = collector.finish(Some(devices), meta)?;
        let bytes = report::render(&input, &ReportOptions::default(), format)?;
        std::fs::write(path, bytes).with_context(|| format!("cannot write {}", path.display()))?;
        diag!("wrote {format} audit report to {}", path.display());
    }
    Ok(())
}

/// `sweepr report`: render an audit report from saved scan data.
fn cmd_report(args: ReportArgs) -> Result<()> {
    let format = match args.format {
        Some(f) => f.into(),
        None => ReportFormat::from_path(&args.output).unwrap_or(ReportFormat::Html),
    };
    let input = report::load_input(&args.input)?;
    let mut opts = ReportOptions::new(args.title.as_deref(), args.org.as_deref());
    if let Some(logo) = &args.logo {
        opts.logo = Some(report::Logo::load(logo)?);
    }
    let bytes = report::render(&input, &opts, format)?;
    std::fs::write(&args.output, bytes)
        .with_context(|| format!("cannot write {}", args.output.display()))?;
    if input.skipped_records > 0 {
        diag!(
            "warning: {} malformed record(s) in {} were skipped",
            input.skipped_records,
            args.input.display()
        );
    }
    diag!(
        "wrote {format} audit report for {} device(s) to {}",
        input.devices.len(),
        args.output.display()
    );
    Ok(())
}

fn print_summary(s: &ScanSummary) {
    diag!(
        "{} device(s), {} VLAN(s), {} neighbor(s) in {:.1} s{}",
        s.devices,
        s.vlans,
        s.neighbors,
        s.elapsed_ms as f64 / 1000.0,
        if s.cancelled { " (cancelled)" } else { "" }
    );
}

async fn cmd_vlans(args: VlansArgs, cancel: CancellationToken) -> Result<()> {
    if args.timeout > MAX_LISTEN_SECS {
        bail!("--timeout must be at most {MAX_LISTEN_SECS} seconds");
    }
    let (tx, mut rx) = mpsc::channel(1024);
    let iface = args.interface.clone();
    let timeout = Duration::from_secs(args.timeout.max(1));
    let job = {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            engine::run_vlan_discovery(iface.as_deref(), timeout, tx, cancel).await
        })
    };
    let mut ui = LiveRenderer::new(false, cancel);
    let mut summary = None;
    while let Some(ev) = rx.recv().await {
        if let ScanEvent::Finished(s) = &ev {
            summary = Some(s.clone());
        }
        ui.handle(ev);
    }
    ui.clear_progress();
    let res: PassiveResults = job.await.context("VLAN discovery task crashed")??;

    if args.json {
        let mut out = io::stdout().lock();
        serde_json::to_writer_pretty(&mut out, &res)?;
        writeln!(out)?;
        out.flush()?;
    } else {
        let mut text = String::new();
        if res.vlans.is_empty() {
            text.push_str("No VLANs observed (the port may be an access port, or nothing was tagged during the window).\n");
        } else {
            text.push_str(&format!("VLANs\n{}\n", render_vlan_table(&res.vlans)));
        }
        if res.neighbors.is_empty() {
            text.push_str(
                "No CDP/LLDP neighbors heard (CDP advertises every 60 s, LLDP every 30 s).",
            );
        } else {
            text.push_str(&format!(
                "\nCDP/LLDP neighbors\n{}",
                render_neighbor_table(&res.neighbors)
            ));
        }
        write_stdout(text)?;
    }
    if let Some(s) = summary {
        print_summary(&s);
    }
    Ok(())
}

async fn cmd_snmp(args: SnmpArgs, cancel: CancellationToken) -> Result<()> {
    let ip: IpAddr = args
        .ip
        .parse()
        .with_context(|| format!("'{}' is not an IP address", args.ip))?;
    let base = args
        .snmp
        .to_config(true)?
        .context("SNMP configuration missing")?;
    let cfg = SnmpConfig {
        port: args.snmp_port,
        timeout_ms: args.timeout_ms.clamp(1, MAX_TIMEOUT_MS),
        retries: args.retries,
        ..base
    };
    cfg.validate()?;
    let client = SnmpClient::new(cfg);
    let info = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        res = client.poll_device(ip) => res.with_context(|| format!("SNMP poll of {ip} failed"))?,
    };

    for w in &info.warnings {
        diag!("warning: partial SNMP result: {}", sanitize_log(w));
    }
    if args.output == SnmpOutput::Json {
        let mut out = io::stdout().lock();
        serde_json::to_writer_pretty(&mut out, &info)?;
        writeln!(out)?;
        out.flush()?;
        return Ok(());
    }

    let opt = |s: &Option<String>| s.as_deref().map(sanitize_text).unwrap_or_default();
    let mut sys = new_table(["Field", "Value"]);
    sys.add_row(["IP".to_string(), ip.to_string()]);
    sys.add_row(["sysName".to_string(), opt(&info.sys_name)]);
    sys.add_row(["sysDescr".to_string(), opt(&info.sys_descr)]);
    sys.add_row(["sysObjectID".to_string(), opt(&info.sys_object_id)]);
    sys.add_row([
        "sysUpTime".to_string(),
        info.sys_uptime_ticks
            .map(|t| format!("{} ({} ticks)", format_uptime(t), t))
            .unwrap_or_default(),
    ]);
    sys.add_row(["Role".to_string(), info.role.label().to_string()]);
    let mut text = format!("System\n{sys}\n");

    if info.vlans.is_empty() {
        text.push_str("\nNo VLANs reported over SNMP.\n");
    } else {
        text.push_str(&format!("\nVLANs\n{}\n", render_vlan_table(&info.vlans)));
    }

    if info.port_mappings.is_empty() {
        text.push_str("\nNo MAC-to-port entries reported over SNMP.\n");
    } else {
        let mut t = new_table(["VLAN", "MAC", "Port", "ifIndex"]);
        for pm in &info.port_mappings {
            t.add_row([
                pm.vlan_id.map(|v| v.to_string()).unwrap_or_default(),
                sanitize_text(&pm.mac),
                sanitize_text(&pm.port_name),
                pm.port_index.map(|i| i.to_string()).unwrap_or_default(),
            ]);
        }
        text.push_str(&format!("\nMAC address table\n{t}\n"));
        // Ports learning many MACs are likely uplinks/trunks, not endpoints.
        let busy: Vec<&_> = info
            .port_mac_counts
            .iter()
            .filter(|c| c.mac_count >= 10)
            .collect();
        if !busy.is_empty() {
            let mut t = new_table(["Port", "MAC count"]);
            for c in busy {
                t.add_row([sanitize_text(&c.port_name), c.mac_count.to_string()]);
            }
            text.push_str(&format!(
                "\nPorts learning many MACs (likely uplinks/trunks)\n{t}\n"
            ));
        }
    }
    write_stdout(text.trim_end())?;
    Ok(())
}

/// Render SNMP sysUpTime (hundredths of a second) as `Nd HH:MM:SS`.
fn format_uptime(ticks: u32) -> String {
    let secs = u64::from(ticks) / 100;
    let (d, h, m, s) = (
        secs / 86400,
        (secs % 86400) / 3600,
        (secs % 3600) / 60,
        secs % 60,
    );
    if d > 0 {
        format!("{d}d {h:02}:{m:02}:{s:02}")
    } else {
        format!("{h:02}:{m:02}:{s:02}")
    }
}

async fn cmd_interfaces() -> Result<()> {
    let ifaces = tokio::task::spawn_blocking(arp_vlan::list_interfaces).await?;
    let mut t = new_table([
        "",
        "Name",
        "Kind",
        "State",
        "MAC",
        "VLAN",
        "Addresses",
        "Description",
    ]);
    for i in &ifaces {
        t.add_row([
            if i.is_default {
                "*".to_string()
            } else {
                String::new()
            },
            sanitize_text(&i.name),
            format!("{:?}", i.kind),
            if i.is_up { "up" } else { "down" }.to_string(),
            i.mac.clone().unwrap_or_default(),
            match (i.vlan_id, &i.parent) {
                (Some(v), Some(p)) => format!("{v} on {p}"),
                (Some(v), None) => v.to_string(),
                _ => String::new(),
            },
            i.addrs
                .iter()
                .map(|a| format!("{}/{}", a.ip, a.prefix))
                .collect::<Vec<_>>()
                .join("\n"),
            i.description
                .as_deref()
                .map(sanitize_text)
                .unwrap_or_default(),
        ]);
    }
    write_stdout(&t)?;
    write_stdout("* = default-route interface")?;
    if arp_vlan::macs_hidden(&ifaces) {
        diag!(
            "note: this OS hides interface MAC addresses from unprivileged processes (MAC \
             column left blank). Run `sudo sweepr interfaces` to see them; active layer-2 \
             scans (ARP, 802.1Q, NDP) need root anyway."
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Utility commands: wake, ping, trace, web, iperf
// ---------------------------------------------------------------------------------------------

/// Milliseconds with two decimals, `-` when unknown.
fn fmt_ms(v: Option<f64>) -> String {
    v.filter(|x| x.is_finite())
        .map(|x| format!("{x:.2}"))
        .unwrap_or_else(|| "-".into())
}

/// `60.12 Gbit/s` (decimal units, like iperf3).
fn fmt_bps(bps: f64) -> String {
    let units = ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"];
    let mut v = if bps.is_finite() { bps.max(0.0) } else { 0.0 };
    let mut i = 0;
    while v >= 1000.0 && i < units.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    format!("{v:.2} {}", units[i])
}

/// `7.00 GiB` (binary units).
fn fmt_bytes(bytes: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.2} {}", units[i])
    }
}

fn parse_ip_arg(s: &str) -> Result<IpAddr> {
    s.trim()
        .parse()
        .with_context(|| format!("'{}' is not an IP address", sanitize_text(s)))
}

async fn cmd_wake(args: WakeArgs) -> Result<()> {
    let mac = wol::parse_wol_mac(&args.mac)?;
    let password = args
        .password
        .as_deref()
        .map(wol::parse_secureon)
        .transpose()?;
    let opts = wol::WakeOptions {
        interface: args.interface.clone(),
        broadcast: args.broadcast,
        ports: args.ports.clone(),
        repeat: args.repeat,
        password,
    };
    let res: WakeResult = wol::wake(mac, &opts).await?;
    write_stdout(format!(
        "sent {} magic packet(s) for {} to {}{}",
        res.packets_sent,
        res.mac,
        res.targets.join(", "),
        res.interface
            .as_deref()
            .map(|i| format!(" via {}", sanitize_text(i)))
            .unwrap_or_default()
    ))?;
    Ok(())
}

fn method_label(m: ProbeMethod) -> &'static str {
    match m {
        ProbeMethod::Icmp => "icmp",
        ProbeMethod::Tcp => "tcp",
    }
}

fn ping_line(s: &LatencySample) -> String {
    format!(
        "{:<15} {:<4} {:>10}  loss {:>5.1}%  avg {}  min {}  max {}  jitter {}  ({}/{})",
        s.ip,
        method_label(s.method),
        s.rtt_ms
            .map(|r| format!("{r:.2} ms"))
            .unwrap_or_else(|| "timeout".into()),
        s.loss_pct,
        fmt_ms(s.avg_ms),
        fmt_ms(s.min_ms),
        fmt_ms(s.max_ms),
        fmt_ms(s.jitter_ms),
        s.received,
        s.sent
    )
}

fn ping_table(samples: &[LatencySample]) -> String {
    let mut t = new_table([
        "Host", "Method", "Sent", "Recv", "Loss %", "Last", "Avg", "Min", "Max", "Jitter",
        "History",
    ]);
    for s in samples {
        t.add_row([
            s.ip.to_string(),
            method_label(s.method).to_string(),
            s.sent.to_string(),
            s.received.to_string(),
            format!("{:.1}", s.loss_pct),
            fmt_ms(s.rtt_ms),
            fmt_ms(s.avg_ms),
            fmt_ms(s.min_ms),
            fmt_ms(s.max_ms),
            fmt_ms(s.jitter_ms),
            latency::sparkline(&s.history, 30),
        ]);
    }
    t.to_string()
}

async fn cmd_ping(args: PingArgs, cancel: CancellationToken) -> Result<()> {
    let ips = args
        .ips
        .iter()
        .map(|s| parse_ip_arg(s))
        .collect::<Result<Vec<_>>>()?;
    let mut cfg = MonitorConfig::new(ips, Some(args.interval_ms))?;
    cfg.count = args.count;
    if !args.tcp_ports.is_empty() {
        for ip in cfg.ips.clone() {
            cfg.tcp_ports.insert(ip, args.tcp_ports.clone());
        }
    }
    let (tx, mut rx) = mpsc::channel(16);
    let job = tokio::spawn(latency::run_monitor(cfg, tx, cancel.clone()));
    let live = args.output == ToolOutput::Table;
    while let Some(batch) = rx.recv().await {
        if live {
            for s in &batch {
                if let Err(e) = write_stdout(ping_line(s)) {
                    cancel.cancel();
                    return Err(e.into());
                }
            }
        }
    }
    let fin = job.await.context("ping task crashed")??;
    match args.output {
        ToolOutput::Table => write_stdout(format!("\n{}", ping_table(&fin)))?,
        ToolOutput::Json => {
            let mut out = io::stdout().lock();
            serde_json::to_writer_pretty(&mut out, &fin)?;
            writeln!(out)?;
            out.flush()?;
        }
    }
    let silent: Vec<String> = fin
        .iter()
        .filter(|s| s.received == 0)
        .map(|s| s.ip.to_string())
        .collect();
    if !silent.is_empty() && !cancel.is_cancelled() {
        bail!("no reply from {}", silent.join(", "));
    }
    Ok(())
}

fn trace_method_label(m: TraceMethod) -> &'static str {
    match m {
        TraceMethod::Raw => "raw ICMP probes",
        TraceMethod::System => {
            "the system traceroute (unprivileged; run as root for raw ICMP probes)"
        }
    }
}

fn trace_table(u: &TraceUpdate) -> String {
    let mut t = new_table([
        "Hop", "Address", "Host", "Loss %", "Sent", "Recv", "Last", "Avg", "Best", "Worst",
    ]);
    for h in &u.hops {
        let mut addr = h.ip.map(|i| i.to_string()).unwrap_or_else(|| "???".into());
        for other in &h.other_ips {
            addr.push_str(&format!("\n{other}"));
        }
        t.add_row([
            h.ttl.to_string(),
            addr,
            h.hostname.as_deref().map(sanitize_text).unwrap_or_default(),
            format!("{:.1}", h.loss_pct),
            h.sent.to_string(),
            h.received.to_string(),
            fmt_ms(h.last_ms),
            fmt_ms(h.avg_ms),
            fmt_ms(h.best_ms),
            fmt_ms(h.worst_ms),
        ]);
    }
    t.to_string()
}

async fn cmd_trace(args: TraceArgs, cancel: CancellationToken) -> Result<()> {
    let ip = trace::parse_target(&args.ip)?;
    let mut opts = TraceOptions::new(Some(args.max_hops), Some(args.rounds))?;
    opts.resolve = !args.no_resolve;
    let (tx, mut rx) = mpsc::channel(64);
    let job = tokio::spawn(trace::run_trace(ip, opts, 0, tx, cancel.clone()));
    let tty = io::stderr().is_terminal();
    let mut announced = false;
    while let Some(u) = rx.recv().await {
        if !announced && u.error.is_none() {
            announced = true;
            diag!(
                "tracing {ip} with {} ({} hops max, {} round(s))",
                trace_method_label(u.method),
                opts.max_hops,
                opts.rounds
            );
        }
        if tty && !u.done {
            let mut err = io::stderr().lock();
            let _ = write!(
                err,
                "\r\x1b[2Kround {}/{}: {} hop(s){}",
                u.round,
                u.rounds,
                u.hops.len(),
                if u.reached {
                    ", destination reached"
                } else {
                    ""
                }
            );
            let _ = err.flush();
        }
    }
    if tty {
        let mut err = io::stderr().lock();
        let _ = write!(err, "\r\x1b[2K");
        let _ = err.flush();
    }
    let fin = job.await.context("trace task crashed")?;
    match args.output {
        ToolOutput::Table => {
            if !fin.hops.is_empty() {
                write_stdout(trace_table(&fin))?;
            }
        }
        ToolOutput::Json => {
            let mut out = io::stdout().lock();
            serde_json::to_writer_pretty(&mut out, &fin)?;
            writeln!(out)?;
            out.flush()?;
        }
    }
    if let Some(e) = &fin.error {
        bail!("{}", sanitize_log(e));
    }
    if !fin.reached && !cancel.is_cancelled() {
        diag!("note: {ip} did not answer within {} hops", opts.max_hops);
    }
    Ok(())
}

fn web_table(id: &WebIdentity) -> String {
    let mut t = new_table(["Port", "Scheme", "Status", "Title", "Server", "Note"]);
    for s in &id.services {
        let mut notes = Vec::new();
        if s.redirects > 0 {
            notes.push(format!(
                "followed {} redirect(s) to {}",
                s.redirects,
                sanitize_text(&s.url)
            ));
        }
        if let Some(r) = &s.redirect_to {
            notes.push(format!("redirects to {}", sanitize_text(r)));
        }
        if let Some(e) = &s.error {
            notes.push(sanitize_text(e));
        }
        t.add_row([
            s.port.to_string(),
            match s.scheme {
                WebScheme::Http => "http".to_string(),
                WebScheme::Https => "https".to_string(),
            },
            s.status.map(|c| c.to_string()).unwrap_or_default(),
            s.title.as_deref().map(sanitize_text).unwrap_or_default(),
            s.server.as_deref().map(sanitize_text).unwrap_or_default(),
            notes.join("\n"),
        ]);
    }
    let mut text = format!("Web services on {}\n{t}", id.ip);
    let mut seen: Vec<String> = Vec::new();
    for c in id.services.iter().filter_map(|s| s.tls_cert.as_ref()) {
        let key = c.sha256.clone().unwrap_or_default();
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        let opt = |s: &Option<String>| s.as_deref().map(sanitize_text).unwrap_or_default();
        let mut ct = new_table(["Field", "Value"]);
        let mut sans = c
            .sans
            .iter()
            .map(|s| sanitize_text(s))
            .collect::<Vec<_>>()
            .join(", ");
        if c.san_count as usize > c.sans.len() {
            sans.push_str(&format!(" (+{} more)", c.san_count as usize - c.sans.len()));
        }
        let validity = match (c.days_remaining, c.expired) {
            (Some(d), true) => format!(
                "{} (expired {} day(s) ago)",
                opt(&c.not_after),
                d.unsigned_abs()
            ),
            (Some(d), false) => format!("{} ({d} day(s) left)", opt(&c.not_after)),
            _ => opt(&c.not_after),
        };
        let key = match (&c.key_type, c.key_bits) {
            (Some(k), Some(b)) => format!("{} ({b} bits)", sanitize_text(k)),
            (Some(k), None) => sanitize_text(k),
            _ => String::new(),
        };
        for (field, value) in [
            ("Port", c.port.to_string()),
            ("Subject CN", opt(&c.subject_cn)),
            ("Subject", opt(&c.subject)),
            ("SANs", sans),
            ("Issuer", opt(&c.issuer)),
            ("Valid from", opt(&c.not_before)),
            ("Valid until", validity),
            (
                "Self-signed",
                if c.self_signed { "yes" } else { "no" }.to_string(),
            ),
            ("Key", key),
            ("Signature", opt(&c.signature_algorithm)),
            ("SHA-256", opt(&c.sha256)),
        ] {
            ct.add_row([field.to_string(), value]);
        }
        text.push_str(&format!("\n\nTLS certificate (port {})\n{ct}", c.port));
    }
    if let Some(identity) = &id.identity {
        text.push_str(&format!(
            "\n\nIdentified as: {}{}",
            sanitize_text(identity),
            id.role_hint
                .map(|r| format!(" ({})", r.label()))
                .unwrap_or_default()
        ));
    }
    text
}

async fn cmd_web(args: WebArgs, cancel: CancellationToken) -> Result<()> {
    let ip = parse_ip_arg(&args.ip)?;
    if ip.is_unspecified() || ip.is_multicast() {
        bail!("{ip} cannot be probed");
    }
    if !(100..=30_000).contains(&args.timeout_ms) {
        bail!("--timeout-ms must be between 100 and 30000");
    }
    let ports = webid::plan_ports(args.ports.as_ref().map(|p| p.0.as_slice()))
        .map_err(anyhow::Error::msg)?;
    let id = webid::grab_web_identity(
        ip,
        &ports,
        Duration::from_millis(args.timeout_ms),
        &cancel,
        SocketBudget::global(),
    )
    .await;
    if cancel.is_cancelled() {
        return Ok(());
    }
    if args.output == ToolOutput::Json {
        let mut out = io::stdout().lock();
        serde_json::to_writer_pretty(&mut out, &id)?;
        writeln!(out)?;
        out.flush()?;
        return Ok(());
    }
    if id.services.is_empty() {
        bail!(
            "no web server answered on {ip} (ports {})",
            ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    write_stdout(web_table(&id))?;
    for w in &id.warnings {
        diag!("warning: {}", sanitize_log(w));
    }
    Ok(())
}

fn iperf_interval_line(i: &IperfInterval) -> String {
    let mut line = format!(
        "[{:>5.1}-{:>5.1} s] {:>12} {:>15}",
        i.start,
        i.end,
        fmt_bytes(i.bytes),
        fmt_bps(i.bits_per_second)
    );
    if let Some(r) = i.retransmits {
        line.push_str(&format!("  retr {r}"));
    }
    if let Some(j) = i.jitter_ms {
        line.push_str(&format!("  jitter {j:.3} ms"));
    }
    if let (Some(lost), Some(total)) = (i.lost_packets, i.packets) {
        line.push_str(&format!("  lost {lost}/{total}"));
    }
    if i.omitted {
        line.push_str("  (omitted)");
    }
    line
}

fn iperf_summary_table(s: &IperfSummary) -> String {
    let mut t = new_table(["Field", "Value"]);
    let opt_bps = |v: Option<f64>| v.map(fmt_bps).unwrap_or_default();
    let opt_bytes = |v: Option<u64>| v.map(fmt_bytes).unwrap_or_default();
    let pct = |v: Option<f64>| v.map(|p| format!("{p:.1} %")).unwrap_or_default();
    let mut rows = vec![
        ("Protocol", s.protocol.to_ascii_uppercase()),
        (
            "Direction",
            if s.reverse {
                "server → this host (reverse)".to_string()
            } else {
                "this host → server".to_string()
            },
        ),
        ("Streams", s.streams.to_string()),
        ("Duration", format!("{:.1} s", s.duration_secs)),
        (
            "Sent",
            format!("{} ({})", opt_bps(s.sent_bps), opt_bytes(s.sent_bytes)),
        ),
        (
            "Received",
            format!(
                "{} ({})",
                opt_bps(s.received_bps),
                opt_bytes(s.received_bytes)
            ),
        ),
    ];
    if let Some(r) = s.retransmits {
        rows.push(("Retransmits", r.to_string()));
    }
    if let Some(j) = s.jitter_ms {
        rows.push(("Jitter", format!("{j:.3} ms")));
    }
    if let (Some(lost), Some(total)) = (s.lost_packets, s.packets) {
        rows.push(("Lost", format!("{lost}/{total} ({})", pct(s.lost_percent))));
    }
    rows.push((
        "CPU local / remote",
        format!("{} / {}", pct(s.cpu_local_pct), pct(s.cpu_remote_pct)),
    ));
    if let Some(h) = &s.remote_host {
        rows.push(("Server", sanitize_text(h)));
    }
    if let Some(v) = &s.version {
        rows.push(("Client", sanitize_text(v)));
    }
    for (k, v) in rows {
        t.add_row([k.to_string(), v]);
    }
    t.to_string()
}

async fn cmd_iperf(args: IperfArgs, cancel: CancellationToken) -> Result<()> {
    let ip = iperf::parse_server(&args.ip)?;
    let opts = IperfOptions {
        port: args.port,
        duration_secs: args.duration,
        reverse: args.reverse,
        streams: args.streams,
        udp: args.udp,
        bitrate: args.bitrate.clone(),
    };
    opts.validate()?;
    let (tx, mut rx) = mpsc::channel(64);
    let job = {
        let (opts, cancel) = (opts.clone(), cancel.clone());
        tokio::spawn(async move { iperf::run_iperf(ip, &opts, tx, cancel).await })
    };
    let live = args.output == ToolOutput::Table;
    let mut intervals = Vec::new();
    while let Some(i) = rx.recv().await {
        if live {
            if let Err(e) = write_stdout(iperf_interval_line(&i)) {
                cancel.cancel();
                return Err(e.into());
            }
        }
        intervals.push(i);
    }
    let summary = match job.await.context("iperf3 task crashed")? {
        Ok(s) => s,
        Err(_) if cancel.is_cancelled() => return Ok(()),
        Err(e) => return Err(e),
    };
    match args.output {
        ToolOutput::Table => write_stdout(format!("\n{}", iperf_summary_table(&summary)))?,
        ToolOutput::Json => {
            let mut out = io::stdout().lock();
            serde_json::to_writer_pretty(
                &mut out,
                &serde_json::json!({ "intervals": intervals, "summary": summary }),
            )?;
            writeln!(out)?;
            out.flush()?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// GUI
// ---------------------------------------------------------------------------------------------

/// Tracks the running scan / discovery job so it can be stopped or superseded.
#[derive(Default)]
struct ScanManager {
    current: Mutex<Option<(u64, CancellationToken)>>,
    next_id: AtomicU64,
}

impl ScanManager {
    /// Cancel any running job and register a new one. Ids start at 1.
    fn begin(&self) -> (u64, CancellationToken) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let token = CancellationToken::new();
        if let Ok(mut cur) = self.current.lock() {
            if let Some((_, old)) = cur.replace((id, token.clone())) {
                old.cancel();
            }
        }
        (id, token)
    }

    fn end(&self, id: u64) {
        if let Ok(mut cur) = self.current.lock() {
            if cur.as_ref().is_some_and(|(cur_id, _)| *cur_id == id) {
                *cur = None;
            }
        }
    }

    /// `true` while `id` is the registered job (not superseded and not ended).
    fn is_current(&self, id: u64) -> bool {
        self.current
            .lock()
            .map(|cur| cur.as_ref().is_some_and(|(cur_id, _)| *cur_id == id))
            .unwrap_or(false)
    }

    /// Cancel the running job (only if it is `id`, when given).
    fn stop(&self, id: Option<u64>) -> bool {
        let Ok(cur) = self.current.lock() else {
            return false;
        };
        match cur.as_ref() {
            Some((cur_id, token)) if id.is_none_or(|i| i == *cur_id) => {
                token.cancel();
                true
            }
            _ => false,
        }
    }
}

/// Payload of the `scan-event` Tauri event: `{ "scanId": 7, "event": { "type", "data" } }`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GuiScanEvent<'a> {
    scan_id: u64,
    event: &'a ScanEvent,
}

/// Run `job` in the background, forwarding its events to the frontend tagged with `id`.
/// Events stop as soon as the job is superseded by a newer one. Failures are reported as an
/// error log followed by a `finished` event so the UI always leaves its busy state.
fn spawn_job<F, Fut>(app: AppHandle, id: u64, cancel: CancellationToken, job: F)
where
    F: FnOnce(mpsc::Sender<ScanEvent>, CancellationToken) -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    tauri::async_runtime::spawn(async move {
        let started = Instant::now();
        let (tx, mut rx) = mpsc::channel::<ScanEvent>(1024);
        let emitter = app.clone();
        let forwarder = tauri::async_runtime::spawn(async move {
            while let Some(ev) = rx.recv().await {
                // A superseded job keeps draining its channel but no longer talks to the UI.
                if !emitter.state::<ScanManager>().is_current(id) {
                    continue;
                }
                let _ = emitter.emit(
                    SCAN_EVENT,
                    GuiScanEvent {
                        scan_id: id,
                        event: &ev,
                    },
                );
            }
        });
        if let Err(e) = job(tx.clone(), cancel.clone()).await {
            let hint = if L2Error::is_permission(&e) {
                format!(" — {ROOT_HINT}")
            } else {
                String::new()
            };
            let _ = tx.send(ScanEvent::error(format!("{e:#}{hint}"))).await;
            let _ = tx
                .send(ScanEvent::Finished(ScanSummary {
                    devices: 0,
                    vlans: 0,
                    neighbors: 0,
                    elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    cancelled: cancel.is_cancelled(),
                }))
                .await;
        }
        drop(tx);
        let _ = forwarder.await;
        app.state::<ScanManager>().end(id);
    });
}

#[tauri::command]
async fn list_interfaces() -> Result<Vec<InterfaceInfo>, String> {
    tauri::async_runtime::spawn_blocking(arp_vlan::list_interfaces)
        .await
        .map_err(|e| e.to_string())
}

/// Start a scan; returns its `scanId` (every `scan-event` of this job carries it).
#[tauri::command]
async fn start_scan(
    app: AppHandle,
    state: State<'_, ScanManager>,
    config: ScanConfig,
) -> Result<u64, String> {
    config.validate().map_err(|e| e.to_string())?;
    let (id, cancel) = state.begin();
    spawn_job(app, id, cancel, move |tx, cancel| async move {
        // The GUI owns the user overrides (load_overrides / save_override) and applies them
        // itself, so the engine must not bake them into device snapshots.
        let opts = ScanOptions {
            apply_overrides: false,
        };
        engine::run_scan_with(config, opts, tx, cancel)
            .await
            .map(|_| ())
    });
    Ok(id)
}

/// Stop the running job (only if it is `scan_id`, when given). Returns `true` if one was
/// signalled; its `finished` event follows. Running drawer port scans are cancelled too.
#[tauri::command]
fn stop_scan(
    state: State<'_, ScanManager>,
    port_scans: State<'_, PortScans>,
    scan_id: Option<u64>,
) -> bool {
    port_scans.cancel_all();
    state.stop(scan_id)
}

/// Start passive VLAN / CDP / LLDP discovery; returns its `scanId`.
#[tauri::command]
async fn start_vlan_discovery(
    app: AppHandle,
    state: State<'_, ScanManager>,
    interface: Option<String>,
    timeout_secs: Option<u64>,
) -> Result<u64, String> {
    let (id, cancel) = state.begin();
    let timeout = Duration::from_secs(timeout_secs.unwrap_or(30).clamp(1, 3600));
    spawn_job(app, id, cancel, move |tx, cancel| async move {
        engine::run_vlan_discovery(interface.as_deref(), timeout, tx, cancel)
            .await
            .map(|_| ())
    });
    Ok(id)
}

/// Final export path for a dialog choice: a missing extension is added (refusing to
/// silently replace an existing file the dialog never asked about); any other extension
/// must match `format`.
fn resolve_export_path(chosen: PathBuf, format: ExportFormat) -> Result<PathBuf, String> {
    if chosen.extension().is_some() {
        return match ExportFormat::from_path(&chosen) {
            Some(f) if f == format => Ok(chosen),
            _ => Err(format!(
                "the file name must end in .{format} for a {format} export"
            )),
        };
    }
    let mut path = chosen.into_os_string();
    path.push(format!(".{format}"));
    let path = PathBuf::from(path);
    if std::fs::symlink_metadata(&path).is_ok() {
        return Err(format!(
            "{} already exists; choose it explicitly to replace it",
            path.display()
        ));
    }
    Ok(path)
}

/// Export `devices` as `format` ("csv", "json" or "xlsx") to a file the user picks in a
/// native save dialog opened by the backend. The webview never supplies a path. Returns the
/// written path, or `null` when the dialog was cancelled.
#[tauri::command]
async fn export_devices(
    app: AppHandle,
    devices: Vec<Device>,
    format: String,
) -> Result<Option<String>, String> {
    let format: ExportFormat = format.parse().map_err(|e: anyhow::Error| e.to_string())?;
    let (label, ext) = match format {
        ExportFormat::Csv => ("CSV", "csv"),
        ExportFormat::Json => ("JSON", "json"),
        ExportFormat::Xlsx => ("Excel workbook", "xlsx"),
    };
    let (done, chosen) = oneshot::channel();
    app.dialog()
        .file()
        .set_title("Export devices")
        .add_filter(label, &[ext])
        .set_file_name(format!("sweepr-devices.{ext}"))
        .save_file(move |path| {
            let _ = done.send(path);
        });
    let Some(chosen) = chosen.await.map_err(|_| "save dialog closed".to_string())? else {
        return Ok(None);
    };
    let path = chosen.into_path().map_err(|e| e.to_string())?;
    let path = resolve_export_path(path, format)?;
    let written = path.clone();
    tauri::async_runtime::spawn_blocking(move || {
        export::export_to_chosen_path(&devices, format, Path::new(&path))
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format!("{e:#}"))?;
    Ok(Some(written.display().to_string()))
}

/// The most recent report written by `generate_report` (the only path `reveal_report` opens).
#[derive(Default)]
struct LastReport(Mutex<Option<PathBuf>>);

/// Build an audit report from the GUI's current data and save it to a file the user picks
/// in a native save dialog opened by the backend (the webview never supplies a path).
/// Records are parsed leniently, so newer device fields are picked up and malformed ones
/// skipped. Returns the written path, or `null` when the dialog was cancelled.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn generate_report(
    app: AppHandle,
    last: State<'_, LastReport>,
    devices: Vec<serde_json::Value>,
    vlans: Option<Vec<serde_json::Value>>,
    neighbors: Option<Vec<serde_json::Value>>,
    port_mappings: Option<Vec<serde_json::Value>>,
    snmp_infos: Option<Vec<serde_json::Value>>,
    meta: Option<serde_json::Value>,
    format: String,
    title: Option<String>,
    org: Option<String>,
) -> Result<Option<String>, String> {
    let format: ReportFormat = format.parse().map_err(|e: anyhow::Error| e.to_string())?;
    let envelope = serde_json::json!({
        "devices": devices,
        "vlans": vlans.unwrap_or_default(),
        "neighbors": neighbors.unwrap_or_default(),
        "portMappings": port_mappings.unwrap_or_default(),
        "snmpInfos": snmp_infos.unwrap_or_default(),
        "meta": meta.unwrap_or_default(),
    });
    let opts = ReportOptions::new(title.as_deref(), org.as_deref());
    let bytes = tauri::async_runtime::spawn_blocking(move || {
        let input = sweepr_core::audit::AuditInput::from_json_value(envelope)?;
        report::render(&input, &opts, format)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format!("{e:#}"))?;

    let (label, ext) = match format {
        ReportFormat::Html => ("HTML report", "html"),
        ReportFormat::Pdf => ("PDF report", "pdf"),
        ReportFormat::Json => ("JSON audit", "json"),
    };
    let (done, chosen) = oneshot::channel();
    app.dialog()
        .file()
        .set_title("Save audit report")
        .add_filter(label, &[ext])
        .set_file_name(format!("sweepr-audit-report.{ext}"))
        .save_file(move |path| {
            let _ = done.send(path);
        });
    let Some(chosen) = chosen.await.map_err(|_| "save dialog closed".to_string())? else {
        return Ok(None);
    };
    let path = chosen.into_path().map_err(|e| e.to_string())?;
    let path = report::resolve_chosen_path(path, format)?;
    let written = path.clone();
    tauri::async_runtime::spawn_blocking(move || {
        report::write_to_chosen_path(&bytes, format, &path)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format!("{e:#}"))?;
    *last.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(written.clone());
    Ok(Some(written.display().to_string()))
}

/// Reveal the report most recently written by `generate_report` in Finder / the file
/// manager. Takes no path, so the webview cannot reveal arbitrary files.
#[tauri::command]
fn reveal_report(app: AppHandle, last: State<'_, LastReport>) -> Result<bool, String> {
    use tauri_plugin_opener::OpenerExt;
    let Some(path) = last
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
    else {
        return Ok(false);
    };
    app.opener()
        .reveal_item_in_dir(&path)
        .map_err(|e| e.to_string())?;
    Ok(true)
}

/// Largest port count a single `scan_ports` command accepts (GUI drawer input bound).
const SCAN_PORTS_CAP: usize = 4096;
/// Drawer port scans allowed to run at once.
const MAX_PORT_SCAN_JOBS: usize = 4;

/// Drawer port scans: a shared cancellation token (cancelled by `stop_scan`) and a guard on
/// how many run at once. Their sockets also draw from the global [`SocketBudget`].
#[derive(Default)]
struct PortScans {
    token: Mutex<CancellationToken>,
    running: AtomicUsize,
}

/// Holds one of the [`MAX_PORT_SCAN_JOBS`] slots until dropped.
struct PortScanSlot<'a>(&'a AtomicUsize);

impl Drop for PortScanSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl PortScans {
    fn try_enter(&self) -> Option<PortScanSlot<'_>> {
        let mut cur = self.running.load(Ordering::Acquire);
        while cur < MAX_PORT_SCAN_JOBS {
            match self.running.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(PortScanSlot(&self.running)),
                Err(actual) => cur = actual,
            }
        }
        None
    }

    fn token(&self) -> CancellationToken {
        self.token
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Cancel every running port scan; later scans get a fresh token.
    fn cancel_all(&self) {
        let mut token = self.token.lock().unwrap_or_else(PoisonError::into_inner);
        token.cancel();
        *token = CancellationToken::new();
    }
}

/// Load the local device-override store (keyed by `Device::key()`); empty when none exist.
/// Rejects when the store is unreadable or corrupt (the file is left untouched).
#[tauri::command]
async fn load_overrides() -> Result<HashMap<String, DeviceOverride>, String> {
    tauri::async_runtime::spawn_blocking(enricher::load_overrides_strict)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("{e:#}"))
}

/// Insert / update / clear one device override, persisting it atomically. A field set to
/// `null` (or whitespace-only) clears it; clearing both removes the entry.
#[tauri::command]
async fn save_override(
    key: String,
    hostname: Option<String>,
    comments: Option<String>,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || enricher::save_override(key, hostname, comments))
        .await
        .map_err(|e| e.to_string())?
        .map(|_| ())
        .map_err(|e| format!("{e:#}"))
}

/// TCP connect scan of `ports` on `ip` for the GUI details drawer. Validates the address,
/// de-duplicates and caps the ports, allows at most [`MAX_PORT_SCAN_JOBS`] concurrent calls,
/// and stops early when `stop_scan` is called.
#[tauri::command]
async fn scan_ports(
    port_scans: State<'_, PortScans>,
    ip: String,
    ports: Vec<u16>,
) -> Result<Vec<u16>, String> {
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| format!("'{ip}' is not an IP address"))?;
    let ports = enricher::dedupe_ports(&ports);
    if ports.len() > SCAN_PORTS_CAP {
        return Err(format!("too many ports (max {SCAN_PORTS_CAP})"));
    }
    let _slot = port_scans.try_enter().ok_or_else(|| {
        format!("{MAX_PORT_SCAN_JOBS} port scans are already running; wait for one to finish")
    })?;
    let cancel = port_scans.token();
    let res = enricher::scan_ports(
        ip,
        &ports,
        128,
        Duration::from_millis(800),
        &cancel,
        SocketBudget::global(),
    )
    .await;
    if cancel.is_cancelled() {
        return Err("port scan stopped".into());
    }
    if !res.unverified.is_empty() {
        return Err(format!(
            "{} of {} port(s) could not be checked because the app ran out of file \
             descriptors (open so far: {})",
            res.unverified.len(),
            ports.len(),
            if res.open.is_empty() {
                "none".to_string()
            } else {
                res.open
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
    }
    Ok(res.open)
}

/// Poll one device over SNMP for the GUI details drawer. `snmp` defaults to the v2c `public`
/// community when omitted.
#[tauri::command]
async fn query_snmp(ip: String, snmp: Option<SnmpConfig>) -> Result<SnmpDeviceInfo, String> {
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| format!("'{ip}' is not an IP address"))?;
    let cfg = snmp.unwrap_or_default();
    cfg.validate().map_err(|e| e.to_string())?;
    SnmpClient::new(cfg)
        .poll_device(ip)
        .await
        .map_err(|e| format!("{e:#}"))
}

// ---------------------------------------------------------------------------------------------
// GUI utilities: Wake-on-LAN, latency monitor, traceroute, web identity, iPerf3
// ---------------------------------------------------------------------------------------------

/// Concurrent utility jobs per kind.
const MAX_LATENCY_MONITORS: usize = 16;
const MAX_TRACES: usize = 8;
const MAX_IPERF_RUNS: usize = 2;
const MAX_WEB_LOOKUPS: usize = 4;
/// TCP fallback ports accepted per monitored host.
const MAX_TCP_PORTS_PER_HOST: usize = 16;

/// Running utility jobs; all are cancelled when the app exits.
struct UtilityJobs {
    latency: JobRegistry,
    traces: JobRegistry,
    iperf: JobRegistry,
    web: JobRegistry,
}

impl Default for UtilityJobs {
    fn default() -> Self {
        Self {
            latency: JobRegistry::new("latency monitor", MAX_LATENCY_MONITORS),
            traces: JobRegistry::new("trace", MAX_TRACES),
            iperf: JobRegistry::new("iPerf3 test", MAX_IPERF_RUNS),
            web: JobRegistry::new("web identity lookup", MAX_WEB_LOOKUPS),
        }
    }
}

impl UtilityJobs {
    fn registries(&self) -> [&JobRegistry; 4] {
        [&self.latency, &self.traces, &self.iperf, &self.web]
    }

    /// Cancel everything, then give the jobs up to `grace` to wind down (child processes
    /// such as traceroute / iperf3 are killed as their tasks finish).
    fn shutdown(&self, grace: Duration) {
        for r in self.registries() {
            r.stop_all();
        }
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline && self.registries().iter().any(|r| !r.is_empty()) {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn gui_ip(s: &str) -> Result<IpAddr, String> {
    s.trim()
        .parse()
        .map_err(|_| format!("'{}' is not an IP address", sanitize_text(s)))
}

/// Send a Wake-on-LAN magic packet. `broadcast` replaces the interface's subnet broadcast
/// and 255.255.255.255; `port` defaults to 9, `repeat` to 3; `password` is an optional
/// SecureOn password written like a MAC address.
#[tauri::command]
async fn wake_device(
    mac: String,
    interface: Option<String>,
    broadcast: Option<String>,
    port: Option<u16>,
    repeat: Option<u8>,
    password: Option<String>,
) -> Result<WakeResult, String> {
    let mac = wol::parse_wol_mac(&mac).map_err(|e| e.to_string())?;
    let broadcast = broadcast
        .as_deref()
        .map(str::trim)
        .filter(|b| !b.is_empty())
        .map(|b| {
            b.parse::<Ipv4Addr>()
                .map_err(|_| format!("'{}' is not an IPv4 address", sanitize_text(b)))
        })
        .transpose()?;
    let password = password
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .map(wol::parse_secureon)
        .transpose()
        .map_err(|e| e.to_string())?;
    let opts = wol::WakeOptions {
        interface: interface.filter(|i| !i.trim().is_empty()),
        broadcast,
        ports: port.map(|p| vec![p]).unwrap_or_default(),
        repeat: repeat
            .unwrap_or(wol::DEFAULT_REPEAT)
            .clamp(1, wol::MAX_REPEAT),
        password,
    };
    wol::wake(mac, &opts).await.map_err(|e| format!("{e:#}"))
}

/// Start pinging `ips` every `intervalMs` (500-10000, default 1000). Returns the
/// `monitorId`; batches arrive as `latency-update` events (≤ 4 per second) until
/// `stop_latency_monitor`. `tcpPorts` maps an IP to its known open ports for the TCP
/// fallback.
#[tauri::command]
async fn start_latency_monitor(
    app: AppHandle,
    jobs: State<'_, UtilityJobs>,
    ips: Vec<String>,
    interval_ms: Option<u64>,
    tcp_ports: Option<HashMap<String, Vec<u16>>>,
) -> Result<u64, String> {
    let ips = ips
        .iter()
        .map(|s| gui_ip(s))
        .collect::<Result<Vec<IpAddr>, String>>()?;
    let mut cfg = MonitorConfig::new(ips, interval_ms).map_err(|e| e.to_string())?;
    for (ip, ports) in tcp_ports.unwrap_or_default() {
        let ip = gui_ip(&ip)?;
        if !cfg.ips.contains(&ip) {
            continue;
        }
        let ports: Vec<u16> = enricher::dedupe_ports(&ports)
            .into_iter()
            .take(MAX_TCP_PORTS_PER_HOST)
            .collect();
        cfg.tcp_ports.insert(ip, ports);
    }
    let reservation = latency::reserve_hosts(cfg.ips.len()).map_err(|e| e.to_string())?;
    let (id, cancel) = jobs.latency.begin()?;
    tauri::async_runtime::spawn(async move {
        let (tx, mut rx) = mpsc::channel::<Vec<LatencySample>>(16);
        let emitter = app.clone();
        let forwarder = tauri::async_runtime::spawn(async move {
            while let Some(samples) = rx.recv().await {
                let _ = emitter.emit(
                    LATENCY_EVENT,
                    LatencyUpdate {
                        monitor_id: id,
                        samples,
                    },
                );
            }
        });
        if let Err(e) =
            latency::run_monitor_reserved(cfg, reservation, tx, cancel, SocketBudget::global())
                .await
        {
            tracing::warn!("latency monitor {id} failed: {e:#}");
        }
        let _ = forwarder.await;
        app.state::<UtilityJobs>().latency.end(id);
    });
    Ok(id)
}

/// Stop a latency monitor. Returns `true` when it was running (one final batch may follow).
#[tauri::command]
fn stop_latency_monitor(jobs: State<'_, UtilityJobs>, monitor_id: u64) -> bool {
    jobs.latency.stop(monitor_id)
}

/// Start an MTR-style trace to `ip` (`maxHops` 1-64, default 30; `rounds` 1-100, default
/// 5). Returns the `traceId`; snapshots arrive as `trace-update` events, the last with
/// `done: true`.
#[tauri::command]
async fn start_trace(
    app: AppHandle,
    jobs: State<'_, UtilityJobs>,
    ip: String,
    max_hops: Option<u8>,
    rounds: Option<u32>,
) -> Result<u64, String> {
    let target = trace::parse_target(&ip).map_err(|e| e.to_string())?;
    let opts = TraceOptions::new(max_hops, rounds).map_err(|e| e.to_string())?;
    let (id, cancel) = jobs.traces.begin()?;
    tauri::async_runtime::spawn(async move {
        let (tx, mut rx) = mpsc::channel::<TraceUpdate>(64);
        let emitter = app.clone();
        let forwarder = tauri::async_runtime::spawn(async move {
            while let Some(update) = rx.recv().await {
                let _ = emitter.emit(TRACE_EVENT, &update);
            }
        });
        trace::run_trace(target, opts, id, tx, cancel).await;
        let _ = forwarder.await;
        app.state::<UtilityJobs>().traces.end(id);
    });
    Ok(id)
}

/// Stop a trace. Returns `true` when it was running (its final `done` update follows).
#[tauri::command]
fn stop_trace(jobs: State<'_, UtilityJobs>, trace_id: u64) -> bool {
    jobs.traces.stop(trace_id)
}

/// One-shot web identity of `ip`: HTTP titles, Server headers and TLS certificates of
/// `ports` (default 80, 443, 8443, 8080, 8000, 10443; at most 16).
#[tauri::command]
async fn grab_web_identity(
    jobs: State<'_, UtilityJobs>,
    ip: String,
    ports: Option<Vec<u16>>,
) -> Result<WebIdentity, String> {
    let ip = gui_ip(&ip)?;
    if ip.is_unspecified() || ip.is_multicast() {
        return Err(format!("{ip} cannot be probed"));
    }
    let ports = webid::plan_ports(ports.as_deref())?;
    let (id, cancel) = jobs.web.begin()?;
    let res = webid::grab_web_identity(
        ip,
        &ports,
        webid::DEFAULT_TIMEOUT,
        &cancel,
        SocketBudget::global(),
    )
    .await;
    let stopped = cancel.is_cancelled();
    jobs.web.end(id);
    if stopped {
        return Err("web identity lookup stopped".into());
    }
    Ok(res)
}

/// Whether the iperf3 binary is installed (path, version, live streaming support).
#[tauri::command]
async fn iperf_available() -> IperfAvailability {
    iperf::availability().await
}

/// Start an iPerf3 client test against `ip`. Rejects immediately (with an install hint)
/// when iperf3 is missing. Returns the `runId`; results arrive as `iperf-update` events,
/// the last with `done: true` and the summary or an error.
#[tauri::command]
async fn start_iperf(
    app: AppHandle,
    jobs: State<'_, UtilityJobs>,
    ip: String,
    options: Option<IperfOptions>,
) -> Result<u64, String> {
    let ip = iperf::parse_server(&ip).map_err(|e| e.to_string())?;
    let opts = options.unwrap_or_default();
    opts.validate().map_err(|e| e.to_string())?;
    let avail = iperf::availability().await;
    if !avail.available {
        return Err(avail
            .install_hint
            .unwrap_or_else(|| format!("iperf3 is not available; {}", iperf::install_hint())));
    }
    let (id, cancel) = jobs.iperf.begin()?;
    tauri::async_runtime::spawn(async move {
        let (tx, mut rx) = mpsc::channel::<IperfInterval>(64);
        let emitter = app.clone();
        let forwarder = tauri::async_runtime::spawn(async move {
            while let Some(interval) = rx.recv().await {
                let _ = emitter.emit(
                    IPERF_EVENT,
                    IperfUpdate {
                        run_id: id,
                        interval: Some(interval),
                        summary: None,
                        done: false,
                        error: None,
                    },
                );
            }
        });
        let res = iperf::run_iperf(ip, &opts, tx, cancel).await;
        let _ = forwarder.await;
        let (summary, error) = match res {
            Ok(s) => (Some(s), None),
            Err(e) => (None, Some(sanitize_log(&format!("{e:#}")))),
        };
        let _ = app.emit(
            IPERF_EVENT,
            IperfUpdate {
                run_id: id,
                interval: None,
                summary,
                done: true,
                error,
            },
        );
        app.state::<UtilityJobs>().iperf.end(id);
    });
    Ok(id)
}

/// Stop an iPerf3 test (kills the iperf3 process). Returns `true` when it was running.
#[tauri::command]
fn stop_iperf(jobs: State<'_, UtilityJobs>, run_id: u64) -> bool {
    jobs.iperf.stop(run_id)
}

fn run_gui() -> ExitCode {
    sweepr_core::init_tracing();
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(ScanManager::default())
        .manage(PortScans::default())
        .manage(LastReport::default())
        .manage(UtilityJobs::default())
        .invoke_handler(tauri::generate_handler![
            list_interfaces,
            start_scan,
            stop_scan,
            start_vlan_discovery,
            export_devices,
            load_overrides,
            save_override,
            scan_ports,
            query_snmp,
            generate_report,
            reveal_report,
            wake_device,
            start_latency_monitor,
            stop_latency_monitor,
            start_trace,
            stop_trace,
            grab_web_identity,
            iperf_available,
            start_iperf,
            stop_iperf
        ])
        .build(tauri::generate_context!());
    match app {
        Ok(app) => {
            app.run(|handle, event| {
                if let tauri::RunEvent::Exit = event {
                    // Stop monitors, traces and iperf3 runs (killing their child processes)
                    // before the process exits.
                    if let Some(s) = handle.try_state::<ScanManager>() {
                        s.stop(None);
                    }
                    if let Some(jobs) = handle.try_state::<UtilityJobs>() {
                        jobs.shutdown(Duration::from_millis(750));
                    }
                }
            });
            ExitCode::SUCCESS
        }
        Err(e) => {
            diag!("error: failed to start the SweepR GUI: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn report_subcommand_and_scan_report_flag_parse() {
        let cli = Cli::try_parse_from([
            "sweepr",
            "report",
            "--input",
            "scan.json",
            "--format",
            "pdf",
            "-o",
            "out.pdf",
            "--title",
            "Q3",
            "--org",
            "Acme",
            "--logo",
            "logo.png",
        ])
        .unwrap();
        let Some(Command::Report(a)) = cli.command else {
            panic!("expected report");
        };
        assert_eq!(a.format, Some(CliReportFormat::Pdf));
        assert_eq!(a.org.as_deref(), Some("Acme"));
        assert!(Cli::try_parse_from(["sweepr", "report", "-o", "x.html"]).is_err());
        let cli = Cli::try_parse_from(["sweepr", "scan", "--report", "audit.html"]).unwrap();
        let Some(Command::Scan(s)) = cli.command else {
            panic!("expected scan");
        };
        assert_eq!(s.report, Some(PathBuf::from("audit.html")));
    }

    #[test]
    fn scan_flags_map_to_config() {
        let cli = Cli::try_parse_from([
            "sweepr",
            "scan",
            "-i",
            "en0",
            "-r",
            "10.177.134.1-10.177.140.254",
            "--vlan",
            "10,20,30",
            "--snmp-community",
            "public",
            "--cdp-lldp",
            "-6",
            "-p",
            "22,443",
            "-o",
            "csv",
        ])
        .unwrap();
        let Some(Command::Scan(args)) = cli.command else {
            panic!("expected scan")
        };
        let cfg = args.to_config().unwrap();
        assert_eq!(cfg.interface.as_deref(), Some("en0"));
        assert_eq!(cfg.vlans, VlanSelection::List(vec![10, 20, 30]));
        assert!(cfg.cdp_lldp && cfg.ipv6);
        assert!(!cfg.snmp_all);
        let snmp = cfg.snmp.unwrap();
        assert_eq!(snmp.community, "public");
        assert_eq!(snmp.version, SnmpVersion::V2c);
        assert_eq!(cfg.ports, vec![22, 443]);
        assert_eq!(args.output, OutputFormat::Csv);
    }

    #[test]
    fn gui_flag_and_bad_input() {
        let cli = Cli::try_parse_from(["sweepr", "--gui"]).unwrap();
        assert!(cli.gui && cli.command.is_none());
        assert!(Cli::try_parse_from(["sweepr", "scan", "--vlan", "5000"]).is_err());
        assert!(Cli::try_parse_from(["sweepr", "scan", "-o", "pdf"]).is_err());
        let v = Cli::try_parse_from(["sweepr", "vlans", "-i", "en0", "--timeout", "30"]).unwrap();
        assert!(matches!(
            v.command,
            Some(Command::Vlans(VlansArgs { timeout: 30, .. }))
        ));
    }

    #[test]
    fn scan_manager_supersedes_and_stops() {
        let m = ScanManager::default();
        let (a, ta) = m.begin();
        let (b, tb) = m.begin();
        assert!(a >= 1 && b > a);
        assert!(ta.is_cancelled() && !tb.is_cancelled());
        // The superseded job is no longer current, so its events are not forwarded.
        assert!(!m.is_current(a) && m.is_current(b));
        m.end(a); // stale id: no effect
        assert!(!m.stop(Some(a)), "stopping a superseded id does nothing");
        assert!(!tb.is_cancelled());
        assert!(m.stop(Some(b)));
        assert!(tb.is_cancelled());
        // Stopped but not yet ended: its final events (finished) still reach the UI.
        assert!(m.is_current(b));
        m.end(b);
        assert!(!m.is_current(b));
        assert!(!m.stop(None));
    }

    #[test]
    fn gui_events_carry_the_scan_id() {
        let ev = ScanEvent::info("hello");
        let v = serde_json::to_value(GuiScanEvent {
            scan_id: 7,
            event: &ev,
        })
        .unwrap();
        assert_eq!(v["scanId"], 7);
        assert_eq!(v["event"]["type"], "log");
        assert_eq!(v["event"]["data"]["message"], "hello");
        // The CLI / core JSON event shape is unchanged.
        let plain = serde_json::to_value(&ev).unwrap();
        assert_eq!(plain["type"], "log");
        assert!(plain.get("scanId").is_none());
    }

    #[test]
    fn export_path_resolution() {
        let dir = std::env::temp_dir().join(format!("sweepr-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ok = dir.join("a.csv");
        assert_eq!(
            resolve_export_path(ok.clone(), ExportFormat::Csv).unwrap(),
            ok
        );
        assert!(resolve_export_path(dir.join("a.txt"), ExportFormat::Csv).is_err());
        assert!(resolve_export_path(dir.join("a.json"), ExportFormat::Xlsx).is_err());
        assert_eq!(
            resolve_export_path(dir.join("devices"), ExportFormat::Xlsx).unwrap(),
            dir.join("devices.xlsx")
        );
        // Adding the extension must not silently clobber a file the dialog never confirmed.
        std::fs::write(dir.join("taken.json"), b"[]").unwrap();
        assert!(resolve_export_path(dir.join("taken"), ExportFormat::Json).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_resolve_flag_disables_name_resolution() {
        let cli = Cli::try_parse_from(["sweepr", "scan", "--no-resolve"]).unwrap();
        let Some(Command::Scan(args)) = cli.command else {
            panic!("expected scan")
        };
        assert!(!args.to_config().unwrap().resolve_names);
        let cli = Cli::try_parse_from(["sweepr", "scan"]).unwrap();
        let Some(Command::Scan(args)) = cli.command else {
            panic!("expected scan")
        };
        let cfg = args.to_config().unwrap();
        assert!(cfg.resolve_names);
        assert!(cfg.snmp.is_none(), "SNMP stays off unless requested");
    }

    #[test]
    fn snmp_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "sweepr",
            "snmp",
            "10.0.0.1",
            "--snmp-community",
            "private",
            "-o",
            "json",
        ])
        .unwrap();
        let Some(Command::Snmp(args)) = cli.command else {
            panic!("expected snmp")
        };
        assert_eq!(args.ip, "10.0.0.1");
        assert_eq!(args.snmp.snmp_community.as_deref(), Some("private"));
        assert_eq!(args.output, SnmpOutput::Json);
        // The `snmp` subcommand defaults to v2c "public".
        let cli = Cli::try_parse_from(["sweepr", "snmp", "10.0.0.1"]).unwrap();
        let Some(Command::Snmp(args)) = cli.command else {
            panic!("expected snmp")
        };
        let cfg = args.snmp.to_config(true).unwrap().unwrap();
        assert_eq!(
            (cfg.version, cfg.community.as_str()),
            (SnmpVersion::V2c, "public")
        );
    }

    /// Serializes the tests that read (or set) the SNMP password environment variables.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn scan_snmp(args: &[&str]) -> Result<Option<SnmpConfig>> {
        let cli = Cli::try_parse_from(["sweepr", "scan"].into_iter().chain(args.iter().copied()))?;
        let Some(Command::Scan(args)) = cli.command else {
            panic!("expected scan")
        };
        Ok(args.to_config()?.snmp)
    }

    #[test]
    fn snmp_version_and_v3_credential_flags() {
        let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        let cfg = scan_snmp(&[
            "--snmp-version",
            "3",
            "--snmp-user",
            "monitor",
            "--snmp-auth-proto",
            "sha256",
            "--snmp-auth-pass",
            "authpass1",
            "--snmp-priv-proto",
            "aes256",
            "--snmp-priv-pass",
            "privpass1",
        ])
        .unwrap()
        .unwrap();
        assert_eq!(cfg.version, SnmpVersion::V3);
        let v3 = cfg.v3.unwrap();
        assert_eq!(v3.username, "monitor");
        assert_eq!(v3.auth_protocol, SnmpAuthProtocol::Sha256);
        assert_eq!(v3.auth_password.as_deref(), Some("authpass1"));
        assert_eq!(v3.priv_protocol, SnmpPrivProtocol::Aes256);
        assert_eq!(v3.priv_password.as_deref(), Some("privpass1"));
        // A user implies v3; v1 by name or alias.
        let cfg = scan_snmp(&["--snmp-user", "monitor"]).unwrap().unwrap();
        assert_eq!(cfg.version, SnmpVersion::V3);
        assert!(cfg.v3.unwrap().auth_password.is_none());
        let cfg = scan_snmp(&["--snmp-version", "v1", "--snmp-community", "c"])
            .unwrap()
            .unwrap();
        assert_eq!(
            (cfg.version, cfg.community.as_str()),
            (SnmpVersion::V1, "c")
        );
        // Invalid combinations are rejected up front.
        assert!(scan_snmp(&["--snmp-version", "3"]).is_err()); // no user
        assert!(scan_snmp(&["--snmp-user", "u", "--snmp-auth-pass", "short"]).is_err());
        assert!(scan_snmp(&["--snmp-user", "u", "--snmp-priv-pass", "privpass1"]).is_err());
        assert!(scan_snmp(&["--snmp-version", "2c", "--snmp-user", "u"]).is_err());
        assert!(scan_snmp(&["--snmp-version", "4"]).is_err());
        assert!(
            scan_snmp(&["--snmp-all"]).is_err(),
            "--snmp-all needs SNMP settings"
        );
        let cli =
            Cli::try_parse_from(["sweepr", "scan", "--snmp-community", "x", "--snmp-all"]).unwrap();
        let Some(Command::Scan(args)) = cli.command else {
            panic!("expected scan")
        };
        assert!(args.to_config().unwrap().snmp_all);
    }

    #[test]
    fn snmp_passwords_come_from_the_environment() {
        let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        std::env::set_var("SWEEPR_SNMP_AUTH_PASS", "env-auth-pass");
        std::env::set_var("SWEEPR_SNMP_PRIV_PASS", "env-priv-pass");
        let res = scan_snmp(&["--snmp-user", "monitor"]);
        let snmp = Cli::try_parse_from(["sweepr", "snmp", "10.0.0.1", "--snmp-user", "u"]);
        std::env::remove_var("SWEEPR_SNMP_AUTH_PASS");
        std::env::remove_var("SWEEPR_SNMP_PRIV_PASS");
        let v3 = res.unwrap().unwrap().v3.unwrap();
        assert_eq!(v3.auth_password.as_deref(), Some("env-auth-pass"));
        assert_eq!(v3.priv_password.as_deref(), Some("env-priv-pass"));
        let Some(Command::Snmp(args)) = snmp.unwrap().command else {
            panic!("expected snmp")
        };
        assert_eq!(args.snmp.snmp_auth_pass.as_deref(), Some("env-auth-pass"));
        // The secret values never show up in --help.
        let help = Cli::command()
            .find_subcommand_mut("scan")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(help.contains("SWEEPR_SNMP_AUTH_PASS") && !help.contains("env-auth-pass"));
    }

    #[test]
    fn port_scan_slots_are_bounded_and_cancellable() {
        let scans = PortScans::default();
        let slots: Vec<_> = (0..MAX_PORT_SCAN_JOBS)
            .map(|_| scans.try_enter().unwrap())
            .collect();
        assert!(scans.try_enter().is_none());
        drop(slots);
        assert!(scans.try_enter().is_some());
        let t = scans.token();
        scans.cancel_all();
        assert!(t.is_cancelled());
        assert!(
            !scans.token().is_cancelled(),
            "later scans get a fresh token"
        );
    }

    #[test]
    fn untagged_in_vlan_list() {
        let cli = Cli::try_parse_from(["sweepr", "scan", "--vlan", "untagged,10,20"]).unwrap();
        let Some(Command::Scan(args)) = cli.command else {
            panic!("expected scan")
        };
        assert_eq!(
            args.to_config().unwrap().vlans,
            VlanSelection::UntaggedAndList(vec![10, 20])
        );
    }

    #[test]
    fn broken_pipe_detection() {
        let pipe = || io::Error::from(io::ErrorKind::BrokenPipe);
        assert!(is_broken_pipe(&anyhow::Error::from(pipe())));
        assert!(is_broken_pipe(&anyhow::Error::from(StdoutClosed)));
        assert!(is_broken_pipe(
            &anyhow::Error::from(serde_json::Error::io(pipe())).context("writing json")
        ));
        assert!(is_broken_pipe(&anyhow::Error::from(csv::Error::from(
            pipe()
        ))));
        assert!(!is_broken_pipe(&anyhow::anyhow!("something else")));
        assert!(!is_broken_pipe(&anyhow::Error::from(io::Error::from(
            io::ErrorKind::PermissionDenied
        ))));
    }

    #[test]
    fn log_sanitizing() {
        assert_eq!(sanitize_log("a\x1b]0;x\x07b\nc"), "a]0;xb c");
    }

    fn parse(args: &[&str]) -> Result<Command, clap::Error> {
        Cli::try_parse_from(["sweepr"].iter().chain(args)).map(|c| c.command.unwrap())
    }

    #[test]
    fn utility_subcommands_parse() {
        let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        let Command::Wake(w) = parse(&[
            "wake",
            "aa:bb:cc:dd:ee:ff",
            "-i",
            "en0",
            "--broadcast",
            "10.0.0.255",
            "--port",
            "9",
            "--port",
            "7",
            "--repeat",
            "5",
        ])
        .unwrap() else {
            panic!("wake")
        };
        assert_eq!(w.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(w.broadcast, Some(Ipv4Addr::new(10, 0, 0, 255)));
        assert_eq!((w.ports.as_slice(), w.repeat), ([9, 7].as_slice(), 5));
        let Command::Wake(w) = parse(&["wake", "aabb.ccdd.eeff"]).unwrap() else {
            panic!("wake")
        };
        assert_eq!((w.ports.as_slice(), w.repeat), ([9].as_slice(), 3));
        assert!(parse(&["wake", "aa:bb:cc:dd:ee:ff", "--broadcast", "host.lan"]).is_err());
        assert!(parse(&["wake", "aa:bb:cc:dd:ee:ff", "--port", "0"]).is_err());
        assert!(parse(&["wake", "aa:bb:cc:dd:ee:ff", "--repeat", "0"]).is_err());
        assert!(parse(&["wake", "aa:bb:cc:dd:ee:ff", "--repeat", "21"]).is_err());

        let Command::Ping(p) = parse(&[
            "ping",
            "127.0.0.1",
            "::1",
            "--count",
            "3",
            "--interval-ms",
            "500",
        ])
        .unwrap() else {
            panic!("ping")
        };
        assert_eq!(p.ips, ["127.0.0.1", "::1"]);
        assert_eq!((p.count, p.interval_ms), (Some(3), 500));
        assert!(parse(&["ping"]).is_err());
        assert!(parse(&["ping", "10.0.0.1", "--count", "0"]).is_err());

        let Command::Trace(t) = parse(&[
            "trace",
            "8.8.8.8",
            "--max-hops",
            "20",
            "--rounds",
            "3",
            "-o",
            "json",
        ])
        .unwrap() else {
            panic!("trace")
        };
        assert_eq!((t.max_hops, t.rounds, t.output), (20, 3, ToolOutput::Json));
        let Command::Trace(t) = parse(&["trace", "8.8.8.8"]).unwrap() else {
            panic!("trace")
        };
        assert_eq!((t.max_hops, t.rounds, t.no_resolve), (30, 5, false));

        let Command::Web(w) = parse(&["web", "10.0.0.1", "-p", "443,8006"]).unwrap() else {
            panic!("web")
        };
        assert_eq!(w.ports.unwrap().0, vec![443, 8006]);

        let Command::Iperf(i) = parse(&[
            "iperf", "10.0.0.2", "-p", "5202", "-t", "5", "-R", "-P", "4", "--udp", "-b", "100M",
        ])
        .unwrap() else {
            panic!("iperf")
        };
        assert_eq!((i.port, i.duration, i.streams), (5202, 5, 4));
        assert!(i.reverse && i.udp);
        assert_eq!(i.bitrate.as_deref(), Some("100M"));

        let Command::Scan(sa) = parse(&["scan", "--no-web"]).unwrap() else {
            panic!("scan")
        };
        assert!(!sa.to_config().unwrap().web_identity);
        let Command::Scan(sa) = parse(&["scan"]).unwrap() else {
            panic!("scan")
        };
        assert!(sa.to_config().unwrap().web_identity);
    }

    #[test]
    fn utility_formatting() {
        assert_eq!(fmt_bps(60_122_147_560.4), "60.12 Gbit/s");
        assert_eq!(fmt_bps(999.0), "999.00 bit/s");
        assert_eq!(fmt_bps(f64::NAN), "0.00 bit/s");
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(7_516_192_768), "7.00 GiB");
        assert_eq!(fmt_ms(None), "-");
        assert_eq!(fmt_ms(Some(1.234_56)), "1.23");
    }

    #[test]
    fn utility_jobs_shut_down() {
        let jobs = UtilityJobs::default();
        let (_a, ta) = jobs.latency.begin().unwrap();
        let (b, tb) = jobs.iperf.begin().unwrap();
        jobs.iperf.end(b);
        jobs.shutdown(Duration::from_millis(50));
        assert!(ta.is_cancelled() && tb.is_cancelled());
        for _ in 0..MAX_TRACES {
            jobs.traces.begin().unwrap();
        }
        assert!(jobs.traces.begin().is_err());
    }
}
