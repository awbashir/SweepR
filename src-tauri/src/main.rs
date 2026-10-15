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
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use comfy_table::{presets::UTF8_FULL_CONDENSED, ContentArrangement, Table};
use serde::Serialize;
use sweepr_core::{
    arp_vlan::{self, L2Error, PassiveResults},
    engine,
    export::{self, ExportFormat},
    models::{
        parse_ports, sanitize_text, CdpLldpNeighbor, Device, InterfaceInfo, LogLevel, ScanConfig,
        ScanEvent, ScanPhase, ScanSummary, SnmpConfig, VlanInfo, VlanSelection, VlanSource,
        DEFAULT_PORTS, MAX_LISTEN_SECS,
    },
};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

/// Tauri event name carrying every [`ScanEvent`] to the frontend, wrapped in a
/// [`GuiScanEvent`] (`{ scanId, event }`).
const SCAN_EVENT: &str = "scan-event";

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
    /// List network interfaces with their kind, VLAN and addresses
    Interfaces,
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

    /// SNMP v2c community for infrastructure polling
    #[arg(long, value_name = "COMMUNITY")]
    snmp_community: Option<String>,

    /// Also discover IPv6 neighbors (ICMPv6 all-nodes echo / NDP)
    #[arg(short = '6', long)]
    ipv6: bool,

    /// TCP ports to probe, e.g. 22,80,443 or 1-1024
    #[arg(short, long, value_name = "PORTS", value_parser = parse_ports_arg)]
    ports: Option<PortList>,

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

fn parse_vlan_arg(s: &str) -> Result<VlanSelection, String> {
    s.parse()
        .map_err(|e: sweepr_core::models::ModelError| e.to_string())
}

fn parse_ports_arg(s: &str) -> Result<PortList, String> {
    parse_ports(s).map(PortList).map_err(|e| e.to_string())
}

impl ScanArgs {
    /// Warnings for options that are accepted but not acted on yet.
    fn deferred_feature_warnings(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.ports.is_some() {
            out.push(
                "-p/--ports is accepted, but TCP port probing arrives in a later release; no \
                 ports will be scanned",
            );
        }
        if self.snmp_community.is_some() {
            out.push(
                "--snmp-community is accepted, but SNMP polling arrives in a later release; no \
                 SNMP queries will be sent",
            );
        }
        out
    }

    fn to_config(&self) -> ScanConfig {
        ScanConfig {
            interface: self.interface.clone(),
            range: self.range.clone(),
            vlans: self.vlan.clone().unwrap_or_default(),
            discover_vlans: self.discover_vlans,
            cdp_lldp: self.cdp_lldp,
            snmp: self.snmp_community.clone().map(SnmpConfig::v2c),
            ipv6: self.ipv6,
            ports: self
                .ports
                .clone()
                .map_or_else(|| DEFAULT_PORTS.to_vec(), |p| p.0),
            resolve_names: true,
            timeout_ms: self.timeout_ms,
            retries: self.retries,
            rate_pps: self.rate_pps,
            concurrency: self.concurrency,
            listen_secs: self.listen_secs,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------------------------

fn main() -> ExitCode {
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
        Command::Interfaces => cmd_interfaces().await,
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
    let cfg = args.to_config();
    cfg.validate()?;
    for w in args.deferred_feature_warnings() {
        diag!("warning: {w}");
    }

    let (tx, mut rx) = mpsc::channel(1024);
    let scan = tokio::spawn(engine::run_scan(cfg, tx, cancel.clone()));
    let mut ui = LiveRenderer::new(args.output == OutputFormat::Table, cancel.clone());
    while let Some(ev) = rx.recv().await {
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
        engine::run_scan(config, tx, cancel).await.map(|_| ())
    });
    Ok(id)
}

/// Stop the running job (only if it is `scan_id`, when given). Returns `true` if one was
/// signalled; its `finished` event follows.
#[tauri::command]
fn stop_scan(state: State<'_, ScanManager>, scan_id: Option<u64>) -> bool {
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

fn run_gui() -> ExitCode {
    sweepr_core::init_tracing();
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(ScanManager::default())
        .invoke_handler(tauri::generate_handler![
            list_interfaces,
            start_scan,
            stop_scan,
            start_vlan_discovery,
            export_devices
        ])
        .run(tauri::generate_context!());
    match result {
        Ok(()) => ExitCode::SUCCESS,
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
        let cfg = args.to_config();
        assert_eq!(cfg.interface.as_deref(), Some("en0"));
        assert_eq!(cfg.vlans, VlanSelection::List(vec![10, 20, 30]));
        assert!(cfg.cdp_lldp && cfg.ipv6);
        assert_eq!(cfg.snmp.unwrap().community, "public");
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
    fn deferred_features_warn() {
        let cli = Cli::try_parse_from(["sweepr", "scan", "-p", "22", "--snmp-community", "public"])
            .unwrap();
        let Some(Command::Scan(args)) = cli.command else {
            panic!("expected scan")
        };
        let w = args.deferred_feature_warnings();
        assert_eq!(w.len(), 2);
        assert!(w[0].contains("--ports") && w[1].contains("--snmp-community"));
        let cli = Cli::try_parse_from(["sweepr", "scan"]).unwrap();
        let Some(Command::Scan(args)) = cli.command else {
            panic!("expected scan")
        };
        assert!(args.deferred_feature_warnings().is_empty());
    }

    #[test]
    fn untagged_in_vlan_list() {
        let cli = Cli::try_parse_from(["sweepr", "scan", "--vlan", "untagged,10,20"]).unwrap();
        let Some(Command::Scan(args)) = cli.command else {
            panic!("expected scan")
        };
        assert_eq!(
            args.to_config().vlans,
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
}
