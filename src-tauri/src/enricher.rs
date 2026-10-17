//! Device enrichment: vendor (embedded IEEE OUI database), DNS PTR, mDNS, NetBIOS, a TCP
//! connect port scan and a no-SNMP management-port role fingerprint. Also the local
//! persistence of user device overrides (hostname / comments).
//!
//! Every parser that consumes network bytes (NetBIOS node-status responses especially) is
//! bounds-checked and hostile-input safe, and every piece of text is run through
//! [`sanitize_text`] before it is kept.

use std::{
    collections::{HashMap, HashSet},
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, OnceLock, PoisonError,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use directories::ProjectDirs;
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::{mpsc::Sender, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use crate::{
    limits::{self, SocketBudget},
    models::{
        format_mac, now_ms, parse_mac, sanitize_override, sanitize_text, Device, DeviceOverride,
        DeviceRole, DiscoverySource, RoleConfidence, RoleSource, ScanConfig, ScanEvent,
        MAX_CONCURRENCY, MAX_MDNS_SERVICES,
    },
    progress::ProgressScope,
};

/// Attempts for a socket operation that fails with `EMFILE` / `ENFILE` (with backoff).
const FD_RETRIES: u32 = 6;

/// Backoff before retry `attempt` after a descriptor-exhaustion error.
fn fd_backoff(attempt: u32) -> Duration {
    Duration::from_millis(20u64 << attempt.min(6))
}

// ---------------------------------------------------------------------------------------------
// Embedded IEEE OUI vendor database
// ---------------------------------------------------------------------------------------------

/// The compact, sorted `<ASSIGNMENT-HEX>\t<VENDOR>` table built by `scripts/build_oui_db.py`
/// from the IEEE MA-L, MA-M and MA-S registries.
static OUI_TSV: &str = include_str!("../data/oui.tsv");

/// Lazily parsed OUI map, keyed by uppercase assignment hex (6, 7 or 9 digits).
fn oui_map() -> &'static HashMap<&'static str, &'static str> {
    static MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        for line in OUI_TSV.lines() {
            if let Some((key, vendor)) = line.split_once('\t') {
                if !key.is_empty() && !vendor.is_empty() {
                    m.insert(key, vendor);
                }
            }
        }
        m
    })
}

/// `true` when the MAC is multicast (I/G bit) or locally administered (U/L bit) — i.e. a
/// group address or a randomized / privacy MAC that is not tied to a real vendor OUI.
pub fn is_locally_administered_or_multicast(mac: &[u8; 6]) -> bool {
    mac[0] & 0x01 != 0 || mac[0] & 0x02 != 0
}

/// Look up the IEEE-registered vendor for a MAC address, trying the most specific assignment
/// first (MA-S /36, then MA-M /28, then MA-L /24). Returns `None` for malformed, multicast or
/// locally-administered (randomized) MACs, and for OUIs not in the registry.
pub fn vendor_for_mac(mac: &str) -> Option<String> {
    let bytes = parse_mac(mac)?;
    if is_locally_administered_or_multicast(&bytes) {
        return None;
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
    let map = oui_map();
    for len in [9usize, 7, 6] {
        if let Some(vendor) = map.get(&hex[..len]) {
            return Some((*vendor).to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------------------------
// NetBIOS node status (UDP 137)
// ---------------------------------------------------------------------------------------------

/// Names learned from a NetBIOS node-status (NBSTAT) reply.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetbiosInfo {
    /// Workstation name (unique name with suffix 0x00).
    pub name: Option<String>,
    /// Workgroup / domain (group name with suffix 0x00).
    pub workgroup: Option<String>,
    /// Adapter MAC from the statistics block, when present and non-zero.
    pub mac: Option<String>,
}

impl NetbiosInfo {
    fn is_empty(&self) -> bool {
        self.name.is_none() && self.workgroup.is_none() && self.mac.is_none()
    }
}

/// NetBIOS names table caps (hostile-response bound).
const MAX_NB_NAMES: usize = 64;

/// Build the NBSTAT (node status) query for the wildcard name `*`.
pub fn build_nbstat_query(txn_id: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(50);
    pkt.extend_from_slice(&txn_id.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // flags: query, unicast
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR = 0
                                                                  // Question name: "*" padded with NULs to 16 bytes, level-1 encoded (two nibbles per byte,
                                                                  // each mapped to 'A'..'P').
    let mut name = [0u8; 16];
    name[0] = b'*';
    pkt.push(0x20); // encoded length = 32
    for b in name {
        pkt.push(b'A' + (b >> 4));
        pkt.push(b'A' + (b & 0x0f));
    }
    pkt.push(0x00); // root label
    pkt.extend_from_slice(&[0x00, 0x21]); // QTYPE = NBSTAT
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    pkt
}

/// Advance past one DNS/NetBIOS name starting at `pos`, returning the offset just after it. A
/// name is a sequence of length-prefixed labels ending in a zero label, or a 2-byte
/// compression pointer (top two bits set).
fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let b = *buf.get(pos)?;
        if b == 0 {
            return Some(pos + 1);
        }
        if b & 0xc0 == 0xc0 {
            return Some(pos + 2); // compression pointer terminates the name
        }
        pos = pos.checked_add(1 + b as usize)?;
    }
}

/// Parse an NBSTAT response. Bounds-checked throughout; returns `None` on any truncation or
/// when nothing useful is present.
pub fn parse_nbstat_response(resp: &[u8]) -> Option<NetbiosInfo> {
    // Header: id(2) flags(2) qd(2) an(2) ns(2) ar(2).
    if resp.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    if ancount == 0 || qdcount > 8 {
        return None;
    }
    // Skip the echoed question section (name + QTYPE + QCLASS each).
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(resp, pos)?;
        pos = pos.checked_add(4)?;
    }
    // Answer RR: name, then TYPE(2) CLASS(2) TTL(4) RDLENGTH(2), then the names count.
    pos = skip_name(resp, pos)?;
    let rr_type = resp.get(pos..pos + 2)?;
    if rr_type != [0x00, 0x21] {
        return None; // not an NBSTAT answer
    }
    let count_pos = pos.checked_add(2 + 2 + 4 + 2)?;
    let count = *resp.get(count_pos)? as usize;
    if count == 0 || count > MAX_NB_NAMES {
        return None;
    }
    let mut info = NetbiosInfo::default();
    let mut p = count_pos + 1;
    for _ in 0..count {
        // 15 bytes name + 1 byte suffix + 2 bytes flags.
        let end = p + 18;
        let entry = resp.get(p..end)?;
        let raw = &entry[0..15];
        let suffix = entry[15];
        let flags = u16::from_be_bytes([entry[16], entry[17]]);
        let is_group = flags & 0x8000 != 0;
        let name = sanitize_text(&String::from_utf8_lossy(raw))
            .trim()
            .to_string();
        if !name.is_empty() && suffix == 0x00 {
            if is_group {
                info.workgroup.get_or_insert(name);
            } else {
                info.name.get_or_insert(name);
            }
        }
        p = end;
    }
    // Statistics block begins with the 6-byte adapter MAC.
    if let Some(mac_bytes) = resp.get(p..p + 6) {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(mac_bytes);
        if mac != [0u8; 6] && mac[0] & 0x01 == 0 {
            info.mac = Some(format_mac(&mac));
        }
    }
    (!info.is_empty()).then_some(info)
}

/// `true` when `resp` is an NBSTAT *response* to the query with transaction id `txn`.
pub fn nbstat_reply_matches(resp: &[u8], txn: u16) -> bool {
    resp.len() >= 4 && resp[0..2] == txn.to_be_bytes() && resp[2] & 0x80 != 0
}

/// Send an NBSTAT query to `ip:137` and parse the reply within `timeout`. The socket is
/// connected to the target (the kernel drops datagrams from anyone else) and replies whose
/// transaction id does not match the query are ignored.
pub async fn netbios_query(
    ip: IpAddr,
    timeout: Duration,
    budget: &SocketBudget,
) -> Option<NetbiosInfo> {
    let bind: SocketAddr = match ip {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => return None, // NetBIOS name service is IPv4-only
    };
    let _permit = budget.acquire().await?;
    let sock = bind_udp(bind, "NetBIOS lookup").await?;
    sock.connect(SocketAddr::new(ip, 137)).await.ok()?;
    let txn = (now_ms() as u16) ^ (std::process::id() as u16) ^ nbstat_salt();
    let query = build_nbstat_query(txn);
    sock.send(&query).await.ok()?;
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = [0u8; 2048];
    loop {
        let n = tokio::time::timeout_at(deadline, sock.recv(&mut buf))
            .await
            .ok()?
            .ok()?;
        if nbstat_reply_matches(&buf[..n], txn) {
            return parse_nbstat_response(&buf[..n]);
        }
        // Stale or forged datagram: keep waiting for the real reply until the deadline.
    }
}

/// Per-query variation so concurrent lookups do not share transaction ids.
fn nbstat_salt() -> u16 {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    (SEQ.fetch_add(0x9e37, Ordering::Relaxed) & 0xffff) as u16
}

/// Bind a UDP socket, retrying with backoff when the process is out of descriptors.
async fn bind_udp(addr: SocketAddr, context: &str) -> Option<UdpSocket> {
    for attempt in 0..FD_RETRIES {
        match UdpSocket::bind(addr).await {
            Ok(sock) => return Some(sock),
            Err(e) if limits::is_fd_exhausted(&e) => {
                limits::warn_fd_exhausted_once(context);
                tokio::time::sleep(fd_backoff(attempt)).await;
            }
            Err(_) => return None,
        }
    }
    None
}

// ---------------------------------------------------------------------------------------------
// DNS PTR
// ---------------------------------------------------------------------------------------------

/// The `nameserver` addresses of a resolv.conf that parse as plain IP addresses. Scoped IPv6
/// link-local entries (`fe80::1%en0`) cannot be expressed as an `IpAddr` and are skipped.
pub fn resolv_conf_nameservers(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let l = l.split(['#', ';']).next()?.trim();
            let mut parts = l.split_whitespace();
            (parts.next()? == "nameserver")
                .then(|| parts.next()?.parse::<IpAddr>().ok())
                .flatten()
        })
        .collect()
}

/// Build a Tokio DNS resolver from the system configuration with bounded per-query timeout
/// and attempts.
///
/// When the system configuration cannot be parsed as a whole (hickory rejects, for example,
/// a scoped link-local IPv6 `nameserver fe80::1%en0` line, which macOS writes routinely), the
/// usable `nameserver` lines of `/etc/resolv.conf` are used instead. When there are none,
/// returns `None`: PTR lookups for internal addresses are then skipped rather than sent to a
/// public resolver, which could neither answer them nor be trusted with the scanned hosts.
fn build_resolver(timeout: Duration, attempts: usize) -> Option<hickory_resolver::TokioResolver> {
    use hickory_resolver::{
        config::{NameServerConfig, ResolverConfig},
        net::runtime::TokioRuntimeProvider,
    };
    let mut builder = match hickory_resolver::TokioResolver::builder_tokio() {
        Ok(b) => b,
        Err(e) => {
            let servers = std::fs::read_to_string("/etc/resolv.conf")
                .map(|t| resolv_conf_nameservers(&t))
                .unwrap_or_default();
            if servers.is_empty() {
                tracing::debug!("cannot read the system DNS configuration: {e}");
                return None;
            }
            tracing::debug!(
                "system DNS configuration only partly readable ({e}); using {servers:?}"
            );
            hickory_resolver::TokioResolver::builder_with_config(
                ResolverConfig::from_name_servers(
                    servers
                        .into_iter()
                        .map(NameServerConfig::udp_and_tcp)
                        .collect(),
                ),
                TokioRuntimeProvider::default(),
            )
        }
    };
    {
        let opts = builder.options_mut();
        opts.timeout = timeout;
        opts.attempts = attempts;
        opts.use_hosts_file = hickory_resolver::config::ResolveHosts::Auto;
    }
    match builder.build() {
        Ok(r) => Some(r),
        Err(e) => {
            tracing::debug!("cannot build the system DNS resolver: {e}");
            None
        }
    }
}

/// Reverse-resolve `ip` to a single PTR hostname (trailing dot stripped, sanitized). Holds
/// one socket permit for the lookup.
async fn dns_ptr(
    resolver: &hickory_resolver::TokioResolver,
    ip: IpAddr,
    budget: &SocketBudget,
) -> Option<String> {
    use hickory_resolver::proto::rr::RData;
    let _permit = budget.acquire().await?;
    let lookup = resolver.reverse_lookup(ip).await.ok()?;
    for record in lookup.answers() {
        if let RData::PTR(ptr) = &record.data {
            let name = sanitize_text(ptr.0.to_utf8().trim_end_matches('.'));
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

/// A reusable reverse-DNS resolver built from the system configuration (traceroute hop
/// names, single-device lookups). Same policy as the scan: no public fallback resolver.
#[derive(Clone)]
pub struct PtrResolver {
    inner: Arc<hickory_resolver::TokioResolver>,
    budget: SocketBudget,
}

impl PtrResolver {
    /// The system resolver with a per-query `timeout` (two attempts), drawing sockets from
    /// the global budget. `None` when the system DNS configuration cannot be used.
    pub fn system(timeout: Duration) -> Option<Self> {
        build_resolver(timeout, 2).map(|r| Self {
            inner: Arc::new(r),
            budget: SocketBudget::global().clone(),
        })
    }

    /// Reverse-resolve `ip` to one sanitized PTR name.
    pub async fn lookup(&self, ip: IpAddr) -> Option<String> {
        dns_ptr(&self.inner, ip, &self.budget).await
    }
}

// ---------------------------------------------------------------------------------------------
// mDNS discovery
// ---------------------------------------------------------------------------------------------

const MAX_MDNS_TYPES: usize = 64;
const MAX_MDNS_HOSTS: usize = 4096;

/// What one host advertised over mDNS: its host name and the DNS-SD service types seen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MdnsHost {
    pub name: String,
    /// Service types without the `.local.` suffix (`_http._tcp`, `_csco-sb._tcp`), at most
    /// [`MAX_MDNS_SERVICES`], in discovery order.
    pub services: Vec<String>,
}

/// `_http._tcp.local.` -> `_http._tcp` (sanitized, lowercase); `None` when unusable.
pub fn normalize_service_type(ty: &str) -> Option<String> {
    let t = ty.trim().trim_end_matches('.');
    let t = t.strip_suffix(".local").unwrap_or(t);
    let t = sanitize_text(t).to_ascii_lowercase();
    (t.starts_with('_') && t.len() <= 64 && !t.contains(' ')).then_some(t)
}

/// Record one resolved service for `host` at `ip` in `map` (bounded).
fn record_mdns(map: &mut HashMap<IpAddr, MdnsHost>, ip: IpAddr, host: &str, service: Option<&str>) {
    if map.len() >= MAX_MDNS_HOSTS && !map.contains_key(&ip) {
        return;
    }
    let entry = map.entry(ip).or_insert_with(|| MdnsHost {
        name: host.to_string(),
        services: Vec::new(),
    });
    if let Some(svc) = service.and_then(normalize_service_type) {
        if entry.services.len() < MAX_MDNS_SERVICES && !entry.services.contains(&svc) {
            entry.services.push(svc);
        }
    }
}

/// Browse the local mDNS realm for `duration`, returning a map of IP address to the
/// advertised host name and service types. Runs the service daemon on a blocking thread (it
/// owns its own background thread and sync channels), so callers should `spawn_blocking`
/// this.
pub fn mdns_discover_blocking(duration: Duration) -> HashMap<IpAddr, MdnsHost> {
    use mdns_sd::{ServiceDaemon, ServiceEvent};
    let mut map: HashMap<IpAddr, MdnsHost> = HashMap::new();
    let Ok(daemon) = ServiceDaemon::new() else {
        return map;
    };
    const META: &str = "_services._dns-sd._udp.local.";
    let Ok(meta) = daemon.browse(META) else {
        let _ = daemon.shutdown();
        return map;
    };
    let deadline = Instant::now() + duration;
    let mut browsed: HashSet<String> = HashSet::new();
    let mut type_receivers = Vec::new();
    let slice = Duration::from_millis(150);

    while Instant::now() < deadline {
        if let Ok(ServiceEvent::ServiceFound(_, service_type)) = meta.recv_timeout(slice) {
            if browsed.len() < MAX_MDNS_TYPES && browsed.insert(service_type.clone()) {
                if let Ok(rx) = daemon.browse(&service_type) {
                    type_receivers.push(rx);
                }
            }
        }
        for rx in &type_receivers {
            while let Ok(event) = rx.try_recv() {
                if let ServiceEvent::ServiceResolved(info) = event {
                    let host = sanitize_text(info.get_hostname().trim_end_matches('.'));
                    if host.is_empty() {
                        continue;
                    }
                    for addr in info.get_addresses() {
                        record_mdns(
                            &mut map,
                            addr.to_ip_addr(),
                            &host,
                            Some(info.ty_domain.as_str()),
                        );
                    }
                }
            }
        }
        if map.len() >= MAX_MDNS_HOSTS {
            break;
        }
    }
    let _ = daemon.shutdown();
    map
}

// ---------------------------------------------------------------------------------------------
// TCP connect port scan
// ---------------------------------------------------------------------------------------------

/// Largest number of ports a single [`scan_ports`] call will probe (bounds GUI input).
pub const MAX_SCAN_PORTS: usize = 65_535;

/// Result of a TCP connect scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortScan {
    /// Ports that accepted a connection, sorted.
    pub open: Vec<u16>,
    /// Ports whose state could not be determined because the process kept running out of file
    /// descriptors (`EMFILE` / `ENFILE`) even after retries. They are *not* closed.
    pub unverified: Vec<u16>,
}

/// Sorted, de-duplicated, non-zero ports.
pub fn dedupe_ports(ports: &[u16]) -> Vec<u16> {
    let mut unique: Vec<u16> = ports.iter().copied().filter(|p| *p != 0).collect();
    unique.sort_unstable();
    unique.dedup();
    unique
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PortState {
    Open,
    Closed,
    Unverified,
}

/// One TCP connect probe holding a socket permit from `budget`. Descriptor exhaustion is
/// retried with backoff and, if it persists, reported as [`PortState::Unverified`].
async fn probe_port(addr: SocketAddr, timeout: Duration, budget: &SocketBudget) -> PortState {
    for attempt in 0..FD_RETRIES {
        let Some(permit) = budget.acquire().await else {
            return PortState::Unverified;
        };
        // The connect timeout starts once we hold a permit, so queueing is not "closed".
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => return PortState::Open,
            Ok(Err(e)) if limits::is_fd_exhausted(&e) => {
                limits::warn_fd_exhausted_once("TCP port scan");
                drop(permit);
                tokio::time::sleep(fd_backoff(attempt)).await;
            }
            _ => return PortState::Closed,
        }
    }
    PortState::Unverified
}

/// TCP connect scan of `ports` on `ip` with at most `concurrency` connects in flight for this
/// call, every socket also drawing from the shared `budget`. Each connect is bounded by
/// `per_timeout`. Banner-free.
pub async fn scan_ports(
    ip: IpAddr,
    ports: &[u16],
    concurrency: usize,
    per_timeout: Duration,
    cancel: &CancellationToken,
    budget: &SocketBudget,
) -> PortScan {
    let mut unique = dedupe_ports(ports);
    unique.truncate(MAX_SCAN_PORTS);

    let semaphore = Arc::new(Semaphore::new(concurrency.clamp(1, MAX_CONCURRENCY)));
    let mut tasks = JoinSet::new();
    let timeout = per_timeout.max(Duration::from_millis(1));
    for port in unique {
        if cancel.is_cancelled() {
            break;
        }
        let Ok(permit) = semaphore.clone().acquire_owned().await else {
            break;
        };
        let (cancel, budget) = (cancel.clone(), budget.clone());
        tasks.spawn(async move {
            let _permit = permit;
            tokio::select! {
                _ = cancel.cancelled() => (port, PortState::Closed),
                state = probe_port(SocketAddr::new(ip, port), timeout, &budget) => (port, state),
            }
        });
        while tasks.try_join_next().is_some() {}
    }
    let mut out = PortScan::default();
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok((port, PortState::Open)) => out.open.push(port),
            Ok((port, PortState::Unverified)) => out.unverified.push(port),
            _ => {}
        }
    }
    out.open.sort_unstable();
    out.unverified.sort_unstable();
    out
}

// ---------------------------------------------------------------------------------------------
// Management-port fingerprint
// ---------------------------------------------------------------------------------------------

/// `true` when an OUI vendor name belongs to a maker of managed network equipment (switches,
/// routers, firewalls, APs). Used to pick SNMP poll candidates, not to assign a role.
pub fn is_network_vendor(vendor: &str) -> bool {
    const VENDORS: &[&str] = &[
        "cisco",
        "meraki",
        "juniper",
        "aruba",
        "hewlett packard enterprise",
        "arista",
        "extreme networks",
        "brocade",
        "ruckus",
        "fortinet",
        "palo alto",
        "ubiquiti",
        "mikrotik",
        "routerboard",
        "h3c",
        "huawei",
        "allied telesis",
        "netgear",
        "zyxel",
        "d-link",
        "tp-link",
        "sonicwall",
        "watchguard",
        "sophos",
        "edgecore",
        "cambium",
        "mellanox",
        "dell emc networking",
        "force10",
        "ruijie",
        "reyee",
        "accton",
        "grandstream",
        "alcatel-lucent enterprise",
        "hirschmann",
        "planet technology",
    ];
    let v = vendor.to_ascii_lowercase();
    VENDORS.iter().any(|n| v.contains(n))
}

/// Ports that mark a general-purpose host or a printer (SMB, RDP, VNC, AFP, NetBIOS session,
/// raw/IPP/LPD printing). Their presence vetoes a "network gear" fingerprint.
const HOST_PORTS: &[u16] = &[139, 445, 548, 3389, 5900, 515, 631, 9100];

/// Best-effort role from the OUI vendor plus the set of open TCP ports, used only when no
/// SNMP / CDP / LLDP evidence exists. Conservative: it only ever returns an infrastructure
/// role on strong vendor + port evidence (never `Host`), so the [`Device::merge`] priority
/// rules can never let it downgrade a better-sourced role.
///
/// The OUI alone is never enough: Fortinet's OUI also covers FortiSwitch / FortiAP / phones,
/// Ubiquiti's covers UniFi switches, gateways, cameras and APs, and HP's covers printers.
pub fn fingerprint_role(vendor: Option<&str>, open_ports: &[u16]) -> Option<DeviceRole> {
    fingerprint(vendor, open_ports).map(|(role, _, _)| role)
}

/// [`fingerprint_role`] with its confidence and a human-readable reason: product-specific
/// management services (FortiGate 10443, Palo Alto, MikroTik Winbox / API) are `medium`; a
/// networking OUI with SSH / Telnet open is only a `low` guess (it could be a router, a
/// wireless controller or an AP as well as a switch).
pub fn fingerprint(
    vendor: Option<&str>,
    open_ports: &[u16],
) -> Option<(DeviceRole, RoleConfidence, String)> {
    let v = vendor?.to_ascii_lowercase();
    let has = |p: u16| open_ports.contains(&p);
    if HOST_PORTS.iter().any(|p| has(*p)) {
        return None;
    }
    let medium = |role, why: &str| Some((role, RoleConfidence::Medium, why.to_string()));

    // FortiGate: the SSL-VPN / admin port 10443 is a FortiGate-only service (FortiSwitch and
    // FortiAP expose plain 22/80/443).
    if (v.contains("fortinet") || v.contains("fortigate")) && has(10443) {
        return medium(
            DeviceRole::Firewall,
            "Fortinet OUI with FortiGate admin port 10443",
        );
    }
    // Palo Alto Networks hardware is firewalls; still require its management plane.
    if v.contains("palo alto") && (has(443) || has(22)) {
        return medium(
            DeviceRole::Firewall,
            "Palo Alto Networks OUI with management open",
        );
    }
    // MikroTik Winbox (8291) / RouterOS API (8728) only run on RouterOS devices.
    if (v.contains("mikrotik") || v.contains("routerboard")) && (has(8291) || has(8728)) {
        return medium(
            DeviceRole::Router,
            "MikroTik OUI with Winbox / RouterOS API open",
        );
    }
    // Vendors whose OUIs are (almost) only network gear: CLI management (SSH / Telnet).
    // Generic HP / HPE OUIs are left out: they also cover printers and ProLiant iLO.
    let networking = v.contains("aruba")
        || v.contains("juniper")
        || (v.contains("cisco") && !v.contains("linksys") && !v.contains("meraki"))
        || v.contains("arista")
        || v.contains("extreme networks");
    if networking && (has(22) || has(23)) {
        let cli = if has(22) { "SSH" } else { "Telnet" };
        return Some((
            DeviceRole::Switch,
            RoleConfidence::Low,
            format!("network-vendor OUI with {cli} management open"),
        ));
    }
    None
}

// ---------------------------------------------------------------------------------------------
// Enrichment pass
// ---------------------------------------------------------------------------------------------

/// Enrich already-discovered `devices` and stream the updated snapshots to `tx`. For each
/// device this fills the vendor (from its MAC) and, when `cfg.resolve_names` is set, the DNS
/// PTR, mDNS and NetBIOS names; when `cfg.ports` is non-empty it adds the open TCP ports and a
/// management-port role fingerprint. Only devices that actually gained data are re-emitted.
///
/// Each emitted [`Device`] carries the original `ip` + `vlanId` so the aggregator upserts it
/// onto the right row by [`Device::key`]. One unit of `progress` is counted per device.
/// Every socket (TCP connect, NetBIOS, DNS) draws from the process-wide
/// [`SocketBudget::global`].
pub async fn enrich_devices(
    devices: Vec<Device>,
    cfg: &ScanConfig,
    tx: Sender<ScanEvent>,
    cancel: CancellationToken,
    progress: ProgressScope,
) {
    enrich_devices_with(devices, cfg, tx, cancel, progress, SocketBudget::global()).await;
}

/// [`enrich_devices`] with an explicit socket budget (tests use a deliberately small one).
pub async fn enrich_devices_with(
    devices: Vec<Device>,
    cfg: &ScanConfig,
    tx: Sender<ScanEvent>,
    cancel: CancellationToken,
    progress: ProgressScope,
    budget: &SocketBudget,
) {
    let resolve = cfg.resolve_names;
    let ports = Arc::new(dedupe_ports(&cfg.ports));
    let name_timeout = Duration::from_millis(cfg.timeout_ms.clamp(200, 5_000));
    let connect_timeout = Duration::from_millis(cfg.timeout_ms.clamp(100, 5_000));

    // Shared, built once: the DNS resolver and the mDNS host map.
    let resolver = if resolve {
        let r = build_resolver(name_timeout, 2).map(Arc::new);
        if r.is_none() {
            let _ = tx
                .send(ScanEvent::warn(
                    "DNS PTR lookups skipped: the system resolver configuration could not be \
                     read",
                ))
                .await;
        }
        r
    } else {
        None
    };
    let mdns = if resolve && !cancel.is_cancelled() {
        let budget =
            Duration::from_millis(cfg.timeout_ms.clamp(500, 4_000)).max(Duration::from_secs(2));
        tokio::task::spawn_blocking(move || mdns_discover_blocking(budget))
            .await
            .unwrap_or_default()
    } else {
        HashMap::new()
    };
    let mdns = Arc::new(mdns);

    // Devices enriched concurrently; the sockets they open are bounded by `budget`.
    let semaphore = Arc::new(Semaphore::new(cfg.concurrency.clamp(1, 256)));
    let unverified = Arc::new(AtomicUsize::new(0));
    let mut tasks: JoinSet<()> = JoinSet::new();

    for device in devices {
        if cancel.is_cancelled() {
            break;
        }
        let Ok(permit) = semaphore.clone().acquire_owned().await else {
            break;
        };
        let (tx, cancel, budget, unverified) = (
            tx.clone(),
            cancel.clone(),
            budget.clone(),
            unverified.clone(),
        );
        let (resolver, mdns, ports, progress) = (
            resolver.clone(),
            mdns.clone(),
            ports.clone(),
            progress.clone(),
        );
        tasks.spawn(async move {
            let _permit = permit;
            if cancel.is_cancelled() {
                progress.add(1);
                return;
            }
            let ctx = EnrichCtx {
                resolve,
                resolver: resolver.as_deref(),
                mdns: &mdns,
                ports: &ports,
                connect_timeout,
                name_timeout,
                cancel: &cancel,
                budget: &budget,
            };
            let (update, missed) = enrich_one(&device, &ctx).await;
            if missed > 0 {
                unverified.fetch_add(missed, Ordering::Relaxed);
            }
            if let Some(update) = update {
                let _ = tx.send(ScanEvent::device(update)).await;
            }
            progress.add(1);
        });
        while tasks.try_join_next().is_some() {}
    }
    while tasks.join_next().await.is_some() {}

    let missed = unverified.load(Ordering::Relaxed);
    if missed > 0 {
        let _ = tx
            .send(ScanEvent::warn(format!(
                "{missed} TCP port probe(s) could not be completed because the process ran out \
                 of file descriptors; those ports are unknown, not closed (raise `ulimit -n`)"
            )))
            .await;
    }
}

/// Shared, per-pass settings for [`enrich_one`].
struct EnrichCtx<'a> {
    resolve: bool,
    resolver: Option<&'a hickory_resolver::TokioResolver>,
    mdns: &'a HashMap<IpAddr, MdnsHost>,
    ports: &'a [u16],
    connect_timeout: Duration,
    name_timeout: Duration,
    cancel: &'a CancellationToken,
    budget: &'a SocketBudget,
}

/// Concurrent connects per device during enrichment (the global budget caps the total).
const PORTS_PER_DEVICE: usize = 64;

/// Enrich one device; returns a sparse [`Device`] (same key) carrying only new data, or `None`
/// when nothing was learned, plus the number of ports that could not be verified.
async fn enrich_one(device: &Device, ctx: &EnrichCtx<'_>) -> (Option<Device>, usize) {
    let cancel = ctx.cancel;
    let mut update = Device::new(device.ip);
    update.vlan_id = device.vlan_id;
    update.sources.clear();
    let mut changed = false;
    let mut missed = 0;

    // Vendor from the MAC (local, always when a usable MAC exists and none is set yet).
    if device.vendor.is_none() {
        if let Some(vendor) = device.mac.as_deref().and_then(vendor_for_mac) {
            update.vendor = Some(vendor);
            changed = true;
        }
    }

    if ctx.resolve && !cancel.is_cancelled() {
        // DNS PTR on the primary IP and any extra IPs until one resolves.
        if device.dns_name.is_none() {
            if let Some(resolver) = ctx.resolver {
                for ip in std::iter::once(device.ip).chain(device.extra_ips.iter().copied()) {
                    if let Some(name) = dns_ptr(resolver, ip, ctx.budget).await {
                        update.dns_name = Some(name);
                        update.add_source(DiscoverySource::Dns);
                        changed = true;
                        break;
                    }
                }
            }
        }
        // mDNS name and service types from the browsed map (primary and extra IPs).
        for hit in std::iter::once(&device.ip)
            .chain(&device.extra_ips)
            .filter_map(|ip| ctx.mdns.get(ip))
        {
            if device.mdns_name.is_none() && update.mdns_name.is_none() {
                update.mdns_name = Some(hit.name.clone());
                update.add_source(DiscoverySource::Mdns);
                changed = true;
            }
            for svc in &hit.services {
                let known =
                    device.mdns_services.contains(svc) || update.mdns_services.contains(svc);
                if !known && update.mdns_services.len() < MAX_MDNS_SERVICES {
                    update.mdns_services.push(svc.clone());
                    update.add_source(DiscoverySource::Mdns);
                    changed = true;
                }
            }
        }
        // NetBIOS node status (IPv4 only).
        if device.smb_name.is_none() && device.ip.is_ipv4() && !cancel.is_cancelled() {
            if let Some(nb) = netbios_query(device.ip, ctx.name_timeout, ctx.budget).await {
                if nb.name.is_some() || nb.workgroup.is_some() {
                    update.smb_name = nb.name;
                    update.smb_domain = nb.workgroup;
                    if update.mac.is_none() && device.mac.is_none() {
                        update.mac = nb.mac;
                    }
                    update.add_source(DiscoverySource::Netbios);
                    changed = true;
                }
            }
        }
    }

    // TCP connect scan + no-SNMP management-port fingerprint.
    if !ctx.ports.is_empty() && !cancel.is_cancelled() {
        let scan = scan_ports(
            device.ip,
            ctx.ports,
            PORTS_PER_DEVICE,
            ctx.connect_timeout,
            cancel,
            ctx.budget,
        )
        .await;
        missed = scan.unverified.len();
        if !scan.open.is_empty() {
            update.open_ports = scan.open;
            update.add_source(DiscoverySource::Tcp);
            changed = true;
        }
        // Only fingerprint when the device has no stronger role yet (still a plain Host).
        if device.role == DeviceRole::Host {
            let vendor = update.vendor.as_deref().or(device.vendor.as_deref());
            let mut all_open = device.open_ports.clone();
            all_open.extend(&update.open_ports);
            if let Some((role, confidence, why)) = fingerprint(vendor, &all_open) {
                update.set_role(role, RoleSource::OuiPorts, confidence, vec![why]);
                changed = true;
            }
        }
    }

    (changed.then_some(update), missed)
}

// ---------------------------------------------------------------------------------------------
// Device override persistence (local, atomic JSON)
// ---------------------------------------------------------------------------------------------

/// Max overrides kept in the store, and the largest override file read (hostile / corrupt
/// file bound).
const MAX_OVERRIDE_ENTRIES: usize = 10_000;
const MAX_OVERRIDE_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Serializes every load-modify-write of the store within this process (GUI commands run on
/// a thread pool, so two saves can race).
static OVERRIDES_LOCK: Mutex<()> = Mutex::new(());
/// Distinguishes temp files of concurrent writers.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Path of the local overrides store (`<data-dir>/overrides.json`).
pub fn overrides_path() -> Option<PathBuf> {
    ProjectDirs::from("com", "SweepR", "SweepR").map(|d| d.data_dir().join("overrides.json"))
}

/// Why the store could not be read.
#[derive(Debug)]
enum StoreError {
    /// The file exists but is not a usable store (unparsable, too large, not a file).
    Corrupt(String),
    /// I/O failure (permissions, ...): the file is left alone.
    Io(anyhow::Error),
}

/// Read and re-sanitize the store at `path`. A missing file is an empty store.
fn read_store(path: &Path) -> Result<HashMap<String, DeviceOverride>, StoreError> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => {
            return Err(StoreError::Io(
                anyhow::Error::from(e).context(format!("cannot read {}", path.display())),
            ))
        }
    };
    if !meta.is_file() {
        return Err(StoreError::Corrupt("not a regular file".into()));
    }
    if meta.len() > MAX_OVERRIDE_FILE_BYTES {
        return Err(StoreError::Corrupt(format!(
            "larger than {MAX_OVERRIDE_FILE_BYTES} bytes"
        )));
    }
    let bytes = std::fs::read(path).map_err(|e| {
        StoreError::Io(anyhow::Error::from(e).context(format!("cannot read {}", path.display())))
    })?;
    let mut map: HashMap<String, DeviceOverride> =
        serde_json::from_slice(&bytes).map_err(|e| StoreError::Corrupt(e.to_string()))?;
    // Re-sanitize on load (the file could have been hand-edited).
    map.retain(|k, _| !k.is_empty());
    for ov in map.values_mut() {
        *ov =
            DeviceOverride::sanitized(ov.hostname.clone(), ov.comments.clone()).unwrap_or_default();
    }
    map.retain(|_, ov| ov.hostname.is_some() || ov.comments.is_some());
    if map.len() > MAX_OVERRIDE_ENTRIES {
        // Deterministic trim: keep the lexicographically-first keys.
        let mut keys: Vec<String> = map.keys().cloned().collect();
        keys.sort();
        for k in keys.into_iter().skip(MAX_OVERRIDE_ENTRIES) {
            map.remove(&k);
        }
    }
    Ok(map)
}

/// Load the store at `path`, failing (without touching the file) when it is unreadable or
/// corrupt. A missing file is an empty store.
pub fn load_overrides_from(path: &Path) -> Result<HashMap<String, DeviceOverride>> {
    let _guard = OVERRIDES_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    read_store(path).map_err(|e| match e {
        StoreError::Corrupt(reason) => anyhow!(
            "{} is not a valid overrides store ({reason}); it is left untouched",
            path.display()
        ),
        StoreError::Io(e) => e,
    })
}

/// Load the device-override store, reporting unreadable / corrupt files as errors (the GUI's
/// `load_overrides` command). A missing file or data directory is an empty store.
pub fn load_overrides_strict() -> Result<HashMap<String, DeviceOverride>> {
    match overrides_path() {
        Some(path) => load_overrides_from(&path),
        None => Ok(HashMap::new()),
    }
}

/// Load the device-override store for a scan. Missing / unreadable / oversized / corrupt
/// files yield an empty map (logged), so a bad file never blocks a scan.
pub fn load_overrides() -> HashMap<String, DeviceOverride> {
    load_overrides_strict().unwrap_or_else(|e| {
        tracing::warn!("ignoring device overrides: {e:#}");
        HashMap::new()
    })
}

/// Insert / update / clear one override in the default store. See [`save_override_at`].
pub fn save_override(
    key: String,
    hostname: Option<String>,
    comments: Option<String>,
) -> Result<HashMap<String, DeviceOverride>> {
    let path = overrides_path().ok_or_else(|| anyhow!("no application data directory"))?;
    save_override_at(&path, key, hostname, comments)
}

/// Insert / update / clear one override in the store at `path`, then persist it durably
/// (unique temp file, fsync, rename, directory fsync). A cleared override (both fields empty)
/// is removed. The whole load-modify-write runs under a process-wide lock, so concurrent saves
/// never lose each other's entries.
///
/// A store that exists but cannot be parsed is never silently replaced: it is moved aside to
/// `<name>.corrupt-<unix-ms>` and the save fails with an error naming the backup (retrying
/// then starts a fresh store). Returns the full, updated map.
pub fn save_override_at(
    path: &Path,
    key: String,
    hostname: Option<String>,
    comments: Option<String>,
) -> Result<HashMap<String, DeviceOverride>> {
    let key = sanitize_override(&key);
    if key.is_empty() {
        return Err(anyhow!("empty device key"));
    }
    let _guard = OVERRIDES_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let mut map = match read_store(path) {
        Ok(map) => map,
        Err(StoreError::Io(e)) => return Err(e),
        Err(StoreError::Corrupt(reason)) => {
            let backup = backup_corrupt_store(path)?;
            bail!(
                "the overrides store {} could not be read ({reason}); it was moved to {} and \
                 nothing was saved. Retry to start a new store.",
                path.display(),
                backup.display()
            );
        }
    };
    match DeviceOverride::sanitized(hostname, comments) {
        Some(ov) => {
            if map.len() >= MAX_OVERRIDE_ENTRIES && !map.contains_key(&key) {
                return Err(anyhow!(
                    "override store is full ({MAX_OVERRIDE_ENTRIES} entries)"
                ));
            }
            map.insert(key, ov);
        }
        None => {
            map.remove(&key);
        }
    }
    write_store(path, &map)?;
    Ok(map)
}

/// Move a corrupt store aside (`<name>.corrupt-<unix-ms>[-n]`); returns the backup path.
fn backup_corrupt_store(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "overrides.json".into());
    let stamp = now_ms();
    for n in 0..100u32 {
        let suffix = if n == 0 {
            format!("{name}.corrupt-{stamp}")
        } else {
            format!("{name}.corrupt-{stamp}-{n}")
        };
        let backup = path.with_file_name(suffix);
        if std::fs::symlink_metadata(&backup).is_ok() {
            continue;
        }
        std::fs::rename(path, &backup).with_context(|| {
            format!(
                "cannot move the corrupt store {} aside to {}",
                path.display(),
                backup.display()
            )
        })?;
        tracing::warn!("corrupt overrides store moved to {}", backup.display());
        return Ok(backup);
    }
    bail!("cannot find a free backup name for {}", path.display())
}

/// Atomically replace the store: write a uniquely named temp file (`create_new`), fsync it,
/// rename it over the store, then fsync the directory (best effort).
fn write_store(path: &Path, map: &HashMap<String, DeviceOverride>) -> Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let dir_is_new = !dir.exists();
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    if dir_is_new {
        crate::owner::give_back_path(dir);
    }
    let json = serde_json::to_vec_pretty(map).context("serialize overrides")?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "overrides.json".into());
    let tmp = dir.join(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .with_context(|| format!("cannot create {}", tmp.display()))?;
        crate::owner::give_back_file(&f);
        f.write_all(&json)
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("cannot sync {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written?;
    // Make the rename itself durable (best effort; not every platform/filesystem supports it).
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Apply the user override for `device`'s key: fill in a missing hostname / comments.
pub fn apply_override(device: &mut Device, overrides: &HashMap<String, DeviceOverride>) {
    if let Some(ov) = overrides.get(&device.key()) {
        if device.hostname.is_none() {
            device.hostname = ov.hostname.clone();
        }
        if device.comments.is_none() {
            device.comments = ov.comments.clone();
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vendors_resolve() {
        assert_eq!(
            vendor_for_mac("00:00:0c:11:22:33").as_deref(),
            Some("Cisco Systems, Inc")
        );
        assert_eq!(
            vendor_for_mac("3C:07:54:aa:bb:cc").as_deref(),
            Some("Apple, Inc.")
        );
        assert_eq!(
            vendor_for_mac("fc:ec:da:11:22:33").as_deref(),
            Some("Ubiquiti Inc")
        );
        assert!(vendor_for_mac("4c:5e:0c:00:11:22")
            .as_deref()
            .unwrap()
            .to_lowercase()
            .contains("routerboard")); // MikroTik
        assert_eq!(
            vendor_for_mac("00:09:0f:00:11:22").as_deref(),
            Some("Fortinet, Inc.")
        );
    }

    #[test]
    fn locally_administered_and_multicast_have_no_vendor() {
        // U/L bit (0x02) set: randomized / locally administered MAC.
        assert!(is_locally_administered_or_multicast(&[0x02, 0, 0, 0, 0, 0]));
        assert_eq!(vendor_for_mac("02:11:22:33:44:55"), None);
        assert_eq!(vendor_for_mac("06:aa:bb:cc:dd:ee"), None);
        // I/G (multicast) bit set.
        assert!(is_locally_administered_or_multicast(&[
            0x01, 0, 0x5e, 0, 0, 1
        ]));
        assert_eq!(vendor_for_mac("01:00:5e:00:00:01"), None);
        // Garbage.
        assert_eq!(vendor_for_mac("not-a-mac"), None);
        // A globally-unique OUI that is simply unassigned returns None, not a vendor.
        assert_eq!(vendor_for_mac("fe:ff:ff:12:34:56"), None);
    }

    #[test]
    fn ma_s_assignment_wins_over_parent() {
        // 00:55:DA is an MA-L block held by the IEEE Registration Authority and delegated in
        // MA-M (/28) pieces: 0055DA1 belongs to KoolPOS, not to the /24 holder.
        assert_eq!(
            vendor_for_mac("00:55:da:10:00:00").as_deref(),
            Some("KoolPOS Inc.")
        );
        // 00:1B:C5 is delegated in MA-S (/36) pieces: 001BC5001 is OpenRB.com.
        assert_eq!(
            vendor_for_mac("00:1b:c5:00:10:00").as_deref(),
            Some("OpenRB.com, Direct SIA")
        );
        assert_eq!(
            vendor_for_mac("00:1b:c5:00:00:00").as_deref(),
            Some("Converging Systems Inc.")
        );
    }

    #[test]
    fn nbstat_query_is_well_formed() {
        let q = build_nbstat_query(0x1234);
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        assert_eq!(&q[4..6], &[0x00, 0x01]); // QDCOUNT
        assert_eq!(q[12], 0x20); // encoded-name length
                                 // "*" => 0x2A => nibbles 2,A => 'C','K'.
        assert_eq!(&q[13..15], b"CK");
        assert_eq!(&q[q.len() - 4..], &[0x00, 0x21, 0x00, 0x01]); // NBSTAT / IN
    }

    /// Build a canned NBSTAT response with the given (name, suffix, group) entries and a MAC.
    fn nbstat_response(entries: &[(&str, u8, bool)], mac: [u8; 6]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&[0x12, 0x34]); // txn id
        r.extend_from_slice(&[0x84, 0x00]); // flags (response)
        r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]); // QD=1 AN=1
                                                                                // Echoed question name (34 bytes: len + 32 + root) — content irrelevant to the parser.
        r.push(0x20);
        r.extend(std::iter::repeat_n(b'A', 32));
        r.push(0x00);
        r.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]); // type NBSTAT, class IN (question)
                                                        // Answer RR: pointer name (0xC0 0x0C), type/class/ttl/rdlength.
        r.extend_from_slice(&[0xc0, 0x0c]);
        r.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]); // type NBSTAT, class IN
        r.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // TTL
        let rdlen = 1 + entries.len() * 18 + 6;
        r.extend_from_slice(&(rdlen as u16).to_be_bytes());
        r.push(entries.len() as u8);
        for (name, suffix, group) in entries {
            let mut field = [0x20u8; 15]; // space-padded
            for (i, b) in name.bytes().take(15).enumerate() {
                field[i] = b;
            }
            r.extend_from_slice(&field);
            r.push(*suffix);
            let flags: u16 = if *group { 0x8000 } else { 0x0400 };
            r.extend_from_slice(&flags.to_be_bytes());
        }
        r.extend_from_slice(&mac);
        r
    }

    #[test]
    fn nbstat_response_parses_names_and_mac() {
        let resp = nbstat_response(
            &[
                ("WORKSTATION1", 0x00, false),
                ("WORKGROUP", 0x00, true),
                ("WORKSTATION1", 0x20, false), // file server service; ignored for name
            ],
            [0x00, 0x1a, 0x2b, 0x03, 0x04, 0x05],
        );
        let info = parse_nbstat_response(&resp).unwrap();
        assert_eq!(info.name.as_deref(), Some("WORKSTATION1"));
        assert_eq!(info.workgroup.as_deref(), Some("WORKGROUP"));
        assert_eq!(info.mac.as_deref(), Some("00:1a:2b:03:04:05"));
    }

    #[test]
    fn nbstat_parser_is_hostile_input_safe() {
        assert_eq!(parse_nbstat_response(&[]), None);
        assert_eq!(parse_nbstat_response(&[0u8; 8]), None);
        // Claims 255 names but is truncated: must not panic or over-read.
        let mut r = Vec::new();
        r.extend_from_slice(&[0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0]); // QD=0 AN=1
        r.push(0x00); // answer name = root label
        r.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]); // TYPE NBSTAT, CLASS IN
        r.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ttl + rdlength
        r.push(0xff); // 255 names, none present
        assert_eq!(parse_nbstat_response(&r), None);
        // A compression-pointer loop / malformed name must terminate, not hang.
        let looped = [0u8, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 0x0c];
        assert_eq!(parse_nbstat_response(&looped), None);
    }

    #[test]
    fn fingerprint_is_conservative() {
        // FortiGate: the FortiGate-only SSL-VPN/admin port is required.
        assert_eq!(
            fingerprint_role(Some("Fortinet, Inc."), &[443, 10443]),
            Some(DeviceRole::Firewall)
        );
        // A Fortinet MAC alone, or FortiSwitch / FortiAP management ports, is not a firewall.
        assert_eq!(fingerprint_role(Some("Fortinet, Inc."), &[]), None);
        assert_eq!(fingerprint_role(Some("Fortinet, Inc."), &[22, 443]), None); // FortiSwitch
        assert_eq!(fingerprint_role(Some("Fortinet, Inc."), &[80, 443]), None); // FortiAP
        assert_eq!(
            fingerprint_role(Some("Routerboard.com"), &[8291, 80]),
            Some(DeviceRole::Router)
        );
        // SwOS switches only serve HTTP: not enough for "router".
        assert_eq!(fingerprint_role(Some("Routerboard.com"), &[80]), None);
        // Ubiquiti's OUI covers UniFi switches, gateways and cameras as well as APs.
        assert_eq!(fingerprint_role(Some("Ubiquiti Inc"), &[443]), None);
        assert_eq!(fingerprint_role(Some("Ubiquiti Inc"), &[22, 443]), None); // UniFi switch
        assert_eq!(
            fingerprint_role(Some("Cisco Systems, Inc"), &[22]),
            Some(DeviceRole::Switch)
        );
        assert_eq!(
            fingerprint_role(Some("Juniper Networks"), &[23, 80]),
            Some(DeviceRole::Switch)
        );
        // SNMP is UDP: a TCP/161 result means nothing and is not required any more.
        assert_eq!(fingerprint_role(Some("Cisco Systems, Inc"), &[161]), None);
        // HP printers (JetDirect exposes telnet) are never network gear.
        assert_eq!(
            fingerprint_role(Some("HP Inc."), &[23, 80, 443, 9100]),
            None
        );
        assert_eq!(
            fingerprint_role(Some("Hewlett Packard"), &[22, 23, 80, 515, 631]),
            None
        );
        // Host ports veto a network-gear guess (e.g. a Cisco UCS / Windows box).
        assert_eq!(
            fingerprint_role(Some("Cisco Systems, Inc"), &[22, 445]),
            None
        );
        // Not enough evidence: no vendor, or no ports => leave it to better sources.
        assert_eq!(fingerprint_role(None, &[22, 443, 161]), None);
        assert_eq!(fingerprint_role(Some("Cisco Systems, Inc"), &[80]), None);
        assert_eq!(fingerprint_role(Some("Dell Inc."), &[22, 443]), None);
        // Confidence: product-specific ports are medium, OUI + SSH is a low guess.
        let conf = |v: &str, p: &[u16]| fingerprint(Some(v), p).map(|(_, c, _)| c);
        assert_eq!(
            conf("Fortinet, Inc.", &[10443]),
            Some(RoleConfidence::Medium)
        );
        assert_eq!(
            conf("Routerboard.com", &[8291]),
            Some(RoleConfidence::Medium)
        );
        assert_eq!(conf("Cisco Systems, Inc", &[22]), Some(RoleConfidence::Low));
        // Cisco web UI only (the reported switches): no fingerprint, the role-hint pass
        // needs a second signal.
        assert_eq!(
            fingerprint_role(Some("Cisco Systems, Inc"), &[80, 443]),
            None
        );
        assert_eq!(fingerprint_role(Some("Cisco-Linksys, LLC"), &[22]), None);
        assert_eq!(fingerprint_role(Some("Cisco Meraki"), &[22]), None);
        // The extended network-vendor list (SNMP candidates).
        for v in [
            "Ruijie Networks Co.,LTD",
            "TP-LINK TECHNOLOGIES CO.,LTD.",
            "Allied Telesis Inc.",
            "Accton Technology Corp",
            "Grandstream Networks, Inc.",
        ] {
            assert!(is_network_vendor(v), "{v}");
        }
        assert!(!is_network_vendor("Dell Inc."));
    }

    #[test]
    fn mdns_service_types_are_kept_per_host() {
        assert_eq!(
            normalize_service_type("_csco-sb._tcp.local.").as_deref(),
            Some("_csco-sb._tcp")
        );
        assert_eq!(
            normalize_service_type("_HTTP._tcp.local").as_deref(),
            Some("_http._tcp")
        );
        assert_eq!(normalize_service_type("bad type.local."), None);
        assert_eq!(normalize_service_type(""), None);
        let mut map = HashMap::new();
        let ip: IpAddr = "10.10.60.5".parse().unwrap();
        record_mdns(
            &mut map,
            ip,
            "switch375bc6.local",
            Some("_csco-sb._tcp.local."),
        );
        record_mdns(&mut map, ip, "other.local", Some("_http._tcp.local."));
        record_mdns(&mut map, ip, "other.local", Some("_http._tcp.local."));
        let h = &map[&ip];
        assert_eq!(h.name, "switch375bc6.local", "the first host name wins");
        assert_eq!(h.services, vec!["_csco-sb._tcp", "_http._tcp"]);
        for i in 0..40 {
            record_mdns(&mut map, ip, "x", Some(&format!("_s{i}._tcp.local.")));
        }
        assert_eq!(map[&ip].services.len(), MAX_MDNS_SERVICES);
    }

    #[tokio::test]
    async fn port_scan_finds_a_live_listener() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let res = scan_ports(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[port, port, 0, port.wrapping_add(1).max(1)],
            16,
            Duration::from_millis(500),
            &CancellationToken::new(),
            &SocketBudget::new(4),
        )
        .await;
        assert!(
            res.open.contains(&port),
            "expected {port} to be open, got {res:?}"
        );
        assert_eq!(res.open.iter().filter(|p| **p == port).count(), 1);
        assert!(res.unverified.is_empty());
        assert_eq!(dedupe_ports(&[443, 0, 22, 443]), vec![22, 443]);
    }

    /// Regression (H2): hundreds of devices x many ports used to open ~2300 sockets at once,
    /// exceeding macOS's default RLIMIT_NOFILE of 256; connects then failed with EMFILE and
    /// were reported as closed. With every socket drawing from one small budget, every
    /// device must still see the listener as open, whatever `ulimit -n` is.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn enrichment_finds_open_ports_under_a_tight_socket_budget() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move {
            loop {
                if let Ok((s, _)) = listener.accept().await {
                    drop(s);
                }
            }
        });
        let n: u16 = 300;
        let devices: Vec<Device> = (1..=n)
            .map(|v| {
                let mut d = Device::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
                d.vlan_id = Some(v);
                d
            })
            .collect();
        let cfg = ScanConfig {
            resolve_names: false,
            ports: vec![port, 22, 23, 80, 443, 445, 8291, 8443, 10443],
            ..ScanConfig::default()
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel(10_000);
        let budget = SocketBudget::new(8);
        enrich_devices_with(
            devices,
            &cfg,
            tx,
            CancellationToken::new(),
            ProgressScope::detached(u64::from(n)),
            &budget,
        )
        .await;
        accept.abort();
        let mut found = 0;
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Device(d) = ev {
                if d.open_ports.contains(&port) {
                    found += 1;
                }
            }
        }
        assert_eq!(
            found,
            usize::from(n),
            "every device must report the open port"
        );
    }

    #[test]
    fn resolv_conf_nameservers_skip_unusable_lines() {
        let conf = "# macOS\nnameserver fe80::8cec:7bff:fe28:7e64%en0\nnameserver 172.20.10.1\n\
                    nameserver 2001:db8::53 # comment\nsearch corp.example\nnameserver\n";
        assert_eq!(
            resolv_conf_nameservers(conf),
            vec![
                "172.20.10.1".parse::<IpAddr>().unwrap(),
                "2001:db8::53".parse().unwrap()
            ]
        );
        assert!(resolv_conf_nameservers("").is_empty());
    }

    #[test]
    fn nbstat_replies_must_match_the_query() {
        let resp = nbstat_response(&[("HOST", 0x00, false)], [0, 1, 2, 3, 4, 5]);
        assert!(nbstat_reply_matches(&resp, 0x1234));
        assert!(!nbstat_reply_matches(&resp, 0x1235)); // wrong transaction id
        let mut query_echo = resp.clone();
        query_echo[2] = 0x00; // not a response
        assert!(!nbstat_reply_matches(&query_echo, 0x1234));
        assert!(!nbstat_reply_matches(&[0x12], 0x1234));
    }

    #[tokio::test]
    async fn netbios_query_fails_cleanly_without_a_responder() {
        // Nothing listens on 127.0.0.1:137: the connected socket gets an ICMP error or times
        // out, and the lookup yields nothing instead of hanging.
        let res = netbios_query(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_millis(200),
            &SocketBudget::new(1),
        )
        .await;
        assert!(res.is_none());
    }

    #[test]
    fn override_sanitization_and_clearing() {
        assert!(DeviceOverride::sanitized(Some("  ".into()), None).is_none());
        let ov =
            DeviceOverride::sanitized(Some("lab-switch\u{1b}[2J".into()), Some("rack 4".into()))
                .unwrap();
        assert_eq!(ov.hostname.as_deref(), Some("lab-switch[2J"));
        assert_eq!(ov.comments.as_deref(), Some("rack 4"));
    }

    fn temp_store(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!(
            "sweepr-overrides-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("overrides.json")
    }

    /// Regression (H3): concurrent saves used to share one temp path and race the
    /// load-modify-write, losing entries. Every distinct key must survive.
    #[test]
    fn concurrent_saves_keep_every_entry() {
        let path = temp_store("concurrent");
        let n = 32;
        let handles: Vec<_> = (0..n)
            .map(|i| {
                let path = path.clone();
                std::thread::spawn(move || {
                    save_override_at(&path, format!("10.0.0.{i}"), Some(format!("h{i}")), None)
                        .map(|_| ())
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap().unwrap();
        }
        let map = load_overrides_from(&path).unwrap();
        assert_eq!(map.len(), n);
        for i in 0..n {
            assert_eq!(
                map[&format!("10.0.0.{i}")].hostname.as_deref(),
                Some(format!("h{i}").as_str())
            );
        }
        // No temp files are left behind.
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
        // Clearing both fields removes the entry.
        let map = save_override_at(&path, "10.0.0.0".into(), None, Some("  ".into())).unwrap();
        assert!(!map.contains_key("10.0.0.0"));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn corrupt_store_is_backed_up_not_overwritten() {
        let path = temp_store("corrupt");
        std::fs::write(&path, b"{ not json").unwrap();
        // Loading reports the problem and leaves the file alone.
        assert!(load_overrides_from(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"{ not json");
        // Saving moves it aside and fails loudly instead of replacing it with one entry.
        let err = save_override_at(&path, "10.0.0.1".into(), Some("x".into()), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("corrupt-"), "{err}");
        let backups: Vec<PathBuf> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.to_string_lossy().contains("overrides.json.corrupt-"))
            .collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(std::fs::read(&backups[0]).unwrap(), b"{ not json");
        // A retry starts a fresh store.
        let map = save_override_at(&path, "10.0.0.1".into(), Some("x".into()), None).unwrap();
        assert_eq!(map.len(), 1);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn apply_override_fills_gaps_only() {
        let mut d = Device::new("10.0.0.5".parse().unwrap());
        let mut ov = HashMap::new();
        ov.insert(
            "10.0.0.5".to_string(),
            DeviceOverride {
                hostname: Some("edge-fw".into()),
                comments: Some("note".into()),
            },
        );
        apply_override(&mut d, &ov);
        assert_eq!(d.hostname.as_deref(), Some("edge-fw"));
        assert_eq!(d.comments.as_deref(), Some("note"));
        // A device that already has a hostname keeps it.
        d.hostname = Some("manual".into());
        apply_override(&mut d, &ov);
        assert_eq!(d.hostname.as_deref(), Some("manual"));
    }
}
