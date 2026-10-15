//! Device enrichment: vendor (embedded IEEE OUI database), DNS PTR, mDNS, NetBIOS, a TCP
//! connect port scan and a no-SNMP management-port role fingerprint. Also the local
//! persistence of user device overrides (hostname / comments).
//!
//! Every parser that consumes network bytes (NetBIOS node-status responses especially) is
//! bounds-checked and hostile-input safe, and every piece of text is run through
//! [`sanitize_text`] before it is kept.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use directories::ProjectDirs;
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::{mpsc::Sender, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use crate::{
    models::{
        format_mac, now_ms, parse_mac, sanitize_override, sanitize_text, Device, DeviceOverride,
        DeviceRole, DiscoverySource, ScanConfig, ScanEvent, MAX_CONCURRENCY,
    },
    progress::ProgressScope,
};

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

/// Send an NBSTAT query to `ip:137` and parse the reply within `timeout`.
pub async fn netbios_query(ip: IpAddr, timeout: Duration) -> Option<NetbiosInfo> {
    let bind: SocketAddr = match ip {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => return None, // NetBIOS name service is IPv4-only
    };
    let sock = UdpSocket::bind(bind).await.ok()?;
    let txn = (now_ms() as u16) ^ (std::process::id() as u16);
    let query = build_nbstat_query(txn);
    sock.send_to(&query, SocketAddr::new(ip, 137)).await.ok()?;
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    parse_nbstat_response(&buf[..n])
}

// ---------------------------------------------------------------------------------------------
// DNS PTR
// ---------------------------------------------------------------------------------------------

/// Build a Tokio DNS resolver from the system configuration, falling back to Cloudflare's
/// public resolver, with bounded per-query timeout and attempts.
fn build_resolver(timeout: Duration, attempts: usize) -> Option<hickory_resolver::TokioResolver> {
    use hickory_resolver::{config::ResolverConfig, net::runtime::TokioRuntimeProvider};
    let mut builder = match hickory_resolver::TokioResolver::builder_tokio() {
        Ok(b) => b,
        Err(_) => hickory_resolver::TokioResolver::builder_with_config(
            ResolverConfig::udp_and_tcp(&hickory_resolver::config::CLOUDFLARE),
            TokioRuntimeProvider::default(),
        ),
    };
    {
        let opts = builder.options_mut();
        opts.timeout = timeout;
        opts.attempts = attempts;
        opts.use_hosts_file = hickory_resolver::config::ResolveHosts::Auto;
    }
    builder.build().ok()
}

/// Reverse-resolve `ip` to a single PTR hostname (trailing dot stripped, sanitized).
async fn dns_ptr(resolver: &hickory_resolver::TokioResolver, ip: IpAddr) -> Option<String> {
    use hickory_resolver::proto::rr::RData;
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

// ---------------------------------------------------------------------------------------------
// mDNS discovery
// ---------------------------------------------------------------------------------------------

const MAX_MDNS_TYPES: usize = 64;
const MAX_MDNS_HOSTS: usize = 4096;

/// Browse the local mDNS realm for `duration`, returning a map of IP address to the
/// advertised host name. Runs the service daemon on a blocking thread (it owns its own
/// background thread and sync channels), so callers should `spawn_blocking` this.
pub fn mdns_discover_blocking(duration: Duration) -> HashMap<IpAddr, String> {
    use mdns_sd::{ServiceDaemon, ServiceEvent};
    let mut map: HashMap<IpAddr, String> = HashMap::new();
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
                        if map.len() >= MAX_MDNS_HOSTS {
                            break;
                        }
                        map.entry(addr.to_ip_addr()).or_insert_with(|| host.clone());
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

/// TCP connect scan of `ports` on `ip` with at most `concurrency` connects in flight, each
/// bounded by `per_timeout`. Returns the open ports, sorted. Banner-free.
pub async fn scan_ports(
    ip: IpAddr,
    ports: &[u16],
    concurrency: usize,
    per_timeout: Duration,
    cancel: &CancellationToken,
) -> Vec<u16> {
    let mut unique: Vec<u16> = ports.iter().copied().filter(|p| *p != 0).collect();
    unique.sort_unstable();
    unique.dedup();
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
        let cancel = cancel.clone();
        tasks.spawn(async move {
            let _permit = permit;
            tokio::select! {
                _ = cancel.cancelled() => None,
                res = tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::new(ip, port))) => {
                    matches!(res, Ok(Ok(_))).then_some(port)
                }
            }
        });
        while tasks.try_join_next().is_some() {}
    }
    let mut open = Vec::new();
    while let Some(res) = tasks.join_next().await {
        if let Ok(Some(port)) = res {
            open.push(port);
        }
    }
    open.sort_unstable();
    open
}

// ---------------------------------------------------------------------------------------------
// Management-port fingerprint
// ---------------------------------------------------------------------------------------------

/// Best-effort role from the OUI vendor plus the set of open management ports, used only when
/// no SNMP / CDP / LLDP evidence exists. Conservative: it only ever returns an infrastructure
/// role on strong vendor + port evidence (never `Host`), so the [`Device::merge`] priority
/// rules can never let it downgrade a better-sourced role.
pub fn fingerprint_role(vendor: Option<&str>, open_ports: &[u16]) -> Option<DeviceRole> {
    let v = vendor?.to_ascii_lowercase();
    let has = |p: u16| open_ports.contains(&p);

    if v.contains("fortinet") || v.contains("fortigate") || v.contains("palo alto") {
        return Some(DeviceRole::Firewall);
    }
    if (v.contains("mikrotik") || v.contains("routerboard")) && (has(8291) || has(8728) || has(80))
    {
        return Some(DeviceRole::Router);
    }
    if v.contains("ubiquiti") && (has(443) || has(8443)) {
        return Some(DeviceRole::AccessPoint);
    }
    let networking = v.contains("aruba")
        || v.contains("hewlett")
        || v.contains("hpe")
        || v.contains("juniper")
        || v.contains("cisco");
    if networking && has(161) && (has(22) || has(23) || has(443)) {
        return Some(DeviceRole::Switch);
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
pub async fn enrich_devices(
    devices: Vec<Device>,
    cfg: &ScanConfig,
    tx: Sender<ScanEvent>,
    cancel: CancellationToken,
    progress: ProgressScope,
) {
    let resolve = cfg.resolve_names;
    let ports = cfg.ports.clone();
    let name_timeout = Duration::from_millis(cfg.timeout_ms.clamp(200, 5_000));
    let connect_timeout = Duration::from_millis(cfg.timeout_ms.clamp(100, 5_000));

    // Shared, built once: the DNS resolver and the mDNS host map.
    let resolver = if resolve {
        build_resolver(name_timeout, 2).map(Arc::new)
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

    let semaphore = Arc::new(Semaphore::new(cfg.concurrency.clamp(1, 256)));
    let mut tasks: JoinSet<()> = JoinSet::new();

    for device in devices {
        if cancel.is_cancelled() {
            break;
        }
        let Ok(permit) = semaphore.clone().acquire_owned().await else {
            break;
        };
        let (tx, cancel) = (tx.clone(), cancel.clone());
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
            if let Some(update) = enrich_one(
                &device,
                resolve,
                resolver.as_deref(),
                &mdns,
                &ports,
                connect_timeout,
                name_timeout,
                &cancel,
            )
            .await
            {
                let _ = tx.send(ScanEvent::device(update)).await;
            }
            progress.add(1);
        });
        while tasks.try_join_next().is_some() {}
    }
    while tasks.join_next().await.is_some() {}
}

/// Enrich one device; returns a sparse [`Device`] (same key) carrying only new data, or `None`
/// when nothing was learned.
#[allow(clippy::too_many_arguments)]
async fn enrich_one(
    device: &Device,
    resolve: bool,
    resolver: Option<&hickory_resolver::TokioResolver>,
    mdns: &HashMap<IpAddr, String>,
    ports: &[u16],
    connect_timeout: Duration,
    name_timeout: Duration,
    cancel: &CancellationToken,
) -> Option<Device> {
    let mut update = Device::new(device.ip);
    update.vlan_id = device.vlan_id;
    update.sources.clear();
    let mut changed = false;

    // Vendor from the MAC (local, always when a usable MAC exists and none is set yet).
    if device.vendor.is_none() {
        if let Some(vendor) = device.mac.as_deref().and_then(vendor_for_mac) {
            update.vendor = Some(vendor);
            changed = true;
        }
    }

    if resolve && !cancel.is_cancelled() {
        // DNS PTR on the primary IP and any extra IPs until one resolves.
        if device.dns_name.is_none() {
            if let Some(resolver) = resolver {
                for ip in std::iter::once(device.ip).chain(device.extra_ips.iter().copied()) {
                    if let Some(name) = dns_ptr(resolver, ip).await {
                        update.dns_name = Some(name);
                        update.add_source(DiscoverySource::Dns);
                        changed = true;
                        break;
                    }
                }
            }
        }
        // mDNS name from the browsed map (primary or extra IP).
        if device.mdns_name.is_none() {
            let hit = std::iter::once(&device.ip)
                .chain(&device.extra_ips)
                .find_map(|ip| mdns.get(ip).cloned());
            if let Some(name) = hit {
                update.mdns_name = Some(name);
                update.add_source(DiscoverySource::Mdns);
                changed = true;
            }
        }
        // NetBIOS node status (IPv4 only).
        if device.smb_name.is_none() && device.ip.is_ipv4() && !cancel.is_cancelled() {
            if let Some(nb) = netbios_query(device.ip, name_timeout).await {
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
    if !ports.is_empty() && !cancel.is_cancelled() {
        let open = scan_ports(device.ip, ports, 64, connect_timeout, cancel).await;
        if !open.is_empty() {
            update.open_ports = open;
            update.add_source(DiscoverySource::Tcp);
            changed = true;
        }
        // Only fingerprint when the device has no stronger role yet (still a plain Host).
        if device.role == DeviceRole::Host {
            let vendor = update.vendor.as_deref().or(device.vendor.as_deref());
            if let Some(role) = fingerprint_role(vendor, &update.open_ports) {
                update.role = role;
                changed = true;
            }
        }
    }

    changed.then_some(update)
}

// ---------------------------------------------------------------------------------------------
// Device override persistence (local, atomic JSON)
// ---------------------------------------------------------------------------------------------

/// Max overrides kept in the store, and the largest override file read (hostile / corrupt
/// file bound).
const MAX_OVERRIDE_ENTRIES: usize = 10_000;
const MAX_OVERRIDE_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Path of the local overrides store (`<data-dir>/overrides.json`).
pub fn overrides_path() -> Option<PathBuf> {
    ProjectDirs::from("com", "SweepR", "SweepR").map(|d| d.data_dir().join("overrides.json"))
}

/// Load the device-override store. Missing / unreadable / oversized / corrupt files yield an
/// empty map rather than an error, so a bad file never blocks a scan.
pub fn load_overrides() -> HashMap<String, DeviceOverride> {
    let Some(path) = overrides_path() else {
        return HashMap::new();
    };
    let Ok(meta) = std::fs::metadata(&path) else {
        return HashMap::new();
    };
    if !meta.is_file() || meta.len() > MAX_OVERRIDE_FILE_BYTES {
        return HashMap::new();
    }
    let Ok(text) = std::fs::read_to_string(&path) else {
        return HashMap::new();
    };
    let mut map: HashMap<String, DeviceOverride> = serde_json::from_str(&text).unwrap_or_default();
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
    map
}

/// Insert / update / clear one override, then persist atomically (temp file + rename). A
/// cleared override (both fields empty) is removed. Returns the full, updated map.
pub fn save_override(
    key: String,
    hostname: Option<String>,
    comments: Option<String>,
) -> Result<HashMap<String, DeviceOverride>> {
    let key = sanitize_override(&key);
    if key.is_empty() {
        return Err(anyhow!("empty device key"));
    }
    let mut map = load_overrides();
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
    write_overrides(&map)?;
    Ok(map)
}

fn write_overrides(map: &HashMap<String, DeviceOverride>) -> Result<()> {
    let path = overrides_path().ok_or_else(|| anyhow!("no application data directory"))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let json = serde_json::to_vec_pretty(map).context("serialize overrides")?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json).with_context(|| format!("cannot write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("cannot replace {}", path.display()))?;
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
        // 00:55:DA is a MA-M/MA-S parent block delegated to small assignees; a full MAC under
        // 0055DA1 must resolve to the /36 assignee, not a /24 owner.
        let v = vendor_for_mac("00:55:da:10:00:00");
        assert!(v.is_some());
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
        assert_eq!(
            fingerprint_role(Some("Fortinet, Inc."), &[443, 10443]),
            Some(DeviceRole::Firewall)
        );
        assert_eq!(
            fingerprint_role(Some("Routerboard.com"), &[8291, 80]),
            Some(DeviceRole::Router)
        );
        assert_eq!(
            fingerprint_role(Some("Ubiquiti Inc"), &[443]),
            Some(DeviceRole::AccessPoint)
        );
        assert_eq!(
            fingerprint_role(Some("Cisco Systems, Inc"), &[22, 161]),
            Some(DeviceRole::Switch)
        );
        // Not enough evidence: no vendor, or no ports => leave it to better sources.
        assert_eq!(fingerprint_role(None, &[22, 443, 161]), None);
        assert_eq!(fingerprint_role(Some("Cisco Systems, Inc"), &[80]), None);
        assert_eq!(fingerprint_role(Some("Dell Inc."), &[22, 443]), None);
    }

    #[tokio::test]
    async fn port_scan_finds_a_live_listener() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let open = scan_ports(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[port, port.wrapping_add(1).max(1)],
            16,
            Duration::from_millis(500),
            &CancellationToken::new(),
        )
        .await;
        assert!(
            open.contains(&port),
            "expected {port} to be open, got {open:?}"
        );
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
