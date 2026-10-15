//! Scan orchestration shared by the CLI and the GUI.
//!
//! [`run_scan`] wires the pieces together: interface + target selection, VLAN resolution,
//! the passive CDP/LLDP/VLAN listener, raw L2 (ARP / NDP) probing of connected and tagged
//! networks, ICMP sweeps of routed targets (and as the unprivileged fallback), and a single
//! aggregator that de-duplicates devices, applies CDP/LLDP roles and streams [`ScanEvent`]s.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_util::sync::CancellationToken;

use crate::{
    arp_vlan::{self, L2Error, PassiveResults},
    enricher,
    models::{
        normalize_mac, CdpLldpNeighbor, Device, DeviceOverride, DiscoverySource, InterfaceInfo,
        InterfaceKind, Ipv4Range, NeighborProtocol, ScanConfig, ScanEvent, ScanPhase, ScanProgress,
        ScanSummary, SwitchPortMapping, VlanInfo, VlanSource, MAX_LISTEN_SECS,
    },
    progress::{ProgressCounter, ProgressScope},
    snmp_infra, sweep,
};

/// Shared, read-only map of user device overrides applied to every emitted [`Device`].
type Overrides = Arc<HashMap<String, DeviceOverride>>;

/// Interval of combined progress events while probing.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(250);

/// Capacity of the internal event channel.
const EVENT_BUFFER: usize = 4096;

/// One raw L2 probing job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2Job {
    pub iface: InterfaceInfo,
    pub targets: Vec<Ipv4Range>,
    /// `None` = untagged on `iface`; `Some(id)` = 802.1Q-tagged probes.
    pub vlans: Vec<Option<u16>>,
}

/// How a scan will be executed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanPlan {
    pub l2_jobs: Vec<L2Job>,
    /// Targets outside the connected subnet: swept with ICMP.
    pub routed: Vec<Ipv4Range>,
    pub notes: Vec<String>,
}

/// Decide which targets are probed at L2 (untagged / tagged / via an OS VLAN sub-interface)
/// and which are routed.
///
/// * Untagged: targets inside `iface`'s subnet go to ARP, the rest to ICMP.
/// * Tagged VLAN with an OS sub-interface (`en0.100`, `vlan0`) that is up and addressed: the
///   kernel does the tagging, so we ARP untagged on the sub-interface (we have a valid
///   source IP there). Without an explicit range its subnet is the target.
/// * Other tagged VLANs: raw 802.1Q-tagged ARP on `iface` over the requested range (or the
///   native subnet when no range was given, which is noted).
pub fn plan_scan(
    iface: &InterfaceInfo,
    all: &[InterfaceInfo],
    targets: &[Ipv4Range],
    vlans: &[Option<u16>],
    explicit_range: bool,
) -> ScanPlan {
    let mut plan = ScanPlan::default();
    let subnet = iface.local_subnet();

    if vlans.contains(&None) {
        let (local, routed) = arp_vlan::split_targets(targets, subnet.as_ref());
        if !local.is_empty() {
            plan.l2_jobs.push(L2Job {
                iface: iface.clone(),
                targets: local,
                vlans: vec![None],
            });
        }
        plan.routed = routed;
    }

    let mut raw_tagged = Vec::new();
    for vid in vlans.iter().flatten().copied() {
        let sub = arp_vlan::vlan_children(&iface.name, all)
            .find(|i| i.vlan_id == Some(vid) && i.is_up && i.mac.is_some())
            .and_then(|i| i.local_subnet().map(|s| (i, s)));
        let sub_targets = sub.as_ref().map(|(_, s)| {
            if explicit_range {
                targets
                    .iter()
                    .filter_map(|t| arp_vlan::intersect(t, s))
                    .collect::<Vec<_>>()
            } else {
                vec![*s]
            }
        });
        match (sub, sub_targets) {
            (Some((sub_iface, _)), Some(t)) if !t.is_empty() => {
                plan.notes.push(format!(
                    "VLAN {vid}: probing via OS sub-interface {}",
                    sub_iface.name
                ));
                plan.l2_jobs.push(L2Job {
                    iface: sub_iface.clone(),
                    targets: t,
                    vlans: vec![None],
                });
            }
            _ => raw_tagged.push(vid),
        }
    }

    if !raw_tagged.is_empty() {
        let tagged_targets = if explicit_range {
            targets.to_vec()
        } else if let Some(s) = subnet {
            plan.notes.push(format!(
                "VLAN {}: no --range given; probing the native subnet {s} inside the tag",
                raw_tagged
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
            vec![s]
        } else {
            Vec::new()
        };
        if tagged_targets.is_empty() {
            plan.notes
                .push("tagged VLAN probing skipped: no target range".to_string());
        } else {
            plan.l2_jobs.push(L2Job {
                iface: iface.clone(),
                targets: tagged_targets,
                vlans: raw_tagged.into_iter().map(Some).collect(),
            });
        }
    }
    plan
}

/// Warning for tagged probing over Wi-Fi, where 802.1Q tags are generally not carried.
pub fn wifi_tagging_warning(iface: &InterfaceInfo, plan: &ScanPlan) -> Option<String> {
    if iface.kind != InterfaceKind::Wifi {
        return None;
    }
    let tagged: Vec<String> = plan
        .l2_jobs
        .iter()
        .filter(|j| j.iface.name == iface.name)
        .flat_map(|j| j.vlans.iter().flatten().map(u16::to_string))
        .collect();
    (!tagged.is_empty()).then(|| {
        format!(
            "{} is a Wi-Fi interface: access points generally do not carry 802.1Q-tagged frames \
             from clients, so tagged probing of VLAN(s) {} will most likely find nothing (use a \
             wired port on a trunk)",
            iface.name,
            tagged.join(",")
        )
    })
}

// ---------------------------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------------------------

/// Final state collected by the aggregator.
#[derive(Debug, Default)]
pub struct Aggregate {
    pub devices: HashMap<String, Device>,
    pub neighbors: HashMap<String, CdpLldpNeighbor>,
    pub vlans: BTreeMap<u16, VlanInfo>,
    /// Lookup indexes so matching devices with neighbors stays cheap for large scans.
    neighbors_by_mac: HashMap<String, BTreeSet<String>>,
    neighbors_by_ip: HashMap<IpAddr, BTreeSet<String>>,
    devices_by_mac: HashMap<String, BTreeSet<String>>,
    devices_by_ip: HashMap<IpAddr, BTreeSet<String>>,
    /// Latest SNMP MAC-to-switch-port mapping for each endpoint MAC (canonical lowercase).
    port_mappings_by_mac: HashMap<String, SwitchPortMapping>,
    neighbor_limit_warned: bool,
}

impl Aggregate {
    /// Devices sorted by VLAN, then IP.
    pub fn sorted_devices(&self) -> Vec<Device> {
        let mut v: Vec<Device> = self.devices.values().cloned().collect();
        v.sort_by_key(|d| (d.vlan_id, d.ip));
        v
    }

    fn index_device(&mut self, key: &str) {
        let Some(d) = self.devices.get(key) else {
            return;
        };
        if let Some(mac) = &d.mac {
            self.devices_by_mac
                .entry(mac.clone())
                .or_default()
                .insert(key.to_string());
        }
        for ip in std::iter::once(d.ip).chain(d.extra_ips.iter().copied()) {
            self.devices_by_ip
                .entry(ip)
                .or_default()
                .insert(key.to_string());
        }
    }

    fn index_neighbor(&mut self, n: &CdpLldpNeighbor, add: bool) {
        let key = n.key();
        let update = |set: &mut BTreeSet<String>| {
            if add {
                set.insert(key.clone());
            } else {
                set.remove(&key);
            }
        };
        update(
            self.neighbors_by_mac
                .entry(n.source_mac.clone())
                .or_default(),
        );
        for ip in &n.management_addrs {
            update(self.neighbors_by_ip.entry(*ip).or_default());
        }
    }

    /// Keys of neighbors that may match `dev` (sorted, so application order is stable).
    fn neighbor_keys_for(&self, dev: &Device) -> BTreeSet<String> {
        let mut keys = BTreeSet::new();
        if let Some(set) = dev.mac.as_ref().and_then(|m| self.neighbors_by_mac.get(m)) {
            keys.extend(set.iter().cloned());
        }
        for ip in std::iter::once(&dev.ip).chain(&dev.extra_ips) {
            if let Some(set) = self.neighbors_by_ip.get(ip) {
                keys.extend(set.iter().cloned());
            }
        }
        keys
    }

    /// Keys of devices that may match `n`.
    fn device_keys_for(&self, n: &CdpLldpNeighbor) -> BTreeSet<String> {
        let mut keys = BTreeSet::new();
        if let Some(set) = self.devices_by_mac.get(&n.source_mac) {
            keys.extend(set.iter().cloned());
        }
        for ip in &n.management_addrs {
            if let Some(set) = self.devices_by_ip.get(ip) {
                keys.extend(set.iter().cloned());
            }
        }
        keys
    }

    /// Apply every known neighbor that matches `dev`.
    fn apply_neighbors(&self, dev: &mut Device) {
        for key in self.neighbor_keys_for(dev) {
            if let Some(n) = self.neighbors.get(&key) {
                apply_neighbor(dev, n);
            }
        }
    }

    /// Merge a device observation; returns its key.
    fn upsert_device(&mut self, d: Device) -> String {
        let key = d.key();
        self.devices
            .entry(key.clone())
            .and_modify(|e| e.merge(&d))
            .or_insert(d);
        self.refresh_device(&key);
        key
    }

    /// Re-index a device after it changed and apply the neighbors (and any known switch-port
    /// mapping) that now match it.
    fn refresh_device(&mut self, key: &str) {
        self.index_device(key);
        if let Some(mut dev) = self.devices.remove(key) {
            self.apply_neighbors(&mut dev);
            self.apply_port_mapping(&mut dev);
            self.devices.insert(key.to_string(), dev);
        }
    }

    /// Fill in `dev.switch_port` from a stored SNMP mapping that matches its MAC.
    fn apply_port_mapping(&self, dev: &mut Device) {
        if dev.switch_port.is_some() {
            return;
        }
        if let Some(mac) = &dev.mac {
            if let Some(pm) = self.port_mappings_by_mac.get(mac) {
                dev.switch_port = Some(pm.clone());
            }
        }
    }

    /// Rebuild the lookup indexes for a pre-populated state (used to seed the enrichment pass
    /// with the devices, neighbors and VLANs discovery already found).
    fn reindex(&mut self) {
        let keys: Vec<String> = self.devices.keys().cloned().collect();
        for key in &keys {
            self.index_device(key);
        }
        let neighbors: Vec<CdpLldpNeighbor> = self.neighbors.values().cloned().collect();
        for n in &neighbors {
            self.index_neighbor(n, true);
        }
    }

    /// Store a neighbor advertisement.
    fn upsert_neighbor(&mut self, n: &CdpLldpNeighbor) -> NeighborUpdate {
        let key = n.key();
        match self.neighbors.get(&key) {
            Some(old) if same_advert(old, n) => return NeighborUpdate::Unchanged,
            Some(old) => {
                let old = old.clone();
                self.index_neighbor(&old, false);
            }
            None if self.neighbors.len() >= arp_vlan::MAX_NEIGHBORS => {
                let first = !self.neighbor_limit_warned;
                self.neighbor_limit_warned = true;
                return NeighborUpdate::OverLimit { first };
            }
            None => {}
        }
        self.neighbors.insert(key, n.clone());
        self.index_neighbor(n, true);
        NeighborUpdate::Stored
    }
}

/// Result of [`Aggregate::upsert_neighbor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NeighborUpdate {
    /// New or changed: forward it and re-match devices.
    Stored,
    /// Identical to what is known: nothing to do.
    Unchanged,
    /// Dropped because the neighbor table is full (`first` = warn now).
    OverLimit { first: bool },
}

/// `true` when two advertisements carry the same information (timestamps aside).
fn same_advert(a: &CdpLldpNeighbor, b: &CdpLldpNeighbor) -> bool {
    CdpLldpNeighbor {
        last_seen_ms: a.last_seen_ms,
        ..b.clone()
    } == *a
}

fn neighbor_matches(dev: &Device, n: &CdpLldpNeighbor) -> bool {
    dev.mac.as_deref() == Some(n.source_mac.as_str())
        || n.management_addrs.contains(&dev.ip)
        || dev
            .extra_ips
            .iter()
            .any(|ip| n.management_addrs.contains(ip))
}

/// Attach a CDP/LLDP neighbor to a matching device; returns `true` when the device changed.
fn apply_neighbor(dev: &mut Device, n: &CdpLldpNeighbor) -> bool {
    if !neighbor_matches(dev, n) {
        return false;
    }
    let before = (dev.role, dev.neighbor.clone(), dev.sources.len());
    let role = n.infer_role();
    if role.priority() > dev.role.priority() {
        dev.role = role;
    }
    dev.neighbor = Some(n.clone());
    dev.add_source(match n.protocol {
        NeighborProtocol::Cdp => DiscoverySource::Cdp,
        NeighborProtocol::Lldp => DiscoverySource::Lldp,
    });
    before != (dev.role, dev.neighbor.clone(), dev.sources.len())
}

/// Clone `dev`, apply any user override, and forward it as a `device` event.
async fn send_device(out: &Sender<ScanEvent>, overrides: &Overrides, dev: &Device) {
    let mut dev = dev.clone();
    enricher::apply_override(&mut dev, overrides);
    let _ = out.send(ScanEvent::device(dev)).await;
}

/// Consume engine-internal events, merge them and forward the merged view to `out`.
///
/// Starts from `state` (empty for discovery, the discovery result when seeding enrichment)
/// and applies `overrides` to every emitted device.
///
/// * IPv6 observations are held back until the end and folded into the IPv4 row with the
///   same MAC and VLAN (as `extraIps`) when `fold_ipv6` is set, so the discovery stream never
///   shows a row that later disappears. When several IPv4 rows share that MAC (multi-homed
///   hosts, proxy ARP), the lowest IPv4 address wins, so the result does not depend on hash
///   order. The enrichment pass sets `fold_ipv6 = false`: rows already exist, so updates are
///   upserted directly.
/// * Neighbor events are forwarded only when new or changed, and at most
///   [`arp_vlan::MAX_NEIGHBORS`] are kept.
/// * VLAN events are cumulative snapshots ([`VlanInfo::merge_snapshot`]); unchanged ones
///   are not forwarded.
/// * PortMapping events set `switchPort` on the matching (by MAC) device rows.
/// * Progress events get the current device count.
async fn aggregate(
    mut state: Aggregate,
    overrides: Overrides,
    fold_ipv6: bool,
    mut rx: Receiver<ScanEvent>,
    out: Sender<ScanEvent>,
) -> Aggregate {
    state.reindex();
    let mut pending_v6: HashMap<String, Device> = HashMap::new();

    while let Some(ev) = rx.recv().await {
        match ev {
            ScanEvent::Device(d) => {
                let d = *d;
                if fold_ipv6 && d.ip.is_ipv6() {
                    pending_v6
                        .entry(d.key())
                        .and_modify(|e| e.merge(&d))
                        .or_insert(d);
                    continue;
                }
                let key = state.upsert_device(d);
                let dev = state.devices[&key].clone();
                send_device(&out, &overrides, &dev).await;
            }
            ScanEvent::Neighbor(n) => {
                match state.upsert_neighbor(&n) {
                    NeighborUpdate::Stored => {}
                    NeighborUpdate::Unchanged | NeighborUpdate::OverLimit { first: false } => {
                        continue
                    }
                    NeighborUpdate::OverLimit { first: true } => {
                        let _ = out
                            .send(ScanEvent::warn(format!(
                                "more than {} CDP/LLDP neighbors; ignoring further neighbors",
                                arp_vlan::MAX_NEIGHBORS
                            )))
                            .await;
                        continue;
                    }
                }
                let _ = out.send(ScanEvent::Neighbor(n.clone())).await;
                for key in state.device_keys_for(&n) {
                    let changed = state
                        .devices
                        .get_mut(&key)
                        .is_some_and(|dev| apply_neighbor(dev, &n));
                    if changed {
                        let dev = state.devices[&key].clone();
                        send_device(&out, &overrides, &dev).await;
                    }
                }
            }
            ScanEvent::PortMapping(pm) => {
                let mac = normalize_mac(&pm.mac).unwrap_or_else(|| pm.mac.clone());
                state.port_mappings_by_mac.insert(mac.clone(), pm.clone());
                // Apply to every device that currently carries this MAC.
                let keys: Vec<String> = state
                    .devices_by_mac
                    .get(&mac)
                    .map(|s| s.iter().cloned().collect())
                    .unwrap_or_default();
                for key in keys {
                    let changed = state.devices.get_mut(&key).is_some_and(|dev| {
                        if dev.switch_port.is_none() {
                            dev.switch_port = Some(pm.clone());
                            dev.add_source(DiscoverySource::Snmp);
                            true
                        } else {
                            false
                        }
                    });
                    if changed {
                        let dev = state.devices[&key].clone();
                        send_device(&out, &overrides, &dev).await;
                    }
                }
                let _ = out.send(ScanEvent::PortMapping(pm)).await;
            }
            ScanEvent::Vlan(v) => {
                let merged = match state.vlans.get_mut(&v.id) {
                    Some(existing) => {
                        let before = existing.clone();
                        existing.merge_snapshot(&v);
                        let unchanged = existing.frames_seen == before.frames_seen
                            && existing.sources == before.sources
                            && existing.name == before.name
                            && existing.switch_name == before.switch_name
                            && existing.interface == before.interface;
                        if unchanged {
                            continue;
                        }
                        existing.clone()
                    }
                    None => {
                        state.vlans.insert(v.id, v.clone());
                        v
                    }
                };
                let _ = out.send(ScanEvent::Vlan(merged)).await;
            }
            ScanEvent::Progress(mut p) => {
                p.devices_found = state.devices.len() as u64;
                let _ = out.send(ScanEvent::Progress(p)).await;
            }
            other => {
                let _ = out.send(other).await;
            }
        }
    }

    let mut v6: Vec<Device> = pending_v6.into_values().collect();
    v6.sort_by_key(|d| (d.vlan_id, d.ip));
    for d6 in v6 {
        let owner = d6
            .mac
            .as_ref()
            .and_then(|mac| state.devices_by_mac.get(mac))
            .into_iter()
            .flatten()
            .filter_map(|k| state.devices.get(k).map(|d| (k, d)))
            .filter(|(_, d)| d.ip.is_ipv4() && d.vlan_id == d6.vlan_id)
            .min_by_key(|(_, d)| d.ip)
            .map(|(k, _)| k.clone());
        let key = match owner {
            Some(k) => {
                if let Some(d) = state.devices.get_mut(&k) {
                    d.merge(&d6);
                }
                // Its new IPv6 addresses may match a neighbor's management address.
                state.refresh_device(&k);
                k
            }
            None => state.upsert_device(d6),
        };
        let dev = state.devices[&key].clone();
        send_device(&out, &overrides, &dev).await;
    }
    state
}

// ---------------------------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------------------------

/// A progress event with the scan-wide probe counters (`devices_found` is filled in by the
/// aggregator).
fn progress(phase: ScanPhase, counter: Option<&ProgressCounter>) -> ScanEvent {
    let (sent, total) = counter.map(ProgressCounter::snapshot).unwrap_or_default();
    ScanEvent::Progress(ScanProgress {
        phase,
        probes_sent: sent,
        probes_total: total,
        devices_found: 0,
    })
}

/// Interface enumeration shells out on macOS (`networksetup`, `route`), so keep it off the
/// async workers.
async fn interfaces() -> Result<Vec<InterfaceInfo>> {
    tokio::task::spawn_blocking(arp_vlan::list_interfaces)
        .await
        .context("interface enumeration failed")
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn range_count(r: &[Ipv4Range]) -> u64 {
    r.iter().map(Ipv4Range::count).sum()
}

/// Run a full scan described by `cfg`, streaming events to `tx`. Always ends with a
/// [`ScanEvent::Finished`] on success; returns the summary.
///
/// Progress events report one combined, monotonic `probesSent / probesTotal` for all
/// probing subsystems (L2 jobs, routed ICMP sweep, ICMP fallback, enrichment).
///
/// After discovery, an enrichment phase ([`ScanPhase::Enriching`]) resolves names
/// (DNS/mDNS/NetBIOS), scans TCP ports, fills vendors from the embedded OUI database and —
/// when `cfg.snmp` is set — polls infrastructure over SNMP and maps endpoint MACs to switch
/// ports, honouring cancellation throughout. User overrides are applied to every emitted
/// device.
pub async fn run_scan(
    cfg: ScanConfig,
    tx: Sender<ScanEvent>,
    cancel: CancellationToken,
) -> Result<ScanSummary> {
    let started = Instant::now();
    cfg.validate()?;
    let overrides: Overrides = Arc::new(enricher::load_overrides());
    let all = interfaces().await?;
    let iface = arp_vlan::select_interface(&all, cfg.interface.as_deref())?;
    let explicit_range = cfg.range.is_some();
    let targets = match cfg.parse_ranges()? {
        Some(t) => t,
        None => vec![iface.local_subnet().ok_or_else(|| {
            anyhow!(
                "interface {} has no IPv4 subnet to scan; pass a range (-r/--range)",
                iface.name
            )
        })?],
    };

    let (itx, irx) = mpsc::channel(EVENT_BUFFER);
    let aggregator = tokio::spawn(aggregate(
        Aggregate::default(),
        overrides.clone(),
        true,
        irx,
        tx.clone(),
    ));
    let _ = itx.send(progress(ScanPhase::Preparing, None)).await;
    let _ = itx
        .send(ScanEvent::info(format!(
            "scanning {} on {} ({:?}{})",
            targets
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            iface.name,
            iface.kind,
            iface
                .primary_ipv4()
                .map(|(ip, p)| format!(", {ip}/{p}"))
                .unwrap_or_default()
        )))
        .await;

    // Passive CDP/LLDP/VLAN listener runs for the whole scan (bounded by listen_secs).
    let listener = (cfg.cdp_lldp || cfg.discover_vlans).then(|| {
        let (itx, cancel, name) = (itx.clone(), cancel.child_token(), iface.name.clone());
        let own = arp_vlan::local_macs(&all);
        let duration = Duration::from_secs(cfg.listen_secs.max(1));
        tokio::spawn(async move {
            arp_vlan::run_passive_sniffer(&name, own, duration, itx, cancel).await
        })
    });

    let vlans = arp_vlan::resolve_vlans(&cfg, &iface, &all, &itx, &cancel).await;
    let plan = plan_scan(&iface, &all, &targets, &vlans, explicit_range);
    for note in &plan.notes {
        let _ = itx.send(ScanEvent::info(note.clone())).await;
    }
    if let Some(w) = wifi_tagging_warning(&iface, &plan) {
        let _ = itx.send(ScanEvent::warn(w)).await;
    }
    if cfg.ipv6 && plan.l2_jobs.is_empty() {
        let _ = itx
            .send(ScanEvent::warn(
                "IPv6 NDP discovery runs on layer-2 scanned links only; no target is on a \
                 connected subnet",
            ))
            .await;
    }

    // One progress budget per subsystem, all reserved up front so the total never moves.
    let counter = ProgressCounter::new();
    let routed_scope = counter.scope(range_count(&plan.routed));
    let job_scopes: Vec<ProgressScope> = plan
        .l2_jobs
        .iter()
        .map(|j| counter.scope(range_count(&j.targets) * j.vlans.len() as u64))
        .collect();
    let _ = itx
        .send(progress(ScanPhase::Discovering, Some(&counter)))
        .await;
    let ticker_stop = CancellationToken::new();
    let ticker = {
        let (itx, counter, stop) = (itx.clone(), counter.clone(), ticker_stop.clone());
        tokio::spawn(async move {
            let mut every = tokio::time::interval(PROGRESS_INTERVAL);
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = every.tick() => {
                        let _ = itx.try_send(progress(ScanPhase::Discovering, Some(&counter)));
                    }
                }
            }
        })
    };

    let routed = async {
        if plan.routed.is_empty() || cancel.is_cancelled() {
            return;
        }
        // Routed probes follow the routing table, so no interface is attributed to them.
        if let Err(e) = sweep::run_icmp_sweep(
            plan.routed.clone(),
            &cfg,
            None,
            None,
            routed_scope.clone(),
            itx.clone(),
            cancel.clone(),
        )
        .await
        {
            let _ = itx
                .send(ScanEvent::error(format!("ICMP sweep failed: {e:#}")))
                .await;
        }
        if !cancel.is_cancelled() {
            routed_scope.finish();
        }
    };
    let local = run_l2_jobs(&plan, &job_scopes, &cfg, &itx, &cancel);
    tokio::join!(routed, local);
    ticker_stop.cancel();
    let _ = ticker.await;
    let _ = itx
        .send(progress(ScanPhase::Discovering, Some(&counter)))
        .await;

    if let Some(handle) = listener {
        if !cancel.is_cancelled() {
            let _ = itx
                .send(progress(ScanPhase::Listening, Some(&counter)))
                .await;
        }
        match handle.await {
            Ok(Ok(res)) => {
                // Final cumulative VLAN counts and the latest neighbor data (the aggregator
                // drops whatever it already has).
                for v in &res.vlans {
                    let _ = itx.send(ScanEvent::Vlan(v.clone())).await;
                }
                for n in &res.neighbors {
                    let _ = itx.send(ScanEvent::Neighbor(n.clone())).await;
                }
                let _ = itx
                    .send(ScanEvent::info(format!(
                        "passive listener: {} VLAN(s), {} CDP/LLDP neighbor(s), {} frame(s)",
                        res.vlans.len(),
                        res.neighbors.len(),
                        res.frames_seen
                    )))
                    .await;
            }
            Ok(Err(e)) => {
                let _ = itx
                    .send(ScanEvent::warn(format!(
                        "passive CDP/LLDP/VLAN listener unavailable: {e:#}"
                    )))
                    .await;
            }
            Err(e) => {
                let _ = itx
                    .send(ScanEvent::error(format!("passive listener crashed: {e}")))
                    .await;
            }
        }
    }

    drop(itx);
    let state = aggregator.await.context("event aggregator crashed")?;

    // Enrichment phase: DNS/mDNS/NetBIOS names, TCP ports, OUI vendors and SNMP infrastructure
    // polling with endpoint-to-switch-port mapping. Seeds a second aggregator with the
    // discovery result so updates upsert onto the existing rows.
    let state = run_enrichment(state, &cfg, &counter, overrides, &tx, &cancel).await?;

    let summary = ScanSummary {
        devices: state.devices.len() as u64,
        vlans: state.vlans.len() as u64,
        neighbors: state.neighbors.len() as u64,
        elapsed_ms: elapsed_ms(started),
        cancelled: cancel.is_cancelled(),
    };
    let (sent, total) = counter.snapshot();
    let _ = tx
        .send(ScanEvent::Progress(ScanProgress {
            phase: ScanPhase::Done,
            probes_sent: sent,
            probes_total: total,
            devices_found: summary.devices,
        }))
        .await;
    let _ = tx.send(ScanEvent::Finished(summary.clone())).await;
    Ok(summary)
}

/// Run the enrichment phase on the discovery result and return the enriched state.
///
/// Enrichment runs when name resolution, port scanning or SNMP is requested. A second
/// aggregator is seeded with `state` so every enrichment update (sparse device snapshots,
/// SNMP VLANs / port mappings / role) upserts onto the discovery rows and streams the merged
/// result to `tx`. Returns `state` unchanged when there is nothing to do or the scan was
/// cancelled before enrichment began.
async fn run_enrichment(
    state: Aggregate,
    cfg: &ScanConfig,
    counter: &ProgressCounter,
    overrides: Overrides,
    tx: &Sender<ScanEvent>,
    cancel: &CancellationToken,
) -> Result<Aggregate> {
    let wants_snmp = cfg.snmp.is_some();
    let wants_enrich = cfg.resolve_names || !cfg.ports.is_empty();
    let devices = state.sorted_devices();
    if cancel.is_cancelled() || devices.is_empty() || !(wants_snmp || wants_enrich) {
        return Ok(state);
    }

    // Candidates for SNMP: every responsive host's primary IP (the user opted in by setting a
    // community / credentials). Bounded, de-duplicated.
    let snmp_candidates: Vec<IpAddr> = if wants_snmp {
        devices
            .iter()
            .map(|d| d.ip)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    } else {
        Vec::new()
    };

    let enrich_scope = counter.scope(if wants_enrich {
        devices.len() as u64
    } else {
        0
    });
    let snmp_scope = counter.scope(snmp_candidates.len() as u64);

    let (etx, erx) = mpsc::channel(EVENT_BUFFER);
    let aggregator = tokio::spawn(aggregate(state, overrides, false, erx, tx.clone()));
    let _ = etx
        .send(progress(ScanPhase::Enriching, Some(counter)))
        .await;

    // Periodic progress while enrichment runs.
    let ticker_stop = CancellationToken::new();
    let ticker = {
        let (etx, counter, stop) = (etx.clone(), counter.clone(), ticker_stop.clone());
        tokio::spawn(async move {
            let mut every = tokio::time::interval(PROGRESS_INTERVAL);
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = every.tick() => {
                        let _ = etx.try_send(progress(ScanPhase::Enriching, Some(&counter)));
                    }
                }
            }
        })
    };

    if wants_enrich {
        enricher::enrich_devices(
            devices.clone(),
            cfg,
            etx.clone(),
            cancel.clone(),
            enrich_scope.clone(),
        )
        .await;
    }
    enrich_scope.finish();

    if wants_snmp && !cancel.is_cancelled() {
        if let Some(snmp) = &cfg.snmp {
            let version = match snmp.version {
                crate::models::SnmpVersion::V1 => "v1",
                crate::models::SnmpVersion::V2c => "v2c",
                crate::models::SnmpVersion::V3 => "v3",
            };
            let _ = etx
                .send(ScanEvent::info(format!(
                    "SNMP: polling {} candidate host(s) over SNMP{version}",
                    snmp_candidates.len(),
                )))
                .await;
            snmp_infra::probe_candidates(snmp_candidates, snmp, etx.clone(), cancel.clone()).await;
        }
    }
    snmp_scope.finish();

    ticker_stop.cancel();
    let _ = ticker.await;
    let _ = etx
        .send(progress(ScanPhase::Enriching, Some(counter)))
        .await;
    drop(etx);
    aggregator.await.context("enrichment aggregator crashed")
}

/// An L2 job whose targets are swept with ICMP instead (raw access unavailable).
struct Fallback {
    iface: String,
    vlan_id: Option<u16>,
    targets: Vec<Ipv4Range>,
    progress: ProgressScope,
}

/// Run the plan's L2 jobs in order. When raw access is unavailable, untagged targets fall back
/// to an ICMP sweep and tagged VLANs are reported as skipped. `scopes[i]` is job `i`'s share
/// of the scan progress; it is completed when the job ends (or is skipped).
async fn run_l2_jobs(
    plan: &ScanPlan,
    scopes: &[ProgressScope],
    cfg: &ScanConfig,
    tx: &Sender<ScanEvent>,
    cancel: &CancellationToken,
) {
    let mut fallback: Vec<Fallback> = Vec::new();
    let mut l2_unavailable: Option<String> = None;

    for (job, scope) in plan.l2_jobs.iter().zip(scopes) {
        if cancel.is_cancelled() {
            return;
        }
        let tagged: Vec<u16> = job.vlans.iter().flatten().copied().collect();
        let to_fallback = || Fallback {
            iface: job.iface.name.clone(),
            // Untagged jobs on an OS VLAN sub-interface still belong to that VLAN.
            vlan_id: job.iface.vlan_id,
            targets: job.targets.clone(),
            progress: scope.clone(),
        };
        if let Some(reason) = &l2_unavailable {
            if tagged.is_empty() {
                fallback.push(to_fallback());
            } else {
                let _ = tx
                    .send(ScanEvent::warn(format!(
                        "tagged VLAN probing skipped ({reason})"
                    )))
                    .await;
                scope.finish();
            }
            continue;
        }
        let res = arp_vlan::run_l2_scan(
            &job.iface,
            job.targets.clone(),
            job.vlans.clone(),
            cfg,
            scope.clone(),
            tx.clone(),
            cancel.clone(),
        )
        .await;
        match res {
            Ok(_) => scope.finish(),
            Err(e) if L2Error::is_l2_unavailable(&e) => {
                let reason = format!("{e:#}");
                if tagged.is_empty() {
                    let _ = tx
                        .send(ScanEvent::warn(format!(
                            "{reason}; falling back to an unprivileged ICMP sweep of {} (hosts that \
                             filter ICMP may be missed{})",
                            job.iface.name,
                            if cfg.ipv6 { ", IPv6 NDP needs raw access" } else { "" }
                        )))
                        .await;
                    fallback.push(to_fallback());
                } else {
                    let _ = tx
                        .send(ScanEvent::warn(format!(
                            "tagged VLAN probing skipped ({reason})"
                        )))
                        .await;
                    scope.finish();
                }
                if L2Error::is_permission(&e) {
                    l2_unavailable = Some(reason);
                }
            }
            Err(e) => {
                let _ = tx
                    .send(ScanEvent::error(format!(
                        "L2 scan on {} failed: {e:#}",
                        job.iface.name
                    )))
                    .await;
                scope.finish();
            }
        }
    }

    for fb in fallback {
        if cancel.is_cancelled() {
            return;
        }
        if let Err(e) = sweep::run_icmp_sweep(
            fb.targets,
            cfg,
            Some(&fb.iface),
            fb.vlan_id,
            fb.progress.clone(),
            tx.clone(),
            cancel.clone(),
        )
        .await
        {
            let _ = tx
                .send(ScanEvent::error(format!(
                    "ICMP fallback sweep failed: {e:#}"
                )))
                .await;
        }
        if !cancel.is_cancelled() {
            fb.progress.finish();
        }
    }
}

/// Passive VLAN + CDP/LLDP discovery (the `vlans` subcommand / GUI VLAN panel): OS VLAN
/// sub-interfaces of the chosen interface plus `timeout` of listening. Ends with
/// [`ScanEvent::Finished`].
pub async fn run_vlan_discovery(
    interface: Option<&str>,
    timeout: Duration,
    tx: Sender<ScanEvent>,
    cancel: CancellationToken,
) -> Result<PassiveResults> {
    let started = Instant::now();
    if timeout > Duration::from_secs(MAX_LISTEN_SECS) {
        return Err(anyhow!(
            "listen timeout must be at most {MAX_LISTEN_SECS} s"
        ));
    }
    let all = interfaces().await?;
    let iface = arp_vlan::select_interface(&all, interface)?;

    let mut os_vlans = Vec::new();
    for child in arp_vlan::vlan_children(&iface.name, &all) {
        if let Some(id) = child.vlan_id {
            let mut v = VlanInfo::new(id, VlanSource::OsInterface);
            v.interface = Some(child.name.clone());
            let _ = tx.send(ScanEvent::Vlan(v.clone())).await;
            os_vlans.push(v);
        }
    }
    let _ = tx
        .send(ScanEvent::info(format!(
            "listening on {} for {} s (802.1Q tags, CDP, LLDP, VTP, DTP)",
            iface.name,
            timeout.as_secs()
        )))
        .await;
    let _ = tx.send(progress(ScanPhase::Listening, None)).await;

    let mut res = arp_vlan::run_passive_sniffer(
        &iface.name,
        arp_vlan::local_macs(&all),
        timeout,
        tx.clone(),
        cancel.clone(),
    )
    .await?;
    for os in os_vlans {
        match res.vlans.iter_mut().find(|v| v.id == os.id) {
            Some(v) => v.merge(&os),
            None => res.vlans.push(os),
        }
    }
    res.vlans.sort_by_key(|v| v.id);

    let summary = ScanSummary {
        devices: 0,
        vlans: res.vlans.len() as u64,
        neighbors: res.neighbors.len() as u64,
        elapsed_ms: elapsed_ms(started),
        cancelled: cancel.is_cancelled(),
    };
    let _ = tx.send(progress(ScanPhase::Done, None)).await;
    let _ = tx.send(ScanEvent::Finished(summary)).await;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Capability, DeviceRole, IfAddr, InterfaceKind};

    fn test_overrides() -> Overrides {
        Arc::new(HashMap::new())
    }

    fn iface(name: &str, addr: &str, prefix: u8) -> InterfaceInfo {
        InterfaceInfo {
            name: name.into(),
            index: 1,
            description: None,
            mac: Some("00:11:22:33:44:55".into()),
            addrs: vec![IfAddr {
                ip: addr.parse().unwrap(),
                prefix,
            }],
            is_up: true,
            kind: InterfaceKind::Ethernet,
            vlan_id: None,
            parent: None,
            is_default: true,
        }
    }

    fn r(s: &str) -> Ipv4Range {
        s.parse().unwrap()
    }

    #[test]
    fn plan_splits_local_and_routed() {
        let en0 = iface("en0", "10.0.0.5", 24);
        let plan = plan_scan(
            &en0,
            std::slice::from_ref(&en0),
            &[r("10.0.0.0/23")],
            &[None],
            true,
        );
        assert_eq!(plan.l2_jobs.len(), 1);
        assert_eq!(plan.l2_jobs[0].targets, vec![r("10.0.0.1-10.0.0.254")]);
        assert_eq!(plan.routed, vec![r("10.0.0.255-10.0.1.254")]);
    }

    #[test]
    fn plan_routes_everything_outside_subnet() {
        let en0 = iface("en0", "10.0.0.5", 24);
        let plan = plan_scan(
            &en0,
            std::slice::from_ref(&en0),
            &[r("127.0.0.1")],
            &[None],
            true,
        );
        assert!(plan.l2_jobs.is_empty());
        assert_eq!(plan.routed, vec![r("127.0.0.1")]);
    }

    #[test]
    fn plan_uses_os_vlan_subinterface_when_available() {
        let en0 = iface("en0", "10.0.0.5", 24);
        let mut sub = iface("en0.100", "10.100.0.5", 24);
        sub.kind = InterfaceKind::Vlan;
        sub.vlan_id = Some(100);
        sub.parent = Some("en0".into());
        let all = vec![en0.clone(), sub];
        let plan = plan_scan(
            &en0,
            &all,
            &[r("10.0.0.0/24")],
            &[None, Some(100), Some(200)],
            false,
        );
        assert_eq!(plan.l2_jobs.len(), 3);
        assert_eq!(plan.l2_jobs[1].iface.name, "en0.100");
        assert_eq!(plan.l2_jobs[1].targets, vec![r("10.100.0.0/24")]);
        assert_eq!(plan.l2_jobs[1].vlans, vec![None]);
        assert_eq!(plan.l2_jobs[2].iface.name, "en0");
        assert_eq!(plan.l2_jobs[2].vlans, vec![Some(200)]);
        assert!(plan.notes.iter().any(|n| n.contains("native subnet")));
    }

    #[test]
    fn plan_tagged_only_with_explicit_range() {
        let en0 = iface("en0", "10.0.0.5", 24);
        let plan = plan_scan(
            &en0,
            std::slice::from_ref(&en0),
            &[r("172.16.10.0/24")],
            &[Some(10), Some(20)],
            true,
        );
        assert!(plan.routed.is_empty());
        assert_eq!(plan.l2_jobs.len(), 1);
        assert_eq!(plan.l2_jobs[0].vlans, vec![Some(10), Some(20)]);
        assert_eq!(plan.l2_jobs[0].targets, vec![r("172.16.10.0/24")]);
    }

    fn switch_neighbor(mac: &str, mgmt: &str) -> CdpLldpNeighbor {
        CdpLldpNeighbor {
            protocol: NeighborProtocol::Lldp,
            local_interface: "en0".into(),
            source_mac: mac.into(),
            device_id: "sw1".into(),
            system_name: Some("sw1".into()),
            system_description: None,
            port_id: Some("1/1/1".into()),
            port_description: None,
            platform: None,
            software_version: None,
            management_addrs: vec![mgmt.parse().unwrap()],
            native_vlan: Some(1),
            voice_vlan: None,
            capabilities: vec![Capability::Switch],
            vtp_domain: None,
            ttl_secs: 120,
            last_seen_ms: 0,
        }
    }

    #[tokio::test]
    async fn aggregator_merges_devices_neighbors_and_ipv6() {
        let (itx, irx) = mpsc::channel(64);
        let (otx, mut orx) = mpsc::channel(256);
        let agg = tokio::spawn(aggregate(
            Aggregate::default(),
            test_overrides(),
            true,
            irx,
            otx,
        ));

        let mut a = Device::new("10.0.0.2".parse().unwrap());
        a.mac = Some("aa:aa:aa:aa:aa:01".into());
        a.add_source(DiscoverySource::Arp);
        let mut a_icmp = Device::new("10.0.0.2".parse().unwrap());
        a_icmp.rtt_ms = Some(1.5);
        a_icmp.add_source(DiscoverySource::Icmp);
        let mut v6 = Device::new("fe80::1".parse().unwrap());
        v6.mac = Some("aa:aa:aa:aa:aa:01".into());
        v6.add_source(DiscoverySource::Ndp);
        let mut lone_v6 = Device::new("fe80::99".parse().unwrap());
        lone_v6.mac = Some("bb:bb:bb:bb:bb:bb".into());

        itx.send(ScanEvent::device(v6)).await.unwrap();
        itx.send(ScanEvent::device(a)).await.unwrap();
        itx.send(ScanEvent::device(a_icmp)).await.unwrap();
        itx.send(ScanEvent::device(lone_v6)).await.unwrap();
        itx.send(ScanEvent::Neighbor(switch_neighbor(
            "cc:cc:cc:cc:cc:cc",
            "10.0.0.2",
        )))
        .await
        .unwrap();
        drop(itx);

        let state = agg.await.unwrap();
        assert_eq!(state.devices.len(), 2);
        let d = &state.devices["10.0.0.2"];
        assert_eq!(d.role, DeviceRole::Switch);
        assert_eq!(d.rtt_ms, Some(1.5));
        assert_eq!(
            d.extra_ips,
            vec!["fe80::1".parse::<std::net::IpAddr>().unwrap()]
        );
        for s in [
            DiscoverySource::Arp,
            DiscoverySource::Icmp,
            DiscoverySource::Lldp,
            DiscoverySource::Ndp,
        ] {
            assert!(d.sources.contains(&s), "{s:?}");
        }
        assert!(state.devices.contains_key("fe80::99"));

        let mut events = Vec::new();
        while let Ok(ev) = orx.try_recv() {
            events.push(ev);
        }
        // IPv6 rows are only emitted after IPv4 rows, never before.
        let first_v6 = events
            .iter()
            .position(|e| matches!(e, ScanEvent::Device(d) if d.ip.is_ipv6()))
            .unwrap();
        assert!(events[..first_v6]
            .iter()
            .any(|e| matches!(e, ScanEvent::Device(_))));
        assert!(events.iter().any(|e| matches!(e, ScanEvent::Neighbor(_))));
    }

    fn drain(orx: &mut Receiver<ScanEvent>) -> Vec<ScanEvent> {
        let mut events = Vec::new();
        while let Ok(ev) = orx.try_recv() {
            events.push(ev);
        }
        events
    }

    #[tokio::test]
    async fn vlan_snapshots_are_not_double_counted() {
        let (itx, irx) = mpsc::channel(64);
        let (otx, mut orx) = mpsc::channel(256);
        let agg = tokio::spawn(aggregate(
            Aggregate::default(),
            test_overrides(),
            true,
            irx,
            otx,
        ));
        let snap = |frames: u64| {
            let mut v = VlanInfo::new(30, VlanSource::Tagged8021q);
            v.frames_seen = frames;
            ScanEvent::Vlan(v)
        };
        // Listener and auto-detect sniff the same 6 frames concurrently: each streams an
        // early snapshot and a final cumulative one.
        for ev in [snap(1), snap(1), snap(4), snap(6), snap(6)] {
            itx.send(ev).await.unwrap();
        }
        drop(itx);
        let state = agg.await.unwrap();
        assert_eq!(state.vlans[&30].frames_seen, 6);
        let forwarded = drain(&mut orx)
            .into_iter()
            .filter(|e| matches!(e, ScanEvent::Vlan(_)))
            .count();
        assert_eq!(forwarded, 3, "unchanged snapshots are not re-sent");
    }

    #[tokio::test]
    async fn ipv6_folding_is_deterministic() {
        for _ in 0..20 {
            let (itx, irx) = mpsc::channel(64);
            let (otx, _orx) = mpsc::channel(256);
            let agg = tokio::spawn(aggregate(
                Aggregate::default(),
                test_overrides(),
                true,
                irx,
                otx,
            ));
            // Proxy-ARP style: several IPv4 rows share one MAC.
            for ip in ["10.0.0.30", "10.0.0.4", "10.0.0.200", "10.0.0.17"] {
                let mut d = Device::new(ip.parse().unwrap());
                d.mac = Some("aa:aa:aa:aa:aa:01".into());
                itx.send(ScanEvent::device(d)).await.unwrap();
            }
            // Same MAC on another VLAN must not attract the IPv6 address.
            let mut other_vlan = Device::new("10.0.0.1".parse().unwrap());
            other_vlan.mac = Some("aa:aa:aa:aa:aa:01".into());
            other_vlan.vlan_id = Some(20);
            itx.send(ScanEvent::device(other_vlan)).await.unwrap();
            let mut v6 = Device::new("fe80::1".parse().unwrap());
            v6.mac = Some("aa:aa:aa:aa:aa:01".into());
            itx.send(ScanEvent::device(v6)).await.unwrap();
            drop(itx);
            let state = agg.await.unwrap();
            let owners: Vec<&str> = state
                .devices
                .iter()
                .filter(|(_, d)| !d.extra_ips.is_empty())
                .map(|(k, _)| k.as_str())
                .collect();
            assert_eq!(owners, vec!["10.0.0.4"]);
        }
    }

    #[tokio::test]
    async fn neighbors_are_deduplicated_and_indexed() {
        let (itx, irx) = mpsc::channel(64);
        let (otx, mut orx) = mpsc::channel(256);
        let agg = tokio::spawn(aggregate(
            Aggregate::default(),
            test_overrides(),
            true,
            irx,
            otx,
        ));
        let n = switch_neighbor("cc:cc:cc:cc:cc:cc", "10.0.0.9");
        itx.send(ScanEvent::Neighbor(n.clone())).await.unwrap();
        let mut again = n.clone();
        again.last_seen_ms += 30_000;
        itx.send(ScanEvent::Neighbor(again)).await.unwrap(); // same advert, later
                                                             // Device learned after the neighbor matches by MAC.
        let mut d = Device::new("10.0.0.50".parse().unwrap());
        d.mac = Some("cc:cc:cc:cc:cc:cc".into());
        itx.send(ScanEvent::device(d)).await.unwrap();
        // A changed advert is forwarded and re-applied.
        let mut changed = n.clone();
        changed.capabilities = vec![Capability::WlanAccessPoint];
        itx.send(ScanEvent::Neighbor(changed)).await.unwrap();
        itx.send(progress(ScanPhase::Discovering, None))
            .await
            .unwrap();
        drop(itx);
        let state = agg.await.unwrap();
        assert_eq!(state.neighbors.len(), 1);
        let dev = &state.devices["10.0.0.50"];
        assert_eq!(dev.role, DeviceRole::Switch);
        assert_eq!(
            dev.neighbor.as_ref().unwrap().capabilities,
            vec![Capability::WlanAccessPoint]
        );
        let events = drain(&mut orx);
        let neighbors = events
            .iter()
            .filter(|e| matches!(e, ScanEvent::Neighbor(_)))
            .count();
        assert_eq!(neighbors, 2);
        assert!(events
            .iter()
            .any(|e| matches!(e, ScanEvent::Progress(p) if p.devices_found == 1)));
    }

    #[tokio::test]
    async fn port_mapping_is_applied_to_matching_device() {
        let (itx, irx) = mpsc::channel(64);
        let (otx, mut orx) = mpsc::channel(256);
        let agg = tokio::spawn(aggregate(
            Aggregate::default(),
            test_overrides(),
            false,
            irx,
            otx,
        ));
        let mut d = Device::new("10.0.0.40".parse().unwrap());
        d.mac = Some("aa:bb:cc:00:11:22".into());
        itx.send(ScanEvent::device(d)).await.unwrap();
        let pm = SwitchPortMapping {
            switch_name: "core-sw-01".into(),
            switch_ip: Some("10.0.0.1".parse().unwrap()),
            port_name: "Gi1/0/24".into(),
            port_index: Some(10024),
            vlan_id: Some(20),
            mac: "AA:BB:CC:00:11:22".into(), // different case: must still match
        };
        itx.send(ScanEvent::PortMapping(pm)).await.unwrap();
        drop(itx);
        let state = agg.await.unwrap();
        let dev = &state.devices["10.0.0.40"];
        assert_eq!(dev.switch_port.as_ref().unwrap().port_name, "Gi1/0/24");
        assert!(dev.sources.contains(&DiscoverySource::Snmp));
        // A device learned *after* the mapping also picks it up.
        let events = drain(&mut orx);
        assert!(events
            .iter()
            .any(|e| matches!(e, ScanEvent::Device(d) if d.switch_port.is_some())));
        assert!(events
            .iter()
            .any(|e| matches!(e, ScanEvent::PortMapping(_))));
    }

    #[tokio::test]
    async fn overrides_are_applied_to_emitted_devices() {
        let (itx, irx) = mpsc::channel(64);
        let (otx, mut orx) = mpsc::channel(256);
        let mut ov = HashMap::new();
        ov.insert(
            "10.0.0.7".to_string(),
            DeviceOverride {
                hostname: Some("edge-fw".into()),
                comments: Some("rack 2".into()),
            },
        );
        let agg = tokio::spawn(aggregate(
            Aggregate::default(),
            Arc::new(ov),
            true,
            irx,
            otx,
        ));
        itx.send(ScanEvent::device(Device::new("10.0.0.7".parse().unwrap())))
            .await
            .unwrap();
        drop(itx);
        let _ = agg.await.unwrap();
        let events = drain(&mut orx);
        assert!(events.iter().any(|e| matches!(
            e,
            ScanEvent::Device(d) if d.hostname.as_deref() == Some("edge-fw")
                && d.comments.as_deref() == Some("rack 2")
        )));
    }

    #[tokio::test]
    async fn neighbor_table_is_capped() {
        let (itx, irx) = mpsc::channel(64);
        let (otx, mut orx) = mpsc::channel(64);
        let agg = tokio::spawn(aggregate(
            Aggregate::default(),
            test_overrides(),
            true,
            irx,
            otx,
        ));
        let drain_task = tokio::spawn(async move {
            let mut warns = 0;
            while let Some(ev) = orx.recv().await {
                if matches!(ev, ScanEvent::Log { .. }) {
                    warns += 1;
                }
            }
            warns
        });
        for i in 0..(arp_vlan::MAX_NEIGHBORS + 10) {
            let mut n = switch_neighbor("cc:cc:cc:cc:cc:cc", "10.0.0.9");
            n.device_id = format!("spoof-{i}");
            itx.send(ScanEvent::Neighbor(n)).await.unwrap();
        }
        drop(itx);
        let state = agg.await.unwrap();
        assert_eq!(state.neighbors.len(), arp_vlan::MAX_NEIGHBORS);
        assert_eq!(drain_task.await.unwrap(), 1);
    }

    #[test]
    fn wifi_tagged_probing_warns() {
        let mut wifi = iface("en0", "10.0.0.5", 24);
        wifi.kind = InterfaceKind::Wifi;
        let plan = plan_scan(
            &wifi,
            std::slice::from_ref(&wifi),
            &[r("10.0.0.0/24")],
            &[None, Some(10)],
            true,
        );
        let w = wifi_tagging_warning(&wifi, &plan).unwrap();
        assert!(w.contains("Wi-Fi") && w.contains("10"));
        let untagged = plan_scan(
            &wifi,
            std::slice::from_ref(&wifi),
            &[r("10.0.0.0/24")],
            &[None],
            true,
        );
        assert!(wifi_tagging_warning(&wifi, &untagged).is_none());
        let eth = iface("en1", "10.0.0.5", 24);
        let tagged = plan_scan(
            &eth,
            std::slice::from_ref(&eth),
            &[r("10.0.0.0/24")],
            &[Some(10)],
            true,
        );
        assert!(wifi_tagging_warning(&eth, &tagged).is_none());
    }
}
