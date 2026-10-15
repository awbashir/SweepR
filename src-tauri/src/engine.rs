//! Scan orchestration shared by the CLI and the GUI.
//!
//! [`run_scan`] wires the pieces together: interface + target selection, VLAN resolution,
//! the passive CDP/LLDP/VLAN listener, raw L2 (ARP / NDP) probing of connected and tagged
//! networks, ICMP sweeps of routed targets (and as the unprivileged fallback), and a single
//! aggregator that de-duplicates devices, applies CDP/LLDP roles and streams [`ScanEvent`]s.

use std::{
    collections::{BTreeMap, HashMap},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_util::sync::CancellationToken;

use crate::{
    arp_vlan::{self, L2Error, PassiveResults},
    models::{
        CdpLldpNeighbor, Device, DiscoverySource, InterfaceInfo, Ipv4Range, NeighborProtocol,
        ScanConfig, ScanEvent, ScanPhase, ScanProgress, ScanSummary, VlanInfo, VlanSource,
    },
    sweep,
};

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

// ---------------------------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------------------------

/// Final state collected by the aggregator.
#[derive(Debug, Default)]
pub struct Aggregate {
    pub devices: HashMap<String, Device>,
    pub neighbors: HashMap<String, CdpLldpNeighbor>,
    pub vlans: BTreeMap<u16, VlanInfo>,
}

impl Aggregate {
    /// Devices sorted by VLAN, then IP.
    pub fn sorted_devices(&self) -> Vec<Device> {
        let mut v: Vec<Device> = self.devices.values().cloned().collect();
        v.sort_by_key(|d| (d.vlan_id, d.ip));
        v
    }
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
    let role = n.infer_role();
    if role.priority() > dev.role.priority() {
        dev.role = role;
    }
    dev.neighbor = Some(n.clone());
    dev.add_source(match n.protocol {
        NeighborProtocol::Cdp => DiscoverySource::Cdp,
        NeighborProtocol::Lldp => DiscoverySource::Lldp,
    });
    true
}

/// Consume engine-internal events, merge them and forward the merged view to `out`.
///
/// IPv6 observations are held back until the end and folded into the IPv4 row with the same
/// MAC and VLAN (as `extraIps`), so the stream never shows a row that later disappears.
async fn aggregate(mut rx: Receiver<ScanEvent>, out: Sender<ScanEvent>) -> Aggregate {
    let mut state = Aggregate::default();
    let mut pending_v6: HashMap<String, Device> = HashMap::new();

    while let Some(ev) = rx.recv().await {
        match ev {
            ScanEvent::Device(d) => {
                let d = *d;
                if d.ip.is_ipv6() {
                    pending_v6
                        .entry(d.key())
                        .and_modify(|e| e.merge(&d))
                        .or_insert(d);
                    continue;
                }
                let entry = state
                    .devices
                    .entry(d.key())
                    .and_modify(|e| e.merge(&d))
                    .or_insert(d);
                for n in state.neighbors.values() {
                    apply_neighbor(entry, n);
                }
                let _ = out.send(ScanEvent::device(entry.clone())).await;
            }
            ScanEvent::Neighbor(n) => {
                let _ = out.send(ScanEvent::Neighbor(n.clone())).await;
                for dev in state.devices.values_mut() {
                    if apply_neighbor(dev, &n) {
                        let _ = out.send(ScanEvent::device(dev.clone())).await;
                    }
                }
                state.neighbors.insert(n.key(), n);
            }
            ScanEvent::Vlan(v) => {
                let merged = match state.vlans.get_mut(&v.id) {
                    Some(existing) => {
                        existing.merge(&v);
                        existing.clone()
                    }
                    None => {
                        state.vlans.insert(v.id, v.clone());
                        v
                    }
                };
                let _ = out.send(ScanEvent::Vlan(merged)).await;
            }
            other => {
                let _ = out.send(other).await;
            }
        }
    }

    let mut v6: Vec<Device> = pending_v6.into_values().collect();
    v6.sort_by_key(|d| (d.vlan_id, d.ip));
    for d6 in v6 {
        let owner = state.devices.values_mut().find(|d| {
            d.ip.is_ipv4() && d.mac.is_some() && d.mac == d6.mac && d.vlan_id == d6.vlan_id
        });
        let merged = match owner {
            Some(d) => {
                d.merge(&d6);
                d.clone()
            }
            None => {
                let mut d = d6;
                for n in state.neighbors.values() {
                    apply_neighbor(&mut d, n);
                }
                state.devices.insert(d.key(), d.clone());
                d
            }
        };
        let _ = out.send(ScanEvent::device(merged)).await;
    }
    state
}

// ---------------------------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------------------------

fn progress(phase: ScanPhase, found: u64) -> ScanEvent {
    ScanEvent::Progress(ScanProgress {
        phase,
        probes_sent: 0,
        probes_total: 0,
        devices_found: found,
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

/// Run a full scan described by `cfg`, streaming events to `tx`. Always ends with a
/// [`ScanEvent::Finished`] on success; returns the summary.
///
/// SNMP polling, name resolution and port scanning settings are accepted but not acted on
/// by this engine version.
pub async fn run_scan(
    cfg: ScanConfig,
    tx: Sender<ScanEvent>,
    cancel: CancellationToken,
) -> Result<ScanSummary> {
    let started = Instant::now();
    cfg.validate()?;
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
    let aggregator = tokio::spawn(aggregate(irx, tx.clone()));
    let _ = itx.send(progress(ScanPhase::Preparing, 0)).await;
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
        let duration = Duration::from_secs(cfg.listen_secs.max(1));
        tokio::spawn(
            async move { arp_vlan::run_passive_sniffer(&name, duration, itx, cancel).await },
        )
    });

    let vlans = arp_vlan::resolve_vlans(&cfg, &iface, &all, &itx, &cancel).await;
    let plan = plan_scan(&iface, &all, &targets, &vlans, explicit_range);
    for note in &plan.notes {
        let _ = itx.send(ScanEvent::info(note.clone())).await;
    }
    if cfg.ipv6 && plan.l2_jobs.is_empty() {
        let _ = itx
            .send(ScanEvent::warn(
                "IPv6 NDP discovery runs on layer-2 scanned links only; no target is on a \
                 connected subnet",
            ))
            .await;
    }
    let _ = itx.send(progress(ScanPhase::Discovering, 0)).await;

    let routed = async {
        if plan.routed.is_empty() || cancel.is_cancelled() {
            return;
        }
        // Routed probes follow the routing table, so no interface is attributed to them.
        if let Err(e) =
            sweep::run_icmp_sweep(plan.routed.clone(), &cfg, None, itx.clone(), cancel.clone())
                .await
        {
            let _ = itx
                .send(ScanEvent::error(format!("ICMP sweep failed: {e:#}")))
                .await;
        }
    };
    let local = run_l2_jobs(&plan, &cfg, &itx, &cancel);
    tokio::join!(routed, local);

    if let Some(handle) = listener {
        if !cancel.is_cancelled() {
            let _ = itx.send(progress(ScanPhase::Listening, 0)).await;
        }
        match handle.await {
            Ok(Ok(res)) => {
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
    let summary = ScanSummary {
        devices: state.devices.len() as u64,
        vlans: state.vlans.len() as u64,
        neighbors: state.neighbors.len() as u64,
        elapsed_ms: elapsed_ms(started),
        cancelled: cancel.is_cancelled(),
    };
    let _ = tx.send(progress(ScanPhase::Done, summary.devices)).await;
    let _ = tx.send(ScanEvent::Finished(summary.clone())).await;
    Ok(summary)
}

/// Run the plan's L2 jobs in order. When raw access is unavailable, untagged targets fall back
/// to an ICMP sweep and tagged VLANs are reported as skipped.
async fn run_l2_jobs(
    plan: &ScanPlan,
    cfg: &ScanConfig,
    tx: &Sender<ScanEvent>,
    cancel: &CancellationToken,
) {
    let mut fallback: Vec<(String, Vec<Ipv4Range>)> = Vec::new();
    let mut l2_unavailable: Option<String> = None;

    for job in &plan.l2_jobs {
        if cancel.is_cancelled() {
            return;
        }
        let tagged: Vec<u16> = job.vlans.iter().flatten().copied().collect();
        if let Some(reason) = &l2_unavailable {
            if tagged.is_empty() {
                fallback.push((job.iface.name.clone(), job.targets.clone()));
            } else {
                let _ = tx
                    .send(ScanEvent::warn(format!(
                        "tagged VLAN probing skipped ({reason})"
                    )))
                    .await;
            }
            continue;
        }
        let res = arp_vlan::run_l2_scan(
            &job.iface,
            job.targets.clone(),
            job.vlans.clone(),
            cfg,
            tx.clone(),
            cancel.clone(),
        )
        .await;
        match res {
            Ok(_) => {}
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
                    fallback.push((job.iface.name.clone(), job.targets.clone()));
                } else {
                    let _ = tx
                        .send(ScanEvent::warn(format!(
                            "tagged VLAN probing skipped ({reason})"
                        )))
                        .await;
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
            }
        }
    }

    for (iface, targets) in fallback {
        if cancel.is_cancelled() {
            return;
        }
        if let Err(e) =
            sweep::run_icmp_sweep(targets, cfg, Some(&iface), tx.clone(), cancel.clone()).await
        {
            let _ = tx
                .send(ScanEvent::error(format!(
                    "ICMP fallback sweep failed: {e:#}"
                )))
                .await;
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
    let _ = tx.send(progress(ScanPhase::Listening, 0)).await;

    let mut res =
        arp_vlan::run_passive_sniffer(&iface.name, timeout, tx.clone(), cancel.clone()).await?;
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
    let _ = tx.send(progress(ScanPhase::Done, 0)).await;
    let _ = tx.send(ScanEvent::Finished(summary)).await;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Capability, DeviceRole, IfAddr, InterfaceKind};

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
        let agg = tokio::spawn(aggregate(irx, otx));

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
}
