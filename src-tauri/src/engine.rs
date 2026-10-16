//! Scan orchestration shared by the CLI and the GUI.
//!
//! [`run_scan`] wires the pieces together: interface + target selection, VLAN resolution,
//! the passive CDP/LLDP/VLAN listener, raw L2 (ARP / NDP) probing of connected and tagged
//! networks, ICMP sweeps of routed targets (and as the unprivileged fallback), and a single
//! aggregator that de-duplicates devices, applies CDP/LLDP roles and streams [`ScanEvent`]s.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_util::sync::CancellationToken;

use crate::{
    arp_vlan::{self, L2Error, PassiveResults},
    dhcp_fp, enricher,
    limits::SocketBudget,
    models::{
        normalize_mac, Capability, CdpLldpNeighbor, Device, DeviceOverride, DeviceRole,
        DiscoverySource, InterfaceInfo, InterfaceKind, Ipv4Range, NeighborProtocol, ScanConfig,
        ScanEvent, ScanPhase, ScanProgress, ScanSummary, SwitchPortMapping, VlanInfo, VlanSource,
        MAX_LISTEN_SECS,
    },
    progress::{ProgressCounter, ProgressScope},
    services, snmp_infra, sweep, webid,
};

/// Shared, read-only map of user device overrides applied to every emitted [`Device`].
type Overrides = Arc<HashMap<String, DeviceOverride>>;

/// How the engine runs, beyond the user's [`ScanConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanOptions {
    /// Fill emitted devices' `hostname` / `comments` from the local override store. The CLI
    /// wants this (its output is final). The GUI does not: it owns the overrides it loaded
    /// with `load_overrides`, applies them itself and must be able to clear them, which it
    /// could not if the engine kept copying them into every device snapshot.
    pub apply_overrides: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            apply_overrides: true,
        }
    }
}

/// A switch port that learned more MACs than this is treated as an uplink / trunk (or an
/// unmanaged switch behind an access port) and is never assigned as a device's `switchPort`.
/// The full CAM table stays available through the `port_mapping` events.
pub const MAX_ACCESS_PORT_MACS: usize = 48;

/// Upper bound of SNMP MAC-to-port entries the aggregator keeps per scan (all switches).
pub const MAX_AGGREGATE_MAPPINGS: usize = 200_000;

/// MAC-only observations (DHCP clients without an address) held for late matching.
const MAX_PENDING_MAC_ONLY: usize = 8192;

/// `(switch name, switch IP, port name)`: one physical switch port.
type PortKey = (String, Option<IpAddr>, String);

fn port_key(pm: &SwitchPortMapping) -> PortKey {
    (pm.switch_name.clone(), pm.switch_ip, pm.port_name.clone())
}

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
    /// Every SNMP MAC-to-switch-port entry, by endpoint MAC (canonical lowercase). A MAC
    /// usually appears on several switches (its access port plus every uplink towards it).
    port_mappings_by_mac: HashMap<String, Vec<SwitchPortMapping>>,
    /// Distinct MACs learned per switch port (uplink / trunk detection).
    port_macs: HashMap<PortKey, HashSet<String>>,
    /// Entries stored in `port_mappings_by_mac` (bounded by [`MAX_AGGREGATE_MAPPINGS`]).
    port_mapping_count: usize,
    neighbor_limit_warned: bool,
    mapping_limit_warned: bool,
    /// Override of [`MAX_AGGREGATE_MAPPINGS`] (tests).
    mapping_limit: Option<usize>,
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

    /// Re-index a device after it changed and apply the neighbors (and the best known
    /// switch-port mapping) that now match it.
    fn refresh_device(&mut self, key: &str) {
        self.index_device(key);
        if let Some(mut dev) = self.devices.remove(key) {
            self.apply_neighbors(&mut dev);
            self.assign_switch_port(&mut dev);
            self.devices.insert(key.to_string(), dev);
        }
    }

    /// Store one SNMP mapping. Exact duplicates are ignored; beyond
    /// [`MAX_AGGREGATE_MAPPINGS`] new entries are dropped.
    fn add_port_mapping(&mut self, pm: &SwitchPortMapping) -> MappingUpdate {
        let mac = normalize_mac(&pm.mac).unwrap_or_else(|| pm.mac.to_ascii_lowercase());
        let entries = self.port_mappings_by_mac.get(&mac);
        let same = |e: &SwitchPortMapping| {
            e.switch_name == pm.switch_name
                && e.switch_ip == pm.switch_ip
                && e.port_name == pm.port_name
                && e.vlan_id == pm.vlan_id
        };
        if entries.is_some_and(|v| v.iter().any(same)) {
            return MappingUpdate::Duplicate;
        }
        if self.port_mapping_count >= self.mapping_limit.unwrap_or(MAX_AGGREGATE_MAPPINGS) {
            let first = !self.mapping_limit_warned;
            self.mapping_limit_warned = true;
            return MappingUpdate::OverLimit { first };
        }
        self.port_mapping_count += 1;
        self.port_macs
            .entry(port_key(pm))
            .or_default()
            .insert(mac.clone());
        self.port_mappings_by_mac
            .entry(mac.clone())
            .or_default()
            .push(pm.clone());
        MappingUpdate::Stored(mac)
    }

    /// `true` when switch port `port` links to other network infrastructure: a MAC learned
    /// on it (other than `own_mac`) belongs to a device known to be a switch, router or
    /// firewall, or to a CDP/LLDP neighbor that is one. Endpoints behind such a port are not
    /// on it; the infrastructure device itself is.
    fn is_infra_link(&self, port: &PortKey, own_mac: &str) -> bool {
        let Some(macs) = self.port_macs.get(port) else {
            return false;
        };
        let infra = |role: DeviceRole| {
            matches!(
                role,
                DeviceRole::Switch | DeviceRole::Router | DeviceRole::Firewall
            )
        };
        macs.iter().filter(|m| m.as_str() != own_mac).any(|m| {
            self.devices_by_mac.get(m).is_some_and(|keys| {
                keys.iter()
                    .filter_map(|k| self.devices.get(k))
                    .any(|d| infra(d.role))
            }) || self.neighbors_by_mac.get(m).is_some_and(|keys| {
                keys.iter()
                    .filter_map(|k| self.neighbors.get(k))
                    .any(|n| infra(n.infer_role()))
            })
        })
    }

    /// The switch port `dev` is most likely plugged into, from every SNMP mapping of its MAC.
    ///
    /// * Ports learning more than [`MAX_ACCESS_PORT_MACS`] MACs (uplinks / trunks) and ports
    ///   that link to other infrastructure are never chosen.
    /// * When the device's VLAN and the mapping's VLAN are both known, a matching VLAN wins.
    /// * Then the port with the fewest MACs (closest to the device) wins; remaining ties are
    ///   broken by switch name, switch IP, port name and VLAN, so the result does not depend
    ///   on the order in which switches answered.
    fn best_port_mapping(&self, dev: &Device) -> Option<SwitchPortMapping> {
        let mac = dev.mac.as_ref()?;
        let candidates = self.port_mappings_by_mac.get(mac)?;
        candidates
            .iter()
            .filter_map(|pm| {
                let key = port_key(pm);
                let count = self.port_macs.get(&key).map_or(0, HashSet::len);
                if count > MAX_ACCESS_PORT_MACS || self.is_infra_link(&key, mac) {
                    return None;
                }
                let vlan_mismatch =
                    matches!((dev.vlan_id, pm.vlan_id), (Some(a), Some(b)) if a != b);
                Some((
                    (
                        vlan_mismatch,
                        count,
                        &pm.switch_name,
                        pm.switch_ip,
                        &pm.port_name,
                        pm.vlan_id,
                    ),
                    pm,
                ))
            })
            .min_by(|a, b| a.0.cmp(&b.0))
            .map(|(_, pm)| pm.clone())
    }

    /// `true` when `dev` is the device a PoE port powers: the only MAC on the port, or the
    /// only powered-looking device (phone / AP / camera / member of the voice VLAN) among
    /// the MACs learned there. A PC daisy-chained behind a phone never gets the phone's power.
    fn is_powered_endpoint(&self, key: &PortKey, dev: &Device, voice: Option<u16>) -> bool {
        let Some(macs) = self.port_macs.get(key) else {
            return true;
        };
        if macs.len() <= 1 {
            return true;
        }
        if !looks_powered(dev, voice) {
            return false;
        }
        let own = dev.mac.as_deref();
        !macs.iter().filter(|m| Some(m.as_str()) != own).any(|m| {
            self.devices_by_mac.get(m).is_some_and(|keys| {
                keys.iter()
                    .filter_map(|k| self.devices.get(k))
                    .any(|d| looks_powered(d, voice))
            })
        })
    }

    /// Recompute `dev.switch_port` (and the PoE / voice VLAN that come with it) from the
    /// stored mappings; returns `true` when anything changed.
    ///
    /// PoE and the voice VLAN are derived from the *chosen* port on every call, falling back
    /// to the endpoint's own CDP/LLDP advertisement, so a provisional choice that later moves
    /// to another port leaves nothing stale behind.
    fn assign_switch_port(&self, dev: &mut Device) -> bool {
        if self.port_mappings_by_mac.is_empty() {
            return false;
        }
        let best = self.best_port_mapping(dev);
        let (own_poe, own_voice) = own_advertisement(dev);
        let (port_poe, port_voice) = match &best {
            Some(pm) => {
                let key = port_key(pm);
                let single = self.port_macs.get(&key).is_none_or(|m| m.len() <= 1);
                let poe = pm
                    .poe
                    .clone()
                    .filter(|_| self.is_powered_endpoint(&key, dev, pm.voice_vlan));
                // The port's voice VLAN describes the phone on it, not a PC behind the phone
                // in the data VLAN.
                let voice = pm.voice_vlan.filter(|v| {
                    single || dev.vlan_id == Some(*v) || looks_powered(dev, pm.voice_vlan)
                });
                (poe, voice)
            }
            None => (None, None),
        };
        let poe = port_poe.or(own_poe);
        let voice = port_voice.or(own_voice);
        if best == dev.switch_port && poe == dev.poe && voice == dev.voice_vlan {
            return false;
        }
        if best.is_some() {
            dev.add_source(DiscoverySource::Snmp);
        }
        dev.switch_port = best;
        dev.poe = poe;
        dev.voice_vlan = voice;
        true
    }

    /// Re-assign the switch port of the devices with `mac`; returns the keys that changed.
    fn reassign_mac(&mut self, mac: &str) -> Vec<String> {
        let keys: Vec<String> = self
            .devices_by_mac
            .get(mac)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
        self.reassign(keys)
    }

    /// Re-assign the switch port of every device with a MAC (the final, order-independent
    /// pass once all mappings and roles are known); returns the keys that changed.
    fn reassign_all(&mut self) -> Vec<String> {
        if self.port_mappings_by_mac.is_empty() {
            return Vec::new();
        }
        let mut keys: Vec<String> = self
            .devices
            .iter()
            .filter(|(_, d)| d.mac.is_some())
            .map(|(k, _)| k.clone())
            .collect();
        keys.sort();
        self.reassign(keys)
    }

    fn reassign(&mut self, keys: Vec<String>) -> Vec<String> {
        let mut changed = Vec::new();
        for key in keys {
            if let Some(mut dev) = self.devices.remove(&key) {
                if self.assign_switch_port(&mut dev) {
                    changed.push(key.clone());
                }
                self.devices.insert(key, dev);
            }
        }
        changed
    }

    /// Fold a MAC-only observation (unspecified IP, e.g. a DHCP client without an address yet)
    /// into every device with that MAC (on the same VLAN, when the observation has one).
    /// Returns the keys that were updated.
    fn apply_by_mac(&mut self, obs: &Device) -> Vec<String> {
        let Some(mac) = obs.mac.as_ref().and_then(|m| normalize_mac(m)) else {
            return Vec::new();
        };
        let keys: Vec<String> = self
            .devices_by_mac
            .get(&mac)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
        let mut changed = Vec::new();
        for key in keys {
            let Some(dev) = self.devices.get_mut(&key) else {
                continue;
            };
            if obs.vlan_id.is_some() && obs.vlan_id != dev.vlan_id {
                continue;
            }
            let mut update = obs.clone();
            update.ip = dev.ip;
            update.vlan_id = dev.vlan_id;
            update.extra_ips.clear();
            dev.merge(&update);
            changed.push(key);
        }
        changed
    }

    /// Every stored SNMP mapping (tests / diagnostics).
    pub fn port_mapping_count(&self) -> usize {
        self.port_mapping_count
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

/// Result of [`Aggregate::add_port_mapping`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum MappingUpdate {
    /// New entry for this (canonical) MAC: forward it and re-evaluate its devices.
    Stored(String),
    /// Already known: nothing to do.
    Duplicate,
    /// Dropped because the mapping table is full (`first` = warn now).
    OverLimit { first: bool },
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

/// A device that typically draws PoE: IP phone, access point, camera, or a member of the
/// port's voice VLAN.
fn looks_powered(dev: &Device, voice: Option<u16>) -> bool {
    dev.role == DeviceRole::AccessPoint
        || matches!(
            dev.device_kind.as_deref(),
            Some(crate::models::DEVICE_KIND_VOIP_PHONE | "camera" | "access_point")
        )
        || dev.onvif.as_ref().is_some_and(|o| o.is_camera)
        || dev.neighbor.as_ref().is_some_and(|n| {
            n.capabilities.contains(&Capability::Telephone)
                || n.capabilities.contains(&Capability::WlanAccessPoint)
        })
        || (voice.is_some() && dev.vlan_id == voice)
        || dev
            .vendor
            .as_deref()
            .is_some_and(crate::sip::is_voip_vendor_strict)
}

/// PoE and voice VLAN from the device's own CDP/LLDP advertisement (an endpoint describing
/// itself; a switch / router advertisement describes the port it is plugged into instead).
fn own_advertisement(dev: &Device) -> (Option<crate::models::PoeInfo>, Option<u16>) {
    match &dev.neighbor {
        Some(n) if !is_infra_role(n.infer_role()) => (
            n.poe_info.as_deref().cloned(),
            n.voice_vlan
                .filter(|_| n.capabilities.contains(&Capability::Telephone)),
        ),
        _ => (None, None),
    }
}

fn is_infra_role(role: DeviceRole) -> bool {
    matches!(
        role,
        DeviceRole::Switch | DeviceRole::Router | DeviceRole::Firewall
    )
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
    let before = (
        dev.role,
        dev.neighbor.clone(),
        dev.sources.len(),
        dev.voice_vlan,
        dev.poe.clone(),
    );
    let role = n.infer_role();
    if role.priority() > dev.role.priority() {
        dev.role = role;
    }
    // An endpoint advertising itself (IP phone, AP, camera): its own LLDP-MED / CDP voice VLAN
    // and the PoE it draws describe it. A switch / router's advertisement describes *our* port,
    // so it is not copied onto the switch's row.
    let infra = matches!(
        role,
        DeviceRole::Switch | DeviceRole::Router | DeviceRole::Firewall
    );
    if !infra {
        if dev.voice_vlan.is_none() && n.capabilities.contains(&Capability::Telephone) {
            dev.voice_vlan = n.voice_vlan;
        }
        if dev.poe.is_none() {
            dev.poe = n.poe_info.as_deref().cloned();
        }
    }
    dev.neighbor = Some(n.clone());
    dev.add_source(match n.protocol {
        NeighborProtocol::Cdp => DiscoverySource::Cdp,
        NeighborProtocol::Lldp => DiscoverySource::Lldp,
    });
    before
        != (
            dev.role,
            dev.neighbor.clone(),
            dev.sources.len(),
            dev.voice_vlan,
            dev.poe.clone(),
        )
}

/// Clone `dev`, apply the user override (when overrides are applied at all), and forward it
/// as a `device` event.
async fn send_device(out: &Sender<ScanEvent>, overrides: Option<&Overrides>, dev: &Device) {
    let mut dev = dev.clone();
    if let Some(overrides) = overrides {
        enricher::apply_override(&mut dev, overrides);
    }
    let _ = out.send(ScanEvent::device(dev)).await;
}

/// Consume engine-internal events, merge them and forward the merged view to `out`.
///
/// Starts from `state` (empty for discovery, the discovery result when seeding enrichment)
/// and applies `overrides` (when given) to every emitted device.
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
/// * PortMapping events are stored (at most [`MAX_AGGREGATE_MAPPINGS`], duplicates dropped)
///   and forwarded; every device with that MAC gets its `switchPort` re-evaluated with
///   [`Aggregate::best_port_mapping`]. When the input ends, a final pass re-evaluates every
///   device, so the result does not depend on event order.
/// * Progress events get the current device count.
async fn aggregate(
    mut state: Aggregate,
    overrides: Option<Overrides>,
    fold_ipv6: bool,
    mut rx: Receiver<ScanEvent>,
    out: Sender<ScanEvent>,
) -> Aggregate {
    let overrides = overrides.as_ref();
    state.reindex();
    let mut pending_v6: HashMap<String, Device> = HashMap::new();
    // MAC-only observations (DHCP clients without an address) not yet matched to a row.
    let mut pending_mac: HashMap<String, Device> = HashMap::new();

    while let Some(ev) = rx.recv().await {
        match ev {
            ScanEvent::Device(d) => {
                let d = *d;
                if d.ip.is_unspecified() {
                    let changed = state.apply_by_mac(&d);
                    if changed.is_empty() {
                        if let Some(mac) = d.mac.as_ref().and_then(|m| normalize_mac(m)) {
                            if pending_mac.len() < MAX_PENDING_MAC_ONLY
                                || pending_mac.contains_key(&mac)
                            {
                                pending_mac
                                    .entry(mac)
                                    .and_modify(|e| e.merge(&d))
                                    .or_insert(d);
                            }
                        }
                    }
                    for key in changed {
                        let dev = state.devices[&key].clone();
                        send_device(&out, overrides, &dev).await;
                    }
                    continue;
                }
                if fold_ipv6 && d.ip.is_ipv6() {
                    pending_v6
                        .entry(d.key())
                        .and_modify(|e| e.merge(&d))
                        .or_insert(d);
                    continue;
                }
                let key = state.upsert_device(d);
                let dev = state.devices[&key].clone();
                send_device(&out, overrides, &dev).await;
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
                        send_device(&out, overrides, &dev).await;
                    }
                }
            }
            ScanEvent::PortMapping(pm) => {
                let mac = match state.add_port_mapping(&pm) {
                    MappingUpdate::Stored(mac) => mac,
                    MappingUpdate::Duplicate | MappingUpdate::OverLimit { first: false } => {
                        continue
                    }
                    MappingUpdate::OverLimit { first: true } => {
                        let _ = out
                            .send(ScanEvent::warn(format!(
                                "more than {MAX_AGGREGATE_MAPPINGS} SNMP MAC-to-port entries; \
                                 ignoring further entries"
                            )))
                            .await;
                        continue;
                    }
                };
                // Provisional: re-evaluate the devices with this MAC now (the final pass
                // settles the choice once every switch has answered).
                for key in state.reassign_mac(&mac) {
                    let dev = state.devices[&key].clone();
                    send_device(&out, overrides, &dev).await;
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

    // Order-independent switch-port assignment: port MAC counts and device roles are final.
    for key in state.reassign_all() {
        let dev = state.devices[&key].clone();
        send_device(&out, overrides, &dev).await;
    }

    // MAC-only observations whose device appeared after them.
    let mut unmatched: Vec<String> = Vec::new();
    let mut pending: Vec<(String, Device)> = pending_mac.into_iter().collect();
    pending.sort_by(|a, b| a.0.cmp(&b.0));
    for (mac, obs) in pending {
        let changed = state.apply_by_mac(&obs);
        if changed.is_empty() {
            let os = obs
                .dhcp_fingerprint
                .as_ref()
                .and_then(|f| f.os.clone())
                .unwrap_or_else(|| "unknown OS".into());
            unmatched.push(format!("{mac} ({os})"));
        }
        for key in changed {
            let dev = state.devices[&key].clone();
            send_device(&out, overrides, &dev).await;
        }
    }
    if !unmatched.is_empty() {
        let shown = unmatched.len().min(10);
        let _ = out
            .send(ScanEvent::info(format!(
                "DHCP: {} client(s) fingerprinted with no address and no discovered row: {}{}",
                unmatched.len(),
                unmatched[..shown].join(", "),
                if unmatched.len() > shown { ", ..." } else { "" }
            )))
            .await;
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
        send_device(&out, overrides, &dev).await;
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
/// device (the CLI behaviour; see [`run_scan_with`]).
pub async fn run_scan(
    cfg: ScanConfig,
    tx: Sender<ScanEvent>,
    cancel: CancellationToken,
) -> Result<ScanSummary> {
    run_scan_with(cfg, ScanOptions::default(), tx, cancel).await
}

/// [`run_scan`] with explicit [`ScanOptions`] (the GUI passes `apply_overrides: false`).
pub async fn run_scan_with(
    cfg: ScanConfig,
    opts: ScanOptions,
    tx: Sender<ScanEvent>,
    cancel: CancellationToken,
) -> Result<ScanSummary> {
    let started = Instant::now();
    cfg.validate()?;
    let overrides: Option<Overrides> = opts
        .apply_overrides
        .then(|| Arc::new(enricher::load_overrides()));
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
    // Passive DHCP fingerprinting over the same window (opt-in: needs raw capture). Clients
    // outside the scan targets are attributed by MAC only, so a fingerprint never creates an
    // out-of-scope row (which enrichment would then actively probe).
    let dhcp_sniffer = cfg.dhcp_fingerprint.then(|| {
        let (dtx, drx) = mpsc::channel(EVENT_BUFFER);
        let relay = tokio::spawn(scope_dhcp_rows(drx, itx.clone(), targets.clone()));
        let (cancel, name) = (cancel.child_token(), iface.name.clone());
        let own = arp_vlan::local_macs(&all);
        let duration = Duration::from_secs(cfg.listen_secs.max(1));
        let sniffer = tokio::spawn(async move {
            dhcp_fp::run_dhcp_fingerprint(&name, own, duration, dtx, cancel).await
        });
        (sniffer, relay)
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
    if let Some((handle, relay)) = dhcp_sniffer {
        if !cancel.is_cancelled() {
            let _ = itx
                .send(progress(ScanPhase::Listening, Some(&counter)))
                .await;
        }
        let res = handle.await;
        let _ = relay.await;
        report_dhcp_result(res, &itx).await;
    }

    drop(itx);
    let state = aggregator.await.context("event aggregator crashed")?;

    // Enrichment phase: DNS/mDNS/NetBIOS names, TCP ports, OUI vendors and SNMP infrastructure
    // polling with endpoint-to-switch-port mapping. Seeds a second aggregator with the
    // discovery result so updates upsert onto the existing rows.
    let state = run_enrichment(state, &cfg, &iface, &counter, overrides, &tx, &cancel).await?;

    let gateway = tokio::task::spawn_blocking(arp_vlan::default_gateway_v4)
        .await
        .ok()
        .flatten()
        .map(IpAddr::V4);
    let summary = ScanSummary {
        devices: state.devices.len() as u64,
        vlans: state.vlans.len() as u64,
        neighbors: state.neighbors.len() as u64,
        elapsed_ms: elapsed_ms(started),
        cancelled: cancel.is_cancelled(),
        interface: Some(iface.name.clone()),
        gateway,
        scanner_host: crate::models::local_hostname(),
        failed: false,
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

/// Forward DHCP fingerprint rows, turning clients whose address lies outside `targets` into
/// MAC-only observations (attached to an existing row by MAC, never creating one).
async fn scope_dhcp_rows(
    mut rx: Receiver<ScanEvent>,
    out: Sender<ScanEvent>,
    targets: Vec<Ipv4Range>,
) {
    while let Some(ev) = rx.recv().await {
        let ev = match ev {
            ScanEvent::Device(mut d) => {
                if !dhcp_ip_in_scope(d.ip, &targets) {
                    if d.dhcp_server == Some(true) {
                        let _ = out
                            .send(ScanEvent::info(format!(
                                "DHCP server {} answered (outside the scan targets{})",
                                d.ip,
                                d.mac
                                    .as_deref()
                                    .map(|m| format!(", MAC {m}"))
                                    .unwrap_or_default()
                            )))
                            .await;
                    }
                    d.ip = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
                }
                ScanEvent::Device(d)
            }
            other => other,
        };
        if out.send(ev).await.is_err() {
            break;
        }
    }
}

/// `true` for an address a DHCP fingerprint may key a row on: inside one of the targets.
fn dhcp_ip_in_scope(ip: IpAddr, targets: &[Ipv4Range]) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_unspecified() && targets.iter().any(|t| t.contains(v4)),
        IpAddr::V6(_) => false,
    }
}

/// Log how the DHCP fingerprint capture ended (count, or why it could not run).
async fn report_dhcp_result(
    res: std::result::Result<Result<u64>, tokio::task::JoinError>,
    tx: &Sender<ScanEvent>,
) {
    let ev = match res {
        Ok(Ok(n)) => ScanEvent::info(format!(
            "DHCP fingerprinting: {n} client fingerprint(s) observed (best-effort heuristics)"
        )),
        Ok(Err(e)) => ScanEvent::warn(format!("DHCP fingerprinting unavailable: {e:#}")),
        Err(e) => ScanEvent::error(format!("DHCP fingerprinting crashed: {e}")),
    };
    let _ = tx.send(ev).await;
}

/// One log line for a DHCP fingerprint that has no IP to key a device row on.
fn dhcp_log_line(d: &Device) -> String {
    let fp = d.dhcp_fingerprint.clone().unwrap_or_default();
    format!(
        "DHCP client {}{}: {} ({} confidence){}{}",
        d.mac.as_deref().unwrap_or("?"),
        d.vlan_id
            .map(|v| format!(" on VLAN {v}"))
            .unwrap_or_default(),
        fp.os.as_deref().unwrap_or("unknown OS"),
        fp.confidence.as_deref().unwrap_or("no"),
        fp.vendor_class
            .as_deref()
            .map(|v| format!(", vendor class '{v}'"))
            .unwrap_or_default(),
        fp.hostname
            .as_deref()
            .map(|h| format!(", hostname '{h}'"))
            .unwrap_or_default(),
    )
}

/// TCP ports whose presence marks a likely managed network device (SSH, Telnet, HTTP(S),
/// MikroTik Winbox) when choosing SNMP poll candidates.
pub const SNMP_HINT_PORTS: &[u16] = &[22, 23, 80, 443, 8291];

/// SNMP poll candidates among the discovered `devices`, most likely infrastructure first.
///
/// Only discovered hosts are ever polled (never addresses outside what the user scanned).
/// Unless `all` is set, only those with some sign of being network gear are kept: the
/// default gateway, CDP/LLDP neighbors (by management address or match), devices already
/// classified as infrastructure, devices whose MAC belongs to a network-equipment vendor,
/// and devices with a management port ([`SNMP_HINT_PORTS`]) open. With `all`, every
/// device's primary IP is polled, still in that priority order. De-duplicated and
/// deterministic.
pub fn snmp_candidates(
    devices: &[Device],
    neighbor_addrs: &[IpAddr],
    gateway: Option<IpAddr>,
    all: bool,
) -> Vec<IpAddr> {
    // Lower rank = polled earlier.
    let mut ranked: BTreeMap<IpAddr, u8> = BTreeMap::new();
    for d in devices {
        let addrs = || std::iter::once(&d.ip).chain(&d.extra_ips);
        let rank = if addrs().any(|ip| Some(*ip) == gateway || neighbor_addrs.contains(ip)) {
            0
        } else if d.role.is_infrastructure() || d.neighbor.is_some() {
            1
        } else if d.vendor.as_deref().is_some_and(enricher::is_network_vendor) {
            2
        } else if d.open_ports.iter().any(|p| SNMP_HINT_PORTS.contains(p)) {
            3
        } else if all {
            4
        } else {
            continue;
        };
        ranked
            .entry(d.ip)
            .and_modify(|r| *r = (*r).min(rank))
            .or_insert(rank);
    }
    let mut out: Vec<(u8, IpAddr)> = ranked.into_iter().map(|(ip, r)| (r, ip)).collect();
    out.sort();
    out.into_iter().map(|(_, ip)| ip).collect()
}

/// Run the enrichment phase on the discovery result and return the enriched state.
///
/// Enrichment runs when name resolution, port scanning or SNMP is requested, in steps,
/// each through an aggregator seeded with the state so far so every update (sparse device
/// snapshots, SNMP VLANs / port mappings / role) upserts onto the existing rows and streams
/// the merged result to `tx`:
///
/// 1. names, vendors and TCP ports ([`enricher::enrich_devices`]);
/// 2. with `webIdentity`, the HTTP title / `Server` header / TLS certificate of devices
///    with a web port open ([`webid::enrich_web`]; its role hints only apply to devices
///    still classified as plain hosts);
/// 3. SNMP polling of the candidates chosen by [`snmp_candidates`] from the enriched state
///    (open ports and vendors are known by then).
///
/// Returns `state` unchanged when there is nothing to do or the scan was cancelled before
/// enrichment began.
async fn run_enrichment(
    state: Aggregate,
    cfg: &ScanConfig,
    iface: &InterfaceInfo,
    counter: &ProgressCounter,
    overrides: Option<Overrides>,
    tx: &Sender<ScanEvent>,
    cancel: &CancellationToken,
) -> Result<Aggregate> {
    let wants_snmp = cfg.snmp.is_some();
    let wants_enrich = cfg.resolve_names || !cfg.ports.is_empty();
    // Web identity needs the port scan (it only probes web ports found open).
    let wants_web = cfg.web_identity && !cfg.ports.is_empty();
    let wants_services = cfg.discover_services;
    let devices = state.sorted_devices();
    if cancel.is_cancelled()
        || devices.is_empty()
        || !(wants_snmp || wants_enrich || wants_services)
    {
        return Ok(state);
    }

    // Progress budgets reserved up front so the total never moves: one unit per device for
    // enrichment, and one per *possible* SNMP candidate (unused units are counted when the
    // candidates are chosen).
    let neighbor_addrs: Vec<IpAddr> = state
        .neighbors
        .values()
        .flat_map(|n| n.management_addrs.iter().copied())
        .collect();
    let snmp_upper = if wants_snmp {
        devices.iter().map(|d| d.ip).collect::<BTreeSet<_>>().len() as u64
    } else {
        0
    };
    let enrich_scope = counter.scope(if wants_enrich {
        devices.len() as u64
    } else {
        0
    });
    let web_scope = counter.scope(if wants_web { devices.len() as u64 } else { 0 });
    let services_scope = counter.scope(if wants_services {
        devices.len() as u64
    } else {
        0
    });
    let snmp_scope = counter.scope(snmp_upper);

    // Periodic progress while enrichment runs (sent straight to the output: progress events
    // carry no device data, and `devices_found` does not change during enrichment).
    let ticker_stop = CancellationToken::new();
    let ticker = {
        let (out, counter, stop) = (tx.clone(), counter.clone(), ticker_stop.clone());
        let found = devices.len() as u64;
        tokio::spawn(async move {
            let mut every = tokio::time::interval(PROGRESS_INTERVAL);
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = every.tick() => {
                        let (sent, total) = counter.snapshot();
                        let _ = out.try_send(ScanEvent::Progress(ScanProgress {
                            phase: ScanPhase::Enriching,
                            probes_sent: sent,
                            probes_total: total,
                            devices_found: found,
                        }));
                    }
                }
            }
        })
    };

    // Step 1: names, vendors, ports.
    let mut state = state;
    if wants_enrich {
        let (etx, erx) = mpsc::channel(EVENT_BUFFER);
        let aggregator = tokio::spawn(aggregate(state, overrides.clone(), false, erx, tx.clone()));
        let _ = etx
            .send(progress(ScanPhase::Enriching, Some(counter)))
            .await;
        enricher::enrich_devices(
            devices.clone(),
            cfg,
            etx.clone(),
            cancel.clone(),
            enrich_scope.clone(),
        )
        .await;
        drop(etx);
        state = aggregator.await.context("enrichment aggregator crashed")?;
    }
    enrich_scope.finish();

    // Step 2: HTTP title / Server header / TLS certificate of devices with web ports open.
    if wants_web && !cancel.is_cancelled() {
        let enriched = state.sorted_devices();
        let web_devices = enriched
            .iter()
            .filter(|d| {
                d.open_ports
                    .iter()
                    .any(|p| webid::DEFAULT_WEB_PORTS.contains(p))
            })
            .count();
        let (wtx, wrx) = mpsc::channel(EVENT_BUFFER);
        let aggregator = tokio::spawn(aggregate(state, overrides.clone(), false, wrx, tx.clone()));
        if web_devices > 0 {
            let _ = wtx
                .send(ScanEvent::info(format!(
                    "web identity: reading titles and TLS certificates of {web_devices} \
                     device(s) with web ports open"
                )))
                .await;
        }
        let timeout = Duration::from_millis(cfg.timeout_ms.clamp(1_000, 5_000));
        webid::enrich_web(
            enriched,
            webid::DEFAULT_WEB_PORTS,
            timeout,
            wtx.clone(),
            cancel.clone(),
            web_scope.clone(),
            SocketBudget::global(),
        )
        .await;
        drop(wtx);
        state = aggregator
            .await
            .context("web identity aggregator crashed")?;
    }
    web_scope.finish();

    // Step 3: service discovery (SSDP/UPnP, WS-Discovery/ONVIF, SIP OPTIONS). Runs on the
    // enriched devices so open ports (5060) and vendors pick the SIP candidates.
    if wants_services && !cancel.is_cancelled() {
        let enriched = state.sorted_devices();
        let (stx, srx) = mpsc::channel(EVENT_BUFFER);
        let aggregator = tokio::spawn(aggregate(state, overrides.clone(), false, srx, tx.clone()));
        let local_v4 = iface.primary_ipv4().map(|(ip, _)| ip);
        let v6_index = (cfg.ipv6 && iface.link_local_v6().is_some()).then_some(iface.index);
        services::enrich_services(
            enriched,
            cfg,
            local_v4,
            v6_index,
            stx.clone(),
            cancel.clone(),
            services_scope.clone(),
        )
        .await;
        drop(stx);
        state = aggregator.await.context("service aggregator crashed")?;
    }
    services_scope.finish();

    // Step 4: SNMP infrastructure polling.
    if let (Some(snmp), false) = (&cfg.snmp, cancel.is_cancelled()) {
        let gateway = if cfg.snmp_all {
            None
        } else {
            tokio::task::spawn_blocking(arp_vlan::default_gateway_v4)
                .await
                .ok()
                .flatten()
                .map(IpAddr::V4)
        };
        let enriched = state.sorted_devices();
        let candidates = snmp_candidates(&enriched, &neighbor_addrs, gateway, cfg.snmp_all);
        snmp_scope.add(snmp_upper.saturating_sub(candidates.len() as u64));

        let (stx, srx) = mpsc::channel(EVENT_BUFFER);
        let aggregator = tokio::spawn(aggregate(state, overrides, false, srx, tx.clone()));
        let version = match snmp.version {
            crate::models::SnmpVersion::V1 => "v1",
            crate::models::SnmpVersion::V2c => "v2c",
            crate::models::SnmpVersion::V3 => "v3",
        };
        let note = if cfg.snmp_all {
            format!("all {} discovered host(s) (snmpAll)", candidates.len())
        } else {
            format!(
                "{} of {} discovered host(s) that look like infrastructure (gateway, CDP/LLDP \
                 neighbors, network-vendor MACs, management ports); enable \"poll all hosts\" \
                 / --snmp-all to poll every host",
                candidates.len(),
                enriched.len()
            )
        };
        let _ = stx
            .send(ScanEvent::info(format!("SNMP{version}: polling {note}")))
            .await;
        snmp_infra::probe_candidates(
            candidates,
            snmp,
            stx.clone(),
            cancel.clone(),
            snmp_scope.clone(),
        )
        .await;
        drop(stx);
        state = aggregator.await.context("SNMP aggregator crashed")?;
    }
    snmp_scope.finish();

    ticker_stop.cancel();
    let _ = ticker.await;
    let (sent, total) = counter.snapshot();
    let _ = tx
        .send(ScanEvent::Progress(ScanProgress {
            phase: ScanPhase::Enriching,
            probes_sent: sent,
            probes_total: total,
            devices_found: state.devices.len() as u64,
        }))
        .await;
    Ok(state)
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
    run_vlan_discovery_with(interface, timeout, false, tx, cancel).await
}

/// [`run_vlan_discovery`], optionally also fingerprinting DHCP clients (`dhcp`) for the same
/// window. Fingerprinted clients with an address stream as `device` events; clients without
/// one (a bare DISCOVER) are reported as log lines, since there is no row to key them on.
pub async fn run_vlan_discovery_with(
    interface: Option<&str>,
    timeout: Duration,
    dhcp: bool,
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
            "listening on {} for {} s (802.1Q tags, CDP, LLDP, VTP, DTP{})",
            iface.name,
            timeout.as_secs(),
            if dhcp { ", DHCP fingerprints" } else { "" }
        )))
        .await;
    let _ = tx.send(progress(ScanPhase::Listening, None)).await;

    // DHCP fingerprints go through a small relay: rows keyed by IP are forwarded, address-less
    // clients become log lines.
    let dhcp_job = dhcp.then(|| {
        let (dtx, mut drx) = mpsc::channel::<ScanEvent>(EVENT_BUFFER);
        let out = tx.clone();
        let relay = tokio::spawn(async move {
            let mut rows = 0u64;
            while let Some(ev) = drx.recv().await {
                let ev = match ev {
                    ScanEvent::Device(d) if d.ip.is_unspecified() => {
                        ScanEvent::info(dhcp_log_line(&d))
                    }
                    ScanEvent::Device(d) => {
                        rows += 1;
                        ScanEvent::Device(d)
                    }
                    other => other,
                };
                let _ = out.send(ev).await;
            }
            rows
        });
        let (name, own, cancel) = (
            iface.name.clone(),
            arp_vlan::local_macs(&all),
            cancel.clone(),
        );
        let sniffer = tokio::spawn(async move {
            dhcp_fp::run_dhcp_fingerprint(&name, own, timeout, dtx, cancel).await
        });
        (sniffer, relay)
    });

    let passive = arp_vlan::run_passive_sniffer(
        &iface.name,
        arp_vlan::local_macs(&all),
        timeout,
        tx.clone(),
        cancel.clone(),
    )
    .await;
    let mut dhcp_rows = 0;
    if let Some((sniffer, relay)) = dhcp_job {
        let res = sniffer.await;
        dhcp_rows = relay.await.unwrap_or(0);
        report_dhcp_result(res, &tx).await;
    }
    let mut res = passive?;
    for os in os_vlans {
        match res.vlans.iter_mut().find(|v| v.id == os.id) {
            Some(v) => v.merge(&os),
            None => res.vlans.push(os),
        }
    }
    res.vlans.sort_by_key(|v| v.id);

    let summary = ScanSummary {
        devices: dhcp_rows,
        vlans: res.vlans.len() as u64,
        neighbors: res.neighbors.len() as u64,
        elapsed_ms: elapsed_ms(started),
        cancelled: cancel.is_cancelled(),
        ..Default::default()
    };
    let _ = tx.send(progress(ScanPhase::Done, None)).await;
    let _ = tx.send(ScanEvent::Finished(summary)).await;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Capability, DeviceRole, IfAddr, InterfaceKind};

    fn test_overrides() -> Option<Overrides> {
        None
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
            poe_watts: None,
            poe_info: None,
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
            poe: None,
            voice_vlan: None,
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
        let ov = Arc::new(ov);
        let agg = tokio::spawn(aggregate(
            Aggregate::default(),
            Some(ov.clone()),
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

        // GUI mode (no overrides applied): the engine never writes the user's fields, so a
        // hostname the GUI later clears cannot come back from a device snapshot (M7).
        let (itx, irx) = mpsc::channel(64);
        let (otx, mut orx) = mpsc::channel(256);
        let agg = tokio::spawn(aggregate(Aggregate::default(), None, true, irx, otx));
        itx.send(ScanEvent::device(Device::new("10.0.0.7".parse().unwrap())))
            .await
            .unwrap();
        drop(itx);
        let state = agg.await.unwrap();
        assert!(state.devices["10.0.0.7"].hostname.is_none());
        assert!(drain(&mut orx).iter().all(|e| match e {
            ScanEvent::Device(d) => d.hostname.is_none() && d.comments.is_none(),
            _ => true,
        }));
        assert!(
            ScanOptions::default().apply_overrides,
            "the CLI default applies them"
        );
    }

    fn pm(switch: &str, port: &str, vlan: Option<u16>, mac: &str) -> SwitchPortMapping {
        SwitchPortMapping {
            switch_name: switch.into(),
            switch_ip: None,
            port_name: port.into(),
            port_index: None,
            vlan_id: vlan,
            mac: mac.into(),
            poe: None,
            voice_vlan: None,
        }
    }

    fn dev_with_mac(ip: &str, mac: &str, vlan: Option<u16>) -> Device {
        let mut d = Device::new(ip.parse().unwrap());
        d.mac = Some(mac.into());
        d.vlan_id = vlan;
        d
    }

    /// Run one aggregator over `events` and return the final state.
    async fn aggregate_all(events: Vec<ScanEvent>) -> Aggregate {
        let (itx, irx) = mpsc::channel(events.len().max(1));
        let (otx, mut orx) = mpsc::channel(1024);
        let sink = tokio::spawn(async move { while orx.recv().await.is_some() {} });
        let agg = tokio::spawn(aggregate(Aggregate::default(), None, false, irx, otx));
        for ev in events {
            itx.send(ev).await.unwrap();
        }
        drop(itx);
        let state = agg.await.unwrap();
        sink.await.unwrap();
        state
    }

    /// M1: a MAC learned on an access port and on an uplink (many MACs) maps to the access
    /// port, whatever order the switches answered in.
    #[tokio::test]
    async fn switch_port_ignores_uplinks_and_is_order_independent() {
        let endpoint = "aa:00:00:00:00:01";
        let mut uplink: Vec<ScanEvent> = (0..60)
            .map(|i| {
                ScanEvent::PortMapping(pm(
                    "core",
                    "Te1/1/1",
                    Some(10),
                    &format!("aa:00:00:00:01:{i:02x}"),
                ))
            })
            .collect();
        uplink.push(ScanEvent::PortMapping(pm(
            "core",
            "Te1/1/1",
            Some(10),
            endpoint,
        )));
        let access = vec![
            ScanEvent::PortMapping(pm("access-1", "Gi1/0/7", Some(10), endpoint)),
            ScanEvent::PortMapping(pm("access-1", "Gi1/0/8", Some(10), "aa:00:00:00:02:01")),
        ];
        let device = ScanEvent::device(dev_with_mac("10.0.0.5", endpoint, None));

        let orders: Vec<Vec<ScanEvent>> = vec![
            [vec![device.clone()], uplink.clone(), access.clone()].concat(),
            [vec![device.clone()], access.clone(), uplink.clone()].concat(),
            [access.clone(), uplink.clone(), vec![device.clone()]].concat(),
            [
                uplink.iter().rev().cloned().collect(),
                vec![device.clone()],
                access.clone(),
            ]
            .concat(),
        ];
        for events in orders {
            let state = aggregate_all(events).await;
            let sp = state.devices["10.0.0.5"].switch_port.clone().unwrap();
            assert_eq!(
                (sp.switch_name.as_str(), sp.port_name.as_str()),
                ("access-1", "Gi1/0/7")
            );
            // The full CAM view is kept.
            assert_eq!(state.port_mappings_by_mac[endpoint].len(), 2);
        }

        // Seen only on the uplink: no switch port at all (rather than a misleading uplink).
        let state = aggregate_all([vec![device.clone()], uplink.clone()].concat()).await;
        assert!(state.devices["10.0.0.5"].switch_port.is_none());
    }

    #[tokio::test]
    async fn switch_port_prefers_matching_vlan_then_fewest_macs() {
        let mac = "aa:00:00:00:00:02";
        let events = vec![
            ScanEvent::device(dev_with_mac("10.0.20.5", mac, Some(20))),
            ScanEvent::PortMapping(pm("sw-b", "Gi1/0/1", Some(10), mac)),
            ScanEvent::PortMapping(pm("sw-a", "Gi1/0/2", Some(20), mac)),
            // A busier port on the right VLAN loses to the quiet one on the same VLAN.
            ScanEvent::PortMapping(pm("sw-c", "Gi1/0/3", Some(20), mac)),
            ScanEvent::PortMapping(pm("sw-c", "Gi1/0/3", Some(20), "aa:00:00:00:09:01")),
        ];
        let state = aggregate_all(events).await;
        let sp = state.devices["10.0.20.5@20"].switch_port.clone().unwrap();
        assert_eq!(
            (sp.switch_name.as_str(), sp.port_name.as_str()),
            ("sw-a", "Gi1/0/2")
        );
        // Exact ties are broken by name, not arrival order.
        for (first, second) in [("sw-y", "sw-x"), ("sw-x", "sw-y")] {
            let state = aggregate_all(vec![
                ScanEvent::device(dev_with_mac("10.0.0.9", "aa:00:00:00:00:03", None)),
                ScanEvent::PortMapping(pm(first, "Gi1/0/1", None, "aa:00:00:00:00:03")),
                ScanEvent::PortMapping(pm(second, "Gi1/0/1", None, "aa:00:00:00:00:03")),
            ])
            .await;
            assert_eq!(
                state.devices["10.0.0.9"]
                    .switch_port
                    .as_ref()
                    .unwrap()
                    .switch_name,
                "sw-x"
            );
        }
    }

    #[tokio::test]
    async fn switch_port_skips_links_to_other_infrastructure() {
        // Port Gi1/0/48 of sw-a learns a downstream switch's MAC and an endpoint behind it.
        let downstream = "aa:00:00:00:00:10";
        let endpoint = "aa:00:00:00:00:11";
        let mut sw = dev_with_mac("10.0.0.2", downstream, None);
        sw.role = DeviceRole::Switch;
        let state = aggregate_all(vec![
            ScanEvent::device(sw),
            ScanEvent::device(dev_with_mac("10.0.0.50", endpoint, None)),
            ScanEvent::PortMapping(pm("sw-a", "Gi1/0/48", None, downstream)),
            ScanEvent::PortMapping(pm("sw-a", "Gi1/0/48", None, endpoint)),
        ])
        .await;
        // The downstream switch really is on that port; the endpoint is not.
        assert_eq!(
            state.devices["10.0.0.2"]
                .switch_port
                .as_ref()
                .unwrap()
                .port_name,
            "Gi1/0/48"
        );
        assert!(state.devices["10.0.0.50"].switch_port.is_none());
    }

    /// H1: the aggregator keeps at most MAX_AGGREGATE_MAPPINGS entries (a smaller limit here
    /// to keep the test light), drops duplicates and warns once.
    #[test]
    fn port_mapping_table_is_capped() {
        const LIMIT: usize = 2_000;
        assert_eq!(MAX_AGGREGATE_MAPPINGS, 200_000);
        let mut state = Aggregate {
            mapping_limit: Some(LIMIT),
            ..Aggregate::default()
        };
        let mac = |i: usize| {
            format!(
                "02:{:02x}:{:02x}:{:02x}:00:01",
                (i >> 16) & 0xff,
                (i >> 8) & 0xff,
                i & 0xff
            )
        };
        assert!(matches!(
            state.add_port_mapping(&pm("sw", "Gi1/0/1", None, &mac(0))),
            MappingUpdate::Stored(_)
        ));
        assert_eq!(
            state.add_port_mapping(&pm("sw", "Gi1/0/1", None, &mac(0).to_uppercase())),
            MappingUpdate::Duplicate
        );
        for i in 1..LIMIT {
            state.add_port_mapping(&pm("sw", "Gi1/0/1", None, &mac(i)));
        }
        assert_eq!(state.port_mapping_count(), LIMIT);
        assert_eq!(
            state.add_port_mapping(&pm("sw", "Gi1/0/2", None, &mac(1))),
            MappingUpdate::OverLimit { first: true }
        );
        assert_eq!(
            state.add_port_mapping(&pm("sw", "Gi1/0/3", None, &mac(2))),
            MappingUpdate::OverLimit { first: false }
        );
        assert_eq!(state.port_mapping_count(), LIMIT);
    }

    #[test]
    fn snmp_candidates_prefer_infrastructure() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let dev = |s: &str| Device::new(ip(s));
        let gw = dev("10.0.0.1");
        let mut mgmt = dev("10.0.0.9");
        mgmt.extra_ips.push(ip("10.9.9.9")); // neighbor management address on a second IP
        let mut sw = dev("10.0.0.2");
        sw.role = DeviceRole::Switch;
        let mut cisco = dev("10.0.0.3");
        cisco.vendor = Some("Cisco Systems, Inc".into());
        let mut ssh = dev("10.0.0.4");
        ssh.open_ports = vec![22];
        let mut laptop = dev("10.0.0.5");
        laptop.vendor = Some("Apple, Inc.".into());
        laptop.open_ports = vec![5000];
        let printer = dev("10.0.0.6");
        let devices = vec![laptop, printer, ssh, cisco, sw, mgmt, gw];
        let picked = snmp_candidates(&devices, &[ip("10.9.9.9")], Some(ip("10.0.0.1")), false);
        assert_eq!(
            picked,
            vec![
                ip("10.0.0.1"),
                ip("10.0.0.9"),
                ip("10.0.0.2"),
                ip("10.0.0.3"),
                ip("10.0.0.4")
            ]
        );
        // snmpAll adds every other discovered host, still infrastructure first.
        let all = snmp_candidates(&devices, &[ip("10.9.9.9")], Some(ip("10.0.0.1")), true);
        assert_eq!(all.len(), 7);
        assert_eq!(&all[..5], &picked[..]);
        // The gateway / neighbor addresses are never polled unless they were discovered.
        let outside = snmp_candidates(
            &[dev("10.0.0.5")],
            &[ip("192.0.2.9")],
            Some(ip("192.0.2.1")),
            false,
        );
        assert!(outside.is_empty());
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

    fn dhcp_obs(mac: &str, os: &str) -> Device {
        let mut d = Device::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        d.mac = Some(mac.into());
        d.dhcp_fingerprint = Some(crate::models::DhcpFingerprint {
            os: Some(os.into()),
            confidence: Some("high".into()),
            ..Default::default()
        });
        d.add_source(DiscoverySource::Dhcp);
        d
    }

    /// A DHCP client fingerprinted before it had an address is attributed to its row by MAC,
    /// whether the row appears before or after the observation; no `0.0.0.0` row is created.
    #[tokio::test]
    async fn mac_only_dhcp_observations_attach_by_mac() {
        let mac = "aa:00:00:00:00:21";
        for obs_first in [true, false] {
            let row = ScanEvent::device(dev_with_mac("10.0.0.21", mac, None));
            let obs = ScanEvent::device(dhcp_obs("AA:00:00:00:00:21", "Windows"));
            let events = if obs_first {
                vec![obs, row]
            } else {
                vec![row, obs]
            };
            let state = aggregate_all(events).await;
            assert_eq!(state.devices.len(), 1, "no 0.0.0.0 row");
            let d = &state.devices["10.0.0.21"];
            assert_eq!(
                d.dhcp_fingerprint.as_ref().unwrap().os.as_deref(),
                Some("Windows")
            );
            assert!(d.extra_ips.is_empty(), "the unspecified IP is not kept");
            assert!(d.sources.contains(&DiscoverySource::Dhcp));
        }
        // No matching row at all: nothing is created (only a log line).
        let state = aggregate_all(vec![ScanEvent::device(dhcp_obs(mac, "iOS"))]).await;
        assert!(state.devices.is_empty());
    }

    /// DHCP fingerprints for addresses outside the scan targets never create rows (review M2).
    #[tokio::test]
    async fn out_of_scope_dhcp_rows_become_mac_only() {
        let (itx, irx) = mpsc::channel(8);
        let (otx, mut orx) = mpsc::channel(8);
        let targets = vec![Ipv4Range::from_cidr("10.0.0.0".parse().unwrap(), 24).unwrap()];
        let relay = tokio::spawn(scope_dhcp_rows(irx, otx, targets));
        let mut inside = dhcp_obs("aa:00:00:00:00:51", "Windows");
        inside.ip = "10.0.0.51".parse().unwrap();
        let mut outside = dhcp_obs("aa:00:00:00:00:52", "Windows");
        outside.ip = "192.168.50.52".parse().unwrap();
        itx.send(ScanEvent::device(inside)).await.unwrap();
        itx.send(ScanEvent::device(outside)).await.unwrap();
        drop(itx);
        relay.await.unwrap();
        let mut ips = Vec::new();
        while let Some(ScanEvent::Device(d)) = orx.recv().await {
            ips.push(d.ip.to_string());
        }
        assert_eq!(ips, vec!["10.0.0.51", "0.0.0.0"]);
        // The MAC-only observation creates no row of its own.
        let mut outside = dhcp_obs("aa:00:00:00:00:52", "Windows");
        outside.ip = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
        let state = aggregate_all(vec![ScanEvent::device(outside)]).await;
        assert!(state.devices.is_empty());
    }

    /// The chosen access port's SNMP PoE and voice VLAN describe the endpoint on it.
    #[tokio::test]
    async fn switch_port_poe_and_voice_vlan_reach_the_endpoint() {
        let mac = "aa:00:00:00:00:31";
        let mut access = pm("access-1", "Gi1/0/5", Some(20), mac);
        access.poe = Some(crate::models::PoeInfo {
            watts: Some(6.5),
            class: Some(2),
            status: Some("delivering".into()),
            switch_name: Some("access-1".into()),
            port: Some("Gi1/0/5".into()),
            ..Default::default()
        });
        access.voice_vlan = Some(120);
        let state = aggregate_all(vec![
            ScanEvent::device(dev_with_mac("10.0.20.31", mac, Some(20))),
            ScanEvent::PortMapping(access),
        ])
        .await;
        let d = &state.devices["10.0.20.31@20"];
        assert_eq!(d.poe.as_ref().unwrap().watts, Some(6.5));
        assert_eq!(d.poe.as_ref().unwrap().port.as_deref(), Some("Gi1/0/5"));
        assert_eq!(d.voice_vlan, Some(120));
    }

    /// An IP phone's own LLDP-MED advert gives it a voice VLAN and PoE draw; a switch's advert
    /// (which describes our port) is not copied onto the switch row.
    #[test]
    fn neighbor_voice_vlan_and_poe_only_for_endpoints() {
        let mut phone_adv = switch_neighbor("aa:00:00:00:00:41", "10.0.0.41");
        phone_adv.capabilities = vec![Capability::Telephone];
        phone_adv.voice_vlan = Some(110);
        phone_adv.poe_watts = Some(5.1);
        phone_adv.poe_info = Some(Box::new(crate::models::PoeInfo {
            watts: Some(5.1),
            ..Default::default()
        }));
        let mut phone = dev_with_mac("10.0.0.41", "aa:00:00:00:00:41", None);
        assert!(apply_neighbor(&mut phone, &phone_adv));
        assert_eq!(phone.voice_vlan, Some(110));
        assert_eq!(phone.poe.as_ref().unwrap().watts, Some(5.1));

        let mut sw_adv = switch_neighbor("aa:00:00:00:00:42", "10.0.0.42");
        sw_adv.voice_vlan = Some(110);
        sw_adv.poe_info = phone_adv.poe_info.clone();
        let mut sw = dev_with_mac("10.0.0.42", "aa:00:00:00:00:42", None);
        assert!(apply_neighbor(&mut sw, &sw_adv));
        assert_eq!(sw.role, DeviceRole::Switch);
        assert!(sw.voice_vlan.is_none() && sw.poe.is_none());
    }

    fn poe(watts: f32, switch: &str, port: &str) -> crate::models::PoeInfo {
        crate::models::PoeInfo {
            watts: Some(watts),
            status: Some("delivering".into()),
            switch_name: Some(switch.into()),
            port: Some(port.into()),
            ..Default::default()
        }
    }

    /// PoE / voice VLAN from a provisional switch-port choice must not stay on the device
    /// after the choice moves to a port without PoE data (review M7).
    #[tokio::test]
    async fn stale_poe_cleared_after_port_change() {
        let mac = "aa:00:00:00:00:31";
        let mut first = pm("acc-a", "Gi1/0/5", Some(20), mac);
        first.poe = Some(poe(6.5, "acc-a", "Gi1/0/5"));
        first.voice_vlan = Some(120);
        let mut events = vec![
            ScanEvent::device(dev_with_mac("10.0.20.31", mac, Some(20))),
            ScanEvent::PortMapping(first),
        ];
        // acc-a Gi1/0/5 turns out to be an uplink (60 MACs).
        for i in 0..60 {
            events.push(ScanEvent::PortMapping(pm(
                "acc-a",
                "Gi1/0/5",
                Some(20),
                &format!("bb:00:00:00:00:{i:02x}"),
            )));
        }
        // The real access port (on a switch without PoE data).
        events.push(ScanEvent::PortMapping(pm(
            "acc-b",
            "Gi1/0/9",
            Some(20),
            mac,
        )));
        let state = aggregate_all(events).await;
        let d = &state.devices["10.0.20.31@20"];
        assert_eq!(d.switch_port.as_ref().unwrap().switch_name, "acc-b");
        assert!(d.poe.is_none(), "stale PoE from acc-a Gi1/0/5: {:?}", d.poe);
        assert!(
            d.voice_vlan.is_none(),
            "stale voice VLAN: {:?}",
            d.voice_vlan
        );
    }

    fn tlv(t: u16, v: &[u8]) -> Vec<u8> {
        let mut out = ((t << 9) | v.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(v);
        out
    }

    /// An IP phone advertising LLDP capabilities Bridge + Telephone (phones with a PC port)
    /// is an endpoint: it keeps its voice VLAN and PoE (review M8).
    #[test]
    fn lldp_phone_with_bridge_capability_is_an_endpoint() {
        let src = [0xaa, 0, 0, 0, 0, 0x51];
        let mut f = vec![0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e];
        f.extend_from_slice(&src);
        f.extend_from_slice(&0x88ccu16.to_be_bytes());
        let mut chassis = vec![4];
        chassis.extend_from_slice(&src);
        f.extend(tlv(1, &chassis));
        f.extend(tlv(2, b"\x07LAN"));
        f.extend(tlv(3, &120u16.to_be_bytes()));
        f.extend(tlv(5, b"SEP00AA00000051"));
        f.extend(tlv(6, b"Cisco IP Phone CP-8865"));
        // System capabilities Bridge|Telephone, enabled Bridge|Telephone.
        f.extend(tlv(7, &[0x00, 0x24, 0x00, 0x24]));
        // LLDP-MED network policy: voice, tagged, VLAN 110, priority 5, DSCP 46.
        let bits: u32 = (1 << 22) | (110 << 9) | (5 << 6) | 46;
        let b = bits.to_be_bytes();
        f.extend(tlv(127, &[0x00, 0x12, 0xbb, 2, 1, b[1], b[2], b[3]]));
        // LLDP-MED extended power: PD, source PSE, priority high, 6.3 W.
        f.extend(tlv(127, &[0x00, 0x12, 0xbb, 4, 0x52, 0x00, 63]));
        f.extend(tlv(0, &[]));
        let n = arp_vlan::parse_lldp(&f, "en0").unwrap();
        assert!(n.capabilities.contains(&Capability::Telephone));
        assert_eq!(n.infer_role(), DeviceRole::Host);
        let mut phone = dev_with_mac("10.0.0.51", "aa:00:00:00:00:51", None);
        apply_neighbor(&mut phone, &n);
        assert_eq!(phone.role, DeviceRole::Host);
        assert_eq!(phone.voice_vlan, Some(110), "phone voice VLAN dropped");
        assert!(phone.poe.is_some(), "phone PoE dropped");
    }

    /// A PC daisy-chained behind a phone shares the phone's switch port: only the phone gets
    /// the port's PoE and voice VLAN, never both (review LOW, engine/models).
    #[tokio::test]
    async fn pc_behind_phone_does_not_get_phone_poe() {
        let port_poe = poe(6.1, "acc", "Gi1/0/7");
        let mut events = Vec::new();
        for (ip, mac, vlan) in [
            ("10.0.110.7", "aa:00:00:00:00:07", 110u16),
            ("10.0.10.7", "bb:00:00:00:00:07", 10),
        ] {
            events.push(ScanEvent::device(dev_with_mac(ip, mac, Some(vlan))));
            let mut m = pm("acc", "Gi1/0/7", Some(vlan), mac);
            m.port_index = Some(10007);
            m.poe = Some(port_poe.clone());
            m.voice_vlan = Some(110);
            events.push(ScanEvent::PortMapping(m));
        }
        let st = aggregate_all(events).await;
        let pc = &st.devices["10.0.10.7@10"];
        let phone = &st.devices["10.0.110.7@110"];
        assert!(pc.poe.is_none(), "PC got the phone's PoE: {:?}", pc.poe);
        assert!(pc.voice_vlan.is_none(), "PC got the voice VLAN");
        assert_eq!(phone.poe.as_ref().and_then(|p| p.watts), Some(6.1));
        assert_eq!(phone.voice_vlan, Some(110));
        // Both still map to the shared port.
        assert_eq!(pc.switch_port.as_ref().unwrap().port_name, "Gi1/0/7");
    }
}
