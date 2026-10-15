//! Service-discovery enrichment: SSDP/UPnP, WS-Discovery/ONVIF and SIP OPTIONS.
//!
//! Runs once per scan after names / ports are known ([`enrich_services`]): the two multicast
//! discoveries (IPv4, plus IPv6 when the scan has `ipv6`) and the SIP OPTIONS probes of the
//! candidates run concurrently, then every *discovered* device whose address answered gets a
//! sparse update carrying `ssdp` / `onvif` / `sip` and a `deviceKind`. Responders that were not
//! discovered by the scan are not added (the same policy as SNMP polling).
//!
//! [`probe_host`] is the single-device variant behind the GUI `discover_services` command
//! (unicast SSDP / WS-Discovery to the host, plus SIP OPTIONS).

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use futures::StreamExt;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;

use crate::{
    limits::SocketBudget,
    models::{
        Capability, Device, DiscoverySource, OnvifInfo, ScanConfig, ScanEvent, ServiceDiscovery,
        SipInfo, SsdpInfo,
    },
    progress::ProgressScope,
    sip, ssdp, wsd,
};

/// TCP ports that mark a SIP endpoint as a probe candidate (5060 SIP, 5061 SIP-TLS).
pub const SIP_HINT_PORTS: &[u16] = &[5060, 5061];
/// SIP OPTIONS probes in flight at once (each also holds global socket permits).
const SIP_CONCURRENCY: usize = 32;

/// Listen window of the multicast discoveries for a scan timeout (SSDP replies are spread over
/// the `MX` = 2 s window, so never shorter than 2.5 s).
pub fn discovery_window(timeout_ms: u64) -> Duration {
    Duration::from_millis(timeout_ms.clamp(2_500, 5_000))
}

/// Per-host SIP OPTIONS timeout for a scan timeout.
pub fn sip_timeout(timeout_ms: u64) -> Duration {
    Duration::from_millis(timeout_ms.clamp(300, 1_500))
}

/// Hosts worth a SIP OPTIONS probe: TCP 5060/5061 open, a VoIP-maker OUI, a CDP/LLDP neighbor
/// that advertises the Telephone capability — or every IPv4 host with `all`. Sorted and
/// de-duplicated; only discovered hosts are ever probed.
pub fn sip_candidates(devices: &[Device], all: bool) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = devices
        .iter()
        .filter(|d| d.ip.is_ipv4())
        .filter(|d| {
            all || d.open_ports.iter().any(|p| SIP_HINT_PORTS.contains(p))
                || d.vendor.as_deref().is_some_and(sip::is_voip_vendor)
                || d.neighbor
                    .as_ref()
                    .is_some_and(|n| n.capabilities.contains(&Capability::Telephone))
        })
        .map(|d| d.ip)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The `deviceKind` implied by service data, most specific first: SIP (PBX / phone), an
/// ONVIF camera, the SSDP description, a WSD-answering computer.
pub fn device_kind(
    ssdp: Option<&SsdpInfo>,
    onvif: Option<&OnvifInfo>,
    sip: Option<&SipInfo>,
) -> Option<String> {
    if let Some(kind) = sip.and_then(|s| s.kind.clone()) {
        return Some(kind);
    }
    if onvif.is_some_and(|o| o.is_camera) {
        return Some("camera".to_string());
    }
    if let Some(kind) = ssdp.and_then(ssdp::classify_ssdp_kind) {
        return Some(kind);
    }
    if onvif.is_some_and(|o| o.is_windows) {
        return Some("computer".to_string());
    }
    None
}

/// Run SSDP + WS-Discovery (multicast) and SIP OPTIONS (candidates) and stream one sparse
/// [`Device`] update per discovered device that answered. One unit of `progress` is counted
/// per device. `local_v4` is the scan interface's IPv4 address (multicast source and SIP
/// `Via`); `v6_index` enables IPv6 multicast on that interface.
pub async fn enrich_services(
    devices: Vec<Device>,
    cfg: &ScanConfig,
    local_v4: Option<Ipv4Addr>,
    v6_index: Option<u32>,
    tx: Sender<ScanEvent>,
    cancel: CancellationToken,
    progress: ProgressScope,
) {
    let budget = SocketBudget::global();
    let window = discovery_window(cfg.timeout_ms);
    let timeout = sip_timeout(cfg.timeout_ms);
    let candidates = match local_v4 {
        Some(_) => sip_candidates(&devices, cfg.sip_all),
        None => Vec::new(),
    };
    let ssdp_fut = ssdp::discover_ssdp(local_v4, v6_index, window, budget, &cancel);
    let wsd_fut = wsd::discover_wsd(local_v4, v6_index, window, budget, &cancel);
    let sip_fut = async {
        let Some(local) = local_v4 else {
            return HashMap::new();
        };
        futures::stream::iter(candidates)
            .map(|ip| {
                let cancel = cancel.clone();
                async move {
                    let info =
                        sip::probe_sip(ip, IpAddr::V4(local), timeout, budget, &cancel).await;
                    (ip, info)
                }
            })
            .buffer_unordered(SIP_CONCURRENCY)
            .filter_map(|(ip, info)| async move { info.map(|i| (ip, i)) })
            .collect::<HashMap<IpAddr, SipInfo>>()
            .await
    };
    let (ssdp_map, wsd_map, sip_map) = tokio::join!(ssdp_fut, wsd_fut, sip_fut);

    let (mut n_ssdp, mut n_wsd, mut n_sip) = (0usize, 0usize, 0usize);
    for dev in &devices {
        progress.add(1);
        if cancel.is_cancelled() {
            continue;
        }
        let addrs = || std::iter::once(&dev.ip).chain(&dev.extra_ips);
        let s = addrs().find_map(|ip| ssdp_map.get(ip)).cloned();
        let o = addrs().find_map(|ip| wsd_map.get(ip)).cloned();
        let p = addrs().find_map(|ip| sip_map.get(ip)).cloned();
        if let Some(update) = service_update(dev, s, o, p) {
            n_ssdp += usize::from(update.ssdp.is_some());
            n_wsd += usize::from(update.onvif.is_some());
            n_sip += usize::from(update.sip.is_some());
            let _ = tx.send(ScanEvent::device(update)).await;
        }
    }
    let _ = tx
        .send(ScanEvent::info(format!(
            "services: {n_ssdp} SSDP/UPnP, {n_wsd} WS-Discovery/ONVIF and {n_sip} SIP device(s) \
             identified ({} UPnP / {} WSD responder(s), {} SIP probe candidate(s))",
            ssdp_map.len(),
            wsd_map.len(),
            sip_candidates(&devices, cfg.sip_all).len()
        )))
        .await;
}

/// A sparse device update (same key as `dev`) carrying the service data, or `None` when no
/// service answered for it.
pub fn service_update(
    dev: &Device,
    ssdp: Option<SsdpInfo>,
    onvif: Option<OnvifInfo>,
    sip: Option<SipInfo>,
) -> Option<Device> {
    if ssdp.is_none() && onvif.is_none() && sip.is_none() {
        return None;
    }
    let mut update = Device::new(dev.ip);
    update.vlan_id = dev.vlan_id;
    update.sources.clear();
    update.device_kind = device_kind(ssdp.as_ref(), onvif.as_ref(), sip.as_ref());
    if ssdp.is_some() {
        update.add_source(DiscoverySource::Ssdp);
    }
    if onvif.is_some() {
        update.add_source(DiscoverySource::Wsd);
    }
    if sip.is_some() {
        update.add_source(DiscoverySource::Sip);
    }
    update.ssdp = ssdp;
    update.onvif = onvif;
    update.sip = sip;
    Some(update)
}

/// Probe one host for services (GUI drawer): unicast SSDP, unicast WS-Discovery and SIP
/// OPTIONS run concurrently. `local_ip` is used in the SIP `Via` / `Contact` headers.
pub async fn probe_host(
    ip: IpAddr,
    local_ip: IpAddr,
    timeout: Duration,
    cancel: &CancellationToken,
) -> ServiceDiscovery {
    let budget = SocketBudget::global();
    let window = timeout.clamp(Duration::from_millis(500), Duration::from_secs(5));
    let (ssdp, onvif, sip) = tokio::join!(
        ssdp::probe_ssdp_host(ip, window, budget, cancel),
        wsd::probe_wsd_host(ip, window, budget, cancel),
        sip::probe_sip(
            ip,
            local_ip,
            sip_timeout(timeout.as_millis() as u64),
            budget,
            cancel
        ),
    );
    ServiceDiscovery {
        ip: Some(ip),
        device_kind: device_kind(ssdp.as_ref(), onvif.as_ref(), sip.as_ref()),
        ssdp,
        onvif,
        sip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CdpLldpNeighbor, NeighborProtocol, DEVICE_KIND_PBX};

    fn dev(ip: &str) -> Device {
        Device::new(ip.parse().unwrap())
    }

    #[test]
    fn sip_candidates_need_a_hint_unless_all() {
        let mut open = dev("10.0.0.2");
        open.open_ports = vec![22, 5060];
        let mut yealink = dev("10.0.0.3");
        yealink.vendor = Some("Yealink(Xiamen) Network Technology Co.,Ltd.".into());
        let mut phone_nbr = dev("10.0.0.4");
        phone_nbr.neighbor = Some(CdpLldpNeighbor {
            protocol: NeighborProtocol::Lldp,
            local_interface: "en0".into(),
            source_mac: "aa:aa:aa:aa:aa:aa".into(),
            device_id: "SEP0011".into(),
            system_name: None,
            system_description: None,
            port_id: None,
            port_description: None,
            platform: None,
            software_version: None,
            management_addrs: vec![],
            native_vlan: None,
            voice_vlan: Some(20),
            capabilities: vec![Capability::Telephone],
            vtp_domain: None,
            poe_watts: None,
            poe_info: None,
            ttl_secs: 120,
            last_seen_ms: 0,
        });
        let laptop = dev("10.0.0.5");
        let v6 = dev("fe80::1");
        let devices = vec![laptop, open, yealink, phone_nbr, v6];
        let ips: Vec<String> = sip_candidates(&devices, false)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(ips, vec!["10.0.0.2", "10.0.0.3", "10.0.0.4"]);
        // --sip-all: every IPv4 host.
        assert_eq!(sip_candidates(&devices, true).len(), 4);
    }

    #[test]
    fn device_kind_precedence() {
        let ssdp = SsdpInfo {
            device_type: Some("urn:schemas-upnp-org:device:MediaServer:1".into()),
            ..SsdpInfo::default()
        };
        let cam = OnvifInfo {
            is_camera: true,
            ..OnvifInfo::default()
        };
        let pbx = SipInfo {
            kind: Some(DEVICE_KIND_PBX.into()),
            ..SipInfo::default()
        };
        assert_eq!(
            device_kind(Some(&ssdp), Some(&cam), Some(&pbx)).as_deref(),
            Some("pbx")
        );
        assert_eq!(
            device_kind(Some(&ssdp), Some(&cam), None).as_deref(),
            Some("camera")
        );
        assert_eq!(
            device_kind(Some(&ssdp), None, None).as_deref(),
            Some("media_server")
        );
        let win = OnvifInfo {
            is_windows: true,
            ..OnvifInfo::default()
        };
        assert_eq!(
            device_kind(None, Some(&win), None).as_deref(),
            Some("computer")
        );
        assert_eq!(device_kind(None, None, None), None);
    }

    #[test]
    fn service_update_is_sparse_and_keyed() {
        let mut d = dev("10.0.0.9");
        d.vlan_id = Some(30);
        d.vendor = Some("Acme".into());
        assert!(service_update(&d, None, None, None).is_none());
        let u = service_update(
            &d,
            None,
            Some(OnvifInfo {
                is_camera: true,
                ..OnvifInfo::default()
            }),
            None,
        )
        .unwrap();
        assert_eq!(u.key(), d.key());
        assert_eq!(u.device_kind.as_deref(), Some("camera"));
        assert_eq!(u.sources, vec![DiscoverySource::Wsd]);
        assert!(u.vendor.is_none(), "only service data is carried");
    }

    #[tokio::test]
    async fn enrichment_without_interface_address_skips_sip_and_reports() {
        // No local IPv4 (multicast disabled, SIP skipped): the pass still completes, counts
        // progress and reports a summary line.
        let mut open = dev("127.0.0.1");
        open.open_ports = vec![5060];
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let progress = ProgressScope::detached(1);
        enrich_services(
            vec![open],
            &ScanConfig {
                timeout_ms: 100,
                ..ScanConfig::default()
            },
            None,
            None,
            tx,
            CancellationToken::new(),
            progress.clone(),
        )
        .await;
        assert_eq!(progress.used(), 1);
        let mut saw_summary = false;
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Log { message, .. } = ev {
                saw_summary |= message.starts_with("services:");
            }
        }
        assert!(saw_summary);
    }
}
