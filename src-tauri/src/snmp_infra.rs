//! Asynchronous SNMP infrastructure discovery (v1 / v2c / v3).
//!
//! Polls a device's system group, VLAN tables (Q-BRIDGE and Cisco VTP) and bridge/CAM tables
//! (802.1D and Q-BRIDGE forwarding databases) to turn switches into structured
//! [`SnmpDeviceInfo`]: a role, the VLANs it owns and a MAC-to-port map.
//!
//! The crate's [`snmp2::AsyncSession`] drives UDP over tokio. Every request is wrapped in a
//! timeout and retried, and every table walk is bounded by an overall per-device deadline, a
//! row cap and strict end-of-MIB / subtree / loop detection, so a hostile or buggy agent can
//! neither hang the poller nor exhaust its memory. All strings coming off the wire pass
//! through [`sanitize_text`].
//!
//! OID / index parsing and role classification are pure functions (unit tested below), and a
//! hand-encoded in-process SNMPv2c responder exercises the walk end to end.

use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use snmp2::{AsyncSession, Oid, Value};
use tokio::sync::{mpsc::Sender, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::models::{
    now_ms, sanitize_text, DeviceRole, DiscoverySource, PortMacCount, ScanEvent, SnmpConfig,
    SnmpDeviceInfo, SnmpVersion, SwitchPortMapping, VlanInfo, VlanSource, MAX_VLAN_ID,
};

// ---------------------------------------------------------------------------------------------
// OIDs (as sub-identifier slices; `Oid` is rebuilt per request)
// ---------------------------------------------------------------------------------------------

const SYS_DESCR: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
const SYS_OBJECT_ID: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 2, 0];
const SYS_UPTIME: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];
const SYS_NAME: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];
const SYS_SERVICES: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 7, 0];

/// dot1qVlanStaticName (Q-BRIDGE-MIB): index = VLAN id.
const DOT1Q_VLAN_STATIC_NAME: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 3, 1, 1];
/// vtpVlanName (CISCO-VTP-MIB): index = domain index . VLAN id.
const VTP_VLAN_NAME: &[u64] = &[1, 3, 6, 1, 4, 1, 9, 9, 46, 1, 3, 1, 1, 4];
/// dot1dTpFdbPort (BRIDGE-MIB): index = 6 MAC octets, value = bridge port number.
const DOT1D_TP_FDB_PORT: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2];
/// dot1qTpFdbPort (Q-BRIDGE-MIB): index = VLAN id + 6 MAC octets, value = bridge port number.
const DOT1Q_TP_FDB_PORT: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2];
/// dot1dBasePortIfIndex (BRIDGE-MIB): index = bridge port number, value = ifIndex.
const DOT1D_BASE_PORT_IFINDEX: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2];
/// ifName (IF-MIB): index = ifIndex, value = short interface name (e.g. `Gi1/0/24`).
const IF_NAME: &[u64] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1];
/// ifDescr (IF-MIB): index = ifIndex, value = long interface description.
const IF_DESCR: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 2];

// ---------------------------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------------------------

/// Hard cap on rows returned by any one table walk (hostile-agent memory bound).
const MAX_WALK_ROWS: usize = 50_000;
/// GETBULK max-repetitions (v2c/v3). Kept modest so a reply fits one datagram comfortably.
const BULK_REPETITIONS: u32 = 20;
/// Overall wall-clock budget for one device poll, independent of per-request timeouts.
const DEVICE_BUDGET: Duration = Duration::from_secs(25);
/// Attempts (initial + retries) are taken from [`SnmpConfig::retries`]; this caps the v3
/// engine-discovery (`AuthUpdated`) retries so a misbehaving agent cannot loop forever.
const MAX_AUTH_UPDATES: u8 = 4;
/// Per-VLAN community-string CAM polling (Cisco Catalyst) is bounded to this many VLANs.
const MAX_COMMUNITY_VLANS: usize = 128;
/// Max concurrent device polls in [`probe_candidates`].
const MAX_CONCURRENT_POLLS: usize = 16;

/// A `(index-suffix, value)` row returned by a table walk / GET.
type OidRow = (Vec<u64>, SnmpValue);
/// Forwarding database: `(vlan, mac)` → `(bridge port, vlan)`.
type FdbMap = BTreeMap<(Option<u16>, [u8; 6]), (u32, Option<u16>)>;

// ---------------------------------------------------------------------------------------------
// Owned SNMP value (decoupled from the session's borrowed receive buffer)
// ---------------------------------------------------------------------------------------------

/// A varbind value copied out of the session buffer so the borrow ends before the next request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SnmpValue {
    Int(i64),
    Bytes(Vec<u8>),
    Oid(Vec<u64>),
    Counter32(u32),
    Counter64(u64),
    Unsigned32(u32),
    Timeticks(u32),
    Ip([u8; 4]),
    EndOfMibView,
    NoSuchObject,
    NoSuchInstance,
    Null,
    Unsupported,
}

impl SnmpValue {
    fn from_value(v: &Value<'_>) -> Self {
        match v {
            Value::Integer(i) => SnmpValue::Int(*i),
            Value::OctetString(b) => SnmpValue::Bytes(b.to_vec()),
            Value::ObjectIdentifier(o) => {
                SnmpValue::Oid(o.iter().map(|it| it.collect()).unwrap_or_default())
            }
            Value::Counter32(n) => SnmpValue::Counter32(*n),
            Value::Counter64(n) => SnmpValue::Counter64(*n),
            Value::Unsigned32(n) => SnmpValue::Unsigned32(*n),
            Value::Timeticks(n) => SnmpValue::Timeticks(*n),
            Value::IpAddress(ip) => SnmpValue::Ip(*ip),
            Value::Null => SnmpValue::Null,
            Value::EndOfMibView => SnmpValue::EndOfMibView,
            Value::NoSuchObject => SnmpValue::NoSuchObject,
            Value::NoSuchInstance => SnmpValue::NoSuchInstance,
            _ => SnmpValue::Unsupported,
        }
    }

    /// `true` for the SNMP exception markers that terminate a walk.
    fn is_end_marker(&self) -> bool {
        matches!(
            self,
            SnmpValue::EndOfMibView | SnmpValue::NoSuchObject | SnmpValue::NoSuchInstance
        )
    }

    fn as_u32(&self) -> Option<u32> {
        match self {
            SnmpValue::Int(i) => u32::try_from(*i).ok(),
            SnmpValue::Counter32(n) | SnmpValue::Unsigned32(n) | SnmpValue::Timeticks(n) => {
                Some(*n)
            }
            SnmpValue::Counter64(n) => u32::try_from(*n).ok(),
            _ => None,
        }
    }

    fn octets(&self) -> Option<&[u8]> {
        match self {
            SnmpValue::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Sanitized UTF-8 (lossy) text, or `None` when the value is empty / not a string.
    fn text(&self) -> Option<String> {
        let b = self.octets()?;
        let s = sanitize_text(&String::from_utf8_lossy(b));
        (!s.is_empty()).then_some(s)
    }
}

// ---------------------------------------------------------------------------------------------
// OID helpers (pure)
// ---------------------------------------------------------------------------------------------

/// Build an owning [`Oid`] from sub-identifiers. The slices here are compile-time constants, so
/// this never fails in practice; a bad slice yields the empty OID rather than panicking.
fn oid(parts: &[u64]) -> Oid<'static> {
    Oid::from(parts).unwrap_or_else(|_| Oid::from(&[0, 0]).expect("0.0 is a valid OID"))
}

/// Sub-identifiers of `full` after the `base` prefix, or `None` when `full` is not a strict,
/// deeper descendant of `base` (so it has left the table/subtree).
fn suffix_of<'a>(base: &[u64], full: &'a [u64]) -> Option<&'a [u64]> {
    (full.len() > base.len() && full.starts_with(base)).then(|| &full[base.len()..])
}

/// The trailing 6 sub-identifiers of a FDB OID index read as a MAC address.
pub fn mac_from_suffix(suffix: &[u64]) -> Option<[u8; 6]> {
    if suffix.len() < 6 {
        return None;
    }
    let tail = &suffix[suffix.len() - 6..];
    let mut mac = [0u8; 6];
    for (slot, v) in mac.iter_mut().zip(tail) {
        *slot = u8::try_from(*v).ok()?;
    }
    Some(mac)
}

/// A Q-BRIDGE FDB index `vlan . mac[0..6]`: the first sub-id is the VLAN, the last six the MAC.
pub fn vlan_and_mac_from_suffix(suffix: &[u64]) -> Option<(u16, [u8; 6])> {
    if suffix.len() < 7 {
        return None;
    }
    let vlan = u16::try_from(suffix[0])
        .ok()
        .filter(|v| *v <= MAX_VLAN_ID)?;
    let mac = mac_from_suffix(suffix)?;
    Some((vlan, mac))
}

/// Resolve a bridge port number to an interface name via the two IF-MIB maps. Falls back to a
/// synthetic `port <n>` label (and no ifIndex) when the maps do not cover the port.
pub fn resolve_port_name(
    bridge_port: u32,
    base_port_ifindex: &HashMap<u32, u32>,
    if_names: &HashMap<u32, String>,
) -> (String, Option<u32>) {
    if let Some(&ifindex) = base_port_ifindex.get(&bridge_port) {
        if let Some(name) = if_names.get(&ifindex) {
            return (name.clone(), Some(ifindex));
        }
        return (format!("ifIndex {ifindex}"), Some(ifindex));
    }
    (format!("port {bridge_port}"), None)
}

/// The IANA/SMI private-enterprise number of a `1.3.6.1.4.1.<N>...` sysObjectID string.
pub fn enterprise_number(sys_object_id: &str) -> Option<u64> {
    let rest = sys_object_id.trim().strip_prefix("1.3.6.1.4.1.")?;
    rest.split('.').next()?.parse().ok()
}

// ---------------------------------------------------------------------------------------------
// Role classification (pure)
// ---------------------------------------------------------------------------------------------

/// Classify a device from its sysObjectID enterprise number, sysDescr text and sysServices
/// bit field. Keyword evidence wins; the enterprise number and services bits are tie-breakers.
pub fn classify_role(
    sys_object_id: Option<&str>,
    sys_descr: &str,
    sys_services: Option<i64>,
) -> DeviceRole {
    let text = sys_descr.to_ascii_lowercase();
    let any = |needles: &[&str]| needles.iter().any(|n| text.contains(n));
    let ent = sys_object_id.and_then(enterprise_number);

    // Firewalls first: the strongest signal, and several overlap switch/router keywords.
    if any(&[
        "fortigate",
        "fortios",
        "palo alto",
        "pan-os",
        "firepower",
        "pfsense",
        "opnsense",
        "sophos",
        "sonicwall",
        "checkpoint",
        "check point",
        "netscreen",
        "cisco asa",
        "adaptive security",
        "srx",
        "meraki mx",
        "watchguard",
        "firewall",
    ]) || matches!(ent, Some(12356) | Some(25461) | Some(3401) | Some(2620) | Some(74) if any(&["firewall", "security", "fortigate", "pan-os", "asa", "srx"]))
    {
        return DeviceRole::Firewall;
    }
    // Access points before switches (many APs advertise bridging).
    if any(&[
        "access point",
        "aironet",
        "air-",
        "ap software",
        "wireless ap",
        "unifi ap",
        "uap-",
        " u6-",
        " u7-",
        "meraki mr",
        "aruba ap",
        "instant ap",
        "arubaos (ap",
        "ruckus",
        "mikrotik cap",
        "wifi access",
    ]) && !any(&["wireless lan controller", "wlc", "switch", "router"])
    {
        return DeviceRole::AccessPoint;
    }
    if any(&[
        "switch",
        "catalyst",
        "ws-c",
        "nexus",
        "procurve",
        "aruba 2",
        "aruba 3",
        "arubaos-cx",
        "fortiswitch",
        "powerconnect",
        "ex2300",
        "ex3400",
        "ex4300",
        "qfx",
        "meraki ms",
    ]) {
        return DeviceRole::Switch;
    }
    if any(&[
        "router",
        "routeros",
        "ios xe software",
        "ios-xr",
        " isr",
        " asr",
        "edgerouter",
        "edgeos",
        "vyos",
        "mx240",
        "mx480",
        "gateway",
    ]) {
        return DeviceRole::Router;
    }

    // No keyword hit: lean on sysServices (bit L set => offers OSI layer L) and the vendor.
    if let Some(bits) = sys_services {
        let offers = |layer: u32| bits & (1 << (layer - 1)) != 0;
        if offers(2) && !offers(4) && !offers(7) {
            return DeviceRole::Switch; // datalink only
        }
        if offers(3) && !offers(7) {
            return DeviceRole::Router; // internet layer, not an application host
        }
    }
    match ent {
        // Pure network-equipment vendors default to infrastructure (Switch) over Host.
        Some(9) | Some(2636) | Some(11) | Some(47196) | Some(14823) | Some(41112) | Some(14988)
        | Some(25506) => DeviceRole::Switch,
        _ => DeviceRole::Host,
    }
}

// ---------------------------------------------------------------------------------------------
// Session construction
// ---------------------------------------------------------------------------------------------

/// Map our auth-protocol enum onto the crate's. Every variant is supported by `crypto-rust`.
fn auth_protocol(p: crate::models::SnmpAuthProtocol) -> snmp2::v3::AuthProtocol {
    use crate::models::SnmpAuthProtocol as A;
    use snmp2::v3::AuthProtocol as P;
    match p {
        A::Md5 => P::Md5,
        A::Sha1 => P::Sha1,
        A::Sha224 => P::Sha224,
        A::Sha256 => P::Sha256,
        A::Sha384 => P::Sha384,
        A::Sha512 => P::Sha512,
    }
}

fn priv_cipher(p: crate::models::SnmpPrivProtocol) -> snmp2::v3::Cipher {
    use crate::models::SnmpPrivProtocol as S;
    use snmp2::v3::Cipher as C;
    match p {
        S::Des => C::Des,
        S::Aes128 => C::Aes128,
        S::Aes192 => C::Aes192,
        S::Aes256 => C::Aes256,
    }
}

/// A configured SNMP poller. Cheap to clone/share; opens a fresh UDP session per device.
#[derive(Debug, Clone)]
pub struct SnmpClient {
    cfg: SnmpConfig,
}

impl SnmpClient {
    pub fn new(cfg: SnmpConfig) -> Self {
        Self { cfg }
    }

    pub fn config(&self) -> &SnmpConfig {
        &self.cfg
    }

    fn per_request_timeout(&self) -> Duration {
        Duration::from_millis(self.cfg.timeout_ms.clamp(1, 600_000))
    }

    fn attempts(&self) -> u8 {
        self.cfg.retries.saturating_add(1)
    }

    /// Open a session to `addr` using `community` (community-string polling can override the
    /// configured community for Cisco per-VLAN `community@vlan` indexing).
    async fn open(&self, addr: SocketAddr, community: &str) -> Result<AsyncSession> {
        let start_id = ((now_ms() as i32) ^ (std::process::id() as i32)) & 0x7fff_ffff;
        match self.cfg.version {
            SnmpVersion::V1 => AsyncSession::new_v1(addr, community.as_bytes(), start_id)
                .await
                .map_err(|e| anyhow!("SNMPv1 session to {addr}: {e}")),
            SnmpVersion::V2c => AsyncSession::new_v2c(addr, community.as_bytes(), start_id)
                .await
                .map_err(|e| anyhow!("SNMPv2c session to {addr}: {e}")),
            SnmpVersion::V3 => {
                let creds = self
                    .cfg
                    .v3
                    .as_ref()
                    .ok_or_else(|| anyhow!("SNMPv3 requires credentials"))?;
                let auth = snmp2::v3::Auth::NoAuthNoPriv;
                let mut security = snmp2::v3::Security::new(
                    creds.username.as_bytes(),
                    creds.auth_password.as_deref().unwrap_or("").as_bytes(),
                )
                .with_auth_protocol(auth_protocol(creds.auth_protocol));
                security = match (&creds.auth_password, &creds.priv_password) {
                    (Some(_), Some(pw)) => security.with_auth(snmp2::v3::Auth::AuthPriv {
                        cipher: priv_cipher(creds.priv_protocol),
                        privacy_password: pw.as_bytes().to_vec(),
                    }),
                    (Some(_), None) => security.with_auth(snmp2::v3::Auth::AuthNoPriv),
                    (None, Some(_)) => bail!(
                        "SNMPv3 privacy requires an authentication password (authPriv has no \
                         noAuthPriv mode)"
                    ),
                    (None, None) => security.with_auth(auth),
                };
                // AES-192/256 with MD5/SHA1 (and AES-256 with SHA224) need a key-extension
                // method; default to Reeder and let the session fall back if needed.
                if priv_cipher(creds.priv_protocol)
                    .priv_key_needs_extension(&auth_protocol(creds.auth_protocol))
                {
                    security = security.with_key_extension_method(snmp2::v3::KeyExtension::Reeder);
                }
                let mut session = AsyncSession::new_v3(addr, start_id, security)
                    .await
                    .map_err(|e| anyhow!("SNMPv3 session to {addr}: {e}"))?;
                // Engine-ID / boots-time discovery. AuthUpdated just means "state learned,
                // retry"; a couple of rounds settles it.
                let timeout = self.per_request_timeout();
                let mut ok = false;
                for _ in 0..MAX_AUTH_UPDATES {
                    match tokio::time::timeout(timeout, session.init()).await {
                        Ok(Ok(())) => {
                            ok = true;
                            break;
                        }
                        Ok(Err(snmp2::Error::AuthUpdated)) => continue,
                        Ok(Err(e)) => {
                            // Try the alternate key-extension method once before giving up.
                            if let Ok(Some(_)) = session.try_another_key_extension_method().await {
                                continue;
                            }
                            bail!("SNMPv3 initialization failed: {e}");
                        }
                        Err(_) => bail!("SNMPv3 initialization to {addr} timed out"),
                    }
                }
                if !ok {
                    bail!("SNMPv3 engine discovery did not converge for {addr}");
                }
                Ok(session)
            }
        }
    }

    fn uses_bulk(&self) -> bool {
        self.cfg.version != SnmpVersion::V1
    }

    // ----- one-shot requests (each copies results out before returning) ----------------------

    /// GET several scalar OIDs in one request; returns `(oid, value)` pairs.
    async fn get_many(
        &self,
        session: &mut AsyncSession,
        oids: &[Oid<'static>],
    ) -> Result<Vec<OidRow>> {
        let refs: Vec<&Oid> = oids.iter().collect();
        let timeout = self.per_request_timeout();
        let mut last_err: Option<String> = None;
        for _ in 0..self.attempts() {
            let mut auth_rounds = 0u8;
            loop {
                match tokio::time::timeout(timeout, session.get_many(&refs)).await {
                    Ok(Ok(pdu)) => {
                        let out = pdu
                            .varbinds
                            .map(|(o, v)| {
                                (
                                    o.iter().map(|it| it.collect()).unwrap_or_default(),
                                    SnmpValue::from_value(&v),
                                )
                            })
                            .collect();
                        return Ok(out);
                    }
                    Ok(Err(snmp2::Error::AuthUpdated)) if auth_rounds < MAX_AUTH_UPDATES => {
                        auth_rounds += 1;
                        continue;
                    }
                    Ok(Err(e)) => {
                        last_err = Some(e.to_string());
                        break;
                    }
                    Err(_) => {
                        last_err = Some("request timed out".into());
                        break;
                    }
                }
            }
        }
        Err(anyhow!(
            "SNMP GET failed: {}",
            last_err.unwrap_or_else(|| "no response".into())
        ))
    }

    /// One GETBULK (v2c/v3) or GETNEXT (v1) step from `from`. Returns `(oid, value)` pairs in
    /// order plus the response error-status (non-zero on v1 end-of-table `noSuchName`).
    async fn step(
        &self,
        session: &mut AsyncSession,
        from: &Oid<'static>,
    ) -> Result<(Vec<OidRow>, u32)> {
        let timeout = self.per_request_timeout();
        let bulk = self.uses_bulk();
        let mut last_err: Option<String> = None;
        for _ in 0..self.attempts() {
            let mut auth_rounds = 0u8;
            loop {
                let fut = async {
                    if bulk {
                        session.getbulk(&[from], 0, BULK_REPETITIONS).await
                    } else {
                        session.getnext(from).await
                    }
                };
                match tokio::time::timeout(timeout, fut).await {
                    Ok(Ok(pdu)) => {
                        let err_status = pdu.error_status;
                        let rows = pdu
                            .varbinds
                            .map(|(o, v)| {
                                (
                                    o.iter().map(|it| it.collect()).unwrap_or_default(),
                                    SnmpValue::from_value(&v),
                                )
                            })
                            .collect();
                        return Ok((rows, err_status));
                    }
                    Ok(Err(snmp2::Error::AuthUpdated)) if auth_rounds < MAX_AUTH_UPDATES => {
                        auth_rounds += 1;
                        continue;
                    }
                    Ok(Err(e)) => {
                        last_err = Some(e.to_string());
                        break;
                    }
                    Err(_) => {
                        last_err = Some("request timed out".into());
                        break;
                    }
                }
            }
        }
        Err(anyhow!(
            "SNMP walk step failed: {}",
            last_err.unwrap_or_else(|| "no response".into())
        ))
    }

    /// Walk the subtree rooted at `base`, returning `(index-suffix, value)` rows. Stops at the
    /// end of the subtree, on an SNMP end marker, when the agent fails to advance (loop), at
    /// the row cap, or when the device deadline passes.
    async fn walk(
        &self,
        session: &mut AsyncSession,
        base: &[u64],
        deadline: Instant,
    ) -> Result<Vec<OidRow>> {
        let mut rows: Vec<OidRow> = Vec::new();
        let mut cursor = oid(base);
        loop {
            if Instant::now() >= deadline {
                break;
            }
            let (batch, err_status) = self.step(session, &cursor).await?;
            // v1 signals the end of a table with noSuchName (error-status 2).
            if !self.uses_bulk() && err_status != 0 {
                break;
            }
            if batch.is_empty() {
                break;
            }
            let mut advanced = false;
            let mut done = false;
            let mut last_full: Option<Vec<u64>> = None;
            for (full, value) in batch {
                let Some(suffix) = suffix_of(base, &full) else {
                    done = true; // left the subtree
                    break;
                };
                if value.is_end_marker() {
                    done = true;
                    break;
                }
                // Loop / non-advance protection: each OID must be strictly greater than the
                // cursor we asked from.
                if oid_le(&full, &oid_vec(&cursor)) {
                    done = true;
                    break;
                }
                rows.push((suffix.to_vec(), value));
                last_full = Some(full);
                advanced = true;
                if rows.len() >= MAX_WALK_ROWS {
                    done = true;
                    break;
                }
            }
            if done || !advanced {
                break;
            }
            if let Some(full) = last_full {
                cursor = oid(&full);
            } else {
                break;
            }
        }
        Ok(rows)
    }

    /// Poll one device and return its structured SNMP view. Fails (rather than returning an
    /// empty record) when the system group cannot be read, so callers can treat the device as
    /// not SNMP-reachable.
    pub async fn poll_device(&self, ip: IpAddr) -> Result<SnmpDeviceInfo> {
        let deadline = Instant::now() + DEVICE_BUDGET;
        let addr = SocketAddr::new(ip, self.cfg.port);
        let community = self.cfg.community.clone();
        let mut session = self.open(addr, &community).await?;

        // --- system group ---
        let sys = self
            .get_many(
                &mut session,
                &[
                    oid(SYS_DESCR),
                    oid(SYS_OBJECT_ID),
                    oid(SYS_UPTIME),
                    oid(SYS_NAME),
                    oid(SYS_SERVICES),
                ],
            )
            .await
            .context("SNMP system group unreadable")?;

        let mut sys_descr = None;
        let mut sys_object_id = None;
        let mut sys_uptime_ticks = None;
        let mut sys_name = None;
        let mut sys_services = None;
        for (o, v) in &sys {
            if o == SYS_DESCR {
                sys_descr = v.text();
            } else if o == SYS_OBJECT_ID {
                if let SnmpValue::Oid(parts) = v {
                    sys_object_id = Some(oid_to_string(parts));
                }
            } else if o == SYS_UPTIME {
                sys_uptime_ticks = v.as_u32();
            } else if o == SYS_NAME {
                sys_name = v.text();
            } else if o == SYS_SERVICES {
                sys_services = match v {
                    SnmpValue::Int(i) => Some(*i),
                    _ => v.as_u32().map(i64::from),
                };
            }
        }
        // A device that answers nothing of the system group is not really SNMP-reachable.
        if sys_descr.is_none() && sys_name.is_none() && sys_object_id.is_none() {
            bail!("{ip} did not return any system MIB values");
        }

        let role = classify_role(
            sys_object_id.as_deref(),
            sys_descr.as_deref().unwrap_or(""),
            sys_services,
        );
        let switch_name = sys_name.clone().unwrap_or_else(|| ip.to_string());

        // --- VLANs (Q-BRIDGE static names, then Cisco VTP) ---
        let mut vlans: BTreeMap<u16, VlanInfo> = BTreeMap::new();
        for (suffix, value) in self
            .walk(&mut session, DOT1Q_VLAN_STATIC_NAME, deadline)
            .await
            .unwrap_or_default()
        {
            if let Some(&id) = suffix.last() {
                if let Ok(id) = u16::try_from(id) {
                    if (1..=MAX_VLAN_ID).contains(&id) {
                        let v = vlans
                            .entry(id)
                            .or_insert_with(|| new_snmp_vlan(id, &switch_name));
                        v.name = value.text().or_else(|| v.name.clone());
                    }
                }
            }
        }
        for (suffix, value) in self
            .walk(&mut session, VTP_VLAN_NAME, deadline)
            .await
            .unwrap_or_default()
        {
            if let Some(&id) = suffix.last() {
                if let Ok(id) = u16::try_from(id) {
                    if (1..=MAX_VLAN_ID).contains(&id) {
                        let v = vlans
                            .entry(id)
                            .or_insert_with(|| new_snmp_vlan(id, &switch_name));
                        if v.name.is_none() {
                            v.name = value.text();
                        }
                    }
                }
            }
        }

        // --- interface-name maps ---
        let mut base_port_ifindex: HashMap<u32, u32> = HashMap::new();
        for (suffix, value) in self
            .walk(&mut session, DOT1D_BASE_PORT_IFINDEX, deadline)
            .await
            .unwrap_or_default()
        {
            if let (Some(&port), Some(ifindex)) = (suffix.last(), value.as_u32()) {
                if let Ok(port) = u32::try_from(port) {
                    base_port_ifindex.insert(port, ifindex);
                }
            }
        }
        let mut if_names: HashMap<u32, String> = HashMap::new();
        for (suffix, value) in self
            .walk(&mut session, IF_NAME, deadline)
            .await
            .unwrap_or_default()
        {
            if let (Some(&ifindex), Some(name)) = (suffix.last(), value.text()) {
                if let Ok(ifindex) = u32::try_from(ifindex) {
                    if_names.insert(ifindex, name);
                }
            }
        }
        for (suffix, value) in self
            .walk(&mut session, IF_DESCR, deadline)
            .await
            .unwrap_or_default()
        {
            if let (Some(&ifindex), Some(name)) = (suffix.last(), value.text()) {
                if let Ok(ifindex) = u32::try_from(ifindex) {
                    if_names.entry(ifindex).or_insert(name);
                }
            }
        }

        // --- forwarding database → MAC-to-port ---
        // Keyed by (vlan, mac) so the same MAC on two VLANs is two mappings.
        let mut mappings: FdbMap = FdbMap::new();

        // Preferred: Q-BRIDGE per-VLAN FDB (also yields the VLAN id).
        for (suffix, value) in self
            .walk(&mut session, DOT1Q_TP_FDB_PORT, deadline)
            .await
            .unwrap_or_default()
        {
            if let (Some((vlan, mac)), Some(port)) =
                (vlan_and_mac_from_suffix(&suffix), value.as_u32())
            {
                if port != 0 {
                    mappings.insert((Some(vlan), mac), (port, Some(vlan)));
                }
            }
        }
        // Fallback: classic 802.1D FDB (no VLAN in the index).
        if mappings.is_empty() {
            for (suffix, value) in self
                .walk(&mut session, DOT1D_TP_FDB_PORT, deadline)
                .await
                .unwrap_or_default()
            {
                if let (Some(mac), Some(port)) = (mac_from_suffix(&suffix), value.as_u32()) {
                    if port != 0 {
                        mappings.insert((None, mac), (port, None));
                    }
                }
            }
        }
        // Cisco Catalyst per-VLAN community indexing when the bridge tables came back empty.
        if mappings.is_empty() && self.cfg.version != SnmpVersion::V3 && !vlans.is_empty() {
            for &vid in vlans.keys().take(MAX_COMMUNITY_VLANS) {
                if Instant::now() >= deadline {
                    break;
                }
                let community = format!("{community}@{vid}");
                let Ok(mut vsession) = self.open(addr, &community).await else {
                    continue;
                };
                for (suffix, value) in self
                    .walk(&mut vsession, DOT1D_TP_FDB_PORT, deadline)
                    .await
                    .unwrap_or_default()
                {
                    if let (Some(mac), Some(port)) = (mac_from_suffix(&suffix), value.as_u32()) {
                        if port != 0 {
                            mappings.insert((Some(vid), mac), (port, Some(vid)));
                        }
                    }
                }
            }
        }

        // Count MACs per resolved port name, then build the mapping list.
        let mut counts: HashMap<(String, Option<u32>), u32> = HashMap::new();
        let mut port_mappings = Vec::with_capacity(mappings.len());
        for ((_, mac), (bridge_port, vlan_id)) in mappings {
            let (port_name, port_index) =
                resolve_port_name(bridge_port, &base_port_ifindex, &if_names);
            *counts.entry((port_name.clone(), port_index)).or_insert(0) += 1;
            port_mappings.push(SwitchPortMapping {
                switch_name: switch_name.clone(),
                switch_ip: Some(ip),
                port_name,
                port_index,
                vlan_id,
                mac: crate::models::format_mac(&mac),
            });
        }
        let mut port_mac_counts: Vec<PortMacCount> = counts
            .into_iter()
            .map(|((port_name, port_index), mac_count)| PortMacCount {
                port_name,
                port_index,
                mac_count,
            })
            .collect();
        port_mac_counts.sort_by(|a, b| {
            b.mac_count
                .cmp(&a.mac_count)
                .then(a.port_name.cmp(&b.port_name))
        });

        Ok(SnmpDeviceInfo {
            sys_name,
            sys_descr,
            sys_uptime_ticks,
            sys_object_id,
            role,
            vlans: vlans.into_values().collect(),
            port_mappings,
            port_mac_counts,
        })
    }
}

fn new_snmp_vlan(id: u16, switch_name: &str) -> VlanInfo {
    let mut v = VlanInfo::new(id, VlanSource::Snmp);
    v.switch_name = Some(switch_name.to_string());
    v
}

/// Render OID sub-identifiers as a dotted string.
fn oid_to_string(parts: &[u64]) -> String {
    parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn oid_vec(o: &Oid<'_>) -> Vec<u64> {
    o.iter().map(|it| it.collect()).unwrap_or_default()
}

/// `a <= b` by SNMP lexicographic OID order.
fn oid_le(a: &[u64], b: &[u64]) -> bool {
    use std::cmp::Ordering;
    for (x, y) in a.iter().zip(b) {
        match x.cmp(y) {
            Ordering::Less => return true,
            Ordering::Greater => return false,
            Ordering::Equal => {}
        }
    }
    a.len() <= b.len()
}

// ---------------------------------------------------------------------------------------------
// Concurrent candidate probing
// ---------------------------------------------------------------------------------------------

/// Poll every candidate in `ips` with bounded concurrency, emitting a [`ScanEvent::Device`]
/// (role + SNMP evidence), one [`ScanEvent::Vlan`] per discovered VLAN and one
/// [`ScanEvent::PortMapping`] per learned MAC. Cancellation stops dispatch promptly.
pub async fn probe_candidates(
    ips: Vec<IpAddr>,
    cfg: &SnmpConfig,
    tx: Sender<ScanEvent>,
    cancel: CancellationToken,
) {
    let client = SnmpClient::new(cfg.clone());
    let semaphore = std::sync::Arc::new(Semaphore::new(MAX_CONCURRENT_POLLS));
    let mut tasks = tokio::task::JoinSet::new();

    for ip in ips {
        if cancel.is_cancelled() {
            break;
        }
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        let (client, tx, cancel) = (client.clone(), tx.clone(), cancel.clone());
        tasks.spawn(async move {
            let _permit = permit;
            if cancel.is_cancelled() {
                return;
            }
            let info = tokio::select! {
                _ = cancel.cancelled() => return,
                res = client.poll_device(ip) => match res {
                    Ok(info) => info,
                    Err(_) => return, // unreachable / wrong credentials: silently skip
                },
            };
            emit_device_info(ip, &info, &tx).await;
        });
        while tasks.try_join_next().is_some() {}
    }
    while tasks.join_next().await.is_some() {}
}

/// Turn one [`SnmpDeviceInfo`] into stream events for `ip`.
async fn emit_device_info(ip: IpAddr, info: &SnmpDeviceInfo, tx: &Sender<ScanEvent>) {
    // The infrastructure device itself: role plus a vendor guess from sysDescr.
    let mut dev = crate::models::Device::new(ip);
    dev.role = info.role;
    dev.vendor = info
        .sys_descr
        .as_deref()
        .map(vendor_hint)
        .filter(|s| !s.is_empty());
    dev.add_source(DiscoverySource::Snmp);
    let _ = tx.send(ScanEvent::device(dev)).await;

    for v in &info.vlans {
        let _ = tx.send(ScanEvent::Vlan(v.clone())).await;
    }
    for pm in &info.port_mappings {
        let _ = tx.send(ScanEvent::PortMapping(pm.clone())).await;
    }
}

/// A coarse vendor label from a sysDescr: its first word, trimmed (e.g. "Cisco").
fn vendor_hint(sys_descr: &str) -> String {
    sys_descr
        .split_whitespace()
        .next()
        .map(sanitize_text)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_parsed_from_oid_suffix() {
        // dot1dTpFdbAddress / dot1dTpFdbPort index: 6 MAC octets.
        assert_eq!(
            mac_from_suffix(&[0x00, 0x1a, 0x2b, 0x03, 0x04, 0x05]),
            Some([0x00, 0x1a, 0x2b, 0x03, 0x04, 0x05])
        );
        // A byte out of range rejects the whole index.
        assert_eq!(mac_from_suffix(&[0, 0, 0, 0, 0, 256]), None);
        assert_eq!(mac_from_suffix(&[1, 2, 3]), None);
    }

    #[test]
    fn vlan_and_mac_parsed_from_qbridge_index() {
        // dot1qTpFdbPort index: vlan . mac[0..6].
        assert_eq!(
            vlan_and_mac_from_suffix(&[20, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            Some((20, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))
        );
        assert_eq!(vlan_and_mac_from_suffix(&[4095, 1, 2, 3, 4, 5, 6]), None); // vlan out of range
        assert_eq!(vlan_and_mac_from_suffix(&[10, 1, 2, 3]), None);
    }

    #[test]
    fn bridge_port_resolves_to_ifname() {
        let base: HashMap<u32, u32> = [(1, 10001), (2, 10002)].into_iter().collect();
        let names: HashMap<u32, String> = [
            (10001, "Gi1/0/1".to_string()),
            (10002, "Gi1/0/24".to_string()),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            resolve_port_name(1, &base, &names),
            ("Gi1/0/1".into(), Some(10001))
        );
        assert_eq!(
            resolve_port_name(2, &base, &names),
            ("Gi1/0/24".into(), Some(10002))
        );
        // No ifName for the ifIndex: fall back to the ifIndex label.
        let base2: HashMap<u32, u32> = [(3, 99)].into_iter().collect();
        assert_eq!(
            resolve_port_name(3, &base2, &names),
            ("ifIndex 99".into(), Some(99))
        );
        // Unknown bridge port: synthetic label, no ifIndex.
        assert_eq!(resolve_port_name(7, &base, &names), ("port 7".into(), None));
    }

    #[test]
    fn enterprise_numbers_parse() {
        assert_eq!(enterprise_number("1.3.6.1.4.1.9.1.516"), Some(9));
        assert_eq!(enterprise_number("1.3.6.1.4.1.12356.101.1"), Some(12356));
        assert_eq!(enterprise_number("1.3.6.1.2.1.1"), None);
        assert_eq!(enterprise_number("garbage"), None);
    }

    #[test]
    fn role_classification() {
        assert_eq!(
            classify_role(
                Some("1.3.6.1.4.1.9.1.516"),
                "Cisco IOS Software, Catalyst L3 Switch",
                None
            ),
            DeviceRole::Switch
        );
        assert_eq!(
            classify_role(Some("1.3.6.1.4.1.12356.101.1"), "FortiGate-60F", None),
            DeviceRole::Firewall
        );
        assert_eq!(
            classify_role(
                Some("1.3.6.1.4.1.25461.2.3"),
                "Palo Alto Networks PA-220",
                None
            ),
            DeviceRole::Firewall
        );
        assert_eq!(
            classify_role(None, "Cisco Aironet 2800 Series AP Software", None),
            DeviceRole::AccessPoint
        );
        assert_eq!(
            classify_role(Some("1.3.6.1.4.1.14988.1"), "RouterOS RB750", None),
            DeviceRole::Router
        );
        // No keywords: sysServices datalink-only => switch; vendor-only => switch; host.
        assert_eq!(
            classify_role(None, "some device", Some(0b10)),
            DeviceRole::Switch
        );
        assert_eq!(
            classify_role(Some("1.3.6.1.4.1.2636.1.1"), "junos box", None),
            DeviceRole::Switch
        );
        assert_eq!(
            classify_role(None, "Linux server 5.15", Some(0b1001110)),
            DeviceRole::Host
        );
    }

    #[test]
    fn walk_cursor_ordering() {
        assert!(oid_le(&[1, 3, 6, 1], &[1, 3, 6, 1]));
        assert!(oid_le(&[1, 3, 6, 1], &[1, 3, 6, 2]));
        assert!(!oid_le(&[1, 3, 6, 2], &[1, 3, 6, 1]));
        assert!(oid_le(&[1, 3, 6], &[1, 3, 6, 1])); // prefix is "<="
        assert!(!oid_le(&[1, 3, 6, 1], &[1, 3, 6]));
    }

    #[test]
    fn suffix_extraction() {
        assert_eq!(
            suffix_of(&[1, 3, 6, 1], &[1, 3, 6, 1, 10, 20]),
            Some(&[10u64, 20][..])
        );
        assert_eq!(suffix_of(&[1, 3, 6, 1], &[1, 3, 6, 1]), None); // not deeper
        assert_eq!(suffix_of(&[1, 3, 6, 1], &[1, 3, 7, 1, 1]), None); // different subtree
    }

    // --- integration-style walk test against a hand-encoded SNMPv2c responder ---------------

    mod ber {
        //! Minimal BER encoder for building canned SNMP responses in-test.

        pub fn len(n: usize) -> Vec<u8> {
            if n < 0x80 {
                vec![n as u8]
            } else {
                let mut bytes = Vec::new();
                let mut v = n;
                while v > 0 {
                    bytes.insert(0, (v & 0xff) as u8);
                    v >>= 8;
                }
                let mut out = vec![0x80 | bytes.len() as u8];
                out.extend(bytes);
                out
            }
        }

        pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            out.extend(len(content.len()));
            out.extend_from_slice(content);
            out
        }

        pub fn int(mut v: i64) -> Vec<u8> {
            // Minimal two's-complement encoding.
            let mut bytes = Vec::new();
            loop {
                bytes.insert(0, (v & 0xff) as u8);
                v >>= 8;
                if (v == 0 && bytes[0] & 0x80 == 0) || (v == -1 && bytes[0] & 0x80 != 0) {
                    break;
                }
            }
            tlv(0x02, &bytes)
        }

        pub fn octet(s: &[u8]) -> Vec<u8> {
            tlv(0x04, s)
        }

        pub fn oid(parts: &[u64]) -> Vec<u8> {
            let mut body = vec![(parts[0] * 40 + parts[1]) as u8];
            for &sub in &parts[2..] {
                let mut stack = Vec::new();
                let mut v = sub;
                stack.push((v & 0x7f) as u8);
                v >>= 7;
                while v > 0 {
                    stack.push((v & 0x7f) as u8 | 0x80);
                    v >>= 7;
                }
                stack.reverse();
                body.extend(stack);
            }
            tlv(0x06, &body)
        }

        pub fn end_of_mib() -> Vec<u8> {
            vec![0x82, 0x00]
        }

        /// SNMP Timeticks (application tag 0x43), minimal unsigned big-endian content.
        pub fn timeticks(mut v: u32) -> Vec<u8> {
            let mut bytes = Vec::new();
            loop {
                bytes.insert(0, (v & 0xff) as u8);
                v >>= 8;
                if v == 0 {
                    break;
                }
            }
            if bytes[0] & 0x80 != 0 {
                bytes.insert(0, 0);
            }
            tlv(0x43, &bytes)
        }

        pub fn varbind(oid_parts: &[u64], value: &[u8]) -> Vec<u8> {
            let mut inner = oid(oid_parts);
            inner.extend_from_slice(value);
            tlv(0x30, &inner)
        }
    }

    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::UdpSocket;

    /// A tiny fixed SNMPv2c agent: answers the system group GET and the two table walks the
    /// poller performs, returning end-of-MIB markers to terminate.
    async fn fake_agent(sock: UdpSocket, cancel: CancellationToken) {
        let mut buf = [0u8; 65535];
        loop {
            let (n, peer) = tokio::select! {
                _ = cancel.cancelled() => return,
                r = sock.recv_from(&mut buf) => match r { Ok(v) => v, Err(_) => return },
            };
            let Ok(req) = snmp2::Pdu::from_bytes(&buf[..n]) else {
                continue;
            };
            let req_id = req.req_id;
            let community = req.community.to_vec();
            let is_bulk = req.message_type == snmp2::MessageType::GetBulkRequest;
            // First requested OID.
            let mut vb = req.varbinds.clone();
            let first = vb.next().map(|(o, _)| {
                o.iter()
                    .map(|it| it.collect::<Vec<u64>>())
                    .unwrap_or_default()
            });

            let varbinds = build_reply(first.as_deref(), is_bulk, &mut vb);
            let pdu = ber::tlv(
                0xa2,
                &[
                    ber::int(i64::from(req_id)),
                    ber::int(0),
                    ber::int(0),
                    ber::tlv(0x30, &varbinds),
                ]
                .concat(),
            );
            let msg = ber::tlv(0x30, &[ber::int(1), ber::octet(&community), pdu].concat());
            let _ = sock.send_to(&msg, peer).await;
        }
    }

    fn build_reply(
        first: Option<&[u64]>,
        is_bulk: bool,
        rest: &mut snmp2::Varbinds<'_>,
    ) -> Vec<u8> {
        let sys_descr: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
        let sys_object_id: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 2, 0];
        let sys_uptime: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];
        let sys_name: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];
        let sys_services: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 7, 0];
        let vlan_base: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 3, 1, 1];

        let value_for = |o: &[u64]| -> Vec<u8> {
            if o == sys_descr {
                ber::octet(b"Cisco IOS Software, Catalyst 3850")
            } else if o == sys_object_id {
                // 1.3.6.1.4.1.9.1.516 (a Cisco enterprise OID value, tag 0x06).
                ber::oid(&[1, 3, 6, 1, 4, 1, 9, 1, 516])
            } else if o == sys_uptime {
                ber::timeticks(123456)
            } else if o == sys_name {
                ber::octet(b"core-sw-01")
            } else if o == sys_services {
                ber::int(0b10) // datalink
            } else {
                vec![0x05, 0x00] // NULL
            }
        };

        if !is_bulk {
            // System group GET (get_many): echo each requested OID with its canned value.
            let mut out = Vec::new();
            if let Some(o) = first {
                out.extend(ber::varbind(o, &value_for(o)));
            }
            for (o, _) in rest.by_ref() {
                let o = o
                    .iter()
                    .map(|it| it.collect::<Vec<u64>>())
                    .unwrap_or_default();
                out.extend(ber::varbind(&o, &value_for(&o)));
            }
            return out;
        }

        // GETBULK: this fake only populates the Q-BRIDGE static VLAN-name table, returning two
        // rows then end-of-MIB; every other walk gets an immediate end-of-MIB so it terminates.
        let Some(start) = first else {
            return ber::varbind(&[0, 0], &ber::end_of_mib());
        };
        if start.starts_with(vlan_base) || start == vlan_base {
            // Determine where we are: fresh walk (== base) returns the two rows; a continuation
            // (cursor at the last row) returns end-of-MIB.
            let row1: Vec<u64> = [vlan_base, &[1]].concat();
            let row2: Vec<u64> = [vlan_base, &[20]].concat();
            if start == vlan_base {
                let mut out = ber::varbind(&row1, &ber::octet(b"default"));
                out.extend(ber::varbind(&row2, &ber::octet(b"USERS")));
                return out;
            }
            // Past the first batch: signal the end.
            return ber::varbind(&row2, &ber::end_of_mib());
        }
        ber::varbind(start, &ber::end_of_mib())
    }

    #[tokio::test]
    async fn polls_fake_v2c_agent_and_terminates_walks() {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = sock.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let agent = tokio::spawn(fake_agent(sock, cancel.clone()));

        let cfg = SnmpConfig {
            port: addr.port(),
            timeout_ms: 400,
            retries: 1,
            ..SnmpConfig::v2c("public")
        };
        let client = SnmpClient::new(cfg);
        let info = client
            .poll_device(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .await
            .expect("poll should succeed against the fake agent");

        assert_eq!(info.sys_name.as_deref(), Some("core-sw-01"));
        assert!(info.sys_descr.as_deref().unwrap().contains("Catalyst"));
        assert_eq!(info.sys_object_id.as_deref(), Some("1.3.6.1.4.1.9.1.516"));
        assert_eq!(info.role, DeviceRole::Switch);
        // The VLAN walk returned two rows and then terminated cleanly.
        let ids: Vec<u16> = info.vlans.iter().map(|v| v.id).collect();
        assert_eq!(ids, vec![1, 20]);
        assert_eq!(info.vlans[1].name.as_deref(), Some("USERS"));
        assert_eq!(info.vlans[0].switch_name.as_deref(), Some("core-sw-01"));

        cancel.cancel();
        let _ = agent.await;
    }

    #[tokio::test]
    async fn poll_times_out_cleanly_against_dead_port() {
        // Nothing is listening: the poll must fail (not hang) within a bounded time.
        let cfg = SnmpConfig {
            port: 1,
            timeout_ms: 200,
            retries: 0,
            ..SnmpConfig::v2c("public")
        };
        let client = SnmpClient::new(cfg);
        let res = tokio::time::timeout(
            Duration::from_secs(5),
            client.poll_device(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await
        .expect("poll_device must return promptly");
        assert!(res.is_err());
    }
}
