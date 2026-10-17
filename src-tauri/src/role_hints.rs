//! Weak-but-useful role evidence: a table-driven classifier for network gear that never
//! answers SNMP and advertises no CDP / LLDP.
//!
//! Small business switches (Cisco Business / Small Business CBS / SG, Ruijie Reyee, TP-Link
//! JetStream, Netgear ProSAFE, ...) often leave SSH and Telnet disabled and only expose a web
//! UI (80 / 443) and SNMP (UDP 161, frequently disabled or with a private community). The OUI
//! plus "80/443 open" alone cannot tell such a switch from a NAS or a camera, so this module
//! combines several weak signals and only guesses a role when they agree:
//!
//! * **Host names** from every name source (DNS PTR, mDNS, NetBIOS, the user label, the TLS
//!   certificate CN), tokenised on word boundaries: Cisco's default `switch` + 6 hex digits
//!   (strongest when the digits are the device's own MAC tail), model names (`sg350`,
//!   `cbs250`, `catalyst`, `usw-24`, `rg-s2910`, `fortigate`, ...) and generic words
//!   (`switch`, `sw-01`, `rtr`, `gw`, `ap-floor2`, `fw`).
//! * **mDNS / DNS-SD service types** (`_csco-sb._tcp` is advertised by Cisco Small Business
//!   gear; printer / AirPlay / SMB / workstation services mark a host).
//! * **Web identity** ([`webid::identify`] on the title, `Server` header and certificate).
//! * **The OUI vendor class**: dedicated network vendors (Cisco, Juniper, Ruijie, ...) add
//!   weight and may supply a default role; mixed vendors (TP-Link, Netgear, D-Link, Zyxel,
//!   Huawei, ...) add none (their OUIs also cover consumer / end devices); other vendors only
//!   accept a web identification or a vendor-independent product name (pfSense, OPNsense,
//!   FortiGate VM, OpenWrt) running on generic hardware.
//!
//! Host evidence vetoes every guess: SMB / RDP / VNC / AFP / printing ports, a device kind
//! from service discovery (phone, printer, camera, TV, NAS, ...), a SIP or ONVIF identity, a
//! CDP / LLDP telephone, a phone-maker OUI, host-like names (`SEP…` Cisco phones, `laptop`,
//! `desktop`, `iphone`, ...) and host mDNS services.
//!
//! Scores: web identification with a role 4, a strong name 2 (3 with the MAC-tail match), a
//! weak name 1, a network-gear mDNS service or network-OS web UI 1, a dedicated network
//! vendor +1. `>= 4` is a `medium`-confidence role, `>= 2` a `low` one; anything less only
//! leaves "possible network device" evidence on the host. CDP / LLDP / SNMP are `high` and
//! always win in [`Device::merge`](crate::models::Device::merge).

use crate::{
    models::{Capability, Device, DeviceRole, RoleConfidence, RoleSource, DEVICE_KIND_VOIP_PHONE},
    sip, webid,
};

// ---------------------------------------------------------------------------------------------
// Vendor classes
// ---------------------------------------------------------------------------------------------

/// How much an OUI vendor says about network gear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VendorClass {
    /// (Almost) only network equipment; `default_role` when the product line is mostly one
    /// kind of device (Cisco / Ruijie / Juniper: switches, Palo Alto: firewalls).
    Network {
        label: &'static str,
        default_role: Option<DeviceRole>,
    },
    /// Network equipment *and* consumer / end devices (TP-Link, Netgear, Huawei phones, ...).
    Mixed { label: &'static str },
    /// A vendor not known for network gear (Dell, Apple, HP Inc., ...).
    Other,
    /// No vendor (no MAC: routed subnet; randomized MAC; unknown OUI).
    Unknown,
}

use DeviceRole::{AccessPoint as Ap, Firewall as Fw, Router as Rt, Switch as Sw};

/// Dedicated network vendors (needle, label, default role). Order matters: Meraki and
/// Linksys before Cisco.
const NETWORK_VENDORS: &[(&str, &str, Option<DeviceRole>)] = &[
    ("meraki", "Cisco Meraki", None),
    ("cisco", "Cisco", Some(Sw)),
    ("juniper", "Juniper", Some(Sw)),
    ("arista", "Arista", Some(Sw)),
    ("extreme networks", "Extreme Networks", Some(Sw)),
    ("aruba", "Aruba", None),
    ("ruijie", "Ruijie", Some(Sw)),
    ("reyee", "Reyee", Some(Sw)),
    ("h3c", "H3C", Some(Sw)),
    ("mikrotik", "MikroTik", Some(Rt)),
    ("routerboard", "MikroTik", Some(Rt)),
    ("allied telesis", "Allied Telesis", Some(Sw)),
    ("edgecore", "Edgecore", Some(Sw)),
    ("accton", "Edgecore / Accton", Some(Sw)),
    ("brocade", "Brocade", Some(Sw)),
    ("mellanox", "Mellanox", Some(Sw)),
    ("dell emc networking", "Dell Networking", Some(Sw)),
    ("force10", "Dell Networking", Some(Sw)),
    ("hirschmann", "Hirschmann", Some(Sw)),
    ("ruckus", "Ruckus", None),
    ("cambium", "Cambium", None),
    ("fortinet", "Fortinet", None),
    ("palo alto", "Palo Alto Networks", Some(Fw)),
    ("sonicwall", "SonicWall", Some(Fw)),
    ("watchguard", "WatchGuard", Some(Fw)),
    ("ubiquiti", "Ubiquiti", None),
];

/// Vendors that make network gear and consumer / end devices.
const MIXED_VENDORS: &[(&str, &str)] = &[
    ("linksys", "Linksys"),
    ("tp-link", "TP-Link"),
    ("tp link", "TP-Link"),
    ("netgear", "Netgear"),
    ("d-link", "D-Link"),
    ("zyxel", "Zyxel"),
    ("huawei", "Huawei"),
    ("grandstream", "Grandstream"),
    ("hewlett packard enterprise", "HPE"),
    ("alcatel-lucent", "Alcatel-Lucent"),
    ("planet technology", "Planet"),
    ("sophos", "Sophos"),
    ("tenda", "Tenda"),
    ("zte", "ZTE"),
];

/// Classify an OUI vendor name.
pub fn vendor_class(vendor: Option<&str>) -> VendorClass {
    let Some(v) = vendor.map(str::trim).filter(|v| !v.is_empty()) else {
        return VendorClass::Unknown;
    };
    let v = v.to_ascii_lowercase();
    // Cisco's OUIs also cover Linksys consumer routers and Scientific-Atlanta set-top boxes.
    if v.contains("linksys") {
        return VendorClass::Mixed { label: "Linksys" };
    }
    if v.contains("spvtg") || v.contains("scientific") {
        return VendorClass::Other;
    }
    if let Some((_, label, default_role)) = NETWORK_VENDORS.iter().find(|(n, _, _)| v.contains(n)) {
        return VendorClass::Network {
            label,
            default_role: *default_role,
        };
    }
    if let Some((_, label)) = MIXED_VENDORS.iter().find(|(n, _)| v.contains(n)) {
        return VendorClass::Mixed { label };
    }
    VendorClass::Other
}

// ---------------------------------------------------------------------------------------------
// Host-name tokens
// ---------------------------------------------------------------------------------------------

/// How specific a name hint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NameStrength {
    /// A generic word (`switch`, `sw01`, `rtr`, `gw`, `ap`, `fw`).
    Weak,
    /// A model / product name or a vendor default host name (`sg350`, `catalyst`,
    /// `switch375bc6`, `usw-24`).
    Strong,
    /// A product that runs on generic hardware (pfSense, OPNsense, FortiGate VM, OpenWrt):
    /// believable with any vendor OUI.
    VendorIndependent,
}

/// What one host name says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameHint {
    /// The name marks an end device (Cisco `SEP…` phone, laptop, printer, ...).
    Host(&'static str),
    Role {
        role: DeviceRole,
        strength: NameStrength,
        /// Why, e.g. "Cisco Business default host name".
        why: &'static str,
        /// `true` when the name embeds the device's own MAC tail (Cisco's `switchXXXXXX`).
        mac_match: bool,
    },
}

/// The first DNS label of `name`, lowercase (`SwitchFA634C.local` -> `switchfa634c`).
pub fn first_label(name: &str) -> String {
    let n = name.trim().trim_end_matches('.');
    n.split('.').next().unwrap_or("").to_ascii_lowercase()
}

/// Word-boundary tokens of the first label (`sw-core_01` -> `sw`, `core`, `01`).
pub fn name_tokens(name: &str) -> Vec<String> {
    first_label(name)
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

/// `tok` is `prefix` followed by a digit and then anything (`sg350x` for `sg`).
fn model(tok: &str, prefix: &str) -> bool {
    tok.strip_prefix(prefix)
        .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
}

/// `tok` is `word` optionally followed by digits only (`sw`, `sw1`, `sw01`).
fn word_num(tok: &str, word: &str) -> bool {
    tok.strip_prefix(word)
        .is_some_and(|rest| rest.is_empty() || all_digits(rest))
}

/// Lowercase hex of the last three MAC octets (`aa:bb:cc:37:5b:c6` -> `375bc6`).
fn mac_tail(mac: Option<&str>) -> Option<String> {
    let hex: String = mac?
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_ascii_lowercase();
    (hex.len() == 12).then(|| hex[6..].to_string())
}

/// Tokens that mark an end device.
const HOST_WORDS: &[&str] = &[
    "laptop",
    "notebook",
    "desktop",
    "workstation",
    "macbook",
    "imac",
    "iphone",
    "ipad",
    "android",
    "galaxy",
    "pixel",
    "printer",
    "phone",
    "camera",
    "cam",
    "nvr",
    "dvr",
    "nas",
    "tv",
    "chromecast",
    "roku",
    "xbox",
    "playstation",
    "pc",
];

/// Classify one host name (`mac` lets Cisco's default `switchXXXXXX` be checked against the
/// device's own address).
pub fn classify_name(name: &str, mac: Option<&str>) -> Option<NameHint> {
    let label = first_label(name);
    let toks = name_tokens(name);
    if toks.is_empty() {
        return None;
    }
    let strong = |role, why| NameHint::Role {
        role,
        strength: NameStrength::Strong,
        why,
        mac_match: false,
    };
    let weak = |role, why| NameHint::Role {
        role,
        strength: NameStrength::Weak,
        why,
        mac_match: false,
    };
    let independent = |role, why| NameHint::Role {
        role,
        strength: NameStrength::VendorIndependent,
        why,
        mac_match: false,
    };

    // End devices first: Cisco IP phones (`SEP` + MAC), HP / Brother printer defaults,
    // Windows / Mac names.
    if let Some(rest) = label.strip_prefix("sep") {
        if rest.len() == 12 && is_hex(rest) {
            return Some(NameHint::Host("Cisco IP phone name (SEP + MAC)"));
        }
    }
    for p in ["npi", "brw", "brn"] {
        if label
            .strip_prefix(p)
            .is_some_and(|r| r.len() >= 6 && is_hex(r))
        {
            return Some(NameHint::Host("printer default name"));
        }
    }
    if toks
        .iter()
        .any(|t| HOST_WORDS.iter().any(|w| word_num(t, w)))
    {
        return Some(NameHint::Host("host-like name"));
    }

    // Vendor default host names: Cisco Business / Small Business "switch" / "router" + the
    // last 3 MAC octets.
    for (word, role) in [("switch", Sw), ("router", Rt)] {
        if let Some(rest) = label.strip_prefix(word) {
            if rest.len() == 6 && is_hex(rest) {
                let mac_match = mac_tail(mac).is_some_and(|t| t == rest);
                return Some(NameHint::Role {
                    role,
                    strength: NameStrength::Strong,
                    why: if role == Sw {
                        "Cisco Business default switch host name"
                    } else {
                        "Cisco Business default router host name"
                    },
                    mac_match,
                });
            }
        }
    }

    // Products on generic hardware.
    for t in &toks {
        match t.as_str() {
            "pfsense" => return Some(independent(Fw, "pfSense default host name")),
            "opnsense" => return Some(independent(Fw, "OPNsense default host name")),
            "openwrt" => return Some(independent(Rt, "OpenWrt default host name")),
            "vyos" => return Some(independent(Rt, "VyOS host name")),
            _ => {}
        }
        if t == "fortigate" || model(t, "fgt") || model(t, "fgvm") {
            return Some(independent(Fw, "FortiGate host name"));
        }
    }

    // Model / product names. APs and firewalls before switches (an "ap" model is not a
    // switch), with the token *following* a short vendor prefix (`rg-rap2200`, `ws-c2960`).
    for (i, t) in toks.iter().enumerate() {
        let next = toks.get(i + 1).map(String::as_str).unwrap_or("");
        let t = t.as_str();
        if t == "aironet"
            || t == "uap"
            || t == "u6"
            || t == "u7"
            || model(t, "eap")
            || model(t, "nwa")
            || model(t, "cbw")
            || model(t, "gwn76")
            || (t == "rg" && (model(next, "rap") || model(next, "ap") || model(next, "eap")))
            || (t == "dap" && all_digits(next))
        {
            return Some(strong(Ap, "access-point model name"));
        }
        if t == "sonicwall"
            || t == "firebox"
            || t == "zywall"
            || model(t, "asa")
            || (t == "pa" && all_digits(next) && next.len() >= 3)
        {
            return Some(strong(Fw, "firewall model name"));
        }
        if t == "catalyst"
            || t == "nexus"
            || t == "procurve"
            || t == "jetstream"
            || t == "fortiswitch"
            || t == "edgeswitch"
            || t == "usw"
            || t == "prosafe"
            || model(t, "cbs")
            || (model(t, "sg") && t.len() >= 5)
            || (model(t, "sf") && t.len() >= 5)
            || model(t, "c9200")
            || model(t, "c9300")
            || model(t, "c9500")
            || model(t, "c3850")
            || model(t, "c2960")
            || model(t, "c1000")
            || model(t, "icx")
            || model(t, "crs")
            || model(t, "css")
            || model(t, "xgs")
            || (model(t, "gs") && t.len() >= 5)
            || (model(t, "ex") && t.len() >= 6)
            || model(t, "gwn78")
            || (t == "ws" && model(next, "c"))
            || (t == "tl" && model(next, "sg"))
            || ((t == "dgs" || t == "dxs") && all_digits(next))
            || (t == "rg" && (model(next, "s") || model(next, "es") || model(next, "nbs")))
        {
            return Some(strong(Sw, "switch model name"));
        }
        if t == "edgerouter"
            || t == "udm"
            || t == "uxg"
            || t == "usg"
            || model(t, "isr")
            || model(t, "asr")
            || model(t, "rv")
            || model(t, "ccr")
            || model(t, "rb")
            || model(t, "gwn70")
            || (t == "rg" && model(next, "eg"))
        {
            return Some(strong(Rt, "router / gateway model name"));
        }
    }

    // Generic words (weak).
    for (i, t) in toks.iter().enumerate() {
        let next = toks.get(i + 1).map(String::as_str).unwrap_or("");
        let t = t.as_str();
        if word_num(t, "switch") || word_num(t, "sw") || t == "lsw" {
            return Some(weak(Sw, "host name says switch"));
        }
        if word_num(t, "firewall") || word_num(t, "fw") {
            return Some(weak(Fw, "host name says firewall"));
        }
        if word_num(t, "router") || word_num(t, "rtr") || word_num(t, "gw") || t == "gateway" {
            return Some(weak(Rt, "host name says router / gateway"));
        }
        if word_num(t, "ap")
            || word_num(t, "wap")
            || t == "accesspoint"
            || (t == "access" && next == "point")
        {
            return Some(weak(Ap, "host name says access point"));
        }
    }
    None
}

// ---------------------------------------------------------------------------------------------
// mDNS services
// ---------------------------------------------------------------------------------------------

/// DNS-SD service types advertised by network gear (no role implied).
const NETWORK_SERVICES: &[(&str, &str)] = &[
    ("_csco-sb", "Cisco Small Business"),
    ("_cisco-sb", "Cisco Small Business"),
];

/// DNS-SD service types that mark an end device (printers, Apple / Google media, file
/// sharing, workstations).
const HOST_SERVICES: &[&str] = &[
    "_ipp.",
    "_ipps.",
    "_printer.",
    "_pdl-datastream.",
    "_scanner.",
    "_uscan.",
    "_uscans.",
    "_smb.",
    "_afpovertcp.",
    "_adisk.",
    "_rfb.",
    "_airplay.",
    "_raop.",
    "_googlecast.",
    "_companion-link.",
    "_homekit.",
    "_hap.",
    "_spotify-connect.",
    "_sleep-proxy.",
    "_apple-mobdev2.",
    "_device-info.",
    "_workstation.",
    "_amzn-wplay.",
];

fn network_service(svc: &str) -> Option<&'static str> {
    NETWORK_SERVICES
        .iter()
        .find(|(p, _)| svc.starts_with(p))
        .map(|(_, label)| *label)
}

fn host_service(svc: &str) -> bool {
    HOST_SERVICES.iter().any(|p| svc.starts_with(p))
}

// ---------------------------------------------------------------------------------------------
// Classifier
// ---------------------------------------------------------------------------------------------

/// Device kinds from service discovery that are network gear (everything else is an end
/// device and vetoes a guess).
const NETWORK_KINDS: &[&str] = &["igd_router", "router", "switch", "access_point", "firewall"];

/// TCP ports a network device typically manages over.
const MGMT_PORTS: &[u16] = &[
    22, 23, 80, 161, 443, 830, 2000, 4786, 8080, 8291, 8443, 8728,
];

/// Ports that mark a general-purpose host or a printer (as the enricher's fingerprint veto).
const HOST_PORTS: &[u16] = &[139, 445, 548, 3389, 5900, 515, 631, 9100];

/// The classifier's verdict for one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleGuess {
    /// `None`: no role guessed (only "possible network device" evidence).
    pub role: Option<DeviceRole>,
    pub source: RoleSource,
    pub confidence: RoleConfidence,
    pub evidence: Vec<String>,
}

/// Why a device is an end device, when it is.
fn host_veto(d: &Device) -> Option<String> {
    if let Some(p) = d.open_ports.iter().find(|p| HOST_PORTS.contains(p)) {
        return Some(format!("host port {p} open"));
    }
    if let Some(k) = d.device_kind.as_deref() {
        if !NETWORK_KINDS.contains(&k) {
            return Some(format!("device kind {k}"));
        }
    }
    if d.sip.is_some() {
        return Some("SIP identity".into());
    }
    if d.onvif
        .as_ref()
        .is_some_and(|o| o.is_camera || o.is_windows)
    {
        return Some("ONVIF / WS-Discovery identity".into());
    }
    if d.neighbor
        .as_ref()
        .is_some_and(|n| n.capabilities.contains(&Capability::Telephone))
    {
        return Some("CDP / LLDP telephone".into());
    }
    if d.vendor.as_deref().is_some_and(sip::is_voip_vendor_strict) {
        return Some("phone-maker OUI".into());
    }
    if let Some(s) = d
        .mdns_services
        .iter()
        .find(|s| host_service(&format!("{s}.")))
    {
        return Some(format!("mDNS service {s}"));
    }
    None
}

/// Every name the device is known by, with where it came from.
fn names(d: &Device, user_label: Option<&str>) -> Vec<(&'static str, String)> {
    let mut v: Vec<(&'static str, String)> = Vec::new();
    let mut push = |src: &'static str, n: Option<&str>| {
        if let Some(n) = n.map(str::trim).filter(|n| !n.is_empty()) {
            v.push((src, n.to_string()));
        }
    };
    push("user label", user_label.or(d.hostname.as_deref()));
    push("mDNS name", d.mdns_name.as_deref());
    push("DNS name", d.dns_name.as_deref());
    push("NetBIOS name", d.smb_name.as_deref());
    push(
        "TLS certificate CN",
        d.tls_cert.as_ref().and_then(|c| c.subject_cn.as_deref()),
    );
    v
}

/// One weighted signal.
struct Signal {
    role: Option<DeviceRole>,
    weight: u8,
    source: RoleSource,
    why: String,
}

/// Guess `d`'s role from the weak evidence it carries (see the module docs). `user_label` is
/// the user's host name override, when the caller has one. Returns `None` when there is
/// nothing to say (an end device, or no network hint at all).
pub fn classify(d: &Device, user_label: Option<&str>) -> Option<RoleGuess> {
    if host_veto(d).is_some() {
        return None;
    }
    let class = vendor_class(d.vendor.as_deref());
    let mut signals: Vec<Signal> = Vec::new();

    // Host names.
    for (src, name) in names(d, user_label) {
        match classify_name(&name, d.mac.as_deref()) {
            Some(NameHint::Host(_)) => return None,
            Some(NameHint::Role {
                role,
                strength,
                why,
                mac_match,
            }) => {
                let counts = match class {
                    VendorClass::Other => strength == NameStrength::VendorIndependent,
                    _ => true,
                };
                if !counts {
                    continue;
                }
                let weight = match strength {
                    NameStrength::Weak => 1,
                    _ if mac_match => 3,
                    _ => 2,
                };
                let tail = if mac_match { ", matching its MAC" } else { "" };
                signals.push(Signal {
                    role: Some(role),
                    weight,
                    source: RoleSource::Name,
                    why: format!("{src} '{name}': {why}{tail}"),
                });
            }
            None => {}
        }
    }

    // mDNS service types.
    for svc in &d.mdns_services {
        if let Some(label) = network_service(svc) {
            signals.push(Signal {
                role: None,
                weight: 1,
                source: RoleSource::MdnsService,
                why: format!("mDNS service {svc} ({label} network gear)"),
            });
            break;
        }
    }

    // Web identity (title / Server header / certificate).
    let mut texts: Vec<&str> = Vec::new();
    texts.extend(d.web_identity.as_deref());
    texts.extend(d.web_title.as_deref());
    texts.extend(d.web_server.as_deref());
    if let Some(c) = &d.tls_cert {
        texts.extend(c.subject.as_deref());
        texts.extend(c.issuer.as_deref());
    }
    if !texts.is_empty() {
        match webid::identify(&texts) {
            Some((identity, Some(role))) => signals.push(Signal {
                role: Some(role),
                weight: 4,
                source: RoleSource::Web,
                why: format!("web UI identified as {identity}"),
            }),
            Some((identity, None)) if webid::NETWORK_IDENTITIES.contains(&identity) => signals
                .push(Signal {
                    role: None,
                    weight: 1,
                    source: RoleSource::Web,
                    why: format!("web UI is {identity} (network equipment)"),
                }),
            _ => {}
        }
    }

    // Vendor / ports context lines.
    let (vendor_bonus, default_role, vendor_line) = match class {
        VendorClass::Network {
            label,
            default_role,
        } => (
            1,
            default_role,
            Some(format!("{label} OUI (network vendor)")),
        ),
        VendorClass::Mixed { label } => (
            0,
            None,
            Some(format!("{label} OUI (also makes end devices)")),
        ),
        _ => (0, None, None),
    };
    let ports_line = (!d.open_ports.is_empty()
        && d.open_ports.iter().all(|p| MGMT_PORTS.contains(p)))
    .then(|| {
        let list: Vec<String> = d.open_ports.iter().map(u16::to_string).collect();
        format!("management ports only ({})", list.join(", "))
    });

    // Pick the role: the largest total weight; ties go to the single strongest signal, then
    // to the role priority. Role-less signals (network service / network-OS web UI) support
    // the chosen role, or the vendor's default role when nothing names one.
    let roles = [Fw, Sw, Ap, Rt];
    let total = |r: DeviceRole| -> u8 {
        signals
            .iter()
            .filter(|s| s.role == Some(r))
            .map(|s| s.weight)
            .sum()
    };
    let best_of = |r: DeviceRole| -> u8 {
        signals
            .iter()
            .filter(|s| s.role == Some(r))
            .map(|s| s.weight)
            .max()
            .unwrap_or(0)
    };
    let named = roles
        .into_iter()
        .filter(|r| total(*r) > 0)
        .max_by_key(|r| (total(*r), best_of(*r), r.priority()));
    let generic: u8 = signals
        .iter()
        .filter(|s| s.role.is_none())
        .map(|s| s.weight)
        .sum();
    let role = named.or(if generic > 0 { default_role } else { None });

    let Some(role) = role else {
        // No role: leave a hint on dedicated network-vendor hosts (or any host with a
        // network signal) so the user can see why it might be gear.
        let mut evidence: Vec<String> = Vec::new();
        let label = match class {
            VendorClass::Network { label, .. } => Some(label),
            VendorClass::Mixed { label } if generic > 0 => Some(label),
            _ => None,
        };
        if label.is_none() && generic == 0 {
            return None;
        }
        evidence.push(match label {
            Some(l) => format!("possible network device: {l} OUI"),
            None => "possible network device".to_string(),
        });
        evidence.extend(signals.iter().map(|s| s.why.clone()));
        if label.is_none() {
            evidence.extend(vendor_line);
        }
        evidence.extend(ports_line);
        return Some(RoleGuess {
            role: None,
            source: RoleSource::OuiPorts,
            confidence: RoleConfidence::Low,
            evidence,
        });
    };

    let score = total(role) + generic + vendor_bonus;
    let confidence = match score {
        s if s >= 4 => RoleConfidence::Medium,
        s if s >= 2 => RoleConfidence::Low,
        _ => {
            // Too weak to guess: keep the hint.
            let mut evidence = vec![format!("possible {}", role.label().to_ascii_lowercase())];
            evidence.extend(signals.iter().map(|s| s.why.clone()));
            evidence.extend(vendor_line);
            evidence.extend(ports_line);
            return Some(RoleGuess {
                role: None,
                source: RoleSource::Name,
                confidence: RoleConfidence::Low,
                evidence,
            });
        }
    };
    // Source: the strongest signal for the role (or the strongest role-less one).
    let lead = signals
        .iter()
        .filter(|s| s.role == Some(role))
        .max_by_key(|s| s.weight)
        .or_else(|| {
            signals
                .iter()
                .filter(|s| s.role.is_none())
                .max_by_key(|s| s.weight)
        });
    let source = lead.map_or(RoleSource::OuiPorts, |s| s.source);
    let mut evidence: Vec<String> = signals
        .iter()
        .filter(|s| s.role == Some(role) || s.role.is_none())
        .map(|s| s.why.clone())
        .collect();
    if named.is_none() {
        evidence.push(format!(
            "{} is the vendor's usual role",
            role.label().to_ascii_lowercase()
        ));
    }
    evidence.extend(vendor_line);
    evidence.extend(ports_line);
    Some(RoleGuess {
        role: Some(role),
        source,
        confidence,
        evidence,
    })
}

/// The sparse update [`classify`] implies for `d` (same key), or `None` when it adds nothing
/// (the merge then decides whether a guessed role beats what the device already has). Also
/// marks a phone-maker OUI host as a `voip_phone` when nothing else identified it.
pub fn guess_update(d: &Device, user_label: Option<&str>) -> Option<Device> {
    let mut update = Device::new(d.ip);
    update.vlan_id = d.vlan_id;
    update.sources.clear();
    let mut changed = false;
    if let Some(g) = classify(d, user_label) {
        match g.role {
            Some(role) => {
                let better = d.effective_role_confidence() < Some(g.confidence)
                    || d.role == role
                    || !d.role.is_infrastructure();
                if better {
                    update.set_role(role, g.source, g.confidence, g.evidence);
                    changed = true;
                }
            }
            None if !d.role.is_infrastructure() => {
                for e in g.evidence {
                    if !d.role_evidence.contains(&e) {
                        update.add_role_evidence(e);
                        changed = true;
                    }
                }
            }
            None => {}
        }
    }
    if d.device_kind.is_none()
        && d.sip.is_none()
        && !d.role.is_infrastructure()
        && d.vendor.as_deref().is_some_and(is_phone_only_vendor)
        && !d.open_ports.iter().any(|p| HOST_PORTS.contains(p))
    {
        update.device_kind = Some(DEVICE_KIND_VOIP_PHONE.to_string());
        changed = true;
    }
    changed.then_some(update)
}

/// Phone makers whose OUIs are (practically) only IP phones (unlike Grandstream, which also
/// makes GWN switches / APs and UCM PBXes).
pub fn is_phone_only_vendor(vendor: &str) -> bool {
    let v = vendor.to_ascii_lowercase();
    sip::is_voip_vendor_strict(vendor)
        && [
            "yealink",
            "snom",
            "polycom",
            "fanvil",
            "htek",
            "spectralink",
            "aastra",
        ]
        .iter()
        .any(|n| v.contains(n))
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CdpLldpNeighbor, NeighborProtocol, SipInfo};

    const CISCO: &str = "Cisco Systems, Inc";

    fn dev(vendor: Option<&str>, mac: Option<&str>, ports: &[u16]) -> Device {
        let mut d = Device::new("10.10.60.5".parse().unwrap());
        d.vendor = vendor.map(str::to_string);
        d.mac = mac.map(str::to_string);
        d.open_ports = ports.to_vec();
        d
    }

    fn role_of(d: &Device) -> Option<(DeviceRole, RoleConfidence)> {
        classify(d, None).and_then(|g| g.role.map(|r| (r, g.confidence)))
    }

    #[test]
    fn name_tokenisation_edge_cases() {
        assert_eq!(first_label("SwitchFA634C.local."), "switchfa634c");
        assert_eq!(
            name_tokens("sw-core_01.corp.example.com"),
            ["sw", "core", "01"]
        );
        assert_eq!(name_tokens("  "), Vec::<String>::new());
        // Only the first label counts: "gw" in the domain is not this host's name.
        assert_eq!(
            classify_name("pc12.gw.example.com", None),
            Some(NameHint::Host("host-like name"))
        );
        assert_eq!(classify_name("build12.gw.example.com", None), None);
        // Word boundaries: "swim", "sweden", "gwen", "apple", "fwd" are not hints.
        for n in [
            "swim-01",
            "sweden",
            "gwen",
            "apple-tv-box",
            "fwd-proxy",
            "swarm",
            "rtx4090",
        ] {
            assert!(
                !matches!(classify_name(n, None), Some(NameHint::Role { .. })),
                "{n} must not be a role hint"
            );
        }
        let role = |n: &str| match classify_name(n, None) {
            Some(NameHint::Role { role, strength, .. }) => Some((role, strength)),
            _ => None,
        };
        use NameStrength::{Strong, VendorIndependent, Weak};
        assert_eq!(role("SWITCH2.local"), Some((Sw, Weak)));
        assert_eq!(role("sw01"), Some((Sw, Weak)));
        assert_eq!(role("core-sw"), Some((Sw, Weak)));
        assert_eq!(role("switch375bc6.local"), Some((Sw, Strong)));
        assert_eq!(role("SwitchFA634C.local"), Some((Sw, Strong)));
        assert_eq!(role("router1a2b3c"), Some((Rt, Strong)));
        assert_eq!(role("SG350-28P"), Some((Sw, Strong)));
        assert_eq!(role("cbs250-lab"), Some((Sw, Strong)));
        assert_eq!(role("catalyst-idf2"), Some((Sw, Strong)));
        assert_eq!(role("ws-c2960x-1"), Some((Sw, Strong)));
        assert_eq!(role("USW-24-PoE"), Some((Sw, Strong)));
        assert_eq!(role("rg-s2910-24gt"), Some((Sw, Strong)));
        assert_eq!(role("RG-RAP2200"), Some((Ap, Strong)));
        assert_eq!(role("rg-eg105g"), Some((Rt, Strong)));
        assert_eq!(role("AP-floor2"), Some((Ap, Weak)));
        assert_eq!(role("wap3"), Some((Ap, Weak)));
        assert_eq!(role("edge-rtr"), Some((Rt, Weak)));
        assert_eq!(role("gw01"), Some((Rt, Weak)));
        assert_eq!(role("fw-dmz"), Some((Fw, Weak)));
        assert_eq!(role("pfSense.home.arpa"), Some((Fw, VendorIndependent)));
        assert_eq!(role("FGT60F1234567890"), Some((Fw, VendorIndependent)));
        // MAC tail match.
        assert!(matches!(
            classify_name("switch375bc6.local", Some("70:1f:53:37:5b:c6")),
            Some(NameHint::Role {
                mac_match: true,
                ..
            })
        ));
        assert!(matches!(
            classify_name("switch375bc6.local", Some("70:1f:53:00:00:01")),
            Some(NameHint::Role {
                mac_match: false,
                ..
            })
        ));
        // Not 6 hex digits: just the generic word.
        assert_eq!(role("switch12345"), Some((Sw, Weak)));
        // Host names.
        assert_eq!(
            classify_name("SEP001122334455", None),
            Some(NameHint::Host("Cisco IP phone name (SEP + MAC)"))
        );
        assert!(matches!(
            classify_name("switch-test-laptop", None),
            Some(NameHint::Host(_))
        ));
        assert!(matches!(
            classify_name("NPI8A1B2C", None),
            Some(NameHint::Host(_))
        ));
        assert!(matches!(
            classify_name("DESKTOP-4KQ2ABC", None),
            Some(NameHint::Host(_))
        ));
    }

    #[test]
    fn vendor_classes() {
        assert!(matches!(
            vendor_class(Some(CISCO)),
            VendorClass::Network {
                default_role: Some(Sw),
                ..
            }
        ));
        assert!(matches!(
            vendor_class(Some("Cisco Meraki")),
            VendorClass::Network {
                default_role: None,
                ..
            }
        ));
        assert!(matches!(
            vendor_class(Some("Cisco-Linksys, LLC")),
            VendorClass::Mixed { .. }
        ));
        assert!(matches!(
            vendor_class(Some("Ruijie Networks Co.,LTD")),
            VendorClass::Network {
                label: "Ruijie",
                default_role: Some(Sw)
            }
        ));
        assert!(matches!(
            vendor_class(Some("TP-LINK TECHNOLOGIES CO.,LTD.")),
            VendorClass::Mixed { .. }
        ));
        assert_eq!(vendor_class(Some("Dell Inc.")), VendorClass::Other);
        assert_eq!(vendor_class(None), VendorClass::Unknown);
        assert!(crate::enricher::is_network_vendor(
            "Ruijie Networks Co.,LTD"
        ));
    }

    /// The reported case: Cisco Business switches named `switchXXXXXX` / `SwitchXXXXXX` over
    /// mDNS with only the web UI open (or nothing open, or only "161" in the TCP list).
    #[test]
    fn cisco_business_switch_with_default_name_is_a_switch() {
        for ports in [&[80, 443][..], &[], &[161], &[443]] {
            let mut d = dev(Some(CISCO), None, ports);
            d.mdns_name = Some("switch375bc6.local".into());
            let g = classify(&d, None).expect("a guess");
            assert_eq!(g.role, Some(Sw), "{ports:?}");
            assert_eq!(g.confidence, RoleConfidence::Low, "{ports:?}");
            assert_eq!(g.source, RoleSource::Name);
            assert!(
                g.evidence[0].contains("mDNS name 'switch375bc6.local'"),
                "{:?}",
                g.evidence
            );
            assert!(g.evidence.iter().any(|e| e == "Cisco OUI (network vendor)"));
        }
        // With the MAC tail matching (the usual case) it is a medium-confidence switch.
        let mut d = dev(Some(CISCO), Some("70:1f:53:fa:63:4c"), &[80, 443]);
        d.mdns_name = Some("SwitchFA634C.local".into());
        assert_eq!(role_of(&d), Some((Sw, RoleConfidence::Medium)));
        // The Cisco Small Business mDNS service adds weight too.
        let mut d = dev(Some(CISCO), None, &[443]);
        d.mdns_name = Some("switch375bc6.local".into());
        d.mdns_services = vec!["_csco-sb._tcp".into(), "_http._tcp".into()];
        assert_eq!(role_of(&d), Some((Sw, RoleConfidence::Medium)));
        // The service alone (no telling name) is a low guess using Cisco's usual role.
        let mut d = dev(Some(CISCO), None, &[80, 443]);
        d.mdns_services = vec!["_csco-sb._tcp".into()];
        let g = classify(&d, None).unwrap();
        assert_eq!(
            (g.role, g.confidence, g.source),
            (Some(Sw), RoleConfidence::Low, RoleSource::MdnsService)
        );
        // "SWITCH2.local": a generic word plus the Cisco OUI.
        let mut d = dev(Some(CISCO), None, &[22, 443]);
        d.mdns_name = Some("SWITCH2.local".into());
        assert_eq!(role_of(&d), Some((Sw, RoleConfidence::Low)));
        // A Cisco Business web UI is a medium-confidence switch on its own.
        let mut d = dev(Some(CISCO), None, &[443]);
        d.web_title = Some("CBS350-24P-4G".into());
        assert_eq!(role_of(&d), Some((Sw, RoleConfidence::Medium)));
    }

    #[test]
    fn cisco_oui_with_web_ports_alone_stays_host_with_a_hint() {
        let d = dev(Some(CISCO), None, &[80, 443]);
        let g = classify(&d, None).unwrap();
        assert_eq!(g.role, None);
        assert_eq!(g.evidence[0], "possible network device: Cisco OUI");
        assert!(g
            .evidence
            .iter()
            .any(|e| e == "management ports only (80, 443)"));
        let u = guess_update(&d, None).unwrap();
        assert_eq!(u.role, DeviceRole::Host);
        assert_eq!(u.role_confidence, None);
        assert!(!u.role_evidence.is_empty());
    }

    #[test]
    fn negative_cases_stay_hosts() {
        // Cisco IP phone.
        let mut phone = dev(Some(CISCO), None, &[80]);
        phone.dns_name = Some("SEP001122334455".into());
        assert_eq!(classify(&phone, None), None);
        // A phone found by SIP / CDP telephone, even with a switch-like name.
        let mut sipd = dev(Some(CISCO), None, &[]);
        sipd.mdns_name = Some("switch375bc6.local".into());
        sipd.sip = Some(SipInfo::default());
        assert_eq!(classify(&sipd, None), None);
        let mut cdp_phone = dev(Some(CISCO), None, &[]);
        cdp_phone.smb_name = Some("SW1".into());
        cdp_phone.neighbor = Some(CdpLldpNeighbor {
            protocol: NeighborProtocol::Cdp,
            local_interface: "en7".into(),
            source_mac: "00:11:22:33:44:55".into(),
            device_id: "SEP001122334455".into(),
            system_name: None,
            system_description: None,
            port_id: None,
            port_description: None,
            platform: Some("Cisco IP Phone 8845".into()),
            software_version: None,
            management_addrs: vec![],
            native_vlan: None,
            voice_vlan: Some(20),
            capabilities: vec![Capability::Telephone, Capability::Switch],
            vtp_domain: None,
            poe_watts: None,
            poe_info: None,
            ttl_secs: 120,
            last_seen_ms: 0,
        });
        assert_eq!(classify(&cdp_phone, None), None);
        // Cisco AP: an access point (low), never a switch.
        let mut ap = dev(Some(CISCO), None, &[22, 80, 443]);
        ap.dns_name = Some("AP-floor2.corp.example".into());
        assert_eq!(role_of(&ap), Some((Ap, RoleConfidence::Low)));
        // Meraki: no default role, so no guess from the OUI + ports.
        let meraki = dev(Some("Cisco Meraki"), None, &[80, 443]);
        assert_eq!(classify(&meraki, None).unwrap().role, None);
        // A Dell laptop named like a switch: not a network vendor.
        let mut dell = dev(Some("Dell Inc."), None, &[22, 443]);
        dell.dns_name = Some("switch-test-laptop".into());
        assert_eq!(classify(&dell, None), None);
        let mut dell2 = dev(Some("Dell Inc."), None, &[22, 443]);
        dell2.dns_name = Some("switch-test".into());
        assert_eq!(classify(&dell2, None), None);
        // HP printer (JetDirect port) even with a "switch" name.
        let mut hp = dev(Some("HP Inc."), None, &[80, 443, 9100]);
        hp.mdns_name = Some("switch-room-printer.local".into());
        assert_eq!(classify(&hp, None), None);
        // Hosts with SMB / RDP ports.
        let mut smb = dev(Some(CISCO), None, &[22, 445]);
        smb.dns_name = Some("sw-core".into());
        assert_eq!(classify(&smb, None), None);
        let mut rdp = dev(Some(CISCO), None, &[3389]);
        rdp.dns_name = Some("switch375bc6".into());
        assert_eq!(classify(&rdp, None), None);
        // Printer mDNS services.
        let mut ipp = dev(Some(CISCO), None, &[80]);
        ipp.mdns_services = vec!["_ipp._tcp".into()];
        ipp.mdns_name = Some("switch375bc6.local".into());
        assert_eq!(classify(&ipp, None), None);
        // FortiSwitch / FortiAP / UniFi switch OUI + ports: no guess (only a hint).
        for v in ["Fortinet, Inc.", "Ubiquiti Inc"] {
            assert_eq!(
                classify(&dev(Some(v), None, &[22, 443]), None)
                    .unwrap()
                    .role,
                None,
                "{v}"
            );
        }
        // ...but their product names are switches / APs.
        let mut usw = dev(Some("Ubiquiti Inc"), None, &[22, 443]);
        usw.mdns_name = Some("USW-24-PoE.local".into());
        assert_eq!(role_of(&usw), Some((Sw, RoleConfidence::Low)));
        // Device kinds from service discovery veto.
        let mut cam = dev(Some(CISCO), None, &[80]);
        cam.device_kind = Some("camera".into());
        cam.dns_name = Some("sw1".into());
        assert_eq!(classify(&cam, None), None);
        // A generic word with no vendor is not enough; an unknown vendor needs a product name.
        let mut anon = dev(None, None, &[22]);
        anon.dns_name = Some("sw-core-01.corp.example.com".into());
        assert_eq!(role_of(&anon), None);
        anon.dns_name = Some("catalyst-core".into());
        assert_eq!(role_of(&anon), Some((Sw, RoleConfidence::Low)));
        // pfSense on generic hardware.
        let mut pf = dev(Some("Super Micro Computer, Inc."), None, &[443]);
        pf.dns_name = Some("pfsense.home.arpa".into());
        assert_eq!(role_of(&pf), Some((Fw, RoleConfidence::Low)));
    }

    #[test]
    fn ruijie_and_small_switch_vendors() {
        const RUIJIE: &str = "Ruijie Networks Co.,LTD";
        // Only 80 open + a Reyee web title: a low-confidence switch.
        let mut r = dev(Some(RUIJIE), Some("ec:b9:70:c8:75:6b"), &[80]);
        r.web_title = Some("Reyee".into());
        let g = classify(&r, None).unwrap();
        assert_eq!((g.role, g.confidence), (Some(Sw), RoleConfidence::Low));
        assert!(
            g.evidence.iter().any(|e| e.contains("Ruijie / Reyee")),
            "{:?}",
            g.evidence
        );
        // The EWEB UI naming a switch model: medium.
        r.web_title = Some("Ruijie EWEB - RG-ES226GC-P".into());
        assert_eq!(role_of(&r), Some((Sw, RoleConfidence::Medium)));
        // An AP model in the title: access point.
        r.web_title = Some("Reyee RG-RAP2260(G)".into());
        assert_eq!(role_of(&r), Some((Ap, RoleConfidence::Medium)));
        // A gateway.
        r.web_title = Some("Ruijie Reyee EG105GW".into());
        assert_eq!(role_of(&r), Some((Rt, RoleConfidence::Medium)));
        // Nothing open, no name: stays Host, flagged as a possible network device.
        let bare = dev(Some(RUIJIE), Some("c0:b8:e6:e4:52:52"), &[]);
        let g = classify(&bare, None).unwrap();
        assert_eq!(g.role, None);
        assert_eq!(
            g.evidence,
            vec!["possible network device: Ruijie OUI".to_string()]
        );
        let u = guess_update(&bare, None).unwrap();
        assert_eq!(u.role, DeviceRole::Host);
        assert_eq!(u.role_evidence, g.evidence);
        // TP-Link consumer device with host ports: Host, no hint at all.
        let mut tp = dev(Some("TP-LINK TECHNOLOGIES CO.,LTD."), None, &[80, 445]);
        tp.mdns_name = Some("switch-hub.local".into());
        assert_eq!(classify(&tp, None), None);
        // A TP-Link OUI with only a generic name: no guess (mixed vendor).
        let mut tp2 = dev(Some("TP-LINK TECHNOLOGIES CO.,LTD."), None, &[80]);
        tp2.dns_name = Some("switch".into());
        assert_eq!(role_of(&tp2), None);
        // ...but a JetStream web UI is a switch.
        tp2.web_title = Some("TL-SG3428 JetStream 24-Port Gigabit L2+ Managed Switch".into());
        assert_eq!(role_of(&tp2), Some((Sw, RoleConfidence::Medium)));
        // Netgear: a model name is a low guess; a consumer router with no hint is nothing.
        let mut ng = dev(Some("NETGEAR"), None, &[80]);
        ng.dns_name = Some("gs724tp-lab".into());
        assert_eq!(role_of(&ng), Some((Sw, RoleConfidence::Low)));
        assert_eq!(
            classify(&dev(Some("NETGEAR"), None, &[80, 443]), None),
            None
        );
    }

    #[test]
    fn yealink_phone_gets_a_device_kind_but_no_role() {
        let d = dev(
            Some("Yealink(Xiamen) Network Technology Co.,Ltd."),
            None,
            &[],
        );
        assert_eq!(classify(&d, None), None);
        let u = guess_update(&d, None).unwrap();
        assert_eq!(u.device_kind.as_deref(), Some(DEVICE_KIND_VOIP_PHONE));
        assert_eq!(u.role, DeviceRole::Host);
        // Grandstream also makes switches / APs: no kind from the OUI alone.
        let gs = dev(Some("Grandstream Networks, Inc."), None, &[]);
        assert!(guess_update(&gs, None).is_none_or(|u| u.device_kind.is_none()));
    }

    #[test]
    fn guess_update_respects_better_evidence() {
        let mut d = dev(Some(CISCO), None, &[80, 443]);
        d.mdns_name = Some("switch375bc6.local".into());
        // Already a high-confidence router from SNMP: the low switch guess is not proposed.
        d.set_role(
            Rt,
            RoleSource::Snmp,
            RoleConfidence::High,
            vec!["snmp".into()],
        );
        assert!(guess_update(&d, None).is_none());
        // A plain host gets it.
        let mut h = d.clone();
        h.role = DeviceRole::Host;
        h.role_source = None;
        h.role_confidence = None;
        h.role_evidence.clear();
        let u = guess_update(&h, None).unwrap();
        assert_eq!(u.role, Sw);
        let mut merged = h.clone();
        merged.merge(&u);
        assert_eq!(merged.role_source, Some(RoleSource::Name));
        // SNMP answering later wins over the guess.
        let mut snmp = Device::new(h.ip);
        snmp.set_role(
            Rt,
            RoleSource::Snmp,
            RoleConfidence::High,
            vec!["sysDescr".into()],
        );
        merged.merge(&snmp);
        assert_eq!(merged.role, Rt);
        assert_eq!(merged.role_confidence, Some(RoleConfidence::High));
        // A user label counts as a name source.
        let plain = dev(Some(CISCO), None, &[80]);
        assert_eq!(
            classify(&plain, Some("idf2-switch")).and_then(|g| g.role),
            Some(Sw)
        );
    }
}
