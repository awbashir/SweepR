//! WS-Discovery (UDP 3702) + ONVIF device identification.
//!
//! Sends a WS-Discovery `Probe` (SOAP over UDP multicast, unique `MessageID`) to
//! `239.255.255.250:3702`, collects `ProbeMatches` / `Hello` for a bounded window, and parses
//! their `XAddrs` / `Types` / `Scopes`. Windows hosts answer WSD (`wsdp:Device` / `pub:Computer`);
//! ONVIF cameras answer as `dn:NetworkVideoTransmitter` / `tds:Device`.
//!
//! For a camera, the device's own `GetDeviceInformation` (and, best-effort, `GetServices`) is
//! queried over HTTP at its `XAddr` — but only when the `XAddr` host is the IP that answered
//! (no SSRF), and never with any credentials. An RTSP URL is reported only when the device
//! itself returns one; otherwise clearly-labelled vendor RTSP URL *templates* are offered as
//! guesses (no credential or default-password probing).
//!
//! Parsing is done with a hardened `quick-xml` reader; pure functions are unit tested, and the
//! SOAP request/response path is tested against a local HTTP responder.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use futures::StreamExt;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_util::sync::CancellationToken;

use crate::{
    limits::SocketBudget,
    models::{now_ms, sanitize_text, sanitize_text_max, OnvifInfo, MAX_SERVICE_LIST, MAX_URL_LEN},
    ssdp::{
        connect_addr, exchange_udp, for_each_xml_text, host_header, local_name, parse_http_url,
        read_http_response, url_host_is, DiscoveryTarget, FetchCtx, HttpUrl, CONCURRENT_FETCHES,
    },
};

/// `XAddrs` of one responder that are queried (after de-duplication).
const MAX_XADDRS_TRIED: usize = 2;

const WSD_MCAST_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
/// WS-Discovery port.
pub const WSD_PORT: u16 = 3702;
const MAX_SOAP_BYTES: usize = 128 * 1024;

/// Generate a pseudo-random `urn:uuid:` for a WS-Discovery `MessageID`. Not cryptographic; it
/// only needs to be unique per probe so responders' `RelatesTo` can be matched if desired.
pub fn message_id() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut state =
        now_ms() ^ (u64::from(std::process::id()) << 32) ^ seq.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut next = || {
        // xorshift64
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let a = next();
    let b = next();
    format!(
        "urn:uuid:{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (a >> 32) as u32,
        (a >> 16) as u16,
        (a as u16) & 0x0fff,
        ((b >> 48) as u16 & 0x3fff) | 0x8000,
        b & 0xffff_ffff_ffff,
    )
}

/// Build a WS-Discovery `Probe` SOAP envelope (matches any device: no Types filter).
pub fn build_probe(message_id: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <s:Header>
    <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
    <a:MessageID>{message_id}</a:MessageID>
    <a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
  </s:Header>
  <s:Body><d:Probe/></s:Body>
</s:Envelope>"#
    )
    .into_bytes()
}

/// One WS-Discovery responder's advertisement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WsdMatch {
    pub xaddrs: Vec<String>,
    pub types: Option<String>,
    pub scopes: Vec<String>,
    pub endpoint: Option<String>,
}

/// Parse a WS-Discovery `ProbeMatches` / `Hello` SOAP message. Collects `XAddrs` (space list),
/// `Types`, `Scopes` (space list) and the endpoint `Address`. Hardened reader, bounded output.
pub fn parse_wsd_match(xml: &[u8]) -> Option<WsdMatch> {
    let mut m = WsdMatch::default();
    for_each_xml_text(xml, |path, value| {
        // Split the list first, then cap each item (a URL may be long; capping the whole
        // list would cut URLs / scopes in half).
        let push_words = |list: &mut Vec<String>| {
            for w in value.split_whitespace() {
                if list.len() >= MAX_SERVICE_LIST {
                    break;
                }
                let w = sanitize_text_max(w, MAX_URL_LEN);
                if !w.is_empty() && !list.contains(&w) {
                    list.push(w);
                }
            }
        };
        match path.last().map(String::as_str) {
            Some("xaddrs") => push_words(&mut m.xaddrs),
            Some("types") if m.types.is_none() => m.types = Some(sanitize_text(value)),
            Some("scopes") => push_words(&mut m.scopes),
            Some("address") if m.endpoint.is_none() => m.endpoint = Some(sanitize_text(value)),
            _ => {}
        }
    });
    (!m.xaddrs.is_empty() || m.types.is_some() || !m.scopes.is_empty()).then_some(m)
}

/// `(is_camera, is_windows)` from the advertised `Types`.
pub fn classify_wsd(types: Option<&str>, scopes: &[String]) -> (bool, bool) {
    let t = types.unwrap_or("").to_ascii_lowercase();
    let scope_blob = scopes.join(" ").to_ascii_lowercase();
    let is_camera = t.contains("networkvideotransmitter")
        || t.contains("networkvideodisplay")
        || scope_blob.contains("onvif://");
    let is_windows = t.contains("computer") || t.contains("publicationservice");
    (is_camera, is_windows)
}

/// Extract `name` / `location` / `hardware` from ONVIF scope URIs
/// (`onvif://www.onvif.org/name/Foo`, `.../location/Bar`, `.../hardware/Baz`).
pub fn onvif_from_scopes(scopes: &[String]) -> (Option<String>, Option<String>, Option<String>) {
    let mut name = None;
    let mut location = None;
    let mut hardware = None;
    for s in scopes {
        let lower = s.to_ascii_lowercase();
        let after = |key: &str| {
            lower
                .find(key)
                .map(|i| decode_scope(&s[i + key.len()..]))
                .filter(|v| !v.is_empty())
        };
        if name.is_none() {
            name = after("/name/");
        }
        if location.is_none() {
            location = after("/location/");
        }
        if hardware.is_none() {
            hardware = after("/hardware/");
        }
    }
    (name, location, hardware)
}

/// Percent-decode a single ONVIF scope component and sanitize it.
fn decode_scope(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    sanitize_text(&String::from_utf8_lossy(&out))
}

/// Build the ONVIF `tds:GetDeviceInformation` SOAP request body (no credentials).
pub fn build_get_device_information() -> Vec<u8> {
    br#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <s:Body><tds:GetDeviceInformation/></s:Body>
</s:Envelope>"#
        .to_vec()
}

/// ONVIF `GetDeviceInformation` response fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OnvifDeviceInformation {
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
    pub serial_number: Option<String>,
    pub hardware_id: Option<String>,
}

impl OnvifDeviceInformation {
    fn is_empty(&self) -> bool {
        self.manufacturer.is_none()
            && self.model.is_none()
            && self.firmware_version.is_none()
            && self.serial_number.is_none()
            && self.hardware_id.is_none()
    }
}

/// Parse a `GetDeviceInformationResponse` SOAP body. Hardened reader.
pub fn parse_get_device_information(xml: &[u8]) -> OnvifDeviceInformation {
    let mut info = OnvifDeviceInformation::default();
    for_each_xml_text(xml, |path, value| {
        let slot = match path.last().map(String::as_str) {
            Some("manufacturer") => &mut info.manufacturer,
            Some("model") => &mut info.model,
            Some("firmwareversion") => &mut info.firmware_version,
            Some("serialnumber") => &mut info.serial_number,
            Some("hardwareid") => &mut info.hardware_id,
            _ => return,
        };
        if slot.is_none() {
            let v = sanitize_text(value);
            if !v.is_empty() {
                *slot = Some(v);
            }
        }
    });
    info
}

/// Remove `user:password@` from a URL's authority, so camera credentials a device embeds in
/// its stream URL are never stored, shown or exported.
pub fn strip_userinfo(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    match authority.rfind('@') {
        Some(i) => format!("{scheme}://{}{tail}", &authority[i + 1..]),
        None => url.to_string(),
    }
}

/// Extract the first `<tt:Uri>` / `<Uri>` value from an ONVIF `GetStreamUriResponse`, only when
/// it is an `rtsp://` URL (what the device itself reported; never a guess). Embedded
/// credentials are stripped.
pub fn parse_stream_uri(xml: &[u8]) -> Option<String> {
    let mut uri = None;
    for_each_xml_text(xml, |path, value| {
        if uri.is_none()
            && path.last().map(String::as_str) == Some("uri")
            && value.trim().to_ascii_lowercase().starts_with("rtsp://")
        {
            uri = Some(strip_userinfo(&sanitize_text_max(value, MAX_URL_LEN)));
        }
    });
    uri
}

/// SOAP envelope around one ONVIF request body element.
fn soap_envelope(ns: &str, body: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" {ns}>
  <s:Body>{body}</s:Body>
</s:Envelope>"#
    )
    .into_bytes()
}

const NS_TDS: &str = r#"xmlns:tds="http://www.onvif.org/ver10/device/wsdl""#;
const NS_TRT: &str = r#"xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema""#;

/// ONVIF `tds:GetCapabilities` (all categories), unauthenticated.
pub fn build_get_capabilities() -> Vec<u8> {
    soap_envelope(
        NS_TDS,
        "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>",
    )
}

/// ONVIF Media `trt:GetProfiles`, unauthenticated.
pub fn build_get_profiles() -> Vec<u8> {
    soap_envelope(NS_TRT, "<trt:GetProfiles/>")
}

/// ONVIF Media `trt:GetStreamUri` for `token` (RTP-Unicast over RTSP). `token` must already be
/// validated by [`valid_profile_token`].
pub fn build_get_stream_uri(token: &str) -> Vec<u8> {
    soap_envelope(
        NS_TRT,
        &format!(
            "<trt:GetStreamUri><trt:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream>\
             <tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup>\
             <trt:ProfileToken>{token}</trt:ProfileToken></trt:GetStreamUri>"
        ),
    )
}

/// A device-supplied profile token is echoed back into our request, so only plain tokens are
/// accepted (no markup can be injected into the SOAP body).
pub fn valid_profile_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 64
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
}

/// The Media service `XAddr` from a `GetCapabilitiesResponse` (`.../Media/XAddr`).
pub fn parse_media_xaddr(xml: &[u8]) -> Option<String> {
    let mut xaddr = None;
    for_each_xml_text(xml, |path, value| {
        if xaddr.is_none()
            && path.last().map(String::as_str) == Some("xaddr")
            && path.iter().any(|p| p == "media")
        {
            xaddr = Some(sanitize_text_max(value, MAX_URL_LEN));
        }
    });
    xaddr
}

/// The `token` attribute of the first `<trt:Profiles>` element of a `GetProfilesResponse`.
pub fn first_profile_token(xml: &[u8]) -> Option<String> {
    use quick_xml::{events::Event, Reader};
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().check_end_names = false;
    let mut buf = Vec::new();
    for _ in 0..100_000 {
        let Ok(event) = reader.read_event_into(&mut buf) else {
            return None;
        };
        match event {
            Event::Start(e) | Event::Empty(e) if local_name(e.name().as_ref()) == "profiles" => {
                let attr = e.try_get_attribute("token").ok()??;
                let token = sanitize_text(&attr.value);
                return valid_profile_token(&token).then_some(token);
            }
            Event::Eof => return None,
            _ => {}
        }
        buf.clear();
    }
    None
}

/// Vendor RTSP URL *templates*, clearly labelled as guesses (never credentials). Picked from
/// the manufacturer / model so the drawer can show likely stream URLs without us connecting.
pub fn rtsp_hints(manufacturer: Option<&str>, model: Option<&str>, host: &str) -> Vec<String> {
    let hay =
        format!("{} {}", manufacturer.unwrap_or(""), model.unwrap_or("")).to_ascii_lowercase();
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let label = |path: &str| format!("rtsp://{host}:554{path} (guess, no credentials tried)");
    if hay.contains("hikvision") {
        vec![label("/Streaming/Channels/101")]
    } else if hay.contains("dahua") {
        vec![label("/cam/realmonitor?channel=1&subtype=0")]
    } else if hay.contains("axis") {
        vec![label("/axis-media/media.amp")]
    } else if hay.contains("reolink") {
        vec![label("/h264Preview_01_main")]
    } else if hay.contains("amcrest") {
        vec![label("/cam/realmonitor?channel=1&subtype=0")]
    } else {
        // Unknown vendor: offer the two most common templates.
        vec![
            label("/Streaming/Channels/101"),
            label("/cam/realmonitor?channel=1&subtype=0"),
        ]
    }
}

/// Discover WS-Discovery / ONVIF devices for `window` over IPv4 multicast from the interface
/// address `v4` and, when `v6_index` is given, IPv6 multicast (`ff02::c` / `ff05::c`), then
/// query each camera over HTTP (SSRF-guarded, no credentials). Only replies from `scope` (the
/// addresses of the devices the scan discovered) are kept and queried; follow-up requests are
/// bounded per responder and per run ([`FetchCtx`]).
pub async fn discover_wsd(
    v4: Option<Ipv4Addr>,
    v6_index: Option<u32>,
    window: Duration,
    scope: &HashSet<IpAddr>,
    budget: &SocketBudget,
    cancel: &CancellationToken,
) -> HashMap<IpAddr, OnvifInfo> {
    let payloads = vec![build_probe(&message_id())];
    let exchange = |t: DiscoveryTarget| {
        exchange_udp(
            t,
            WSD_PORT,
            WSD_MCAST_V4,
            &payloads,
            window,
            Some(scope),
            budget,
            cancel,
        )
    };
    let v4_fut = async {
        match v4 {
            Some(ip) => exchange(DiscoveryTarget::MulticastV4(ip)).await,
            None => Vec::new(),
        }
    };
    let v6_fut = async {
        match v6_index {
            Some(index) => exchange(DiscoveryTarget::MulticastV6(index)).await,
            None => Vec::new(),
        }
    };
    let (a, b) = tokio::join!(v4_fut, v6_fut);
    let ctx = FetchCtx::run(budget, cancel, v6_index.unwrap_or(0));
    identify_responders(a.into_iter().chain(b), ctx).await
}

/// Unicast WS-Discovery probe of one host (`Probe` straight to `ip:3702`), for the drawer.
pub async fn probe_wsd_host(
    ip: IpAddr,
    window: Duration,
    budget: &SocketBudget,
    cancel: &CancellationToken,
) -> Option<OnvifInfo> {
    let payloads = vec![build_probe(&message_id())];
    let t = DiscoveryTarget::Unicast(ip);
    let replies = exchange_udp(
        t,
        WSD_PORT,
        WSD_MCAST_V4,
        &payloads,
        window,
        None,
        budget,
        cancel,
    )
    .await;
    identify_responders(replies, FetchCtx::run(budget, cancel, 0))
        .await
        .remove(&ip)
}

/// Parse reply datagrams into per-responder matches and build [`OnvifInfo`] for each, querying
/// cameras for their identity and (unauthenticated) stream URL within `ctx`'s deadline (and
/// the per-responder budget).
pub(crate) async fn identify_responders(
    replies: impl IntoIterator<Item = (IpAddr, Vec<u8>)>,
    ctx: FetchCtx<'_>,
) -> HashMap<IpAddr, OnvifInfo> {
    let mut matches: HashMap<IpAddr, WsdMatch> = HashMap::new();
    for (ip, datagram) in replies {
        if let Some(m) = parse_wsd_match(&datagram) {
            matches.entry(ip).or_insert(m);
        }
    }
    futures::stream::iter(matches)
        .map(|(ip, m)| async move { (ip, identify_one(ip, m, ctx.responder()).await) })
        .buffer_unordered(CONCURRENT_FETCHES)
        .collect()
        .await
}

/// Build the [`OnvifInfo`] of one responder: cameras get `GetDeviceInformation` and a stream
/// URI attempt; other WSD devices (Windows hosts, printers) get a WS-Transfer metadata `Get`
/// for their name / model. All requests go to the responder's own address, unauthenticated,
/// and stop at `ctx.deadline` (what was learned until then is kept).
async fn identify_one(ip: IpAddr, m: WsdMatch, ctx: FetchCtx<'_>) -> OnvifInfo {
    let (is_camera, is_windows) = classify_wsd(m.types.as_deref(), &m.scopes);
    let (name, location, hardware) = onvif_from_scopes(&m.scopes);
    let mut info = OnvifInfo {
        xaddrs: m.xaddrs.clone(),
        types: m.types.clone(),
        scopes: m.scopes.clone(),
        name,
        location,
        hardware_id: hardware,
        is_camera,
        is_windows,
        ..OnvifInfo::default()
    };
    if ctx.cancel.is_cancelled() {
        return info;
    }
    if is_camera {
        if let Some(di) = query_device_information(ip, &m.xaddrs, ctx).await {
            info.manufacturer = di.manufacturer.or(info.manufacturer);
            info.model = di.model.or(info.model);
            info.firmware_version = di.firmware_version;
            info.serial_number = di.serial_number;
            info.hardware_id = di.hardware_id.or(info.hardware_id);
        }
        info.rtsp_url = query_stream_uri(ip, &m.xaddrs, ctx).await;
        // Templates only when the device did not report its own stream URL.
        if info.rtsp_url.is_none() {
            info.rtsp_hints = rtsp_hints(
                info.manufacturer.as_deref(),
                info.model.as_deref(),
                &ip.to_string(),
            );
        }
    } else if let Some(endpoint) = m.endpoint.as_deref().filter(|e| valid_endpoint(e)) {
        if let Some(meta) = query_metadata(ip, endpoint, &m.xaddrs, ctx).await {
            info.name = meta.computer.or(meta.friendly_name).or(info.name);
            info.manufacturer = meta.manufacturer.or(info.manufacturer);
            info.model = meta.model.or(info.model);
            info.serial_number = meta.serial_number.or(info.serial_number);
            info.firmware_version = meta.firmware.or(info.firmware_version);
            if info.name.is_some() && m.types.as_deref().is_some_and(|t| t.contains("Computer")) {
                info.is_windows = true;
            }
        }
    }
    info
}

/// A WSD endpoint reference is echoed into our `wsa:To`, so only a plain URN is accepted.
pub fn valid_endpoint(endpoint: &str) -> bool {
    endpoint.len() <= 128
        && endpoint.starts_with("urn:")
        && endpoint
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '.' | '_'))
}

/// WS-Transfer `Get` (device metadata) addressed to `endpoint`.
pub fn build_metadata_get(endpoint: &str, message_id: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <s:Header>
    <a:To>{endpoint}</a:To>
    <a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>
    <a:MessageID>{message_id}</a:MessageID>
    <a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
  </s:Header>
  <s:Body/>
</s:Envelope>"#
    )
    .into_bytes()
}

/// Identity fields from a WS-Transfer `GetResponse` (DPWS `ThisModel` / `ThisDevice` and the
/// Windows `pub:Computer` relationship, e.g. `DESKTOP-1/Workgroup:WORKGROUP`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WsdMetadata {
    /// Computer name (the part before `/` of `pub:Computer`).
    pub computer: Option<String>,
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub firmware: Option<String>,
}

/// Parse a WS-Transfer `GetResponse` metadata document.
pub fn parse_metadata(xml: &[u8]) -> WsdMetadata {
    let mut meta = WsdMetadata::default();
    for_each_xml_text(xml, |path, value| {
        let slot = match path.last().map(String::as_str) {
            Some("computer") => {
                if meta.computer.is_none() {
                    let name = sanitize_text(value.split('/').next().unwrap_or(value));
                    if !name.is_empty() {
                        meta.computer = Some(name);
                    }
                }
                return;
            }
            Some("friendlyname") => &mut meta.friendly_name,
            Some("manufacturer") => &mut meta.manufacturer,
            Some("modelname") => &mut meta.model,
            Some("serialnumber") => &mut meta.serial_number,
            Some("firmwareversion") => &mut meta.firmware,
            _ => return,
        };
        if slot.is_none() {
            let v = sanitize_text(value);
            if !v.is_empty() {
                *slot = Some(v);
            }
        }
    });
    meta
}

/// Fetch WSD metadata from the responder's own `XAddr` (Windows hosts serve it on 5357).
async fn query_metadata(
    responder: IpAddr,
    endpoint: &str,
    xaddrs: &[String],
    ctx: FetchCtx<'_>,
) -> Option<WsdMetadata> {
    let request = build_metadata_get(endpoint, &message_id());
    for url in own_xaddrs(responder, xaddrs) {
        let action = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get";
        if let Some(body) = soap_call(responder, &url, &request, action, ctx).await {
            let meta = parse_metadata(&body);
            if meta != WsdMetadata::default() {
                return Some(meta);
            }
        }
    }
    None
}

/// Query the first usable `XAddr` whose host is the responder itself for
/// `GetDeviceInformation`. No credentials are ever sent.
async fn query_device_information(
    responder: IpAddr,
    xaddrs: &[String],
    ctx: FetchCtx<'_>,
) -> Option<OnvifDeviceInformation> {
    let request = build_get_device_information();
    for url in own_xaddrs(responder, xaddrs) {
        let action = "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation";
        if let Some(body) = soap_call(responder, &url, &request, action, ctx).await {
            let di = parse_get_device_information(&body);
            if !di.is_empty() {
                return Some(di);
            }
        }
    }
    None
}

/// The device's `XAddrs` that point at the responder itself (SSRF guard), parsed,
/// de-duplicated and limited to [`MAX_XADDRS_TRIED`].
fn own_xaddrs(responder: IpAddr, xaddrs: &[String]) -> Vec<HttpUrl> {
    let mut out: Vec<HttpUrl> = Vec::new();
    for u in xaddrs
        .iter()
        .filter_map(|x| parse_http_url(x))
        .filter(|u| url_host_is(u, responder))
    {
        if out.len() >= MAX_XADDRS_TRIED {
            break;
        }
        if !out.contains(&u) {
            out.push(u);
        }
    }
    out
}

/// Ask the camera, unauthenticated, for its RTSP stream URL: `GetCapabilities` (Media XAddr) →
/// `GetProfiles` (first token) → `GetStreamUri`. Most cameras require authentication for the
/// media service; then this returns `None` and only labelled templates are shown. Every request
/// goes to the responder's own address.
async fn query_stream_uri(
    responder: IpAddr,
    xaddrs: &[String],
    ctx: FetchCtx<'_>,
) -> Option<String> {
    let device = own_xaddrs(responder, xaddrs).into_iter().next()?;
    let caps = soap_call(
        responder,
        &device,
        &build_get_capabilities(),
        "http://www.onvif.org/ver10/device/wsdl/GetCapabilities",
        ctx,
    )
    .await;
    // The Media service XAddr, when reported and on the same host; else the device service.
    let media = caps
        .as_deref()
        .and_then(parse_media_xaddr)
        .and_then(|x| parse_http_url(&x))
        .filter(|u| url_host_is(u, responder))
        .unwrap_or(device);
    let profiles = soap_call(
        responder,
        &media,
        &build_get_profiles(),
        "http://www.onvif.org/ver10/media/wsdl/GetProfiles",
        ctx,
    )
    .await?;
    let token = first_profile_token(&profiles)?;
    let stream = soap_call(
        responder,
        &media,
        &build_get_stream_uri(&token),
        "http://www.onvif.org/ver10/media/wsdl/GetStreamUri",
        ctx,
    )
    .await?;
    parse_stream_uri(&stream)
}

/// One SOAP request to `url` on `responder`, holding a socket permit, cancellable and bounded
/// by `ctx`'s deadline.
async fn soap_call(
    responder: IpAddr,
    url: &HttpUrl,
    body: &[u8],
    action: &str,
    ctx: FetchCtx<'_>,
) -> Option<Vec<u8>> {
    if !url_host_is(url, responder) || tokio::time::Instant::now() >= ctx.deadline {
        return None;
    }
    let _permit = ctx.budget.acquire().await?;
    tokio::select! {
        _ = ctx.cancel.cancelled() => None,
        r = tokio::time::timeout_at(
            ctx.request_deadline(),
            soap_post(responder, url, body, action, ctx.scope_id),
        ) => r.ok().flatten(),
    }
}

/// POST a SOAP request to `ip:url.port` for `url.path`, returning the response body (bounded;
/// `Content-Length` and chunked bodies are honoured). The caller bounds the time.
async fn soap_post(
    ip: IpAddr,
    url: &HttpUrl,
    body: &[u8],
    action: &str,
    scope_id: u32,
) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect(connect_addr(ip, url.port, scope_id))
        .await
        .ok()?;
    let req = format!(
        "POST {} HTTP/1.0\r\nHost: {}\r\n\
         Content-Type: application/soap+xml; charset=utf-8; action=\"{}\"\r\n\
         Content-Length: {}\r\nUser-Agent: SweepR/1.0\r\nConnection: close\r\n\r\n",
        url.path,
        host_header(&url.host, url.port),
        action,
        body.len()
    );
    // One write: some embedded HTTP stacks answer after their first read and close, which
    // would reset a separate body write.
    let mut request = req.into_bytes();
    request.extend_from_slice(body);
    stream.write_all(&request).await.ok()?;
    // The status is not checked: some cameras answer 200, some 400 with a SOAP fault that
    // still names the device.
    read_http_response(&mut stream, MAX_SOAP_BYTES)
        .await
        .map(|m| m.body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn message_ids_are_unique_and_well_formed() {
        let a = message_id();
        let b = message_id();
        assert_ne!(a, b);
        assert!(a.starts_with("urn:uuid:"));
        let hex = a.trim_start_matches("urn:uuid:");
        // 8-4-4-4-12 with a version-4 marker.
        let parts: Vec<&str> = hex.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(parts[2].starts_with('4'));
    }

    #[test]
    fn probe_is_well_formed() {
        let p = String::from_utf8(build_probe("urn:uuid:test")).unwrap();
        assert!(p.contains("<d:Probe/>"));
        assert!(p.contains("discovery/Probe"));
        assert!(p.contains("<a:MessageID>urn:uuid:test</a:MessageID>"));
    }

    const CAMERA_MATCH: &[u8] = br#"<?xml version="1.0"?>
      <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
          xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
          xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
          xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
        <s:Body><d:ProbeMatches><d:ProbeMatch>
          <a:EndpointReference><a:Address>urn:uuid:1419d68a-1dd2-11b2-a105-00408c184d1a</a:Address></a:EndpointReference>
          <d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>
          <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/name/HIKVISION%20DS-2CD2042 onvif://www.onvif.org/hardware/DS-2CD2042WD onvif://www.onvif.org/location/Lobby</d:Scopes>
          <d:XAddrs>http://192.168.1.50/onvif/device_service</d:XAddrs>
          <d:MetadataVersion>1</d:MetadataVersion>
        </d:ProbeMatch></d:ProbeMatches></s:Body>
      </s:Envelope>"#;

    #[test]
    fn parses_camera_probe_match() {
        let m = parse_wsd_match(CAMERA_MATCH).unwrap();
        assert_eq!(m.xaddrs, vec!["http://192.168.1.50/onvif/device_service"]);
        assert!(m
            .types
            .as_deref()
            .unwrap()
            .contains("NetworkVideoTransmitter"));
        assert!(m.scopes.iter().any(|s| s.contains("/name/")));
        assert!(m.endpoint.as_deref().unwrap().starts_with("urn:uuid:"));
        let (cam, win) = classify_wsd(m.types.as_deref(), &m.scopes);
        assert!(cam && !win);
        let (name, location, hardware) = onvif_from_scopes(&m.scopes);
        assert_eq!(name.as_deref(), Some("HIKVISION DS-2CD2042")); // %20 decoded
        assert_eq!(location.as_deref(), Some("Lobby"));
        assert_eq!(hardware.as_deref(), Some("DS-2CD2042WD"));
    }

    #[test]
    fn classifies_windows_host() {
        let types = Some("wsdp:Device pub:Computer");
        let (cam, win) = classify_wsd(types, &[]);
        assert!(!cam && win);
    }

    #[test]
    fn rtsp_hints_are_labelled_guesses() {
        let h = rtsp_hints(Some("Hikvision"), Some("DS-2CD2042"), "192.168.1.50");
        assert_eq!(h.len(), 1);
        assert!(h[0].contains("/Streaming/Channels/101"));
        assert!(h[0].contains("guess"));
        // Unknown vendor: two common templates, still labelled.
        let h = rtsp_hints(None, None, "10.0.0.9");
        assert_eq!(h.len(), 2);
        assert!(h.iter().all(|s| s.contains("guess")));
    }

    const DEVICE_INFO_RESPONSE: &[u8] = br#"<?xml version="1.0"?>
      <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
          xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
        <s:Body><tds:GetDeviceInformationResponse>
          <tds:Manufacturer>HIKVISION</tds:Manufacturer>
          <tds:Model>DS-2CD2042WD-I</tds:Model>
          <tds:FirmwareVersion>V5.4.5 build 170123</tds:FirmwareVersion>
          <tds:SerialNumber>DS-2CD2042WD0120170101</tds:SerialNumber>
          <tds:HardwareId>88</tds:HardwareId>
        </tds:GetDeviceInformationResponse></s:Body>
      </s:Envelope>"#;

    #[test]
    fn parses_get_device_information() {
        let di = parse_get_device_information(DEVICE_INFO_RESPONSE);
        assert_eq!(di.manufacturer.as_deref(), Some("HIKVISION"));
        assert_eq!(di.model.as_deref(), Some("DS-2CD2042WD-I"));
        assert!(di.firmware_version.as_deref().unwrap().contains("V5.4.5"));
        assert_eq!(di.serial_number.as_deref(), Some("DS-2CD2042WD0120170101"));
        assert_eq!(di.hardware_id.as_deref(), Some("88"));
    }

    /// The ONVIF SOAP POST + parse against a local HTTP responder (host == 127.0.0.1).
    #[tokio::test]
    async fn queries_device_information_from_local_responder() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut b = [0u8; 2048];
                let _ = s.read(&mut b).await;
                let body = DEVICE_INFO_RESPONSE;
                let resp = format!(
                    "HTTP/1.0 200 OK\r\nContent-Type: application/soap+xml\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.write_all(body).await;
            }
        });
        let xaddr = format!("http://127.0.0.1:{port}/onvif/device_service");
        let (budget, cancel) = (SocketBudget::new(2), CancellationToken::new());
        let di = query_device_information(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[xaddr],
            FetchCtx::run(&budget, &cancel, 0),
        )
        .await
        .expect("device info query should succeed");
        assert_eq!(di.manufacturer.as_deref(), Some("HIKVISION"));
        assert_eq!(di.model.as_deref(), Some("DS-2CD2042WD-I"));
        let _ = server.await;
    }

    /// A fake ONVIF device service on loopback: answers each SOAP request by its body.
    async fn fake_onvif(listener: tokio::net::TcpListener, port: u16, with_stream: bool) {
        for _ in 0..8 {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let mut raw = Vec::new();
            let mut chunk = [0u8; 4096];
            // Read headers + body (Content-Length bounded by our own small requests).
            while let Ok(n) = s.read(&mut chunk).await {
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&chunk[..n]);
                if raw.windows(12).any(|w| w == b"</s:Envelope") || raw.len() > 16_384 {
                    break;
                }
            }
            let req = String::from_utf8_lossy(&raw);
            let body = if req.contains("GetDeviceInformation") {
                String::from_utf8_lossy(DEVICE_INFO_RESPONSE).into_owned()
            } else if req.contains("GetCapabilities") {
                format!(
                    "<s:Envelope xmlns:s=\"x\" xmlns:tt=\"y\"><s:Body><tds:GetCapabilitiesResponse>\
                     <tds:Capabilities><tt:Media><tt:XAddr>http://127.0.0.1:{port}/onvif/Media\
                     </tt:XAddr></tt:Media></tds:Capabilities></tds:GetCapabilitiesResponse>\
                     </s:Body></s:Envelope>"
                )
            } else if req.contains("GetProfiles") && with_stream {
                "<s:Envelope xmlns:s=\"x\"><s:Body><trt:GetProfilesResponse>\
                 <trt:Profiles token=\"Profile_1\" fixed=\"true\"><tt:Name>main</tt:Name>\
                 </trt:Profiles></trt:GetProfilesResponse></s:Body></s:Envelope>"
                    .to_string()
            } else if req.contains("GetStreamUri") && req.contains("Profile_1") {
                "<s:Envelope xmlns:s=\"x\"><s:Body><trt:GetStreamUriResponse><trt:MediaUri>\
                 <tt:Uri>rtsp://127.0.0.1:554/Streaming/Channels/101</tt:Uri>\
                 </trt:MediaUri></trt:GetStreamUriResponse></s:Body></s:Envelope>"
                    .to_string()
            } else {
                // Media service requires authentication: a SOAP fault.
                "<s:Envelope xmlns:s=\"x\"><s:Body><s:Fault><s:Reason>Sender not authorized\
                 </s:Reason></s:Fault></s:Body></s:Envelope>"
                    .to_string()
            };
            let status = if body.contains("Fault") {
                "400 Bad Request"
            } else {
                "200 OK"
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/soap+xml\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes()).await;
        }
    }

    /// End to end on loopback: unicast WS-Discovery Probe to a fake responder, ProbeMatch with
    /// an XAddr on a fake ONVIF service, device information + unauthenticated stream URI.
    #[tokio::test]
    async fn wsd_exchange_and_onvif_identify_against_fake_device() {
        for with_stream in [true, false] {
            let http = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let http_port = http.local_addr().unwrap().port();
            let onvif = tokio::spawn(fake_onvif(http, http_port, with_stream));
            let udp = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let udp_port = udp.local_addr().unwrap().port();
            let responder = tokio::spawn(async move {
                let mut b = [0u8; 4096];
                if let Ok((n, from)) = udp.recv_from(&mut b).await {
                    assert!(String::from_utf8_lossy(&b[..n]).contains("<d:Probe/>"));
                    let reply = String::from_utf8_lossy(CAMERA_MATCH).replace(
                        "http://192.168.1.50/onvif/device_service",
                        &format!("http://127.0.0.1:{http_port}/onvif/device_service"),
                    );
                    let _ = udp.send_to(reply.as_bytes(), from).await;
                }
            });
            let budget = SocketBudget::new(4);
            let cancel = CancellationToken::new();
            let replies = exchange_udp(
                DiscoveryTarget::Unicast(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                udp_port,
                WSD_MCAST_V4,
                &[build_probe(&message_id())],
                Duration::from_millis(400),
                None,
                &budget,
                &cancel,
            )
            .await;
            let map = identify_responders(replies, FetchCtx::run(&budget, &cancel, 0)).await;
            let info = &map[&IpAddr::V4(Ipv4Addr::LOCALHOST)];
            assert!(info.is_camera && !info.is_windows);
            assert_eq!(info.manufacturer.as_deref(), Some("HIKVISION"));
            assert_eq!(
                info.serial_number.as_deref(),
                Some("DS-2CD2042WD0120170101")
            );
            assert_eq!(info.location.as_deref(), Some("Lobby"));
            if with_stream {
                assert_eq!(
                    info.rtsp_url.as_deref(),
                    Some("rtsp://127.0.0.1:554/Streaming/Channels/101")
                );
                assert!(info.rtsp_hints.is_empty());
            } else {
                // Media needs auth: no reported URL, only labelled guesses.
                assert!(info.rtsp_url.is_none());
                assert!(!info.rtsp_hints.is_empty());
                assert!(info.rtsp_hints.iter().all(|h| h.contains("guess")));
            }
            let _ = responder.await;
            onvif.abort();
        }
    }

    #[test]
    fn profile_tokens_are_validated_before_echoing() {
        assert!(valid_profile_token("Profile_1"));
        assert!(valid_profile_token("MainStream.0:1-a"));
        assert!(!valid_profile_token(""));
        assert!(!valid_profile_token("x</trt:ProfileToken><evil/>"));
        assert!(!valid_profile_token(&"a".repeat(65)));
        let xml = br#"<r><trt:Profiles token="bad&lt;tok"/></r>"#;
        assert!(first_profile_token(xml).is_none());
        let xml = br#"<r><trt:Profiles token="ok_1"><x/></trt:Profiles></r>"#;
        assert_eq!(first_profile_token(xml).as_deref(), Some("ok_1"));
        assert!(String::from_utf8(build_get_stream_uri("ok_1"))
            .unwrap()
            .contains("<trt:ProfileToken>ok_1</trt:ProfileToken>"));
    }

    #[test]
    fn parses_windows_metadata_and_validates_endpoints() {
        let xml = br#"<s:Envelope xmlns:s="x" xmlns:wsdp="y" xmlns:pub="z"><s:Body>
          <wsx:Metadata><wsx:MetadataSection>
            <wsdp:ThisModel><wsdp:Manufacturer>Microsoft Corporation</wsdp:Manufacturer>
              <wsdp:ModelName>Windows</wsdp:ModelName></wsdp:ThisModel>
            <wsdp:ThisDevice><wsdp:FriendlyName>Microsoft Publication Service Device Host</wsdp:FriendlyName></wsdp:ThisDevice>
            <wsdp:Relationship><wsdp:Host><pub:Computer>DESKTOP-7Q2/Workgroup:WORKGROUP</pub:Computer></wsdp:Host></wsdp:Relationship>
          </wsx:MetadataSection></wsx:Metadata></s:Body></s:Envelope>"#;
        let meta = parse_metadata(xml);
        assert_eq!(meta.computer.as_deref(), Some("DESKTOP-7Q2"));
        assert_eq!(meta.manufacturer.as_deref(), Some("Microsoft Corporation"));
        assert_eq!(meta.model.as_deref(), Some("Windows"));
        assert!(valid_endpoint(
            "urn:uuid:1419d68a-1dd2-11b2-a105-00408c184d1a"
        ));
        assert!(!valid_endpoint("urn:uuid:x</a:To><evil/>"));
        assert!(!valid_endpoint("http://10.0.0.1/"));
        let get = String::from_utf8(build_metadata_get("urn:uuid:abc", "urn:uuid:m1")).unwrap();
        assert!(get.contains("<a:To>urn:uuid:abc</a:To>"));
        assert!(get.contains("transfer/Get"));
    }

    #[test]
    fn stream_uri_must_be_rtsp() {
        let ok = br#"<e><tt:Uri>rtsp://10.0.0.5:554/live</tt:Uri></e>"#;
        assert_eq!(
            parse_stream_uri(ok).as_deref(),
            Some("rtsp://10.0.0.5:554/live")
        );
        let not_rtsp = br#"<e><tt:Uri>http://10.0.0.5/snapshot.jpg</tt:Uri></e>"#;
        assert!(parse_stream_uri(not_rtsp).is_none());
    }

    #[tokio::test]
    async fn device_query_refuses_foreign_xaddr_host() {
        // XAddr host 10.0.0.1 but responder 127.0.0.1: skipped (no connection).
        let (budget, cancel) = (SocketBudget::new(2), CancellationToken::new());
        let di = query_device_information(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &["http://10.0.0.1/onvif/device_service".to_string()],
            FetchCtx::run(&budget, &cancel, 0),
        )
        .await;
        assert!(di.is_none());
    }

    /// Lists are split before each item is capped, so long XAddrs / ONVIF scopes survive
    /// (review M5); duplicates are dropped.
    #[test]
    fn long_xaddr_and_scope_lists_are_split_before_capping() {
        let many: String = (0..200)
            .map(|i| format!("http://10.0.0.5:{}/onvif/device_service ", 1000 + i))
            .collect();
        let long_scope = format!("onvif://www.onvif.org/name/{}", "N".repeat(400));
        let xml = format!(
            "<a><d:XAddrs>{many} http://10.0.0.5:1000/onvif/device_service</d:XAddrs>\
             <d:Scopes>{long_scope} onvif://www.onvif.org/location/Lobby</d:Scopes></a>"
        );
        let m = parse_wsd_match(xml.as_bytes()).unwrap();
        assert_eq!(m.xaddrs.len(), MAX_SERVICE_LIST);
        assert!(m
            .xaddrs
            .iter()
            .all(|x| x.ends_with("/onvif/device_service")));
        assert_eq!(m.scopes.len(), 2);
        assert_eq!(m.scopes[0], long_scope);
        let (_, location, _) = onvif_from_scopes(&m.scopes);
        assert_eq!(location.as_deref(), Some("Lobby"));
        // At most two distinct own XAddrs are queried.
        let own = own_xaddrs(
            "10.0.0.5".parse().unwrap(),
            &[
                "http://10.0.0.5/a".to_string(),
                "http://10.0.0.5/a".to_string(),
                "http://10.0.0.9/x".to_string(),
                "http://10.0.0.5/b".to_string(),
                "http://10.0.0.5/c".to_string(),
            ],
        );
        let paths: Vec<&str> = own.iter().map(|u| u.path.as_str()).collect();
        assert_eq!(paths, vec!["/a", "/b"]);
    }

    #[test]
    fn stream_uri_credentials_are_stripped() {
        let rtsp = b"<e><tt:Uri>rtsp://admin:Secret123@10.0.0.5:554/live?x=1</tt:Uri></e>";
        let uri = parse_stream_uri(rtsp).unwrap();
        assert_eq!(uri, "rtsp://10.0.0.5:554/live?x=1");
        assert!(!uri.contains("Secret123"));
        assert_eq!(strip_userinfo("rtsp://10.0.0.5/a@b"), "rtsp://10.0.0.5/a@b");
        // IPv6 hosts are bracketed in the templates.
        assert!(rtsp_hints(None, None, "fe80::1")[0].starts_with("rtsp://[fe80::1]:554/"));
    }

    /// A camera that accepts connections on many XAddrs but never answers is bounded by the
    /// per-responder deadline (review M4).
    #[tokio::test]
    async fn stalled_camera_is_bounded() {
        let http = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = http.local_addr().unwrap().port();
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = accepted.clone();
        let stall = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = http.accept().await {
                count.fetch_add(1, Ordering::Relaxed);
                held.push(s);
            }
        });
        let xaddrs: String = (0..20)
            .map(|i| format!("http://127.0.0.1:{port}/onvif/device_service{i} "))
            .collect();
        let reply = String::from_utf8_lossy(CAMERA_MATCH)
            .replace("http://192.168.1.50/onvif/device_service", &xaddrs);
        let (budget, cancel) = (SocketBudget::new(8), CancellationToken::new());
        let ctx = FetchCtx {
            deadline: tokio::time::Instant::now() + Duration::from_millis(1500),
            ..FetchCtx::run(&budget, &cancel, 0)
        };
        let started = std::time::Instant::now();
        let map = identify_responders(
            vec![(IpAddr::V4(Ipv4Addr::LOCALHOST), reply.into_bytes())],
            ctx,
        )
        .await;
        let took = started.elapsed();
        assert!(took < Duration::from_secs(4), "took {took:?}");
        let info = &map[&IpAddr::V4(Ipv4Addr::LOCALHOST)];
        assert!(info.is_camera && info.manufacturer.is_none());
        assert!(accepted.load(Ordering::Relaxed) <= MAX_XADDRS_TRIED + 1);
        stall.abort();
    }
}
