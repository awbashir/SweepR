//! SSDP / UPnP discovery (UDP 1900).
//!
//! Sends SSDP `M-SEARCH` requests to the `239.255.255.250:1900` multicast group (and the IPv6
//! groups when enabled), collects the responders for a bounded window, keeps only responders
//! whose address belongs to a device the scan discovered (the scan scope), then fetches each
//! one's description XML — but **only** when the `LOCATION` URL's host is the IP that
//! answered, over plain HTTP, with a size cap, per-request / per-responder / per-run
//! deadlines and same-origin redirects only. A hostile responder cannot point `LOCATION` at
//! an internal service, and out-of-scope (or spoofed out-of-scope) responders get no request.
//!
//! The XML is parsed with a hardened `quick-xml` pull reader (no DTD / entity expansion, so a
//! "billion laughs" description cannot blow up memory) into model / serial / service data, and
//! every string is run through [`sanitize_text`]. Pure parsers are unit tested; the
//! SSRF-guarded fetch is tested against a local HTTP responder.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    time::Duration,
};

use futures::StreamExt;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::{
    limits::SocketBudget,
    models::{sanitize_text, sanitize_text_max, SsdpInfo, MAX_SERVICE_LIST, MAX_URL_LEN},
};

/// Time one responder's follow-up requests (description fetch, SOAP calls) may take in total.
pub(crate) const PER_RESPONDER_BUDGET: Duration = Duration::from_secs(6);
/// Time all follow-up requests of one discovery run may take after the listen window.
pub(crate) const PER_RUN_BUDGET: Duration = Duration::from_secs(12);
/// Timeout of one HTTP request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(4);

/// What follow-up HTTP requests of a discovery run may do: the socket budget, cancellation,
/// the deadline they must finish by, and the interface index used as the scope of IPv6
/// link-local addresses.
#[derive(Clone, Copy)]
pub(crate) struct FetchCtx<'a> {
    pub budget: &'a SocketBudget,
    pub cancel: &'a CancellationToken,
    pub deadline: Instant,
    pub scope_id: u32,
}

impl<'a> FetchCtx<'a> {
    /// A run context whose deadline is [`PER_RUN_BUDGET`] from now.
    pub fn run(budget: &'a SocketBudget, cancel: &'a CancellationToken, scope_id: u32) -> Self {
        FetchCtx {
            budget,
            cancel,
            deadline: Instant::now() + PER_RUN_BUDGET,
            scope_id,
        }
    }

    /// The context of one responder: [`PER_RESPONDER_BUDGET`] from now, never past the run
    /// deadline.
    pub fn responder(self) -> Self {
        FetchCtx {
            deadline: self.deadline.min(Instant::now() + PER_RESPONDER_BUDGET),
            ..self
        }
    }

    /// The deadline of one request started now.
    pub fn request_deadline(&self) -> Instant {
        self.deadline.min(Instant::now() + REQUEST_TIMEOUT)
    }
}

/// Socket address for `ip:port`, giving IPv6 link-local addresses the interface scope.
pub(crate) fn connect_addr(ip: IpAddr, port: u16, scope_id: u32) -> SocketAddr {
    match ip {
        IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80 => {
            SocketAddrV6::new(v6, port, 0, scope_id).into()
        }
        _ => SocketAddr::new(ip, port),
    }
}

/// `host:port` for a `Host` header, bracketing IPv6 literals.
pub(crate) fn host_header(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// IPv4 SSDP multicast group.
const SSDP_MCAST_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;
/// Size cap on a fetched device description (hostile-input bound).
const MAX_DESCRIPTION_BYTES: usize = 256 * 1024;
/// Reply datagram buffer (SOAP-over-UDP WS-Discovery replies can be several KiB).
const MAX_DATAGRAM: usize = 64 * 1024;
/// Responders processed per discovery run (bounds work on a hostile segment).
const MAX_RESPONDERS: usize = 512;
/// Datagrams kept per responder (only the first headers / match of each are used).
const MAX_DATAGRAMS_PER_RESPONDER: usize = 32;
/// Reply bytes kept per discovery exchange (hostile-input memory bound).
const MAX_REPLY_BYTES: usize = 4 * 1024 * 1024;
/// Redirects followed while fetching a description (same-origin only).
const MAX_REDIRECTS: u8 = 3;

/// Search targets probed (`ssdp:all` finds every device; `upnp:rootdevice` the root devices).
const SEARCH_TARGETS: [&str; 2] = ["ssdp:all", "upnp:rootdevice"];

/// Build an SSDP `M-SEARCH` request for search target `st` with `MX` seconds.
pub fn build_msearch(st: &str, mx: u8) -> Vec<u8> {
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: {mx}\r\n\
         ST: {st}\r\n\
         USER-AGENT: SweepR/1.0 UPnP/1.1\r\n\r\n"
    )
    .into_bytes()
}

/// The SSDP headers of one responder's reply.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SsdpHeaders {
    pub location: Option<String>,
    pub server: Option<String>,
    pub search_target: Option<String>,
    pub usn: Option<String>,
}

/// Parse an SSDP response / NOTIFY (an HTTP-style message) into its headers. Header names are
/// matched case-insensitively; values are sanitized and length-capped.
pub fn parse_ssdp_response(buf: &[u8]) -> Option<SsdpHeaders> {
    // Non-UTF-8 bytes (Latin-1 server strings) are tolerated.
    let text = String::from_utf8_lossy(buf);
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let start = lines.next()?;
    // Accept an M-SEARCH response (`HTTP/1.1 200 OK`, also HTTP/1.0) or a NOTIFY advert.
    let ok = start.starts_with("HTTP/1.1 200")
        || start.starts_with("HTTP/1.0 200")
        || start.starts_with("NOTIFY");
    if !ok {
        return None;
    }
    let mut h = SsdpHeaders::default();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, raw)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_uppercase();
        // URLs keep their full length; other values are names.
        let value = if name == "LOCATION" {
            sanitize_text_max(raw.trim(), MAX_URL_LEN)
        } else {
            sanitize_text(raw.trim())
        };
        if value.is_empty() {
            continue;
        }
        match name.as_str() {
            "LOCATION" => h.location = Some(value),
            "SERVER" => h.server = Some(value),
            "ST" | "NT" => {
                h.search_target.get_or_insert(value);
            }
            "USN" => h.usn = Some(value),
            _ => {}
        }
    }
    (h.location.is_some() || h.server.is_some() || h.usn.is_some()).then_some(h)
}

/// A minimally-parsed `http://host[:port]/path` URL (the only scheme SSDP descriptions use).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpUrl {
    pub host: String,
    pub port: u16,
    pub path: String,
}

/// Parse an `http://` URL. Returns `None` for any other scheme (no https: device descriptions
/// are plain HTTP, and allowing other schemes would widen the SSRF surface).
pub fn parse_http_url(url: &str) -> Option<HttpUrl> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("HTTP://"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    // Strip any userinfo (`user@host`) — never honoured, and it hides the real host.
    let authority = authority.rsplit('@').next()?;
    let (host, port) = match authority.rfind(':') {
        // IPv6 literal `[::1]:80` or `host:port`.
        Some(i) if !authority[i..].contains(']') => {
            (&authority[..i], authority[i + 1..].parse().ok()?)
        }
        _ => (authority, 80u16),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return None;
    }
    Some(HttpUrl {
        host: host.to_string(),
        port,
        path: path.to_string(),
    })
}

/// `true` when `url`'s host is the IP literal `responder` — the only case in which we fetch a
/// device description (so a hostile `LOCATION` cannot make us connect anywhere else).
pub fn url_host_is(url: &HttpUrl, responder: IpAddr) -> bool {
    url.host
        .parse::<IpAddr>()
        .map(|h| h == responder)
        .unwrap_or(false)
}

/// Lowercase alphanumeric words of `text` (word-boundary matching: "panasonic" is not "nas",
/// "duplex" is not "plex").
fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

/// `true` when the word sequence of `needle` occurs in `hay` (whole words, in order).
fn has_phrase(hay: &[String], needle: &str) -> bool {
    let n = words(needle);
    !n.is_empty() && hay.windows(n.len()).any(|w| w == n.as_slice())
}

/// The UPnP device type name of a `urn:<domain>:device:<Type>:<version>` URN, lowercased.
fn upnp_device_type(urn: &str) -> Option<String> {
    let mut parts = urn.split(':');
    while let Some(p) = parts.next() {
        if p.eq_ignore_ascii_case("device") {
            return parts
                .next()
                .filter(|t| !t.is_empty())
                .map(str::to_ascii_lowercase);
        }
    }
    None
}

/// Text keywords per kind, most specific first (whole-word phrases).
const KIND_WORDS: &[(&str, &[&str])] = &[
    (
        "camera",
        &[
            "network camera",
            "ip camera",
            "ipcamera",
            "network video",
            "hikvision",
            "dahua",
            "axis",
            "onvif",
            "nvr",
        ],
    ),
    (
        "printer",
        &[
            "printer",
            "multi function printer",
            "mfp",
            "laserjet",
            "officejet",
            "deskjet",
            "jetdirect",
            "ipp",
            "printbasic",
        ],
    ),
    ("scanner", &["scanner"]),
    (
        "tv",
        &[
            "tv",
            "smart tv",
            "television",
            "bravia",
            "aquos",
            "webos",
            "tizen",
            "android tv",
            "roku",
            "appletv",
            "apple tv",
            "chromecast",
            "shield",
        ],
    ),
    (
        "nas",
        &[
            "nas",
            "synology",
            "qnap",
            "diskstation",
            "readynas",
            "wd my cloud",
            "truenas",
            "terramaster",
        ],
    ),
    (
        "media_server",
        &[
            "media server",
            "plex",
            "jellyfin",
            "emby",
            "minidlna",
            "dlna server",
        ],
    ),
];

/// Classify the device kind from the parsed description: the UPnP device type URN first
/// (`InternetGatewayDevice`, `MediaServer`, `MediaRenderer`, `Printer`, ...), refined by the
/// identity text, then the identity text alone. Keywords match whole words only. Returns a
/// coarse `device_kind` label, or `None` when nothing matches.
pub fn classify_ssdp_kind(info: &SsdpInfo) -> Option<String> {
    let text = [
        info.model_name.as_deref(),
        info.model_description.as_deref(),
        info.friendly_name.as_deref(),
        info.manufacturer.as_deref(),
        info.server.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ");
    let hay = words(&text);
    let is = |kind: &str| {
        KIND_WORDS
            .iter()
            .find(|(k, _)| *k == kind)
            .is_some_and(|(_, ws)| ws.iter().any(|w| has_phrase(&hay, w)))
    };
    let urn_type = info
        .device_type
        .as_deref()
        .or(info.search_target.as_deref())
        .and_then(upnp_device_type);
    let by_type = match urn_type.as_deref() {
        Some("internetgatewaydevice" | "wandevice" | "wanconnectiondevice") => Some("igd_router"),
        Some("printer") => Some("printer"),
        Some("scanner") => Some("scanner"),
        Some("digitalsecuritycamera") => Some("camera"),
        // A NAS or TV that also shares media is a NAS / TV.
        Some("mediaserver") if is("nas") => Some("nas"),
        Some("mediaserver") if is("tv") => Some("tv"),
        Some("mediaserver") => Some("media_server"),
        // Renderers play media: TVs, speakers (Sonos), receivers; not media servers.
        Some("mediarenderer") if is("tv") => Some("tv"),
        Some("mediarenderer" | "zoneplayer") => Some("media_player"),
        _ => None,
    };
    if let Some(kind) = by_type {
        return Some(kind.to_string());
    }
    KIND_WORDS
        .iter()
        .find(|(_, ws)| ws.iter().any(|w| has_phrase(&hay, w)))
        .map(|(k, _)| (*k).to_string())
}

/// Deepest element nesting the XML walker follows (hostile-input bound).
const MAX_XML_DEPTH: usize = 64;
/// Events processed per document (hostile-input bound; documents are also size-capped).
const MAX_XML_EVENTS: usize = 100_000;
/// Text accumulated for one element before further text is dropped (an element may hold a
/// list of URLs, e.g. WS-Discovery `XAddrs`).
pub(crate) const MAX_XML_TEXT: usize = 16 * 1024;

/// Resolve an entity reference the hardened walker allows: the five XML predefined entities
/// and numeric character references. Everything else (entities a DTD would define) is dropped,
/// never expanded, so "billion laughs" documents cannot grow.
fn resolve_reference(name: &str) -> Option<char> {
    match name {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => {
            let num = name.strip_prefix('#')?;
            let code = match num.strip_prefix('x').or_else(|| num.strip_prefix('X')) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => num.parse().ok()?,
            };
            char::from_u32(code)
        }
    }
}

/// Local element name (namespace prefix stripped) in lowercase.
pub(crate) fn local_name(name: &str) -> String {
    name.rsplit(':').next().unwrap_or(name).to_ascii_lowercase()
}

/// Walk an XML document with a hardened pull reader and call `f(path, text)` for each run of
/// text directly inside an element (`path` = lowercase local names from the root). DTDs are
/// ignored, only predefined / numeric entity references are resolved, and depth, event count
/// and per-element text are bounded. Control characters are removed before `f` sees the text,
/// but it is only capped at [`MAX_XML_TEXT`]: callers split lists first and then cap each
/// value ([`sanitize_text`] for names, [`MAX_URL_LEN`] for URLs). Non-UTF-8 documents are
/// decoded lossily. Malformed input simply ends the walk.
pub(crate) fn for_each_xml_text(xml: &[u8], mut f: impl FnMut(&[String], &str)) {
    use quick_xml::{events::Event, Reader};

    let lossy;
    let xml = match std::str::from_utf8(xml) {
        Ok(_) => xml,
        Err(_) => {
            lossy = String::from_utf8_lossy(xml).into_owned();
            lossy.as_bytes()
        }
    };
    let mut reader = Reader::from_reader(xml);
    // No per-event trimming: text split around entity references must keep its spaces (the
    // accumulated text is trimmed once, in `flush`).
    reader.config_mut().trim_text(false);
    reader.config_mut().check_end_names = false;
    let mut path: Vec<String> = Vec::new();
    let mut text = String::new();
    let mut buf = Vec::new();
    let mut flush = |path: &[String], text: &mut String| {
        if !text.trim().is_empty() {
            let value = sanitize_text_max(text, MAX_XML_TEXT);
            if !value.is_empty() {
                f(path, &value);
            }
        }
        text.clear();
    };
    for _ in 0..MAX_XML_EVENTS {
        let Ok(event) = reader.read_event_into(&mut buf) else {
            break;
        };
        match event {
            Event::Start(e) => {
                flush(&path, &mut text);
                if path.len() >= MAX_XML_DEPTH {
                    break;
                }
                path.push(local_name(e.name().as_ref()));
            }
            Event::End(_) => {
                flush(&path, &mut text);
                path.pop();
            }
            Event::Empty(_) => flush(&path, &mut text),
            Event::Text(t) if text.len() < MAX_XML_TEXT => text.push_str(&t.xml10_content()),
            Event::CData(c) if text.len() < MAX_XML_TEXT => text.push_str(&c.xml10_content()),
            Event::GeneralRef(r) if text.len() < MAX_XML_TEXT => {
                if let Some(c) = resolve_reference(&r.xml10_content()) {
                    text.push(c);
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
}

/// Parse a UPnP device description XML (hardened, see [`for_each_xml_text`]). Reads the root
/// `<device>`'s identity fields (the first value of each wins, so embedded sub-devices do not
/// override the root) and every advertised `serviceType` (capped).
pub fn parse_device_description(xml: &[u8]) -> SsdpInfo {
    let mut info = SsdpInfo::default();
    for_each_xml_text(xml, |path, value| {
        let in_device = path.iter().any(|p| p == "device");
        let Some(tag) = path.last() else { return };
        let set = |slot: &mut Option<String>| {
            if slot.is_none() {
                let v = if tag == "presentationurl" {
                    sanitize_text_max(value, MAX_URL_LEN)
                } else {
                    sanitize_text(value)
                };
                if !v.is_empty() {
                    *slot = Some(v);
                }
            }
        };
        match tag.as_str() {
            "friendlyname" if in_device => set(&mut info.friendly_name),
            "manufacturer" if in_device => set(&mut info.manufacturer),
            "modelname" if in_device => set(&mut info.model_name),
            "modelnumber" if in_device => set(&mut info.model_number),
            "modeldescription" if in_device => set(&mut info.model_description),
            "serialnumber" if in_device => set(&mut info.serial_number),
            "devicetype" if in_device => set(&mut info.device_type),
            "udn" if in_device => set(&mut info.udn),
            "presentationurl" if in_device => set(&mut info.presentation_url),
            "servicetype" if info.services.len() < MAX_SERVICE_LIST => {
                let v = sanitize_text(value);
                if !v.is_empty() && !info.services.contains(&v) {
                    info.services.push(v);
                }
            }
            _ => {}
        }
    });
    info
}

/// IPv6 SSDP / WS-Discovery multicast groups (link-local and site-local scope).
pub(crate) const MCAST_V6_LINK: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0c);
pub(crate) const MCAST_V6_SITE: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0x0c);

/// Where a UDP discovery request is sent from / to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiscoveryTarget {
    /// IPv4 multicast out of the interface with this address.
    MulticastV4(Ipv4Addr),
    /// IPv6 multicast (link- and site-local groups) out of the interface with this index.
    MulticastV6(u32),
    /// One host, unicast (the single-device drawer probe).
    Unicast(IpAddr),
}

/// Bind a UDP socket for a discovery exchange. Multicast sockets are pinned to the scanning
/// interface and limited to the local segment (TTL / hop limit 2, no loopback).
fn discovery_socket(target: DiscoveryTarget) -> std::io::Result<UdpSocket> {
    let v6 = match target {
        DiscoveryTarget::MulticastV4(_) => false,
        DiscoveryTarget::MulticastV6(_) => true,
        DiscoveryTarget::Unicast(ip) => ip.is_ipv6(),
    };
    let domain = if v6 { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    let bind: SocketAddr = if v6 {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    sock.bind(&bind.into())?;
    match target {
        DiscoveryTarget::MulticastV4(ifaddr) => {
            sock.set_multicast_if_v4(&ifaddr)?;
            sock.set_multicast_ttl_v4(2)?;
            let _ = sock.set_multicast_loop_v4(false);
        }
        DiscoveryTarget::MulticastV6(index) => {
            sock.set_multicast_if_v6(index)?;
            sock.set_multicast_hops_v6(2)?;
            let _ = sock.set_multicast_loop_v6(false);
        }
        DiscoveryTarget::Unicast(_) => {}
    }
    sock.set_nonblocking(true)?;
    UdpSocket::from_std(sock.into())
}

/// Send each of `payloads` to `port` on `target` (both IPv6 groups for `MulticastV6`), then
/// collect reply datagrams for `window`: at most [`MAX_RESPONDERS`] distinct responders,
/// [`MAX_DATAGRAMS_PER_RESPONDER`] datagrams each and [`MAX_REPLY_BYTES`] in total. For a
/// unicast target only datagrams from that host count; with `scope`, only datagrams from
/// those addresses (the devices the scan discovered). Holds one socket permit.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn exchange_udp(
    target: DiscoveryTarget,
    port: u16,
    group_v4: Ipv4Addr,
    payloads: &[Vec<u8>],
    window: Duration,
    scope: Option<&HashSet<IpAddr>>,
    budget: &SocketBudget,
    cancel: &CancellationToken,
) -> Vec<(IpAddr, Vec<u8>)> {
    let mut out = Vec::new();
    let Some(_permit) = budget.acquire().await else {
        return out;
    };
    let sock = match discovery_socket(target) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("discovery socket for {target:?} unavailable: {e}");
            return out;
        }
    };
    let dests: Vec<SocketAddr> = match target {
        DiscoveryTarget::MulticastV4(_) => vec![(group_v4, port).into()],
        DiscoveryTarget::MulticastV6(index) => vec![
            SocketAddrV6::new(MCAST_V6_LINK, port, 0, index).into(),
            SocketAddrV6::new(MCAST_V6_SITE, port, 0, index).into(),
        ],
        DiscoveryTarget::Unicast(ip) => vec![SocketAddr::new(ip, port)],
    };
    for dest in &dests {
        for p in payloads {
            if let Err(e) = sock.send_to(p, dest).await {
                tracing::debug!("discovery send to {dest} failed: {e}");
            }
        }
    }
    let only = match target {
        DiscoveryTarget::Unicast(ip) => Some(ip),
        _ => None,
    };
    let deadline = tokio::time::Instant::now() + window;
    let mut per_source: HashMap<IpAddr, usize> = HashMap::new();
    let mut kept_bytes = 0usize;
    let mut buf = vec![0u8; MAX_DATAGRAM];
    while !cancel.is_cancelled() {
        let recv = tokio::select! {
            _ = cancel.cancelled() => break,
            r = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)) => r,
        };
        let Ok(Ok((n, from))) = recv else { break };
        let ip = from.ip();
        if only.is_some_and(|o| o != ip) || scope.is_some_and(|s| !s.contains(&ip)) {
            continue;
        }
        if !per_source.contains_key(&ip) && per_source.len() >= MAX_RESPONDERS {
            continue;
        }
        let count = per_source.entry(ip).or_default();
        // Bound what is retained (a responder may repeat itself or flood).
        if *count < MAX_DATAGRAMS_PER_RESPONDER && kept_bytes + n <= MAX_REPLY_BYTES {
            *count += 1;
            kept_bytes += n;
            out.push((ip, buf[..n].to_vec()));
        }
    }
    out
}

/// Every address of the scan's devices: the only responders follow-up requests may go to.
pub fn scope_of<'a>(ips: impl IntoIterator<Item = &'a IpAddr>) -> HashSet<IpAddr> {
    ips.into_iter().copied().collect()
}

/// Discover UPnP devices for `window` over IPv4 multicast from the interface address `v4`
/// and, when `v6_index` is given, IPv6 multicast (`ff02::c` / `ff05::c`) on that interface.
/// Only replies from `scope` (the addresses of the devices the scan discovered) are kept, so
/// descriptions are fetched from in-scope devices only, never from arbitrary multicast
/// responders. Fetches are bounded per responder and per run ([`FetchCtx`]). Returns responder
/// IP → [`SsdpInfo`] (headers plus the description fetched from the responder itself).
pub async fn discover_ssdp(
    v4: Option<Ipv4Addr>,
    v6_index: Option<u32>,
    window: Duration,
    scope: &HashSet<IpAddr>,
    budget: &SocketBudget,
    cancel: &CancellationToken,
) -> HashMap<IpAddr, SsdpInfo> {
    let payloads: Vec<Vec<u8>> = SEARCH_TARGETS
        .iter()
        .map(|st| build_msearch(st, 2))
        .collect();
    let exchange = |t: DiscoveryTarget| {
        exchange_udp(
            t,
            SSDP_PORT,
            SSDP_MCAST_V4,
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
    describe_responders(a.into_iter().chain(b), ctx).await
}

/// Unicast SSDP probe of one host (`M-SEARCH` straight to `ip:1900`), for the details drawer.
/// The description fetch is bounded like a discovery run.
pub async fn probe_ssdp_host(
    ip: IpAddr,
    window: Duration,
    budget: &SocketBudget,
    cancel: &CancellationToken,
) -> Option<SsdpInfo> {
    let payloads: Vec<Vec<u8>> = SEARCH_TARGETS
        .iter()
        .map(|st| build_msearch(st, 1))
        .collect();
    let t = DiscoveryTarget::Unicast(ip);
    let replies = exchange_udp(
        t,
        SSDP_PORT,
        SSDP_MCAST_V4,
        &payloads,
        window,
        None,
        budget,
        cancel,
    )
    .await;
    describe_responders(replies, FetchCtx::run(budget, cancel, 0))
        .await
        .remove(&ip)
}

/// Fold reply datagrams into per-responder headers, then fetch each responder's description
/// (SSRF-guarded, within `ctx`'s deadline and [`PER_RESPONDER_BUDGET`] each) and build the
/// result map. A responder whose fetch runs out of time keeps its headers.
pub(crate) async fn describe_responders(
    replies: impl IntoIterator<Item = (IpAddr, Vec<u8>)>,
    ctx: FetchCtx<'_>,
) -> HashMap<IpAddr, SsdpInfo> {
    let mut headers: HashMap<IpAddr, SsdpHeaders> = HashMap::new();
    for (ip, datagram) in replies {
        let Some(h) = parse_ssdp_response(&datagram) else {
            continue;
        };
        let entry = headers.entry(ip).or_default();
        // Keep the first value of each header seen.
        entry.location = entry.location.take().or(h.location);
        entry.server = entry.server.take().or(h.server);
        entry.usn = entry.usn.take().or(h.usn);
        entry.search_target = entry.search_target.take().or(h.search_target);
    }
    // Fetch descriptions concurrently (bounded; every socket also draws from the budget).
    futures::stream::iter(headers)
        .map(|(ip, h)| async move {
            let mut info = SsdpInfo {
                location: h.location.clone(),
                server: h.server,
                search_target: h.search_target,
                usn: h.usn,
                ..SsdpInfo::default()
            };
            let url = h.location.as_deref().and_then(parse_http_url);
            if let Some(url) = url.filter(|u| url_host_is(u, ip)) {
                if !ctx.cancel.is_cancelled() {
                    if let Some(body) = fetch_description(ip, &url, ctx.responder()).await {
                        merge_description(&mut info, parse_device_description(&body));
                    }
                }
            }
            (ip, info)
        })
        .buffer_unordered(CONCURRENT_FETCHES)
        .collect()
        .await
}

/// Description fetches / SOAP identifications run concurrently per discovery run.
pub(crate) const CONCURRENT_FETCHES: usize = 16;

/// Fold a parsed description into the header-derived info (descriptions win for identity).
fn merge_description(info: &mut SsdpInfo, desc: SsdpInfo) {
    info.friendly_name = desc.friendly_name.or(info.friendly_name.take());
    info.manufacturer = desc.manufacturer.or(info.manufacturer.take());
    info.model_name = desc.model_name.or(info.model_name.take());
    info.model_number = desc.model_number.or(info.model_number.take());
    info.model_description = desc.model_description.or(info.model_description.take());
    info.serial_number = desc.serial_number.or(info.serial_number.take());
    info.device_type = desc.device_type.or(info.device_type.take());
    info.udn = desc.udn.or(info.udn.take());
    info.presentation_url = desc.presentation_url.or(info.presentation_url.take());
    info.services = desc.services;
}

/// Fetch `url` from `responder` over HTTP with a size cap, timeout and same-origin redirects
/// only, finishing by `ctx.deadline`. Returns the body bytes, or `None` on any error / policy
/// violation.
pub(crate) async fn fetch_description(
    responder: IpAddr,
    url: &HttpUrl,
    ctx: FetchCtx<'_>,
) -> Option<Vec<u8>> {
    let mut url = url.clone();
    for _ in 0..=MAX_REDIRECTS {
        // Never connect anywhere but the responder itself.
        if !url_host_is(&url, responder) {
            return None;
        }
        let _permit = ctx.budget.acquire().await?;
        let resp = tokio::select! {
            _ = ctx.cancel.cancelled() => return None,
            r = tokio::time::timeout_at(ctx.request_deadline(), http_get(responder, &url, ctx.scope_id)) => r.ok()?,
        }?;
        drop(_permit);
        match resp.status {
            200 => return Some(resp.body),
            301 | 302 | 303 | 307 | 308 => {
                let next = resp.header("location")?;
                let next = parse_http_url(next)?;
                // Same-origin only.
                if !url_host_is(&next, responder) {
                    return None;
                }
                url = next;
            }
            _ => return None,
        }
    }
    None
}

/// A parsed HTTP response: status, headers (bounded) and body (bounded).
pub(crate) struct HttpMessage {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpMessage {
    /// The first header named `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Longest HTTP header block read.
const MAX_HTTP_HEAD: usize = 16 * 1024;
/// Most response headers kept.
const MAX_HTTP_HEADERS: usize = 100;

/// Read one HTTP/1.x response from `r`: the header block, then a body framed by
/// `Content-Length`, the chunked transfer coding, or the end of the connection, keeping at most
/// `max_body` bytes. Returns early once a `Content-Length` body is complete (keep-alive peers
/// need not close). Returns `None` for anything that is not an HTTP response.
pub(crate) async fn read_http_response<R: AsyncRead + Unpin>(
    r: &mut R,
    max_body: usize,
) -> Option<HttpMessage> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let (head_len, sep_len) = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break (i, 4);
        }
        if let Some(i) = buf.windows(2).position(|w| w == b"\n\n") {
            break (i, 2);
        }
        if buf.len() > MAX_HTTP_HEAD {
            return None;
        }
        let n = r.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_len]).into_owned();
    let mut rest = buf.split_off(head_len + sep_len);
    let mut lines = head.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let status_line = lines.next()?;
    if !status_line.starts_with("HTTP/") {
        return None;
    }
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .take(MAX_HTTP_HEADERS)
        .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
        .collect();
    let msg = |body: Vec<u8>| HttpMessage {
        status,
        headers: headers.clone(),
        body,
    };
    let find = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.to_ascii_lowercase())
    };
    if find("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        return Some(msg(read_chunked(r, rest, max_body).await));
    }
    let length = find("content-length").and_then(|v| v.trim().parse::<usize>().ok());
    let want = length.map_or(max_body, |l| l.min(max_body));
    while rest.len() < want {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => rest.extend_from_slice(&chunk[..n]),
        }
    }
    rest.truncate(want);
    Some(msg(rest))
}

/// Decode a chunked body (`rest` holds bytes already read), keeping at most `max_body` bytes.
/// A truncated stream yields what arrived.
async fn read_chunked<R: AsyncRead + Unpin>(
    r: &mut R,
    mut rest: Vec<u8>,
    max_body: usize,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    // Make sure `rest` holds at least `n` bytes (or the stream ended).
    async fn fill<R: AsyncRead + Unpin>(
        r: &mut R,
        rest: &mut Vec<u8>,
        chunk: &mut [u8],
        n: usize,
    ) -> bool {
        while rest.len() < n {
            match r.read(chunk).await {
                Ok(0) | Err(_) => return false,
                Ok(k) => rest.extend_from_slice(&chunk[..k]),
            }
        }
        true
    }
    loop {
        // Chunk-size line.
        let line_end = loop {
            if let Some(i) = rest.iter().position(|b| *b == b'\n') {
                break i;
            }
            let want = rest.len() + 1;
            if want > 1024 || !fill(r, &mut rest, &mut chunk, want).await {
                return out;
            }
        };
        let line = String::from_utf8_lossy(&rest[..line_end]).into_owned();
        rest.drain(..=line_end);
        let size_text = line.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(size_text, 16) else {
            return out;
        };
        if size == 0 {
            return out;
        }
        let complete = fill(r, &mut rest, &mut chunk, size.saturating_add(2)).await;
        let take = size.min(rest.len());
        let room = max_body.saturating_sub(out.len());
        out.extend_from_slice(&rest[..take.min(room)]);
        if !complete || out.len() >= max_body {
            return out;
        }
        rest.drain(..(size + 2).min(rest.len()));
    }
}

/// Perform one HTTP/1.0 GET to `ip:url.port` for `url.path`, reading at most
/// [`MAX_DESCRIPTION_BYTES`] of body. The caller bounds the time.
async fn http_get(ip: IpAddr, url: &HttpUrl, scope_id: u32) -> Option<HttpMessage> {
    let mut stream = TcpStream::connect(connect_addr(ip, url.port, scope_id))
        .await
        .ok()?;
    let req = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: SweepR/1.0\r\nAccept: */*\r\n\
         Connection: close\r\n\r\n",
        url.path,
        host_header(&url.host, url.port)
    );
    stream.write_all(req.as_bytes()).await.ok()?;
    read_http_response(&mut stream, MAX_DESCRIPTION_BYTES).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn msearch_is_well_formed() {
        let m = String::from_utf8(build_msearch("ssdp:all", 2)).unwrap();
        assert!(m.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(m.contains("HOST: 239.255.255.250:1900\r\n"));
        assert!(m.contains("MAN: \"ssdp:discover\"\r\n"));
        assert!(m.contains("ST: ssdp:all\r\n"));
        assert!(m.contains("MX: 2\r\n"));
        assert!(m.ends_with("\r\n\r\n"));
    }

    #[test]
    fn parses_ssdp_response_headers() {
        let r = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\n\
                 LOCATION: http://192.168.1.10:49152/desc.xml\r\n\
                 SERVER: Linux/4.4 UPnP/1.1 MiniDLNA/1.2\r\n\
                 ST: urn:schemas-upnp-org:device:MediaServer:1\r\n\
                 USN: uuid:abcd::urn:schemas-upnp-org:device:MediaServer:1\r\n\r\n";
        let h = parse_ssdp_response(r.as_bytes()).unwrap();
        assert_eq!(
            h.location.as_deref(),
            Some("http://192.168.1.10:49152/desc.xml")
        );
        assert!(h.server.as_deref().unwrap().contains("MiniDLNA"));
        assert_eq!(
            h.search_target.as_deref(),
            Some("urn:schemas-upnp-org:device:MediaServer:1")
        );
        assert!(h.usn.as_deref().unwrap().starts_with("uuid:"));
        // A NOTIFY advert is also accepted.
        let notify = "NOTIFY * HTTP/1.1\r\nLOCATION: http://10.0.0.5:80/x.xml\r\nNT: upnp:rootdevice\r\n\r\n";
        assert!(parse_ssdp_response(notify.as_bytes()).is_some());
        // Junk is rejected.
        assert!(parse_ssdp_response(b"not http").is_none());
    }

    #[test]
    fn http_url_parsing_and_ssrf_guard() {
        let u = parse_http_url("http://192.168.1.10:49152/desc.xml").unwrap();
        assert_eq!(u.host, "192.168.1.10");
        assert_eq!(u.port, 49152);
        assert_eq!(u.path, "/desc.xml");
        assert!(url_host_is(&u, "192.168.1.10".parse().unwrap()));
        assert!(!url_host_is(&u, "192.168.1.11".parse().unwrap()));
        // Default port, no path.
        let u = parse_http_url("http://10.0.0.1").unwrap();
        assert_eq!((u.port, u.path.as_str()), (80, "/"));
        // A hostile LOCATION pointing at a name (not the responder IP) is not a match.
        let u = parse_http_url("http://metadata.internal/latest").unwrap();
        assert!(!url_host_is(&u, "10.0.0.1".parse().unwrap()));
        // userinfo cannot smuggle a different host.
        let u = parse_http_url("http://192.168.1.10@evil.example/x").unwrap();
        assert_eq!(u.host, "evil.example");
        assert!(!url_host_is(&u, "192.168.1.10".parse().unwrap()));
        // https and other schemes are rejected.
        assert!(parse_http_url("https://10.0.0.1/x").is_none());
        assert!(parse_http_url("ftp://10.0.0.1/x").is_none());
    }

    const SAMPLE_DESC: &[u8] = br#"<?xml version="1.0"?>
      <root xmlns="urn:schemas-upnp-org:device-1-0">
        <specVersion><major>1</major><minor>0</minor></specVersion>
        <device>
          <deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>
          <friendlyName>Living Room NAS</friendlyName>
          <manufacturer>Synology</manufacturer>
          <modelName>DS220+</modelName>
          <modelNumber>220+</modelNumber>
          <modelDescription>Synology DiskStation</modelDescription>
          <serialNumber>2010ABCDEF</serialNumber>
          <UDN>uuid:4d696e69-44-4c-4e-41-123456789abc</UDN>
          <presentationURL>http://192.168.1.10:5000/</presentationURL>
          <serviceList>
            <service><serviceType>urn:schemas-upnp-org:service:ContentDirectory:1</serviceType></service>
            <service><serviceType>urn:schemas-upnp-org:service:ConnectionManager:1</serviceType></service>
          </serviceList>
        </device>
      </root>"#;

    #[test]
    fn parses_device_description() {
        let info = parse_device_description(SAMPLE_DESC);
        assert_eq!(info.friendly_name.as_deref(), Some("Living Room NAS"));
        assert_eq!(info.manufacturer.as_deref(), Some("Synology"));
        assert_eq!(info.model_name.as_deref(), Some("DS220+"));
        assert_eq!(info.model_number.as_deref(), Some("220+"));
        assert_eq!(info.serial_number.as_deref(), Some("2010ABCDEF"));
        assert_eq!(
            info.device_type.as_deref(),
            Some("urn:schemas-upnp-org:device:MediaServer:1")
        );
        assert!(info.udn.as_deref().unwrap().starts_with("uuid:"));
        assert_eq!(info.services.len(), 2);
        assert!(info.services.iter().any(|s| s.contains("ContentDirectory")));
    }

    #[test]
    fn classifies_device_kinds() {
        let media = SsdpInfo {
            device_type: Some("urn:schemas-upnp-org:device:MediaServer:1".into()),
            ..SsdpInfo::default()
        };
        assert_eq!(classify_ssdp_kind(&media).as_deref(), Some("media_server"));
        let igd = SsdpInfo {
            device_type: Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1".into()),
            ..SsdpInfo::default()
        };
        assert_eq!(classify_ssdp_kind(&igd).as_deref(), Some("igd_router"));
        let nas = SsdpInfo {
            manufacturer: Some("Synology".into()),
            model_description: Some("DiskStation NAS".into()),
            ..SsdpInfo::default()
        };
        assert_eq!(classify_ssdp_kind(&nas).as_deref(), Some("nas"));
        let tv = SsdpInfo {
            friendly_name: Some("Samsung Smart TV".into()),
            ..SsdpInfo::default()
        };
        assert_eq!(classify_ssdp_kind(&tv).as_deref(), Some("tv"));
        assert_eq!(classify_ssdp_kind(&SsdpInfo::default()), None);
    }

    #[test]
    fn hardened_xml_rejects_entity_expansion() {
        // A "billion laughs" style DTD: the hardened reader must not expand it, and must not
        // hang or allocate unboundedly. We simply require it returns (bounded) without panic.
        let bomb = br#"<?xml version="1.0"?>
          <!DOCTYPE root [
            <!ENTITY a "AAAAAAAAAA">
            <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
          ]>
          <root><device><friendlyName>&b;</friendlyName></device></root>"#;
        let info = parse_device_description(bomb);
        // The entity is NOT expanded into a huge string (quick-xml leaves &b; unexpanded).
        assert!(info
            .friendly_name
            .as_deref()
            .map(|n| n.len() < 64)
            .unwrap_or(true));
    }

    /// The SSRF-guarded fetch + XML parse, exercised against a local HTTP responder on
    /// loopback (host == responder IP == 127.0.0.1).
    #[tokio::test]
    async fn fetches_and_parses_description_from_local_responder() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                let body = SAMPLE_DESC;
                let resp = format!(
                    "HTTP/1.0 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.write_all(body).await;
            }
        });
        let url = HttpUrl {
            host: "127.0.0.1".into(),
            port,
            path: "/desc.xml".into(),
        };
        let (budget, cancel) = (SocketBudget::new(2), CancellationToken::new());
        let body = fetch_description(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &url,
            FetchCtx::run(&budget, &cancel, 0),
        )
        .await
        .expect("fetch should succeed against the local responder");
        let info = parse_device_description(&body);
        assert_eq!(info.model_name.as_deref(), Some("DS220+"));
        let _ = server.await;
    }

    /// End to end on loopback: a fake SSDP responder answers the M-SEARCH with a LOCATION on a
    /// fake HTTP server (same IP), and the description is fetched and parsed. A second reply
    /// whose LOCATION points elsewhere is never fetched.
    #[tokio::test]
    async fn ssdp_exchange_and_describe_against_fake_responder() {
        let http = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let http_port = http.local_addr().unwrap().port();
        let http_task = tokio::spawn(async move {
            if let Ok((mut s, _)) = http.accept().await {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    SAMPLE_DESC.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(SAMPLE_DESC).await;
            }
        });
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let udp_port = udp.local_addr().unwrap().port();
        let udp_task = tokio::spawn(async move {
            let mut b = [0u8; 2048];
            if let Ok((n, from)) = udp.recv_from(&mut b).await {
                assert!(b[..n].starts_with(b"M-SEARCH * HTTP/1.1"));
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:{http_port}/desc.xml\r\n\
                     SERVER: Linux/5.10 UPnP/1.0 Synology/DSM\r\n\
                     ST: upnp:rootdevice\r\nUSN: uuid:abc::upnp:rootdevice\r\n\r\n"
                );
                let _ = udp.send_to(reply.as_bytes(), from).await;
            }
        });
        let budget = SocketBudget::new(4);
        let cancel = CancellationToken::new();
        let replies = exchange_udp(
            DiscoveryTarget::Unicast(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            udp_port,
            SSDP_MCAST_V4,
            &[build_msearch("ssdp:all", 1)],
            Duration::from_millis(400),
            None,
            &budget,
            &cancel,
        )
        .await;
        assert_eq!(replies.len(), 1);
        let map = describe_responders(replies, FetchCtx::run(&budget, &cancel, 0)).await;
        let info = &map[&IpAddr::V4(Ipv4Addr::LOCALHOST)];
        assert_eq!(info.model_name.as_deref(), Some("DS220+"));
        assert_eq!(info.serial_number.as_deref(), Some("2010ABCDEF"));
        assert!(info.server.as_deref().unwrap().contains("Synology"));
        // A Synology serving DLNA is a NAS, not a media server.
        assert_eq!(classify_ssdp_kind(info).as_deref(), Some("nas"));
        let _ = (udp_task.await, http_task.await);

        // A reply naming a foreign LOCATION host keeps its headers but fetches nothing.
        let foreign = vec![(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            b"HTTP/1.1 200 OK\r\nLOCATION: http://169.254.169.254/latest\r\nSERVER: x\r\n\r\n"
                .to_vec(),
        )];
        let map = describe_responders(foreign, FetchCtx::run(&budget, &cancel, 0)).await;
        let info = &map[&IpAddr::V4(Ipv4Addr::LOCALHOST)];
        assert!(info.model_name.is_none());
        assert_eq!(
            info.location.as_deref(),
            Some("http://169.254.169.254/latest")
        );
    }

    #[tokio::test]
    async fn fetch_follows_same_origin_redirect_only() {
        let http = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = http.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            // 1st: same-origin redirect; 2nd: the document.
            for i in 0..2 {
                if let Ok((mut s, _)) = http.accept().await {
                    let mut b = [0u8; 1024];
                    let _ = s.read(&mut b).await;
                    let resp = if i == 0 {
                        format!(
                            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/real.xml\r\n\r\n"
                        )
                    } else {
                        format!(
                            "HTTP/1.1 200 OK\r\n\r\n{}",
                            String::from_utf8_lossy(SAMPLE_DESC)
                        )
                    };
                    let _ = s.write_all(resp.as_bytes()).await;
                }
            }
        });
        let url = parse_http_url(&format!("http://127.0.0.1:{port}/desc.xml")).unwrap();
        let (budget, cancel) = (SocketBudget::new(2), CancellationToken::new());
        let body = fetch_description(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &url,
            FetchCtx::run(&budget, &cancel, 0),
        )
        .await
        .expect("same-origin redirect is followed");
        assert!(parse_device_description(&body).model_name.is_some());
        let _ = task.await;
        // A cross-origin redirect is refused.
        let http = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = http.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            if let Ok((mut s, _)) = http.accept().await {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                let _ = s
                    .write_all(b"HTTP/1.1 301 Moved\r\nLocation: http://10.1.2.3/x\r\n\r\n")
                    .await;
            }
        });
        let url = parse_http_url(&format!("http://127.0.0.1:{port}/desc.xml")).unwrap();
        let (budget, cancel) = (SocketBudget::new(2), CancellationToken::new());
        let res = fetch_description(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &url,
            FetchCtx::run(&budget, &cancel, 0),
        )
        .await;
        assert!(res.is_none());
        let _ = task.await;
    }

    #[test]
    fn entity_references_are_resolved_only_when_predefined() {
        let xml = br#"<root><device><friendlyName>A &amp; B &#x41;&#66;</friendlyName>
            <manufacturer>X&custom;Y</manufacturer></device></root>"#;
        let info = parse_device_description(xml);
        assert_eq!(info.friendly_name.as_deref(), Some("A & B AB"));
        assert_eq!(info.manufacturer.as_deref(), Some("XY"));
    }

    #[tokio::test]
    async fn fetch_refuses_host_other_than_responder() {
        // LOCATION host is 10.0.0.1 but the responder is 127.0.0.1: must refuse without
        // connecting anywhere.
        let url = HttpUrl {
            host: "10.0.0.1".into(),
            port: 80,
            path: "/x".into(),
        };
        let (budget, cancel) = (SocketBudget::new(2), CancellationToken::new());
        let res = fetch_description(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &url,
            FetchCtx::run(&budget, &cancel, 0),
        )
        .await;
        assert!(res.is_none());
    }

    /// Description fetches stop at the context deadline even when the device accepts the
    /// connection and never answers (review M4); the responder keeps its headers.
    #[tokio::test]
    async fn stalled_description_server_is_bounded_by_the_deadline() {
        let http = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = http.local_addr().unwrap().port();
        let stall = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = http.accept().await {
                held.push(s); // accept, never answer
            }
        });
        let (budget, cancel) = (SocketBudget::new(4), CancellationToken::new());
        let ctx = FetchCtx {
            deadline: Instant::now() + Duration::from_millis(800),
            ..FetchCtx::run(&budget, &cancel, 0)
        };
        // The per-responder context never extends the run deadline.
        assert!(ctx.responder().deadline <= ctx.deadline);
        let reply = format!(
            "HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:{port}/d.xml\r\nSERVER: x\r\n\r\n"
        );
        let started = std::time::Instant::now();
        let map = describe_responders(
            vec![(IpAddr::V4(Ipv4Addr::LOCALHOST), reply.into_bytes())],
            ctx,
        )
        .await;
        let took = started.elapsed();
        assert!(took < Duration::from_millis(3000), "took {took:?}");
        let info = &map[&IpAddr::V4(Ipv4Addr::LOCALHOST)];
        assert_eq!(info.server.as_deref(), Some("x"));
        assert!(info.model_name.is_none());
        stall.abort();
    }

    /// Only datagrams from in-scope addresses are kept (review M1), and a flooding responder
    /// is capped per source.
    #[tokio::test]
    async fn exchange_keeps_only_in_scope_responders_and_caps_floods() {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = udp.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut b = [0u8; 2048];
            if let Ok((_, from)) = udp.recv_from(&mut b).await {
                for _ in 0..100 {
                    let _ = udp
                        .send_to(b"HTTP/1.1 200 OK\r\nSERVER: x\r\n\r\n", from)
                        .await;
                }
            }
        });
        let (budget, cancel) = (SocketBudget::new(2), CancellationToken::new());
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let replies = exchange_udp(
            DiscoveryTarget::Unicast(lo),
            port,
            SSDP_MCAST_V4,
            &[build_msearch("ssdp:all", 1)],
            Duration::from_millis(400),
            None,
            &budget,
            &cancel,
        )
        .await;
        assert_eq!(replies.len(), MAX_DATAGRAMS_PER_RESPONDER);
        let _ = task.await;
        // Out of scope: nothing kept.
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = udp.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut b = [0u8; 2048];
            if let Ok((_, from)) = udp.recv_from(&mut b).await {
                let _ = udp
                    .send_to(b"HTTP/1.1 200 OK\r\nSERVER: x\r\n\r\n", from)
                    .await;
            }
        });
        let scope = scope_of(&["10.0.0.1".parse::<IpAddr>().unwrap()]);
        let replies = exchange_udp(
            DiscoveryTarget::Unicast(lo),
            port,
            SSDP_MCAST_V4,
            &[build_msearch("ssdp:all", 1)],
            Duration::from_millis(300),
            Some(&scope),
            &budget,
            &cancel,
        )
        .await;
        assert!(replies.is_empty());
        let _ = task.await;
    }

    /// Bodies framed by Content-Length (keep-alive peers) and chunked bodies are read
    /// correctly.
    #[tokio::test]
    async fn http_reader_handles_content_length_and_chunked() {
        let keep_alive = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA".to_vec();
        let m = read_http_response(&mut keep_alive.as_slice(), 1024)
            .await
            .unwrap();
        assert_eq!(m.body, b"hello");
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;x=y\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
                .to_vec();
        let m = read_http_response(&mut chunked.as_slice(), 1024)
            .await
            .unwrap();
        assert_eq!(m.body, b"hello world");
        // Body cap applies to chunked data too.
        let m = read_http_response(&mut chunked.as_slice(), 7)
            .await
            .unwrap();
        assert_eq!(m.body, b"hello w");
        assert!(read_http_response(&mut &b"garbage"[..], 10).await.is_none());
        // A keep-alive server that does not close: the read completes without waiting.
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
        let m = tokio::time::timeout(Duration::from_secs(2), read_http_response(&mut b, 100))
            .await
            .expect("must not wait for close")
            .unwrap();
        assert_eq!(m.body, b"ok");
        drop(a);
    }

    #[test]
    fn ssdp_response_variants_and_long_location() {
        for r in [
            "HTTP/1.0 200 OK\r\nLOCATION: http://1.2.3.4/x\r\n\r\n",
            "HTTP/1.1 200 OK\nLOCATION: http://1.2.3.4/x\nSERVER: a\n\n",
            "HTTP/1.1 200 OK\r\nlocation: http://1.2.3.4/x\r\n\r\n",
        ] {
            let h = parse_ssdp_response(r.as_bytes()).unwrap();
            assert_eq!(h.location.as_deref(), Some("http://1.2.3.4/x"), "{r:?}");
        }
        // A long LOCATION is kept whole (not cut at the 256-character name cap).
        let long = format!("http://1.2.3.4/{}", "a".repeat(600));
        let mut bytes = format!("HTTP/1.1 200 OK\r\nLOCATION: {long}\r\nSERVER: Caf").into_bytes();
        // Non-UTF-8 (Latin-1) server text is tolerated.
        bytes.extend_from_slice(b"\xe9\r\n\r\n");
        let h = parse_ssdp_response(&bytes).unwrap();
        assert_eq!(h.location.as_deref(), Some(long.as_str()));
        assert!(h.server.unwrap().starts_with("Caf"));
    }

    #[test]
    fn latin1_description_is_decoded_lossily() {
        let latin1 = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root><device><friendlyName>Caf\xe9</friendlyName><manufacturer>Acme</manufacturer></device></root>";
        let i = parse_device_description(latin1);
        assert!(i.friendly_name.unwrap().starts_with("Caf"));
        assert_eq!(i.manufacturer.as_deref(), Some("Acme"));
    }

    /// Table-driven classification: URN first, whole-word keywords (review M6).
    #[test]
    fn classification_table() {
        let s = |dt: &str, fname: &str, manu: &str, model: &str, desc: &str| SsdpInfo {
            device_type: (!dt.is_empty()).then(|| dt.into()),
            friendly_name: (!fname.is_empty()).then(|| fname.into()),
            manufacturer: (!manu.is_empty()).then(|| manu.into()),
            model_name: (!model.is_empty()).then(|| model.into()),
            model_description: (!desc.is_empty()).then(|| desc.into()),
            ..SsdpInfo::default()
        };
        let urn = |t: &str| format!("urn:schemas-upnp-org:device:{t}:1");
        let cases: Vec<(&str, SsdpInfo, Option<&str>)> = vec![
            (
                "LG webOS TV",
                s(
                    &urn("MediaRenderer"),
                    "[LG] webOS TV OLED55C1PUB",
                    "LG Electronics",
                    "LG TV",
                    "",
                ),
                Some("tv"),
            ),
            (
                "Sony Bravia",
                s(
                    &urn("MediaRenderer"),
                    "BRAVIA KD-55X85J",
                    "Sony Corporation",
                    "KD-55X85J",
                    "",
                ),
                Some("tv"),
            ),
            (
                "Samsung TV",
                s(
                    &urn("MediaRenderer"),
                    "[TV] Samsung Q60 Series (55)",
                    "Samsung Electronics",
                    "QN55Q60RAFXZA",
                    "Samsung TV DMR",
                ),
                Some("tv"),
            ),
            (
                "Synology DLNA",
                s(
                    &urn("MediaServer"),
                    "DS220+",
                    "Synology",
                    "DS220+",
                    "Synology DLNA/UPnP Media Server",
                ),
                Some("nas"),
            ),
            (
                "Panasonic camera",
                s(
                    &urn("Basic"),
                    "WV-S1131",
                    "Panasonic",
                    "WV-S1131",
                    "Network Camera",
                ),
                Some("camera"),
            ),
            (
                "Panasonic printer",
                s(
                    &urn("Basic"),
                    "KX-MB2120",
                    "Panasonic",
                    "KX-MB2120",
                    "Multi-Function Printer",
                ),
                Some("printer"),
            ),
            (
                "Printer w/ duplex",
                s(
                    &urn("Printer"),
                    "Office MFP",
                    "Brother",
                    "MFC-L2750DW",
                    "Monochrome laser, automatic duplex",
                ),
                Some("printer"),
            ),
            (
                "Windows WMP",
                s(
                    &urn("MediaServer"),
                    "DESKTOP-1: user:",
                    "Microsoft Corporation",
                    "Windows Media Player Sharing",
                    "Media Server",
                ),
                Some("media_server"),
            ),
            (
                "Sonos",
                s(
                    "urn:schemas-upnp-org:device:ZonePlayer:1",
                    "Sonos One",
                    "Sonos, Inc.",
                    "Sonos One",
                    "",
                ),
                Some("media_player"),
            ),
            (
                "Hue bridge",
                s(
                    &urn("Basic"),
                    "Hue Bridge",
                    "Signify",
                    "Philips hue bridge 2015",
                    "Philips hue Personal Wireless Lighting",
                ),
                None,
            ),
            (
                "IGD",
                s(&urn("InternetGatewayDevice"), "", "", "", ""),
                Some("igd_router"),
            ),
            (
                "Plex",
                s("", "Plex Media Server", "Plex, Inc.", "", ""),
                Some("media_server"),
            ),
        ];
        for (label, info, want) in cases {
            assert_eq!(classify_ssdp_kind(&info).as_deref(), want, "{label}");
        }
    }
}
