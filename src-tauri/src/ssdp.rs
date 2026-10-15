//! SSDP / UPnP discovery (UDP 1900).
//!
//! Sends SSDP `M-SEARCH` requests to the `239.255.255.250:1900` multicast group (and the IPv6
//! groups when enabled), collects the responders for a bounded window, then fetches each
//! device's description XML — but **only** when the `LOCATION` URL's host is the IP that
//! answered, over plain HTTP, with a size cap, a timeout and same-origin redirects only. This
//! closes the obvious SSRF: a hostile responder cannot point `LOCATION` at an internal service.
//!
//! The XML is parsed with a hardened `quick-xml` pull reader (no DTD / entity expansion, so a
//! "billion laughs" description cannot blow up memory) into model / serial / service data, and
//! every string is run through [`sanitize_text`]. Pure parsers are unit tested; the
//! SSRF-guarded fetch is tested against a local HTTP responder.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    time::Duration,
};

use futures::StreamExt;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};
use tokio_util::sync::CancellationToken;

use crate::{
    limits::SocketBudget,
    models::{sanitize_text, SsdpInfo, MAX_SERVICE_LIST},
};

/// IPv4 SSDP multicast group.
const SSDP_MCAST_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;
/// Size cap on a fetched device description (hostile-input bound).
const MAX_DESCRIPTION_BYTES: usize = 256 * 1024;
/// Reply datagram buffer (SOAP-over-UDP WS-Discovery replies can be several KiB).
const MAX_DATAGRAM: usize = 64 * 1024;
/// Responders processed per discovery run (bounds work on a hostile segment).
const MAX_RESPONDERS: usize = 512;
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
    let text = std::str::from_utf8(buf).ok()?;
    let mut lines = text.split("\r\n");
    let start = lines.next()?;
    // Accept either an M-SEARCH response (`HTTP/1.1 200 OK`) or a NOTIFY advertisement.
    let ok = start.starts_with("HTTP/1.1 200") || start.starts_with("NOTIFY");
    if !ok {
        return None;
    }
    let mut h = SsdpHeaders::default();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = sanitize_text(value.trim());
        if value.is_empty() {
            continue;
        }
        match name.trim().to_ascii_uppercase().as_str() {
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

/// Classify the device kind from the parsed description (deviceType URN plus model / server
/// text). Returns a coarse `device_kind` label, or `None` when nothing matches.
pub fn classify_ssdp_kind(info: &SsdpInfo) -> Option<String> {
    let hay = [
        info.device_type.as_deref(),
        info.model_name.as_deref(),
        info.model_description.as_deref(),
        info.friendly_name.as_deref(),
        info.manufacturer.as_deref(),
        info.server.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
    .to_ascii_lowercase();
    let any = |ns: &[&str]| ns.iter().any(|n| hay.contains(n));

    let kind = if any(&["internetgatewaydevice", "wandevice", "wanconnectiondevice"]) {
        "igd_router"
    } else if any(&[
        "mediaserver",
        "contentdirectory",
        "mediarenderer",
        "dlna",
        "plex",
        "jellyfin",
        "emby",
    ]) {
        "media_server"
    } else if any(&[
        "printer",
        "printbasic",
        "ipp",
        "jetdirect",
        "laserjet",
        "officejet",
    ]) {
        "printer"
    } else if any(&["scanner", "scan:"]) {
        "scanner"
    } else if any(&[
        "tvdevice",
        " tv ",
        "smart tv",
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
    ]) {
        "tv"
    } else if any(&[
        "synology",
        "qnap",
        "diskstation",
        "nas",
        "readynas",
        "western digital",
        "wd my cloud",
        "truenas",
    ]) {
        "nas"
    } else if any(&[
        "camera",
        "ipcamera",
        "network video",
        "hikvision",
        "dahua",
        "axis",
        "onvif",
    ]) {
        "camera"
    } else {
        return None;
    };
    Some(kind.to_string())
}

/// Deepest element nesting the XML walker follows (hostile-input bound).
const MAX_XML_DEPTH: usize = 64;
/// Events processed per document (hostile-input bound; documents are also size-capped).
const MAX_XML_EVENTS: usize = 100_000;
/// Text accumulated for one element before further text is dropped.
const MAX_XML_TEXT: usize = 4096;

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
/// and per-element text are bounded. Text is sanitized before `f` sees it. Malformed input
/// simply ends the walk.
pub(crate) fn for_each_xml_text(xml: &[u8], mut f: impl FnMut(&[String], &str)) {
    use quick_xml::{events::Event, Reader};

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
            let value = sanitize_text(text);
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
                *slot = Some(value.to_string());
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
            "servicetype"
                if info.services.len() < MAX_SERVICE_LIST
                    && !info.services.iter().any(|s| s == value) =>
            {
                info.services.push(value.to_string());
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
/// collect reply datagrams for `window`: at most `max_sources` distinct responders, and for a
/// unicast target only datagrams from that host. Holds one socket permit for the exchange.
pub(crate) async fn exchange_udp(
    target: DiscoveryTarget,
    port: u16,
    group_v4: Ipv4Addr,
    payloads: &[Vec<u8>],
    window: Duration,
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
    let mut sources: std::collections::HashSet<IpAddr> = std::collections::HashSet::new();
    let mut buf = vec![0u8; MAX_DATAGRAM];
    while !cancel.is_cancelled() {
        let recv = tokio::select! {
            _ = cancel.cancelled() => break,
            r = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)) => r,
        };
        let Ok(Ok((n, from))) = recv else { break };
        let ip = from.ip();
        if only.is_some_and(|o| o != ip) {
            continue;
        }
        if !sources.contains(&ip) && sources.len() >= MAX_RESPONDERS {
            continue;
        }
        sources.insert(ip);
        // Bound the total retained datagrams too (a responder may repeat itself).
        if out.len() < MAX_RESPONDERS * 8 {
            out.push((ip, buf[..n].to_vec()));
        }
    }
    out
}

/// Discover UPnP devices for `window` over IPv4 multicast from the interface address `v4`
/// and, when `v6_index` is given, IPv6 multicast (`ff02::c` / `ff05::c`) on that interface.
/// Returns responder IP → [`SsdpInfo`] (headers plus the description fetched from the
/// responder itself).
pub async fn discover_ssdp(
    v4: Option<Ipv4Addr>,
    v6_index: Option<u32>,
    window: Duration,
    budget: &SocketBudget,
    cancel: &CancellationToken,
) -> HashMap<IpAddr, SsdpInfo> {
    let payloads: Vec<Vec<u8>> = SEARCH_TARGETS
        .iter()
        .map(|st| build_msearch(st, 2))
        .collect();
    let v4_fut = async {
        match v4 {
            Some(ip) => {
                let t = DiscoveryTarget::MulticastV4(ip);
                exchange_udp(
                    t,
                    SSDP_PORT,
                    SSDP_MCAST_V4,
                    &payloads,
                    window,
                    budget,
                    cancel,
                )
                .await
            }
            None => Vec::new(),
        }
    };
    let v6_fut = async {
        match v6_index {
            Some(index) => {
                let t = DiscoveryTarget::MulticastV6(index);
                exchange_udp(
                    t,
                    SSDP_PORT,
                    SSDP_MCAST_V4,
                    &payloads,
                    window,
                    budget,
                    cancel,
                )
                .await
            }
            None => Vec::new(),
        }
    };
    let (a, b) = tokio::join!(v4_fut, v6_fut);
    describe_responders(a.into_iter().chain(b), budget, cancel).await
}

/// Unicast SSDP probe of one host (`M-SEARCH` straight to `ip:1900`), for the details drawer.
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
        budget,
        cancel,
    )
    .await;
    describe_responders(replies, budget, cancel)
        .await
        .remove(&ip)
}

/// Fold reply datagrams into per-responder headers, then fetch each responder's description
/// (SSRF-guarded) and build the result map.
async fn describe_responders(
    replies: impl IntoIterator<Item = (IpAddr, Vec<u8>)>,
    budget: &SocketBudget,
    cancel: &CancellationToken,
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
    // Fetch descriptions concurrently (bounded; every socket also draws from `budget`).
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
                if !cancel.is_cancelled() {
                    if let Some(body) = fetch_description(ip, &url, budget, cancel).await {
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
/// only. Returns the body bytes, or `None` on any error / policy violation.
pub async fn fetch_description(
    responder: IpAddr,
    url: &HttpUrl,
    budget: &SocketBudget,
    cancel: &CancellationToken,
) -> Option<Vec<u8>> {
    let mut url = url.clone();
    for _ in 0..=MAX_REDIRECTS {
        // Never connect anywhere but the responder itself.
        if !url_host_is(&url, responder) {
            return None;
        }
        let _permit = budget.acquire().await?;
        let resp = tokio::select! {
            _ = cancel.cancelled() => return None,
            r = http_get(responder, &url) => r,
        }?;
        drop(_permit);
        match resp.status {
            200 => return Some(resp.body),
            301 | 302 | 303 | 307 | 308 => {
                let next = resp.location?;
                let next = parse_http_url(&next)?;
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

/// A minimal HTTP response (status code, `Location` for redirects, body up to the cap).
struct HttpResponse {
    status: u16,
    location: Option<String>,
    body: Vec<u8>,
}

/// Perform one HTTP/1.0 GET to `ip:url.port` for `url.path`, reading at most
/// [`MAX_DESCRIPTION_BYTES`] of body, under a short timeout.
async fn http_get(ip: IpAddr, url: &HttpUrl) -> Option<HttpResponse> {
    let timeout = Duration::from_secs(4);
    let fut = async {
        let mut stream = TcpStream::connect(SocketAddr::new(ip, url.port))
            .await
            .ok()?;
        let req = format!(
            "GET {} HTTP/1.0\r\nHost: {}:{}\r\nUser-Agent: SweepR/1.0\r\nAccept: */*\r\n\
             Connection: close\r\n\r\n",
            url.path, url.host, url.port
        );
        stream.write_all(req.as_bytes()).await.ok()?;
        let mut raw = Vec::with_capacity(4096);
        let mut chunk = [0u8; 4096];
        // Read headers + body, capped (leave room for a header block).
        let cap = MAX_DESCRIPTION_BYTES + 8 * 1024;
        loop {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&chunk[..n]);
            if raw.len() >= cap {
                raw.truncate(cap);
                break;
            }
        }
        Some(raw)
    };
    let raw = tokio::time::timeout(timeout, fut).await.ok()??;
    parse_http_response(&raw)
}

/// Split an HTTP response into status / Location / body (bounded).
fn parse_http_response(raw: &[u8]) -> Option<HttpResponse> {
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..sep]).ok()?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next()?;
    // `HTTP/1.x <code> <reason>`
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;
    let mut location = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("location") {
                location = Some(value.trim().to_string());
            }
        }
    }
    let mut body = raw[sep + 4..].to_vec();
    body.truncate(MAX_DESCRIPTION_BYTES);
    Some(HttpResponse {
        status,
        location,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let body = fetch_description(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &url,
            &SocketBudget::new(2),
            &CancellationToken::new(),
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
            &budget,
            &cancel,
        )
        .await;
        assert_eq!(replies.len(), 1);
        let map = describe_responders(replies, &budget, &cancel).await;
        let info = &map[&IpAddr::V4(Ipv4Addr::LOCALHOST)];
        assert_eq!(info.model_name.as_deref(), Some("DS220+"));
        assert_eq!(info.serial_number.as_deref(), Some("2010ABCDEF"));
        assert!(info.server.as_deref().unwrap().contains("Synology"));
        assert_eq!(classify_ssdp_kind(info).as_deref(), Some("media_server"));
        let _ = (udp_task.await, http_task.await);

        // A reply naming a foreign LOCATION host keeps its headers but fetches nothing.
        let foreign = vec![(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            b"HTTP/1.1 200 OK\r\nLOCATION: http://169.254.169.254/latest\r\nSERVER: x\r\n\r\n"
                .to_vec(),
        )];
        let map = describe_responders(foreign, &budget, &cancel).await;
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
        let body = fetch_description(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &url,
            &SocketBudget::new(2),
            &CancellationToken::new(),
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
        let res = fetch_description(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &url,
            &SocketBudget::new(2),
            &CancellationToken::new(),
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
        let res = fetch_description(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &url,
            &SocketBudget::new(2),
            &CancellationToken::new(),
        )
        .await;
        assert!(res.is_none());
    }
}
