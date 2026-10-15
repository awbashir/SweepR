//! SIP OPTIONS discovery (UDP/TCP 5060).
//!
//! Sends an RFC 3261-conformant `OPTIONS` request (unique Call-ID / branch / tag, `Max-Forwards`
//! 70, `Via` with `rport`, `Contact`, `Accept: application/sdp`) to a candidate over UDP 5060
//! first, then TCP 5060. The response's status line and `Server` / `User-Agent` / `Allow` /
//! `Supported` headers are parsed and run through a vendor pattern table to name the PBX
//! (Asterisk/FreePBX, 3CX, Cisco CUCM, FreeSWITCH, Kamailio/OpenSIPS, Yeastar, Grandstream UCM)
//! or the desk phone (Yealink, Grandstream, Poly/Polycom, Cisco SPA/CP, Snom, Fanvil, …) with
//! its model and firmware.
//!
//! No credentials are ever sent and no registration is attempted: this is an identification
//! ping only. Pure parsers / the pattern table are unit tested; the probe is tested against a
//! local UDP responder on loopback.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};
use tokio_util::sync::CancellationToken;

use crate::{
    limits::SocketBudget,
    models::{now_ms, sanitize_text, SipInfo, DEVICE_KIND_PBX, DEVICE_KIND_VOIP_PHONE},
};

/// Standard SIP port.
pub const SIP_PORT: u16 = 5060;
const MAX_RESPONSE_BYTES: usize = 16 * 1024;

/// A per-process-unique SIP token (Call-ID / tag / branch nonce).
fn unique_token() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut state =
        now_ms() ^ (u64::from(std::process::id()) << 24) ^ seq.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    format!("{state:016x}")
}

/// Which transport an OPTIONS request is sent over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SipTransport {
    Udp,
    Tcp,
}

impl SipTransport {
    fn via(self) -> &'static str {
        match self {
            SipTransport::Udp => "UDP",
            SipTransport::Tcp => "TCP",
        }
    }

    fn label(self) -> &'static str {
        match self {
            SipTransport::Udp => "udp",
            SipTransport::Tcp => "tcp",
        }
    }
}

/// Build an RFC 3261 `OPTIONS` request to `target` from `local`, over `transport`.
pub fn build_options(local: SocketAddr, target: SocketAddr, transport: SipTransport) -> String {
    let branch = format!("z9hG4bK{}", unique_token());
    let tag = unique_token();
    let call_id = format!("{}@{}", unique_token(), local.ip());
    let via = transport.via();
    format!(
        "OPTIONS sip:{tip}:{tport} SIP/2.0\r\n\
         Via: SIP/2.0/{via} {lip}:{lport};branch={branch};rport\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:sweepr@{lip}>;tag={tag}\r\n\
         To: <sip:{tip}:{tport}>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 OPTIONS\r\n\
         Contact: <sip:sweepr@{lip}:{lport}>\r\n\
         Accept: application/sdp\r\n\
         User-Agent: SweepR/1.0\r\n\
         Content-Length: 0\r\n\r\n",
        tip = target.ip(),
        tport = target.port(),
        lip = local.ip(),
        lport = local.port(),
    )
}

/// A parsed SIP response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SipResponse {
    pub status: Option<String>,
    pub server: Option<String>,
    pub user_agent: Option<String>,
    pub allow: Option<String>,
    pub supported: Option<String>,
    pub contact: Option<String>,
}

/// Parse a SIP response message (`SIP/2.0 <code> <reason>` + headers). Returns `None` when the
/// first line is not a SIP status line.
pub fn parse_sip_response(buf: &[u8]) -> Option<SipResponse> {
    let text = std::str::from_utf8(buf).ok()?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next()?;
    let rest = status_line.strip_prefix("SIP/2.0 ")?;
    let mut r = SipResponse {
        status: Some(sanitize_text(rest.trim())),
        ..SipResponse::default()
    };
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
        match name.trim().to_ascii_lowercase().as_str() {
            "server" => r.server = Some(value),
            "user-agent" => r.user_agent = Some(value),
            "allow" => r.allow = Some(value),
            "supported" | "k" => {
                r.supported.get_or_insert(value);
            }
            "contact" | "m" => {
                r.contact.get_or_insert(value);
            }
            _ => {}
        }
    }
    Some(r)
}

/// `true` when an OUI vendor name belongs to a VoIP-endpoint maker, used to pick SIP probe
/// candidates without an open-port hint.
pub fn is_voip_vendor(vendor: &str) -> bool {
    const VENDORS: &[&str] = &[
        "yealink",
        "grandstream",
        "polycom",
        "poly",
        "cisco",
        "snom",
        "fanvil",
        "avaya",
        "mitel",
        "sangoma",
        "audiocodes",
        "gigaset",
        "htek",
        "akuvox",
    ];
    let v = vendor.to_ascii_lowercase();
    VENDORS.iter().any(|n| v.contains(n))
}

/// Identify `(vendor, model, firmware, kind)` from a SIP `Server` / `User-Agent` string.
/// `kind` is [`DEVICE_KIND_PBX`] or [`DEVICE_KIND_VOIP_PHONE`] when recognised. Tested against
/// a range of real-format identifiers.
pub fn identify(
    agent: Option<&str>,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let Some(agent) = agent.map(str::trim).filter(|s| !s.is_empty()) else {
        return (None, None, None, None);
    };
    let lower = agent.to_ascii_lowercase();

    // --- PBX / softswitch identifiers (checked first; several share phone keywords). ---
    let pbx = |vendor: &str, model: Option<&str>| {
        (
            Some(vendor.to_string()),
            model.map(String::from),
            extract_version(agent),
            Some(DEVICE_KIND_PBX.to_string()),
        )
    };
    if lower.contains("freeswitch") {
        return pbx("FreeSWITCH", None);
    }
    if lower.contains("asterisk") {
        return pbx("Asterisk", None);
    }
    if lower.starts_with("fpbx") || lower.contains("freepbx") {
        return pbx("FreePBX", None);
    }
    if lower.contains("issabel") {
        return pbx("Issabel", None);
    }
    if lower.contains("3cx") {
        return pbx("3CX", None);
    }
    if lower.contains("kamailio") {
        return pbx("Kamailio", None);
    }
    if lower.contains("opensips") || lower.contains("openser") {
        return pbx("OpenSIPS", None);
    }
    if lower.contains("cucm")
        || lower.contains("communicationsmanager")
        || lower.contains("cisco-sipgateway")
    {
        return pbx("Cisco CUCM", None);
    }
    if lower.contains("yeastar") {
        return pbx("Yeastar", None);
    }
    if lower.contains("ucm") && lower.contains("grandstream") {
        return pbx("Grandstream UCM", None);
    }

    // --- Desk phones (vendor + model + firmware). ---
    let phone = |vendor: &str, model: Option<String>, fw: Option<String>| {
        (
            Some(vendor.to_string()),
            model,
            fw,
            Some(DEVICE_KIND_VOIP_PHONE.to_string()),
        )
    };
    // "Yealink SIP-T54W 96.86.0.5"
    if lower.contains("yealink") {
        let mut parts = agent.split_whitespace();
        let _ = parts.next(); // "Yealink"
        let model = parts.next().map(sanitize_text).filter(|m| !m.is_empty());
        let fw = parts.next().map(sanitize_text).filter(|m| !m.is_empty());
        return phone("Yealink", model, fw);
    }
    // "Grandstream GXP2170 1.0.11.70" / "Grandstream HT801 ..."
    if lower.contains("grandstream") {
        let mut parts = agent.split_whitespace();
        let _ = parts.next();
        let model = parts.next().map(sanitize_text).filter(|m| !m.is_empty());
        let fw = parts.next().map(sanitize_text).filter(|m| !m.is_empty());
        return phone("Grandstream", model, fw);
    }
    // "PolycomVVX-VVX_411-UA/5.9.5.0614" or "Polycom/5.9.5 ..."
    if lower.contains("polycom") || lower.starts_with("poly") {
        let (model, fw) = split_slash(agent);
        let model = model
            .strip_prefix("Polycom")
            .map(str::to_string)
            .filter(|m| !m.is_empty())
            .or(Some(model));
        return phone("Poly", model, fw);
    }
    // "snom870/8.7.5.35"
    if lower.starts_with("snom") {
        let (model, fw) = split_slash(agent);
        return phone("Snom", Some(model), fw);
    }
    // "Fanvil X4/2.12.5.6938"
    if lower.contains("fanvil") {
        let (model, fw) = split_slash(agent);
        let model = model.replace("Fanvil", "");
        let model = sanitize_text(model.trim());
        return phone("Fanvil", (!model.is_empty()).then_some(model), fw);
    }
    // "Cisco-CP8841/12.6.1" / "Cisco/SPA504G-7.6.2"
    if lower.contains("cisco") {
        let (model, fw) = split_slash(agent);
        // "Cisco/SPA504G-7.6.2d": the model and firmware both follow the slash.
        if model.eq_ignore_ascii_case("cisco") {
            if let Some(rest) = fw {
                let (m, f) = match rest.split_once('-') {
                    Some((m, f)) => (m.to_string(), Some(f.to_string())),
                    None => (rest, None),
                };
                return phone(
                    "Cisco",
                    Some(sanitize_text(&m)),
                    f.map(|f| sanitize_text(&f)),
                );
            }
        }
        let model = model
            .trim_start_matches("Cisco-")
            .trim_start_matches("Cisco/")
            .trim_start_matches("Cisco ")
            .to_string();
        let model = sanitize_text(model.trim());
        return phone("Cisco", (!model.is_empty()).then_some(model), fw);
    }
    // Avaya / Mitel desk phones.
    if lower.contains("avaya") {
        let (model, fw) = split_slash(agent);
        return phone("Avaya", Some(model), fw);
    }
    if lower.contains("mitel") {
        let (model, fw) = split_slash(agent);
        return phone("Mitel", Some(model), fw);
    }

    // Unknown but still a SIP agent: keep the raw string as the vendor, no kind.
    (
        Some(sanitize_text(agent)),
        None,
        extract_version(agent),
        None,
    )
}

/// Split a `product/version` identifier into `(product, Some(version))`.
fn split_slash(s: &str) -> (String, Option<String>) {
    match s.split_once('/') {
        Some((p, v)) => (
            sanitize_text(p.trim()),
            Some(sanitize_text(v.trim())).filter(|v| !v.is_empty()),
        ),
        None => (sanitize_text(s.trim()), None),
    }
}

/// Pull a dotted version number out of a free-form agent string (first token that looks like
/// `N.N[.N...]`), or the content of the last `(...)` group (FreePBX / Asterisk style).
fn extract_version(s: &str) -> Option<String> {
    // Prefer a parenthesised version, e.g. "FPBX-15.0.17(16.20.0)".
    if let (Some(open), Some(close)) = (s.rfind('('), s.rfind(')')) {
        if open < close {
            let inner = s[open + 1..close].trim();
            if looks_like_version(inner) {
                return Some(sanitize_text(inner));
            }
        }
    }
    for token in s.split(|c: char| c.is_whitespace() || c == '/' || c == '-') {
        let token = token.trim_matches(|c: char| c == '(' || c == ')');
        if looks_like_version(token) {
            return Some(sanitize_text(token));
        }
    }
    None
}

/// `true` for a dotted numeric version like `5.9.5` or `96.86.0.5`.
fn looks_like_version(s: &str) -> bool {
    let mut dots = 0;
    if s.is_empty() {
        return false;
    }
    for c in s.chars() {
        match c {
            '0'..='9' => {}
            '.' => dots += 1,
            _ => return false,
        }
    }
    dots >= 1
}

/// Probe one host with SIP OPTIONS over UDP then TCP. `local_ip` is the scanning interface's
/// address (used in the `Via` / `Contact` / `From` headers). Returns the identified
/// [`SipInfo`], or `None` when neither transport answers within `timeout`.
pub async fn probe_sip(
    target: IpAddr,
    local_ip: IpAddr,
    timeout: Duration,
    budget: &SocketBudget,
    cancel: &CancellationToken,
) -> Option<SipInfo> {
    probe_sip_at(
        SocketAddr::new(target, SIP_PORT),
        local_ip,
        timeout,
        budget,
        cancel,
    )
    .await
}

/// [`probe_sip`] against an explicit address (tests point it at a loopback responder).
pub async fn probe_sip_at(
    dst: SocketAddr,
    local_ip: IpAddr,
    timeout: Duration,
    budget: &SocketBudget,
    cancel: &CancellationToken,
) -> Option<SipInfo> {
    // UDP first (the primary SIP transport), then TCP. Both are cancellable.
    let udp = tokio::select! {
        _ = cancel.cancelled() => return None,
        r = probe_udp(dst, local_ip, timeout, budget) => r,
    };
    if udp.is_some() {
        return udp;
    }
    tokio::select! {
        _ = cancel.cancelled() => None,
        r = probe_tcp(dst, local_ip, timeout, budget) => r,
    }
}

async fn probe_udp(
    dst: SocketAddr,
    local_ip: IpAddr,
    timeout: Duration,
    budget: &SocketBudget,
) -> Option<SipInfo> {
    let _permit = budget.acquire().await?;
    let bind: SocketAddr = match dst {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let sock = UdpSocket::bind(bind).await.ok()?;
    // Connected: the kernel drops datagrams from anyone but the target.
    sock.connect(dst).await.ok()?;
    let local = SocketAddr::new(local_ip, sock.local_addr().ok()?.port());
    let req = build_options(local, dst, SipTransport::Udp);
    sock.send(req.as_bytes()).await.ok()?;
    let mut buf = vec![0u8; MAX_RESPONSE_BYTES];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let n = tokio::time::timeout_at(deadline, sock.recv(&mut buf))
            .await
            .ok()?
            .ok()?;
        // Skip provisional 1xx responses (e.g. 100 Trying) and wait for a final one.
        match parse_sip_response(&buf[..n]) {
            Some(r) if r.status.as_deref().is_some_and(|s| s.starts_with('1')) => continue,
            Some(r) => return Some(to_info(r, SipTransport::Udp)),
            None => continue,
        }
    }
}

async fn probe_tcp(
    dst: SocketAddr,
    local_ip: IpAddr,
    timeout: Duration,
    budget: &SocketBudget,
) -> Option<SipInfo> {
    let _permit = budget.acquire().await?;
    let fut = async {
        let mut stream = TcpStream::connect(dst).await.ok()?;
        let local = SocketAddr::new(local_ip, stream.local_addr().ok()?.port());
        let req = build_options(local, dst, SipTransport::Tcp);
        stream.write_all(req.as_bytes()).await.ok()?;
        // Read until the end of the header block of a final (non-1xx) response, bounded.
        let mut raw: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&chunk[..n]);
            if raw.len() >= MAX_RESPONSE_BYTES {
                raw.truncate(MAX_RESPONSE_BYTES);
                break;
            }
            // Drop complete provisional responses at the front.
            while raw.starts_with(b"SIP/2.0 1") {
                match raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    Some(end) => {
                        raw.drain(..end + 4);
                    }
                    None => break,
                }
            }
            if !raw.starts_with(b"SIP/2.0 1") && raw.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        (!raw.is_empty()).then_some(raw)
    };
    let raw = tokio::time::timeout(timeout, fut).await.ok()??;
    parse_sip_response(&raw).map(|r| to_info(r, SipTransport::Tcp))
}

/// Turn a parsed response into a [`SipInfo`], running the identity pattern table.
fn to_info(r: SipResponse, transport: SipTransport) -> SipInfo {
    let agent = r.server.as_deref().or(r.user_agent.as_deref());
    let (vendor, model, firmware, kind) = identify(agent);
    SipInfo {
        status: r.status,
        server: r.server,
        user_agent: r.user_agent,
        allow: r.allow,
        supported: r.supported,
        transport: Some(transport.label().to_string()),
        vendor,
        model,
        firmware,
        kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_request_is_rfc3261_conformant() {
        let local: SocketAddr = "192.168.1.5:5062".parse().unwrap();
        let target: SocketAddr = "192.168.1.50:5060".parse().unwrap();
        let req = build_options(local, target, SipTransport::Udp);
        assert!(req.starts_with("OPTIONS sip:192.168.1.50:5060 SIP/2.0\r\n"));
        assert!(req.contains("Via: SIP/2.0/UDP 192.168.1.5:5062;branch=z9hG4bK"));
        assert!(req.contains(";rport"));
        assert!(req.contains("Max-Forwards: 70\r\n"));
        assert!(req.contains("CSeq: 1 OPTIONS\r\n"));
        assert!(req.contains("Accept: application/sdp\r\n"));
        assert!(req.contains("Content-Length: 0\r\n"));
        assert!(req.contains(";tag="));
        assert!(req.contains("Call-ID:"));
        assert!(req.ends_with("\r\n\r\n"));
        // Branch / Call-ID vary between requests.
        let req2 = build_options(local, target, SipTransport::Tcp);
        assert!(req2.contains("Via: SIP/2.0/TCP"));
        assert_ne!(req, req2);
    }

    #[test]
    fn parses_sip_response() {
        let resp = "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.168.1.5:5062;branch=z9hG4bKabc\r\n\
                    From: <sip:sweepr@192.168.1.5>;tag=x\r\nTo: <sip:192.168.1.50>;tag=y\r\n\
                    Call-ID: abc@192.168.1.5\r\nCSeq: 1 OPTIONS\r\n\
                    Server: Yealink SIP-T54W 96.86.0.5\r\n\
                    Allow: INVITE, ACK, CANCEL, OPTIONS, BYE\r\n\
                    Supported: replaces\r\nContent-Length: 0\r\n\r\n";
        let r = parse_sip_response(resp.as_bytes()).unwrap();
        assert_eq!(r.status.as_deref(), Some("200 OK"));
        assert_eq!(r.server.as_deref(), Some("Yealink SIP-T54W 96.86.0.5"));
        assert!(r.allow.as_deref().unwrap().contains("OPTIONS"));
        assert_eq!(r.supported.as_deref(), Some("replaces"));
        assert!(parse_sip_response(b"HTTP/1.1 200 OK\r\n\r\n").is_none());
    }

    #[test]
    fn identifies_phones_and_pbxes() {
        // (agent, expected vendor, expected model substring, expected kind)
        let cases: &[(&str, &str, Option<&str>, &str)] = &[
            (
                "Yealink SIP-T54W 96.86.0.5",
                "Yealink",
                Some("SIP-T54W"),
                DEVICE_KIND_VOIP_PHONE,
            ),
            (
                "Grandstream GXP2170 1.0.11.70",
                "Grandstream",
                Some("GXP2170"),
                DEVICE_KIND_VOIP_PHONE,
            ),
            (
                "PolycomVVX-VVX_411-UA/5.9.5.0614",
                "Poly",
                Some("VVX"),
                DEVICE_KIND_VOIP_PHONE,
            ),
            (
                "snom870/8.7.5.35",
                "Snom",
                Some("snom870"),
                DEVICE_KIND_VOIP_PHONE,
            ),
            (
                "Fanvil X4/2.12.5.6938",
                "Fanvil",
                Some("X4"),
                DEVICE_KIND_VOIP_PHONE,
            ),
            (
                "Cisco-CP8841/12.6.1",
                "Cisco",
                Some("CP8841"),
                DEVICE_KIND_VOIP_PHONE,
            ),
            (
                "Cisco/SPA504G-7.6.2d",
                "Cisco",
                Some("SPA504G"),
                DEVICE_KIND_VOIP_PHONE,
            ),
            ("Asterisk PBX 16.20.0", "Asterisk", None, DEVICE_KIND_PBX),
            ("FPBX-15.0.17(16.20.0)", "FreePBX", None, DEVICE_KIND_PBX),
            ("3CXPhoneSystem 18.0.3.461", "3CX", None, DEVICE_KIND_PBX),
            (
                "FreeSWITCH-mod_sofia/1.10.7-release",
                "FreeSWITCH",
                None,
                DEVICE_KIND_PBX,
            ),
            (
                "kamailio (5.5.2 (x86_64/linux))",
                "Kamailio",
                None,
                DEVICE_KIND_PBX,
            ),
            (
                "OpenSIPS (3.1.3 (x86_64/linux))",
                "OpenSIPS",
                None,
                DEVICE_KIND_PBX,
            ),
        ];
        for (agent, vendor, model, kind) in cases {
            let (v, m, _fw, k) = identify(Some(agent));
            assert_eq!(v.as_deref(), Some(*vendor), "vendor for {agent}");
            assert_eq!(k.as_deref(), Some(*kind), "kind for {agent}");
            if let Some(model) = model {
                assert!(
                    m.as_deref().unwrap_or("").contains(model),
                    "model for {agent}: got {m:?}, want substring {model}"
                );
            }
        }
        // Firmware extraction on a few.
        let (_, _, fw, _) = identify(Some("Yealink SIP-T54W 96.86.0.5"));
        assert_eq!(fw.as_deref(), Some("96.86.0.5"));
        let (_, _, fw, _) = identify(Some("FPBX-15.0.17(16.20.0)"));
        assert_eq!(fw.as_deref(), Some("16.20.0"));
        // Unknown agent: vendor kept, no kind.
        let (v, _, _, k) = identify(Some("MyCustomUA/1.0"));
        assert_eq!(v.as_deref(), Some("MyCustomUA/1.0"));
        assert!(k.is_none());
        assert_eq!(identify(None), (None, None, None, None));
    }

    #[test]
    fn voip_vendor_detection() {
        assert!(is_voip_vendor("Yealink( GmbH )"));
        assert!(is_voip_vendor("Grandstream Networks, Inc."));
        assert!(is_voip_vendor("Polycom"));
        assert!(!is_voip_vendor("Apple, Inc."));
    }

    /// The UDP probe against a local responder that answers an OPTIONS with a 200 OK naming a
    /// Grandstream phone.
    #[tokio::test]
    async fn probes_local_udp_responder() {
        let responder = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = responder.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            if let Ok((n, from)) = responder.recv_from(&mut buf).await {
                let req = std::str::from_utf8(&buf[..n]).unwrap_or("").to_string();
                // A provisional response first: the probe must wait for the final one.
                let _ = responder
                    .send_to(b"SIP/2.0 100 Trying\r\nContent-Length: 0\r\n\r\n", from)
                    .await;
                let reply = "SIP/2.0 200 OK\r\nServer: Grandstream GXP2170 1.0.11.70\r\n\
                             Allow: INVITE, ACK, OPTIONS, BYE\r\nContent-Length: 0\r\n\r\n";
                let _ = responder.send_to(reply.as_bytes(), from).await;
                return req;
            }
            String::new()
        });
        let info = probe_sip_at(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_millis(800),
            &SocketBudget::new(2),
            &CancellationToken::new(),
        )
        .await
        .expect("probe should get a response");
        assert_eq!(info.status.as_deref(), Some("200 OK"));
        assert_eq!(info.vendor.as_deref(), Some("Grandstream"));
        assert_eq!(info.model.as_deref(), Some("GXP2170"));
        assert_eq!(info.firmware.as_deref(), Some("1.0.11.70"));
        assert_eq!(info.kind.as_deref(), Some(DEVICE_KIND_VOIP_PHONE));
        assert_eq!(info.transport.as_deref(), Some("udp"));
        let req = server.await.unwrap();
        assert!(req.starts_with("OPTIONS sip:127.0.0.1:"), "{req}");
        assert!(req.contains("Max-Forwards: 70"));
    }

    /// No UDP answer (nothing bound on that UDP port): the probe falls back to TCP, where a
    /// fake PBX answers.
    #[tokio::test]
    async fn falls_back_to_tcp_responder() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let reply = "SIP/2.0 200 OK\r\nServer: Asterisk PBX 18.9.0\r\n\
                             Allow: INVITE, ACK, CANCEL, OPTIONS, BYE\r\nContent-Length: 0\r\n\r\n";
                let _ = s.write_all(reply.as_bytes()).await;
            }
        });
        let info = probe_sip_at(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_millis(500),
            &SocketBudget::new(2),
            &CancellationToken::new(),
        )
        .await
        .expect("TCP fallback should answer");
        assert_eq!(info.transport.as_deref(), Some("tcp"));
        assert_eq!(info.vendor.as_deref(), Some("Asterisk"));
        assert_eq!(info.kind.as_deref(), Some(DEVICE_KIND_PBX));
        assert_eq!(info.firmware.as_deref(), Some("18.9.0"));
        let _ = server.await;
    }

    #[tokio::test]
    async fn silent_host_yields_nothing_promptly() {
        // Port 9 (discard) on loopback: nothing answers on UDP or TCP.
        let started = std::time::Instant::now();
        let info = probe_sip_at(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_millis(200),
            &SocketBudget::new(2),
            &CancellationToken::new(),
        )
        .await;
        assert!(info.is_none());
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
