//! Web identity: HTTP `<title>` / `Server` header and TLS certificate grabber.
//!
//! For each web port (80, 443, 8443, 8080, 8000, 10443 by default) this sends one
//! `GET /` (HTTP/1.1, `Connection: close`, short timeouts), reads at most 16 KiB of headers
//! and 64 KiB of body, follows at most two redirects that stay on the same host (an IP
//! literal; scheme and port may change, e.g. `http://ip/` → `https://ip/`), and extracts the
//! `<title>` (entity-decoded, sanitized) and `Server` header. HTTPS ports also yield the
//! server certificate: subject / issuer, SANs, validity, key type and SHA-256 fingerprint.
//!
//! The title, server header and certificate names identify common appliances (Proxmox VE,
//! Synology DSM, iDRAC, iLO, vCenter / ESXi, UniFi, pfSense, FortiGate, MikroTik, ...),
//! and expired / soon-to-expire / self-signed certificates are flagged as warnings.
//!
//! Nothing here authenticates anybody: no credentials, cookies or form data are ever sent,
//! and the TLS client deliberately accepts any certificate *only so it can read it* (see
//! [`AcceptAnyCert`]). Every byte from the network is bounded and sanitized.

use std::{
    net::IpAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, SignatureScheme,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc::Sender, Semaphore},
    task::JoinSet,
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use crate::{
    limits::SocketBudget,
    models::{
        now_ms, sanitize_text, Device, DeviceRole, ScanEvent, TlsCertInfo, WebIdentity, WebScheme,
        WebService,
    },
    progress::ProgressScope,
};

/// Ports probed by default (and by the scan, among a device's open ports).
pub const DEFAULT_WEB_PORTS: &[u16] = &[80, 443, 8443, 8080, 8000, 10443];
/// Ports where TLS is tried first.
const TLS_FIRST_PORTS: &[u16] = &[443, 4443, 5001, 7443, 8006, 8007, 8443, 9443, 10443];
/// Most ports one request may probe.
pub const MAX_WEB_PORTS: usize = 16;
pub const MAX_REDIRECTS: u8 = 2;
const MAX_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_URL_LEN: usize = 1024;
const MAX_SANS: usize = 8;
/// Certificates expiring within this many days are flagged.
pub const EXPIRY_WARNING_DAYS: i64 = 30;
/// Default per-request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
/// Devices probed at once during a scan (their sockets also draw from the global budget).
const SCAN_CONCURRENCY: usize = 32;

// ---------------------------------------------------------------------------------------------
// TLS: read-only certificate access
// ---------------------------------------------------------------------------------------------

/// A certificate "verifier" that accepts every certificate and handshake signature.
///
/// SECURITY: this is only acceptable because the connection exists purely to *read* the
/// certificate the server presents (subject, expiry, issuer) and the page title. The grabber
/// never sends credentials, cookies, or any data beyond a plain `GET` and never trusts what
/// comes back for anything but display. Do not reuse this config for anything that sends
/// secrets.
#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    // Handshake signatures are not checked either: appliances with legacy keys (e.g. 1024-bit
    // RSA, which `ring` refuses) must still show their certificate.
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
        ]
    }
}

/// The shared read-only TLS client config (TLS 1.2 + 1.3, ALPN `http/1.1`, `ring`).
fn tls_connector() -> Option<TlsConnector> {
    static CFG: OnceLock<Option<Arc<ClientConfig>>> = OnceLock::new();
    CFG.get_or_init(|| {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| tracing::warn!("TLS client unavailable: {e}"))
            .ok()?;
        let mut cfg = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Some(Arc::new(cfg))
    })
    .clone()
    .map(TlsConnector::from)
}

// ---------------------------------------------------------------------------------------------
// Certificate parsing
// ---------------------------------------------------------------------------------------------

/// Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// `2026-01-31T12:00:00Z` for Unix seconds.
pub fn iso8601(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn signature_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        other => other,
    }
    .to_string()
}

/// Parse a DER certificate read from `port`, computing expiry relative to `now_ms`.
pub fn parse_cert(der: &[u8], port: u16, now_ms: u64) -> Option<TlsCertInfo> {
    use x509_parser::{
        certificate::X509Certificate, extensions::GeneralName, prelude::FromDer,
        public_key::PublicKey,
    };
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let text = |s: String| Some(sanitize_text(&s)).filter(|t| !t.is_empty());
    let cn = |name: &x509_parser::x509::X509Name<'_>| {
        name.iter_common_name()
            .next()
            .and_then(|a| a.as_str().ok())
            .and_then(|s| text(s.to_string()))
    };
    let subject = cert.subject();
    let issuer = cert.issuer();

    let mut sans = Vec::new();
    let mut san_count = 0u32;
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            let rendered = match name {
                GeneralName::DNSName(s) => text(s.to_string()),
                GeneralName::IPAddress(b) => match b.len() {
                    4 => Some(IpAddr::from(<[u8; 4]>::try_from(*b).ok()?).to_string()),
                    16 => Some(IpAddr::from(<[u8; 16]>::try_from(*b).ok()?).to_string()),
                    _ => None,
                },
                GeneralName::RFC822Name(s) | GeneralName::URI(s) => text(s.to_string()),
                _ => None,
            };
            if let Some(r) = rendered {
                san_count = san_count.saturating_add(1);
                if sans.len() < MAX_SANS {
                    sans.push(r);
                }
            }
        }
    }

    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    let now_secs = i64::try_from(now_ms / 1000).unwrap_or(i64::MAX);
    let days_remaining = not_after.saturating_sub(now_secs).div_euclid(86_400);

    let spki = cert.public_key();
    let alg = spki.algorithm.algorithm.to_id_string();
    let (key_type, key_bits) = match spki.parsed() {
        Ok(PublicKey::RSA(rsa)) => (Some("RSA".to_string()), Some(rsa.key_size())),
        Ok(PublicKey::EC(ec)) => {
            let bits = ec.key_size();
            let name = match bits {
                256 | 384 | 521 => format!("EC P-{bits}"),
                _ => "EC".to_string(),
            };
            (Some(name), Some(bits))
        }
        Ok(PublicKey::DSA(_)) => (Some("DSA".to_string()), None),
        _ if alg == "1.3.101.112" => (Some("Ed25519".to_string()), Some(256)),
        _ if alg == "1.3.101.113" => (Some("Ed448".to_string()), Some(456)),
        _ => (None, None),
    };
    let self_signed = subject.as_raw() == issuer.as_raw() && cert.verify_signature(None).is_ok();
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let sha256 = digest
        .as_ref()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");

    Some(TlsCertInfo {
        port,
        subject_cn: cn(subject),
        subject: text(subject.to_string()),
        sans,
        san_count,
        issuer_cn: cn(issuer),
        issuer: text(issuer.to_string()),
        not_before: Some(iso8601(not_before)),
        not_after: Some(iso8601(not_after)),
        not_before_ms: Some(not_before.saturating_mul(1000)),
        not_after_ms: Some(not_after.saturating_mul(1000)),
        days_remaining: Some(days_remaining),
        self_signed,
        expired: now_secs > not_after,
        key_type,
        key_bits: key_bits
            .and_then(|b| u32::try_from(b).ok())
            .filter(|b| *b > 0),
        signature_algorithm: Some(signature_name(
            &cert.signature_algorithm.algorithm.to_id_string(),
        )),
        sha256: Some(sha256),
    })
}

/// Warnings for an expired, soon-expiring, not-yet-valid or self-signed certificate.
pub fn cert_warnings(c: &TlsCertInfo, now_ms: u64) -> Vec<String> {
    let mut out = Vec::new();
    let date = c
        .not_after
        .as_deref()
        .map(|d| d.get(..10).unwrap_or(d).to_string())
        .unwrap_or_default();
    let days = c.days_remaining.unwrap_or(i64::MAX);
    if c.expired {
        let ago = days.unsigned_abs().max(1);
        out.push(format!(
            "TLS certificate on port {} expired {ago} day(s) ago ({date})",
            c.port
        ));
    } else if days < EXPIRY_WARNING_DAYS {
        out.push(format!(
            "TLS certificate on port {} expires in {days} day(s) ({date})",
            c.port
        ));
    }
    let now = i64::try_from(now_ms).unwrap_or(i64::MAX);
    if c.not_before_ms.is_some_and(|nb| now < nb) {
        out.push(format!(
            "TLS certificate on port {} is not valid until {}",
            c.port,
            c.not_before.as_deref().unwrap_or_default()
        ));
    }
    if c.self_signed {
        out.push(format!("TLS certificate on port {} is self-signed", c.port));
    }
    out
}

// ---------------------------------------------------------------------------------------------
// HTML title, entities, meta refresh
// ---------------------------------------------------------------------------------------------

fn named_entity(name: &str) -> Option<char> {
    Some(match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => ' ',
        "copy" => '©',
        "reg" => '®',
        "trade" => '™',
        "ndash" => '–',
        "mdash" => '—',
        "hellip" => '…',
        "laquo" => '«',
        "raquo" => '»',
        "middot" => '·',
        "bull" => '•',
        "euro" => '€',
        _ => return None,
    })
}

/// Decode HTML character references (`&amp;`, `&#39;`, `&#x27;`, common named ones).
/// Unknown or invalid references are kept literally; control characters are dropped later by
/// [`sanitize_text`].
pub fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        let end = after.find(';').filter(|e| *e <= 10);
        // `Some((Some(c), len))`: decoded; `Some((None, len))`: a numeric reference to NUL or
        // an invalid code point, dropped.
        let decoded = end.and_then(|e| {
            let name = &after[..e];
            if let Some(num) = name.strip_prefix('#') {
                let code = match num.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => num.parse::<u32>().ok(),
                };
                code.map(|c| (char::from_u32(c).filter(|c| *c != '\0'), e))
            } else {
                named_entity(name).map(|c| (Some(c), e))
            }
        });
        match decoded {
            Some((c, e)) => {
                out.extend(c);
                rest = &after[e + 1..];
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Bytes as text: UTF-8 when valid, else Latin-1.
fn bytes_to_text(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => b.iter().map(|&c| char::from(c)).collect(),
    }
}

fn find_ci(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (from..=hay.len() - needle.len())
        .find(|&i| hay[i..i + needle.len()].eq_ignore_ascii_case(needle))
}

fn rfind_ci(hay: &[u8], needle: &[u8], before: usize) -> Option<usize> {
    if needle.is_empty() || before < needle.len() {
        return None;
    }
    (0..=before.min(hay.len()).saturating_sub(needle.len()))
        .rev()
        .find(|&i| hay[i..i + needle.len()].eq_ignore_ascii_case(needle))
}

/// The document `<title>`: the first real `<title>` element (not `<titlefoo>`, not inside an
/// inline `<svg>`) that is properly closed. Entity-decoded, whitespace-collapsed, sanitized;
/// `None` when empty.
pub fn extract_title(body: &[u8]) -> Option<String> {
    let body = &body[..body.len().min(MAX_BODY_BYTES)];
    let mut from = 0;
    while let Some(i) = find_ci(body, b"<title", from) {
        from = i + 6;
        let next = *body.get(i + 6)?;
        if !(next == b'>' || next.is_ascii_whitespace()) {
            continue;
        }
        // Inside an inline SVG? (an opening <svg before it without a closing </svg).
        if let Some(svg) = rfind_ci(body, b"<svg", i) {
            if rfind_ci(body, b"</svg", i).is_none_or(|close| close < svg) {
                continue;
            }
        }
        let open_end = body[i..].iter().position(|b| *b == b'>')? + i + 1;
        let close = find_ci(body, b"</title", open_end)?;
        let raw = &body[open_end..close.min(open_end + 2048)];
        let decoded = decode_entities(&bytes_to_text(raw));
        let collapsed = decoded.split_whitespace().collect::<Vec<_>>().join(" ");
        let title = sanitize_text(&collapsed);
        return (!title.is_empty()).then_some(title);
    }
    None
}

/// Target of `<meta http-equiv="refresh" content="0; url=...">`, if any.
pub fn meta_refresh_target(body: &[u8]) -> Option<String> {
    let body = &body[..body.len().min(MAX_BODY_BYTES)];
    let mut from = 0;
    while let Some(i) = find_ci(body, b"<meta", from) {
        from = i + 5;
        let end = body[i..].iter().position(|b| *b == b'>').map(|p| i + p)?;
        let tag = bytes_to_text(&body[i..end]);
        let lower = tag.to_ascii_lowercase();
        if !lower.contains("http-equiv") || !lower.contains("refresh") {
            continue;
        }
        let url_at = lower.find("url=")?;
        let url = tag[url_at + 4..]
            .trim_start_matches(['\'', '"', ' '])
            .split(['\'', '"', '>'])
            .next()?
            .trim();
        let url = decode_entities(url);
        return (!url.is_empty() && url.len() <= MAX_URL_LEN).then_some(url);
    }
    None
}

// ---------------------------------------------------------------------------------------------
// HTTP/1.1 response parsing (bounded)
// ---------------------------------------------------------------------------------------------

/// A parsed HTTP response (headers lower-cased, values sanitized; body bounded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Length of the header block (through the blank line), when complete.
fn header_len(raw: &[u8]) -> Option<usize> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    match httparse::Response::new(&mut headers).parse(raw) {
        Ok(httparse::Status::Complete(n)) => Some(n),
        _ => None,
    }
}

/// Decode as much of a chunked body as is present and well-formed.
fn decode_chunked(mut b: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = b.windows(2).position(|w| w == b"\r\n") else {
            return (out, false);
        };
        let size_txt = std::str::from_utf8(&b[..line_end]).unwrap_or("");
        let size_txt = size_txt.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(size_txt, 16) else {
            return (out, false);
        };
        b = &b[line_end + 2..];
        if size == 0 {
            return (out, true);
        }
        let take = size.min(b.len());
        out.extend_from_slice(&b[..take]);
        if out.len() >= MAX_BODY_BYTES {
            out.truncate(MAX_BODY_BYTES);
            return (out, true);
        }
        if take < size || b.len() < size + 2 {
            return (out, false);
        }
        b = &b[size + 2..];
    }
}

/// `true` once `raw` holds a complete response (by `Content-Length`, chunked terminator,
/// or a status without a body).
fn response_complete(raw: &[u8]) -> bool {
    let Some(n) = header_len(raw) else {
        return raw.len() >= MAX_HEADER_BYTES;
    };
    let Ok(resp) = parse_response(raw) else {
        return true;
    };
    if matches!(resp.status, 100..=199 | 204 | 304) {
        return true;
    }
    if resp
        .header("transfer-encoding")
        .is_some_and(|t| t.to_ascii_lowercase().contains("chunked"))
    {
        return decode_chunked(&raw[n..]).1;
    }
    match resp
        .header("content-length")
        .and_then(|v| v.trim().parse::<usize>().ok())
    {
        Some(len) => raw.len() >= n + len.min(MAX_BODY_BYTES),
        None => raw.len() >= n + MAX_BODY_BYTES,
    }
}

/// Parse a raw HTTP/1.x response. Fails when it is not HTTP or the headers are incomplete.
pub fn parse_response(raw: &[u8]) -> Result<HttpResponse, &'static str> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    let n = match resp.parse(raw) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Err("incomplete HTTP response headers"),
        Err(_) => return Err("not an HTTP response"),
    };
    let status = resp.code.ok_or("missing status code")?;
    let headers: Vec<(String, String)> = resp
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_ascii_lowercase(),
                sanitize_text(&bytes_to_text(h.value)),
            )
        })
        .collect();
    let chunked = headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"));
    let rest = &raw[n..];
    let mut body = if chunked {
        decode_chunked(rest).0
    } else {
        let len = headers
            .iter()
            .find(|(k, _)| k == "content-length")
            .and_then(|(_, v)| v.trim().parse::<usize>().ok())
            .unwrap_or(rest.len());
        rest[..len.min(rest.len())].to_vec()
    };
    body.truncate(MAX_BODY_BYTES);
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

// ---------------------------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------------------------

/// One request target on the probed host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub scheme: WebScheme,
    pub port: u16,
    /// Absolute path (+ query), validated printable ASCII.
    pub path: String,
}

fn host_literal(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

fn default_port(scheme: WebScheme) -> u16 {
    match scheme {
        WebScheme::Http => 80,
        WebScheme::Https => 443,
    }
}

impl Target {
    pub fn url(&self, ip: IpAddr) -> String {
        let scheme = match self.scheme {
            WebScheme::Http => "http",
            WebScheme::Https => "https",
        };
        let port = if self.port == default_port(self.scheme) {
            String::new()
        } else {
            format!(":{}", self.port)
        };
        format!("{scheme}://{}{port}{}", host_literal(ip), self.path)
    }

    fn host_header(&self, ip: IpAddr) -> String {
        if self.port == default_port(self.scheme) {
            host_literal(ip)
        } else {
            format!("{}:{}", host_literal(ip), self.port)
        }
    }
}

fn valid_path(p: &str) -> bool {
    p.starts_with('/') && p.len() <= MAX_URL_LEN && p.bytes().all(|b| b.is_ascii_graphic())
}

/// Resolve a redirect `location` relative to `cur` on host `ip`. Only same-host targets are
/// returned (relative paths, or absolute URLs whose host is the same IP literal); the scheme
/// and port may change.
pub fn resolve_redirect(cur: &Target, location: &str, ip: IpAddr) -> Option<Target> {
    let loc = location.trim();
    let loc = loc.split('#').next().unwrap_or(loc);
    if loc.is_empty() || loc.len() > MAX_URL_LEN {
        return None;
    }
    let lower = loc.to_ascii_lowercase();
    let (scheme, rest) = if let Some(r) = lower.strip_prefix("http://") {
        (Some(WebScheme::Http), &loc[loc.len() - r.len()..])
    } else if let Some(r) = lower.strip_prefix("https://") {
        (Some(WebScheme::Https), &loc[loc.len() - r.len()..])
    } else if let Some(r) = loc.strip_prefix("//") {
        (Some(cur.scheme), r)
    } else {
        (None, loc)
    };
    let Some(scheme) = scheme else {
        // Any other scheme (`javascript:`, `ftp:`, ...) is never followed.
        let first_delim = loc.find(['/', '?', '#']).unwrap_or(loc.len());
        if let Some(colon) = loc[..first_delim].find(':') {
            let name = &loc[..colon];
            let schemey = !name.is_empty()
                && name.starts_with(|c: char| c.is_ascii_alphabetic())
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
            if schemey {
                return None;
            }
        }
        // Relative reference.
        let path = if loc.starts_with('/') {
            loc.to_string()
        } else {
            let base = cur.path.split('?').next().unwrap_or("/");
            let dir = &base[..base.rfind('/').map_or(1, |i| i + 1)];
            format!("{dir}{loc}")
        };
        return valid_path(&path).then_some(Target {
            scheme: cur.scheme,
            port: cur.port,
            path,
        });
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_string()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_string()),
    };
    if authority.contains('@') {
        return None; // userinfo: never follow
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let end = v6.find(']')?;
        let port = v6[end + 1..].strip_prefix(':');
        (&v6[..end], port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port = match port {
        Some(p) => p.parse::<u16>().ok().filter(|p| *p != 0)?,
        None => default_port(scheme),
    };
    let same_host = host.parse::<IpAddr>().ok() == Some(ip);
    (same_host && valid_path(&path)).then_some(Target { scheme, port, path })
}

/// Why a fetch failed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FetchError {
    /// TCP connect refused / timed out: the port is not open.
    Connect(String),
    /// The port is open but does not speak this protocol (TLS handshake failure, not HTTP).
    Protocol(String),
}

/// What one request produced: the TLS certificate (HTTPS) and the response, if any.
#[derive(Debug, Clone)]
struct Fetched {
    cert: Option<TlsCertInfo>,
    response: Result<HttpResponse, String>,
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

async fn read_response<S: AsyncRead + Unpin>(
    s: &mut S,
    deadline: tokio::time::Instant,
) -> Result<Vec<u8>, String> {
    let cap = MAX_HEADER_BYTES + MAX_BODY_BYTES;
    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut chunk = vec![0u8; 8192];
    while buf.len() < cap {
        match tokio::time::timeout_at(deadline, s.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                let room = cap - buf.len();
                buf.extend_from_slice(&chunk[..n.min(room)]);
                if response_complete(&buf) {
                    break;
                }
            }
            // A TLS peer closing without close_notify, a reset after the response, ...
            Ok(Err(e)) if buf.is_empty() => return Err(e.to_string()),
            Ok(Err(_)) => break,
            Err(_) if buf.is_empty() => return Err("timed out waiting for a response".into()),
            Err(_) => break,
        }
    }
    if buf.is_empty() {
        return Err("empty response".into());
    }
    Ok(buf)
}

/// One `GET` to `ip` / `target`, holding a socket permit from `budget`.
async fn fetch(
    ip: IpAddr,
    target: &Target,
    timeout: Duration,
    budget: &SocketBudget,
) -> Result<Fetched, FetchError> {
    let _permit = budget
        .acquire()
        .await
        .ok_or_else(|| FetchError::Connect("socket budget closed".into()))?;
    let deadline = tokio::time::Instant::now() + timeout * 2;
    let tcp = match tokio::time::timeout(timeout, TcpStream::connect((ip, target.port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(FetchError::Connect(e.to_string())),
        Err(_) => return Err(FetchError::Connect("connect timed out".into())),
    };
    let _ = tcp.set_nodelay(true);
    let (mut stream, cert): (Box<dyn Stream>, Option<TlsCertInfo>) = match target.scheme {
        WebScheme::Http => (Box::new(tcp), None),
        WebScheme::Https => {
            let connector =
                tls_connector().ok_or_else(|| FetchError::Protocol("TLS is unavailable".into()))?;
            let name = ServerName::IpAddress(ip.into());
            let tls = match tokio::time::timeout_at(deadline, connector.connect(name, tcp)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    return Err(FetchError::Protocol(format!("TLS handshake failed: {e}")))
                }
                Err(_) => return Err(FetchError::Protocol("TLS handshake timed out".into())),
            };
            let cert = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .and_then(|der| parse_cert(der.as_ref(), target.port, now_ms()));
            (Box::new(tls), cert)
        }
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: SweepR/{} (network inventory)\r\n\
         Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.5\r\n\
         Accept-Encoding: identity\r\nConnection: close\r\n\r\n",
        target.path,
        target.host_header(ip),
        env!("CARGO_PKG_VERSION"),
    );
    let write = tokio::time::timeout_at(deadline, async {
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await
    })
    .await;
    if !matches!(write, Ok(Ok(()))) {
        return Ok(Fetched {
            cert,
            response: Err("could not send the request".into()),
        });
    }
    let response = read_response(&mut stream, deadline)
        .await
        .and_then(|raw| parse_response(&raw).map_err(str::to_string));
    let _ = tokio::time::timeout(Duration::from_millis(200), stream.shutdown()).await;
    if cert.is_none() {
        if let Err(e) = &response {
            // Plain HTTP that is not HTTP at all: let the caller try TLS instead.
            return Err(FetchError::Protocol(e.clone()));
        }
    }
    Ok(Fetched { cert, response })
}

/// `true` when TLS should be tried first on `port`.
pub fn tls_first(port: u16) -> bool {
    TLS_FIRST_PORTS.contains(&port)
}

/// Probe one port: try the likely scheme first, the other on a protocol mismatch, then
/// follow same-host redirects. `None` when the port does not accept connections.
pub async fn probe_port(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    budget: &SocketBudget,
) -> Option<WebService> {
    let schemes = if tls_first(port) {
        [WebScheme::Https, WebScheme::Http]
    } else {
        [WebScheme::Http, WebScheme::Https]
    };
    let mut first_error = None;
    for scheme in schemes {
        let mut target = Target {
            scheme,
            port,
            path: "/".into(),
        };
        let fetched = match fetch(ip, &target, timeout, budget).await {
            Ok(f) => f,
            Err(FetchError::Connect(_)) => return None,
            Err(FetchError::Protocol(e)) => {
                first_error.get_or_insert(e);
                continue;
            }
        };
        let mut service = WebService {
            port,
            scheme,
            url: target.url(ip),
            status: None,
            title: None,
            server: None,
            redirects: 0,
            redirect_to: None,
            tls_cert: fetched.cert.clone(),
            error: None,
        };
        let mut current = fetched;
        loop {
            let resp = match current.response {
                Ok(r) => r,
                Err(e) => {
                    service.error = Some(sanitize_text(&e));
                    break;
                }
            };
            service.status = Some(resp.status);
            service.url = target.url(ip);
            if let Some(s) = resp.header("server").filter(|s| !s.is_empty()) {
                service.server = Some(s.to_string());
            }
            let title = extract_title(&resp.body);
            if title.is_some() {
                service.title = title.clone();
            }
            let location = match resp.status {
                301 | 302 | 303 | 307 | 308 => resp.header("location").map(str::to_string),
                200 if title.is_none() => meta_refresh_target(&resp.body),
                _ => None,
            };
            let Some(location) = location else { break };
            let next = resolve_redirect(&target, &location, ip);
            match next {
                Some(next) if service.redirects < MAX_REDIRECTS && next != target => {
                    service.redirects += 1;
                    target = next;
                    match fetch(ip, &target, timeout, budget).await {
                        Ok(f) => {
                            if service.tls_cert.is_none() {
                                service.tls_cert = f.cert.clone();
                            }
                            current = f;
                        }
                        Err(FetchError::Connect(e) | FetchError::Protocol(e)) => {
                            service.redirect_to = Some(target.url(ip));
                            service.error = Some(sanitize_text(&e));
                            break;
                        }
                    }
                }
                _ => {
                    service.redirect_to = Some(sanitize_text(&location));
                    break;
                }
            }
        }
        return Some(service);
    }
    // Open, but neither scheme spoke HTTP.
    Some(WebService {
        port,
        scheme: schemes[0],
        url: Target {
            scheme: schemes[0],
            port,
            path: "/".into(),
        }
        .url(ip),
        status: None,
        title: None,
        server: None,
        redirects: 0,
        redirect_to: None,
        tls_cert: None,
        error: first_error.map(|e| sanitize_text(&e)),
    })
}

// ---------------------------------------------------------------------------------------------
// Appliance identification
// ---------------------------------------------------------------------------------------------

struct Rule {
    /// Lower-case needles. Needles of 4 characters or fewer must match whole words.
    needles: &'static [&'static str],
    identity: &'static str,
    role: Option<DeviceRole>,
}

const fn rule(
    needles: &'static [&'static str],
    identity: &'static str,
    role: Option<DeviceRole>,
) -> Rule {
    Rule {
        needles,
        identity,
        role,
    }
}

/// Ordered: more specific products first.
const RULES: &[Rule] = &[
    rule(&["proxmox backup server"], "Proxmox Backup Server", None),
    rule(
        &["proxmox virtual environment", "pve cluster", "proxmox ve"],
        "Proxmox VE",
        None,
    ),
    rule(
        &["synology", "diskstation", "rackstation"],
        "Synology DSM",
        None,
    ),
    rule(&["qnap", "qts"], "QNAP QTS", None),
    rule(&["truenas", "freenas"], "TrueNAS", None),
    rule(&["unraid"], "Unraid", None),
    rule(&["openmediavault"], "OpenMediaVault", None),
    rule(
        &["idrac", "integrated dell remote access"],
        "Dell iDRAC",
        None,
    ),
    rule(&["ilo", "integrated lights-out", "hp-ilo"], "HPE iLO", None),
    rule(&["xclarity"], "Lenovo XClarity Controller", None),
    rule(&["supermicro"], "Supermicro BMC", None),
    rule(&["megarac"], "AMI MegaRAC BMC", None),
    rule(&["esxi", "vmware host client"], "VMware ESXi", None),
    rule(
        &["vcenter", "vsphere", "id_vc_welcome"],
        "VMware vCenter",
        None,
    ),
    rule(&["pfsense"], "pfSense", Some(DeviceRole::Firewall)),
    rule(&["opnsense"], "OPNsense", Some(DeviceRole::Firewall)),
    rule(
        &["fortigate"],
        "Fortinet FortiGate",
        Some(DeviceRole::Firewall),
    ),
    rule(
        &["fortiswitch"],
        "Fortinet FortiSwitch",
        Some(DeviceRole::Switch),
    ),
    rule(
        &["fortiap"],
        "Fortinet FortiAP",
        Some(DeviceRole::AccessPoint),
    ),
    rule(&["sonicwall"], "SonicWall", Some(DeviceRole::Firewall)),
    rule(
        &["watchguard", "fireware"],
        "WatchGuard Firebox",
        Some(DeviceRole::Firewall),
    ),
    rule(
        &["pan-os", "palo alto networks", "globalprotect"],
        "Palo Alto Networks",
        Some(DeviceRole::Firewall),
    ),
    rule(
        &["cisco asdm", "adaptive security device", "cisco asa"],
        "Cisco ASA",
        Some(DeviceRole::Firewall),
    ),
    rule(&["sophos"], "Sophos Firewall", Some(DeviceRole::Firewall)),
    rule(
        &["check point", "gaia portal"],
        "Check Point",
        Some(DeviceRole::Firewall),
    ),
    rule(&["swos"], "MikroTik SwOS", Some(DeviceRole::Switch)),
    rule(
        &["routeros", "mikrotik", "webfig"],
        "MikroTik RouterOS",
        Some(DeviceRole::Router),
    ),
    rule(
        &["edgeos", "edgerouter", "edgeswitch"],
        "Ubiquiti EdgeOS",
        None,
    ),
    rule(&["unifi", "ubiquiti"], "Ubiquiti UniFi", None),
    rule(&["openwrt", "luci"], "OpenWrt", Some(DeviceRole::Router)),
    rule(&["dd-wrt"], "DD-WRT", Some(DeviceRole::Router)),
    rule(&["omada"], "TP-Link Omada", None),
    rule(&["meraki"], "Cisco Meraki", None),
    rule(
        &["arubaos", "aruba instant", "aruba networks"],
        "Aruba",
        None,
    ),
    rule(&["pi-hole", "pihole"], "Pi-hole", None),
    rule(&["adguard home"], "AdGuard Home", None),
    rule(&["home assistant"], "Home Assistant", None),
    rule(&["hikvision"], "Hikvision camera / NVR", None),
    rule(&["dahua"], "Dahua camera / NVR", None),
    rule(
        &["laserjet", "officejet", "hp embedded web server"],
        "HP printer",
        None,
    ),
    rule(&["grafana"], "Grafana", None),
    rule(&["portainer"], "Portainer", None),
    rule(&["webmin"], "Webmin", None),
    rule(&["nextcloud"], "Nextcloud", None),
    rule(&["jenkins"], "Jenkins", None),
    rule(&["gitlab"], "GitLab", None),
    rule(&["jellyfin"], "Jellyfin", None),
    rule(&["plex"], "Plex Media Server", None),
];

fn words(s: &str) -> Vec<&str> {
    s.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect()
}

/// Identify an appliance from page titles, `Server` headers and certificate names.
/// Returns `(identity, role hint)`.
pub fn identify(texts: &[&str]) -> Option<(&'static str, Option<DeviceRole>)> {
    let hay = texts
        .iter()
        .map(|t| t.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" | ");
    let hay_words = words(&hay);
    let has = |needle: &str| {
        if needle.len() <= 4 && needle.chars().all(|c| c.is_ascii_alphanumeric()) {
            hay_words.contains(&needle)
        } else {
            hay.contains(needle)
        }
    };
    if let Some(r) = RULES.iter().find(|r| r.needles.iter().any(|n| has(n))) {
        return Some((r.identity, r.role));
    }
    // FortiGate's factory certificate: CN = the serial number (FGT..., FG...), issuer Fortinet.
    if hay.contains("fortinet")
        && hay_words
            .iter()
            .any(|w| w.starts_with("fg") && w.len() >= 8)
    {
        return Some(("Fortinet FortiGate", Some(DeviceRole::Firewall)));
    }
    None
}

/// Text that identifies a service: title, server header, certificate subject and issuer.
fn service_texts(s: &WebService) -> Vec<&str> {
    let mut v: Vec<&str> = Vec::new();
    v.extend(s.title.as_deref());
    v.extend(s.server.as_deref());
    if let Some(c) = &s.tls_cert {
        v.extend(c.subject.as_deref());
        v.extend(c.issuer.as_deref());
    }
    v
}

/// Combine per-port results into a [`WebIdentity`]: HTTPS services first for title, server
/// and certificate; identity from the first service that matches a rule.
pub fn summarize(ip: IpAddr, mut services: Vec<WebService>, now_ms: u64) -> WebIdentity {
    services.sort_by_key(|s| (s.scheme != WebScheme::Https, s.port != 443, s.port));
    let title = services.iter().find_map(|s| s.title.clone());
    let server = services.iter().find_map(|s| s.server.clone());
    let tls_cert = services.iter().find_map(|s| s.tls_cert.clone());
    let found = services.iter().find_map(|s| identify(&service_texts(s)));
    let mut warnings: Vec<String> = Vec::new();
    let mut seen_certs: Vec<String> = Vec::new();
    for c in services.iter().filter_map(|s| s.tls_cert.as_ref()) {
        let key = c.sha256.clone().unwrap_or_default();
        if seen_certs.contains(&key) {
            continue;
        }
        seen_certs.push(key);
        for w in cert_warnings(c, now_ms) {
            if !warnings.contains(&w) {
                warnings.push(w);
            }
        }
    }
    WebIdentity {
        ip,
        services,
        title,
        server,
        tls_cert,
        identity: found.map(|(i, _)| i.to_string()),
        role_hint: found.and_then(|(_, r)| r),
        warnings,
    }
}

/// Normalize a requested port list (`None` / empty = [`DEFAULT_WEB_PORTS`]).
pub fn plan_ports(ports: Option<&[u16]>) -> Result<Vec<u16>, String> {
    let mut out: Vec<u16> = Vec::new();
    for p in ports.filter(|p| !p.is_empty()).unwrap_or(DEFAULT_WEB_PORTS) {
        if *p == 0 {
            return Err("port 0 is not valid".into());
        }
        if !out.contains(p) {
            out.push(*p);
        }
    }
    if out.len() > MAX_WEB_PORTS {
        return Err(format!("at most {MAX_WEB_PORTS} web ports"));
    }
    Ok(out)
}

/// Probe `ports` of `ip` concurrently and summarize them.
pub async fn grab_web_identity(
    ip: IpAddr,
    ports: &[u16],
    timeout: Duration,
    cancel: &CancellationToken,
    budget: &SocketBudget,
) -> WebIdentity {
    let mut tasks = JoinSet::new();
    for port in ports.iter().copied().take(MAX_WEB_PORTS) {
        let (budget, cancel) = (budget.clone(), cancel.clone());
        tasks.spawn(async move {
            tokio::select! {
                _ = cancel.cancelled() => None,
                s = probe_port(ip, port, timeout, &budget) => s,
            }
        });
    }
    let mut services = Vec::new();
    while let Some(res) = tasks.join_next().await {
        if let Ok(Some(s)) = res {
            services.push(s);
        }
    }
    summarize(ip, services, now_ms())
}

/// The sparse device update carrying `id` for `device` (same key), or `None` when there is
/// nothing to add. The role hint only applies to a device that is still a plain host, so it
/// never overrides CDP / LLDP / SNMP / fingerprint evidence.
pub fn device_update(device: &Device, id: &WebIdentity) -> Option<Device> {
    let mut update = Device::new(device.ip);
    update.vlan_id = device.vlan_id;
    update.sources.clear();
    update.web_title = id.title.clone();
    update.web_server = id.server.clone();
    update.tls_cert = id.tls_cert.clone();
    update.web_identity = id.identity.clone();
    for w in &id.warnings {
        update.add_warning(w.clone());
    }
    if let Some(role) = id.role_hint {
        if device.role == DeviceRole::Host {
            update.role = role;
        }
    }
    let changed = update.web_title.is_some()
        || update.web_server.is_some()
        || update.tls_cert.is_some()
        || update.web_identity.is_some()
        || !update.warnings.is_empty()
        || update.role != DeviceRole::Host;
    changed.then_some(update)
}

/// Scan enrichment: grab the web identity of every device with one of `web_ports` open (the
/// engine passes [`DEFAULT_WEB_PORTS`]) and stream sparse device updates to `tx`. One
/// progress unit per device in `devices`.
pub async fn enrich_web(
    devices: Vec<Device>,
    web_ports: &[u16],
    timeout: Duration,
    tx: Sender<ScanEvent>,
    cancel: CancellationToken,
    progress: ProgressScope,
    budget: &SocketBudget,
) {
    let semaphore = Arc::new(Semaphore::new(SCAN_CONCURRENCY));
    let mut tasks = JoinSet::new();
    for device in devices {
        let ports: Vec<u16> = device
            .open_ports
            .iter()
            .copied()
            .filter(|p| web_ports.contains(p))
            .take(MAX_WEB_PORTS)
            .collect();
        if ports.is_empty() || cancel.is_cancelled() {
            progress.add(1);
            continue;
        }
        let Ok(permit) = semaphore.clone().acquire_owned().await else {
            break;
        };
        let (tx, cancel, budget, progress) =
            (tx.clone(), cancel.clone(), budget.clone(), progress.clone());
        tasks.spawn(async move {
            let _permit = permit;
            let id = grab_web_identity(device.ip, &ports, timeout, &cancel, &budget).await;
            if let Some(update) = device_update(&device, &id) {
                let _ = tx.send(ScanEvent::device(update)).await;
            }
            progress.add(1);
        });
        while tasks.try_join_next().is_some() {}
    }
    while tasks.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{pem::PemObject, PrivateKeyDer};
    use std::net::Ipv4Addr;

    // Throwaway self-signed test certificate (P-256, CN=pve.example.lan, O=PVE Cluster Node,
    // SAN DNS:pve.example.lan + IP:127.0.0.1, valid 2026-10-15 .. 2046-10-10), generated with
    // `openssl req -x509` for these tests only. The key protects nothing.
    const TEST_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBhDCCASugAwIBAgIJAPMIgOt2QDYSMAoGCCqGSM49BAMCMDUxGDAWBgNVBAMM
D3B2ZS5leGFtcGxlLmxhbjEZMBcGA1UECgwQUFZFIENsdXN0ZXIgTm9kZTAeFw0y
NjEwMTUyMDQ2MjJaFw00NjEwMTAyMDQ2MjJaMDUxGDAWBgNVBAMMD3B2ZS5leGFt
cGxlLmxhbjEZMBcGA1UECgwQUFZFIENsdXN0ZXIgTm9kZTBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABOoYJS3WHihqFt0aHuIrrjtJGToE86cRRGtYv7X9A4HZXygJ
ErIKi4Q2jFT5+gxfNuubWOr8xYuXJvqwkf+rnw2jJDAiMCAGA1UdEQQZMBeCD3B2
ZS5leGFtcGxlLmxhbocEfwAAATAKBggqhkjOPQQDAgNHADBEAiBwA3ha7TyD0vLk
veNkXd+bBk3LTvSves5MZCqvz62dEgIgDGkVW4SaEx+HwnfdfwOSz+J64ApZRGPF
U7fWatQEkXc=
-----END CERTIFICATE-----
";
    const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZcr67heAALOTi4wr
sljbLNykPpl9ca73i3eYuX/01ImhRANCAATqGCUt1h4oahbdGh7iK647SRk6BPOn
EURrWL+1/QOB2V8oCRKyCouENoxU+foMXzbrm1jq/MWLlyb6sJH/q58N
-----END PRIVATE KEY-----
";
    /// 2027-01-01T00:00:00Z.
    const NOW_2027: u64 = 1_798_761_600_000;

    fn cert_der() -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(TEST_CERT.as_bytes()).unwrap()
    }

    #[test]
    fn certificate_details() {
        let c = parse_cert(cert_der().as_ref(), 8443, NOW_2027).unwrap();
        assert_eq!(c.port, 8443);
        assert_eq!(c.subject_cn.as_deref(), Some("pve.example.lan"));
        assert_eq!(c.issuer_cn.as_deref(), Some("pve.example.lan"));
        assert!(c.subject.as_deref().unwrap().contains("PVE Cluster Node"));
        assert_eq!(c.sans, vec!["pve.example.lan", "127.0.0.1"]);
        assert_eq!(c.san_count, 2);
        assert_eq!(c.not_before.as_deref(), Some("2026-10-15T20:46:22Z"));
        assert_eq!(c.not_after.as_deref(), Some("2046-10-10T20:46:22Z"));
        assert!(c.self_signed && !c.expired);
        assert_eq!(c.key_type.as_deref(), Some("EC P-256"));
        assert_eq!(c.key_bits, Some(256));
        assert_eq!(c.signature_algorithm.as_deref(), Some("ecdsa-with-SHA256"));
        assert_eq!(c.sha256.as_deref().unwrap().len(), 32 * 3 - 1);
        assert!(c.days_remaining.unwrap() > 7000);
        assert_eq!(
            cert_warnings(&c, NOW_2027),
            vec!["TLS certificate on port 8443 is self-signed"]
        );

        // Ten days before expiry, and after it.
        let soon = c.not_after_ms.unwrap() as u64 - 10 * 86_400_000;
        let c2 = parse_cert(cert_der().as_ref(), 443, soon).unwrap();
        assert_eq!(c2.days_remaining, Some(10));
        let w = cert_warnings(&c2, soon);
        assert!(w[0].contains("expires in 10 day(s) (2046-10-10)"), "{w:?}");
        let later = c.not_after_ms.unwrap() as u64 + 3 * 86_400_000;
        let c3 = parse_cert(cert_der().as_ref(), 443, later).unwrap();
        assert!(c3.expired);
        assert!(cert_warnings(&c3, later)[0].contains("expired 3 day(s) ago"));
        // Before notBefore.
        let early = 1_700_000_000_000;
        let c4 = parse_cert(cert_der().as_ref(), 443, early).unwrap();
        assert!(!c4.expired);
        assert!(cert_warnings(&c4, early)
            .iter()
            .any(|w| w.contains("not valid until")));
        // Garbage never panics.
        assert!(parse_cert(b"", 443, NOW_2027).is_none());
        assert!(parse_cert(&[0x30, 0x82, 0xff, 0xff, 1, 2, 3], 443, NOW_2027).is_none());
        let der = cert_der();
        for n in [1, 10, 100, der.as_ref().len() - 1] {
            assert!(parse_cert(&der.as_ref()[..n], 443, NOW_2027).is_none());
        }
    }

    #[test]
    fn iso_dates() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso8601(1_798_761_599), "2026-12-31T23:59:59Z");
        assert_eq!(iso8601(-86_400), "1969-12-31T00:00:00Z");
    }

    #[test]
    fn titles_are_strict_and_decoded() {
        let t = |s: &str| extract_title(s.as_bytes());
        assert_eq!(
            t("<html><head><TITLE>pve - Proxmox Virtual Environment</TITLE></head>").as_deref(),
            Some("pve - Proxmox Virtual Environment")
        );
        assert_eq!(
            t("<title lang=\"en\">\n  Synology&nbsp;DiskStation &amp; more &#x2013; &#169;\n</title>")
                .as_deref(),
            Some("Synology DiskStation & more – ©")
        );
        assert_eq!(
            t("<titlex>no</titlex><title>yes</title>").as_deref(),
            Some("yes")
        );
        assert_eq!(t("<title>unterminated"), None);
        assert_eq!(t("<title>   </title>"), None);
        assert_eq!(t("no title here"), None);
        // An inline SVG's <title> is not the page title.
        assert_eq!(
            t("<body><svg><title>icon</title></svg><title>Real</title>").as_deref(),
            Some("Real")
        );
        assert_eq!(t("<svg><title>icon</title></svg>"), None);
        // Escapes and control characters are removed, length is capped.
        let evil = t("<title>a\u{1b}[2J&#27;b&#0;c&#x202E;d</title>").unwrap();
        assert_eq!(evil, "a[2Jbcd");
        let long = format!("<title>{}</title>", "x".repeat(10_000));
        assert!(t(&long).unwrap().len() <= crate::models::MAX_TEXT_LEN);
        // Latin-1 pages.
        assert_eq!(
            extract_title(b"<title>Caf\xe9</title>").as_deref(),
            Some("Café")
        );
        assert_eq!(
            decode_entities("&bogus; &amp &#xZZ; &#99999999;"),
            "&bogus; &amp &#xZZ; "
        );
    }

    #[test]
    fn meta_refresh() {
        assert_eq!(
            meta_refresh_target(b"<META HTTP-EQUIV=\"Refresh\" CONTENT=\"0;URL='/ui/'\">")
                .as_deref(),
            Some("/ui/")
        );
        assert_eq!(
            meta_refresh_target(
                b"<meta http-equiv=refresh content=\"1; url=https://10.0.0.1:8443/\">"
            )
            .as_deref(),
            Some("https://10.0.0.1:8443/")
        );
        assert_eq!(meta_refresh_target(b"<meta charset=utf-8>"), None);
    }

    #[test]
    fn http_parsing_is_bounded() {
        let raw =
            "HTTP/1.1 200 OK\r\nServer: nginx \u{202e}evil\r\nContent-Length: 5\r\n\r\nhelloEXTRA"
                .as_bytes();
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(
            r.header("server"),
            Some("nginx evil"),
            "bidi overrides are stripped"
        );
        // Raw control characters in a header make it "not HTTP" (httparse rejects them).
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nServer: a\x1b[2J\r\n\r\n").is_err());
        assert_eq!(r.body, b"hello");
        assert!(response_complete(raw));
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;x=y\r\n world\r\n0\r\n\r\n";
        assert_eq!(parse_response(chunked).unwrap().body, b"hello world");
        assert!(response_complete(chunked));
        assert!(!response_complete(&chunked[..chunked.len() - 5]));
        assert!(!response_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc"
        ));
        assert!(response_complete(b"HTTP/1.1 304 Not Modified\r\n\r\n"));
        assert!(parse_response(b"SSH-2.0-OpenSSH_9.6\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nX: y").is_err());
        // Malformed chunk sizes stop decoding instead of panicking.
        let (body, done) = decode_chunked(b"zz\r\nabc\r\n");
        assert!(body.is_empty() && !done);
        let (body, done) = decode_chunked(b"ffffffffffffffff\r\nabc");
        assert_eq!((body.as_slice(), done), (b"abc".as_slice(), false));
    }

    #[test]
    fn redirects_stay_on_the_same_host() {
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        let cur = Target {
            scheme: WebScheme::Http,
            port: 80,
            path: "/admin/index.html".into(),
        };
        let r = |loc: &str| resolve_redirect(&cur, loc, ip);
        assert_eq!(
            r("https://10.0.0.5/").unwrap(),
            Target {
                scheme: WebScheme::Https,
                port: 443,
                path: "/".into()
            }
        );
        assert_eq!(r("https://10.0.0.5:8006/#x").unwrap().port, 8006);
        assert_eq!(r("/login?next=/").unwrap().path, "/login?next=/");
        assert_eq!(r("login.html").unwrap().path, "/admin/login.html");
        assert_eq!(r("HTTPS://10.0.0.5?a=1").unwrap().path, "/?a=1");
        assert_eq!(r("//10.0.0.5:81/x").unwrap().port, 81);
        for other in [
            "https://evil.example/",
            "https://10.0.0.6/",
            "https://user@10.0.0.5/",
            "https://10.0.0.5:0/",
            "https://10.0.0.5:99999/",
            "/path with space",
            "javascript:alert(1)",
            "",
        ] {
            assert!(r(other).is_none(), "{other}");
        }
        let v6: IpAddr = "2001:db8::5".parse().unwrap();
        let t6 = Target {
            scheme: WebScheme::Https,
            port: 443,
            path: "/".into(),
        };
        assert_eq!(
            resolve_redirect(&t6, "https://[2001:db8::5]:8443/ui", v6)
                .unwrap()
                .port,
            8443
        );
        assert_eq!(t6.url(v6), "https://[2001:db8::5]/");
        assert_eq!(
            Target {
                scheme: WebScheme::Http,
                port: 8080,
                path: "/".into()
            }
            .url(ip),
            "http://10.0.0.5:8080/"
        );
    }

    #[test]
    fn appliances_are_identified() {
        let id = |t: &[&str]| identify(t);
        assert_eq!(
            id(&["pve - Proxmox Virtual Environment"]).unwrap().0,
            "Proxmox VE"
        );
        assert_eq!(id(&["Synology DiskStation"]).unwrap().0, "Synology DSM");
        assert_eq!(id(&["iDRAC9 - Login"]).unwrap().0, "Dell iDRAC");
        assert_eq!(id(&["", "HP-iLO-Server/1.30"]).unwrap().0, "HPE iLO");
        assert_eq!(id(&["iLO 5"]).unwrap().0, "HPE iLO");
        assert!(id(&["Pilot program"]).is_none(), "'ilo' only as a word");
        assert_eq!(id(&["VMware ESXi"]).unwrap().0, "VMware ESXi");
        assert_eq!(id(&["ID_VC_Welcome"]).unwrap().0, "VMware vCenter");
        assert_eq!(id(&["UniFi OS"]).unwrap().0, "Ubiquiti UniFi");
        assert_eq!(
            id(&["pfSense - Login"]).unwrap(),
            ("pfSense", Some(DeviceRole::Firewall))
        );
        assert_eq!(
            id(&[
                "",
                "",
                "CN=FGT60FTK21000000, O=Fortinet",
                "CN=support, O=Fortinet"
            ])
            .unwrap(),
            ("Fortinet FortiGate", Some(DeviceRole::Firewall))
        );
        assert_eq!(
            id(&["RouterOS router configuration page"]).unwrap(),
            ("MikroTik RouterOS", Some(DeviceRole::Router))
        );
        assert_eq!(id(&["QTS"]).unwrap().0, "QNAP QTS");
        assert_eq!(id(&["TrueNAS"]).unwrap().0, "TrueNAS");
        assert_eq!(id(&["Pi-hole - raspberrypi"]).unwrap().0, "Pi-hole");
        assert_eq!(id(&["Home Assistant"]).unwrap().0, "Home Assistant");
        assert!(id(&["Welcome to nginx!", "nginx/1.25"]).is_none());
        assert!(id(&[]).is_none());
    }

    #[test]
    fn device_updates_never_override_better_roles() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let wid = WebIdentity {
            ip,
            services: vec![],
            title: Some("pfSense - Login".into()),
            server: Some("nginx".into()),
            tls_cert: None,
            identity: Some("pfSense".into()),
            role_hint: Some(DeviceRole::Firewall),
            warnings: vec!["TLS certificate on port 443 is self-signed".into()],
        };
        let mut host = Device::new(ip);
        host.vlan_id = Some(10);
        let u = device_update(&host, &wid).unwrap();
        assert_eq!(u.key(), host.key());
        assert_eq!(u.role, DeviceRole::Firewall);
        assert_eq!(u.web_identity.as_deref(), Some("pfSense"));
        assert_eq!(u.warnings.len(), 1);
        assert!(u.sources.is_empty());
        let mut sw = Device::new(ip);
        sw.role = DeviceRole::Switch;
        assert_eq!(device_update(&sw, &wid).unwrap().role, DeviceRole::Host);
        let empty = summarize(ip, vec![], NOW_2027);
        assert!(device_update(&host, &empty).is_none());
        assert_eq!(plan_ports(None).unwrap(), DEFAULT_WEB_PORTS);
        assert_eq!(plan_ports(Some(&[443, 443, 80])).unwrap(), vec![443, 80]);
        assert!(plan_ports(Some(&[0])).is_err());
        assert!(plan_ports(Some(&(1..=17).collect::<Vec<u16>>())).is_err());
    }

    /// Serve `responses` (one per connection) over plain HTTP; returns the port.
    async fn http_server(responses: Vec<String>) -> u16 {
        let l = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            for resp in responses {
                let Ok((mut s, _)) = l.accept().await else {
                    return;
                };
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(resp.replace("{PORT}", &port.to_string()).as_bytes())
                    .await;
                let _ = s.shutdown().await;
            }
        });
        port
    }

    #[tokio::test]
    async fn plain_http_title_server_and_redirect() {
        let port = http_server(vec![
            "HTTP/1.1 302 Found\r\nLocation: /ui/\r\nContent-Length: 0\r\n\r\n".into(),
            "HTTP/1.1 200 OK\r\nServer: lighttpd/1.4\r\nContent-Type: text/html\r\n\r\n\
             <html><head><title>Pi-hole &#8211; dns</title></head><body>x</body></html>"
                .into(),
        ])
        .await;
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let s = probe_port(ip, port, Duration::from_secs(2), &SocketBudget::new(2))
            .await
            .unwrap();
        assert_eq!(s.scheme, WebScheme::Http);
        assert_eq!(s.status, Some(200));
        assert_eq!(s.redirects, 1);
        assert_eq!(s.url, format!("http://127.0.0.1:{port}/ui/"));
        assert_eq!(s.title.as_deref(), Some("Pi-hole – dns"));
        assert_eq!(s.server.as_deref(), Some("lighttpd/1.4"));
        let id = summarize(ip, vec![s], now_ms());
        assert_eq!(id.identity.as_deref(), Some("Pi-hole"));

        // A redirect to another host is reported, not followed.
        let port = http_server(vec![
            "HTTP/1.1 301 Moved\r\nLocation: https://evil.example/\r\nContent-Length: 0\r\n\r\n"
                .into(),
        ])
        .await;
        let s = probe_port(ip, port, Duration::from_secs(2), &SocketBudget::new(2))
            .await
            .unwrap();
        assert_eq!((s.status, s.redirects), (Some(301), 0));
        assert_eq!(s.redirect_to.as_deref(), Some("https://evil.example/"));

        // A redirect loop stops after MAX_REDIRECTS.
        let looped = "HTTP/1.1 302 Found\r\nLocation: /a{N}\r\nContent-Length: 0\r\n\r\n";
        let port = http_server(
            (0..4)
                .map(|n| looped.replace("{N}", &n.to_string()))
                .collect(),
        )
        .await;
        let s = probe_port(ip, port, Duration::from_secs(2), &SocketBudget::new(2))
            .await
            .unwrap();
        assert_eq!(s.redirects, MAX_REDIRECTS);
        assert!(s.redirect_to.is_some());

        // A closed port yields no service at all.
        let closed = {
            let l = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            l.local_addr().unwrap().port()
        };
        assert!(
            probe_port(ip, closed, Duration::from_secs(1), &SocketBudget::new(1))
                .await
                .is_none()
        );
    }

    /// Scan integration: only devices with a web port open are probed, and they get a sparse
    /// update (same key) with the title and server header.
    #[tokio::test]
    async fn scan_enrichment_updates_devices_with_web_ports() {
        let port = http_server(vec![
            "HTTP/1.1 200 OK\r\nServer: mini_httpd\r\nContent-Length: 28\r\n\r\n<title>TrueNAS - nas</title>"
                .into(),
        ])
        .await;
        let mut web = Device::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        web.vlan_id = Some(20);
        web.open_ports = vec![22, port];
        let mut other = Device::new("127.0.0.2".parse().unwrap());
        other.open_ports = vec![22];
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let progress = ProgressScope::detached(2);
        enrich_web(
            vec![web.clone(), other],
            &[port],
            Duration::from_secs(2),
            tx,
            CancellationToken::new(),
            progress.clone(),
            &SocketBudget::new(4),
        )
        .await;
        assert_eq!(progress.used(), 2);
        let Ok(ScanEvent::Device(d)) = rx.try_recv() else {
            panic!("expected one device update")
        };
        assert_eq!(d.key(), web.key());
        assert_eq!(d.web_title.as_deref(), Some("TrueNAS - nas"));
        assert_eq!(d.web_server.as_deref(), Some("mini_httpd"));
        assert_eq!(d.web_identity.as_deref(), Some("TrueNAS"));
        assert!(
            rx.try_recv().is_err(),
            "the device without web ports is not probed"
        );
    }

    /// HTTPS end to end against an in-process rustls server with the self-signed test cert.
    #[tokio::test]
    async fn https_certificate_and_title() {
        let cert = cert_der();
        let key = PrivateKeyDer::from_pem_slice(TEST_KEY.as_bytes()).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(s).await else {
                        return;
                    };
                    let mut buf = [0u8; 2048];
                    let _ = tls.read(&mut buf).await;
                    let body = "<title>pve - Proxmox Virtual Environment</title>";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nServer: pve-api-daemon/3.0\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let id = grab_web_identity(
            ip,
            &[port],
            Duration::from_secs(3),
            &CancellationToken::new(),
            &SocketBudget::new(4),
        )
        .await;
        assert_eq!(id.services.len(), 1, "{id:?}");
        let s = &id.services[0];
        // Not a TLS-first port: plain HTTP fails at the protocol level, then TLS works.
        assert_eq!(s.scheme, WebScheme::Https);
        assert_eq!(s.status, Some(200));
        assert_eq!(
            id.title.as_deref(),
            Some("pve - Proxmox Virtual Environment")
        );
        assert_eq!(id.server.as_deref(), Some("pve-api-daemon/3.0"));
        assert_eq!(id.identity.as_deref(), Some("Proxmox VE"));
        assert_eq!(id.role_hint, None);
        let c = id.tls_cert.as_ref().unwrap();
        assert_eq!(c.subject_cn.as_deref(), Some("pve.example.lan"));
        assert!(c.self_signed);
        assert!(id.warnings.iter().any(|w| w.contains("self-signed")));
    }
}
