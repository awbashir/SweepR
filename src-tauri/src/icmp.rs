//! ICMP / ICMPv6 echo for the routed sweep ([`crate::sweep`]) and the latency monitor
//! ([`crate::latency`]).
//!
//! * **macOS / Linux**: `surge-ping`, one shared socket per address family. It opens an
//!   unprivileged `SOCK_DGRAM` ICMP socket where the OS allows it (macOS, Linux with
//!   `net.ipv4.ping_group_range`) and a raw socket otherwise.
//! * **Windows**: unprivileged ICMP sockets do not exist and raw sockets need Administrator
//!   rights, so echoes go through the ICMP helper API (`IcmpSendEcho` / `Icmp6SendEcho2`, what
//!   `ping.exe` uses; no elevation needed). Each call blocks, so it runs on tokio's blocking
//!   pool; [`WINDOWS_MAX_IN_FLIGHT`] caps how many wait at once so echoes never starve other
//!   blocking work (packet capture loops, file I/O).

use std::{io, net::IpAddr, time::Duration};

/// Address family of an [`EchoClient`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn of(ip: &IpAddr) -> Self {
        if ip.is_ipv4() {
            Self::V4
        } else {
            Self::V6
        }
    }
}

/// Most ICMP helper API calls waiting at once (Windows).
pub const WINDOWS_MAX_IN_FLIGHT: usize = 256;

/// A shared echo client for one address family. Cheap to clone.
#[derive(Clone)]
pub struct EchoClient {
    #[cfg(not(windows))]
    inner: surge_ping::Client,
    #[cfg(windows)]
    family: Family,
}

impl EchoClient {
    /// Open the client. Fails when the OS refuses ICMP sockets (e.g. Linux without
    /// `ping_group_range` and without `CAP_NET_RAW`).
    pub fn new(family: Family) -> io::Result<Self> {
        #[cfg(not(windows))]
        {
            let kind = match family {
                Family::V4 => surge_ping::ICMP::V4,
                Family::V6 => surge_ping::ICMP::V6,
            };
            let config = surge_ping::Config::builder().kind(kind).build();
            Ok(Self {
                inner: surge_ping::Client::new(&config)?,
            })
        }
        #[cfg(windows)]
        {
            // Probe once so a broken ICMP stack is reported up front, like a socket error.
            crate::win::IcmpHandle::open(family == Family::V6)?;
            Ok(Self { family })
        }
    }

    /// A pinger for `ip` (whose family must match the client's) with the echo identifier
    /// `ident` (ignored on Windows, where the OS matches replies) and per-echo `timeout`.
    pub async fn pinger(&self, ip: IpAddr, ident: u16, timeout: Duration) -> EchoPinger {
        #[cfg(not(windows))]
        {
            let mut p = self
                .inner
                .pinger(ip, surge_ping::PingIdentifier(ident))
                .await;
            p.timeout(timeout);
            EchoPinger { inner: p }
        }
        #[cfg(windows)]
        {
            let _ = ident;
            debug_assert_eq!(Family::of(&ip), self.family);
            EchoPinger {
                ip,
                timeout,
                handle: None,
            }
        }
    }
}

/// Sends echo requests to one host.
pub struct EchoPinger {
    #[cfg(not(windows))]
    inner: surge_ping::Pinger,
    #[cfg(windows)]
    ip: IpAddr,
    #[cfg(windows)]
    timeout: Duration,
    #[cfg(windows)]
    handle: Option<std::sync::Arc<crate::win::IcmpHandle>>,
}

impl EchoPinger {
    /// One echo request with sequence number `seq`; the round-trip time when the host
    /// itself answered within the timeout.
    pub async fn ping(&mut self, seq: u16, payload: &[u8]) -> Option<Duration> {
        #[cfg(not(windows))]
        {
            self.inner
                .ping(surge_ping::PingSequence(seq), payload)
                .await
                .ok()
                .map(|(_, rtt)| rtt)
        }
        #[cfg(windows)]
        {
            let _ = seq;
            windows_echo(self, payload).await
        }
    }
}

#[cfg(windows)]
async fn windows_echo(p: &mut EchoPinger, payload: &[u8]) -> Option<Duration> {
    use std::sync::{Arc, OnceLock};
    use tokio::sync::Semaphore;

    static IN_FLIGHT: OnceLock<Arc<Semaphore>> = OnceLock::new();
    let permit = IN_FLIGHT
        .get_or_init(|| Arc::new(Semaphore::new(WINDOWS_MAX_IN_FLIGHT)))
        .clone()
        .acquire_owned()
        .await
        .ok()?;
    let handle = match &p.handle {
        Some(h) => h.clone(),
        None => {
            let h = Arc::new(crate::win::IcmpHandle::open(p.ip.is_ipv6()).ok()?);
            p.handle = Some(h.clone());
            h
        }
    };
    let (ip, timeout, payload) = (p.ip, p.timeout, payload.to_vec());
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        handle
            .echo(ip, &payload, timeout, None)
            .filter(|a| a.is_echo_reply() && a.from == ip)
            .map(|a| a.rtt)
    })
    .await
    .ok()
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Loopback answers wherever the OS lets us open an ICMP client at all (always on
    /// Windows and macOS; on Linux only with `ping_group_range` or `CAP_NET_RAW`).
    #[tokio::test]
    async fn loopback_echo() {
        let client = match EchoClient::new(Family::V4) {
            Ok(c) => c,
            // Only Linux may refuse unprivileged ICMP (ping_group_range).
            Err(e) if cfg!(target_os = "linux") => {
                eprintln!("skipping: {e}");
                return;
            }
            Err(e) => panic!("ICMP client unavailable: {e}"),
        };
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut p = client.pinger(ip, 0x5357, Duration::from_secs(2)).await;
        let rtt = p.ping(1, b"SweepR-icmp-test").await;
        if cfg!(any(windows, target_os = "macos")) {
            assert!(rtt.is_some(), "no echo reply from loopback");
        }
    }
}
