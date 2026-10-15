//! Process-wide file-descriptor budget.
//!
//! macOS starts processes with a soft `RLIMIT_NOFILE` of 256. Enrichment (TCP connect scans,
//! NetBIOS, DNS) and SNMP polling can easily want more sockets than that at once, and a
//! connect that fails with `EMFILE` must never be mistaken for a closed port. Two layers keep
//! that from happening:
//!
//! * [`raise_nofile_limit`] lifts the soft limit toward `min(hard, 10240)` at startup (CLI and
//!   GUI).
//! * [`SocketBudget::global`] is one semaphore shared by every enrichment / SNMP socket, sized
//!   from the limit actually in force with headroom for everything else the process opens
//!   (pcap/BPF handles, the GUI's own descriptors, log files, ...).
//!
//! Code that still hits `EMFILE` / `ENFILE` treats it as retryable ([`is_fd_exhausted`]) and
//! reports it once ([`warn_fd_exhausted_once`]).

use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Soft `RLIMIT_NOFILE` the process asks for (macOS `OPEN_MAX`).
pub const NOFILE_TARGET: u64 = 10_240;
/// Descriptors kept out of the socket budget for everything else the process opens.
const RESERVED_FDS: u64 = 128;
/// Bounds of the global socket budget.
pub const MIN_SOCKET_PERMITS: usize = 16;
pub const MAX_SOCKET_PERMITS: usize = 1024;
/// Budget used when the descriptor limit cannot be read.
const FALLBACK_SOCKET_PERMITS: usize = 128;

/// Current `(soft, hard)` `RLIMIT_NOFILE`, when it can be read.
#[cfg(unix)]
#[allow(clippy::useless_conversion)]
pub fn nofile_limit() -> Option<(u64, u64)> {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `getrlimit` only writes into the struct we pass.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } != 0 {
        return None;
    }
    Some((
        u64::try_from(rl.rlim_cur).unwrap_or(u64::MAX),
        u64::try_from(rl.rlim_max).unwrap_or(u64::MAX),
    ))
}

#[cfg(not(unix))]
pub fn nofile_limit() -> Option<(u64, u64)> {
    None
}

/// Raise the soft `RLIMIT_NOFILE` toward `min(hard, NOFILE_TARGET)` (never lowers it).
/// Returns the `(soft, hard)` limit in force afterwards. Call once at startup, before the
/// first [`SocketBudget::global`] use, so the budget is sized from the raised limit.
#[cfg(unix)]
#[allow(clippy::useless_conversion)]
pub fn raise_nofile_limit() -> Option<(u64, u64)> {
    let (soft, hard) = nofile_limit()?;
    let want = NOFILE_TARGET.min(hard);
    if soft < want {
        // `rlim_t` is `u64` on the supported targets; the conversions are no-ops there.
        let rl = libc::rlimit {
            rlim_cur: libc::rlim_t::try_from(want).unwrap_or(libc::RLIM_INFINITY),
            rlim_max: libc::rlim_t::try_from(hard).unwrap_or(libc::RLIM_INFINITY),
        };
        // SAFETY: `setrlimit` only reads the struct we pass.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rl) } != 0 {
            // Some kernels reject values above an internal ceiling; keep what we have.
            tracing::debug!("could not raise RLIMIT_NOFILE to {want}");
        }
    }
    let now = nofile_limit();
    if let Some((soft, hard)) = now {
        tracing::debug!("RLIMIT_NOFILE soft={soft} hard={hard}");
    }
    now
}

#[cfg(not(unix))]
pub fn raise_nofile_limit() -> Option<(u64, u64)> {
    None
}

/// Socket permits for a soft descriptor limit: half of what is left after the reserve,
/// clamped to `[MIN_SOCKET_PERMITS, MAX_SOCKET_PERMITS]`.
pub fn permits_for_limit(soft: Option<u64>) -> usize {
    match soft {
        Some(soft) => {
            let usable = soft.saturating_sub(RESERVED_FDS) / 2;
            usize::try_from(usable)
                .unwrap_or(MAX_SOCKET_PERMITS)
                .clamp(MIN_SOCKET_PERMITS, MAX_SOCKET_PERMITS)
        }
        None => FALLBACK_SOCKET_PERMITS,
    }
}

/// A shared cap on concurrently open enrichment / SNMP sockets. Cheap to clone.
#[derive(Debug, Clone)]
pub struct SocketBudget {
    sem: Arc<Semaphore>,
    permits: usize,
}

impl SocketBudget {
    /// A private budget of `permits` sockets (tests, or callers that need a tighter cap).
    pub fn new(permits: usize) -> Self {
        let permits = permits.max(1);
        Self {
            sem: Arc::new(Semaphore::new(permits)),
            permits,
        }
    }

    /// The process-wide budget, sized from the descriptor limit at first use.
    pub fn global() -> &'static SocketBudget {
        static GLOBAL: OnceLock<SocketBudget> = OnceLock::new();
        GLOBAL.get_or_init(|| {
            let permits = permits_for_limit(nofile_limit().map(|(soft, _)| soft));
            tracing::debug!("socket budget: {permits} concurrent sockets");
            SocketBudget::new(permits)
        })
    }

    /// Total permits of this budget.
    pub fn capacity(&self) -> usize {
        self.permits
    }

    /// Wait for one socket permit. Never fails in practice (the semaphore is never closed).
    pub async fn acquire(&self) -> Option<OwnedSemaphorePermit> {
        self.sem.clone().acquire_owned().await.ok()
    }
}

/// `true` when `err` means the process or the system ran out of file descriptors.
pub fn is_fd_exhausted(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(code) if code == libc::EMFILE || code == libc::ENFILE)
}

static FD_WARNED: AtomicBool = AtomicBool::new(false);

/// Log (once per process) that sockets hit the descriptor limit. Returns `true` the first
/// time, so callers can also surface it to the user once.
pub fn warn_fd_exhausted_once(context: &str) -> bool {
    let first = !FD_WARNED.swap(true, Ordering::Relaxed);
    if first {
        tracing::warn!(
            "{context}: out of file descriptors (EMFILE/ENFILE); retrying with backoff. \
             Raise `ulimit -n` if this persists."
        );
    }
    first
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permits_scale_with_limit_and_are_bounded() {
        assert_eq!(permits_for_limit(None), FALLBACK_SOCKET_PERMITS);
        // macOS default soft limit: (256 - 128) / 2 = 64.
        assert_eq!(permits_for_limit(Some(256)), 64);
        assert_eq!(permits_for_limit(Some(10_240)), MAX_SOCKET_PERMITS);
        assert_eq!(permits_for_limit(Some(100)), MIN_SOCKET_PERMITS);
        assert_eq!(permits_for_limit(Some(u64::MAX)), MAX_SOCKET_PERMITS);
    }

    #[test]
    fn fd_exhaustion_is_recognized() {
        assert!(is_fd_exhausted(&io::Error::from_raw_os_error(libc::EMFILE)));
        assert!(is_fd_exhausted(&io::Error::from_raw_os_error(libc::ENFILE)));
        assert!(!is_fd_exhausted(&io::Error::from_raw_os_error(
            libc::ECONNREFUSED
        )));
        assert!(!is_fd_exhausted(&io::Error::other("x")));
    }

    #[cfg(unix)]
    #[test]
    fn raising_the_limit_never_lowers_it() {
        let before = nofile_limit().unwrap();
        let after = raise_nofile_limit().unwrap();
        assert!(after.0 >= before.0);
        assert!(after.0 >= before.0.min(NOFILE_TARGET.min(before.1)));
    }
}
