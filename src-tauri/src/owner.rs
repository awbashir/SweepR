//! Ownership of files written under `sudo`.
//!
//! `sudo sweepr ...` (and the macOS "SweepR (Administrator)" launcher) run as root on behalf
//! of a user whose `HOME` is kept, so exports, reports and the overrides store land in that
//! user's folders. Files and directories SweepR *creates* are handed back to the invoking
//! user (`SUDO_UID` / `SUDO_GID`); otherwise later unprivileged runs could not replace them.
//! Existing files keep their owner. Failures are logged and otherwise ignored: the data was
//! written, only its owner is wrong.

use std::fs::File;
use std::path::Path;

/// The invoking user's `(uid, gid)` when this process runs as root under sudo.
#[cfg(unix)]
pub fn sudo_owner() -> Option<(libc::uid_t, libc::gid_t)> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let uid: libc::uid_t = std::env::var("SUDO_UID").ok()?.trim().parse().ok()?;
    let gid: libc::gid_t = std::env::var("SUDO_GID").ok()?.trim().parse().ok()?;
    (uid != 0).then_some((uid, gid))
}

/// Give a file SweepR just created (open descriptor) to the sudo user.
pub fn give_back_file(file: &File) {
    #[cfg(unix)]
    if let Some((uid, gid)) = sudo_owner() {
        use std::os::unix::io::AsRawFd;
        // SAFETY: the descriptor is valid for the lifetime of `file`.
        if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
            tracing::debug!(
                "cannot hand a new file to uid {uid}: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    #[cfg(not(unix))]
    let _ = file;
}

/// Give a file or directory SweepR just created (by path, never following a symlink) to the
/// sudo user.
pub fn give_back_path(path: &Path) {
    #[cfg(unix)]
    if let Some((uid, gid)) = sudo_owner() {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return;
        };
        // SAFETY: `c_path` is a valid NUL-terminated string.
        if unsafe { libc::lchown(c_path.as_ptr(), uid, gid) } != 0 {
            tracing::debug!(
                "cannot hand {} to uid {uid}: {}",
                path.display(),
                std::io::Error::last_os_error()
            );
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn not_root_or_no_sudo_means_no_owner_change() {
        // Tests do not run as root under sudo with these variables set; either way the
        // helpers must be harmless no-ops on files we own.
        let dir = std::env::temp_dir().join(format!("sweepr-owner-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.txt");
        let f = File::create(&path).unwrap();
        give_back_file(&f);
        give_back_path(&path);
        give_back_path(&dir.join("missing"));
        assert!(path.is_file());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
