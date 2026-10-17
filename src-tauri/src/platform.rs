//! Small cross-platform helpers: privilege checks and hints, packet-capture availability,
//! system tool paths, child processes without console windows, file-open hardening flags.
//!
//! macOS / Linux behaviour is what it always was (root = euid 0, `sudo` hints, `O_NOFOLLOW`);
//! the Windows equivalents live here so call sites stay free of `cfg` noise.

use std::path::PathBuf;

/// `true` when the process has the privileges raw packet access usually needs: euid 0 on
/// Unix, an elevated ("Run as administrator") token on Windows.
pub fn is_privileged() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        crate::win::is_elevated()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// What raw layer-2 access requires on this OS, phrased to complete "raw packet access
/// requires ...". Every message carrying it starts with [`RAW_ACCESS_PREFIX`].
#[cfg(not(windows))]
pub const RAW_ACCESS_REQUIREMENT: &str = "root: run with sudo";
#[cfg(windows)]
pub const RAW_ACCESS_REQUIREMENT: &str =
    "Npcap (https://npcap.com); if Npcap is restricted to Administrators, run SweepR from an \
     elevated terminal";

/// Prefix of every "raw access unavailable" message (used to recognize them in logs).
pub const RAW_ACCESS_PREFIX: &str = "raw packet access requires";

/// The CLI's hint after a raw-access failure.
#[cfg(not(windows))]
pub const ROOT_HINT: &str = "hint: active layer-2 scanning (ARP, 802.1Q, NDP) and CDP/LLDP \
     capture need root: run `sudo sweepr ...`. On macOS, BPF device access (e.g. Wireshark's \
     ChmodBPF) is enough for passive capture only; active probes also need the interface MAC \
     address, which macOS hides from non-root processes.";
#[cfg(windows)]
pub const ROOT_HINT: &str = "hint: active layer-2 scanning (ARP, 802.1Q, NDP) and CDP/LLDP \
     capture need Npcap (https://npcap.com). If Npcap was installed with \"Restrict Npcap \
     driver's access to Administrators only\", run SweepR from an elevated terminal \
     (Run as administrator).";

/// How to run something with privileges, for short messages ("run with sudo").
pub fn elevate_hint() -> &'static str {
    if cfg!(windows) {
        "run from an elevated terminal (Run as administrator)"
    } else {
        "run with sudo"
    }
}

/// `Err(reason)` when the packet-capture library cannot be used at all (Windows without
/// Npcap). Always `Ok` on macOS / Linux, where libpcap is linked normally.
pub fn capture_driver_status() -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::win::npcap_status()
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

/// Absolute path of a Windows system tool (`System32\<exe>`), so `PATH` cannot substitute it.
pub fn system32_tool(exe: &str) -> PathBuf {
    #[cfg(windows)]
    {
        crate::win::system_dir().join(exe)
    }
    #[cfg(not(windows))]
    {
        PathBuf::from(exe)
    }
}

/// `CREATE_NO_WINDOW`: console tools run by the GUI (which has no console of its own) must
/// not pop up a console window.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Run `cmd` without a console window on Windows (no-op elsewhere).
pub fn hide_console_std(cmd: &mut std::process::Command) -> &mut std::process::Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// [`hide_console_std`] for `tokio::process::Command`.
pub fn hide_console(cmd: &mut tokio::process::Command) -> &mut tokio::process::Command {
    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// `FILE_FLAG_OPEN_REPARSE_POINT`: open a symbolic link / junction at the final path
/// component itself instead of following it (the Windows counterpart of `O_NOFOLLOW`).
#[cfg(windows)]
pub const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// `true` when `meta` (of an opened file) is a reparse point: a symbolic link, junction or
/// other redirection SweepR must not write through.
#[cfg(windows)]
pub fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_name_the_platform_mechanism() {
        let _ = is_privileged();
        assert!(capture_driver_status().is_ok() || cfg!(windows));
        if cfg!(windows) {
            assert!(RAW_ACCESS_REQUIREMENT.contains("Npcap"));
            assert!(elevate_hint().contains("administrator"));
        } else {
            assert!(RAW_ACCESS_REQUIREMENT.contains("sudo"));
            assert!(ROOT_HINT.contains("sudo"));
        }
    }
}
