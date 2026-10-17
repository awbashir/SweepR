//! Windows-only system glue (Win32 through `windows-sys`), the counterpart of the Unix tools
//! and syscalls used elsewhere:
//!
//! * [`adapters`]: network adapters from `GetAdaptersAddresses` (friendly name, GUID, type,
//!   state, MAC, IPv4 + IPv6 addresses with prefix lengths, gateways).
//! * [`nic_vlan_ids`]: the NIC-level `VlanID` driver setting from the registry.
//! * [`IcmpHandle`]: ICMP / ICMPv6 echo through the ICMP helper API (`IcmpSendEcho`,
//!   `Icmp6SendEcho2`), which needs no Administrator rights, unlike raw sockets.
//! * [`npcap_status`]: loads Npcap's `Packet.dll` / `wpcap.dll` from `System32\Npcap`. Both
//!   are delay-loaded (see `build.rs`), so SweepR starts without Npcap and only the raw
//!   layer-2 features need it.
//! * [`is_elevated`], [`computer_name`], [`detach_console_if_owned`], [`set_unicast_if_v4`].
//!
//! The parsers for Windows tool output (`route print`, `arp -a`, `tracert`) are pure functions
//! next to their Unix counterparts, so they are unit tested on every OS.

use std::{
    ffi::{CStr, OsString},
    io,
    iter::once,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    ptr,
    sync::OnceLock,
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE},
    NetworkManagement::{
        IpHelper::{
            GetAdaptersAddresses, Icmp6CreateFile, Icmp6ParseReplies, Icmp6SendEcho2,
            IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, GAA_FLAG_INCLUDE_GATEWAYS,
            GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
            ICMPV6_ECHO_REPLY_LH, ICMP_ECHO_REPLY, IP_ADAPTER_ADDRESSES_LH, IP_OPTION_INFORMATION,
            IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT,
        },
        Ndis::IfOperStatusUp,
    },
    Networking::WinSock::{
        setsockopt, AF_INET, AF_INET6, AF_UNSPEC, IN6_ADDR, IN6_ADDR_0, IPPROTO_IP, IP_UNICAST_IF,
        SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET,
    },
    Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
    System::{
        Console::{FreeConsole, GetConsoleProcessList},
        LibraryLoader::{LoadLibraryExW, LOAD_WITH_ALTERED_SEARCH_PATH},
        Registry::{
            RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE,
            KEY_READ, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
        },
        SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW, GetSystemDirectoryW},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

// ---------------------------------------------------------------------------------------------
// Process facts
// ---------------------------------------------------------------------------------------------

/// `true` when the process token is elevated ("Run as administrator").
pub fn is_elevated() -> bool {
    // SAFETY: plain Win32 calls with valid out-pointers; the token handle is closed below.
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// `C:\Windows\System32` (from `GetSystemDirectoryW`).
pub fn system_dir() -> PathBuf {
    let mut buf = [0u16; 512];
    // SAFETY: `buf` is valid for `buf.len()` UTF-16 units.
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        return PathBuf::from(r"C:\Windows\System32");
    }
    PathBuf::from(OsString::from_wide(&buf[..n]))
}

/// The DNS host name of this machine.
pub fn computer_name() -> Option<String> {
    let mut buf = [0u16; 256];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` UTF-16 units; on success `len` is the length without the NUL.
    let ok = unsafe { GetComputerNameExW(ComputerNameDnsHostname, buf.as_mut_ptr(), &mut len) };
    (ok != 0 && (len as usize) <= buf.len())
        .then(|| String::from_utf16_lossy(&buf[..len as usize]))
        .filter(|s| !s.is_empty())
}

/// When a GUI launch is the only process attached to its console (started from Explorer or
/// a shortcut, not from a terminal), release the console so no empty window stays open next
/// to the app. A launch from a terminal keeps it (that terminal shares the console).
pub fn detach_console_if_owned() {
    let mut pids = [0u32; 4];
    // SAFETY: `pids` is valid for its length.
    let attached = unsafe { GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) };
    if attached == 1 {
        // SAFETY: no preconditions.
        unsafe { FreeConsole() };
    }
}

/// `IP_UNICAST_IF`: send IPv4 unicast *and broadcast* traffic of `sock` out of the interface
/// with index `index` (the Windows counterpart of macOS `IP_BOUND_IF`). Best effort.
pub fn set_unicast_if_v4(sock: &socket2::Socket, index: u32) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    // The option takes the index in network byte order.
    let value: u32 = index.to_be();
    // SAFETY: `value` outlives the call and `optlen` matches its size.
    let rc = unsafe {
        setsockopt(
            sock.as_raw_socket() as SOCKET,
            IPPROTO_IP,
            IP_UNICAST_IF,
            (&value as *const u32).cast(),
            size_of::<u32>() as i32,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn wide(s: &Path) -> Vec<u16> {
    s.as_os_str().encode_wide().chain(once(0)).collect()
}

fn wide_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(once(0)).collect()
}

// ---------------------------------------------------------------------------------------------
// Npcap
// ---------------------------------------------------------------------------------------------

/// Whether Npcap (the Windows packet-capture driver and its `wpcap.dll` / `Packet.dll`) is
/// usable; the error says how to fix it. Checked once per process.
///
/// Both DLLs are delay-loaded, so nothing in them runs before this succeeds. They are loaded
/// here by full path from `System32\Npcap` (a default Npcap install) or `System32` (Npcap's
/// "WinPcap API-compatible mode" / legacy WinPcap); the delay-load helper then finds the
/// already loaded modules by name.
pub fn npcap_status() -> Result<(), String> {
    static STATUS: OnceLock<Result<(), String>> = OnceLock::new();
    STATUS.get_or_init(load_npcap).clone()
}

fn load_npcap() -> Result<(), String> {
    let sys = system_dir();
    for dir in [sys.join("Npcap"), sys.clone()] {
        let (packet, wpcap) = (dir.join("Packet.dll"), dir.join("wpcap.dll"));
        if !packet.is_file() || !wpcap.is_file() {
            continue;
        }
        // Packet.dll first: wpcap.dll imports it, and LOAD_WITH_ALTERED_SEARCH_PATH resolves
        // a module's dependencies from its own directory.
        if load_library(&packet) && load_library(&wpcap) {
            tracing::debug!("Npcap loaded from {}", dir.display());
            return Ok(());
        }
    }
    Err(format!(
        "Npcap is not installed (no wpcap.dll / Packet.dll in {}\\Npcap); install it from \
         https://npcap.com",
        sys.display()
    ))
}

fn load_library(path: &Path) -> bool {
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated. The module stays loaded for the process lifetime.
    let module = unsafe {
        LoadLibraryExW(
            name.as_ptr(),
            ptr::null_mut(),
            LOAD_WITH_ALTERED_SEARCH_PATH,
        )
    };
    !module.is_null()
}

// ---------------------------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------------------------

/// One network adapter as reported by `GetAdaptersAddresses`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adapter {
    /// `{GUID}` (the adapter name; Npcap's device is `\Device\NPF_{GUID}`).
    pub guid: String,
    /// The connection name shown by Windows ("Ethernet", "Wi-Fi", "vEthernet (WSL)").
    pub friendly_name: String,
    /// Driver description ("Intel(R) Ethernet Connection I219-LM").
    pub description: String,
    /// IPv4 interface index (IPv6 index when IPv4 is disabled on the adapter).
    pub index: u32,
    /// IANA ifType (6 Ethernet, 71 IEEE 802.11, 24 loopback, 131 tunnel, ...).
    pub if_type: u32,
    pub up: bool,
    pub mac: Option<[u8; 6]>,
    /// Unicast addresses with their on-link prefix length.
    pub addrs: Vec<(IpAddr, u8)>,
    pub gateways: Vec<IpAddr>,
    pub ipv4_metric: u32,
}

impl Adapter {
    /// The Npcap / WinPcap device name for libpcap and `Packet.dll`.
    pub fn npf_name(&self) -> String {
        format!(r"\Device\NPF_{}", self.guid)
    }
}

/// Every adapter bound to TCP/IP (empty when the API fails).
pub fn adapters() -> Vec<Adapter> {
    let flags = GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER
        | GAA_FLAG_INCLUDE_GATEWAYS;
    // Microsoft recommends starting with 15 KB; retry with the size the call asks for.
    let mut size: u32 = 16 * 1024;
    for _ in 0..4 {
        // u64 elements: the list must be 8-byte aligned.
        let mut buf: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
        let first = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: `buf` is valid for `size` bytes; the API writes a linked list inside it.
        let rc = unsafe {
            GetAdaptersAddresses(u32::from(AF_UNSPEC), flags, ptr::null(), first, &mut size)
        };
        if rc == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if rc != ERROR_SUCCESS {
            tracing::debug!("GetAdaptersAddresses failed: {rc}");
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut cur = first.cast_const();
        // SAFETY: every node and every pointer in it points into `buf`, which outlives the walk.
        while let Some(a) = unsafe { cur.as_ref() } {
            out.push(unsafe { convert_adapter(a) });
            cur = a.Next.cast_const();
            if out.len() > 4096 {
                break;
            }
        }
        return out;
    }
    Vec::new()
}

/// # Safety
/// `a` must come from a successful `GetAdaptersAddresses` call whose buffer is still alive.
unsafe fn convert_adapter(a: &IP_ADAPTER_ADDRESSES_LH) -> Adapter {
    let guid = if a.AdapterName.is_null() {
        String::new()
    } else {
        CStr::from_ptr(a.AdapterName.cast_const().cast())
            .to_string_lossy()
            .into_owned()
    };
    let mac = (a.PhysicalAddressLength == 6)
        .then(|| {
            let mut m = [0u8; 6];
            m.copy_from_slice(&a.PhysicalAddress[..6]);
            m
        })
        .filter(|m| *m != [0; 6]);

    let mut addrs = Vec::new();
    let mut u = a.FirstUnicastAddress.cast_const();
    while let Some(ua) = u.as_ref() {
        if let Some(ip) = sockaddr_ip(ua.Address.lpSockaddr) {
            addrs.push((ip, ua.OnLinkPrefixLength));
        }
        u = ua.Next.cast_const();
        if addrs.len() > 256 {
            break;
        }
    }
    let mut gateways = Vec::new();
    let mut g = a.FirstGatewayAddress.cast_const();
    while let Some(ga) = g.as_ref() {
        if let Some(ip) = sockaddr_ip(ga.Address.lpSockaddr) {
            gateways.push(ip);
        }
        g = ga.Next.cast_const();
        if gateways.len() > 64 {
            break;
        }
    }
    let if_index = a.Anonymous1.Anonymous.IfIndex;
    Adapter {
        guid,
        friendly_name: wide_ptr_to_string(a.FriendlyName),
        description: wide_ptr_to_string(a.Description),
        index: if if_index != 0 {
            if_index
        } else {
            a.Ipv6IfIndex
        },
        if_type: a.IfType,
        up: a.OperStatus == IfOperStatusUp,
        mac,
        addrs,
        gateways,
        ipv4_metric: a.Ipv4Metric,
    }
}

/// # Safety
/// `p` must be null or point to a NUL-terminated UTF-16 string.
unsafe fn wide_ptr_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while len < 4096 && *p.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

/// # Safety
/// `sa` must be null or point to a valid `SOCKADDR_IN` / `SOCKADDR_IN6` (by its family).
unsafe fn sockaddr_ip(sa: *const SOCKADDR) -> Option<IpAddr> {
    let family = sa.as_ref()?.sa_family;
    if family == AF_INET {
        let sin = &*sa.cast::<SOCKADDR_IN>();
        Some(IpAddr::V4(Ipv4Addr::from(
            sin.sin_addr.S_un.S_addr.to_ne_bytes(),
        )))
    } else if family == AF_INET6 {
        let sin6 = &*sa.cast::<SOCKADDR_IN6>();
        Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.u.Byte)))
    } else {
        None
    }
}

/// NIC-level 802.1Q settings: adapter `{GUID}` → `VlanID` (the "VLAN ID" advanced property
/// many Intel / Realtek / Broadcom drivers offer; the NIC then tags everything it sends).
/// Read from the network adapter class key in the registry; unreadable keys are skipped.
pub fn nic_vlan_ids() -> Vec<(String, u16)> {
    const CLASS: &str =
        r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
    let class = wide_str(CLASS);
    let mut key: HKEY = ptr::null_mut();
    // SAFETY: valid NUL-terminated key path and out-pointer; the key is closed below.
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, class.as_ptr(), 0, KEY_READ, &mut key) }
        != ERROR_SUCCESS
    {
        return Vec::new();
    }
    let mut out = Vec::new();
    for index in 0..1024u32 {
        let mut name = [0u16; 256];
        let mut len = name.len() as u32;
        // SAFETY: `name` holds `len` units; the optional out-parameters are null.
        let rc = unsafe {
            RegEnumKeyExW(
                key,
                index,
                name.as_mut_ptr(),
                &mut len,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if rc != ERROR_SUCCESS {
            break;
        }
        let sub = String::from_utf16_lossy(&name[..len as usize]);
        let (Some(guid), Some(vid)) = (
            reg_string(key, &sub, "NetCfgInstanceId"),
            reg_string(key, &sub, "VlanID").or_else(|| reg_string(key, &sub, "VLANID")),
        ) else {
            continue;
        };
        if let Ok(vid) = vid.trim().parse::<u16>() {
            if (1..=crate::models::MAX_VLAN_ID).contains(&vid) {
                out.push((guid, vid));
            }
        }
    }
    // SAFETY: `key` was opened above.
    unsafe { RegCloseKey(key) };
    out
}

/// A `REG_SZ` (or `REG_DWORD`, rendered in decimal) value under `parent\sub`.
fn reg_string(parent: HKEY, sub: &str, value: &str) -> Option<String> {
    let (sub_w, value_w) = (wide_str(sub), wide_str(value));
    let mut buf = [0u16; 128];
    let mut bytes = (buf.len() * 2) as u32;
    let mut kind = 0u32;
    // SAFETY: `buf` is valid for `bytes` bytes; strings are NUL-terminated.
    let rc = unsafe {
        RegGetValueW(
            parent,
            sub_w.as_ptr(),
            value_w.as_ptr(),
            RRF_RT_REG_SZ | RRF_RT_REG_DWORD,
            &mut kind,
            buf.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    const REG_DWORD: u32 = 4;
    if kind == REG_DWORD && bytes >= 4 {
        let v = u32::from(buf[0]) | (u32::from(buf[1]) << 16);
        return Some(v.to_string());
    }
    let units = (bytes as usize / 2).min(buf.len());
    let end = buf[..units].iter().position(|c| *c == 0).unwrap_or(units);
    Some(String::from_utf16_lossy(&buf[..end]))
}

// ---------------------------------------------------------------------------------------------
// ICMP helper API
// ---------------------------------------------------------------------------------------------

/// The answer to one ICMP helper API echo.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EchoAnswer {
    /// Who answered: the target for an echo reply, a router for TTL expired.
    pub from: IpAddr,
    /// `IP_SUCCESS` (0), `IP_TTL_EXPIRED_TRANSIT` (11013), `IP_DEST_*_UNREACHABLE`, ...
    pub status: u32,
    /// Wall-clock round trip (the API itself only reports whole milliseconds).
    pub rtt: Duration,
}

impl EchoAnswer {
    pub fn is_echo_reply(&self) -> bool {
        self.status == IP_SUCCESS
    }

    pub fn is_ttl_expired(&self) -> bool {
        self.status == IP_TTL_EXPIRED_TRANSIT
    }
}

/// An ICMP (`IcmpCreateFile`) or ICMPv6 (`Icmp6CreateFile`) handle. Echo calls block, so run
/// them on a blocking thread.
#[derive(Debug)]
pub struct IcmpHandle {
    handle: HANDLE,
    v6: bool,
}

// SAFETY: an ICMP handle is a kernel handle; the API may be used from any thread.
unsafe impl Send for IcmpHandle {}
// SAFETY: see above; `echo` takes `&self` and the API keeps no per-handle user state.
unsafe impl Sync for IcmpHandle {}

impl IcmpHandle {
    pub fn open(v6: bool) -> io::Result<Self> {
        // SAFETY: no preconditions.
        let handle = unsafe {
            if v6 {
                Icmp6CreateFile()
            } else {
                IcmpCreateFile()
            }
        };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle, v6 })
    }

    /// One echo request to `dst` (blocking for at most `timeout`), optionally with a TTL /
    /// hop limit. `None` when nothing answered in time.
    pub fn echo(
        &self,
        dst: IpAddr,
        payload: &[u8],
        timeout: Duration,
        ttl: Option<u8>,
    ) -> Option<EchoAnswer> {
        let payload = &payload[..payload.len().min(1024)];
        let options = IP_OPTION_INFORMATION {
            Ttl: ttl.unwrap_or(128),
            Tos: 0,
            Flags: 0,
            OptionsSize: 0,
            OptionsData: ptr::null_mut(),
        };
        let timeout_ms = u32::try_from(timeout.as_millis())
            .unwrap_or(u32::MAX)
            .max(1);
        // Reply buffer: the reply struct + our payload + 8 bytes for an ICMP error + slack for
        // the IO_STATUS_BLOCK Icmp6SendEcho2 needs. u64 elements for alignment.
        let reply_len = size_of::<ICMP_ECHO_REPLY>() + payload.len() + 8 + 64;
        let mut reply: Vec<u64> = vec![0; reply_len.div_ceil(8)];
        let reply_bytes = (reply.len() * 8) as u32;
        let started = Instant::now();
        match (dst, self.v6) {
            (IpAddr::V4(v4), false) => {
                // SAFETY: all buffers are valid for the sizes passed; the call is synchronous.
                let n = unsafe {
                    IcmpSendEcho(
                        self.handle,
                        u32::from_ne_bytes(v4.octets()),
                        payload.as_ptr().cast(),
                        payload.len() as u16,
                        &options,
                        reply.as_mut_ptr().cast(),
                        reply_bytes,
                        timeout_ms,
                    )
                };
                let rtt = started.elapsed();
                if n == 0 {
                    return None;
                }
                // SAFETY: on success the buffer starts with an ICMP_ECHO_REPLY.
                let r = unsafe { ptr::read_unaligned(reply.as_ptr().cast::<ICMP_ECHO_REPLY>()) };
                Some(EchoAnswer {
                    from: IpAddr::V4(Ipv4Addr::from(r.Address.to_ne_bytes())),
                    status: r.Status,
                    rtt,
                })
            }
            (IpAddr::V6(v6), true) => {
                let source = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    ..Default::default()
                };
                let dest = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 { Byte: v6.octets() },
                    },
                    ..Default::default()
                };
                // SAFETY: as above; no event / APC routine, so the call is synchronous.
                let n = unsafe {
                    Icmp6SendEcho2(
                        self.handle,
                        ptr::null_mut(),
                        None,
                        ptr::null(),
                        &source,
                        &dest,
                        payload.as_ptr().cast(),
                        payload.len() as u16,
                        &options,
                        reply.as_mut_ptr().cast(),
                        reply_bytes,
                        timeout_ms,
                    )
                };
                let rtt = started.elapsed();
                // SAFETY: the buffer is the one the echo call filled.
                if n == 0
                    || unsafe { Icmp6ParseReplies(reply.as_mut_ptr().cast(), reply_bytes) } == 0
                {
                    return None;
                }
                // SAFETY: on success the buffer starts with an ICMPV6_ECHO_REPLY_LH (packed
                // address, hence the unaligned read).
                let r =
                    unsafe { ptr::read_unaligned(reply.as_ptr().cast::<ICMPV6_ECHO_REPLY_LH>()) };
                let words = r.Address.sin6_addr;
                let mut bytes = [0u8; 16];
                for (i, w) in words.iter().enumerate() {
                    bytes[i * 2..i * 2 + 2].copy_from_slice(&w.to_ne_bytes());
                }
                Some(EchoAnswer {
                    from: IpAddr::V6(Ipv6Addr::from(bytes)),
                    status: r.Status,
                    rtt,
                })
            }
            _ => None,
        }
    }
}

impl Drop for IcmpHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from Icmp(6)CreateFile and is closed exactly once.
        unsafe { IcmpCloseHandle(self.handle) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapters_include_the_loopback_pseudo_interface() {
        let all = adapters();
        assert!(!all.is_empty(), "GetAdaptersAddresses returned nothing");
        assert!(all.iter().all(|a| a.guid.starts_with('{')), "{all:?}");
        assert!(
            all.iter()
                .any(|a| a.if_type == 24 && a.addrs.iter().any(|(ip, _)| ip.is_loopback())),
            "{all:?}"
        );
    }

    #[test]
    fn icmp_api_pings_loopback_without_elevation() {
        let h = IcmpHandle::open(false).unwrap();
        let ans = h
            .echo(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                b"SweepR-test",
                Duration::from_secs(2),
                None,
            )
            .expect("loopback must answer");
        assert!(ans.is_echo_reply(), "{ans:?}");
        assert_eq!(ans.from, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn icmpv6_api_pings_loopback() {
        let Ok(h) = IcmpHandle::open(true) else {
            return; // IPv6 disabled on this host
        };
        if let Some(ans) = h.echo(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            b"SweepR-test",
            Duration::from_secs(2),
            None,
        ) {
            assert!(ans.is_echo_reply(), "{ans:?}");
            assert_eq!(ans.from, IpAddr::V6(Ipv6Addr::LOCALHOST));
        }
    }

    #[test]
    fn process_facts_do_not_fail() {
        let _ = is_elevated();
        assert!(system_dir().is_absolute());
        assert!(computer_name().is_some());
        let _ = nic_vlan_ids();
        // Either loads or says how to install it; never crashes.
        if let Err(e) = npcap_status() {
            assert!(e.contains("npcap.com"), "{e}");
        }
    }
}
