use std::{fs, path::Path};

fn main() {
    // `tauri::generate_context!` embeds `build.frontendDist` and fails to compile when the
    // directory is missing. Create it so `cargo build` / `cargo check` (CLI-only workflows)
    // work on a fresh checkout before the frontend has been built.
    let dist = Path::new("..").join("dist");
    if !dist.exists() {
        let _ = fs::create_dir_all(&dist);
    }
    // The frontend is embedded into the binary at compile time. Without this, cargo does not
    // notice that `npm run build` changed `dist/`, so a binary built while `dist/` was empty keeps
    // serving nothing ("asset not found: index.html") until the crate is touched.
    println!("cargo:rerun-if-changed=../dist");
    windows_link_setup();
    // Declare the app's own IPC commands so they go through Tauri's ACL: only commands
    // granted in `capabilities/` (as `allow-<command>`) are callable from the webview.
    let attributes =
        tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(&[
            "list_interfaces",
            "start_scan",
            "stop_scan",
            "start_vlan_discovery",
            "export_devices",
            "load_overrides",
            "save_override",
            "scan_ports",
            "query_snmp",
            "generate_report",
            "reveal_report",
            "wake_device",
            "start_latency_monitor",
            "stop_latency_monitor",
            "start_trace",
            "stop_trace",
            "grab_web_identity",
            "iperf_available",
            "start_iperf",
            "stop_iperf",
            "discover_services",
            "save_file",
        ]));
    tauri_build::try_build(attributes).expect("failed to run tauri-build");
}

/// Windows (MSVC): libpcap (`wpcap.dll`) and pnet's `Packet.dll` come from Npcap, which is
/// not installed on every machine. Delay-load both so `sweepr.exe` starts without them; the
/// program loads them explicitly from `System32\Npcap` before the first packet-capture call
/// (`src/win.rs`) and reports "install Npcap" instead of failing to start.
///
/// Linking needs the import libraries from the Npcap SDK: set `LIBPCAP_LIBDIR` to its
/// `Lib\x64` folder (the `pcap` crate adds it to the linker search path; `LIB` works too)
/// and `LIBPCAP_VER` to the libpcap version Npcap is based on (e.g. `1.10.5`).
fn windows_link_setup() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" || target_env != "msvc" {
        return;
    }
    // pnet links Packet.lib itself; make sure the SDK folder is searched for it too.
    println!("cargo:rerun-if-env-changed=LIBPCAP_LIBDIR");
    if let Ok(dir) = std::env::var("LIBPCAP_LIBDIR") {
        println!("cargo:rustc-link-search=native={dir}");
    }
    for dll in ["wpcap.dll", "Packet.dll"] {
        println!("cargo:rustc-link-arg=/DELAYLOAD:{dll}");
    }
    // LNK4199 ("/DELAYLOAD ignored; no imports found") for targets that never capture, such
    // as the report example.
    println!("cargo:rustc-link-arg=/IGNORE:4199");
    // The delay-load helper from the MSVC runtime.
    println!("cargo:rustc-link-arg=delayimp.lib");
}
