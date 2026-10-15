use std::{fs, path::Path};

fn main() {
    // `tauri::generate_context!` embeds `build.frontendDist` and fails to compile when the
    // directory is missing. Create it so `cargo build` / `cargo check` (CLI-only workflows)
    // work on a fresh checkout before the frontend has been built.
    let dist = Path::new("..").join("dist");
    if !dist.exists() {
        let _ = fs::create_dir_all(&dist);
    }
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
        ]));
    tauri_build::try_build(attributes).expect("failed to run tauri-build");
}
