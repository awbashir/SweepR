//! `sweepr-core`: the SweepR scan engine shared by the `sweepr` CLI and the Tauri GUI.

pub mod arp_vlan;
pub mod engine;
pub mod enricher;
pub mod export;
pub mod iperf;
pub mod jobs;
pub mod latency;
pub mod limits;
pub mod models;
pub mod progress;
pub mod snmp_infra;
pub mod sweep;
pub mod trace;
pub mod webid;
pub mod wol;

/// Install a `tracing` subscriber writing to stderr. The filter comes from `RUST_LOG`
/// (default `warn`). Safe to call more than once.
pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}
