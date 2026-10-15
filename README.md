# SweepR

SweepR (`sweepr`) is an IPv4/IPv6 network scanner for macOS and Linux, built for enterprise
networks. It combines LanScan-style live discovery with IEEE 802.1Q VLAN scanning and
switch / firewall / access-point discovery over CDP and LLDP.

The `sweepr` binary has two front-ends that share one Rust engine (`sweepr_core`):

- **CLI**: run it with a subcommand (`sweepr scan ...`). It scans in the terminal and exits.
- **GUI**: run it with no arguments, with `--gui`, or open the `.app`. This starts the Tauri
  desktop app.

## What it does

- **Interfaces**: finds every interface and labels it Ethernet, Wi-Fi, 802.1Q
  sub-interface (`vlan0`, `en0.100`, `eth0.10`), VPN, bridge/virtual or loopback. The
  default-route interface is marked.
- **Local IPv4 discovery**: sends broadcast ARP over the interface's connected subnet. Sending
  is rate-limited (`--rate-pps`), unanswered addresses get extra passes (`--retries`), and
  each result shows up as soon as it is found.
- **VLAN scanning**: sends 802.1Q-tagged ARP for one or more VLANs (`--vlan 10,20,30`,
  `--vlan 1-100`, or `--vlan untagged,10,20` to include the native network). Tagged replies
  are matched back to their VLAN. If the OS already has a VLAN sub-interface for an ID,
  SweepR scans through that sub-interface instead. Wi-Fi generally does not carry tagged
  frames; SweepR warns when tagged probing is requested on a Wi-Fi interface.
- **VLAN discovery**: listens passively for 802.1Q tags, Cisco VTP (VLAN names) and DTP
  (trunk negotiation). It also lists the OS's VLAN sub-interfaces. `--vlan auto` combines
  both sources.
- **Infrastructure discovery**: decodes CDP and LLDP to report device name, platform/model,
  OS version, remote port, management IPs, native and voice VLANs (including LLDP-MED
  network policy), and capabilities. A device that matches a neighbor is labelled as a
  Switch, Router, Access Point or Firewall.
- **Routed ranges**: addresses outside the connected subnet get an async ICMP echo sweep,
  then MAC addresses are filled in from the OS neighbor cache (only for hosts that answered,
  or entries the sweep itself created; stale cache entries are ignored).
- **IPv6** (`-6`): sends an ICMPv6 echo to `ff02::1` from the link-local address and from
  every global / unique-local address of the interface, sends neighbor solicitations for the
  EUI-64 addresses of hosts that answered ARP, and listens for neighbor and router
  advertisements. IPv6 addresses are attached to the matching IPv4 host as extra IPs
  ("Other IPs" column).
- **Export**: live terminal table, JSON, CSV or XLSX. Text learned from the network is
  stripped of control/escape characters, and CSV cells that a spreadsheet would treat as
  formulas are prefixed with `'`.

The SNMP v2c/v3 polling, name resolution (DNS/mDNS/NetBIOS) and TCP port fingerprinting
options (`--snmp-community`, `-p`) are accepted but do not run yet (the CLI prints a warning
when they are used). They arrive with the infrastructure/enrichment module.

## CLI usage

```sh
# Scan the default interface's subnet (live table)
sudo sweepr scan

# Scan a range
sweepr scan --range 10.0.0.0/24

# Probe VLANs 10, 20, 30 with tagged ARP and listen for CDP/LLDP
sudo sweepr scan -i en0 -r 10.177.134.1-10.177.140.254 --vlan 10,20,30 --snmp-community public --cdp-lldp

# Listen passively on a trunk for VLANs and CDP/LLDP neighbors
sudo sweepr vlans -i en0 --timeout 30

# Include IPv6 neighbors and export to Excel
sudo sweepr scan -r 192.168.1.0/24 -6 -o xlsx -f devices.xlsx

# JSON / CSV go to stdout unless --file is given
sweepr scan -r 10.0.0.0/24 -o json > devices.json

# List interfaces (kind, VLAN ID/parent, addresses)
sweepr interfaces
```

Main `scan` flags:

| Flag | Meaning |
| --- | --- |
| `-i, --interface` | Interface to use. Defaults to the default-route interface. |
| `-r, --range` | Targets as `10.0.0.0/24`, `10.0.0.1-10.0.3.254`, `10.0.0.1-50` or a comma list. Defaults to the interface's subnet. |
| `--vlan <IDS>` | 802.1Q VLAN IDs: `10,20,30`, `1-100`, `untagged,10,20` or `auto`. |
| `--discover-vlans` | Sniff 802.1Q tags, VTP and DTP while scanning. |
| `--cdp-lldp` | Listen for CDP/LLDP advertisements while scanning. |
| `--snmp-community` | SNMP v2c community (accepted; polling is not implemented yet). |
| `-6, --ipv6` | IPv6 neighbor discovery. |
| `-p, --ports` | TCP ports, e.g. `22,80,443` or `1-1024` (accepted; scanning is not implemented yet). |
| `-o, --output` | `table` (default, live), `json`, `csv` or `xlsx`. |
| `-f, --file` | Output file. Required for `xlsx`. |
| `--timeout-ms`, `--rate-pps`, `--retries`, `--listen-secs`, `--concurrency` | Timing and pacing (validated: timeout <= 600000 ms, rate 1-1000000 pps, retries <= 10, listen <= 86400 s, concurrency 1-65535). |

Press Ctrl-C once to stop and still get the results found so far. Press it twice to abort.
Piping into a reader that exits early (`sweepr scan | head -1`) stops the scan quietly with
exit status 0. If the OS transmit queue fills up (ENOBUFS), SweepR backs off and slows down
instead of failing, and reports how many probe frames were dropped.
Set `RUST_LOG=debug` for diagnostic logging.

## Privileges

Raw frames (ARP, 802.1Q tags, NDP) and passive capture (CDP, LLDP, VTP, DTP) need raw
packet access.

- **Linux**: run with `sudo`, or give the binary capabilities:
  `sudo setcap cap_net_raw,cap_net_admin=eip ./sweepr`.
- **macOS**: run with `sudo`. Giving your user access to `/dev/bpf*` (for example with
  Wireshark's *ChmodBPF* launch daemon) is enough for passive capture, but recent macOS
  versions hide interface MAC addresses from unprivileged processes (`sweepr interfaces`
  then shows no MACs and says so), and active ARP/802.1Q/NDP probes need the real MAC, so
  active layer-2 scans require `sudo`.

Without these privileges SweepR does not stop. It prints a warning and falls back to an
unprivileged ICMP sweep plus the OS neighbor cache, so hosts that block ICMP can be missed.
Tagged VLAN probing, IPv6 NDP and passive listening are skipped. Routed ranges always use
ICMP. On Linux, unprivileged ICMP needs `net.ipv4.ping_group_range` to include your group.

The NIC and driver must pass 802.1Q tags through for tagged scanning and tag discovery to
work. Capture is promiscuous, and libpcap re-inserts tags that Linux moves into packet
metadata. Some NICs, especially on macOS, still strip tags in hardware.

## Building

You need:

- Rust 1.90 or newer (`rustup`); this is the MSRV of Tauri 2.12 and its plugins
- libpcap: ships with macOS. On Debian/Ubuntu, install `libpcap-dev`.
- Tauri v2 system dependencies on Linux: `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`,
  `librsvg2-dev`, `libayatana-appindicator3-dev`
- Node.js 20 or newer for the React frontend

```sh
# CLI / engine only (the frontend is not needed for cargo builds)
cd src-tauri
cargo build --release
./target/release/sweepr --help

# Tests and lints
cargo test
cargo clippy --all-targets -- -D warnings

# Desktop app (from the repository root)
npm install
npm run tauri:dev      # development
npm run tauri:build    # .app/.dmg (macOS), .deb/.AppImage (Linux)
```

## Layout

```
src-tauri/
  src/main.rs      sweepr binary: chooses CLI or GUI, clap commands, Tauri commands
  src/lib.rs       sweepr_core library root
  src/models.rs    shared data model (Device, VlanInfo, CdpLldpNeighbor, ScanConfig, ScanEvent, ...)
  src/arp_vlan.rs  interface discovery, 802.1Q/ARP/NDP frames, CDP/LLDP/VTP/DTP parsers, L2 engine
  src/sweep.rs     ICMP sweep and OS neighbor cache
  src/engine.rs    scan planning, orchestration and result aggregation
  src/export.rs    CSV / JSON / XLSX export and terminal tables
```

## GUI backend contract

The webview may call only the commands listed in `src-tauri/build.rs` and granted in
`src-tauri/capabilities/default.json` (Tauri ACL):

| Command | Arguments | Returns |
| --- | --- | --- |
| `list_interfaces` | none | `InterfaceInfo[]` |
| `start_scan` | `{ config: ScanConfig }` | `scanId` (number). Cancels any running job. |
| `start_vlan_discovery` | `{ interface?: string, timeoutSecs?: number }` | `scanId` (number). Cancels any running job. |
| `stop_scan` | `{ scanId?: number }` | `true` if a job was signalled. With `scanId`, only that job is stopped. |
| `export_devices` | `{ devices: Device[], format: "csv" \| "json" \| "xlsx" }` | The written path, or `null` if the user cancelled. |

`export_devices` opens the native save dialog from the backend. The webview never passes a
file path. The chosen file must have the format's extension (it is added when missing), and
symbolic links and non-regular files are refused.

Scan progress arrives on the Tauri event `scan-event`. Every payload is wrapped with the id
of the job that produced it:

```json
{ "scanId": 7, "event": { "type": "device", "data": { "ip": "10.0.0.5", "...": "..." } } }
```

- `event` has the same `{ type, data }` shape as the CLI JSON events (`device`, `vlan`,
  `neighbor`, `port_mapping`, `progress`, `log`, `finished`).
- Only the current job emits. Once a new `start_scan` / `start_vlan_discovery` supersedes a
  job, that job emits nothing more, including its `finished`. The frontend should still
  ignore any payload whose `scanId` is not the id returned by its latest start call.
- A stopped (not superseded) job still sends its remaining events and ends with `finished`
  (`cancelled: true`).
- `device` and `vlan` events are full, merged snapshots: replace the row with the same key
  (device: `ip` plus `vlanId`; VLAN: `id`). `neighbor` events are sent when a neighbor is
  new or its advertisement changed.
- `progress` events report one combined `probesSent / probesTotal` for the whole scan. Both
  values only grow.
