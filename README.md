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

- **Enrichment**: after discovery, resolved hosts are enriched: the IEEE OUI database
  (embedded) names the vendor, DNS PTR / mDNS / NetBIOS fill host names, a bounded TCP
  connect scan (`-p`) lists open ports, and a management-port fingerprint classifies gear
  when nothing better is known (it needs vendor *and* port evidence, e.g. a Fortinet MAC
  is only a firewall with the FortiGate-only port 10443 open). Name resolution is on by
  default (`--no-resolve` disables it). PTR lookups use the system resolver only; if its
  configuration cannot be read they are skipped (never sent to a public resolver).
  All enrichment and SNMP sockets share one process-wide budget sized from the open-file
  limit, which SweepR raises at startup toward `min(hard limit, 10240)` (macOS defaults to
  256). A connect that still fails with "too many open files" is retried and, if it keeps
  failing, reported as unknown — never as closed.
- **SNMP** (`--snmp-community` / `--snmp-version` / `--snmp-user`, or the
  `sweepr snmp <IP>` subcommand): polls the system MIB, VLAN tables (Q-BRIDGE and Cisco
  VTP) and the bridge / CAM tables (v1 GETNEXT, v2c/v3 GETBULK) to classify infrastructure
  by role and map endpoint MACs to named switch ports (`Gi1/0/24`). During a scan only
  likely infrastructure is polled (the default gateway, CDP/LLDP neighbors' management
  addresses, devices already classified as infrastructure, network-vendor MACs and hosts
  with TCP 22/23/80/443/8291 open) unless `--snmp-all` is given; each host first gets a
  short reachability probe, and a summary line reports how many hosts answered, timed out
  or failed authentication. Walks are bounded (row and byte caps, at most 50,000 MAC
  entries per device, per-device deadline, end-of-MIB / loop detection) so a hostile agent
  cannot hang or exhaust memory; a walk that fails part-way keeps what it collected and the
  result is marked partial. A device's switch port ignores uplinks / trunks (ports that
  learned more than 48 MACs, or that lead to another switch, router or firewall), prefers
  the device's VLAN and then the port with the fewest MACs.

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

# Poll one switch over SNMP: system info, VLAN table and MAC-to-port table
sweepr snmp 10.0.0.1 --snmp-community public
sweepr snmp 10.0.0.1 --snmp-community public -o json

# SNMPv3 (authPriv). Pass passwords through the environment, not argv (other local users
# can read command lines)
SWEEPR_SNMP_AUTH_PASS='...' SWEEPR_SNMP_PRIV_PASS='...' \
  sweepr snmp 10.0.0.1 --snmp-user monitor --snmp-auth-proto sha256 --snmp-priv-proto aes128

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
| `--snmp-community` | SNMP v1/v2c community. Enables SNMP infrastructure polling. |
| `--snmp-version 1\|2c\|3` | SNMP version (default `3` when `--snmp-user` is given, else `2c`). Enables SNMP polling. |
| `--snmp-user` | SNMPv3 user name. Enables SNMPv3 polling. |
| `--snmp-auth-proto`, `--snmp-priv-proto` | SNMPv3 protocols: `md5`, `sha1` (default), `sha224`, `sha256`, `sha384`, `sha512`; `des`, `aes128` (default), `aes192`, `aes256`. |
| `--snmp-auth-pass`, `--snmp-priv-pass` | SNMPv3 passwords (at least 8 characters; privacy needs authentication). Also read from `SWEEPR_SNMP_AUTH_PASS` / `SWEEPR_SNMP_PRIV_PASS` — prefer those, since arguments are visible in the process list. |
| `--snmp-all` | Poll every discovered host over SNMP, not only likely infrastructure (slow on large ranges). |

AES-192 / AES-256 privacy with MD5 or SHA-1 authentication (and AES-256 with SHA-224) needs a
privacy-key extension, which agents implement in one of two incompatible ways (Reeder,
used by Cisco and most vendors, or Blumenthal). SweepR tries Reeder first and, if the first
encrypted request fails or times out, repeats it once with Blumenthal.
| `-6, --ipv6` | IPv6 neighbor discovery. |
| `-p, --ports` | TCP ports to connect-scan, e.g. `22,80,443` or `1-1024`. |
| `--no-resolve` | Disable DNS / mDNS / NetBIOS name resolution. |
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
  src/engine.rs    scan planning, orchestration, aggregation and the enrichment phase
  src/snmp_infra.rs  async SNMP (v1/v2c/v3): system MIB, VLAN tables, bridge/CAM mapping
  src/enricher.rs  OUI vendor DB, DNS/mDNS/NetBIOS, port scan, fingerprint, local overrides
  src/export.rs    CSV / JSON / XLSX export and terminal tables
  data/oui.tsv     embedded IEEE OUI database (generated by scripts/build_oui_db.py)
```

## GUI backend contract

The webview may call only the commands listed in `src-tauri/build.rs` and granted in
`src-tauri/capabilities/default.json` (Tauri ACL):

| Command | Arguments | Returns |
| --- | --- | --- |
| `list_interfaces` | none | `InterfaceInfo[]` |
| `start_scan` | `{ config: ScanConfig }` | `scanId` (number). Cancels any running job. |
| `start_vlan_discovery` | `{ interface?: string, timeoutSecs?: number }` | `scanId` (number). Cancels any running job. |
| `stop_scan` | `{ scanId?: number }` | `true` if a job was signalled. With `scanId`, only that job is stopped. Also cancels running `scan_ports` calls. |
| `export_devices` | `{ devices: Device[], format: "csv" \| "json" \| "xlsx" }` | The written path, or `null` if the user cancelled. |
| `load_overrides` | none | `Record<string, DeviceOverride>` (may be empty). Rejects when the store is unreadable or corrupt (the file is left untouched). |
| `save_override` | `{ key: string, hostname: string \| null, comments: string \| null }` | `null`. Rejects on a write error or a corrupt store (which is moved aside first). |
| `scan_ports` | `{ ip: string, ports: number[] }` | `number[]` of open ports (sorted). Rejects on a bad IP, > 4096 distinct ports, when 4 port scans are already running, when stopped by `stop_scan`, or when some ports could not be checked (out of file descriptors). |
| `query_snmp` | `{ ip: string, snmp: SnmpConfig \| null }` | `SnmpDeviceInfo`. Rejects on a bad IP, invalid config or unreachable device. |

Tauri maps Rust snake_case command arguments to camelCase in JS automatically (so
`scan_id` is `scanId`, `timeout_secs` is `timeoutSecs`).

`export_devices` opens the native save dialog from the backend. The webview never passes a
file path. The chosen file must have the format's extension (it is added when missing), and
symbolic links and non-regular files are refused.

`save_override` persists one record to a JSON file under the OS application-data directory.
Saves are serialized by a process-wide lock and written durably (uniquely named temp file,
fsync, rename, directory fsync). Strings are sanitized and capped at 1024 characters;
sending `null` (or a whitespace-only string) for a field clears it, and clearing both
removes the entry. A store that exists but cannot be parsed is never overwritten: it is
renamed to `overrides.json.corrupt-<unix-ms>` and the save rejects with a message naming
the backup (a retry starts a new store). `load_overrides` returns the whole store, keyed by
a device's `ip` (plus `@vlanId` when the device has a VLAN).

Overrides are the GUI's to apply: scans started with `start_scan` never write them into
`device.hostname` / `device.comments` (both stay `null` in `device` events), so the frontend
shows the overrides it loaded and a cleared label disappears immediately. Exports carry the
user's labels because the frontend fills `hostname` / `comments` from its overrides in the
`devices` it passes to `export_devices`. The CLI, whose output is final, still fills them
from the store.

`scan_ports` and `query_snmp` are single-device helpers for the details drawer; they run
independently of any scan job and do not emit `scan-event`s. `query_snmp` validates the
configuration first (SNMPv3 passwords must be at least 8 characters, privacy needs an
authentication password, port 1-65535) and returns partial results (`partial: true`) when
some tables could not be walked completely.

The webview holds only `opener:allow-open-url`, scoped to `http://`, `https://`, `ssh://`
and `telnet://` URLs; any other scheme, and every other opener command (such as revealing
files), is denied.

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
- `port_mapping` events (`{ type: "port_mapping", data: SwitchPortMapping }`) carry one
  SNMP-learned MAC→switch-port entry (at most 50,000 per polled device and 200,000 per
  scan; exact duplicates are not re-sent). The backend picks each device's `switchPort`
  from all of them — never an uplink / trunk (a port with more than 48 MACs or one leading
  to another switch, router or firewall), the device's VLAN first, then the port with the
  fewest MACs, ties broken by name — and re-emits the `device` when the choice changes (a
  final, order-independent pass runs when polling ends). The raw `port_mapping` events are
  forwarded for callers that want the full CAM table.
- `progress` events report one combined `probesSent / probesTotal` for the whole scan. Both
  values only grow. After discovery the scan runs an enrichment phase
  (`progress.phase === "enriching"`) that streams further `device`, `vlan` and
  `port_mapping` snapshots as names, ports, vendors and SNMP data arrive.

### New / enrichment data shapes

The engine fills these fields on `Device` during enrichment: `vendor` (IEEE OUI lookup),
`dnsName`, `mdnsName`, `smbName`, `smbDomain`, `openPorts` and `switchPort`. The command and
event payloads use these TypeScript-style shapes (all camelCase):

```ts
interface SwitchPortMapping {
  switchName: string;
  switchIp: string | null;
  portName: string;      // e.g. "Gi1/0/24"
  portIndex: number | null;
  vlanId: number | null;
  mac: string;
}

interface DeviceOverride {
  hostname: string | null;
  comments: string | null;
}

interface PortMacCount {
  portName: string;
  portIndex: number | null;
  macCount: number;      // high counts flag uplink / trunk ports
}

interface SnmpDeviceInfo {
  sysName: string | null;
  sysDescr: string | null;
  sysUptimeTicks: number | null;   // hundredths of a second
  sysObjectId: string | null;
  role: "switch" | "firewall" | "access_point" | "router" | "host"; // never null
  vlans: VlanInfo[];
  portMappings: SwitchPortMapping[];
  portMacCounts: PortMacCount[];
  partial: boolean;       // some walks failed / were cut short; data is what was collected
  warnings: string[];     // why (one line per failed or truncated walk)
}

// ScanConfig.snmpAll (boolean, default false): poll every discovered host over SNMP instead
// of only the gateway, CDP/LLDP neighbors and likely network gear.

// Passed to query_snmp (and nested in ScanConfig.snmp). Omitted fields default
// (v2c / "public" / port 161 / 2000 ms / 1 retry).
interface SnmpConfig {
  version: "v1" | "v2c" | "v3";
  community: string;
  v3: {
    username: string;
    authProtocol: "md5" | "sha1" | "sha224" | "sha256" | "sha384" | "sha512";
    authPassword: string | null;
    privProtocol: "des" | "aes128" | "aes192" | "aes256";
    privPassword: string | null;
  } | null;
  port: number;
  timeoutMs: number;
  retries: number;
}
```
