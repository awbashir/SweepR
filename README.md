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
- **Service discovery** (on by default; `--no-services` disables it): after names and ports,
  SweepR identifies discovered hosts over three protocols at once. Only hosts the scan
  already found are enriched; responders it did not find are not added.
  - **SSDP / UPnP** (UDP 1900): `M-SEARCH` (`ssdp:all`, `upnp:rootdevice`) to
    `239.255.255.250` from the scan interface (and `ff02::c` / `ff05::c` with `-6`). Each
    device description XML is fetched **only** when the `LOCATION` host is the IP that
    answered, over plain HTTP, at most 256 KiB, with a timeout and same-origin redirects only,
    so a hostile reply cannot make SweepR connect anywhere else. The XML is read with a
    hardened parser (no DTD, no entity expansion, bounded depth / size) for friendly name,
    manufacturer, model, serial, device type, UDN and services, and the device is classified
    (`media_server`, `igd_router`, `printer`, `tv`, `nas`, `camera`, ...).
  - **WS-Discovery / ONVIF** (UDP 3702): a SOAP `Probe` collects `XAddrs` / `Types` /
    `Scopes`. Windows hosts (WSD `pub:Computer`) get their computer name from a WS-Transfer
    `Get`; ONVIF cameras are asked for `GetDeviceInformation` (manufacturer, model, firmware,
    serial, hardware id) and, unauthenticated, `GetCapabilities` → `GetProfiles` →
    `GetStreamUri`. All of it only at the camera's own address and **never with credentials**.
    An RTSP URL is reported only when the camera returns one; otherwise common vendor URL
    templates (Hikvision, Dahua, Axis, ...) are listed as `rtspHints`, labelled as guesses.
  - **SIP OPTIONS** (UDP 5060, then TCP 5060): an RFC 3261 `OPTIONS` ping to hosts with
    5060/5061 open, a VoIP-maker MAC (Yealink, Grandstream, Poly, Cisco, Snom, Fanvil, Avaya,
    Mitel, ...) or a CDP/LLDP Telephone capability (`--sip-all`: every host). The `Server` /
    `User-Agent` names the PBX (Asterisk, FreePBX/Issabel, 3CX, Cisco CUCM, FreeSWITCH,
    Kamailio/OpenSIPS, Yeastar, Grandstream UCM) or the desk phone with its model and
    firmware. No registration or authentication is ever attempted. SIP over TLS (5061) is not
    probed.
- **PoE and voice VLANs**: CDP Power Consumption / Power Available, LLDP IEEE 802.3
  Power-via-MDI (class, 802.3at requested / allocated power) and LLDP-MED Extended
  Power-via-MDI (value, source, priority) are decoded from neighbor adverts. Over SNMP, the
  POWER-ETHERNET-MIB port table (status, class) and main PSE table (budget, consumption,
  threshold), Cisco's per-port power consumption and Cisco `vmVoiceVlanId` are read; the
  endpoint on an access port gets that port's `poe` and `voiceVlan`, and each switch's PoE
  budget appears in `query_snmp`. PoE ports are indexed by module/port, not ifIndex, so the
  PoE-port-to-interface match is a documented heuristic (port number = last number of the
  interface name, and the PSE group = its first number when the switch has several).
- **DHCP fingerprinting** (`--dhcp-fingerprint`, opt-in, needs root like the other sniffers):
  during the listen window (and in `sweepr vlans --dhcp-fingerprint`), inbound DHCP
  DISCOVER / REQUEST / INFORM packets (BPF `udp and (port 67 or port 68)`, VLAN tags honoured)
  are parsed and the option-55 parameter list, vendor class (option 60) and hostname are
  matched against an embedded table (`data/dhcp_fingerprints.tsv`). **These are best-effort
  heuristics with a confidence level (high / medium / low), not an authoritative OS
  identification**; the Fingerbank API is not used. A client that has no address yet is
  attributed to its row by MAC.

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
| `--no-services` | Skip service discovery (SSDP/UPnP, WS-Discovery/ONVIF, SIP OPTIONS). |
| `--sip-all` | SIP OPTIONS to every discovered IPv4 host, not only 5060-open / VoIP-vendor / telephone hosts. |
| `--dhcp-fingerprint` | Passively fingerprint DHCP clients during the listen window (needs root). Also on `sweepr vlans`. |
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

# Run the GUI straight from cargo with the embedded frontend (no dev server):
npm run build
cd src-tauri && cargo run --features custom-protocol -- --gui
```

Without `--features custom-protocol`, a debug binary loads `devUrl` (http://localhost:1420) and
shows a blank window unless `npm run dev` is running. `tauri build` enables the feature for you.

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
  src/services.rs  service-discovery enrichment (SSDP + WSD + SIP) and the single-host probe
  src/ssdp.rs      SSDP/UPnP M-SEARCH, SSRF-guarded description fetch, hardened XML walker
  src/wsd.rs       WS-Discovery probe, ONVIF device info / stream URI, WSD metadata
  src/sip.rs       SIP OPTIONS ping and PBX / phone identification table
  src/dhcp_fp.rs   passive DHCP capture, option parser and fingerprint matcher
  src/export.rs    CSV / JSON / XLSX export and terminal tables
  data/oui.tsv     embedded IEEE OUI database (generated by scripts/build_oui_db.py)
  data/dhcp_fingerprints.tsv  embedded DHCP signature table (best-effort heuristics)
```

## GUI backend contract

The webview may call only the commands listed in `src-tauri/build.rs` and granted in
`src-tauri/capabilities/default.json` (Tauri ACL):

| Command | Arguments | Returns |
| --- | --- | --- |
| `list_interfaces` | none | `InterfaceInfo[]` |
| `start_scan` | `{ config: ScanConfig }` | `scanId` (number). Cancels any running job. |
| `start_vlan_discovery` | `{ interface?: string, timeoutSecs?: number, dhcpFingerprint?: boolean }` | `scanId` (number). Cancels any running job. `dhcpFingerprint` also fingerprints DHCP clients for the same window (needs root). |
| `stop_scan` | `{ scanId?: number }` | `true` if a job was signalled. With `scanId`, only that job is stopped. Also cancels running `scan_ports` calls. |
| `export_devices` | `{ devices: Device[], format: "csv" \| "json" \| "xlsx" }` | The written path, or `null` if the user cancelled. |
| `load_overrides` | none | `Record<string, DeviceOverride>` (may be empty). Rejects when the store is unreadable or corrupt (the file is left untouched). |
| `save_override` | `{ key: string, hostname: string \| null, comments: string \| null }` | `null`. Rejects on a write error or a corrupt store (which is moved aside first). |
| `scan_ports` | `{ ip: string, ports: number[] }` | `number[]` of open ports (sorted). Rejects on a bad IP, > 4096 distinct ports, when 4 port scans are already running, when stopped by `stop_scan`, or when some ports could not be checked (out of file descriptors). |
| `query_snmp` | `{ ip: string, snmp: SnmpConfig \| null }` | `SnmpDeviceInfo`. Rejects on a bad IP, invalid config or unreachable device. |
| `discover_services` | `{ ip: string, timeoutMs?: number }` | `ServiceDiscovery`. Unicast SSDP + WS-Discovery to the host plus SIP OPTIONS (`timeoutMs` default 2500, clamped 500-5000). Rejects on a bad IP, when 4 probes are already running, or when stopped by `stop_scan`. |

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
  poe: PoeInfo | null;        // PoE on this port (POWER-ETHERNET-MIB), see below
  voiceVlan: number | null;   // voice VLAN of this port (Cisco vmVoiceVlanId)
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
  poeBudget: PoeBudget | null;  // switch-wide PoE budget, when the agent has POWER-ETHERNET-MIB
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

### Service discovery, PoE / voice VLAN and DHCP data shapes

All additive: every new field is optional on input (missing = `null` / `false` / `[]`) and
always present on output. Every string learned from the network is sanitized (control /
escape / bidi characters stripped, 256 characters max).

```ts
// New ScanConfig fields.
interface ScanConfig {
  // ...existing fields...
  discoverServices: boolean;  // default true: SSDP/UPnP + WS-Discovery/ONVIF + SIP OPTIONS
  sipAll: boolean;            // default false: SIP OPTIONS to every discovered IPv4 host
  dhcpFingerprint: boolean;   // default false: passive DHCP fingerprinting (needs root / BPF)
}

// New Device fields (all null when unknown).
interface Device {
  // ...existing fields...
  voiceVlan: number | null;          // CDP/LLDP-MED voice VLAN (phones) or the SNMP port's
  deviceKind: DeviceKind | null;     // finer category than `role` (role is unchanged)
  ssdp: SsdpInfo | null;
  onvif: OnvifInfo | null;
  sip: SipInfo | null;
  poe: PoeInfo | null;               // PoE this endpoint draws (its switch port / own advert)
  dhcpFingerprint: DhcpFingerprint | null;
}

// Additive: new strings may appear; render unknown ones as-is.
type DeviceKind =
  | "voip_phone" | "pbx"                      // SIP
  | "camera"                                  // ONVIF NetworkVideoTransmitter / SSDP
  | "computer"                                // Windows host answering WS-Discovery
  | "media_server" | "igd_router" | "printer" | "scanner" | "tv" | "nas"; // SSDP/UPnP

// Device.sources may now also contain "ssdp" | "wsd" | "sip" | "dhcp".

interface SsdpInfo {
  location: string | null;        // advertised LOCATION URL (only fetched if host == device IP)
  server: string | null;          // SSDP SERVER header
  searchTarget: string | null;    // ST / NT
  usn: string | null;
  friendlyName: string | null;
  manufacturer: string | null;
  modelName: string | null;
  modelNumber: string | null;
  modelDescription: string | null;
  serialNumber: string | null;
  deviceType: string | null;      // e.g. "urn:schemas-upnp-org:device:MediaServer:1"
  udn: string | null;             // "uuid:..."
  presentationUrl: string | null; // device web UI (from the device; open via opener rules)
  services: string[];             // UPnP serviceType URNs (max 64)
}

interface OnvifInfo {
  xaddrs: string[];               // WS-Discovery transport addresses (max 64)
  types: string | null;           // e.g. "dn:NetworkVideoTransmitter tds:Device"
  scopes: string[];               // onvif://www.onvif.org/... scope URIs (max 64)
  name: string | null;            // ONVIF scope name, or a Windows computer name
  location: string | null;        // ONVIF scope location
  manufacturer: string | null;
  model: string | null;
  firmwareVersion: string | null;
  serialNumber: string | null;
  hardwareId: string | null;
  isCamera: boolean;              // ONVIF NetworkVideoTransmitter
  isWindows: boolean;             // WSD pub:Computer
  rtspUrl: string | null;         // ONLY a URL the camera itself returned (unauthenticated)
  rtspHints: string[];            // vendor templates when rtspUrl is null; each ends with
                                  // "(guess, no credentials tried)"; never verified
}

interface SipInfo {
  status: string | null;          // final status line, e.g. "200 OK" / "405 Method Not Allowed"
  server: string | null;
  userAgent: string | null;
  allow: string | null;
  supported: string | null;
  transport: "udp" | "tcp" | null;
  vendor: string | null;          // e.g. "Yealink", "Asterisk", "3CX"
  model: string | null;           // e.g. "SIP-T54W"
  firmware: string | null;        // e.g. "96.86.0.5"
  kind: "voip_phone" | "pbx" | null;
}

interface PoeInfo {
  watts: number | null;           // power drawn / requested, W
  maxWatts: number | null;        // allocated / available budget, W
  class: number | null;           // IEEE class 0-8
  status: "delivering" | "searching" | "disabled" | "fault" | "test" | null;
  source: "pse" | "local" | "pse+local" | null;   // LLDP-MED / 802.3at power source
  priority: "critical" | "high" | "low" | null;
  switchName: string | null;      // set for SNMP-derived port data
  port: string | null;            // e.g. "Gi1/0/5"
}

interface PoeBudget {
  nominalWatts: number | null;    // PSE nominal power (sum over PSE groups)
  consumedWatts: number | null;   // measured consumption
  usageThresholdPct: number | null;
  portsDelivering: number;
}

interface DhcpFingerprint {       // best-effort heuristic, never authoritative
  os: string | null;              // e.g. "Windows", "Android 14", "macOS", "Cisco IP phone"
  confidence: "high" | "medium" | "low" | null;
  vendorClass: string | null;     // option 60
  hostname: string | null;        // option 12 (client-chosen; not a DNS name)
  paramList: number[];            // option 55, in the client's order
}

// New CdpLldpNeighbor fields (from CDP / LLDP power TLVs).
interface CdpLldpNeighbor {
  // ...existing fields...
  poeWatts: number | null;        // headline: drawn power, else the advertised budget
  poeInfo: PoeInfo | null;        // switchName / port are null here
}

// Returned by discover_services.
interface ServiceDiscovery {
  ip: string | null;
  deviceKind: DeviceKind | null;
  ssdp: SsdpInfo | null;
  onvif: OnvifInfo | null;
  sip: SipInfo | null;
}
```

Event behaviour of these features:

- Service discovery runs during the enrichment phase (`progress.phase === "enriching"`), after
  names / ports and before SNMP. It streams `device` snapshots carrying `ssdp` / `onvif` /
  `sip` / `deviceKind`, then one `log` line (`services: N SSDP/UPnP, ...`).
- With `dhcpFingerprint`, fingerprints arrive during discovery as `device` snapshots with
  `dhcpFingerprint` (and source `"dhcp"`). A client that already has an address keys its own
  row (which may be a host no probe found); one that has none is merged into the row with
  the same MAC. In `start_vlan_discovery`, address-less clients become `log` lines instead.
  A capture that cannot start (no root / BPF) is reported as a `warn` log, never a failure.
- `poe` / `voiceVlan` on an endpoint come from its chosen `switchPort` mapping when the switch
  reported them (re-evaluated whenever the switch-port choice changes), else from the
  endpoint's own CDP/LLDP advert. A switch's own adverts describe the scanning host's port
  and are not copied onto the switch row.

`discover_services` is a single-device drawer helper like `scan_ports`: it runs independently
of any scan job, emits no `scan-event`s, holds one of 4 slots, and is cancelled by
`stop_scan`. It uses unicast SSDP / WS-Discovery straight to the host, so it also works for
hosts on routed subnets.

Exports (CSV / XLSX / terminal table) add the columns **Device Kind**, **Model/Firmware**
(SIP, then ONVIF, then UPnP), **PoE (W)**, **Voice VLAN** and **OS (DHCP)** (as
`OS (confidence)`), between *TCP Ports* and *Comments*. In the terminal table they are
hidden when empty for every device; in XLSX, PoE and Voice VLAN are numeric cells.
