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

- **Audit report**: `sweepr report` (or `sweepr scan --report`) turns scan data into a
  branded audit: a single-file interactive HTML page, a PDF executive summary, or JSON.
  See [Audit report](#audit-report).
- **Network utilities**:
  - **Wake-on-LAN** (`sweepr wake`, GUI `wake_device`): sends the magic packet (6 x `0xFF`
    + the MAC 16 times, optional 6-byte SecureOn password) over UDP (port 9 by default) to
    the interface's subnet broadcast and `255.255.255.255`, from a socket bound to that
    interface with `SO_BROADCAST`. `--broadcast` sends to one address instead (e.g. the
    directed broadcast of a remote subnet).
  - **Latency monitor** (`sweepr ping`, GUI `start_latency_monitor`): pings hosts every
    0.5-10 s with unprivileged ICMP / ICMPv6 and keeps the last 120 samples per host (last /
    avg / min / max / jitter / loss, plus a sparkline history). Hosts that never answer ICMP
    fall back to TCP connect round trips (SYN → SYN-ACK or RST) on a known open port or on
    443 / 80 / 22 / 445. At most 2,000 hosts are monitored at once.
  - **MTR / traceroute** (`sweepr trace`, GUI `start_trace`): per-hop loss and last / avg /
    best / worst latency over several rounds, with reverse-DNS hop names. As root (or with
    `CAP_NET_RAW`) it sends raw ICMP echo probes with increasing TTL; otherwise it runs the
    system tool once per round (`traceroute -n -q 1 -w 1 -m <max>`; macOS ships a setuid
    `/usr/sbin/traceroute` / `traceroute6`, Linux needs `traceroute` or `tracepath`). Only IP
    literals are accepted and arguments are never passed through a shell.
  - **Web identity** (`sweepr web`, GUI `grab_web_identity`, and automatically during scans
    for devices with 80 / 443 / 8443 / 8080 / 8000 / 10443 open; `--no-web` disables it):
    the HTML `<title>`, `Server` header and TLS certificate (subject / SANs / issuer /
    validity / key / SHA-256) of each web port. Requests are a plain `GET /` with short
    timeouts, a 64 KiB body cap and at most two same-host redirects; no credentials are ever
    sent, and certificates are read without being trusted. Known appliances (Proxmox VE,
    Synology DSM, QNAP, TrueNAS, iDRAC, iLO, ESXi / vCenter, UniFi, pfSense / OPNsense,
    FortiGate, MikroTik, Pi-hole, Home Assistant, ...) are named in `webIdentity`; firewall /
    router appliances also suggest a role, which is only applied to devices still classified
    as plain hosts. Expired, soon-to-expire (< 30 days), not-yet-valid and self-signed
    certificates are listed in `warnings`.
  - **iPerf3** (`sweepr iperf`, GUI `start_iperf`): runs the installed `iperf3` client
    (looked up on `PATH`, `/opt/homebrew/bin`, `/usr/local/bin`) with validated arguments
    (IP literal, port, 1-60 s, 1-16 streams, TCP or UDP with a numeric bitrate) and reports
    per-second intervals and the summary (throughput, retransmits, UDP jitter / loss, CPU).
    iperf3 3.17+ streams intervals live (`--json-stream`); older versions report them at
    the end. Without iperf3 it says how to install it (`brew install iperf3`).

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

# Scan and write an audit report right away (.html, .pdf or .json by extension)
sudo sweepr scan -i en0 --vlan untagged,10,20 --cdp-lldp --snmp-community public --report audit.html

# Build reports from saved scan data
sweepr report --input audit.json -o audit.pdf --title "Q3 network audit" --org "Acme Corp" --logo acme.png
sweepr report --input devices.json --format html -o audit.html

# Wake-on-LAN (any MAC notation); --broadcast for a remote subnet, --port 7 for echo
sweepr wake aa:bb:cc:dd:ee:ff -i en0
sweepr wake aabb.ccdd.eeff --broadcast 10.20.0.255 --port 9 --port 7 --repeat 5

# Continuous ping with loss / jitter statistics (Ctrl-C to stop) or a fixed count
sweepr ping 10.0.0.1 10.0.0.2
sweepr ping 10.0.0.1 --count 10 --interval-ms 500 -o json

# MTR-style traceroute (no sudo needed: uses the system traceroute when unprivileged)
sweepr trace 8.8.8.8 --max-hops 30 --rounds 10
sweepr trace 2001:4860:4860::8888 -o json

# Web page titles, Server headers and TLS certificates
sweepr web 10.0.0.10
sweepr web 10.0.0.10 -p 443,8006 -o json

# Throughput against an iperf3 server (iperf3 must be installed)
sweepr iperf 10.0.0.20 -t 10 -P 4
sweepr iperf 10.0.0.20 -R --udp -b 100M
```

`ping` exits with status 1 when a host never answered (and 130 after Ctrl-C, like the other
commands). The SecureOn password for `wake --password` can also come from
`SWEEPR_WOL_PASSWORD`.

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
| `--no-web` | Do not read web titles / TLS certificates of devices with web ports open. |
| `-o, --output` | `table` (default, live), `json`, `csv` or `xlsx`. |
| `-f, --file` | Output file. Required for `xlsx`. |
| `--timeout-ms`, `--rate-pps`, `--retries`, `--listen-secs`, `--concurrency` | Timing and pacing (validated: timeout <= 600000 ms, rate 1-1000000 pps, retries <= 10, listen <= 86400 s, concurrency 1-65535). |

Press Ctrl-C once to stop and still get the results found so far. Press it twice to abort.
Piping into a reader that exits early (`sweepr scan | head -1`) stops the scan quietly with
exit status 0. If the OS transmit queue fills up (ENOBUFS), SweepR backs off and slows down
instead of failing, and reports how many probe frames were dropped.
Set `RUST_LOG=debug` for diagnostic logging.

## Audit report

`sweepr report --input <scan.json> [--format html|pdf|json] -o <path> [--title ...] [--org ...]
[--logo logo.png]` builds a report from saved data; `sweepr scan ... --report <path>` builds one
from the scan that just ran (format from the extension). The input may be the device array
written by `sweepr scan -o json` (devices only), or the full envelope written by
`sweepr scan --report x.json` / `sweepr report --format json`, which also carries VLANs,
CDP/LLDP neighbors, MAC-to-port mappings, SNMP poll results and scan metadata. Unknown fields
are kept, so data added by newer scanner features (TLS certificates, latency, voice VLAN,
PoE, ...) is picked up when present; malformed records are skipped and counted.

- **HTML**: one self-contained file (no network requests, no external fonts or scripts, a
  strict Content-Security-Policy pinning the embedded CSS/JS by hash). Executive summary with
  risk grade, hosts per VLAN, device roles, findings by severity and category, switch port
  utilization per switch (active vs. total ports, busiest ports, uplinks / trunks, with a
  "not available (no SNMP)" state), top vendors, open services, a sortable / filterable
  findings table with expandable evidence and remediation, a searchable device inventory with
  column toggles, CDP/LLDP neighbors and device attachment, rule coverage and a methodology
  appendix. Light/dark follows the system (with a toggle); browser Print -> PDF uses a print
  stylesheet. All scan-derived text is HTML-escaped; the JSON copy embedded for "Download
  JSON" is escaped so it cannot close its `<script type="application/json">` element.
- **PDF**: executive summary (cover with grade and summary cards, VLAN / role / severity /
  vendor / service charts, top 15 findings with remediation, switch port utilization,
  rule coverage and appendix). Written in pure Rust with `pdf-writer` using the standard
  Helvetica fonts (no font file embedded; characters outside Windows-1252 print as `?`).
- **JSON**: score, findings, rule coverage, statistics and the normalized input (it can be
  fed back into `sweepr report`). SNMP communities are never written: only whether the
  default `public` / `private` or a custom community was used.

Rules (stable IDs, CWE / CIS Controls reference text, thresholds in the appendix): Telnet,
FTP, TFTP, r-services, SMB / NetBIOS on infrastructure and broad SMB exposure, RDP, VNC,
HTTP-only management on infrastructure, SSH + Telnet, default SNMP community, SNMPv1/v2c,
incomplete SNMP walks, expired / expiring (< 30 days) / self-signed certificates and weak keys
or signatures, unidentified devices, locally administered MACs, duplicate IPs, one MAC on
several IPs, multiple DHCP servers, multiple IPv6 routers (rogue RA), CDP/LLDP on user-facing
ports, native VLAN 1, native VLAN mismatch, phones outside a voice VLAN, many hosts in VLAN 1,
unused VLANs, and several MACs on an access port. Rules whose data was not collected are
listed as "not evaluated" instead of passing.

Risk score: each finding contributes `weight x min(1 + log2(affected), 4)` points (critical
15, high 8, medium 4, low 1.5, info 0); `score = round(100 * e^(-points/80))`; grade A >= 90,
B >= 80, C >= 65, D >= 50, else F; any critical finding caps the grade at D and any high
finding at B.

`cargo run --example sample_audit_input > sample.json` writes a synthetic 300-device network
for trying the report.

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
  src/export.rs    CSV / JSON / XLSX export and terminal tables
  src/audit.rs     lenient report input model, audit rules, risk score
  src/report.rs    report statistics, JSON output, scan collection, file writing
  src/report_html.rs  self-contained interactive HTML report (templates/report.css, .js)
  src/report_pdf.rs   PDF executive summary (pdf-writer, Helvetica metrics)
  src/wol.rs       Wake-on-LAN magic packets
  src/latency.rs   latency monitor (ICMP / TCP fallback, rolling stats, sparklines)
  src/trace.rs     MTR-style traceroute (raw ICMP as root, system traceroute otherwise)
  src/webid.rs     HTTP title / Server header / TLS certificate grabber, appliance identification
  src/iperf.rs     iperf3 client runner and JSON parsers
  src/jobs.rs      registry of running utility jobs (monitors, traces, iperf3 runs)
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
| `generate_report` | `GenerateReportArgs` (below) | The written path, or `null` if the user cancelled the save dialog. Rejects on an unknown format, a wrong extension, or a symlink / non-regular target. |
| `reveal_report` | none | `true` after revealing the report last written by `generate_report` in Finder / the file manager; `false` if none was written yet. |
| `wake_device` | `{ mac: string, interface?: string \| null, broadcast?: string \| null, port?: number \| null, repeat?: number \| null, password?: string \| null }` | `WakeResult`. Rejects a malformed / broadcast / multicast MAC, a non-IPv4 or multicast `broadcast`, port 0, a malformed SecureOn password, or when nothing could be sent. |
| `start_latency_monitor` | `{ ips: string[], intervalMs?: number \| null, tcpPorts?: Record<string, number[]> \| null }` | `monitorId` (number). Rejects bad IPs, an empty list, `intervalMs` outside 500-10000 (default 1000), more than 2,000 monitored hosts in total, or when 16 monitors are running. |
| `stop_latency_monitor` | `{ monitorId: number }` | `true` if it was running (one final batch may follow). |
| `start_trace` | `{ ip: string, maxHops?: number \| null, rounds?: number \| null }` | `traceId` (number). `maxHops` 1-64 (default 30), `rounds` 1-100 (default 5). Rejects host names, unspecified / multicast / broadcast addresses, or when 8 traces are running. |
| `stop_trace` | `{ traceId: number }` | `true` if it was running (its final `done` update follows). |
| `grab_web_identity` | `{ ip: string, ports?: number[] \| null }` | `WebIdentity`. `ports` defaults to `[80, 443, 8443, 8080, 8000, 10443]` (at most 16). Rejects a bad IP or when 4 lookups are running. |
| `iperf_available` | none | `IperfAvailability` |
| `start_iperf` | `{ ip: string, options?: IperfOptions \| null }` | `runId` (number). Rejects right away when iperf3 is missing (message includes the install hint), on invalid options, or when 2 runs are active. |
| `stop_iperf` | `{ runId: number }` | `true` if it was running (the iperf3 process is killed; a final `done` update with an error follows). |

Tauri maps Rust snake_case command arguments to camelCase in JS automatically (so
`scan_id` is `scanId`, `timeout_secs` is `timeoutSecs`).

`export_devices` opens the native save dialog from the backend. The webview never passes a
file path. The chosen file must have the format's extension (it is added when missing), and
symbolic links and non-regular files are refused.

`generate_report` builds the audit in the backend and opens the native save dialog there,
like `export_devices`: the webview never passes a path, the extension must match the format
(it is added when missing, refusing to replace an existing file the dialog did not confirm),
and symbolic links and non-regular files are refused. `reveal_report` takes no arguments, so
it can only reveal the file the user just saved (the webview still has no opener permission
for files).

```ts
interface GenerateReportArgs {
  devices: Device[];                 // as shown in the table (with overrides applied); extra
                                     // fields (tlsCert, latency, voiceVlan, poeWatts, ...) are used when present
  vlans?: VlanInfo[];
  neighbors?: CdpLldpNeighbor[];
  portMappings?: SwitchPortMapping[]; // the raw port_mapping events
  snmpInfos?: (SnmpDeviceInfo & { ip: string })[]; // query_snmp results, keyed by agent IP
  meta?: ReportMeta;
  format: "html" | "pdf" | "json";
  title?: string;                    // default "SweepR Network Audit Report"
  org?: string;                      // customer / organization shown on the cover
}

interface ReportMeta {               // every field optional
  toolVersion?: string;
  interface?: string;
  ranges?: string[];
  vlans?: string;                    // e.g. "untagged,10,20"
  portSpec?: string;                 // scanned TCP ports, e.g. "22,23,80,443,1000-2000"
  startedMs?: number;
  finishedMs?: number;
  cancelled?: boolean;
  ipv6?: boolean;
  cdpLldp?: boolean;
  discoverVlans?: boolean;
  resolveNames?: boolean;
  snmpAll?: boolean;
  // `community` is only classified ("public" | "private" | "custom") and never written out.
  snmp?: { version?: "v1" | "v2c" | "v3"; community?: string };
  gateway?: string;
  dhcpServers?: string[];            // DHCP servers observed (rogue DHCP rule)
  ipv6Routers?: string[];            // IPv6 RA sources observed (rogue RA rule)
  scannerHost?: string;
}
```

Without `portSpec` the service rules still run on the open ports present but cannot tell
"closed" from "not scanned"; without `snmp` the SNMP rules are reported as not evaluated.

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

### Network utility commands and events

Utility jobs run independently of scans (a scan never stops them and they never emit
`scan-event`s). Each kind numbers its jobs from 1. Every running monitor, trace and iperf3
run is cancelled when the app exits (child processes are killed).

- `latency-update` (`LatencyUpdate`): at most one batch per 250 ms per monitor (≤ 4 events
  per second), carrying only the hosts that got a new sample since the previous batch. The
  statistics cover the host's window (its last 120 samples); `history` is that window,
  oldest first, `null` for lost probes. A monitor stops when `stop_latency_monitor` is called
  (one final batch may follow) or when the app exits. The engine never fills
  `device.latency`; the GUI may copy a sample into it (`lastMs = rttMs`, `updatedMs = ts`,
  the other fields by name) so that exports show the Latency / Loss % columns.
- `trace-update` (`TraceUpdate`): a full snapshot at most every 250 ms while probes arrive,
  one at the end of each round, and always a final one with `done: true` (also when the trace
  is stopped or fails; on failure `error` says why, e.g. no traceroute tool installed). `hops` is
  TTL 1..N, where N is the destination's TTL once it answered (`reached: true`) or the
  highest TTL probed so far. Hop names arrive asynchronously (a later snapshot fills
  `hostname`). `method` is `"system"` for unprivileged runs, `"raw"` as root.
- `iperf-update` (`IperfUpdate`): one event per interval (`interval` set), then a final
  `done: true` event with `summary` or `error`. With iperf3 older than 3.17 all intervals
  arrive just before the final event (`IperfAvailability.streaming` is `false`).
- `grab_web_identity` returns a `WebIdentity` directly. During scans the same data is
  merged into `device` events (`webTitle`, `webServer`, `tlsCert`, `webIdentity`,
  `warnings`, and possibly `role`) for devices with 80 / 443 / 8443 / 8080 / 8000 / 10443
  open, unless `ScanConfig.webIdentity` is `false` (it is ignored when `ports` is empty).

Tabular exports (CSV / XLSX / CLI table) gained the columns `Latency (ms)` (average),
`Loss %`, `Web Title`, `Cert CN` and `Cert Expires` (date, `(expired)` when past), placed
before `Comments`; the CLI table hides them when empty for every device.

```ts
// New Device fields (always serialized; optional when sending devices back to
// export_devices: missing fields default to null / []).
interface Device {
  // ...existing fields...
  latency: LatencyStats | null;
  webTitle: string | null;
  webServer: string | null;
  tlsCert: TlsCertInfo | null;
  webIdentity: string | null;  // e.g. "Proxmox VE", "Dell iDRAC", "Fortinet FortiGate"
  warnings: string[];          // e.g. "TLS certificate on port 443 expires in 12 day(s) (2026-11-01)"
}

// ScanConfig.webIdentity (boolean, default true): read web titles / TLS certificates of
// devices with web ports open during enrichment (needs a non-empty `ports`).

type ProbeMethod = "icmp" | "tcp";

interface LatencyStats {
  lastMs: number | null;
  avgMs: number | null;
  minMs: number | null;
  maxMs: number | null;
  jitterMs: number | null;   // mean |difference| between consecutive replies
  lossPct: number;           // 0-100 over the window
  sent: number;              // probes in the window
  received: number;
  method: ProbeMethod;
  updatedMs: number;         // Unix ms of the newest sample
}

interface LatencySample {
  ip: string;
  rttMs: number | null;      // newest probe, null = lost
  ts: number;                // Unix ms when the newest probe was sent
  method: ProbeMethod;       // "tcp" once the host fell back to TCP connect round trips
  lossPct: number;
  avgMs: number | null;
  minMs: number | null;
  maxMs: number | null;
  jitterMs: number | null;
  sent: number;
  received: number;
  history: (number | null)[]; // up to 120 samples, oldest first
}

interface LatencyUpdate {      // event "latency-update"
  monitorId: number;
  samples: LatencySample[];    // sorted by IP
}

type TraceMethod = "raw" | "system";

interface TraceHop {
  ttl: number;
  ip: string | null;         // newest responder; null while the hop never answered
  hostname: string | null;   // reverse DNS
  otherIps: string[];        // other responders for this TTL (load balancing), at most 4
  sent: number;
  received: number;
  lossPct: number;
  lastMs: number | null;
  avgMs: number | null;
  bestMs: number | null;
  worstMs: number | null;
}

interface TraceUpdate {        // event "trace-update"
  traceId: number;
  target: string;
  method: TraceMethod;
  round: number;               // rounds completed
  rounds: number;              // rounds requested
  hops: TraceHop[];
  reached: boolean;
  done: boolean;
  error: string | null;        // only on the final update
}

interface TlsCertInfo {
  port: number;
  subjectCn: string | null;
  subject: string | null;      // "CN=pve.lan, O=PVE Cluster Node"
  sans: string[];              // first 8 DNS names / IPs
  sanCount: number;
  issuerCn: string | null;
  issuer: string | null;
  notBefore: string | null;    // ISO 8601 UTC, "2026-01-31T12:00:00Z"
  notAfter: string | null;
  notBeforeMs: number | null;  // Unix ms
  notAfterMs: number | null;
  daysRemaining: number | null; // negative once expired
  selfSigned: boolean;
  expired: boolean;
  keyType: string | null;      // "RSA", "EC P-256", "Ed25519", ...
  keyBits: number | null;
  signatureAlgorithm: string | null; // "sha256WithRSAEncryption", "ecdsa-with-SHA256", ...
  sha256: string | null;       // "AB:CD:..."
}

type WebScheme = "http" | "https";

interface WebService {
  port: number;
  scheme: WebScheme;           // TLS is tried first on 443, 8443, 10443, 8006, 5001, ...
  url: string;                 // final URL after redirects
  status: number | null;
  title: string | null;
  server: string | null;
  redirects: number;           // followed (at most 2, same host only)
  redirectTo: string | null;   // redirect that was not followed (other host / limit)
  tlsCert: TlsCertInfo | null;
  error: string | null;
}

interface WebIdentity {
  ip: string;
  services: WebService[];      // ports that accepted a connection, HTTPS first
  title: string | null;
  server: string | null;
  tlsCert: TlsCertInfo | null;
  identity: string | null;
  roleHint: DeviceRole | null; // "firewall" for pfSense / FortiGate / ..., "router" for MikroTik
  warnings: string[];
}

interface IperfOptions {       // every field optional; defaults shown
  port: number;                // 5201
  durationSecs: number;        // 10 (1-60)
  reverse: boolean;            // false (-R: server sends)
  streams: number;             // 1 (1-16, -P)
  udp: boolean;                // false
  bitrate: string | null;      // null; "100M", "1G", "500K", "0" (-b)
}

interface IperfAvailability {
  available: boolean;
  path: string | null;
  version: string | null;      // "3.17.1"
  streaming: boolean;          // live intervals (3.17+)
  installHint: string | null;  // e.g. "iperf3 was not found; install it with `brew install iperf3`"
}

interface IperfInterval {
  start: number;               // seconds since the test started
  end: number;
  bytes: number;
  bitsPerSecond: number;
  retransmits: number | null;  // TCP sender
  jitterMs: number | null;     // UDP
  lostPackets: number | null;
  packets: number | null;
  lostPercent: number | null;
  omitted: boolean;
}

interface IperfSummary {
  protocol: "tcp" | "udp";
  reverse: boolean;
  streams: number;
  durationSecs: number;
  sentBytes: number | null;
  sentBps: number | null;
  receivedBytes: number | null;
  receivedBps: number | null;
  retransmits: number | null;
  jitterMs: number | null;
  lostPackets: number | null;
  packets: number | null;
  lostPercent: number | null;
  cpuLocalPct: number | null;
  cpuRemotePct: number | null;
  remoteHost: string | null;   // "10.0.0.20:5201"
  version: string | null;      // local iperf3, "iperf 3.17.1"
}

interface IperfUpdate {        // event "iperf-update"
  runId: number;
  interval: IperfInterval | null;
  summary: IperfSummary | null; // final event only, on success
  done: boolean;
  error: string | null;         // final event only, on failure / stop
}

interface WakeResult {
  mac: string;                 // "aa:bb:cc:dd:ee:ff"
  targets: string[];           // "192.168.1.255:9", "255.255.255.255:9"
  packetsSent: number;
  interface: string | null;
  sourceIp: string | null;
}
```
