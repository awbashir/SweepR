// TypeScript mirror of `src-tauri/src/models.rs` (serde camelCase / snake_case enums).
// `IpAddr` serializes as a string, `Option<T>` as `T | null`, `u64` as `number`.

export type DeviceRole = "switch" | "firewall" | "access_point" | "router" | "host";

export const DEVICE_ROLES: readonly DeviceRole[] = [
  "switch",
  "firewall",
  "access_point",
  "router",
  "host",
];

export const ROLE_LABEL: Record<DeviceRole, string> = {
  switch: "Switch",
  firewall: "Firewall",
  access_point: "Access Point",
  router: "Router",
  host: "Host",
};

export type DiscoverySource =
  | "arp"
  | "ndp"
  | "icmp"
  | "tcp"
  | "neighbor_cache"
  | "cdp"
  | "lldp"
  | "snmp"
  | "dns"
  | "mdns"
  | "netbios";

export type VlanSource =
  | "os_interface"
  | "tagged8021q"
  | "cdp"
  | "lldp"
  | "vtp"
  | "snmp"
  | "user_configured";

export interface VlanInfo {
  id: number;
  name: string | null;
  sources: VlanSource[];
  interface: string | null;
  switchName: string | null;
  framesSeen: number;
  firstSeenMs: number;
  lastSeenMs: number;
}

/** Adjacently tagged: `#[serde(tag = "mode", content = "ids", rename_all = "snake_case")]`. */
export type VlanSelection =
  | { mode: "untagged" }
  | { mode: "list"; ids: number[] }
  | { mode: "auto_detect" }
  | { mode: "untagged_and_list"; ids: number[] };

export type NeighborProtocol = "cdp" | "lldp";

export type Capability =
  | "router"
  | "switch"
  | "wlan_access_point"
  | "firewall"
  | "repeater"
  | "telephone"
  | "docsis_cable"
  | "host"
  | "other";

export interface CdpLldpNeighbor {
  protocol: NeighborProtocol;
  localInterface: string;
  sourceMac: string;
  deviceId: string;
  systemName: string | null;
  systemDescription: string | null;
  portId: string | null;
  portDescription: string | null;
  platform: string | null;
  softwareVersion: string | null;
  managementAddrs: string[];
  nativeVlan: number | null;
  voiceVlan: number | null;
  capabilities: Capability[];
  vtpDomain: string | null;
  ttlSecs: number;
  lastSeenMs: number;
}

export interface SwitchPortMapping {
  switchName: string;
  switchIp: string | null;
  portName: string;
  portIndex: number | null;
  vlanId: number | null;
  mac: string;
}

export interface Device {
  ip: string;
  extraIps: string[];
  mac: string | null;
  vlanId: number | null;
  role: DeviceRole;
  hostname: string | null;
  dnsName: string | null;
  mdnsName: string | null;
  smbName: string | null;
  smbDomain: string | null;
  vendor: string | null;
  switchPort: SwitchPortMapping | null;
  openPorts: number[];
  comments: string | null;
  interface: string | null;
  rttMs: number | null;
  sources: DiscoverySource[];
  neighbor: CdpLldpNeighbor | null;
  firstSeenMs: number;
  lastSeenMs: number;
  /** Never filled by the engine; the GUI copies its live latency here for exports. */
  latency: LatencyStats | null;
  /** HTML `<title>` of the device's web interface. */
  webTitle: string | null;
  /** HTTP `Server` header of the device's web interface. */
  webServer: string | null;
  /** TLS certificate of the device's HTTPS interface. */
  tlsCert: TlsCertInfo | null;
  /** Recognized product, e.g. "Proxmox VE", "Dell iDRAC", "Fortinet FortiGate". */
  webIdentity: string | null;
  /** Problems worth flagging (expired / expiring / self-signed certificates, ...). */
  warnings: string[];
}

export type InterfaceKind =
  | "ethernet"
  | "wifi"
  | "vlan"
  | "bridge"
  | "vpn"
  | "virtual"
  | "loopback"
  | "unknown";

export interface IfAddr {
  ip: string;
  prefix: number;
}

export interface InterfaceInfo {
  name: string;
  index: number;
  description: string | null;
  mac: string | null;
  addrs: IfAddr[];
  isUp: boolean;
  kind: InterfaceKind;
  vlanId: number | null;
  parent: string | null;
  isDefault: boolean;
}

export type SnmpVersion = "v1" | "v2c" | "v3";
export type SnmpAuthProtocol = "md5" | "sha1" | "sha224" | "sha256" | "sha384" | "sha512";
export type SnmpPrivProtocol = "des" | "aes128" | "aes192" | "aes256";

export interface SnmpV3Credentials {
  username: string;
  authProtocol: SnmpAuthProtocol;
  authPassword: string | null;
  privProtocol: SnmpPrivProtocol;
  privPassword: string | null;
}

export interface SnmpConfig {
  version: SnmpVersion;
  community: string;
  v3: SnmpV3Credentials | null;
  port: number;
  timeoutMs: number;
  retries: number;
}

export interface ScanConfig {
  interface: string | null;
  range: string | null;
  vlans: VlanSelection;
  discoverVlans: boolean;
  cdpLldp: boolean;
  snmp: SnmpConfig | null;
  /** Poll every discovered host over SNMP, not only likely infrastructure (default false). */
  snmpAll: boolean;
  ipv6: boolean;
  ports: number[];
  resolveNames: boolean;
  timeoutMs: number;
  retries: number;
  ratePps: number;
  concurrency: number;
  listenSecs: number;
  /** Read web titles / TLS certificates of devices with web ports open (default true). */
  webIdentity: boolean;
}

export type ScanPhase = "preparing" | "discovering" | "enriching" | "listening" | "done";

export interface ScanProgress {
  phase: ScanPhase;
  probesSent: number;
  probesTotal: number;
  devicesFound: number;
}

export type LogLevel = "info" | "warn" | "error";

export interface LogMessage {
  level: LogLevel;
  message: string;
}

export interface ScanSummary {
  devices: number;
  vlans: number;
  neighbors: number;
  elapsedMs: number;
  cancelled: boolean;
}

/** `#[serde(tag = "type", content = "data", rename_all = "snake_case")]` */
export type ScanEvent =
  | { type: "device"; data: Device }
  | { type: "vlan"; data: VlanInfo }
  | { type: "neighbor"; data: CdpLldpNeighbor }
  | { type: "port_mapping"; data: SwitchPortMapping }
  | { type: "progress"; data: ScanProgress }
  | { type: "log"; data: LogMessage }
  | { type: "finished"; data: ScanSummary };

/** Payload of the Tauri `scan-event` event. */
export interface ScanEventPayload {
  scanId: number;
  event: ScanEvent;
}

export type ExportFormat = "csv" | "json" | "xlsx";

export interface DeviceOverride {
  hostname?: string | null;
  comments?: string | null;
}

/** `load_overrides()` result keyed by device key (`ip` or `ip@vlan`). */
export type Overrides = Record<string, DeviceOverride>;

/** MAC addresses learned on one switch port (`PortMacCount` in models.rs). */
export interface PortMacCount {
  portName: string;
  portIndex: number | null;
  macCount: number;
}

/** `query_snmp()` result (`SnmpDeviceInfo` in models.rs). */
export interface SnmpDeviceInfo {
  sysName: string | null;
  sysDescr: string | null;
  sysUptimeTicks: number | null;
  sysObjectId: string | null;
  role: DeviceRole;
  vlans: VlanInfo[];
  portMappings: SwitchPortMapping[];
  portMacCounts: PortMacCount[];
  /** Some table walks failed or were cut short; the data above is what was collected. */
  partial: boolean;
  /** Why the result is partial (one line per failed / truncated walk). */
  warnings: string[];
}

/** Longest hostname / comment the backend keeps (`MAX_OVERRIDE_LEN`). */
export const MAX_OVERRIDE_LEN = 1024;

// --- Network utilities (Roadmap 1a): Wake-on-LAN, latency, trace, web identity, iPerf3 ---------

export interface WakeResult {
  mac: string;
  /** "192.168.1.255:9", "255.255.255.255:9" */
  targets: string[];
  packetsSent: number;
  interface: string | null;
  sourceIp: string | null;
}

/** Optional `wake_device` arguments (`mac` is passed separately). */
export interface WakeOptions {
  interface?: string | null;
  broadcast?: string | null;
  port?: number | null;
  repeat?: number | null;
  password?: string | null;
}

export type ProbeMethod = "icmp" | "tcp";

export interface LatencyStats {
  lastMs: number | null;
  avgMs: number | null;
  minMs: number | null;
  maxMs: number | null;
  /** Mean |difference| between consecutive replies. */
  jitterMs: number | null;
  /** 0-100 over the window. */
  lossPct: number;
  sent: number;
  received: number;
  method: ProbeMethod;
  /** Unix ms of the newest sample. */
  updatedMs: number;
}

export interface LatencySample {
  ip: string;
  /** Newest probe, `null` = lost. */
  rttMs: number | null;
  /** Unix ms when the newest probe was sent. */
  ts: number;
  method: ProbeMethod;
  lossPct: number;
  avgMs: number | null;
  minMs: number | null;
  maxMs: number | null;
  jitterMs: number | null;
  sent: number;
  received: number;
  /** Up to 120 samples, oldest first; `null` for lost probes. */
  history: (number | null)[];
}

/** Payload of the `latency-update` event. */
export interface LatencyUpdate {
  monitorId: number;
  /** Sorted by IP; only hosts with a new sample since the previous batch. */
  samples: LatencySample[];
}

export type TraceMethod = "raw" | "system";

export interface TraceHop {
  ttl: number;
  /** Newest responder; `null` while the hop never answered. */
  ip: string | null;
  hostname: string | null;
  /** Other responders for this TTL (load balancing), at most 4. */
  otherIps: string[];
  sent: number;
  received: number;
  lossPct: number;
  lastMs: number | null;
  avgMs: number | null;
  bestMs: number | null;
  worstMs: number | null;
}

/** Payload of the `trace-update` event (a full snapshot). */
export interface TraceUpdate {
  traceId: number;
  target: string;
  method: TraceMethod;
  round: number;
  rounds: number;
  hops: TraceHop[];
  reached: boolean;
  done: boolean;
  /** Only on the final update. */
  error: string | null;
}

export interface TlsCertInfo {
  port: number;
  subjectCn: string | null;
  subject: string | null;
  /** First 8 DNS names / IPs. */
  sans: string[];
  sanCount: number;
  issuerCn: string | null;
  issuer: string | null;
  /** ISO 8601 UTC. */
  notBefore: string | null;
  notAfter: string | null;
  notBeforeMs: number | null;
  notAfterMs: number | null;
  /** Negative once expired. */
  daysRemaining: number | null;
  selfSigned: boolean;
  expired: boolean;
  keyType: string | null;
  keyBits: number | null;
  signatureAlgorithm: string | null;
  /** "AB:CD:..." */
  sha256: string | null;
}

export type WebScheme = "http" | "https";

export interface WebService {
  port: number;
  scheme: WebScheme;
  /** Final URL after redirects. */
  url: string;
  status: number | null;
  title: string | null;
  server: string | null;
  redirects: number;
  /** A redirect that was not followed (other host / limit). */
  redirectTo: string | null;
  tlsCert: TlsCertInfo | null;
  error: string | null;
}

export interface WebIdentity {
  ip: string;
  /** Ports that accepted a connection, HTTPS first. */
  services: WebService[];
  title: string | null;
  server: string | null;
  tlsCert: TlsCertInfo | null;
  identity: string | null;
  roleHint: DeviceRole | null;
  warnings: string[];
}

/** Every field optional on the wire; the backend fills defaults. */
export interface IperfOptions {
  port: number;
  /** 1-60 */
  durationSecs: number;
  /** -R: server sends. */
  reverse: boolean;
  /** 1-16 (-P) */
  streams: number;
  udp: boolean;
  /** "100M", "1G", "500K", "0" (-b); `null` = iperf3 default. */
  bitrate: string | null;
}

export interface IperfAvailability {
  available: boolean;
  path: string | null;
  version: string | null;
  /** Live intervals (iperf3 3.17+). */
  streaming: boolean;
  installHint: string | null;
}

export interface IperfInterval {
  /** Seconds since the test started. */
  start: number;
  end: number;
  bytes: number;
  bitsPerSecond: number;
  retransmits: number | null;
  jitterMs: number | null;
  lostPackets: number | null;
  packets: number | null;
  lostPercent: number | null;
  omitted: boolean;
}

export interface IperfSummary {
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
  remoteHost: string | null;
  version: string | null;
}

/** Payload of the `iperf-update` event. */
export interface IperfUpdate {
  runId: number;
  interval: IperfInterval | null;
  summary: IperfSummary | null;
  done: boolean;
  error: string | null;
}
