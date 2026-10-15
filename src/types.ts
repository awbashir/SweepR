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
