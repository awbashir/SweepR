// Framework-free scan result store. Events are applied immediately to Maps; React is notified
// at most every `flushMs` with an immutable snapshot, so a burst of thousands of `device`
// events costs one re-render, and 50k+ rows stay responsive.

import type {
  CdpLldpNeighbor,
  Device,
  DeviceOverride,
  DeviceRole,
  LogLevel,
  Overrides,
  ScanEvent,
  ScanEventPayload,
  ScanProgress,
  ScanSummary,
  SnmpDeviceInfo,
  SwitchPortMapping,
  VlanInfo,
} from "../types.ts";
import { deviceKey, ipSortKey } from "./ip.ts";

export interface DeviceRow {
  key: string;
  device: Device;
  /** User override, else the device's own hostname. */
  hostname: string;
  comments: string;
  /** `Cisco-SW01 [Gi1/0/24]` */
  switchPort: string;
  ports: string;
  /** Numeric IP order (IPv4 before IPv6) then VLAN. */
  ipSort: string;
  /** Lower-case text of every visible column, for the search box. */
  search: string;
}

export interface LogEntry {
  id: number;
  ts: number;
  level: LogLevel;
  message: string;
}

export type JobKind = "scan" | "vlan_discovery";

export interface StoreSnapshot {
  rows: DeviceRow[];
  roleCounts: Record<DeviceRole, number>;
  vlans: VlanInfo[];
  neighbors: CdpLldpNeighbor[];
  portMappings: SwitchPortMapping[];
  progress: ScanProgress | null;
  summary: ScanSummary | null;
  logs: LogEntry[];
  running: boolean;
  starting: boolean;
  jobKind: JobKind | null;
  scanId: number | null;
  overrides: Overrides;
  snmp: Record<string, SnmpDeviceInfo>;
}

const MAX_LOGS = 1000;
const MAX_BUFFERED = 200_000;

export function neighborKey(n: CdpLldpNeighbor): string {
  return `${n.protocol}|${n.deviceId}|${n.portId ?? ""}`;
}

export function mappingKey(m: SwitchPortMapping): string {
  return `${m.switchName}|${m.switchIp ?? ""}|${m.portName}|${m.vlanId ?? ""}|${m.mac.toLowerCase()}`;
}

export function switchPortLabel(m: SwitchPortMapping | null): string {
  return m ? `${m.switchName} [${m.portName}]` : "";
}

function emptyRoleCounts(): Record<DeviceRole, number> {
  return { switch: 0, firewall: 0, access_point: 0, router: 0, host: 0 };
}

function overrideText(o: DeviceOverride | undefined, field: keyof DeviceOverride): string | null {
  const v = o?.[field];
  return typeof v === "string" ? v : null;
}

export function buildRow(key: string, device: Device, override: DeviceOverride | undefined): DeviceRow {
  const hostname = overrideText(override, "hostname") ?? device.hostname ?? "";
  const comments = overrideText(override, "comments") ?? device.comments ?? "";
  const switchPort = switchPortLabel(device.switchPort);
  const ports = device.openPorts.join(", ");
  const search = [
    device.ip,
    ...device.extraIps,
    device.mac,
    device.vlanId,
    device.role === "access_point" ? "access point ap" : device.role,
    hostname,
    device.vendor,
    switchPort,
    device.dnsName,
    device.mdnsName,
    device.smbName,
    device.smbDomain,
    ports,
    comments,
    device.neighbor?.platform,
    device.neighbor?.systemName,
  ]
    .filter((v) => v !== null && v !== undefined && v !== "")
    .join("\u0001")
    .toLowerCase();
  const vlanSort = (device.vlanId ?? 0).toString().padStart(4, "0");
  return {
    key,
    device,
    hostname,
    comments,
    switchPort,
    ports,
    ipSort: `${ipSortKey(device.ip)}@${vlanSort}`,
    search,
  };
}

/** Device as it should be exported: user hostname/comments applied. */
export function exportDevice(row: DeviceRow): Device {
  return {
    ...row.device,
    hostname: row.hostname === "" ? null : row.hostname,
    comments: row.comments === "" ? null : row.comments,
  };
}

type Scheduler = (fn: () => void, ms: number) => unknown;
type DirtyPart = "rows" | "vlans" | "neighbors" | "mappings" | "other";

export class ScanStore {
  private devices = new Map<string, Device>();
  private rowCache = new Map<string, DeviceRow>();
  private vlans = new Map<number, VlanInfo>();
  private neighbors = new Map<string, CdpLldpNeighbor>();
  private mappings = new Map<string, SwitchPortMapping>();
  private logs: LogEntry[] = [];
  private logSeq = 0;
  private overrides: Overrides = {};
  private snmp: Record<string, SnmpDeviceInfo> = {};
  private progress: ScanProgress | null = null;
  private summary: ScanSummary | null = null;
  private running = false;
  private starting = false;
  private jobKind: JobKind | null = null;
  private scanId: number | null = null;
  /** Events that arrived before `start_*` resolved with their job id. */
  private buffer: ScanEventPayload[] = [];

  private listeners = new Set<() => void>();
  private snapshot: StoreSnapshot;
  private dirty: Record<DirtyPart, boolean> = { rows: false, vlans: false, neighbors: false, mappings: false, other: false };
  private flushPending = false;
  private readonly schedule: Scheduler;

  constructor(schedule: Scheduler = (fn, ms) => setTimeout(fn, ms)) {
    this.schedule = schedule;
    this.snapshot = this.build(true);
  }

  // --- React glue (useSyncExternalStore) -------------------------------------------------

  subscribe = (fn: () => void): (() => void) => {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  };

  getSnapshot = (): StoreSnapshot => this.snapshot;

  /** Rebuild the snapshot now (tests, or before an export). */
  flushNow(): StoreSnapshot {
    this.flushPending = false;
    this.snapshot = this.build(false);
    for (const fn of this.listeners) fn();
    return this.snapshot;
  }

  private markDirty(part: DirtyPart): void {
    this.dirty[part] = true;
    if (this.flushPending) return;
    this.flushPending = true;
    // Larger tables re-sort less often while streaming.
    const ms = this.devices.size > 20_000 ? 400 : this.devices.size > 2_000 ? 200 : 80;
    this.schedule(() => {
      if (this.flushPending) this.flushNow();
    }, ms);
  }

  private build(force: boolean): StoreSnapshot {
    const prev = this.snapshot as StoreSnapshot | undefined;
    const d = this.dirty;
    let rows = prev?.rows ?? [];
    let roleCounts = prev?.roleCounts ?? emptyRoleCounts();
    if (force || d.rows || !prev) {
      rows = new Array<DeviceRow>(this.devices.size);
      roleCounts = emptyRoleCounts();
      let i = 0;
      for (const [key, device] of this.devices) {
        let row = this.rowCache.get(key);
        if (!row) {
          row = buildRow(key, device, this.overrides[key]);
          this.rowCache.set(key, row);
        }
        rows[i++] = row;
        roleCounts[device.role] += 1;
      }
    }
    const snap: StoreSnapshot = {
      rows,
      roleCounts,
      vlans:
        force || d.vlans || !prev ? [...this.vlans.values()].sort((a, b) => a.id - b.id) : prev.vlans,
      neighbors: force || d.neighbors || !prev ? [...this.neighbors.values()] : prev.neighbors,
      portMappings: force || d.mappings || !prev ? [...this.mappings.values()] : prev.portMappings,
      progress: this.progress,
      summary: this.summary,
      logs: this.logs,
      running: this.running,
      starting: this.starting,
      jobKind: this.jobKind,
      scanId: this.scanId,
      overrides: this.overrides,
      snmp: this.snmp,
    };
    this.dirty = { rows: false, vlans: false, neighbors: false, mappings: false, other: false };
    return snap;
  }

  // --- Job lifecycle ------------------------------------------------------------------------

  /** Call right before invoking `start_scan` / `start_vlan_discovery`. */
  beginStart(kind: JobKind): void {
    this.starting = true;
    this.running = true;
    this.jobKind = kind;
    this.scanId = null;
    this.buffer = [];
    this.progress = null;
    this.summary = null;
    this.markDirty("other");
  }

  /** The start command resolved: adopt its id and replay events that raced ahead of it. */
  startResolved(scanId: number): void {
    this.scanId = scanId;
    this.starting = false;
    const pending = this.buffer;
    this.buffer = [];
    for (const p of pending) if (p.scanId === scanId) this.apply(p.event);
    this.markDirty("other");
  }

  startFailed(message: string): void {
    this.starting = false;
    this.running = false;
    this.buffer = [];
    this.log("error", message);
  }

  /** Route a `scan-event` payload: only the current job's events are applied. */
  handlePayload = (payload: ScanEventPayload): void => {
    if (this.scanId !== null && payload.scanId === this.scanId) {
      this.apply(payload.event);
    } else if (this.starting && this.buffer.length < MAX_BUFFERED) {
      this.buffer.push(payload);
    }
  };

  apply(event: ScanEvent): void {
    switch (event.type) {
      case "device": {
        const dev = event.data;
        const key = deviceKey(dev.ip, dev.vlanId);
        this.devices.set(key, dev);
        this.rowCache.delete(key);
        this.markDirty("rows");
        break;
      }
      case "vlan":
        this.vlans.set(event.data.id, event.data);
        this.markDirty("vlans");
        break;
      case "neighbor":
        this.neighbors.set(neighborKey(event.data), event.data);
        this.markDirty("neighbors");
        break;
      case "port_mapping":
        this.mappings.set(mappingKey(event.data), event.data);
        this.markDirty("mappings");
        break;
      case "progress":
        this.progress = event.data;
        this.markDirty("other");
        break;
      case "log":
        this.log(event.data.level, event.data.message);
        break;
      case "finished":
        this.summary = event.data;
        this.running = false;
        this.starting = false;
        if (this.progress) this.progress = { ...this.progress, phase: "done" };
        this.log(
          "info",
          `${event.data.cancelled ? "Stopped" : "Finished"}: ${event.data.devices} devices, ${event.data.vlans} VLANs, ${event.data.neighbors} neighbors in ${(event.data.elapsedMs / 1000).toFixed(1)} s`,
        );
        break;
    }
  }

  // --- Local mutations ------------------------------------------------------------------------

  log(level: LogLevel, message: string): void {
    const entry: LogEntry = { id: ++this.logSeq, ts: Date.now(), level, message };
    const next = this.logs.length >= MAX_LOGS ? this.logs.slice(-MAX_LOGS + 1) : this.logs.slice();
    next.push(entry);
    this.logs = next;
    this.markDirty("other");
  }

  clearLogs(): void {
    this.logs = [];
    this.markDirty("other");
  }

  setOverrides(overrides: Overrides): void {
    this.overrides = { ...overrides };
    this.rowCache.clear();
    this.markDirty("rows");
  }

  setOverride(key: string, override: DeviceOverride): void {
    const next = { ...this.overrides };
    if (!override.hostname && !override.comments) delete next[key];
    else next[key] = override;
    this.overrides = next;
    this.rowCache.delete(key);
    this.markDirty("rows");
  }

  setSnmpResult(key: string, info: SnmpDeviceInfo): void {
    this.snmp = { ...this.snmp, [key]: info };
    for (const v of info.vlans ?? []) {
      const existing = this.vlans.get(v.id);
      this.vlans.set(v.id, existing ? { ...existing, ...v, name: v.name ?? existing.name } : v);
    }
    for (const m of info.portMappings ?? []) this.mappings.set(mappingKey(m), m);
    this.markDirty("vlans");
    this.markDirty("mappings");
  }

  /** Merge a port-scan result into the device (local only; it is not a backend snapshot). */
  setOpenPorts(key: string, ports: number[]): void {
    const dev = this.devices.get(key);
    if (!dev) return;
    const merged = [...new Set([...dev.openPorts, ...ports])].sort((a, b) => a - b);
    this.devices.set(key, { ...dev, openPorts: merged });
    this.rowCache.delete(key);
    this.markDirty("rows");
  }

  removeDevices(keys: Iterable<string>): void {
    for (const k of keys) {
      this.devices.delete(k);
      this.rowCache.delete(k);
    }
    this.markDirty("rows");
  }

  getDevice(key: string): Device | undefined {
    return this.devices.get(key);
  }

  clearResults(): void {
    this.devices.clear();
    this.rowCache.clear();
    this.vlans.clear();
    this.neighbors.clear();
    this.mappings.clear();
    this.snmp = {};
    this.summary = null;
    if (!this.running) this.progress = null;
    this.markDirty("rows");
    this.markDirty("vlans");
    this.markDirty("neighbors");
    this.markDirty("mappings");
  }
}
