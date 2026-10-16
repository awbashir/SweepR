// Framework-free scan result store. Events are applied immediately to Maps; React is notified
// at most every `flushMs` with an immutable snapshot, so a burst of thousands of `device`
// events costs one re-render, and 50k+ rows stay responsive.

import type {
  CdpLldpNeighbor,
  Device,
  DeviceOverride,
  DeviceRole,
  LatencyStats,
  LogLevel,
  Overrides,
  ScanEvent,
  ScanEventPayload,
  ScanProgress,
  ScanSummary,
  ServiceDiscovery,
  SnmpAgentStatus,
  SnmpDeviceInfo,
  SwitchPortMapping,
  VlanInfo,
  WebIdentity,
} from "../types.ts";
import { deviceKey, ipSortKey } from "./ip.ts";
import { deviceKindLabel, deviceKindOf, dhcpOsLabel, modelFirmware, netServiceBadges, withServiceDiscovery } from "./services.ts";
import { recordAgent, snmpViewFor, type SnmpView } from "./snmpAgents.ts";

export interface DeviceRow {
  key: string;
  device: Device;
  /**
   * The user's label from the override store ("" when none). In the GUI the engine never
   * fills `device.hostname` / `device.comments` (they are user fields owned by the override
   * store), so clearing an override clears the cell immediately.
   */
  hostname: string;
  comments: string;
  /** `Cisco-SW01 [Gi1/0/24]` */
  switchPort: string;
  ports: string;
  /** Device kind label ("IP Phone"; "" when unknown). */
  kind: string;
  /** "SIP-T54W / 96.86.0.5" (SIP, then ONVIF, then UPnP; "" when unknown). */
  modelFw: string;
  /** "Windows (high)" ("" when unknown). */
  dhcpOs: string;
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

/** What the `finished` event of the latest full scan said about where it ran (report metadata). */
export interface ScanSummaryMeta {
  interface?: string;
  gateway?: string;
  scannerHost?: string;
}

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
  /** `query_snmp` results by device key. */
  snmp: Record<string, SnmpDeviceInfo>;
  /** SNMP agents the latest full scan polled (`snmp_agent` events; community class only). */
  snmpAgents: SnmpAgentStatus[];
  /** `snmp` merged with the answered agents (identity / PoE budget without a Query SNMP). */
  snmpView: Record<string, SnmpView>;
  /** Interface / gateway / scanner host from the latest full scan's `finished` event. */
  scanMeta: ScanSummaryMeta | null;
  /** Wall-clock start / end of the latest job (report metadata). */
  jobStartedMs: number | null;
  jobFinishedMs: number | null;
}

const MAX_LOGS = 1000;
const MAX_BUFFERED = 200_000;
/** CAM-table entries kept (mirrors the backend aggregator's cap). */
export const MAX_MAPPINGS = 200_000;

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
  // User fields come only from the override store: falling back to `device.hostname` would
  // resurrect a label the user just cleared.
  const hostname = overrideText(override, "hostname") ?? "";
  const comments = overrideText(override, "comments") ?? "";
  const switchPort = switchPortLabel(device.switchPort);
  const ports = device.openPorts.join(", ");
  const kindId = deviceKindOf(device);
  const kind = deviceKindLabel(kindId);
  const modelFw = modelFirmware(device);
  const dhcpOs = dhcpOsLabel(device.dhcpFingerprint);
  const fp = device.dhcpFingerprint;
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
    device.webTitle,
    device.webIdentity,
    device.webServer,
    device.tlsCert?.subjectCn,
    ...(device.warnings ?? []),
    kindId,
    kind,
    modelFw,
    device.ssdp?.friendlyName,
    device.ssdp?.manufacturer,
    device.ssdp?.serialNumber,
    device.onvif?.manufacturer,
    device.onvif?.name,
    device.onvif?.serialNumber,
    device.sip?.vendor,
    device.sip?.userAgent,
    device.sip?.server,
    device.voiceVlan != null ? `voice ${device.voiceVlan}` : null,
    device.poe ? "poe" : null,
    dhcpOs,
    ...netServiceBadges(device).map((b) => (b.id === "ipv6_router" ? `${b.label} ipv6 router advertisement` : b.label)),
    fp?.vendorClass,
    fp?.hostname,
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
    kind,
    modelFw,
    dhcpOs,
    ipSort: `${ipSortKey(device.ip)}@${vlanSort}`,
    search,
  };
}

/**
 * Device as it should be exported: user hostname/comments applied, and the live latency the
 * GUI measured (the engine never fills `device.latency`).
 */
export function exportDevice(row: DeviceRow, latency?: LatencyStats | null): Device {
  return {
    ...row.device,
    hostname: row.hostname === "" ? null : row.hostname,
    comments: row.comments === "" ? null : row.comments,
    latency: latency ?? row.device.latency ?? null,
  };
}

/** A device with a `grab_web_identity` result merged in (warnings de-duplicated). */
export function withWebIdentity(dev: Device, wi: WebIdentity): Device {
  const warnings = [...new Set([...(dev.warnings ?? []), ...wi.warnings])];
  const promote = dev.role === "host" && wi.roleHint !== null && wi.roleHint !== "host";
  return {
    ...dev,
    webTitle: wi.title ?? dev.webTitle,
    webServer: wi.server ?? dev.webServer,
    tlsCert: wi.tlsCert ?? dev.tlsCert,
    webIdentity: wi.identity ?? dev.webIdentity,
    warnings,
    role: promote && wi.roleHint ? wi.roleHint : dev.role,
    openPorts: [...new Set([...dev.openPorts, ...wi.services.filter((s) => s.status !== null).map((s) => s.port)])].sort((a, b) => a - b),
  };
}

type Scheduler = (fn: () => void, ms: number) => unknown;
type DirtyPart = "rows" | "vlans" | "neighbors" | "mappings" | "snmp" | "other";

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
  private agents = new Map<string, SnmpAgentStatus>();
  private scanMeta: ScanSummaryMeta | null = null;
  private progress: ScanProgress | null = null;
  private summary: ScanSummary | null = null;
  private running = false;
  private starting = false;
  private jobKind: JobKind | null = null;
  private scanId: number | null = null;
  private jobStartedMs: number | null = null;
  private jobFinishedMs: number | null = null;
  /** Events that arrived before `start_*` resolved with their job id. */
  private buffer: ScanEventPayload[] = [];
  /** Token of the latest `beginStart`; replies to older starts are ignored. */
  private startToken = 0;
  /** A job id an outdated start resolved with (adopted if the newer start fails). */
  private orphanId: number | null = null;
  /** The latest start failed (so an older start that resolves late may be adopted). */
  private latestFailed = false;
  private mappingCapWarned = false;

  private listeners = new Set<() => void>();
  private snapshot: StoreSnapshot;
  private dirty: Record<DirtyPart, boolean> = { rows: false, vlans: false, neighbors: false, mappings: false, snmp: false, other: false };
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
      snmpAgents: force || d.snmp || !prev ? [...this.agents.values()] : prev.snmpAgents,
      snmpView: force || d.snmp || d.rows || !prev ? this.buildSnmpView() : prev.snmpView,
      scanMeta: this.scanMeta,
      jobStartedMs: this.jobStartedMs,
      jobFinishedMs: this.jobFinishedMs,
    };
    this.dirty = { rows: false, vlans: false, neighbors: false, mappings: false, snmp: false, other: false };
    return snap;
  }

  private buildSnmpView(): Record<string, SnmpView> {
    if (this.agents.size === 0) return this.snmp;
    // Agents are usually untagged infrastructure (key = IP); index VLAN keys only when needed.
    let byIp: Map<string, string[]> | null = null;
    const keysOf = (ip: string): string[] => {
      if (this.devices.has(ip)) return [ip];
      if (!byIp) {
        byIp = new Map();
        for (const [key, dev] of this.devices) {
          if (key === dev.ip) continue;
          const l = byIp.get(dev.ip);
          if (l) l.push(key);
          else byIp.set(dev.ip, [key]);
        }
      }
      return byIp.get(ip) ?? [];
    };
    return snmpViewFor(
      this.snmp,
      this.agents,
      keysOf,
      (key) => this.devices.get(key)?.role,
      (key) => this.devices.get(key)?.ip ?? key,
    );
  }

  // --- Job lifecycle ------------------------------------------------------------------------

  /**
   * Call right before invoking `start_scan` / `start_vlan_discovery`. Returns a token to pass
   * to `startResolved` / `startFailed`, so a reply to an earlier, superseded start (two rapid
   * starts) cannot adopt the wrong job or throw away the newer job's buffered events.
   */
  beginStart(kind: JobKind): number {
    this.starting = true;
    this.running = true;
    this.jobKind = kind;
    this.scanId = null;
    this.buffer = [];
    this.orphanId = null;
    this.latestFailed = false;
    this.progress = null;
    this.summary = null;
    this.jobStartedMs = Date.now();
    this.jobFinishedMs = null;
    if (kind === "scan") {
      // Per scan job: a VLAN discovery keeps the latest scan's agents and metadata.
      this.agents.clear();
      this.scanMeta = null;
      this.markDirty("snmp");
    }
    this.markDirty("other");
    return ++this.startToken;
  }

  /** The start command resolved: adopt its id and replay events that raced ahead of it. */
  startResolved(scanId: number, token: number = this.startToken): void {
    if (token !== this.startToken) {
      // An older start finished after a newer one began: the backend has already superseded
      // (or is about to supersede) it. Keep buffering for the newer start.
      if (this.starting) {
        this.orphanId = Math.max(this.orphanId ?? 0, scanId);
      } else if (this.latestFailed && this.scanId === null) {
        // The newer start already failed; this older job is the one actually running.
        this.running = true;
        this.adopt(scanId);
      }
      return;
    }
    this.adopt(scanId);
  }

  startFailed(message: string, token: number = this.startToken): void {
    this.log("error", message);
    if (token !== this.startToken) return;
    if (this.orphanId !== null) {
      // The newer start failed before superseding the older job, which is still running.
      this.adopt(this.orphanId);
      return;
    }
    this.starting = false;
    this.running = false;
    this.latestFailed = true;
    this.buffer = [];
  }

  private adopt(scanId: number): void {
    this.scanId = scanId;
    this.starting = false;
    this.orphanId = null;
    this.latestFailed = false;
    const pending = this.buffer;
    this.buffer = [];
    for (const p of pending) if (p.scanId === scanId) this.apply(p.event);
    this.markDirty("other");
  }

  /**
   * Leave the busy state when the backend job is gone without a `finished` event (it crashed,
   * or `finished` was lost): only when `scanId` is still the adopted, running job. Late events
   * of that job are still applied. Returns whether the state was reset.
   */
  forceIdle(scanId: number | null, reason: string): boolean {
    if (!this.running || this.starting || this.scanId === null || (scanId !== null && scanId !== this.scanId)) return false;
    this.running = false;
    this.jobFinishedMs = Date.now();
    this.log("warn", reason);
    this.markDirty("other");
    return true;
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
        if (this.addMapping(event.data)) this.markDirty("mappings");
        break;
      case "snmp_agent":
        if (recordAgent(this.agents, event.data)) this.markDirty("snmp");
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
        if (this.jobKind === "scan") this.scanMeta = summaryMeta(event.data, this.scanMeta);
        this.jobFinishedMs = Date.now();
        this.running = false;
        this.starting = false;
        if (this.progress) this.progress = { ...this.progress, phase: "done" };
        if (event.data.failed === true) {
          this.log("error", `Failed after ${(event.data.elapsedMs / 1000).toFixed(1)} s${event.data.cancelled ? " (stopped)" : ""}`);
        } else {
          this.log(
            "info",
            `${event.data.cancelled ? "Stopped" : "Finished"}: ${event.data.devices} devices, ${event.data.vlans} VLANs, ${event.data.neighbors} neighbors in ${(event.data.elapsedMs / 1000).toFixed(1)} s`,
          );
        }
        break;
    }
  }

  /** Store one CAM entry; beyond `MAX_MAPPINGS` new entries are ignored (warned once). */
  private addMapping(m: SwitchPortMapping): boolean {
    const key = mappingKey(m);
    if (!this.mappings.has(key) && this.mappings.size >= MAX_MAPPINGS) {
      if (!this.mappingCapWarned) {
        this.mappingCapWarned = true;
        this.log("warn", `More than ${MAX_MAPPINGS.toLocaleString()} MAC-to-port entries; ignoring further entries.`);
      }
      return false;
    }
    this.mappings.set(key, m);
    return true;
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
    for (const m of info.portMappings ?? []) this.addMapping(m);
    this.markDirty("vlans");
    this.markDirty("mappings");
    this.markDirty("snmp");
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

  /** Merge a `grab_web_identity` result into the device (local only, like `setOpenPorts`). */
  setWebIdentity(key: string, wi: WebIdentity): void {
    const dev = this.devices.get(key);
    if (!dev) return;
    this.devices.set(key, withWebIdentity(dev, wi));
    this.rowCache.delete(key);
    this.markDirty("rows");
  }

  /** Merge a `discover_services` result into the device (local only, like `setOpenPorts`). */
  setServices(key: string, sd: ServiceDiscovery): void {
    const dev = this.devices.get(key);
    if (!dev) return;
    this.devices.set(key, withServiceDiscovery(dev, sd));
    this.rowCache.delete(key);
    this.markDirty("rows");
  }

  /** Remove rows from the results; returns what was removed (for Undo). */
  removeDevices(keys: Iterable<string>): Array<[string, Device]> {
    const removed: Array<[string, Device]> = [];
    for (const k of keys) {
      const dev = this.devices.get(k);
      if (dev) removed.push([k, dev]);
      this.devices.delete(k);
      this.rowCache.delete(k);
    }
    this.markDirty("rows");
    return removed;
  }

  /** Undo `removeDevices`. A row the scan re-emitted in the meantime keeps its newer data. */
  restoreDevices(entries: Array<[string, Device]>): void {
    for (const [k, dev] of entries) {
      if (!this.devices.has(k)) {
        this.devices.set(k, dev);
        this.rowCache.delete(k);
      }
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
    this.mappingCapWarned = false;
    this.snmp = {};
    this.agents.clear();
    this.scanMeta = null;
    this.summary = null;
    if (!this.running) this.progress = null;
    this.markDirty("rows");
    this.markDirty("vlans");
    this.markDirty("neighbors");
    this.markDirty("mappings");
    this.markDirty("snmp");
  }
}

/** Interface / gateway / scanner host of a `finished` summary; absent fields keep `prev`'s value. */
export function summaryMeta(s: ScanSummary, prev: ScanSummaryMeta | null = null): ScanSummaryMeta | null {
  const out: ScanSummaryMeta = { ...prev };
  for (const k of ["interface", "gateway", "scannerHost"] as const) {
    const v = s[k];
    if (typeof v === "string" && v.trim() !== "") out[k] = v;
  }
  return Object.keys(out).length > 0 ? out : null;
}
