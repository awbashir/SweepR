// Builds the `generate_report` input from the GUI's state: devices as exported (overrides and
// live latency applied), VLANs, CDP/LLDP neighbors, CAM entries, cached SNMP polls, the SNMP
// agents the scan polled (`snmp_agent` events) and the scan metadata (including interface /
// gateway / scanner host from the scan's `finished` summary). Secrets never leave the GUI: the SNMP community is reduced to its classification
// and SNMPv3 credentials are dropped. Framework-free for tests.

import type {
  CdpLldpNeighbor,
  Device,
  GenerateReportArgs,
  LatencyStats,
  ReportFormat,
  ReportMeta,
  ScanConfig,
  SnmpAgentStatus,
  SnmpConfig,
  SnmpDeviceInfo,
  SwitchPortMapping,
  VlanInfo,
  VlanSelection,
} from "../types.ts";
import { formatPorts } from "./parse.ts";
import { reportSnmpAgents, reportSnmpInfos } from "./snmpAgents.ts";
import { exportDevice, type DeviceRow, type ScanSummaryMeta } from "./store.ts";

export const REPORT_FORMATS: ReadonlyArray<{ format: ReportFormat; label: string; ext: string }> = [
  { format: "html", label: "HTML report", ext: "html" },
  { format: "pdf", label: "PDF summary", ext: "pdf" },
  { format: "json", label: "JSON findings", ext: "json" },
];

export const DEFAULT_REPORT_TITLE = "SweepR Network Audit Report";

/** Where the backend classifies the community (`SnmpMeta::redact` in audit.rs), done here instead. */
export function classifyCommunity(c: string | null | undefined): "public" | "private" | "custom" | "none" {
  const t = (c ?? "").trim();
  if (t === "") return "none";
  if (t === "public" || t === "private") return t;
  return "custom";
}

/** `{ mode: "untagged_and_list", ids: [10, 20] }` -> "untagged,10,20". */
export function vlanSpec(sel: VlanSelection): string {
  switch (sel.mode) {
    case "untagged":
      return "untagged";
    case "auto_detect":
      return "auto";
    case "list":
      return sel.ids.join(",");
    case "untagged_and_list":
      return ["untagged", ...sel.ids].join(",");
  }
}

/** SNMP settings without any secret: version plus the community classification (v1 / v2c). */
export function snmpMeta(c: SnmpConfig | null | undefined): ReportMeta["snmp"] | undefined {
  if (!c) return undefined;
  if (c.version === "v3") return { version: "v3" };
  return { version: c.version, communityKind: classifyCommunity(c.community) };
}

export interface ScanContext {
  /** The configuration the latest scan ran with (null: no scan from this window yet). */
  config: ScanConfig | null;
  /** Interface the scan used (the resolved default when `config.interface` is null). */
  iface: string | null;
  /** Ranges when `config.range` is null (the interface subnet, e.g. "10.0.0.0/24"). */
  defaultRanges: string[];
  startedMs: number | null;
  finishedMs: number | null;
  cancelled: boolean;
  toolVersion: string | null;
  /** Interface / gateway / scanner host from the latest full scan's `finished` event. */
  summary?: ScanSummaryMeta | null;
  /** SNMP agents the latest full scan polled (`snmp_agent` events). */
  snmpAgents?: readonly SnmpAgentStatus[];
}

/** Scan metadata for the report (never the SNMP community or SNMPv3 passwords). */
export function buildReportMeta(ctx: ScanContext): ReportMeta {
  const meta: ReportMeta = {};
  if (ctx.toolVersion) meta.toolVersion = ctx.toolVersion;
  const c = ctx.config;
  // The backend's own account of the scan wins; absent fields never clear known values.
  const sum = ctx.summary ?? null;
  const iface = sum?.interface || c?.interface || ctx.iface;
  if (iface) meta.interface = iface;
  if (sum?.gateway) meta.gateway = sum.gateway;
  if (sum?.scannerHost) meta.scannerHost = sum.scannerHost;
  if (c) {
    const ranges = c.range ? c.range.split(",").map((r) => r.trim()).filter(Boolean) : ctx.defaultRanges;
    if (ranges.length > 0) meta.ranges = ranges;
    meta.vlans = vlanSpec(c.vlans);
    if (c.ports.length > 0) meta.portSpec = formatPorts(c.ports);
    meta.ipv6 = c.ipv6;
    meta.cdpLldp = c.cdpLldp;
    meta.discoverVlans = c.discoverVlans;
    meta.resolveNames = c.resolveNames;
    meta.snmpAll = c.snmpAll;
    const snmp = snmpMeta(c.snmp);
    if (snmp) meta.snmp = snmp;
  }
  if (ctx.startedMs !== null) meta.startedMs = ctx.startedMs;
  if (ctx.finishedMs !== null) meta.finishedMs = ctx.finishedMs;
  if (ctx.cancelled) meta.cancelled = true;
  const agents = reportSnmpAgents(ctx.snmpAgents ?? []);
  if (agents.length > 0) meta.snmpAgents = agents;
  return meta;
}

/** Secrets of an SNMP configuration (for the leak check before sending). */
export function snmpSecrets(c: SnmpConfig | null | undefined): string[] {
  if (!c) return [];
  const out: string[] = [];
  // A default community is not a secret (and "public" appears in plenty of harmless text).
  if (c.version !== "v3" && classifyCommunity(c.community) === "custom") out.push(c.community.trim());
  if (c.v3?.authPassword) out.push(c.v3.authPassword);
  if (c.v3?.privPassword) out.push(c.v3.privPassword);
  return out.filter((s) => s.length > 0);
}

/** `true` when the serialized value contains one of the secrets. */
export function leaksSecret(value: unknown, secrets: readonly string[]): boolean {
  if (secrets.length === 0) return false;
  const json = JSON.stringify(value) ?? "";
  return secrets.some((s) => json.includes(JSON.stringify(s).slice(1, -1)));
}

export interface ReportSource {
  rows: readonly DeviceRow[];
  latency: (ip: string) => LatencyStats | null | undefined;
  vlans: readonly VlanInfo[];
  neighbors: readonly CdpLldpNeighbor[];
  portMappings: readonly SwitchPortMapping[];
  /** Cached `query_snmp` results by device key (`ip` or `ip@vlan`). */
  snmp: Readonly<Record<string, SnmpDeviceInfo>>;
  /** Agents the latest scan polled: answered ones add `snmpInfos` entries (queries win). */
  snmpAgents?: readonly SnmpAgentStatus[];
}

export interface ReportOptions {
  format: ReportFormat;
  title?: string;
  org?: string;
}

/** IP of a device key (`10.0.0.1@20` -> `10.0.0.1`; IPv6 keys contain no `@` either). */
export function ipOfKey(key: string): string {
  const at = key.indexOf("@");
  return at < 0 ? key : key.slice(0, at);
}

export interface BuildProgress {
  done: number;
  total: number;
}

/**
 * The `generate_report` arguments. Devices are converted in chunks; `pause` runs between
 * chunks (the GUI yields to the event loop there, so 50k rows never block a frame for long).
 */
export async function buildReportArgs(
  src: ReportSource,
  meta: ReportMeta,
  opts: ReportOptions,
  pause: (p: BuildProgress) => Promise<void> = async () => undefined,
  chunk = 5000,
): Promise<GenerateReportArgs> {
  const total = src.rows.length;
  const devices = new Array<Device>(total);
  for (let i = 0; i < total; i += chunk) {
    const end = Math.min(total, i + chunk);
    for (let k = i; k < end; k++) {
      const row = src.rows[k]!;
      devices[k] = exportDevice(row, src.latency(row.device.ip));
    }
    if (end < total) await pause({ done: end, total });
  }
  const snmpInfos = reportSnmpInfos(
    Object.entries(src.snmp).map(([key, info]) => ({ ...info, ip: ipOfKey(key) })),
    src.snmpAgents ?? [],
  );
  const title = opts.title?.trim();
  const org = opts.org?.trim();
  const args: GenerateReportArgs = {
    devices,
    vlans: [...src.vlans],
    neighbors: [...src.neighbors],
    portMappings: [...src.portMappings],
    snmpInfos,
    meta,
    format: opts.format,
  };
  if (title) args.title = title;
  if (org) args.org = org;
  return args;
}

/** Yield to the browser between chunks (a macrotask, so input and paint can run). */
export function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}
