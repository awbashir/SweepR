// SNMP agents polled during a scan (`snmp_agent` events): a bounded per-scan record, the view
// the topology / details drawer use (the agent's identity and PoE budget without a Query SNMP
// click) and the report inputs (`meta.snmpAgents`, `snmpInfos`), as `sweepr scan --report`
// builds them. The events carry the community *class* only, never the community.
// Framework-free for tests.

import type { DeviceRole, ReportMeta, ReportSnmpInfo, SnmpAgentStatus, SnmpDeviceInfo } from "../types.ts";

/** Agents remembered per scan (the backend's report aggregator keeps 250,000). */
export const MAX_SNMP_AGENTS = 10_000;

/** SNMP data shown for a device: a `query_snmp` result, or what the scan's agent poll returned. */
export type SnmpView = SnmpDeviceInfo & {
  /** Only the scan's `snmp_agent` event is known (no Query SNMP yet). */
  fromScan?: boolean;
};

/**
 * Record one `snmp_agent` event. An agent that answered once stays answered (a later timeout
 * of the same IP does not hide its data); events without an IP and new agents beyond `cap` are
 * dropped. Returns whether the map changed.
 */
export function recordAgent(map: Map<string, SnmpAgentStatus>, a: SnmpAgentStatus, cap = MAX_SNMP_AGENTS): boolean {
  if (!a || typeof a.ip !== "string" || a.ip === "") return false;
  const prev = map.get(a.ip);
  if (!prev && map.size >= cap) return false;
  if (prev?.answered && !a.answered) return false;
  map.set(a.ip, a);
  return true;
}

/** An answered agent as `SnmpDeviceInfo` (identity, role and PoE budget; no tables). */
export function agentAsInfo(a: SnmpAgentStatus, fallbackRole: DeviceRole = "host"): SnmpView {
  return {
    sysName: a.sysName ?? null,
    sysDescr: a.sysDescr ?? null,
    sysUptimeTicks: null,
    sysObjectId: null,
    role: a.role ?? fallbackRole,
    vlans: [],
    portMappings: [],
    portMacCounts: [],
    poeBudget: a.poeBudget ?? null,
    partial: a.partial === true,
    warnings: Array.isArray(a.warnings) ? a.warnings : [],
    fromScan: true,
  };
}

/** A `query_snmp` result with the agent's data filling its gaps (the query wins on conflicts). */
export function mergeQueryWithAgent(q: SnmpDeviceInfo, a: SnmpAgentStatus | undefined): SnmpView {
  if (!a?.answered) return q;
  return {
    ...q,
    sysName: q.sysName ?? a.sysName ?? null,
    sysDescr: q.sysDescr ?? a.sysDescr ?? null,
    poeBudget: q.poeBudget ?? a.poeBudget ?? null,
  };
}

/** `meta.snmpAgents`: every polled agent with an IP, community class only. */
export function reportSnmpAgents(agents: readonly SnmpAgentStatus[]): NonNullable<ReportMeta["snmpAgents"]> {
  const out: NonNullable<ReportMeta["snmpAgents"]> = [];
  for (const a of agents) {
    if (typeof a.ip !== "string" || a.ip === "") continue;
    const rec: NonNullable<ReportMeta["snmpAgents"]>[number] = { ip: a.ip, answered: a.answered === true };
    if (a.version) rec.version = a.version;
    if (a.communityClass) rec.communityClass = a.communityClass;
    out.push(rec);
  }
  return out;
}

/** The `snmpInfos` record of an answered agent (`{ ip, sysName, sysDescr, role, poeBudget, partial, warnings }`). */
export function agentReportInfo(a: SnmpAgentStatus & { ip: string }): ReportSnmpInfo {
  const info: ReportSnmpInfo = {
    ip: a.ip,
    sysName: a.sysName ?? null,
    sysDescr: a.sysDescr ?? null,
    poeBudget: a.poeBudget ?? null,
    partial: a.partial === true,
    warnings: Array.isArray(a.warnings) ? a.warnings : [],
  };
  if (a.role) info.role = a.role;
  return info;
}

/**
 * `snmpInfos` for the report: the `query_snmp` results (keyed by agent IP) merged with the
 * answered agents of the scan. Where both exist the query result wins; the agent only fills
 * fields the query left empty (e.g. a PoE budget).
 */
export function reportSnmpInfos(
  queries: ReadonlyArray<SnmpDeviceInfo & { ip: string }>,
  agents: readonly SnmpAgentStatus[],
): ReportSnmpInfo[] {
  const answered = new Map<string, SnmpAgentStatus & { ip: string }>();
  for (const a of agents) if (a.answered && typeof a.ip === "string" && a.ip !== "") answered.set(a.ip, a as SnmpAgentStatus & { ip: string });
  const out: ReportSnmpInfo[] = [];
  const used = new Set<string>();
  for (const q of queries) {
    const a = answered.get(q.ip);
    if (a) used.add(q.ip);
    out.push({ ...mergeQueryWithAgent(q, a), ip: q.ip });
  }
  for (const [ip, a] of answered) if (!used.has(ip)) out.push(agentReportInfo(a));
  return out;
}

/**
 * The SNMP data per device key the UI shows: `query_snmp` results (merged with the agent's
 * PoE budget / identity) plus, for devices nobody queried, what the scan's agent poll returned.
 * `keysOf(ip)` returns the device keys of an IP (`ip`, `ip@vlan`).
 */
export function snmpViewFor(
  queries: Readonly<Record<string, SnmpDeviceInfo>>,
  agents: ReadonlyMap<string, SnmpAgentStatus>,
  keysOf: (ip: string) => readonly string[],
  roleOf: (key: string) => DeviceRole | undefined,
  ipOfKey: (key: string) => string,
): Record<string, SnmpView> {
  const out: Record<string, SnmpView> = {};
  for (const [key, q] of Object.entries(queries)) out[key] = mergeQueryWithAgent(q, agents.get(ipOfKey(key)));
  for (const a of agents.values()) {
    if (!a.answered || !a.ip) continue;
    for (const key of keysOf(a.ip)) {
      if (!(key in out)) out[key] = agentAsInfo(a, roleOf(key));
    }
  }
  return out;
}
