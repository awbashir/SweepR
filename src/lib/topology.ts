// Pure Layer-2/Layer-3 topology builder: turns devices, CDP/LLDP neighbors, CAM tables (SNMP
// MAC -> switch port), VLANs and cached SNMP results into a hierarchy of nodes and edges.
//
// Hierarchy (top-down): firewalls / routers -> core / distribution switches -> access switches
// -> access points -> endpoints. Links between infrastructure come from the CAM tables (the
// switch port with the fewest MACs that learned a device's MAC is the port it is plugged into,
// the "edge port" heuristic) and from CDP/LLDP adverts heard by this computer. Endpoints attach
// to their switch port (`device.switchPort` or the CAM table), to an access point when their MAC
// is learned on the AP's switch port (wireless clients), or to a per-VLAN group when nothing is
// known. Large groups of endpoints collapse into cluster nodes, so 50k devices become a few
// hundred nodes. No React, no DOM: everything here is unit tested.

import type {
  CdpLldpNeighbor,
  Device,
  DeviceRole,
  SnmpDeviceInfo,
  PoeInfo,
  SwitchPortMapping,
  VlanInfo,
} from "../types.ts";
import { normMac } from "./infra.ts";
import { budgetUsage, deviceKindOf, portPoeTotal } from "./services.ts";
import type { Tone } from "./latency.ts";
import { ipSortKey } from "./ip.ts";
import { formatPorts } from "./parse.ts";

// --- public types -------------------------------------------------------------------------------

/** One device row (a `DeviceRow` from the store satisfies this). */
export interface TopoDeviceInput {
  key: string;
  device: Device;
  /** User label from the override store ("" when none). */
  hostname: string;
}

export interface TopologyInput {
  devices: readonly TopoDeviceInput[];
  neighbors: readonly CdpLldpNeighbor[];
  vlans: readonly VlanInfo[];
  portMappings: readonly SwitchPortMapping[];
  /** Cached `query_snmp` results by device key. */
  snmp: Readonly<Record<string, SnmpDeviceInfo>>;
}

/** VLAN filter value for untagged / unknown VLAN. */
export const UNTAGGED = 0;

export interface TopologyOptions {
  /** Expanded clusters: cluster id -> number of members shown. */
  expanded?: ReadonlyMap<string, number>;
  /** Show only these roles (plus the infrastructure path to them). */
  roles?: ReadonlySet<DeviceRole> | null;
  /** Show only these VLANs (`UNTAGGED` for none), plus the path to them. */
  vlans?: ReadonlySet<number> | null;
  /** Device keys listed first in expanded clusters (search matches). */
  priorityKeys?: ReadonlySet<string> | null;
  /** A parent with at most this many endpoints shows them individually (default 5). */
  individualMax?: number;
  /** Endpoints on one port that form their own cluster (default 4). */
  portClusterMin?: number;
}

export type TopoNodeKind = "device" | "infra" | "scanner" | "root" | "cluster";
export type ClusterKind = "vlan" | "port" | "wireless" | "unattached";
export type TopoStatus = "ok" | "warn" | "unknown";

export interface TopoMember {
  deviceKind: string | null;
  poeWatts: number | null;
  key: string;
  label: string;
  ip: string;
  mac: string | null;
  vendor: string | null;
  port: string | null;
  vlan: number | null;
}

export interface TopoNode {
  id: string;
  kind: TopoNodeKind;
  role: DeviceRole | null;
  label: string;
  ip: string | null;
  mac: string | null;
  /** Vendor / model line. */
  detail: string | null;
  vlans: number[];
  /** Device row behind the node (null for synthetic nodes and clusters). */
  deviceKey: string | null;
  parentId: string | null;
  depth: number;
  /** Port on the parent this node hangs off (endpoints). */
  port: string | null;
  status: TopoStatus;
  /** Why the node is where it is (tooltip). */
  note: string | null;
  // Clusters.
  clusterKind: ClusterKind | null;
  count: number;
  portsLabel: string | null;
  memberKeys: readonly string[];
  members: TopoMember[];
  expanded: boolean;
  /** Members not shown in an expanded cluster ("+N more"). */
  more: number;
  /** Endpoint kind from service discovery (`voip_phone`, `camera`, ...). */
  deviceKind: string | null;
  /** PoE the endpoint draws. */
  poe: PoeInfo | null;
  /** Switches: PoE budget (SNMP) or the PoE drawn on its ports (CAM entries). */
  poeUsage: { consumed: number | null; nominal: number | null; pct: number | null; tone: Tone; ports: number } | null;
}

export type TopoEdgeKind = "trunk" | "access" | "wireless" | "inferred";

export interface TopoEdge {
  id: string;
  source: string;
  target: string;
  kind: TopoEdgeKind;
  sourcePort: string | null;
  targetPort: string | null;
  vlans: number[];
  nativeVlan: number | null;
  label: string | null;
  sublabel: string | null;
  /** Part of the spanning tree used for the layout (cross links are drawn, not ranked). */
  tree: boolean;
  /** Minimum rank distance for the layout. */
  minlen: number;
}

export interface TopologyStats {
  devices: number;
  infra: number;
  endpoints: number;
  clusters: number;
  unattached: number;
  inferredLinks: number;
  hasNeighbors: boolean;
  hasCam: boolean;
  /** Any real hierarchy data (CDP/LLDP or CAM): false means the fallback layout. */
  hasInfraData: boolean;
}

export interface TopologyGraph {
  nodes: TopoNode[];
  edges: TopoEdge[];
  stats: TopologyStats;
  /** Device key -> node id that shows it (a device node or the cluster that holds it). */
  nodeOfKey: Map<string, string>;
}

// --- formatting helpers ---------------------------------------------------------------------------

const PORT_ABBREV: Array<[RegExp, string]> = [
  [/^HundredGig(abit)?E(thernet)?/i, "Hu"],
  [/^FortyGig(abit)?E(thernet)?/i, "Fo"],
  [/^TwentyFiveGig(abit)?E(thernet)?/i, "Twe"],
  [/^TenGig(abit)?E(thernet)?/i, "Te"],
  [/^GigabitEthernet/i, "Gi"],
  [/^FastEthernet/i, "Fa"],
  [/^Port-channel/i, "Po"],
  [/^Ethernet/i, "Eth"],
];

/** `GigabitEthernet1/0/48` -> `Gi1/0/48` (other names unchanged). */
export function shortPort(port: string): string {
  const hit = shortPortCache.get(port);
  if (hit !== undefined) return hit;
  let p = port.trim();
  for (const [re, abbr] of PORT_ABBREV) {
    if (re.test(p)) {
      p = p.replace(re, abbr);
      break;
    }
  }
  if (shortPortCache.size > 50_000) shortPortCache.clear();
  shortPortCache.set(port, p);
  return p;
}
const shortPortCache = new Map<string, string>();

/** `[10, 20, 21, 22, 23, 24, 25]` -> `10,20-25` (sorted, de-duplicated). */
export function compressVlans(vlans: Iterable<number>): string {
  return formatPorts([...new Set(vlans)].sort((a, b) => a - b));
}

const collator = new Intl.Collator(undefined, { numeric: true });
const naturalCmp = (a: string, b: string): number => collator.compare(a, b);

/**
 * `Gi1/0/14, Gi1/0/15, Gi1/0/16, Gi1/0/20, 1/1/3` -> `Gi1/0/14-16,20, 1/1/3`; at most
 * `maxGroups` prefixes are listed, then `+N`; a prefix with more than `maxSegments` runs shows
 * its span (`Gi1/0/2-42`).
 */
export function compressPorts(ports: Iterable<string>, maxGroups = 3, maxSegments = 4): string {
  const groups = new Map<string, Set<number>>();
  const plain = new Set<string>();
  for (const raw of ports) {
    const p = shortPort(raw);
    const m = /^(.*?)(\d+)$/.exec(p);
    if (!m) {
      plain.add(p);
      continue;
    }
    const prefix = m[1] ?? "";
    const set = groups.get(prefix) ?? new Set<number>();
    set.add(Number(m[2]));
    groups.set(prefix, set);
  }
  const parts: string[] = [];
  for (const prefix of [...groups.keys()].sort(naturalCmp)) {
    const nums = [...(groups.get(prefix) ?? [])].sort((a, b) => a - b);
    const list = formatPorts(nums);
    // Scattered ports collapse to their span: `Gi1/0/2-42` rather than a long list.
    parts.push(list.split(",").length > maxSegments ? `${prefix}${nums[0]}-${nums[nums.length - 1]}` : `${prefix}${list}`);
  }
  for (const p of [...plain].sort(naturalCmp)) parts.push(p);
  if (parts.length <= maxGroups) return parts.join(", ");
  return `${parts.slice(0, maxGroups).join(", ")} +${parts.length - maxGroups}`;
}

/** VLAN line for an edge: `VLANs 1,10,20-25 · native 1`. */
export function vlanLabel(vlans: readonly number[], native: number | null): string | null {
  const list = vlans.filter((v) => v > 0);
  if (list.length === 0 && native === null) return null;
  const parts: string[] = [];
  if (list.length > 0) parts.push(`${list.length === 1 ? "VLAN" : "VLANs"} ${compressVlans(list)}`);
  if (native !== null && !(list.length === 1 && list[0] === native)) parts.push(`native ${native}`);
  return parts.join(" · ");
}

/**
 * Display name: user hostname -> SNMP / CDP name -> DNS -> mDNS -> NetBIOS -> IP. Discovered
 * names drop their domain (`core-sw01.corp.example` -> `core-sw01`) to keep map labels short.
 */
export function displayName(d: Device, hostname: string, snmp?: SnmpDeviceInfo): string {
  const discovered =
    (d.role !== "host" ? (nonEmpty(snmp?.sysName) ?? nonEmpty(d.neighbor?.systemName)) : null) ??
    nonEmpty(d.dnsName) ??
    nonEmpty(d.mdnsName) ??
    nonEmpty(d.smbName);
  return nonEmpty(hostname) ?? nonEmpty(d.hostname) ?? (discovered ? hostLabel(discovered) : d.ip);
}

function hostLabel(name: string): string {
  return /^[\d.:]+$/.test(name) ? name : (name.split(".")[0] ?? name);
}

function nonEmpty(s: string | null | undefined): string | null {
  return s && s.trim() !== "" ? s.trim() : null;
}

function shortVendor(v: string | null): string | null {
  if (!v) return null;
  return v.replace(/,?\s+(Inc\.?|Ltd\.?|Co\.?|Corporation|Corp\.?|Systems|Technology|Trading|LLC)\b.*$/i, "").trim() || v;
}

/** Effective VLAN of a device: its scan VLAN, else the VLAN its MAC was learned in. */
export function deviceVlan(d: Device): number | null {
  return d.vlanId ?? d.switchPort?.vlanId ?? null;
}

const ROLE_RANK: Record<DeviceRole, number> = { firewall: 0, router: 0, switch: 1, access_point: 2, host: 3 };

function roleFromCaps(caps: readonly string[]): DeviceRole | null {
  if (caps.includes("firewall")) return "firewall";
  if (caps.includes("wlan_access_point")) return "access_point";
  if (caps.includes("switch")) return "switch";
  if (caps.includes("router")) return "router";
  return null;
}

// --- builder ---------------------------------------------------------------------------------------

interface InfraNode {
  id: string;
  role: DeviceRole;
  row: TopoDeviceInput | null;
  label: string;
  ip: string | null;
  macs: Set<string>;
  names: Set<string>;
  detail: string | null;
  synthetic: boolean;
  snmp: SnmpDeviceInfo | undefined;
  /** Other device keys that are the same box (same MAC seen in several VLANs). */
  aliasKeys: string[];
}

interface Link {
  a: string;
  b: string;
  portA: string | null;
  portB: string | null;
  vlans: Set<number>;
  native: number | null;
  source: "cam" | "cdp" | "switchport";
}

interface Endpoint {
  row: TopoDeviceInput;
  port: string | null;
  vlan: number | null;
  wireless: boolean;
  /** No switch port known: hangs off the per-VLAN anchor. */
  unattached: boolean;
}

interface Loc {
  sw: string;
  port: string;
}

const DEFAULT_INDIVIDUAL_MAX = 5;
const DEFAULT_PORT_CLUSTER_MIN = 4;
/** Default number of members an expanded cluster shows (and the "+N more" step). */
export const EXPAND_STEP = 60;

export const ROOT_ID = "root";
export const SCANNER_ID = "me";

function nodeIdForKey(key: string): string {
  return `d:${key}`;
}

export function buildTopology(input: TopologyInput, opts: TopologyOptions = {}): TopologyGraph {
  const individualMax = opts.individualMax ?? DEFAULT_INDIVIDUAL_MAX;
  const portClusterMin = opts.portClusterMin ?? DEFAULT_PORT_CLUSTER_MIN;
  const expanded = opts.expanded ?? new Map<string, number>();
  const roleF = opts.roles && opts.roles.size > 0 ? opts.roles : null;
  const vlanF = opts.vlans && opts.vlans.size > 0 ? opts.vlans : null;

  // 1. Indexes over device rows -------------------------------------------------------------------
  const byIp = new Map<string, TopoDeviceInput>();
  const byMac = new Map<string, TopoDeviceInput>();
  const byName = new Map<string, TopoDeviceInput>();
  const addName = (n: string | null | undefined, row: TopoDeviceInput): void => {
    if (!n) return;
    const l = n.trim().toLowerCase();
    if (l === "") return;
    const prev = byName.get(l);
    // Infrastructure wins name collisions (switch names are what CAM tables refer to).
    if (!prev || (prev.device.role === "host" && row.device.role !== "host")) byName.set(l, row);
    const short = l.split(".")[0];
    if (short && short !== l && !byName.has(short)) byName.set(short, row);
  };
  for (const row of input.devices) {
    const d = row.device;
    const ips = [d.ip, ...d.extraIps];
    for (const ip of ips) {
      const prev = byIp.get(ip);
      if (!prev || (prev.device.vlanId !== null && d.vlanId === null)) byIp.set(ip, row);
    }
    const mac = normMac(d.mac);
    if (mac) {
      const prev = byMac.get(mac);
      if (!prev || (prev.device.role === "host" && d.role !== "host")) byMac.set(mac, row);
    }
    const s = input.snmp[row.key];
    for (const n of [row.hostname, d.hostname, d.dnsName, d.mdnsName, d.smbName, d.neighbor?.systemName, d.neighbor?.deviceId, s?.sysName]) {
      addName(n, row);
    }
  }

  // 2. Infrastructure nodes ----------------------------------------------------------------------------
  const infra = new Map<string, InfraNode>();
  /** Device key -> infra node id (a box seen in several VLANs maps to one node). */
  const infraOfKey = new Map<string, string>();
  const infraOfMac = new Map<string, string>();
  const synthByName = new Map<string, string>();

  const infraForRow = (row: TopoDeviceInput, forceRole?: DeviceRole): InfraNode => {
    const existing = infraOfKey.get(row.key);
    if (existing) {
      const n = infra.get(existing)!;
      if (forceRole && n.role === "host") n.role = forceRole;
      return n;
    }
    const d = row.device;
    const mac = normMac(d.mac);
    // Same MAC already an infra node (L3 switch answering in several VLANs): alias it.
    const same = mac ? infraOfMac.get(mac) : undefined;
    if (same) {
      const n = infra.get(same)!;
      n.aliasKeys.push(row.key);
      infraOfKey.set(row.key, same);
      return n;
    }
    const s = input.snmp[row.key];
    const role: DeviceRole = d.role !== "host" ? d.role : (forceRole ?? (s && s.role !== "host" ? s.role : "switch"));
    const platform = d.neighbor?.platform ?? null;
    const vendor = shortVendor(d.vendor);
    const node: InfraNode = {
      id: nodeIdForKey(row.key),
      role,
      row,
      label: displayName(d, row.hostname, s),
      ip: d.ip,
      macs: new Set(mac ? [mac] : []),
      names: new Set(),
      detail: platform ? (vendor && !platform.toLowerCase().includes(vendor.toLowerCase().split(" ")[0] ?? "") ? `${vendor} ${platform}` : platform) : vendor,
      synthetic: false,
      snmp: s,
      aliasKeys: [],
    };
    if (d.neighbor) {
      const sm = normMac(d.neighbor.sourceMac);
      if (sm) node.macs.add(sm);
    }
    infra.set(node.id, node);
    infraOfKey.set(row.key, node.id);
    for (const m of node.macs) if (!infraOfMac.has(m)) infraOfMac.set(m, node.id);
    return node;
  };

  for (const row of input.devices) {
    const d = row.device;
    const s = input.snmp[row.key];
    if (d.role !== "host" || (s && s.role !== "host")) infraForRow(row);
  }

  const syntheticInfra = (name: string, ip: string | null, role: DeviceRole, detail: string | null, mac?: string): InfraNode => {
    const keys = [name.toLowerCase(), name.toLowerCase().split(".")[0] ?? "", ip ?? ""].filter((k) => k !== "");
    for (const k of keys) {
      const id = synthByName.get(k);
      if (id) {
        const n = infra.get(id)!;
        if (mac) n.macs.add(mac);
        if (!n.ip && ip) n.ip = ip;
        return n;
      }
    }
    const id = `s:${keys[0] ?? "unknown"}`;
    const node: InfraNode = {
      id,
      role,
      row: null,
      label: name || ip || "Unknown switch",
      ip,
      macs: new Set(mac ? [mac] : []),
      names: new Set(keys),
      detail,
      synthetic: true,
      snmp: undefined,
      aliasKeys: [],
    };
    infra.set(id, node);
    for (const k of keys) synthByName.set(k, id);
    if (mac && !infraOfMac.has(mac)) infraOfMac.set(mac, id);
    return node;
  };

  /** Switch named by a CAM entry -> infra node id. */
  const switchCache = new Map<string, string>();
  const resolveSwitch = (name: string, ip: string | null): string => {
    const ck = `${name}|${ip ?? ""}`;
    const cached = switchCache.get(ck);
    if (cached) return cached;
    let row = ip ? byIp.get(ip) : undefined;
    if (!row && name) row = byName.get(name.toLowerCase()) ?? byName.get(name.toLowerCase().split(".")[0] ?? "");
    const id = row ? infraForRow(row, "switch").id : syntheticInfra(name, ip, "switch", null).id;
    switchCache.set(ck, id);
    return id;
  };

  /** CDP/LLDP advert -> infra node id (null for non-infrastructure such as phones). */
  const resolveNeighbor = (n: CdpLldpNeighbor): string | null => {
    const mac = normMac(n.sourceMac);
    let row: TopoDeviceInput | undefined;
    for (const a of n.managementAddrs) {
      row = byIp.get(a);
      if (row) break;
    }
    if (!row && mac) row = byMac.get(mac);
    if (!row) {
      for (const nm of [n.systemName, n.deviceId]) {
        if (!nm) continue;
        const l = nm.toLowerCase();
        row = byName.get(l) ?? byName.get(l.split(".")[0] ?? "");
        if (row) break;
      }
    }
    const capRole = roleFromCaps(n.capabilities);
    if (row) {
      if (row.device.role === "host" && !capRole && !infraOfKey.has(row.key)) return null;
      const node = infraForRow(row, capRole ?? "switch");
      if (mac) {
        node.macs.add(mac);
        if (!infraOfMac.has(mac)) infraOfMac.set(mac, node.id);
      }
      return node.id;
    }
    if (!capRole) return null;
    const name = n.systemName ?? n.deviceId;
    return syntheticInfra(name, n.managementAddrs[0] ?? null, capRole, n.platform, mac || undefined).id;
  };

  // 3. CAM index ------------------------------------------------------------------------------------------
  const portMacs = new Map<string, Map<string, Set<string>>>();
  const portVlans = new Map<string, Map<string, Set<number>>>();
  const macLoc = new Map<string, Loc[]>();
  /** Port the backend chose for a MAC (`device.switchPort`), preferred on ties. */
  const preferred = new Map<string, Loc>();
  let camEntries = 0;
  /** CAM entries carrying PoE, per switch node (PoE drawn when SNMP has no budget). */
  const portPoe = new Map<string, SwitchPortMapping[]>();

  const addCam = (m: SwitchPortMapping, isPreferred: boolean): void => {
    const mac = normMac(m.mac);
    if (!mac || !m.portName) return;
    const sw = resolveSwitch(m.switchName, m.switchIp);
    const port = shortPort(m.portName);
    let ports = portMacs.get(sw);
    if (!ports) portMacs.set(sw, (ports = new Map()));
    let set = ports.get(port);
    if (!set) ports.set(port, (set = new Set()));
    if (!set.has(mac)) {
      set.add(mac);
      const locs = macLoc.get(mac);
      if (locs) locs.push({ sw, port });
      else macLoc.set(mac, [{ sw, port }]);
    }
    if (m.vlanId !== null && m.vlanId > 0) {
      let vp = portVlans.get(sw);
      if (!vp) portVlans.set(sw, (vp = new Map()));
      let vs = vp.get(port);
      if (!vs) vp.set(port, (vs = new Set()));
      vs.add(m.vlanId);
    }
    if (isPreferred) preferred.set(mac, { sw, port });
    if (m.poe && m.poe.watts !== null) {
      let pp = portPoe.get(sw);
      if (!pp) portPoe.set(sw, (pp = []));
      pp.push({ ...m, portName: port });
    }
  };
  for (const m of input.portMappings) {
    addCam(m, false);
    camEntries++;
  }
  for (const row of input.devices) {
    const sp = row.device.switchPort;
    if (sp) addCam({ ...sp, mac: row.device.mac ?? sp.mac }, true);
  }

  /** Learned-MAC count of a port: CAM entries, or SNMP's per-port count when larger. */
  const snmpCounts = new Map<string, Map<string, number>>();
  for (const n of infra.values()) {
    const counts = n.snmp?.portMacCounts;
    if (!Array.isArray(counts) || counts.length === 0) continue;
    const m = new Map<string, number>();
    for (const c of counts) m.set(shortPort(c.portName), c.macCount);
    snmpCounts.set(n.id, m);
  }
  const portCount = (sw: string, port: string): number =>
    Math.max(portMacs.get(sw)?.get(port)?.size ?? 0, snmpCounts.get(sw)?.get(port) ?? 0);

  /**
   * Uplink ports: where a gateway's (firewall / router) MAC is learned. A MAC seen there is
   * upstream of the switch, so it is not plugged into that switch.
   */
  const uplinks = new Map<string, Set<string>>();
  const computeUplinks = (): void => {
    uplinks.clear();
    for (const n of infra.values()) {
      if (n.role !== "firewall" && n.role !== "router") continue;
      for (const m of n.macs) {
        for (const loc of macLoc.get(m) ?? []) {
          const set = uplinks.get(loc.sw);
          if (set) set.add(loc.port);
          else uplinks.set(loc.sw, new Set([loc.port]));
        }
      }
    }
  };

  /**
   * Best location of a MAC: the port with the fewest learned MACs (the edge port), looking at
   * downstream (non-uplink) ports first.
   */
  const bestLoc = (macs: Iterable<string>, exclude: string | null, downstreamFirst = true): Loc | null => {
    const list = [...macs];
    const pick = (skipUplinks: boolean): Loc | null => {
      let best: Loc | null = null;
      let bestCount = Infinity;
      let bestPref = false;
      for (const mac of list) {
        const pref = preferred.get(mac);
        for (const loc of macLoc.get(mac) ?? []) {
          if (loc.sw === exclude) continue;
          if (skipUplinks && uplinks.get(loc.sw)?.has(loc.port)) continue;
          const c = portCount(loc.sw, loc.port);
          const isPref = pref !== undefined && pref.sw === loc.sw && pref.port === loc.port;
          if (
            c < bestCount ||
            (c === bestCount && isPref && !bestPref) ||
            (c === bestCount && isPref === bestPref && best !== null && naturalCmp(`${loc.sw}|${loc.port}`, `${best.sw}|${best.port}`) < 0)
          ) {
            best = loc;
            bestCount = c;
            bestPref = isPref;
          }
        }
      }
      return best;
    };
    return (downstreamFirst ? pick(true) : null) ?? pick(false);
  };

  // 4. Neighbors heard by this computer --------------------------------------------------------------
  const links = new Map<string, Link>();
  const linkKey = (a: string, b: string): string => (a < b ? `${a}\u0000${b}` : `${b}\u0000${a}`);
  const addLink = (a: string, portA: string | null, b: string, portB: string | null, vlans: Iterable<number>, native: number | null, source: Link["source"]): void => {
    if (a === b) return;
    const k = linkKey(a, b);
    const l = links.get(k);
    if (!l) {
      links.set(k, { a, b, portA, portB, vlans: new Set(vlans), native, source });
      return;
    }
    const pa = l.a === a ? portA : portB;
    const pb = l.a === a ? portB : portA;
    if (!l.portA && pa) l.portA = pa;
    if (!l.portB && pb) l.portB = pb;
    for (const v of vlans) l.vlans.add(v);
    if (l.native === null) l.native = native;
  };

  let scannerLink: { parent: string; iface: string; port: string | null; native: number | null; voice: number | null } | null = null;
  const neighborPrio = (id: string): number => {
    const r = infra.get(id)?.role;
    return r === "switch" ? 0 : r === "router" ? 1 : r === "firewall" ? 2 : 3;
  };
  for (const n of input.neighbors) {
    const id = resolveNeighbor(n);
    if (!id) continue;
    const cand = { parent: id, iface: n.localInterface, port: n.portId ? shortPort(n.portId) : null, native: n.nativeVlan, voice: n.voiceVlan };
    if (!scannerLink || neighborPrio(id) < neighborPrio(scannerLink.parent)) scannerLink = cand;
  }
  // Devices that carry a matched advert but whose advert was not in the neighbor list.
  for (const row of input.devices) {
    if (row.device.neighbor && !infraOfKey.has(row.key)) resolveNeighbor(row.device.neighbor);
  }

  // 5. Infrastructure links from the CAM tables ---------------------------------------------------
  computeUplinks();
  for (const node of infra.values()) {
    if (node.macs.size === 0) continue;
    const gateway = node.role === "firewall" || node.role === "router";
    const loc = bestLoc(node.macs, node.id, !gateway);
    if (!loc) continue;
    // Our side: the port on this node where the other switch's MACs are learned.
    let ownPort: string | null = null;
    const other = infra.get(loc.sw);
    if (other && portMacs.has(node.id)) {
      let bestC = Infinity;
      for (const [port, macs] of portMacs.get(node.id)!) {
        let hit = false;
        for (const m of other.macs) if (macs.has(m)) hit = true;
        if (hit && portCount(node.id, port) < bestC) {
          bestC = portCount(node.id, port);
          ownPort = port;
        }
      }
    }
    const vl = new Set<number>(portVlans.get(loc.sw)?.get(loc.port) ?? []);
    if (ownPort) for (const v of portVlans.get(node.id)?.get(ownPort) ?? []) vl.add(v);
    addLink(loc.sw, loc.port, node.id, ownPort, vl, null, "cam");
  }

  // 6. Ranks: BFS from firewalls / routers over the infrastructure links ---------------------------
  const adj = new Map<string, string[]>();
  for (const l of links.values()) {
    (adj.get(l.a) ?? adj.set(l.a, []).get(l.a)!).push(l.b);
    (adj.get(l.b) ?? adj.set(l.b, []).get(l.b)!).push(l.a);
  }
  const infraList = [...infra.values()].sort((x, y) => ROLE_RANK[x.role] - ROLE_RANK[y.role] || naturalCmp(x.label, y.label));
  const depth = new Map<string, number>();
  const parentOf = new Map<string, string | null>();
  const treeLinks = new Set<string>();
  const bfs = (starts: string[], startDepth: number): void => {
    const queue: string[] = [];
    for (const s of starts) {
      if (depth.has(s)) continue;
      depth.set(s, startDepth);
      if (!parentOf.has(s)) parentOf.set(s, null);
      queue.push(s);
    }
    for (let qi = 0; qi < queue.length; qi++) {
      const cur = queue[qi]!;
      const nexts = [...(adj.get(cur) ?? [])].sort((x, y) => {
        const nx = infra.get(x)!;
        const ny = infra.get(y)!;
        return ROLE_RANK[nx.role] - ROLE_RANK[ny.role] || naturalCmp(nx.label, ny.label);
      });
      for (const nx of nexts) {
        if (depth.has(nx)) continue;
        depth.set(nx, depth.get(cur)! + 1);
        parentOf.set(nx, cur);
        treeLinks.add(linkKey(cur, nx));
        queue.push(nx);
      }
    }
  };
  const gateways = infraList.filter((n) => n.role === "firewall" || n.role === "router").map((n) => n.id);
  bfs(gateways, 0);
  const primaryRoot = gateways[0] ?? null;
  const inferredEdges: Array<{ parent: string; child: string; minlen: number }> = [];
  // Components without a gateway: root them at their best-connected switch.
  for (;;) {
    const rest = infraList.filter((n) => !depth.has(n.id));
    if (rest.length === 0) break;
    const comp = new Set<string>();
    const stack = [rest[0]!.id];
    while (stack.length > 0) {
      const c = stack.pop()!;
      if (comp.has(c)) continue;
      comp.add(c);
      for (const x of adj.get(c) ?? []) if (!depth.has(x)) stack.push(x);
    }
    const members = rest.filter((n) => comp.has(n.id));
    const top = [...members].sort(
      (x, y) => ROLE_RANK[x.role] - ROLE_RANK[y.role] || (adj.get(y.id)?.length ?? 0) - (adj.get(x.id)?.length ?? 0) || naturalCmp(x.label, y.label),
    )[0]!;
    if (primaryRoot) {
      parentOf.set(top.id, primaryRoot);
      bfs([top.id], 1);
      inferredEdges.push({ parent: primaryRoot, child: top.id, minlen: Math.max(1, ROLE_RANK[top.role]) });
      // Re-rank by role so an AP without a link sits below the switches.
      const shift = Math.max(1, ROLE_RANK[top.role]) - 1;
      if (shift > 0) for (const id of comp) depth.set(id, (depth.get(id) ?? 1) + shift);
    } else {
      bfs([top.id], 0);
    }
  }

  // 7. Scanner node --------------------------------------------------------------------------------
  const anyInfra = infra.size > 0;
  const hasInfraData = links.size > 0 || scannerLink !== null || camEntries > 0;

  // 8. Endpoints -------------------------------------------------------------------------------------
  /** `${switch}|${port}` -> infrastructure node linked through that port. */
  const infraOnPort = new Map<string, string>();
  for (const l of links.values()) {
    if (l.portA) infraOnPort.set(`${l.a}|${l.portA}`, l.b);
    if (l.portB) infraOnPort.set(`${l.b}|${l.portB}`, l.a);
  }
  const endpointsOf = new Map<string, Endpoint[]>();
  const unattached: Endpoint[] = [];
  let endpointCount = 0;
  for (const row of input.devices) {
    if (infraOfKey.has(row.key)) continue;
    endpointCount++;
    const d = row.device;
    const vlan = deviceVlan(d);
    let loc: Loc | null = null;
    if (d.switchPort) loc = { sw: resolveSwitch(d.switchPort.switchName, d.switchPort.switchIp), port: shortPort(d.switchPort.portName) };
    else {
      const mac = normMac(d.mac);
      if (mac) loc = bestLoc([mac], null);
    }
    if (!loc) {
      unattached.push({ row, port: null, vlan, wireless: false, unattached: true });
      continue;
    }
    let parent = loc.sw;
    let port: string | null = loc.port;
    let wireless = false;
    const behind = infraOnPort.get(`${loc.sw}|${loc.port}`);
    if (behind) {
      const b = infra.get(behind)!;
      if (b.role === "access_point") {
        parent = behind;
        port = null;
        wireless = true;
      } else if ((depth.get(behind) ?? 0) > (depth.get(loc.sw) ?? 0)) {
        // Learned on an uplink towards a switch we have no CAM table for: it is behind that switch.
        parent = behind;
        port = null;
      }
    }
    const list = endpointsOf.get(parent);
    const ep: Endpoint = { row, port, vlan, wireless, unattached: false };
    if (list) list.push(ep);
    else endpointsOf.set(parent, [ep]);
  }

  // 9. Filters -----------------------------------------------------------------------------------
  const vlanKey = (v: number | null): number => v ?? UNTAGGED;
  const endpointVisible = (ep: Endpoint): boolean =>
    (roleF === null || roleF.has(ep.row.device.role)) && (vlanF === null || vlanF.has(vlanKey(ep.vlan)));
  const infraVlans = new Map<string, Set<number>>();
  for (const n of infra.values()) infraVlans.set(n.id, new Set(n.row?.device.vlanId ? [n.row.device.vlanId] : []));
  for (const l of links.values()) {
    for (const v of l.vlans) {
      infraVlans.get(l.a)?.add(v);
      infraVlans.get(l.b)?.add(v);
    }
  }
  for (const v of input.vlans) {
    if (!v.switchName) continue;
    const id = byName.get(v.switchName.toLowerCase()) ? infraOfKey.get(byName.get(v.switchName.toLowerCase())!.key) : synthByName.get(v.switchName.toLowerCase());
    if (id) infraVlans.get(id)?.add(v.id);
  }
  const visible = new Set<string>();
  const markWithAncestors = (id: string): void => {
    let cur: string | null | undefined = id;
    while (cur && !visible.has(cur)) {
      visible.add(cur);
      cur = parentOf.get(cur);
    }
  };
  for (const n of infra.values()) {
    const roleOk = roleF === null || roleF.has(n.role);
    const vlanOk = vlanF === null || [...(infraVlans.get(n.id) ?? [])].some((v) => vlanF.has(v));
    if (roleOk && vlanOk) markWithAncestors(n.id);
  }
  const visibleEndpoints = new Map<string, Endpoint[]>();
  for (const [parent, eps] of endpointsOf) {
    const vis = eps.filter(endpointVisible);
    if (vis.length === 0) continue;
    visibleEndpoints.set(parent, vis);
    markWithAncestors(parent);
  }
  const visibleUnattached = unattached.filter(endpointVisible);

  // 10. Emit nodes + edges ------------------------------------------------------------------------------
  const nodes: TopoNode[] = [];
  const edges: TopoEdge[] = [];
  const nodeOfKey = new Map<string, string>();
  let clusterCount = 0;

  const baseNode = (id: string, kind: TopoNodeKind, parentId: string | null, dep: number): TopoNode => ({
    id,
    kind,
    role: null,
    label: "",
    ip: null,
    mac: null,
    detail: null,
    vlans: [],
    deviceKey: null,
    parentId,
    depth: dep,
    port: null,
    status: "ok",
    note: null,
    clusterKind: null,
    count: 1,
    portsLabel: null,
    memberKeys: [],
    members: [],
    expanded: false,
    more: 0,
    deviceKind: null,
    poe: null,
    poeUsage: null,
  });

  // Anchor for endpoints nobody knows the switch of.
  let anchor: string | null = null;
  if (visibleUnattached.length > 0 || (!anyInfra && input.devices.length > 0)) {
    if (primaryRoot && visible.has(primaryRoot)) anchor = primaryRoot;
    else if (primaryRoot && visibleUnattached.length > 0) {
      markWithAncestors(primaryRoot);
      anchor = primaryRoot;
    } else {
      const firstTop = infraList.find((n) => visible.has(n.id) && (parentOf.get(n.id) ?? null) === null);
      anchor = firstTop?.id ?? ROOT_ID;
    }
  }

  const emitEdge = (e: Omit<TopoEdge, "id">): void => {
    edges.push({ id: `e:${e.source}->${e.target}`, ...e });
  };

  const infraNodeOut = (n: InfraNode): TopoNode => {
    const dep = depth.get(n.id) ?? 0;
    const out = baseNode(n.id, "infra", parentOf.get(n.id) ?? null, dep);
    out.role = n.role;
    out.label = n.label;
    out.ip = n.ip;
    out.mac = n.row?.device.mac ?? ([...n.macs][0] ?? null);
    out.detail = n.detail;
    out.vlans = [...(infraVlans.get(n.id) ?? [])].sort((a, b) => a - b);
    out.deviceKey = n.row?.key ?? null;
    out.memberKeys = n.row ? [n.row.key, ...n.aliasKeys] : [];
    if (n.role === "switch") {
      const usage = budgetUsage(n.snmp?.poeBudget);
      const drawn = usage ? null : portPoeTotal(portPoe.get(n.id) ?? []);
      out.poeUsage = usage ?? (drawn ? { consumed: drawn.watts, nominal: null, pct: null, tone: "none", ports: drawn.ports } : null);
    }
    if (n.synthetic) {
      out.status = "unknown";
      out.note = "Known only from CAM tables / CDP-LLDP; not answering the scan.";
    } else if (n.snmp?.partial) {
      out.status = "warn";
      out.note = "SNMP data is partial.";
    }
    if (inferredEdges.some((e) => e.child === n.id)) {
      out.status = out.status === "ok" ? "warn" : out.status;
      out.note = [out.note, "No link data: placed under the gateway by role."].filter(Boolean).join(" ");
    }
    if (n.row) {
      nodeOfKey.set(n.row.key, n.id);
      for (const k of n.aliasKeys) nodeOfKey.set(k, n.id);
    }
    return out;
  };

  const memberOf = (ep: Endpoint): TopoMember => ({
    deviceKind: deviceKindOf(ep.row.device),
    poeWatts: ep.row.device.poe?.watts ?? null,
    key: ep.row.key,
    label: displayName(ep.row.device, ep.row.hostname),
    ip: ep.row.device.ip,
    mac: ep.row.device.mac,
    vendor: shortVendor(ep.row.device.vendor),
    port: ep.port,
    vlan: ep.vlan,
  });

  const endpointNode = (ep: Endpoint, parentId: string, dep: number): void => {
    const d = ep.row.device;
    const id = nodeIdForKey(ep.row.key);
    const out = baseNode(id, "device", parentId, dep);
    out.role = d.role;
    out.label = displayName(d, ep.row.hostname);
    out.ip = d.ip;
    out.mac = d.mac;
    out.detail = shortVendor(d.vendor);
    out.vlans = ep.vlan !== null ? [ep.vlan] : [];
    out.deviceKey = ep.row.key;
    out.memberKeys = [ep.row.key];
    out.port = ep.port;
    out.deviceKind = deviceKindOf(d);
    out.poe = d.poe ?? null;
    nodes.push(out);
    nodeOfKey.set(ep.row.key, id);
    const unknown = ep.unattached;
    emitEdge({
      source: parentId,
      target: id,
      kind: ep.wireless ? "wireless" : unknown ? "inferred" : "access",
      sourcePort: ep.port,
      targetPort: null,
      vlans: ep.vlan !== null ? [ep.vlan] : [],
      nativeVlan: null,
      label: ep.wireless ? "Wi-Fi" : ep.port,
      sublabel: unknown ? (ep.vlan !== null ? `VLAN ${ep.vlan}` : "untagged") : null,
      tree: true,
      minlen: 1,
    });
  };

  const clusterNode = (id: string, kind: ClusterKind, eps: Endpoint[], parentId: string, dep: number, title: string): void => {
    clusterCount++;
    const out = baseNode(id, "cluster", parentId, dep);
    out.role = "host";
    out.clusterKind = kind;
    out.count = eps.length;
    const ports = new Set<string>();
    const vlanSet = new Set<number>();
    const vendors = new Map<string, number>();
    const keys = new Array<string>(eps.length);
    for (let i = 0; i < eps.length; i++) {
      const ep = eps[i]!;
      keys[i] = ep.row.key;
      nodeOfKey.set(ep.row.key, id);
      if (ep.port) ports.add(ep.port);
      if (ep.vlan !== null) vlanSet.add(ep.vlan);
      const v = shortVendor(ep.row.device.vendor);
      if (v) vendors.set(v, (vendors.get(v) ?? 0) + 1);
    }
    out.memberKeys = keys;
    out.portsLabel = ports.size > 0 ? compressPorts(ports) : null;
    out.vlans = [...vlanSet].sort((a, b) => a - b);
    out.label = title;
    out.detail =
      [...vendors]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([v, c]) => `${v} ${c}`)
        .join(" · ") || null;
    const limit = expanded.get(id);
    if (limit !== undefined && limit > 0) {
      out.expanded = true;
      const prio = opts.priorityKeys;
      const sorted = [...eps].sort(
        (a, b) =>
          (prio ? (prio.has(a.row.key) ? 0 : 1) - (prio.has(b.row.key) ? 0 : 1) : 0) ||
          naturalCmp(a.port ?? "~", b.port ?? "~") ||
          (ipSortKey(a.row.device.ip) < ipSortKey(b.row.device.ip) ? -1 : ipSortKey(a.row.device.ip) > ipSortKey(b.row.device.ip) ? 1 : 0),
      );
      out.members = sorted.slice(0, limit).map(memberOf);
      out.more = Math.max(0, eps.length - limit);
    }
    nodes.push(out);
    const unknown = kind === "unattached";
    emitEdge({
      source: parentId,
      target: id,
      kind: kind === "wireless" ? "wireless" : unknown ? "inferred" : "access",
      sourcePort: out.portsLabel,
      targetPort: null,
      vlans: out.vlans,
      nativeVlan: null,
      label: kind === "wireless" ? "Wi-Fi" : out.portsLabel,
      sublabel: unknown || kind === "vlan" ? (out.vlans.length > 0 ? `VLAN ${compressVlans(out.vlans)}` : "untagged") : null,
      tree: true,
      minlen: 1,
    });
  };

  const vlanTitle = (v: number | null): string => {
    if (v === null) return "untagged";
    const name = input.vlans.find((x) => x.id === v)?.name;
    return name ? `VLAN ${v} · ${name}` : `VLAN ${v}`;
  };

  const emitEndpoints = (parentId: string, eps: Endpoint[], dep: number, kindHint: "wired" | "wireless" | "unattached"): void => {
    if (eps.length <= individualMax) {
      for (const ep of sortEndpoints(eps)) endpointNode(ep, parentId, dep);
      return;
    }
    let rest = eps;
    if (kindHint === "wired") {
      const byPort = new Map<string, Endpoint[]>();
      for (const ep of eps) {
        if (!ep.port || ep.wireless) continue;
        const l = byPort.get(ep.port);
        if (l) l.push(ep);
        else byPort.set(ep.port, [ep]);
      }
      const portClustered = new Set<Endpoint>();
      for (const port of [...byPort.keys()].sort(naturalCmp)) {
        const l = byPort.get(port)!;
        if (l.length < portClusterMin) continue;
        for (const ep of l) portClustered.add(ep);
        clusterNode(`c:${parentId}|p:${port}`, "port", l, parentId, dep, `${l.length} hosts on ${port}`);
      }
      if (portClustered.size > 0) rest = eps.filter((ep) => !portClustered.has(ep));
    }
    const byVlan = new Map<number, Endpoint[]>();
    for (const ep of rest) {
      const k = vlanKey(ep.vlan);
      const l = byVlan.get(k);
      if (l) l.push(ep);
      else byVlan.set(k, [ep]);
    }
    for (const v of [...byVlan.keys()].sort((a, b) => a - b)) {
      const l = byVlan.get(v)!;
      if (l.length <= 2) {
        for (const ep of sortEndpoints(l)) endpointNode(ep, parentId, dep);
        continue;
      }
      const vlan = v === UNTAGGED ? null : v;
      if (kindHint === "wireless") clusterNode(`c:${parentId}|w:${v}`, "wireless", l, parentId, dep, `${l.length} wireless clients`);
      else if (kindHint === "unattached") clusterNode(`c:${parentId}|u:${v}`, "unattached", l, parentId, dep, `${vlanTitle(vlan)} · ${l.length} hosts`);
      else clusterNode(`c:${parentId}|v:${v}`, "vlan", l, parentId, dep, `${l.length} hosts`);
    }
  };

  // Root (no infrastructure at all).
  if (anchor === ROOT_ID) {
    const root = baseNode(ROOT_ID, "root", null, 0);
    root.label = "Network";
    root.detail = hasInfraData ? null : "No CDP/LLDP or SNMP data";
    root.status = "unknown";
    root.note = "Synthetic root: turn on CDP/LLDP and SNMP for the real hierarchy.";
    const vs = new Set<number>();
    for (const ep of visibleUnattached) if (ep.vlan !== null) vs.add(ep.vlan);
    root.vlans = [...vs].sort((a, b) => a - b);
    nodes.push(root);
  }

  // Depth-first from the roots so related nodes are emitted together (stable layout order).
  const childrenOf = new Map<string, InfraNode[]>();
  for (const n of infraList) {
    const p = parentOf.get(n.id) ?? null;
    if (p === null) continue;
    const l = childrenOf.get(p);
    if (l) l.push(n);
    else childrenOf.set(p, [n]);
  }
  const inferredSet = new Map(inferredEdges.map((e) => [e.child, e]));
  const emitInfra = (n: InfraNode): void => {
    if (!visible.has(n.id)) return;
    const out = infraNodeOut(n);
    nodes.push(out);
    const p = parentOf.get(n.id) ?? null;
    if (p !== null) {
      const inf = inferredSet.get(n.id);
      if (inf) {
        emitEdge({
          source: p,
          target: n.id,
          kind: "inferred",
          sourcePort: null,
          targetPort: null,
          vlans: [],
          nativeVlan: null,
          label: null,
          sublabel: "link unknown",
          tree: true,
          minlen: inf.minlen,
        });
      } else {
        const l = links.get(linkKey(p, n.id))!;
        const pPort = l.a === p ? l.portA : l.portB;
        const cPort = l.a === p ? l.portB : l.portA;
        edges.push(linkEdge(p, n.id, pPort, cPort, l, infra.get(p)!.role, n.role, true));
      }
    }
    const kids = (childrenOf.get(n.id) ?? []).slice().sort((x, y) => {
      const lx = links.get(linkKey(n.id, x.id));
      const ly = links.get(linkKey(n.id, y.id));
      const px = lx ? (lx.a === n.id ? lx.portA : lx.portB) : null;
      const py = ly ? (ly.a === n.id ? ly.portA : ly.portB) : null;
      return ROLE_RANK[x.role] - ROLE_RANK[y.role] || naturalCmp(px ?? "~", py ?? "~") || naturalCmp(x.label, y.label);
    });
    for (const k of kids) emitInfra(k);
    if (n.id === scannerLink?.parent && roleF === null && vlanF === null) emitScanner(n.id, (depth.get(n.id) ?? 0) + 1);
    const eps = visibleEndpoints.get(n.id);
    if (eps) emitEndpoints(n.id, eps, (depth.get(n.id) ?? 0) + 1, n.role === "access_point" ? "wireless" : "wired");
    if (anchor === n.id && visibleUnattached.length > 0) emitEndpoints(n.id, visibleUnattached, (depth.get(n.id) ?? 0) + 1, "unattached");
  };

  const emitScanner = (parentId: string, dep: number): void => {
    if (!scannerLink) return;
    const me = baseNode(SCANNER_ID, "scanner", parentId, dep);
    me.label = "This computer";
    me.detail = scannerLink.iface;
    me.port = scannerLink.port;
    const vl = [scannerLink.native, scannerLink.voice].filter((v): v is number => v !== null);
    me.vlans = [...new Set(vl)];
    me.note = "Where SweepR is plugged in (from the CDP/LLDP advert heard on this interface).";
    nodes.push(me);
    emitEdge({
      source: parentId,
      target: SCANNER_ID,
      kind: "access",
      sourcePort: scannerLink.port,
      targetPort: scannerLink.iface,
      vlans: vl,
      nativeVlan: scannerLink.native,
      label: scannerLink.port ? `${scannerLink.port} ↔ ${scannerLink.iface}` : scannerLink.iface,
      sublabel: vlanLabel(scannerLink.voice !== null ? [scannerLink.voice] : [], scannerLink.native)?.replace(/^VLAN /, "voice ") ?? null,
      tree: true,
      minlen: 1,
    });
  };

  for (const n of infraList) if ((parentOf.get(n.id) ?? null) === null) emitInfra(n);
  if (anchor === ROOT_ID) emitEndpoints(ROOT_ID, visibleUnattached.length > 0 ? visibleUnattached : [], 1, "unattached");

  // Cross links (redundant uplinks, HA pairs): drawn, but not used for ranking.
  const emitted = new Set(nodes.map((n) => n.id));
  for (const [k, l] of links) {
    if (treeLinks.has(k) || !emitted.has(l.a) || !emitted.has(l.b)) continue;
    const [up, down] = (depth.get(l.a) ?? 0) <= (depth.get(l.b) ?? 0) ? [l.a, l.b] : [l.b, l.a];
    const upPort = up === l.a ? l.portA : l.portB;
    const downPort = up === l.a ? l.portB : l.portA;
    edges.push(linkEdge(up, down, upPort, downPort, l, infra.get(up)!.role, infra.get(down)!.role, false));
  }

  return {
    nodes,
    edges,
    nodeOfKey,
    stats: {
      devices: input.devices.length,
      infra: infra.size,
      endpoints: endpointCount,
      clusters: clusterCount,
      unattached: unattached.length,
      inferredLinks: inferredEdges.length,
      hasNeighbors: input.neighbors.length > 0 || input.devices.some((r) => r.device.neighbor !== null),
      hasCam: camEntries > 0 || preferred.size > 0,
      hasInfraData,
    },
  };
}

function linkEdge(
  source: string,
  target: string,
  sourcePort: string | null,
  targetPort: string | null,
  l: Link,
  sourceRole: DeviceRole,
  targetRole: DeviceRole,
  tree: boolean,
): TopoEdge {
  const vlans = [...l.vlans].sort((a, b) => a - b);
  const toAp = sourceRole === "access_point" || targetRole === "access_point";
  const kind: TopoEdgeKind = toAp && vlans.length <= 1 ? "access" : "trunk";
  // Unknown ends are left blank: "Gi1/0/48 ↔ Te1/1/1", "↔ Gi1/0/1", "Gi1/0/45 ↔".
  const ports = sourcePort || targetPort ? `${sourcePort ?? ""} ↔ ${targetPort ?? ""}`.trim() : null;
  return {
    id: `e:${source}->${target}`,
    source,
    target,
    kind,
    sourcePort,
    targetPort,
    vlans,
    nativeVlan: l.native,
    label: ports,
    sublabel: vlanLabel(vlans, l.native),
    tree,
    minlen: 1,
  };
}

function sortEndpoints(eps: Endpoint[]): Endpoint[] {
  return [...eps].sort(
    (a, b) =>
      naturalCmp(a.port ?? "~", b.port ?? "~") ||
      (ipSortKey(a.row.device.ip) < ipSortKey(b.row.device.ip) ? -1 : ipSortKey(a.row.device.ip) > ipSortKey(b.row.device.ip) ? 1 : 0),
  );
}

/** Ids of every cluster in the graph (for "expand all" style actions and tests). */
export function clusterIds(graph: TopologyGraph): string[] {
  return graph.nodes.filter((n) => n.kind === "cluster").map((n) => n.id);
}
