// Scan settings as edited in the toolbar, and their conversion to the backend `ScanConfig`.

import type { InterfaceInfo, ScanConfig, SnmpConfig, VlanSelection } from "./types.ts";
import { formatPorts, parsePorts, parseRange, parseVlanSelection, type Parsed } from "./lib/parse.ts";
import { DEFAULT_SCAN_PORTS } from "./lib/ports.ts";
import { ipv4ToNumber, numberToIpv4 } from "./lib/ip.ts";

export type VlanMode = "untagged" | "list" | "untagged_and_list" | "auto_detect";

export interface ScanSettings {
  /** Interface name; empty = backend default (default-route interface). */
  iface: string;
  range: string;
  vlanMode: VlanMode;
  vlanIds: string;
  ipv6: boolean;
  cdpLldp: boolean;
  discoverVlans: boolean;
  resolveNames: boolean;
  ports: string;
  snmpEnabled: boolean;
  /** Poll every host over SNMP instead of only likely infrastructure. */
  snmpAll: boolean;
  snmp: SnmpConfig;
}

export const DEFAULT_SNMP: SnmpConfig = {
  version: "v2c",
  community: "public",
  v3: null,
  port: 161,
  timeoutMs: 2000,
  retries: 1,
};

export const DEFAULT_SETTINGS: ScanSettings = {
  iface: "",
  range: "",
  vlanMode: "untagged",
  vlanIds: "",
  ipv6: false,
  cdpLldp: true,
  discoverVlans: false,
  resolveNames: true,
  ports: formatPorts(DEFAULT_SCAN_PORTS),
  snmpEnabled: false,
  snmpAll: false,
  snmp: DEFAULT_SNMP,
};

/** What gets written to localStorage: never SNMP secrets (community / v3 passwords). */
export function persistableSettings(s: ScanSettings): ScanSettings {
  return {
    ...s,
    snmp: {
      ...s.snmp,
      community: "public",
      v3: s.snmp.v3 ? { ...s.snmp.v3, authPassword: null, privPassword: null } : null,
    },
  };
}

export function vlanSelectionFrom(s: Pick<ScanSettings, "vlanMode" | "vlanIds">): Parsed<VlanSelection> {
  switch (s.vlanMode) {
    case "untagged":
      return { ok: true, value: { mode: "untagged" } };
    case "auto_detect":
      return { ok: true, value: { mode: "auto_detect" } };
    case "list": {
      if (s.vlanIds.trim() === "") return { ok: false, error: "enter VLAN IDs, e.g. 10, 20, 30-35" };
      const r = parseVlanSelection(s.vlanIds);
      if (!r.ok) return r;
      if (r.value.mode === "auto_detect") return { ok: false, error: "use Auto-Detect VLANs mode for 'auto'" };
      return r;
    }
    case "untagged_and_list": {
      if (s.vlanIds.trim() === "") return { ok: false, error: "enter VLAN IDs, e.g. 10, 20" };
      return parseVlanSelection(`untagged,${s.vlanIds}`);
    }
  }
}

export interface BuiltConfig {
  config: ScanConfig;
  targetCount: number | null;
}

export function buildScanConfig(s: ScanSettings): Parsed<BuiltConfig> {
  const range = parseRange(s.range);
  if (!range.ok) return { ok: false, error: `Range: ${range.error}` };
  const vlans = vlanSelectionFrom(s);
  if (!vlans.ok) return { ok: false, error: `VLAN: ${vlans.error}` };
  const ports = parsePorts(s.ports);
  if (!ports.ok) return { ok: false, error: `Ports: ${ports.error}` };
  if (s.snmpEnabled && s.snmp.version === "v3") {
    const problem = snmpV3Problem(s.snmp);
    if (problem) return { ok: false, error: `${problem} (SNMP Settings)` };
  }
  const config: ScanConfig = {
    interface: s.iface === "" ? null : s.iface,
    range: range.value.spec,
    vlans: vlans.value,
    discoverVlans: s.discoverVlans || vlans.value.mode === "auto_detect",
    cdpLldp: s.cdpLldp,
    snmp: s.snmpEnabled ? snmpForWire(s.snmp) : null,
    snmpAll: s.snmpEnabled && s.snmpAll,
    ipv6: s.ipv6,
    ports: ports.value,
    resolveNames: s.resolveNames,
    timeoutMs: 1500,
    retries: 1,
    ratePps: 2000,
    concurrency: 512,
    listenSecs: 10,
    webIdentity: true,
  };
  return { ok: true, value: { config, targetCount: range.value.spec === null ? null : range.value.count } };
}

/** RFC 3414 minimum SNMPv3 password length (the backend rejects shorter ones). */
export const MIN_SNMPV3_PASSWORD_LEN = 8;

/** Why an SNMPv3 configuration would be rejected by the backend, or `null` when it is fine. */
export function snmpV3Problem(c: SnmpConfig): string | null {
  if (c.version !== "v3") return null;
  const v3 = c.v3;
  if (!v3 || v3.username.trim() === "") return "SNMPv3 requires a username";
  const auth = v3.authPassword ?? "";
  const priv = v3.privPassword ?? "";
  if ((auth !== "" && auth.length < MIN_SNMPV3_PASSWORD_LEN) || (priv !== "" && priv.length < MIN_SNMPV3_PASSWORD_LEN)) {
    return `SNMPv3 passwords must be at least ${MIN_SNMPV3_PASSWORD_LEN} characters`;
  }
  if (auth === "" && priv !== "") return "SNMPv3 privacy needs an authentication password";
  return null;
}

/** Drop v3 credentials for v1/v2c and empty passwords → null. */
export function snmpForWire(c: SnmpConfig): SnmpConfig {
  if (c.version !== "v3") return { ...c, v3: null };
  const v3 = c.v3;
  return {
    ...c,
    v3: v3
      ? {
          ...v3,
          authPassword: v3.authPassword ? v3.authPassword : null,
          privPassword: v3.privPassword ? v3.privPassword : null,
        }
      : null,
  };
}

const KIND_LABEL: Record<InterfaceInfo["kind"], string> = {
  ethernet: "Ethernet",
  wifi: "Wi-Fi",
  vlan: "VLAN",
  bridge: "Bridge",
  vpn: "VPN",
  virtual: "Virtual",
  loopback: "Loopback",
  unknown: "Other",
};

export function primaryIpv4(i: InterfaceInfo): { ip: string; prefix: number } | null {
  return i.addrs.find((a) => !a.ip.includes(":")) ?? null;
}

export function interfaceLabel(i: InterfaceInfo): string {
  const kind = i.kind === "vlan" && i.vlanId !== null ? `VLAN ${i.vlanId}${i.parent ? ` on ${i.parent}` : ""}` : KIND_LABEL[i.kind];
  const v4 = primaryIpv4(i);
  return `${i.name} — ${kind}${v4 ? ` · ${v4.ip}/${v4.prefix}` : ""}${i.isDefault ? " (default)" : ""}${i.isUp ? "" : " (down)"}`;
}

/** "10.0.0.1 – 10.0.0.254" for the interface subnet (placeholder for the range box). */
export function subnetHint(i: InterfaceInfo | undefined): string | null {
  const v4 = i ? primaryIpv4(i) : null;
  if (!v4) return null;
  const n = ipv4ToNumber(v4.ip);
  if (n === null || v4.prefix < 8 || v4.prefix > 30) return `${v4.ip}/${v4.prefix}`;
  const size = 2 ** (32 - v4.prefix);
  const net = Math.floor(n / size) * size;
  return `${numberToIpv4(net + 1)} to ${numberToIpv4(net + size - 2)}`;
}
