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
  /** SSDP/UPnP, WS-Discovery/ONVIF and SIP OPTIONS during enrichment. */
  discoverServices: boolean;
  /** SIP OPTIONS to every host, not only likely VoIP gear. */
  sipAll: boolean;
  /** Passive DHCP fingerprinting (needs root, like the other sniffers). */
  dhcpFingerprint: boolean;
  /**
   * The saved SNMP settings used a community or SNMPv3 password, which is never stored: it
   * must be re-entered (SNMP Settings) before SNMP is used again. Until then scans run without
   * SNMP instead of silently polling with "public" or v3 noAuthNoPriv.
   */
  snmpCredentialsMissing: boolean;
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
  discoverServices: true,
  sipAll: false,
  dhcpFingerprint: false,
  snmpCredentialsMissing: false,
};

/** A community worth protecting: anything but the well-known read default ("public") or none. */
export function isSecretCommunity(community: string): boolean {
  const t = community.trim();
  return t !== "" && t !== "public";
}

/** Whether `c`, as used for polling, depends on a secret that is never persisted. */
export function snmpHasSecret(c: SnmpConfig): boolean {
  if (c.version === "v3") return Boolean(c.v3?.authPassword) || Boolean(c.v3?.privPassword);
  return isSecretCommunity(c.community);
}

/**
 * Stored settings as the app uses them: defaults for missing fields. Settings saved before
 * `snmpCredentialsMissing` existed had their community replaced by "public" on save, so with
 * SNMP enabled they need the credentials re-entered too.
 */
export function normalizeSettings(raw: Partial<ScanSettings> | null | undefined): ScanSettings {
  const r = raw ?? {};
  return {
    ...DEFAULT_SETTINGS,
    ...r,
    snmp: { ...DEFAULT_SNMP, ...r.snmp },
    snmpCredentialsMissing: typeof r.snmpCredentialsMissing === "boolean" ? r.snmpCredentialsMissing : r.snmpEnabled === true,
  };
}

/**
 * What gets written to localStorage: never SNMP secrets (a community other than "public", v3
 * passwords). When one was in use (or is still missing from an earlier session), the stored
 * settings say so, and the next session asks for it instead of polling without it.
 */
export function persistableSettings(s: ScanSettings): ScanSettings {
  const n = normalizeSettings(s);
  return {
    ...n,
    snmpCredentialsMissing: n.snmpCredentialsMissing || snmpHasSecret(n.snmp),
    snmp: {
      ...n.snmp,
      community: isSecretCommunity(n.snmp.community) ? "" : n.snmp.community,
      v3: n.snmp.v3 ? { ...n.snmp.v3, authPassword: null, privPassword: null } : null,
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
  /** SNMP is enabled but its credentials must be re-entered: the scan runs without SNMP. */
  snmpSkipped: boolean;
}

export function buildScanConfig(s: ScanSettings): Parsed<BuiltConfig> {
  const range = parseRange(s.range);
  if (!range.ok) return { ok: false, error: `Range: ${range.error}` };
  const vlans = vlanSelectionFrom(s);
  if (!vlans.ok) return { ok: false, error: `VLAN: ${vlans.error}` };
  const ports = parsePorts(s.ports);
  if (!ports.ok) return { ok: false, error: `Ports: ${ports.error}` };
  const snmpSkipped = s.snmpEnabled && s.snmpCredentialsMissing === true;
  const snmpOn = s.snmpEnabled && !snmpSkipped;
  if (snmpOn && s.snmp.version === "v3") {
    const problem = snmpV3Problem(s.snmp);
    if (problem) return { ok: false, error: `${problem} (SNMP Settings)` };
  }
  const config: ScanConfig = {
    interface: s.iface === "" ? null : s.iface,
    range: range.value.spec,
    vlans: vlans.value,
    discoverVlans: s.discoverVlans || vlans.value.mode === "auto_detect",
    cdpLldp: s.cdpLldp,
    snmp: snmpOn ? snmpForWire(s.snmp) : null,
    snmpAll: snmpOn && s.snmpAll,
    ipv6: s.ipv6,
    ports: ports.value,
    resolveNames: s.resolveNames,
    timeoutMs: 1500,
    retries: 1,
    ratePps: 2000,
    concurrency: 512,
    listenSecs: 10,
    webIdentity: true,
    discoverServices: s.discoverServices,
    sipAll: s.discoverServices && s.sipAll,
    dhcpFingerprint: s.dhcpFingerprint,
  };
  return { ok: true, value: { config, targetCount: range.value.spec === null ? null : range.value.count, snmpSkipped } };
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

/** "10.0.0.0/24" for the interface's IPv4 subnet (what an empty range scans). */
export function interfaceCidr(i: InterfaceInfo | undefined): string | null {
  const v4 = i ? primaryIpv4(i) : null;
  if (!v4) return null;
  const n = ipv4ToNumber(v4.ip);
  if (n === null || v4.prefix < 0 || v4.prefix > 32) return null;
  const size = 2 ** (32 - v4.prefix);
  return `${numberToIpv4(Math.floor(n / size) * size)}/${v4.prefix}`;
}
