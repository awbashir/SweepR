// Joins between devices and infrastructure data (CDP/LLDP neighbors, CAM tables, VLANs).

import type {
  CdpLldpNeighbor,
  Device,
  PortMacCount,
  SnmpDeviceInfo,
  SwitchPortMapping,
  VlanInfo,
} from "../types.ts";

export function normMac(mac: string | null | undefined): string {
  if (!mac) return "";
  const hex = mac.toLowerCase().replace(/[^0-9a-f]/g, "");
  return hex.length === 12 ? hex : mac.toLowerCase();
}

/** Every name the device is known by (lower-case), used to match switch names. */
export function deviceNames(device: Device, hostname: string, snmp?: SnmpDeviceInfo): Set<string> {
  const names = [
    hostname,
    device.hostname,
    device.dnsName,
    device.dnsName?.split(".")[0],
    device.mdnsName,
    device.smbName,
    device.neighbor?.systemName,
    device.neighbor?.deviceId,
    snmp?.sysName,
    snmp?.sysName?.split(".")[0],
  ];
  const out = new Set<string>();
  for (const n of names) if (n) out.add(n.toLowerCase());
  return out;
}

/** CDP/LLDP advertisements that came from this device (by MAC, IP or management address). */
export function neighborsForDevice(device: Device, neighbors: CdpLldpNeighbor[]): CdpLldpNeighbor[] {
  const mac = normMac(device.mac);
  const ips = new Set([device.ip, ...device.extraIps]);
  const out: CdpLldpNeighbor[] = [];
  const seen = new Set<string>();
  const push = (n: CdpLldpNeighbor): void => {
    const k = `${n.protocol}|${n.deviceId}|${n.portId ?? ""}`;
    if (!seen.has(k)) {
      seen.add(k);
      out.push(n);
    }
  };
  if (device.neighbor) push(device.neighbor);
  for (const n of neighbors) {
    if ((mac !== "" && normMac(n.sourceMac) === mac) || n.managementAddrs.some((a) => ips.has(a))) {
      push(n);
    }
  }
  return out;
}

/** CAM-table entries learned on this switch. */
export function mappingsForSwitch(
  device: Device,
  names: Set<string>,
  mappings: SwitchPortMapping[],
): SwitchPortMapping[] {
  const ips = new Set([device.ip, ...device.extraIps]);
  return mappings.filter(
    (m) =>
      (m.switchIp !== null && ips.has(m.switchIp)) ||
      (m.switchIp === null && names.has(m.switchName.toLowerCase())),
  );
}

/** VLANs this switch advertised (VTP/CDP/LLDP/SNMP). */
export function vlansForSwitch(names: Set<string>, vlans: VlanInfo[]): VlanInfo[] {
  return vlans.filter((v) => v.switchName !== null && names.has(v.switchName.toLowerCase()));
}

/** `portMacCounts` as sorted `[port, count]` pairs (natural port order). */
export function normalizePortMacCounts(counts: PortMacCount[] | null | undefined): Array<[string, number]> {
  if (!Array.isArray(counts)) return [];
  return counts
    .map((c): [string, number] => [c.portName, c.macCount])
    .sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true }));
}

export function formatUptime(ticks: number | null | undefined): string {
  if (ticks === null || ticks === undefined) return "—";
  let secs = Math.floor(ticks / 100);
  const days = Math.floor(secs / 86400);
  secs -= days * 86400;
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return `${days}d ${h}h ${m}m`;
}
