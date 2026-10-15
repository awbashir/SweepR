// Simulated campus network for the mock backend: firewall + WAN router -> core switch ->
// (distribution ->) access switches -> access points -> endpoints. It decides where every
// simulated host is plugged in and produces consistent SNMP CAM tables (MAC -> switch port), so
// the topology view can be developed and stress-tested without real gear.
//
// Small scans (a /24, a few VLANs): 1 firewall, 1 router, 1 core, 3 access switches, 4 APs.
// Big scans (e.g. 10.0.0.0/16, ~50k hosts): 4 distribution switches and one access switch with
// two APs per /24.

import type { CdpLldpNeighbor, DeviceRole, SwitchPortMapping } from "./types.ts";
import { numberToIpv4 } from "./lib/ip.ts";

export type MockTier = "firewall" | "router" | "core" | "dist" | "access" | "ap";

export interface MockInfra {
  ipNum: number;
  ip: string;
  tier: MockTier;
  role: DeviceRole;
  name: string;
  vendor: string;
  oui: string;
  platform: string;
  software: string;
  caps: CdpLldpNeighbor["capabilities"];
  protocol: CdpLldpNeighbor["protocol"];
  ports: number[];
  mac: string;
  parent: MockInfra | null;
  /** Port on the parent this device is plugged into. */
  parentPort: string | null;
  /** This device's own port towards its parent. */
  uplink: string | null;
  children: MockInfra[];
  /** Access switches: name of access port `i` (1-based). */
  accessPort?: (i: number) => string;
  accessPortCount?: number;
  aps?: MockInfra[];
}

export interface Placement {
  /** Switch the MAC is learned on at the edge. */
  sw: MockInfra;
  port: string;
  ap: MockInfra | null;
}

export function macFor(oui: string, n: number): string {
  const b = [(n >>> 16) & 255, (n >>> 8) & 255, n & 255].map((x) => x.toString(16).padStart(2, "0"));
  return `${oui}:${b.join(":")}`;
}

function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

interface Model {
  vendor: string;
  oui: string;
  platform: string;
  software: string;
  caps: CdpLldpNeighbor["capabilities"];
  protocol: CdpLldpNeighbor["protocol"];
  ports: number[];
}

const FORTIGATE: Model = {
  vendor: "Fortinet, Inc.",
  oui: "00:09:0f",
  platform: "FortiGate-200F",
  software: "FortiOS v7.4.4 build2662",
  caps: ["router", "firewall"],
  protocol: "lldp",
  ports: [22, 443, 10443],
};
const MIKROTIK: Model = {
  vendor: "Routerboard.com",
  oui: "48:8f:5a",
  platform: "CCR2004-16G-2S+",
  software: "RouterOS 7.15.3",
  caps: ["router"],
  protocol: "lldp",
  ports: [22, 80, 8291],
};
const C9500: Model = {
  vendor: "Cisco Systems, Inc",
  oui: "00:1b:54",
  platform: "cisco C9500-24Y4C",
  software: "Cisco IOS XE Software, Version 17.09.04a",
  caps: ["router", "switch"],
  protocol: "cdp",
  ports: [22, 161, 443],
};
const C9200: Model = {
  vendor: "Cisco Systems, Inc",
  oui: "00:1b:54",
  platform: "cisco C9200-48P",
  software: "Cisco IOS XE Software, Version 17.09.04a",
  caps: ["switch"],
  protocol: "cdp",
  ports: [22, 80, 161, 443],
};
const ARUBA6100: Model = {
  vendor: "Hewlett Packard Enterprise",
  oui: "94:b4:0f",
  platform: "Aruba JL675A 6100 48G",
  software: "ArubaOS-CX PL.10.13.1000",
  caps: ["switch"],
  protocol: "lldp",
  ports: [22, 443],
};
const UNIFI: Model = {
  vendor: "Ubiquiti Inc.",
  oui: "24:5a:4c",
  platform: "UniFi U6-Pro",
  software: "UAP firmware 6.6.77",
  caps: ["wlan_access_point"],
  protocol: "lldp",
  ports: [22],
};
const C9120: Model = {
  vendor: "Cisco Systems, Inc",
  oui: "00:1b:54",
  platform: "cisco C9120AXI-B",
  software: "Cisco AP Software, ap3g3-k9w8 17.9",
  caps: ["wlan_access_point"],
  protocol: "cdp",
  ports: [22, 443],
};

const TIER_ROLE: Record<MockTier, DeviceRole> = {
  firewall: "firewall",
  router: "router",
  core: "switch",
  dist: "switch",
  access: "switch",
  ap: "access_point",
};

export class MockNet {
  readonly infra: MockInfra[] = [];
  readonly switches: MockInfra[] = [];
  private byIp = new Map<number, MockInfra>();
  private accessByBlock = new Map<number, MockInfra>();
  private accessList: MockInfra[] = [];
  readonly big: boolean;

  /** `blocks`: /24 network numbers being scanned (first one hosts the core gear). */
  constructor(blocks: number[], big: boolean) {
    this.big = big;
    const base = blocks[0] ?? 0x0ab18600;
    const fw = this.add(base + 1, "firewall", "FW-EDGE01", FORTIGATE, null, null, null);
    const core = this.add(base + 2, "core", "CORE-SW01", C9500, fw, "port1", "Te1/0/23");
    this.add(base + 254, "router", "WAN-RTR01", MIKROTIK, core, "Te1/0/24", "ether1");
    if (!big) {
      const specs: Array<[number, string, Model]> = [
        [3, "ACC-SW01", C9200],
        [4, "ACC-SW02", ARUBA6100],
        [5, "ACC-SW03", C9200],
      ];
      specs.forEach(([octet, name, model], i) => {
        const aruba = model === ARUBA6100;
        const acc = this.add(base + octet, "access", name, model, core, `Te1/0/${i + 1}`, aruba ? "1/1/49" : "Te1/1/1");
        // Two-member stacks: 1/0/1-46 (47-48 are AP ports) and 2/0/1-48.
        acc.accessPort = aruba ? (p) => (p <= 46 ? `1/1/${p}` : `2/1/${p - 46}`) : (p) => (p <= 46 ? `Gi1/0/${p}` : `Gi2/0/${p - 46}`);
        acc.accessPortCount = 94;
        acc.aps = [];
        this.accessList.push(acc);
      });
      const apSpecs: Array<[number, string, Model, number, number]> = [
        [6, "AP-FLOOR1", UNIFI, 0, 47],
        [7, "AP-FLOOR2", C9120, 0, 48],
        [8, "AP-FLOOR3", UNIFI, 1, 47],
        [9, "AP-FLOOR4", C9120, 2, 47],
      ];
      for (const [octet, name, model, accIdx, port] of apSpecs) {
        const acc = this.accessList[accIdx]!;
        const ap = this.add(base + octet, "ap", name, model, acc, acc.accessPort!(port), model === UNIFI ? "eth0" : "Gi0");
        acc.aps!.push(ap);
      }
    } else {
      const dists = [0, 1, 2, 3].map((d) => this.add(base + 10 + d, "dist", `DIST-SW0${d + 1}`, C9500, core, `Hu1/0/${d + 1}`, "Hu1/0/49"));
      const dCount = dists.map(() => 0);
      blocks.slice(0, 1024).forEach((b, i) => {
        const d = i % dists.length;
        const k = dCount[d]!++;
        const n = String(i + 1).padStart(3, "0");
        const acc = this.add(b + 250, "access", `ACC-SW${n}`, C9200, dists[d]!, `Te${1 + Math.floor(k / 48)}/0/${(k % 48) + 1}`, "Te1/1/1");
        acc.accessPort = (p) => (p <= 46 ? `Gi1/0/${p}` : `Gi2/0/${p - 46}`);
        acc.accessPortCount = 94;
        acc.aps = [
          this.add(b + 251, "ap", `AP-${n}-1`, UNIFI, acc, "Gi1/0/47", "eth0"),
          this.add(b + 252, "ap", `AP-${n}-2`, C9120, acc, "Gi1/0/48", "Gi0"),
        ];
        this.accessList.push(acc);
        this.accessByBlock.set(b, acc);
      });
    }
  }

  private add(ipNum: number, tier: MockTier, name: string, m: Model, parent: MockInfra | null, parentPort: string | null, uplink: string | null): MockInfra {
    const x: MockInfra = {
      ipNum,
      ip: numberToIpv4(ipNum),
      tier,
      role: TIER_ROLE[tier],
      name,
      vendor: m.vendor,
      oui: m.oui,
      platform: m.platform,
      software: m.software,
      caps: m.caps,
      protocol: m.protocol,
      ports: m.ports,
      mac: macFor(m.oui, ipNum & 0xffffff),
      parent,
      parentPort,
      uplink,
      children: [],
    };
    parent?.children.push(x);
    this.infra.push(x);
    this.byIp.set(ipNum, x);
    if (tier === "core" || tier === "dist" || tier === "access") this.switches.push(x);
    return x;
  }

  infraAt(ipNum: number): MockInfra | undefined {
    return this.byIp.get(ipNum);
  }

  /** The access switch the scanning computer is plugged into. */
  get scannerSwitch(): MockInfra {
    return this.accessList[0]!;
  }

  /** Where a host is plugged in: an access port, an AP (wireless) or a shared port. */
  place(ipNum: number, vlan: number | null): Placement {
    const h = hash(`place${ipNum}@${vlan ?? ""}`);
    const acc = this.accessByBlock.get((ipNum & 0xffffff00) >>> 0) ?? this.accessList[h % this.accessList.length]!;
    const aps = acc.aps ?? [];
    const r = (h >>> 8) % 100;
    if (r < 26 && aps.length > 0) {
      // Small scans spread wireless clients over every AP, not just the ones on this switch.
      const pool = this.big ? aps : this.infra.filter((x) => x.tier === "ap");
      const ap = pool[(h >>> 16) % pool.length]!;
      return { sw: ap.parent!, port: ap.parentPort!, ap };
    }
    if (!this.big && r < 31) {
      // An unmanaged desk switch: several MACs on one port of the Aruba.
      const aruba = this.accessList[1] ?? acc;
      return { sw: aruba, port: aruba.accessPort!(20), ap: null };
    }
    if (this.big) {
      // One switch per /24: octet -> port keeps it at 1-3 MACs per port.
      return { sw: acc, port: acc.accessPort!(1 + ((ipNum & 255) % (acc.accessPortCount ?? 94))), ap: null };
    }
    // Small nets: spread over the three access switches, about one host per port.
    // Each scanned network (untagged, VLAN 10, ...) gets its own slice of ports.
    const idx = (ipNum & 255) + ((vlan ?? 0) % 7) * 254;
    const sw = this.accessList[idx % this.accessList.length]!;
    const count = sw.accessPortCount ?? 94;
    return { sw, port: sw.accessPort!(1 + (Math.floor(idx / this.accessList.length) % count)), ap: null };
  }

  /** Port on switch `sw` where traffic from `x` (or from a host behind `x` at `edgePort`) is learned. */
  private portOn(sw: MockInfra, x: MockInfra, edgePort: string | null): string | null {
    if (sw === x) return edgePort;
    // Is x below sw? Walk up from x.
    let cur: MockInfra | null = x;
    while (cur && cur.parent !== sw) cur = cur.parent;
    if (cur) return cur.parentPort;
    return sw.uplink;
  }

  private isAncestor(a: MockInfra, of: MockInfra): boolean {
    for (let cur = of.parent; cur; cur = cur.parent) if (cur === a) return true;
    return false;
  }

  private entry(sw: MockInfra, port: string, mac: string, vlanId: number): SwitchPortMapping {
    return { switchName: sw.name, switchIp: sw.ip, portName: port, portIndex: portIndex(port), vlanId, mac };
  }

  /** CAM entries for the infrastructure MACs (every switch in small nets; the relevant ones in big nets). */
  infraCam(): SwitchPortMapping[] {
    const out: SwitchPortMapping[] = [];
    for (const sw of this.switches) {
      for (const x of this.infra) {
        if (x === sw) continue;
        if (this.big) {
          const relevant = this.isAncestor(sw, x) || this.isAncestor(x, sw) || x.tier === "firewall" || x.tier === "router";
          if (!relevant) continue;
        }
        // The AP's MAC is learned on its switch port; for everyone else x itself is the edge.
        const port = this.portOn(sw, x.tier === "ap" ? x.parent! : x, x.tier === "ap" ? x.parentPort : null);
        if (port) out.push(this.entry(sw, port, x.mac, 1));
      }
    }
    return out;
  }

  /** CAM entries for one host MAC (its edge port plus the path up / other switches' uplinks). */
  hostCam(mac: string, place: Placement, vlan: number): SwitchPortMapping[] {
    const out: SwitchPortMapping[] = [this.entry(place.sw, place.port, mac, vlan)];
    if (this.big) {
      for (let cur = place.sw.parent; cur; cur = cur.parent) {
        if (cur.tier === "firewall") break;
        const port = this.portOn(cur, place.sw, null);
        if (port) out.push(this.entry(cur, port, mac, vlan));
      }
      return out;
    }
    for (const sw of this.switches) {
      if (sw === place.sw) continue;
      const port = this.portOn(sw, place.sw, null);
      if (port) out.push(this.entry(sw, port, mac, vlan));
    }
    return out;
  }

  /** The CDP/LLDP advert a device sends (heard by this computer on `iface`). */
  neighborOf(x: MockInfra, iface: string, port: string, nativeVlan: number | null): CdpLldpNeighbor {
    const cdp = x.protocol === "cdp";
    return {
      protocol: x.protocol,
      localInterface: iface,
      sourceMac: x.mac,
      deviceId: cdp ? `${x.name}.corp.example` : x.mac,
      systemName: x.name,
      systemDescription: x.software,
      portId: cdp ? port.replace(/^Gi/, "GigabitEthernet").replace(/^Te/, "TenGigabitEthernet") : port,
      portDescription: "Access port",
      platform: x.platform,
      softwareVersion: x.software,
      managementAddrs: [x.ip],
      nativeVlan: nativeVlan ?? 1,
      voiceVlan: x.role === "switch" ? 30 : null,
      capabilities: x.caps,
      vtpDomain: cdp ? "CORP" : null,
      ttlSecs: cdp ? 180 : 120,
      lastSeenMs: Date.now(),
    };
  }
}

function portIndex(port: string): number | null {
  const m = /(\d+)$/.exec(port);
  return m ? Number(m[1]) : null;
}
