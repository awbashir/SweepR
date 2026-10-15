// Simulated backend for a plain browser (no `window.__TAURI_INTERNALS__`). It follows the real
// contract: job ids, superseding jobs, full device snapshots, progress, logs and `finished`.
// Large ranges (e.g. `10.0.0.0/16`) stream ~50k devices in big batches for performance testing.
// The simulated campus topology (CAM tables, CDP/LLDP) lives in `mockTopology.ts`: switch ports
// and CAM entries are reported only when SNMP is configured, as with the real backend.

import type { Backend } from "./api.ts";
import type {
  Device,
  ExportFormat,
  InterfaceInfo,
  Overrides,
  ScanConfig,
  ScanEvent,
  ScanEventPayload,
  SnmpDeviceInfo,
  SwitchPortMapping,
  VlanInfo,
  VlanSource,
} from "./types.ts";
import { ipv4ToNumber, numberToIpv4 } from "./lib/ip.ts";
import { parseRange, type Ipv4Span } from "./lib/parse.ts";
import { MockNet, macFor } from "./mockTopology.ts";

const INTERFACES: InterfaceInfo[] = [
  {
    name: "en0",
    index: 6,
    description: "Thunderbolt Ethernet",
    mac: "a4:83:e7:12:34:56",
    addrs: [
      { ip: "10.177.134.25", prefix: 24 },
      { ip: "fe80::1c2b:3aff:fe4d:5e6f", prefix: 64 },
    ],
    isUp: true,
    kind: "ethernet",
    vlanId: null,
    parent: null,
    isDefault: true,
  },
  {
    name: "en1",
    index: 7,
    description: "Wi-Fi",
    mac: "a4:83:e7:aa:bb:cc",
    addrs: [{ ip: "192.168.1.42", prefix: 24 }],
    isUp: true,
    kind: "wifi",
    vlanId: null,
    parent: null,
    isDefault: false,
  },
  {
    name: "vlan0",
    index: 12,
    description: null,
    mac: "a4:83:e7:12:34:56",
    addrs: [{ ip: "10.20.0.25", prefix: 24 }],
    isUp: true,
    kind: "vlan",
    vlanId: 20,
    parent: "en0",
    isDefault: false,
  },
  {
    name: "utun3",
    index: 21,
    description: "VPN",
    mac: null,
    addrs: [{ ip: "172.16.8.3", prefix: 32 }],
    isUp: true,
    kind: "vpn",
    vlanId: null,
    parent: null,
    isDefault: false,
  },
  {
    name: "lo0",
    index: 1,
    description: null,
    mac: null,
    addrs: [{ ip: "127.0.0.1", prefix: 8 }],
    isUp: true,
    kind: "loopback",
    vlanId: null,
    parent: null,
    isDefault: false,
  },
];

// --- deterministic pseudo-random data ---------------------------------------------------------

function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pick<T>(r: () => number, items: readonly T[]): T {
  return items[Math.floor(r() * items.length)] as T;
}

const HOST_VENDORS = [
  { vendor: "Apple, Inc.", oui: "a4:83:e7", names: ["MacBook-Pro", "iPhone", "iPad", "iMac"] },
  { vendor: "Dell Inc.", oui: "f8:bc:12", names: ["DESKTOP", "LAPTOP", "WS"] },
  { vendor: "HP Inc.", oui: "3c:d9:2b", names: ["HP-LaserJet", "HPPRINT", "ELITEBOOK"] },
  { vendor: "Lenovo", oui: "54:ee:75", names: ["THINKPAD", "LT"] },
  { vendor: "Samsung Electronics", oui: "8c:77:12", names: ["Galaxy", "SmartTV"] },
  { vendor: "Yealink Network Technology", oui: "80:5e:c0", names: ["SIP-T46U", "SIP-T54W"] },
  { vendor: "Hikvision Digital Technology", oui: "44:19:b6", names: ["CAM", "NVR"] },
  { vendor: "Raspberry Pi Trading", oui: "dc:a6:32", names: ["raspberrypi", "pihole"] },
  { vendor: "VMware, Inc.", oui: "00:50:56", names: ["vm-web", "vm-db", "esx"] },
] as const;

function blankDevice(ip: string, now: number): Device {
  return {
    ip,
    extraIps: [],
    mac: null,
    vlanId: null,
    role: "host",
    hostname: null,
    dnsName: null,
    mdnsName: null,
    smbName: null,
    smbDomain: null,
    vendor: null,
    switchPort: null,
    openPorts: [],
    comments: null,
    interface: null,
    rttMs: null,
    sources: ["arp"],
    neighbor: null,
    firstSeenMs: now,
    lastSeenMs: now,
  };
}

/**
 * One simulated device. Infrastructure lives in the scanned base /24 (see `MockNet`); hosts get
 * their switch port only when SNMP is configured (the real backend reads it from CAM tables).
 */
function makeDevice(ipNum: number, vlanId: number | null, iface: string, withNames: boolean, net: MockNet, withSnmp: boolean): Device {
  const now = Date.now();
  const ip = numberToIpv4(ipNum);
  const r = rng(hash(`${ip}@${vlanId ?? ""}`));
  const dev = blankDevice(ip, now);
  dev.vlanId = vlanId;
  dev.interface = iface;
  dev.rttMs = Math.round((0.3 + r() * 8) * 100) / 100;
  const infra = vlanId === null ? net.infraAt(ipNum) : undefined;
  if (infra) {
    dev.role = infra.role;
    dev.vendor = infra.vendor;
    dev.mac = infra.mac;
    dev.dnsName = `${infra.name.toLowerCase()}.corp.example`;
    dev.openPorts = withNames ? infra.ports : [];
    dev.sources = withSnmp ? ["arp", "snmp", "dns"] : ["arp", "dns"];
    return dev;
  }
  const v = pick(r, HOST_VENDORS);
  dev.vendor = v.vendor;
  dev.mac = macFor(v.oui, Math.floor(r() * 0xffffff));
  const label = `${pick(r, v.names)}-${(ipNum & 0xfff).toString(16).toUpperCase()}`;
  if (withNames) {
    if (r() < 0.6) dev.dnsName = `${label.toLowerCase()}.corp.example`;
    if (v.vendor.startsWith("Apple") && r() < 0.8) dev.mdnsName = `${label}.local`;
    if (!v.vendor.startsWith("Apple") && r() < 0.5) {
      dev.smbName = label.toUpperCase().slice(0, 15);
      dev.smbDomain = "CORP";
    }
    if (r() < 0.35) dev.openPorts = [pick(r, [22, 80, 443, 445, 3389, 5060, 554, 9100])];
  }
  if (withSnmp) {
    const place = net.place(ipNum, vlanId);
    dev.switchPort = {
      switchName: place.sw.name,
      switchIp: place.sw.ip,
      portName: place.port,
      portIndex: Number(/(\d+)$/.exec(place.port)?.[1] ?? 0) || null,
      vlanId: vlanId ?? 1,
      mac: dev.mac,
    };
  }
  if (r() < 0.15) dev.extraIps = [`fe80::${(ipNum & 0xffff).toString(16)}:${Math.floor(r() * 0xffff).toString(16)}`];
  dev.sources = withNames ? ["arp", "dns"] : ["arp"];
  return dev;
}

/** /24 networks covered by untagged scan targets (the first one hosts the core gear). */
function blocksOf(spans: Ipv4Span[], limit: number): number[] {
  const out: number[] = [];
  const seen = new Set<number>();
  for (const s of spans) {
    for (let b = (s.start & 0xffffff00) >>> 0; b <= s.end && out.length < limit; b += 256) {
      if (!seen.has(b)) {
        seen.add(b);
        out.push(b);
      }
    }
  }
  return out;
}

function ifaceBlock(iface: InterfaceInfo): number {
  const base = ipv4ToNumber(iface.addrs.find((a) => ipv4ToNumber(a.ip) !== null)?.ip ?? "10.177.134.1") ?? 0;
  return (base & 0xffffff00) >>> 0;
}

// --- job runner ---------------------------------------------------------------------------------

type Listener = (p: ScanEventPayload) => void;

interface Job {
  id: number;
  timers: number[];
  cancelled: boolean;
  finished: boolean;
  startedAt: number;
}

function download(name: string, mime: string, text: string): void {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function csvCell(v: unknown): string {
  const s = v === null || v === undefined ? "" : String(v);
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

const OVERRIDES_KEY = "sweepr.mock.overrides";

export function createMockBackend(): Backend {
  const listeners = new Set<Listener>();
  let nextId = 1;
  let job: Job | null = null;

  const emit = (j: Job, event: ScanEvent): void => {
    if (job !== j) return; // superseded jobs emit nothing
    for (const l of listeners) l({ scanId: j.id, event });
  };
  const later = (j: Job, ms: number, fn: () => void): void => {
    j.timers.push(window.setTimeout(fn, ms));
  };
  const finish = (j: Job, devices: number, vlans: number, neighbors: number): void => {
    if (j.finished) return;
    j.finished = true;
    j.timers.forEach((t) => clearTimeout(t));
    emit(j, {
      type: "finished",
      data: { devices, vlans, neighbors, elapsedMs: Date.now() - j.startedAt, cancelled: j.cancelled },
    });
  };
  const newJob = (): Job => {
    if (job) job.timers.forEach((t) => clearTimeout(t));
    const j: Job = { id: nextId++, timers: [], cancelled: false, finished: false, startedAt: Date.now() };
    job = j;
    return j;
  };

  /** Network of the latest scan (SNMP queries answer from it). */
  let lastNet: MockNet | null = null;
  /** CAM entries the latest scan reported, by switch IP. */
  let lastCam = new Map<string, SwitchPortMapping[]>();
  const netFor = (iface: InterfaceInfo): MockNet => lastNet ?? new MockNet([ifaceBlock(iface)], false);

  const vlanInfo = (id: number, source: VlanSource, iface: string, switchName: string): VlanInfo => ({
    id,
    name: { 1: "default", 10: "USERS", 20: "SERVERS", 30: "VOICE", 99: "MGMT", 100: "GUEST" }[id] ?? null,
    sources: [source],
    interface: iface,
    switchName,
    framesSeen: 10 + (id % 17) * 3,
    firstSeenMs: Date.now(),
    lastSeenMs: Date.now(),
  });

  function runScan(j: Job, config: ScanConfig): void {
    const iface = INTERFACES.find((i) => i.name === config.interface) ?? INTERFACES[0]!;
    // Targets: explicit range, or the interface's /24.
    let spans: Ipv4Span[];
    const parsed = parseRange(config.range ?? "");
    if (parsed.ok && parsed.value.spans.length > 0) {
      spans = parsed.value.spans;
    } else {
      const base = ifaceBlock(iface);
      spans = [{ start: base + 1, end: base + 254 }];
    }
    // VLANs: each VLAN ID maps to its own 10.<id>.0.0/24 network.
    const sel = config.vlans;
    const vlanIds: Array<number | null> = [];
    if (sel.mode === "untagged" || sel.mode === "untagged_and_list" || sel.mode === "auto_detect") vlanIds.push(null);
    if (sel.mode === "list" || sel.mode === "untagged_and_list") vlanIds.push(...sel.ids.slice(0, 64));
    if (sel.mode === "auto_detect") vlanIds.push(10, 20, 30);

    const targets: Array<{ span: Ipv4Span; vlan: number | null }> = [];
    for (const vlan of vlanIds) {
      if (vlan === null) for (const span of spans) targets.push({ span, vlan });
      else targets.push({ span: { start: 167772160 + vlan * 256 + 1, end: 167772160 + vlan * 256 + 254 }, vlan });
    }
    const total = Math.min(
      targets.reduce((n, t) => n + (t.span.end - t.span.start + 1), 0),
      200_000,
    );
    const big = total > 4096;
    const batch = big ? 3000 : 6;
    const tick = big ? 30 : 25;
    const replyRate = big ? 0.8 : 0.6;
    const withSnmp = config.snmp !== null;
    // The simulated campus: built from the untagged /24s being scanned (or the interface's).
    const untaggedSpans = vlanIds.includes(null) ? spans : [];
    const blocks = blocksOf(untaggedSpans.length > 0 ? untaggedSpans : [{ start: ifaceBlock(iface) + 1, end: ifaceBlock(iface) + 254 }], 1024);
    const net = new MockNet(blocks, big);
    lastNet = net;
    lastCam = new Map();
    const scannerSw = net.scannerSwitch;
    const recordCam = (entries: SwitchPortMapping[]): void => {
      for (const m of entries) {
        const k = m.switchIp ?? m.switchName;
        const l = lastCam.get(k);
        if (l) l.push(m);
        else lastCam.set(k, [m]);
        emit(j, { type: "port_mapping", data: m });
      }
    };

    emit(j, { type: "progress", data: { phase: "preparing", probesSent: 0, probesTotal: total, devicesFound: 0 } });
    emit(j, { type: "log", data: { level: "warn", message: "Browser mock mode: no Tauri backend, showing simulated devices." } });
    if (iface.kind === "wifi" && sel.mode !== "untagged") {
      emit(j, { type: "log", data: { level: "warn", message: `${iface.name} is Wi-Fi; tagged 802.1Q frames are usually dropped.` } });
    }

    let vlanCount = 0;
    if (sel.mode === "auto_detect" || config.discoverVlans || sel.mode === "list" || sel.mode === "untagged_and_list") {
      const ids = sel.mode === "list" || sel.mode === "untagged_and_list" ? sel.ids.slice(0, 64) : [1, 10, 20, 30, 99, 100];
      ids.forEach((id, i) =>
        later(j, 200 + i * 150, () => {
          emit(j, {
            type: "vlan",
            data: vlanInfo(id, sel.mode === "auto_detect" ? "tagged8021q" : "user_configured", iface.name, scannerSw.name),
          });
        }),
      );
      vlanCount = ids.length;
    }

    // CDP/LLDP: this computer hears the access switch it is plugged into (Gi1/0/12).
    let neighbors = 0;
    const scannerAdvert = net.neighborOf(scannerSw, iface.name, scannerSw.accessPort?.(12) ?? "Gi1/0/12", 1);
    if (config.cdpLldp) {
      neighbors = 1;
      later(j, 400, () => emit(j, { type: "neighbor", data: scannerAdvert }));
    }
    if (withSnmp) {
      emit(j, { type: "log", data: { level: "info", message: `SNMP: polling ${net.switches.length} switches for MAC address tables (mock)` } });
    }

    // Flatten target addresses lazily.
    let ti = 0;
    let addr = targets[0]?.span.start ?? 0;
    let sent = 0;
    let found = 0;
    const discovered: Device[] = [];
    let infraCamSent = false;

    const step = (): void => {
      if (j.cancelled) {
        finish(j, found, vlanCount, neighbors);
        return;
      }
      if (withSnmp && !infraCamSent) {
        infraCamSent = true;
        recordCam(net.infraCam());
      }
      for (let k = 0; k < batch && ti < targets.length && sent < total; k++) {
        const t = targets[ti]!;
        const ipNum = addr;
        sent++;
        addr++;
        if (addr > t.span.end) {
          ti++;
          addr = targets[ti]?.span.start ?? 0;
        }
        const r = rng(hash(`r${ipNum}`))();
        const isInfra = t.vlan === null && net.infraAt(ipNum) !== undefined;
        if (!isInfra && r > replyRate) continue;
        const dev = makeDevice(ipNum, t.vlan, iface.name, isInfra || !big || r < 0.5, net, withSnmp);
        if (isInfra && config.cdpLldp && dev.ip === scannerSw.ip) {
          dev.neighbor = scannerAdvert;
          dev.sources = [...dev.sources, scannerAdvert.protocol];
        }
        found++;
        discovered.push(dev);
        emit(j, { type: "device", data: dev });
        if (withSnmp && !isInfra && dev.mac && dev.switchPort) {
          const place = net.place(ipNum, t.vlan);
          recordCam(net.hostCam(dev.mac, place, t.vlan ?? 1));
        }
      }
      emit(j, { type: "progress", data: { phase: "discovering", probesSent: sent, probesTotal: total, devicesFound: found } });
      if (sent < total && ti < targets.length) {
        later(j, tick, step);
        return;
      }
      // Enrichment pass: re-emit some snapshots with names / ports (exercise upserts).
      emit(j, { type: "progress", data: { phase: "enriching", probesSent: sent, probesTotal: total, devicesFound: found } });
      const sample = discovered.filter((_, i) => i % (big ? 50 : 4) === 0);
      later(j, big ? 100 : 600, () => {
        for (const d of sample) {
          const named = makeDevice(ipv4ToNumber(d.ip) ?? 0, d.vlanId, iface.name, true, net, withSnmp);
          if (named.role === "host" && named.openPorts.length === 0) named.openPorts = [443];
          named.neighbor = d.neighbor;
          emit(j, { type: "device", data: { ...named, sources: [...named.sources, "tcp"], lastSeenMs: Date.now() } });
        }
        if (config.cdpLldp) {
          emit(j, { type: "progress", data: { phase: "listening", probesSent: sent, probesTotal: total, devicesFound: found } });
        }
        later(j, config.cdpLldp ? 900 : 200, () => {
          emit(j, { type: "progress", data: { phase: "done", probesSent: sent, probesTotal: total, devicesFound: found } });
          finish(j, found, vlanCount, neighbors);
        });
      });
    };
    later(j, 150, step);
  }

  function runVlanDiscovery(j: Job, ifaceName: string | null, timeoutSecs: number): void {
    const iface = INTERFACES.find((i) => i.name === ifaceName) ?? INTERFACES[0]!;
    const net = netFor(iface);
    const sw = net.scannerSwitch;
    const ids = [1, 10, 20, 30, 99, 100, 200, 310];
    const duration = Math.min(timeoutSecs, 8) * 1000;
    emit(j, { type: "progress", data: { phase: "listening", probesSent: 0, probesTotal: 0, devicesFound: 0 } });
    emit(j, { type: "log", data: { level: "info", message: `Listening on ${iface.name} for 802.1Q tags, VTP, DTP, CDP and LLDP (mock, ${duration / 1000}s)` } });
    ids.forEach((id, i) =>
      later(j, ((i + 1) * duration) / (ids.length + 2), () =>
        emit(j, { type: "vlan", data: vlanInfo(id, i % 3 === 0 ? "vtp" : "tagged8021q", iface.name, sw.name) }),
      ),
    );
    later(j, duration / 3, () => emit(j, { type: "neighbor", data: net.neighborOf(sw, iface.name, sw.accessPort?.(12) ?? "Gi1/0/12", 1) }));
    later(j, duration, () => finish(j, 0, ids.length, 1));
  }

  return {
    isMock: true,
    listInterfaces: async () => INTERFACES,
    startScan: async (config) => {
      const j = newJob();
      runScan(j, config);
      return j.id;
    },
    stopScan: async (scanId) => {
      const j = job;
      if (!j || j.finished || (scanId !== undefined && scanId !== j.id)) return false;
      j.cancelled = true;
      j.timers.forEach((t) => clearTimeout(t));
      window.setTimeout(() => finish(j, 0, 0, 0), 50);
      return true;
    },
    startVlanDiscovery: async (iface, timeoutSecs) => {
      const j = newJob();
      runVlanDiscovery(j, iface, timeoutSecs ?? 30);
      return j.id;
    },
    exportDevices: async (devices, format: ExportFormat) => {
      if (format === "xlsx") throw "XLSX export needs the desktop app (mock mode cannot write workbooks)";
      if (format === "json") {
        download("sweepr-devices.json", "application/json", JSON.stringify(devices, null, 2));
      } else {
        const cols: Array<[string, (d: Device) => unknown]> = [
          ["IP", (d) => d.ip],
          ["MAC", (d) => d.mac],
          ["VLAN", (d) => d.vlanId],
          ["Role", (d) => d.role],
          ["Hostname", (d) => d.hostname],
          ["Vendor", (d) => d.vendor],
          ["Switch Port", (d) => (d.switchPort ? `${d.switchPort.switchName} [${d.switchPort.portName}]` : "")],
          ["DNS", (d) => d.dnsName],
          ["mDNS", (d) => d.mdnsName],
          ["SMB", (d) => d.smbName],
          ["SMB Domain", (d) => d.smbDomain],
          ["Ports", (d) => d.openPorts.join(" ")],
          ["Comments", (d) => d.comments],
        ];
        const lines = [cols.map((c) => c[0]).join(",")];
        for (const d of devices) lines.push(cols.map(([, f]) => csvCell(f(d))).join(","));
        download("sweepr-devices.csv", "text/csv", lines.join("\n"));
      }
      return `~/Downloads/sweepr-devices.${format}`;
    },
    loadOverrides: async () => {
      try {
        const raw = localStorage.getItem(OVERRIDES_KEY);
        return raw ? (JSON.parse(raw) as Overrides) : {};
      } catch {
        return {};
      }
    },
    saveOverride: async (key, hostname, comments) => {
      try {
        const raw = localStorage.getItem(OVERRIDES_KEY);
        const all = raw ? (JSON.parse(raw) as Overrides) : {};
        if (!hostname && !comments) delete all[key];
        else all[key] = { hostname, comments };
        localStorage.setItem(OVERRIDES_KEY, JSON.stringify(all));
      } catch {
        /* storage unavailable: keep it in memory only */
      }
    },
    scanPorts: (ip, ports) =>
      new Promise((resolve, reject) => {
        if (ports.length === 0) {
          reject("no ports to scan");
          return;
        }
        const r = rng(hash(`ports${ip}`));
        const likely = new Set([22, 80, 443, 445, 3389, 8080, 8443, 161, 23, 5060, 9100, 8291, 10443]);
        const open = ports.filter((p) => likely.has(p) && r() < 0.55);
        window.setTimeout(() => resolve(open), 400 + Math.min(ports.length, 1000) * 2);
      }),
    querySnmp: (ip, snmp) =>
      new Promise((resolve, reject) => {
        const n = ipv4ToNumber(ip);
        const net = netFor(INTERFACES[0]!);
        const spec = n === null ? undefined : net.infraAt(n);
        window.setTimeout(() => {
          if (!spec) {
            reject(`SNMP request to ${ip} timed out (community '${snmp?.community ?? "public"}')`);
            return;
          }
          const vlans: VlanInfo[] = [1, 10, 20, 30, 99].map((id) => vlanInfo(id, "snmp", "en0", spec.name));
          const isSwitch = spec.role === "switch";
          const all = isSwitch ? (lastCam.get(spec.ip) ?? net.infraCam().filter((m) => m.switchIp === spec.ip)) : [];
          const counts = new Map<string, { portIndex: number | null; macCount: number }>();
          for (const m of all) {
            const c = counts.get(m.portName) ?? { portIndex: m.portIndex, macCount: 0 };
            c.macCount += 1;
            counts.set(m.portName, c);
          }
          const info: SnmpDeviceInfo = {
            sysName: spec.name,
            sysDescr: `${spec.platform} — ${spec.software}`,
            sysUptimeTicks: 123_456_789 + (spec.ipNum & 0xffff),
            sysObjectId: spec.protocol === "cdp" ? "1.3.6.1.4.1.9.1.2694" : "1.3.6.1.4.1.12356.101.1.1",
            role: spec.role,
            vlans,
            portMappings: all.slice(0, 5000),
            portMacCounts: [...counts].map(([portName, c]) => ({ portName, ...c })),
            partial: all.length > 5000,
            warnings: all.length > 5000 ? [`MAC table truncated to 5,000 of ${all.length.toLocaleString()} entries`] : [],
          };
          resolve(info);
        }, 500);
      }),
    onScanEvent: async (handler) => {
      // A fresh wrapper per subscription, so unsubscribing one never removes another
      // subscription of the same handler (React StrictMode subscribes twice).
      const l: Listener = (p) => handler(p);
      listeners.add(l);
      return () => {
        listeners.delete(l);
      };
    },
    openUrl: async (url) => {
      if (/^https?:\/\//i.test(url)) window.open(url, "_blank", "noopener,noreferrer");
      else console.info(`[mock] would open ${url}`);
    },
  };
}
