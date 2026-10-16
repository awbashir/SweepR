// Unit tests for the topology graph builder and its layout stability.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  EXPAND_STEP,
  ROOT_ID,
  SCANNER_ID,
  UNTAGGED,
  buildTopology,
  compressPorts,
  compressVlans,
  shortPort,
  vlanLabel,
  type TopoDeviceInput,
  type TopologyInput,
} from "./topology.ts";
import { layoutInput, nodeSize, stableLayout, stackedLeaves, type Pos } from "./topologyLayout.ts";
import { MAX_CANVAS_AREA, MAX_CANVAS_SIDE, bytesToBase64, exportFileName, pngScale, svgDataUrl, topologySvg } from "./topologySvg.ts";
import type { CdpLldpNeighbor, Device, DeviceRole, SwitchPortMapping } from "../types.ts";

function dev(ip: string, patch: Partial<Device> = {}): Device {
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
    sources: [],
    neighbor: null,
    firstSeenMs: 0,
    lastSeenMs: 0,
    latency: null,
    webTitle: null,
    webServer: null,
    tlsCert: null,
    webIdentity: null,
    warnings: [],
    ...patch,
  };
}

const row = (d: Device, hostname = ""): TopoDeviceInput => ({ key: d.vlanId === null ? d.ip : `${d.ip}@${d.vlanId}`, device: d, hostname });
const mac = (n: number): string => `00:00:00:00:${((n >> 8) & 255).toString(16).padStart(2, "0")}:${(n & 255).toString(16).padStart(2, "0")}`;

interface Lab {
  input: TopologyInput;
  hostsAcc1: Device[];
  wireless: Device[];
}

/** FW -> CORE -> ACC1 / ACC2, AP1 on ACC1 Gi1/0/45; full CAM tables on the three switches. */
function lab(opts: { acc1Hosts?: number; acc2Hosts?: number; wireless?: number; switchPort?: boolean; neighbors?: boolean } = {}): Lab {
  const infra = (n: number, role: DeviceRole, name: string): Device =>
    dev(`10.0.0.${n}`, { role, mac: mac(n), dnsName: `${name.toLowerCase()}.corp`, vendor: "Cisco Systems, Inc" });
  const fw = infra(1, "firewall", "FW1");
  const core = infra(2, "switch", "CORE");
  const acc1 = infra(3, "switch", "ACC1");
  const acc2 = infra(4, "switch", "ACC2");
  const ap = infra(6, "access_point", "AP1");
  const devices: Device[] = [fw, core, acc1, acc2, ap];
  const cam: SwitchPortMapping[] = [];
  const add = (sw: Device, name: string, port: string, m: string, vlanId: number | null): void => {
    cam.push({ switchName: name, switchIp: sw.ip, portName: port, portIndex: null, vlanId, mac: m });
  };
  const hostsAcc1: Device[] = [];
  const hostsAcc2: Device[] = [];
  const wireless: Device[] = [];
  let n = 100;
  for (let i = 0; i < (opts.acc1Hosts ?? 30); i++) {
    const vlan = i % 3 === 0 ? 20 : 10;
    const port = `Gi1/0/${(i % 40) + 1}`;
    const d = dev(`10.0.1.${i + 1}`, {
      mac: mac(n++),
      vlanId: vlan,
      vendor: "Dell Inc.",
      switchPort: opts.switchPort ? { switchName: "ACC1", switchIp: acc1.ip, portName: port, portIndex: null, vlanId: vlan, mac: "" } : null,
    });
    hostsAcc1.push(d);
    add(acc1, "ACC1", port, d.mac!, vlan);
  }
  for (let i = 0; i < (opts.acc2Hosts ?? 3); i++) {
    const d = dev(`10.0.2.${i + 1}`, { mac: mac(n++), vlanId: 10 });
    hostsAcc2.push(d);
    add(acc2, "ACC2", `1/1/${i + 1}`, d.mac!, 10);
  }
  for (let i = 0; i < (opts.wireless ?? 4); i++) {
    const d = dev(`10.0.3.${i + 1}`, { mac: mac(n++), vlanId: 30, vendor: "Apple, Inc." });
    wireless.push(d);
    add(acc1, "ACC1", "Gi1/0/45", d.mac!, 30);
  }
  devices.push(...hostsAcc1, ...hostsAcc2, ...wireless);
  // Infrastructure MACs as the switches learned them.
  add(core, "CORE", "Gi1/0/1", fw.mac!, 1);
  add(core, "CORE", "Te1/0/1", acc1.mac!, 1);
  add(core, "CORE", "Te1/0/1", ap.mac!, 1);
  add(core, "CORE", "Te1/0/2", acc2.mac!, 1);
  for (const h of [...hostsAcc1, ...wireless]) add(core, "CORE", "Te1/0/1", h.mac!, h.vlanId);
  for (const h of hostsAcc2) add(core, "CORE", "Te1/0/2", h.mac!, h.vlanId);
  for (const m of [core.mac!, fw.mac!, acc2.mac!, ...hostsAcc2.map((h) => h.mac!)]) add(acc1, "ACC1", "Te1/1/1", m, 1);
  add(acc1, "ACC1", "Te1/1/1", mac(9999), 25);
  for (const v of [20, 21, 22, 23, 24]) add(acc1, "ACC1", "Te1/1/1", mac(9000 + v), v);
  add(acc1, "ACC1", "Gi1/0/45", ap.mac!, 1);
  for (const m of [core.mac!, fw.mac!, acc1.mac!, ap.mac!, ...hostsAcc1.map((h) => h.mac!), ...wireless.map((h) => h.mac!)]) {
    add(acc2, "ACC2", "1/1/49", m, 1);
  }
  const neighbors: CdpLldpNeighbor[] = opts.neighbors
    ? [
        {
          protocol: "cdp",
          localInterface: "en0",
          sourceMac: mac(3),
          deviceId: "ACC1.corp",
          systemName: "ACC1",
          systemDescription: null,
          portId: "GigabitEthernet1/0/12",
          portDescription: null,
          platform: "cisco C9200",
          softwareVersion: null,
          managementAddrs: ["10.0.0.3"],
          nativeVlan: 10,
          voiceVlan: 30,
          capabilities: ["switch"],
          vtpDomain: null,
          ttlSecs: 180,
          lastSeenMs: 0,
        },
      ]
    : [];
  return { input: { devices: devices.map((d) => row(d)), neighbors, vlans: [], portMappings: cam, snmp: {} }, hostsAcc1, wireless };
}

test("formatting: VLAN range compression, port names, edge VLAN labels", () => {
  assert.equal(compressVlans([25, 10, 20, 21, 22, 23, 24, 10]), "10,20-25");
  assert.equal(compressVlans([1, 2]), "1,2");
  assert.equal(shortPort("GigabitEthernet1/0/48"), "Gi1/0/48");
  assert.equal(shortPort("TenGigabitEthernet1/1/1"), "Te1/1/1");
  assert.equal(shortPort("ethernet1/1/48"), "Eth1/1/48");
  assert.equal(compressPorts(["Gi1/0/14", "Gi1/0/16", "Gi1/0/15", "Gi1/0/24"]), "Gi1/0/14-16,24");
  assert.equal(compressPorts(["a1", "b1", "c1", "d1", "e1"], 2), "a1, b1 +3");
  assert.equal(vlanLabel([1, 10, 20, 21, 22], 1), "VLANs 1,10,20-22 · native 1");
  assert.equal(vlanLabel([10], 10), "VLAN 10");
  assert.equal(vlanLabel([], null), null);
});

test("hierarchy: firewall -> core -> access -> AP -> endpoints, from CAM tables", () => {
  const { input } = lab();
  const g = buildTopology(input);
  const depth = (id: string): number | undefined => g.nodes.find((n) => n.id === id)?.depth;
  assert.equal(depth("d:10.0.0.1"), 0);
  assert.equal(depth("d:10.0.0.2"), 1);
  assert.equal(depth("d:10.0.0.3"), 2);
  assert.equal(depth("d:10.0.0.4"), 2);
  assert.equal(depth("d:10.0.0.6"), 3);
  const parent = (id: string): string | null | undefined => g.nodes.find((n) => n.id === id)?.parentId;
  assert.equal(parent("d:10.0.0.2"), "d:10.0.0.1");
  assert.equal(parent("d:10.0.0.3"), "d:10.0.0.2");
  assert.equal(parent("d:10.0.0.6"), "d:10.0.0.3");
  assert.equal(g.stats.hasInfraData, true);
  assert.equal(g.stats.inferredLinks, 0);
  // Every node but the root has exactly one tree edge into it.
  const treeTargets = g.edges.filter((e) => e.tree).map((e) => e.target);
  assert.equal(new Set(treeTargets).size, treeTargets.length);
  assert.equal(treeTargets.length, g.nodes.length - 1);
});

test("edge labels: both trunk ports, compressed VLANs, endpoint ports, wireless", () => {
  const { input } = lab({ acc2Hosts: 3 });
  const g = buildTopology(input);
  const edge = (s: string, t: string) => g.edges.find((e) => e.source === s && e.target === t);
  const up = edge("d:10.0.0.2", "d:10.0.0.3");
  assert.ok(up);
  assert.equal(up.kind, "trunk");
  assert.equal(up.label, "Te1/0/1 ↔ Te1/1/1");
  assert.equal(up.sublabel, "VLANs 1,10,20-25,30");
  const fw = edge("d:10.0.0.1", "d:10.0.0.2");
  assert.ok(fw);
  assert.equal(fw.label, "↔ Gi1/0/1");
  const ap = edge("d:10.0.0.3", "d:10.0.0.6");
  assert.ok(ap);
  assert.equal(ap.label, "Gi1/0/45 ↔");
  // ACC2 has 3 endpoints: shown individually with their port.
  const h = edge("d:10.0.0.4", "d:10.0.2.2@10");
  assert.ok(h);
  assert.equal(h.kind, "access");
  assert.equal(h.label, "1/1/2");
  // Wireless clients (learned on the AP's switch port) hang off the AP.
  const wifi = g.edges.filter((e) => e.source === "d:10.0.0.6");
  assert.equal(wifi.length, 4);
  assert.ok(wifi.every((e) => e.kind === "wireless" && e.label === "Wi-Fi"));
});

test("scanner node from the CDP advert heard on en0", () => {
  const g = buildTopology(lab({ neighbors: true }).input);
  const me = g.nodes.find((n) => n.id === SCANNER_ID);
  assert.ok(me);
  assert.equal(me.parentId, "d:10.0.0.3");
  const e = g.edges.find((x) => x.target === SCANNER_ID);
  assert.equal(e?.label, "Gi1/0/12 ↔ en0");
});

test("clustering: per-VLAN clusters, port clusters, expansion cap with +N more", () => {
  const { input } = lab({ acc1Hosts: 60, switchPort: true });
  const g = buildTopology(input);
  const clusters = g.nodes.filter((n) => n.kind === "cluster" && n.parentId === "d:10.0.0.3");
  const v10 = clusters.find((c) => c.id === "c:d:10.0.0.3|v:10");
  const v20 = clusters.find((c) => c.id === "c:d:10.0.0.3|v:20");
  assert.ok(v10 && v20);
  assert.equal(v10.count + v20.count, 60);
  assert.equal(v10.label, `${v10.count} hosts`);
  assert.match(v10.portsLabel ?? "", /^Gi1\/0\//);
  assert.equal(v10.expanded, false);
  assert.equal(v10.members.length, 0);
  // Every host maps to the node that shows it.
  assert.equal(g.nodeOfKey.get("10.0.1.2@10"), v10.id);

  const g2 = buildTopology(input, { expanded: new Map([[v10.id, 8]]) });
  const e10 = g2.nodes.find((n) => n.id === v10.id)!;
  assert.equal(e10.expanded, true);
  assert.equal(e10.members.length, 8);
  assert.equal(e10.more, v10.count - 8);
  assert.ok(nodeSize(e10).h > nodeSize(v10).h);
  assert.equal(EXPAND_STEP > 8, true);

  // Five MACs on one port (an unmanaged switch / hypervisor) become their own cluster.
  const extra = [1, 2, 3, 4, 5].map((i) =>
    row(dev(`10.0.9.${i}`, { mac: mac(5000 + i), vlanId: 10, switchPort: { switchName: "ACC1", switchIp: "10.0.0.3", portName: "Gi1/0/47", portIndex: null, vlanId: 10, mac: "" } })),
  );
  const g3 = buildTopology({ ...input, devices: [...input.devices, ...extra] });
  const pc = g3.nodes.find((n) => n.id === "c:d:10.0.0.3|p:Gi1/0/47");
  assert.ok(pc);
  assert.equal(pc.count, 5);
  assert.equal(pc.label, "5 hosts on Gi1/0/47");
});

test("fallback: no infrastructure data -> synthetic root with per-VLAN groups", () => {
  const devices: TopoDeviceInput[] = [];
  for (let i = 1; i <= 12; i++) devices.push(row(dev(`10.0.0.${i}`, { vlanId: i <= 8 ? 10 : null, mac: mac(i) })));
  const g = buildTopology({ devices, neighbors: [], vlans: [{ id: 10, name: "USERS", sources: [], interface: null, switchName: null, framesSeen: 0, firstSeenMs: 0, lastSeenMs: 0 }], portMappings: [], snmp: {} });
  const root = g.nodes.find((n) => n.id === ROOT_ID);
  assert.ok(root);
  assert.equal(root.kind, "root");
  assert.equal(g.stats.hasInfraData, false);
  assert.equal(g.stats.unattached, 12);
  const users = g.nodes.find((n) => n.id === `${"c:root"}|u:10`);
  assert.ok(users);
  assert.equal(users.label, "VLAN 10 · USERS · 8 hosts");
  assert.equal(users.clusterKind, "unattached");
  const untagged = g.nodes.find((n) => n.id === `c:root|u:${UNTAGGED}`);
  assert.equal(untagged?.count, 4);
  assert.ok(g.edges.filter((e) => e.source === ROOT_ID).every((e) => e.kind === "inferred"));
});

test("fallback: infrastructure without links hangs off the gateway by role; unknown hosts per VLAN", () => {
  const devices = [
    row(dev("10.0.0.1", { role: "firewall", mac: mac(1) })),
    row(dev("10.0.0.2", { role: "switch", mac: mac(2) })),
    row(dev("10.0.0.6", { role: "access_point", mac: mac(6) })),
    ...[1, 2, 3, 4, 5, 6, 7].map((i) => row(dev(`10.0.0.${20 + i}`, { mac: mac(20 + i) }))),
  ];
  const g = buildTopology({ devices, neighbors: [], vlans: [], portMappings: [], snmp: {} });
  const sw = g.nodes.find((n) => n.id === "d:10.0.0.2")!;
  const ap = g.nodes.find((n) => n.id === "d:10.0.0.6")!;
  assert.equal(sw.parentId, "d:10.0.0.1");
  assert.equal(sw.status, "warn");
  assert.ok(ap.depth > sw.depth, "APs rank below switches");
  assert.equal(g.edges.find((e) => e.target === ap.id)?.minlen, 2);
  const cluster = g.nodes.find((n) => n.kind === "cluster");
  assert.equal(cluster?.parentId, "d:10.0.0.1");
  assert.equal(cluster?.count, 7);
});

test("unknown switches named by CAM entries become synthetic nodes", () => {
  const devices = [1, 2, 3].map((i) =>
    row(dev(`10.0.5.${i}`, { mac: mac(i), switchPort: { switchName: "IDF-9", switchIp: "10.9.9.9", portName: `Gi0/${i}`, portIndex: null, vlanId: 5, mac: "" } })),
  );
  const g = buildTopology({ devices, neighbors: [], vlans: [], portMappings: [], snmp: {} });
  const sw = g.nodes.find((n) => n.id === "s:idf-9");
  assert.ok(sw);
  assert.equal(sw.status, "unknown");
  assert.equal(g.edges.filter((e) => e.source === sw.id).length, 3);
});

test("filters keep the infrastructure path to what matches", () => {
  const { input } = lab();
  const aps = buildTopology(input, { roles: new Set(["access_point"]) });
  assert.deepEqual(aps.nodes.map((n) => n.id).sort(), ["d:10.0.0.1", "d:10.0.0.2", "d:10.0.0.3", "d:10.0.0.6"]);
  const v30 = buildTopology(input, { vlans: new Set([30]) });
  const ids = new Set(v30.nodes.map((n) => n.id));
  assert.ok(ids.has("d:10.0.0.6"));
  assert.ok(!v30.nodes.some((n) => n.kind === "device" && n.vlans.length > 0 && !n.vlans.includes(30)));
});

test("layout: positions stay put when an endpoint is added; no overlaps", () => {
  const { input } = lab({ acc1Hosts: 30, acc2Hosts: 3 });
  const g1 = buildTopology(input);
  const l1 = layoutInput(g1.nodes, g1.edges);
  const r1 = stableLayout({ seq: 1, ...l1, dir: "TB", prev: null, prevSizes: null, pinned: {}, fresh: true });
  assert.equal(r1.mode, "fresh");
  // Same structure -> positions reused verbatim, no layout run.
  const again = stableLayout({ seq: 2, ...l1, dir: "TB", prev: r1.positions, prevSizes: r1.sizes, pinned: {}, fresh: false });
  assert.equal(again.mode, "reuse");
  assert.deepEqual(again.positions, r1.positions);

  // One more endpoint on ACC2 (4 now, still individual nodes).
  const extra = row(dev("10.0.2.50", { mac: mac(7777), vlanId: 10, switchPort: { switchName: "ACC2", switchIp: "10.0.0.4", portName: "1/1/20", portIndex: null, vlanId: 10, mac: "" } }));
  const g2 = buildTopology({ ...input, devices: [...input.devices, extra] });
  const l2 = layoutInput(g2.nodes, g2.edges);
  const dragged: Pos = { x: -500, y: 900 };
  const r2 = stableLayout({ seq: 3, ...l2, dir: "TB", prev: r1.positions, prevSizes: r1.sizes, pinned: { "d:10.0.0.4": dragged }, fresh: false });
  assert.equal(r2.mode, "incremental");
  for (const n of g1.nodes) {
    if (n.id === "d:10.0.0.4") continue;
    assert.deepEqual(r2.positions[n.id], r1.positions[n.id], `${n.id} moved`);
  }
  assert.deepEqual(r2.positions["d:10.0.0.4"], dragged);
  assertNoOverlap(r2.positions, r2.sizes, new Set(["d:10.0.0.4"]));

  // Expanding a cluster grows it; neighbours are pushed aside, nothing overlaps.
  const cid = g1.nodes.find((n) => n.kind === "cluster")!.id;
  const g3 = buildTopology(input, { expanded: new Map([[cid, 30]]) });
  const l3 = layoutInput(g3.nodes, g3.edges);
  const r3 = stableLayout({ seq: 4, ...l3, dir: "TB", prev: r1.positions, prevSizes: r1.sizes, pinned: {}, fresh: false });
  assert.equal(r3.mode, "incremental");
  assertNoOverlap(r3.positions, r3.sizes, new Set());
  assert.deepEqual(r3.positions["d:10.0.0.1"], r1.positions["d:10.0.0.1"]);
});

function assertNoOverlap(pos: Record<string, Pos>, sizes: Record<string, { w: number; h: number }>, ignore: Set<string>): void {
  const ids = Object.keys(pos).filter((id) => !ignore.has(id));
  for (let i = 0; i < ids.length; i++) {
    for (let j = i + 1; j < ids.length; j++) {
      const a = { ...pos[ids[i]!]!, ...sizes[ids[i]!]! };
      const b = { ...pos[ids[j]!]!, ...sizes[ids[j]!]! };
      const hit = a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
      assert.ok(!hit, `${ids[i]} overlaps ${ids[j]}`);
    }
  }
}

test("truncated CAM tables: uplinks (where the gateway MAC is learned) are not mistaken for edge ports", () => {
  // CORE -> DIST -> ACC1/ACC2; each switch only reports its own MACs plus a few upstream ones,
  // so an access uplink holds fewer MACs than the distribution switch's real downlink.
  const sw = (n: number, name: string, role: DeviceRole = "switch"): Device => dev(`10.0.0.${n}`, { role, mac: mac(n), dnsName: name });
  const fw = sw(1, "fw", "firewall");
  const core = sw(2, "core");
  const dist = sw(3, "dist");
  const a1 = sw(4, "acc1");
  const a2 = sw(5, "acc2");
  const cam: SwitchPortMapping[] = [];
  const add = (s: Device, port: string, m: string): void => {
    cam.push({ switchName: s.dnsName!, switchIp: s.ip, portName: port, portIndex: null, vlanId: 1, mac: m });
  };
  add(core, "Te1/0/23", fw.mac!);
  for (const m of [dist.mac!, a1.mac!, a2.mac!]) add(core, "Hu1/0/1", m);
  for (let i = 0; i < 6; i++) add(core, "Hu1/0/1", mac(500 + i));
  add(dist, "Hu1/0/49", fw.mac!);
  add(dist, "Hu1/0/49", core.mac!);
  add(dist, "Te1/0/1", a1.mac!);
  add(dist, "Te1/0/2", a2.mac!);
  for (let i = 0; i < 3; i++) add(dist, "Te1/0/1", mac(500 + i));
  for (let i = 3; i < 6; i++) add(dist, "Te1/0/2", mac(500 + i));
  for (const s of [a1, a2]) for (const m of [fw.mac!, core.mac!, dist.mac!]) add(s, "Te1/1/1", m);
  const g = buildTopology({ devices: [fw, core, dist, a1, a2].map((d) => row(d)), neighbors: [], vlans: [], portMappings: cam, snmp: {} });
  const parent = (ip: string): string | null | undefined => g.nodes.find((n) => n.id === `d:${ip}`)?.parentId;
  assert.equal(parent("10.0.0.2"), "d:10.0.0.1");
  assert.equal(parent("10.0.0.3"), "d:10.0.0.2");
  assert.equal(parent("10.0.0.4"), "d:10.0.0.3");
  assert.equal(parent("10.0.0.5"), "d:10.0.0.3");
  assert.equal(g.edges.find((e) => e.target === "d:10.0.0.4")?.label, "Te1/0/1 ↔ Te1/1/1");
});

test("SVG export: plain vector shapes, escaped text, bus edges for stacked leaves", () => {
  const { input } = lab({ acc1Hosts: 30, acc2Hosts: 4 });
  const extra = row(dev("10.0.2.99", { mac: mac(8888), vlanId: 10, hostname: "a<b>&c", switchPort: { switchName: "ACC2", switchIp: "10.0.0.4", portName: "1/1/30", portIndex: null, vlanId: 10, mac: "" } }));
  const g = buildTopology({ ...input, devices: [...input.devices, extra] });
  const l = layoutInput(g.nodes, g.edges);
  const r = stableLayout({ seq: 1, ...l, dir: "TB", prev: null, prevSizes: null, pinned: {}, fresh: true });
  const stacked = new Set([...stackedLeaves(l.nodes, "TB").values()].flat());
  assert.ok(stacked.has("d:10.0.2.99@10"));
  const { svg, width, height } = topologySvg({ nodes: g.nodes, edges: g.edges, positions: r.positions, sizes: r.sizes, dir: "TB", stacked });
  assert.ok(width > 0 && height > 0);
  assert.ok(svg.startsWith("<svg") && svg.endsWith("</svg>"));
  assert.ok(!svg.includes("foreignObject"));
  assert.ok(svg.includes("a&lt;b&gt;&amp;c"));
  assert.ok(svg.includes("Te1/0/1 ↔ Te1/1/1"));
  assert.equal((svg.match(/<path /g) ?? []).length, g.edges.length);
});

test("map export: data: URLs (the CSP has no blob:), chunked base64, canvas limits, file names", () => {
  const bytes = new Uint8Array(200_000).map((_, i) => (i * 31) & 0xff);
  assert.equal(bytesToBase64(bytes), Buffer.from(bytes).toString("base64"));
  assert.equal(bytesToBase64(new Uint8Array()), "");
  const svg = `<svg xmlns="http://www.w3.org/2000/svg"><text>Bâtiment ⇄ “core” 交换机</text></svg>`;
  const url = svgDataUrl(svg);
  assert.ok(url.startsWith("data:image/svg+xml;base64,"));
  assert.equal(Buffer.from(url.slice(url.indexOf(",") + 1), "base64").toString("utf8"), svg);
  assert.equal(pngScale(800, 600), 2, "small maps at 2x");
  for (const [w, h] of [[92_000, 300], [9000, 9000], [1, 400_000]] as const) {
    const s = pngScale(w, h);
    assert.ok(w * s <= MAX_CANVAS_SIDE + 1 || s === 0.05, `${w}x${h}`);
    assert.ok(w * h * s * s <= MAX_CANVAS_AREA + 1 || s === 0.05, `${w}x${h}`);
  }
  assert.equal(exportFileName("png", new Date("2026-10-16T14:03:22.123Z")), "sweepr-topology-2026-10-16-14-03-22.png");
});

// --- unlinked infrastructure: clustering and build cost ----------------------------------------------

function unlinkedLab(aps: number, switches: number, gateway = true): TopologyInput & { devices: TopoDeviceInput[] } {
  const devices: Device[] = [];
  if (gateway) devices.push(dev("10.0.0.1", { role: "firewall", mac: mac(1), dnsName: "fw1.corp" }));
  for (let i = 0; i < aps; i++) devices.push(dev(`10.30.${i >> 8}.${i & 255}`, { role: "access_point", mac: mac(1000 + i), vlanId: 30, vendor: "Aruba Networks" }));
  for (let i = 0; i < switches; i++) devices.push(dev(`10.40.0.${i + 1}`, { role: "switch", mac: mac(30000 + i), dnsName: `sw${i + 1}.corp` }));
  return { devices: devices.map((d) => row(d)), neighbors: [], vlans: [], portMappings: [], snmp: {} };
}

test("unlinked infrastructure of one role and VLAN is clustered (expandable, searchable, filterable)", () => {
  const input = unlinkedLab(10, 3);
  const g = buildTopology(input);
  const cluster = g.nodes.find((n) => n.kind === "cluster" && n.clusterKind === "infra");
  assert.ok(cluster, "the APs form a cluster");
  assert.equal(cluster.role, "access_point");
  assert.equal(cluster.label, "10 access points");
  assert.equal(cluster.count, 10);
  assert.deepEqual(cluster.vlans, [30]);
  assert.equal(cluster.parentId, "d:10.0.0.1", "under the gateway");
  assert.equal(cluster.memberKeys.length, 10);
  assert.equal(g.nodeOfKey.get("10.30.0.3@30"), cluster.id, "search / selection lands on the cluster");
  const edge = g.edges.find((e) => e.target === cluster.id);
  assert.equal(edge?.kind, "inferred");
  assert.equal(edge?.minlen, 2, "APs rank below switches");
  // Below the threshold: the three switches stay individual cards.
  assert.equal(g.nodes.filter((n) => n.kind === "infra" && n.role === "switch").length, 3);
  assert.equal(g.nodes.some((n) => n.id === "d:10.30.0.0@30"), false, "clustered APs have no own node");
  assert.equal(g.stats.clusters, 1);

  // Expanded: members in natural order, "+N more" past the limit.
  const ex = buildTopology(input, { expanded: new Map([[cluster.id, 4]]), priorityKeys: new Set(["10.30.0.9@30"]) });
  const exC = ex.nodes.find((n) => n.id === cluster.id)!;
  assert.equal(exC.expanded, true);
  assert.equal(exC.members.length, 4);
  assert.equal(exC.members[0]?.key, "10.30.0.9@30", "search matches first");
  assert.equal(exC.more, 6);

  // Role filter: only switches -> no AP cluster.
  const sw = buildTopology(input, { roles: new Set(["switch"]) });
  assert.equal(sw.nodes.some((n) => n.clusterKind === "infra"), false);
  assert.equal(sw.nodes.filter((n) => n.role === "switch").length, 3);

  // Many switches without a gateway: a root-level cluster (no edge).
  const noGw = buildTopology(unlinkedLab(0, 40, false));
  const swc = noGw.nodes.find((n) => n.clusterKind === "infra");
  assert.equal(swc?.label, "40 switches");
  assert.equal(swc?.parentId, null);
  assert.equal(noGw.edges.length, 0);

  // A switch with endpoints attached is never folded into a cluster.
  const withHost = unlinkedLab(0, 8);
  withHost.devices.push(row(dev("10.40.9.9", { mac: mac(50000), switchPort: { switchName: "sw1.corp", switchIp: "10.40.0.1", portName: "Gi1/0/7", portIndex: null, vlanId: null, mac: "" } })));
  const wh = buildTopology(withHost);
  assert.ok(wh.nodes.some((n) => n.id === "d:10.40.0.1" && n.kind === "infra"), "sw1 keeps its own node");
  assert.equal(wh.nodes.find((n) => n.clusterKind === "infra")?.count, 7);
});

test("perf: 6,000 unlinked infrastructure devices and 20,000 hosts build quickly", () => {
  const big = unlinkedLab(4000, 2000);
  for (let i = 0; i < 20_000; i++) big.devices.push(row(dev(`10.50.${i >> 8}.${i & 255}`, { mac: mac(60000 + i) })));
  // Warm-up, then measure (CI machines vary: the bound is generous; the old builder took ~1 s).
  buildTopology(big);
  let t0 = performance.now();
  const g = buildTopology(big);
  const clustered = performance.now() - t0;
  assert.ok(g.nodes.length < 20, `compact map (${g.nodes.length} nodes)`);
  assert.ok(clustered < 400, `clustered build took ${clustered.toFixed(0)} ms`);
  // Even without clustering the ranking pass stays linear.
  t0 = performance.now();
  const flat = buildTopology(big, { infraClusterMin: 1_000_000 });
  const unclustered = performance.now() - t0;
  assert.equal(flat.nodes.filter((n) => n.kind === "infra").length, 6001);
  assert.ok(unclustered < 400, `unclustered build took ${unclustered.toFixed(0)} ms`);
});
