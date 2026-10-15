// Unit tests for the framework-free modules. Run with `npm test` (Node's built-in runner with
// native TypeScript type stripping; no extra test dependencies).

import { test } from "node:test";
import assert from "node:assert/strict";
import { deviceKey, ipSortKey, ipv6Groups, urlHost } from "./ip.ts";
import { formatPorts, parsePorts, parseRange, parseVlanSelection } from "./parse.ts";
import { ScanStore, buildRow, exportDevice } from "./store.ts";
import { normalizePortMacCounts, neighborsForDevice } from "./infra.ts";
import type { CdpLldpNeighbor, Device, ScanEventPayload } from "../types.ts";

function device(ip: string, patch: Partial<Device> = {}): Device {
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
    ...patch,
  };
}

test("IPv4 sorts numerically, IPv6 after IPv4", () => {
  const ips = ["10.0.0.10", "fe80::1", "10.0.0.9", "2001:db8::1", "9.255.255.255", "10.0.0.100", "::ffff:10.0.0.1"];
  const sorted = [...ips].sort((a, b) => (ipSortKey(a) < ipSortKey(b) ? -1 : 1));
  assert.deepEqual(sorted, ["9.255.255.255", "10.0.0.9", "10.0.0.10", "10.0.0.100", "::ffff:10.0.0.1", "2001:db8::1", "fe80::1"]);
});

test("IPv6 expansion", () => {
  assert.deepEqual(ipv6Groups("::1"), [0, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(ipv6Groups("fe80::1%en0"), [0xfe80, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(ipv6Groups("::ffff:10.0.0.1"), [0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001]);
  assert.deepEqual(ipv6Groups("::10.0.0.1"), [0, 0, 0, 0, 0, 0, 0x0a00, 0x0001]);
  assert.equal(ipv6Groups("1:2:3:4:5:6:7:8:9"), null);
  assert.equal(ipv6Groups("10.0.0.1"), null);
});

test("device keys and URL hosts mirror the backend", () => {
  assert.equal(deviceKey("10.0.0.1", null), "10.0.0.1");
  assert.equal(deviceKey("10.0.0.1", 20), "10.0.0.1@20");
  assert.equal(urlHost("10.0.0.1"), "10.0.0.1");
  assert.equal(urlHost("fe80::1%en0"), "[fe80::1%25en0]");
});

test("VLAN selection serializes like serde (tag=mode, content=ids, snake_case)", () => {
  const json = (s: string): string => {
    const r = parseVlanSelection(s);
    assert.ok(r.ok, s);
    return JSON.stringify(r.value);
  };
  assert.equal(json(""), '{"mode":"untagged"}');
  assert.equal(json("native"), '{"mode":"untagged"}');
  assert.equal(json("auto"), '{"mode":"auto_detect"}');
  assert.equal(json("VLAN 10, 20"), '{"mode":"list","ids":[10,20]}');
  assert.equal(json("30-32,10,10"), '{"mode":"list","ids":[10,30,31,32]}');
  assert.equal(json("untagged,10,20"), '{"mode":"untagged_and_list","ids":[10,20]}');
  assert.equal(parseVlanSelection("0").ok, false);
  assert.equal(parseVlanSelection("4095").ok, false);
  assert.equal(parseVlanSelection("20-10").ok, false);
  assert.equal(parseVlanSelection("auto,10").ok, false);
});

test("ports parse and compact", () => {
  const r = parsePorts("443, 22,80-82");
  assert.ok(r.ok);
  assert.deepEqual(r.value, [22, 80, 81, 82, 443]);
  assert.equal(formatPorts(r.value), "22,80-82,443");
  assert.equal(formatPorts([1, 2]), "1,2");
  assert.equal(parsePorts("0").ok, false);
  assert.equal(parsePorts("70000").ok, false);
  assert.deepEqual(parsePorts(""), { ok: true, value: [] });
});

test("range box accepts CLI syntax and 'from X to Y'", () => {
  const r1 = parseRange("Scan from 10.0.0.1 to 10.0.0.50");
  assert.ok(r1.ok);
  assert.equal(r1.value.spec, "10.0.0.1-10.0.0.50");
  assert.equal(r1.value.count, 50);
  const r2 = parseRange("10.0.0.0/24, 10.1.0.5-20");
  assert.ok(r2.ok);
  assert.equal(r2.value.count, 254 + 16);
  const r3 = parseRange("10.0.0.0/16");
  assert.ok(r3.ok);
  assert.equal(r3.value.count, 65534);
  assert.deepEqual(parseRange(""), { ok: true, value: { spec: null, spans: [], count: 0 } });
  assert.equal(parseRange("10.0.0.9-10.0.0.1").ok, false);
  assert.equal(parseRange("10.0.0.0/33").ok, false);
});

test("store applies only the current job, buffers events that race the start reply", () => {
  const timers: Array<() => void> = [];
  const store = new ScanStore((fn) => timers.push(fn));
  const ev = (scanId: number, ip: string): ScanEventPayload => ({ scanId, event: { type: "device", data: device(ip) } });

  store.beginStart("scan");
  store.handlePayload(ev(7, "10.0.0.1")); // arrives before start_scan resolves
  store.handlePayload(ev(6, "10.0.0.99")); // stale job
  store.startResolved(7);
  store.handlePayload(ev(7, "10.0.0.2"));
  store.handlePayload(ev(8, "10.0.0.3")); // unknown job
  const snap = store.flushNow();
  assert.deepEqual(snap.rows.map((r) => r.key).sort(), ["10.0.0.1", "10.0.0.2"]);
  assert.equal(snap.running, true);
  assert.equal(timers.length > 0, true);

  store.handlePayload({ scanId: 7, event: { type: "finished", data: { devices: 2, vlans: 0, neighbors: 0, elapsedMs: 5, cancelled: false } } });
  assert.equal(store.flushNow().running, false);
});

test("device snapshots upsert by ip@vlan and keep user overrides", () => {
  const store = new ScanStore(() => undefined);
  store.setOverrides({ "10.0.0.1@20": { hostname: "core-sw", comments: "rack 4" } });
  store.apply({ type: "device", data: device("10.0.0.1", { vlanId: 20, hostname: "from-net" }) });
  store.apply({ type: "device", data: device("10.0.0.1", { vlanId: null }) });
  store.apply({ type: "device", data: device("10.0.0.1", { vlanId: 20, vendor: "Cisco" }) });
  const rows = store.flushNow().rows;
  assert.equal(rows.length, 2);
  const tagged = rows.find((r) => r.key === "10.0.0.1@20");
  assert.ok(tagged);
  assert.equal(tagged.hostname, "core-sw");
  assert.equal(tagged.comments, "rack 4");
  assert.equal(tagged.device.vendor, "Cisco");
  assert.equal(exportDevice(tagged).hostname, "core-sw");

  store.setOverride("10.0.0.1@20", { hostname: null, comments: null });
  const after = store.flushNow().rows.find((r) => r.key === "10.0.0.1@20");
  assert.equal(after?.hostname, "");
});

test("row search text includes all visible columns", () => {
  const row = buildRow(
    "10.0.0.5",
    device("10.0.0.5", {
      mac: "aa:bb:cc:dd:ee:ff",
      role: "access_point",
      switchPort: { switchName: "Cisco-SW01", switchIp: null, portName: "Gi1/0/24", portIndex: 24, vlanId: 10, mac: "aa:bb:cc:dd:ee:ff" },
      openPorts: [22, 443],
    }),
    undefined,
  );
  assert.equal(row.switchPort, "Cisco-SW01 [Gi1/0/24]");
  for (const t of ["10.0.0.5", "aa:bb", "access point", "gi1/0/24", "443"]) assert.ok(row.search.includes(t), t);
});

test("50k-row snapshot builds quickly", () => {
  const store = new ScanStore(() => undefined);
  for (let i = 0; i < 50_000; i++) {
    store.apply({ type: "device", data: device(`10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`) });
  }
  const t0 = performance.now();
  const snap = store.flushNow();
  const build = performance.now() - t0;
  const t1 = performance.now();
  const sorted = [...snap.rows].sort((a, b) => (a.ipSort < b.ipSort ? -1 : a.ipSort > b.ipSort ? 1 : 0));
  const sort = performance.now() - t1;
  assert.equal(sorted.length, 50_000);
  assert.ok(build < 1500, `build ${build}ms`);
  assert.ok(sort < 1000, `sort ${sort}ms`);
});

test("infra helpers", () => {
  assert.deepEqual(
    normalizePortMacCounts([
      { portName: "Gi1/0/10", portIndex: 10, macCount: 2 },
      { portName: "Gi1/0/2", portIndex: 2, macCount: 5 },
    ]),
    [
      ["Gi1/0/2", 5],
      ["Gi1/0/10", 2],
    ],
  );
  const n: CdpLldpNeighbor = {
    protocol: "cdp",
    localInterface: "en0",
    sourceMac: "00-1B-54-00-00-01",
    deviceId: "SW1",
    systemName: null,
    systemDescription: null,
    portId: "Gi1/0/48",
    portDescription: null,
    platform: null,
    softwareVersion: null,
    managementAddrs: ["10.9.9.9"],
    nativeVlan: 1,
    voiceVlan: null,
    capabilities: ["switch"],
    vtpDomain: null,
    ttlSecs: 180,
    lastSeenMs: 0,
  };
  assert.equal(neighborsForDevice(device("10.0.0.2", { mac: "00:1b:54:00:00:01" }), [n]).length, 1);
  assert.equal(neighborsForDevice(device("10.9.9.9"), [n]).length, 1);
  assert.equal(neighborsForDevice(device("10.0.0.3"), [n]).length, 0);
});
