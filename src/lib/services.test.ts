// Unit tests for the deeper-discovery and audit-report logic: Model/Firmware precedence, PoE
// tones, device kinds, RTSP candidates, service merging, column auto-show and the report input
// (secret stripping, chunked device conversion, SNMP results keyed by IP).

import { test } from "node:test";
import assert from "node:assert/strict";
import type { Device, OnvifInfo, PoeInfo, ScanConfig, SipInfo, SnmpAgentStatus, SnmpConfig, SnmpDeviceInfo, SsdpInfo } from "../types.ts";
import {
  budgetUsage,
  deviceKindLabel,
  deviceKindOf,
  dhcpOsLabel,
  modelFirmware,
  modelSerialText,
  netServiceBadges,
  poeTone,
  portPoeTotal,
  rtspCandidates,
  safeHttpUrl,
  shortUrn,
  withServiceDiscovery,
} from "./services.ts";
import { detectAutoColumns, effectiveVisibility } from "./columns.ts";
import { ScanStore, buildRow, summaryMeta } from "./store.ts";
import { MAX_SNMP_AGENTS, recordAgent, reportSnmpAgents, reportSnmpInfos, snmpViewFor } from "./snmpAgents.ts";
import {
  buildReportArgs,
  buildReportMeta,
  classifyCommunity,
  ipOfKey,
  leaksSecret,
  snmpMeta,
  snmpSecrets,
  vlanSpec,
  type ScanContext,
} from "./report.ts";

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
    latency: null,
    webTitle: null,
    webServer: null,
    tlsCert: null,
    webIdentity: null,
    warnings: [],
    ...patch,
  };
}

const ssdp = (p: Partial<SsdpInfo>): SsdpInfo => ({
  location: null,
  server: null,
  searchTarget: null,
  usn: null,
  friendlyName: null,
  manufacturer: null,
  modelName: null,
  modelNumber: null,
  modelDescription: null,
  serialNumber: null,
  deviceType: null,
  udn: null,
  presentationUrl: null,
  services: [],
  ...p,
});

const onvif = (p: Partial<OnvifInfo>): OnvifInfo => ({
  xaddrs: [],
  types: null,
  scopes: [],
  name: null,
  location: null,
  manufacturer: null,
  model: null,
  firmwareVersion: null,
  serialNumber: null,
  hardwareId: null,
  isCamera: false,
  isWindows: false,
  rtspUrl: null,
  rtspHints: [],
  ...p,
});

const sip = (p: Partial<SipInfo>): SipInfo => ({
  status: null,
  server: null,
  userAgent: null,
  allow: null,
  supported: null,
  transport: null,
  vendor: null,
  model: null,
  firmware: null,
  kind: null,
  ...p,
});

const poe = (p: Partial<PoeInfo>): PoeInfo => ({
  watts: null,
  maxWatts: null,
  class: null,
  status: null,
  source: null,
  priority: null,
  switchName: null,
  port: null,
  ...p,
});

test("model/firmware: SIP, then ONVIF, then UPnP (backend export format)", () => {
  const all = {
    sip: sip({ model: "SIP-T54W", firmware: "96.86.0.5" }),
    onvif: onvif({ model: "DS-2CD2143G2-I", firmwareVersion: "V5.7.3" }),
    ssdp: ssdp({ modelName: "MediaServer", modelNumber: "7" }),
  };
  assert.equal(modelFirmware(all), "SIP-T54W / 96.86.0.5");
  assert.equal(modelFirmware({ ...all, sip: sip({ vendor: "Asterisk" }) }), "DS-2CD2143G2-I / V5.7.3", "a SIP answer without model/firmware falls through");
  assert.equal(modelFirmware({ sip: sip({ firmware: "20.9.2" }) }), "fw 20.9.2");
  assert.equal(modelFirmware({ onvif: onvif({ model: "Q6135" }) }), "Q6135");
  assert.equal(modelFirmware({ ssdp: ssdp({ modelName: "DS920+", modelNumber: "DS920" }) }), "DS920+", "number already in the name");
  assert.equal(modelFirmware({ ssdp: ssdp({ modelName: "Plex Media Server", modelNumber: "1.41" }) }), "Plex Media Server 1.41");
  assert.equal(modelFirmware({ ssdp: ssdp({ modelNumber: "AllShare1.0" }) }), "AllShare1.0");
  assert.equal(modelFirmware({ ssdp: ssdp({ modelName: "  " }) }), "");
  assert.equal(modelFirmware({}), "");
  assert.equal(
    modelSerialText({ onvif: onvif({ manufacturer: "HIKVISION", model: "DS-2CD", firmwareVersion: "V5", serialNumber: "SN1" }) }),
    "HIKVISION DS-2CD / V5, S/N SN1",
  );
  assert.equal(modelSerialText({}), "");
});

test("PoE tones by load: allocation, class budget, absolute fallback, fault", () => {
  assert.equal(poeTone(null), "none");
  assert.equal(poeTone(poe({ maxWatts: 15.4 })), "none", "budget only, nothing drawn");
  assert.equal(poeTone(poe({ watts: 6, maxWatts: 15.4 })), "ok");
  assert.equal(poeTone(poe({ watts: 11.6, maxWatts: 15.4 })), "ok", "75 % of the allocation is normal");
  assert.equal(poeTone(poe({ watts: 13.2, maxWatts: 15.4 })), "warn", ">= 85 % of the allocation");
  assert.equal(poeTone(poe({ watts: 15.2, maxWatts: 15.4 })), "bad", ">= 98 % of the allocation");
  assert.equal(poeTone(poe({ watts: 16, maxWatts: 15.4 })), "bad", "over the allocation");
  // Class 2 PDs may draw 6.49 W.
  assert.equal(poeTone(poe({ watts: 3, class: 2 })), "ok");
  assert.equal(poeTone(poe({ watts: 5.8, class: 2 })), "warn");
  assert.equal(poeTone(poe({ watts: 6.4, class: 2 })), "bad");
  // No allocation or class: absolute 802.3af / at limits.
  assert.equal(poeTone(poe({ watts: 15 })), "ok");
  assert.equal(poeTone(poe({ watts: 20 })), "warn");
  assert.equal(poeTone(poe({ watts: 45 })), "bad");
  assert.equal(poeTone(poe({ status: "fault" })), "bad");
});

test("PoE budget usage and per-port totals", () => {
  assert.equal(budgetUsage(null), null);
  const u = budgetUsage({ nominalWatts: 740, consumedWatts: 185, usageThresholdPct: 80, portsDelivering: 12 });
  assert.equal(u?.pct, 25);
  assert.equal(u?.tone, "ok");
  assert.equal(budgetUsage({ nominalWatts: 370, consumedWatts: 300, usageThresholdPct: 80, portsDelivering: 30 })?.tone, "warn");
  assert.equal(budgetUsage({ nominalWatts: 370, consumedWatts: 300, usageThresholdPct: null, portsDelivering: 30 })?.tone, "warn", "default 80 %");
  assert.equal(budgetUsage({ nominalWatts: 370, consumedWatts: 360, usageThresholdPct: 99, portsDelivering: 30 })?.tone, "bad");
  assert.equal(budgetUsage({ nominalWatts: null, consumedWatts: null, usageThresholdPct: null, portsDelivering: 0 }), null);
  const m = (port: string, w: number | null) => ({ switchName: "sw", switchIp: null, portName: port, portIndex: null, vlanId: 1, mac: "x", poe: w === null ? null : poe({ watts: w }) });
  // One value per port (several MACs behind a phone share its port).
  assert.deepEqual(portPoeTotal([m("Gi1/0/1", 5), m("Gi1/0/1", 5), m("Gi1/0/2", 10), m("Gi1/0/3", null)]), { watts: 15, ports: 2 });
  assert.equal(portPoeTotal([m("Gi1/0/3", null)]), null);
});

test("device kinds: labels, unknown strings as-is, fallbacks from service data", () => {
  assert.equal(deviceKindLabel("voip_phone"), "IP Phone");
  assert.equal(deviceKindLabel("igd_router"), "Internet Gateway");
  assert.equal(deviceKindLabel("smart_fridge"), "smart fridge");
  assert.equal(deviceKindLabel(null), "");
  assert.equal(deviceKindOf({ deviceKind: "printer" }), "printer");
  assert.equal(deviceKindOf({ sip: sip({ kind: "pbx" }) }), "pbx");
  assert.equal(deviceKindOf({ onvif: onvif({ isCamera: true }) }), "camera");
  assert.equal(deviceKindOf({ onvif: onvif({ isWindows: true }) }), "computer");
  assert.equal(deviceKindOf({}), null);
  assert.equal(dhcpOsLabel({ os: "Windows", confidence: "high", vendorClass: null, hostname: null, paramList: [] }), "Windows (high)");
  assert.equal(dhcpOsLabel({ os: null, confidence: null, vendorClass: "MSFT 5.0", hostname: null, paramList: [1] }), "");
});

test("RTSP: the camera's own URL first, guesses stripped of their label, non-RTSP dropped", () => {
  const c = rtspCandidates(
    onvif({
      rtspUrl: "rtsp://10.0.0.5:554/stream1",
      rtspHints: ["rtsp://10.0.0.5:554/Streaming/Channels/101 (guess, no credentials tried)", "javascript:alert(1) (guess, no credentials tried)", "rtsp://10.0.0.5:554/stream1"],
    }),
  );
  assert.deepEqual(c, [
    { url: "rtsp://10.0.0.5:554/stream1", guess: false },
    { url: "rtsp://10.0.0.5:554/Streaming/Channels/101", guess: true },
  ]);
  assert.deepEqual(rtspCandidates(null), []);
  assert.equal(safeHttpUrl("http://10.0.0.5/"), "http://10.0.0.5/");
  assert.equal(safeHttpUrl("javascript:alert(1)"), null);
  assert.equal(safeHttpUrl("file:///etc/passwd"), null);
  assert.equal(shortUrn("urn:schemas-upnp-org:service:AVTransport:1"), "AVTransport:1");
});

test("discover_services results merge into the device; rows are searchable by the new fields", () => {
  const before = device("10.0.0.9", { sources: ["arp"], ssdp: ssdp({ friendlyName: "old" }) });
  const after = withServiceDiscovery(before, { ip: "10.0.0.9", deviceKind: "voip_phone", ssdp: null, onvif: null, sip: sip({ vendor: "Yealink", model: "SIP-T54W", kind: "voip_phone" }) });
  assert.equal(after.ssdp?.friendlyName, "old", "a null part keeps what the scan found");
  assert.equal(after.sip?.model, "SIP-T54W");
  assert.equal(after.deviceKind, "voip_phone");
  assert.deepEqual(after.sources, ["arp", "sip"]);
  const row = buildRow("10.0.0.9", { ...after, voiceVlan: 30, dhcpFingerprint: { os: "Yealink IP phone", confidence: "high", vendorClass: "yealink", hostname: "SIP-T54W-1", paramList: [] } }, undefined);
  assert.equal(row.kind, "IP Phone");
  assert.equal(row.modelFw, "SIP-T54W");
  assert.equal(row.dhcpOs, "Yealink IP phone (high)");
  for (const term of ["phone", "voip_phone", "yealink", "sip-t54w", "voice 30"]) assert.ok(row.search.includes(term), term);
});

test("new columns show up automatically once some device has data; explicit choices win", () => {
  const rows = [
    buildRow("a", device("10.0.0.1"), undefined),
    buildRow("b", device("10.0.0.2", { poe: poe({ watts: 4 }), voiceVlan: 30 }), undefined),
  ];
  const auto = detectAutoColumns(rows);
  assert.deepEqual(auto, { webTitle: false, certExpires: false, deviceKind: false, modelFw: false, poe: true, voiceVlan: true, dhcpOs: false });
  const vis = effectiveVisibility({ voiceVlan: false }, { liveLatency: false, ...auto });
  assert.equal(vis.poe, true);
  assert.equal(vis.voiceVlan, false, "hidden from the header menu stays hidden");
  assert.equal(vis.deviceKind, false);
  // A budget-only PoE advert (nothing drawn yet) still counts as data; an empty object does not.
  assert.equal(detectAutoColumns([buildRow("c", device("10.0.0.3", { poe: poe({}) }), undefined)]).poe, false);
});

// --- report input -----------------------------------------------------------------------------

const SECRET_COMMUNITY = "s3cr3t-Community!";
const AUTH = "auth-pass-123";
const PRIV = "priv-pass-456";

function config(snmp: SnmpConfig | null): ScanConfig {
  return {
    interface: "en0",
    range: "10.0.0.0/24, 10.0.1.0/24",
    vlans: { mode: "untagged_and_list", ids: [10, 20] },
    discoverVlans: false,
    cdpLldp: true,
    snmp,
    snmpAll: false,
    ipv6: false,
    ports: [22, 23, 80, 443, 1000, 1001, 1002],
    resolveNames: true,
    timeoutMs: 1500,
    retries: 1,
    ratePps: 2000,
    concurrency: 512,
    listenSecs: 10,
    webIdentity: true,
    discoverServices: true,
    sipAll: false,
    dhcpFingerprint: false,
  };
}

const ctx = (c: ScanConfig | null): ScanContext => ({
  config: c,
  iface: "en0",
  defaultRanges: ["10.9.0.0/24"],
  startedMs: 1000,
  finishedMs: 5000,
  cancelled: false,
  toolVersion: "SweepR 0.1.0",
});

test("report metadata: the scan config without SNMP secrets", () => {
  assert.equal(classifyCommunity("public"), "public");
  assert.equal(classifyCommunity(" private "), "private");
  assert.equal(classifyCommunity(""), "none");
  assert.equal(classifyCommunity(SECRET_COMMUNITY), "custom");
  assert.equal(vlanSpec({ mode: "untagged_and_list", ids: [10, 20] }), "untagged,10,20");
  assert.equal(vlanSpec({ mode: "auto_detect" }), "auto");

  const v2: SnmpConfig = { version: "v2c", community: SECRET_COMMUNITY, v3: null, port: 161, timeoutMs: 2000, retries: 1 };
  const meta = buildReportMeta(ctx(config(v2)));
  assert.deepEqual(meta, {
    toolVersion: "SweepR 0.1.0",
    interface: "en0",
    ranges: ["10.0.0.0/24", "10.0.1.0/24"],
    vlans: "untagged,10,20",
    portSpec: "22,23,80,443,1000-1002",
    ipv6: false,
    cdpLldp: true,
    discoverVlans: false,
    resolveNames: true,
    snmpAll: false,
    snmp: { version: "v2c", communityKind: "custom" },
    startedMs: 1000,
    finishedMs: 5000,
  });
  assert.equal(JSON.stringify(meta).includes(SECRET_COMMUNITY), false);
  assert.equal(leaksSecret(meta, snmpSecrets(v2)), false);
  assert.equal(leaksSecret({ snmp: { community: SECRET_COMMUNITY } }, snmpSecrets(v2)), true, "the leak check catches a raw community");

  const v3: SnmpConfig = {
    version: "v3",
    community: SECRET_COMMUNITY,
    v3: { username: "monitor", authProtocol: "sha256", authPassword: AUTH, privProtocol: "aes128", privPassword: PRIV },
    port: 161,
    timeoutMs: 2000,
    retries: 1,
  };
  assert.deepEqual(snmpMeta(v3), { version: "v3" });
  const m3 = buildReportMeta(ctx(config(v3)));
  const json = JSON.stringify(m3);
  for (const s of [SECRET_COMMUNITY, AUTH, PRIV, "monitor"]) assert.equal(json.includes(s), false, s);
  assert.deepEqual(snmpSecrets(v3), [AUTH, PRIV]);

  // No SNMP: the SNMP rules are "not evaluated"; no scan: only what is known.
  assert.equal(buildReportMeta(ctx(config(null))).snmp, undefined);
  const none = buildReportMeta({ ...ctx(null), startedMs: null, finishedMs: null, toolVersion: null });
  assert.deepEqual(none, { interface: "en0" });
  // Empty range: the interface subnet.
  assert.deepEqual(buildReportMeta(ctx({ ...config(null), range: null })).ranges, ["10.9.0.0/24"]);
});

test("report input: devices as exported, built in chunks; SNMP results keyed by IP", async () => {
  assert.equal(ipOfKey("10.0.0.1@20"), "10.0.0.1");
  assert.equal(ipOfKey("fe80::1"), "fe80::1");
  const rows = Array.from({ length: 12 }, (_, i) => buildRow(`10.0.0.${i}`, device(`10.0.0.${i}`), i === 3 ? { hostname: "core", comments: "rack 4" } : undefined));
  const snmpInfo: SnmpDeviceInfo = {
    sysName: "sw1",
    sysDescr: null,
    sysUptimeTicks: null,
    sysObjectId: null,
    role: "switch",
    vlans: [],
    portMappings: [],
    portMacCounts: [],
    poeBudget: { nominalWatts: 740, consumedWatts: 100, usageThresholdPct: 80, portsDelivering: 5 },
    partial: false,
    warnings: [],
  };
  const pauses: number[] = [];
  const args = await buildReportArgs(
    {
      rows,
      latency: (ip) =>
        ip === "10.0.0.4" ? { lastMs: 1, avgMs: 2, minMs: 1, maxMs: 3, jitterMs: 0.5, lossPct: 0, sent: 3, received: 3, method: "icmp", updatedMs: 9 } : undefined,
      vlans: [],
      neighbors: [],
      portMappings: [],
      snmp: { "10.0.0.2@20": snmpInfo },
    },
    { toolVersion: "x" },
    { format: "html", title: "  Audit  ", org: "  " },
    async (p) => {
      pauses.push(p.done);
    },
    5,
  );
  assert.deepEqual(pauses, [5, 10], "yields between chunks, not after the last");
  assert.equal(args.devices.length, 12);
  assert.equal(args.devices[3]?.hostname, "core");
  assert.equal(args.devices[3]?.comments, "rack 4");
  assert.equal(args.devices[0]?.hostname, null);
  assert.equal(args.devices[4]?.latency?.avgMs, 2);
  assert.equal(args.snmpInfos?.[0]?.ip, "10.0.0.2");
  assert.equal(args.snmpInfos?.[0]?.poeBudget?.nominalWatts, 740);
  assert.equal(args.title, "Audit");
  assert.equal("org" in args, false, "blank organization is omitted");
  assert.equal(args.format, "html");
});

// --- snmp_agent events, scan summary metadata, DHCP / RA badges --------------------------------------

function agent(ip: string | null, patch: Partial<SnmpAgentStatus> = {}): SnmpAgentStatus {
  return {
    ip,
    version: "v2c",
    communityClass: "custom",
    answered: true,
    partial: false,
    sysName: ip ? `sw-${ip}` : null,
    sysDescr: "Cisco IOS-XE",
    role: "switch",
    poeBudget: null,
    warnings: [],
    ...patch,
  };
}

const BUDGET = { nominalWatts: 370, consumedWatts: 300, usageThresholdPct: 80, portsDelivering: 30 };

test("snmp agents: bounded, answered stays answered, no IP dropped", () => {
  const m = new Map<string, SnmpAgentStatus>();
  assert.equal(recordAgent(m, agent(null)), false);
  assert.equal(recordAgent(m, agent("10.0.0.2")), true);
  assert.equal(recordAgent(m, agent("10.0.0.2", { answered: false, sysName: null })), false, "a later timeout keeps the answer");
  assert.equal(m.get("10.0.0.2")?.sysName, "sw-10.0.0.2");
  assert.equal(recordAgent(m, agent("10.0.0.3", { answered: false })), true);
  assert.equal(recordAgent(m, agent("10.0.0.3")), true, "an answer replaces a timeout");
  assert.equal(recordAgent(m, agent("10.0.0.4"), 2), false, "cap");
  assert.equal(m.size, 2);
  assert.ok(MAX_SNMP_AGENTS >= 1000);
});

test("snmp agents feed the report: meta.snmpAgents and snmpInfos, query results win", () => {
  const agents = [
    agent("10.0.0.2", { poeBudget: BUDGET, sysName: "from-agent" }),
    agent("10.0.0.3", { role: null, partial: true, warnings: ["walk truncated"] }),
    agent("10.0.0.9", { answered: false, communityClass: "public", sysName: null }),
    agent(null),
  ];
  assert.deepEqual(reportSnmpAgents(agents), [
    { ip: "10.0.0.2", version: "v2c", communityClass: "custom", answered: true },
    { ip: "10.0.0.3", version: "v2c", communityClass: "custom", answered: true },
    { ip: "10.0.0.9", version: "v2c", communityClass: "public", answered: false },
  ]);
  const query: SnmpDeviceInfo & { ip: string } = {
    ip: "10.0.0.2",
    sysName: "from-query",
    sysDescr: null,
    sysUptimeTicks: 5,
    sysObjectId: null,
    role: "switch",
    vlans: [],
    portMappings: [],
    portMacCounts: [],
    poeBudget: null,
    partial: false,
    warnings: [],
  };
  const infos = reportSnmpInfos([query], agents);
  assert.equal(infos.length, 2, "timeouts add no snmpInfos entry");
  assert.equal(infos[0]?.sysName, "from-query", "query wins");
  assert.equal(infos[0]?.sysDescr, "Cisco IOS-XE", "agent fills gaps");
  assert.deepEqual(infos[0]?.poeBudget, BUDGET, "agent PoE budget fills a query without one");
  assert.equal(infos[0]?.sysUptimeTicks, 5);
  assert.deepEqual(infos[1], { ip: "10.0.0.3", sysName: "sw-10.0.0.3", sysDescr: "Cisco IOS-XE", poeBudget: null, partial: true, warnings: ["walk truncated"] });
  assert.equal("role" in infos[1]!, false, "a null role is omitted (the backend defaults it)");
});

test("snmp view: agents fill devices nobody queried (by IP, also VLAN keys), queries merge the budget", () => {
  const agents = new Map([
    ["10.0.0.2", agent("10.0.0.2", { poeBudget: BUDGET })],
    ["10.0.20.1", agent("10.0.20.1", { role: null })],
    ["10.0.0.9", agent("10.0.0.9", { answered: false })],
  ]);
  const query: SnmpDeviceInfo = { sysName: "q", sysDescr: null, sysUptimeTicks: 1, sysObjectId: null, role: "switch", vlans: [], portMappings: [], portMacCounts: [], poeBudget: null, partial: false, warnings: [] };
  const keys: Record<string, string[]> = { "10.0.0.2": ["10.0.0.2"], "10.0.20.1": ["10.0.20.1@20"], "10.0.0.9": ["10.0.0.9"], "10.0.0.5": ["10.0.0.5"] };
  const view = snmpViewFor(
    { "10.0.0.5": query, "10.0.0.2": { ...query, sysName: "queried" } },
    agents,
    (ip) => keys[ip] ?? [],
    (key) => (key === "10.0.20.1@20" ? "router" : undefined),
    (key) => key.split("@")[0]!,
  );
  assert.equal(view["10.0.0.2"]?.sysName, "queried");
  assert.deepEqual(view["10.0.0.2"]?.poeBudget, BUDGET);
  assert.equal(view["10.0.0.2"]?.fromScan, undefined);
  assert.equal(view["10.0.20.1@20"]?.fromScan, true);
  assert.equal(view["10.0.20.1@20"]?.role, "router", "null agent role falls back to the device's");
  assert.equal(view["10.0.0.9"], undefined, "timeouts are not shown as SNMP data");
  assert.equal(view["10.0.0.5"], query);
});

test("store: snmp_agent events and the full scan's summary metadata, per scan job", () => {
  const timers: Array<() => void> = [];
  const store = new ScanStore((fn) => timers.push(fn));
  const t = store.beginStart("scan");
  store.startResolved(1, t);
  store.handlePayload({ scanId: 1, event: { type: "device", data: device("10.0.0.2", { role: "switch" }) } });
  store.handlePayload({ scanId: 1, event: { type: "snmp_agent", data: agent("10.0.0.2", { poeBudget: BUDGET }) } });
  store.handlePayload({ scanId: 1, event: { type: "snmp_agent", data: agent("10.0.0.7", { answered: false }) } });
  store.handlePayload({ scanId: 2, event: { type: "snmp_agent", data: agent("10.0.0.8") } });
  store.handlePayload({
    scanId: 1,
    event: { type: "finished", data: { devices: 1, vlans: 0, neighbors: 0, elapsedMs: 5, cancelled: false, interface: "en0", gateway: "10.0.0.1", scannerHost: "mac.local" } },
  });
  let snap = store.flushNow();
  assert.deepEqual(snap.snmpAgents.map((a) => a.ip), ["10.0.0.2", "10.0.0.7"]);
  assert.deepEqual(snap.snmpView["10.0.0.2"]?.poeBudget, BUDGET, "switch PoE without Query SNMP");
  assert.deepEqual(snap.snmpAgents.length, 2);
  assert.deepEqual(snap.scanMeta, { interface: "en0", gateway: "10.0.0.1", scannerHost: "mac.local" });
  assert.deepEqual(snap.snmp, {}, "query results stay separate");
  // VLAN discovery keeps the scan's agents and metadata (its summary has neither).
  const t2 = store.beginStart("vlan_discovery");
  store.startResolved(2, t2);
  store.handlePayload({ scanId: 2, event: { type: "finished", data: { devices: 0, vlans: 3, neighbors: 1, elapsedMs: 5, cancelled: false } } });
  snap = store.flushNow();
  assert.equal(snap.snmpAgents.length, 2);
  assert.equal(snap.scanMeta?.gateway, "10.0.0.1");
  // A new full scan starts over.
  const t3 = store.beginStart("scan");
  store.startResolved(3, t3);
  snap = store.flushNow();
  assert.equal(snap.snmpAgents.length, 0);
  assert.equal(snap.scanMeta, null);
  // Absent summary fields never clear known values.
  assert.deepEqual(summaryMeta({ devices: 0, vlans: 0, neighbors: 0, elapsedMs: 0, cancelled: true }, { gateway: "10.0.0.1" }), { gateway: "10.0.0.1" });
  assert.equal(summaryMeta({ devices: 0, vlans: 0, neighbors: 0, elapsedMs: 0, cancelled: false, interface: " " }), null);
});

test("report metadata: interface / gateway / scanner host from the scan summary, agents without secrets", () => {
  const v2: SnmpConfig = { version: "v2c", community: SECRET_COMMUNITY, v3: null, port: 161, timeoutMs: 2000, retries: 1 };
  const meta = buildReportMeta({
    ...ctx(config(v2)),
    summary: { interface: "en7", gateway: "10.0.0.1", scannerHost: "mac.local" },
    snmpAgents: [agent("10.0.0.2"), agent("10.0.0.3", { answered: false, communityClass: "public" })],
  });
  assert.equal(meta.interface, "en7", "the backend's interface wins");
  assert.equal(meta.gateway, "10.0.0.1");
  assert.equal(meta.scannerHost, "mac.local");
  assert.deepEqual(meta.snmpAgents?.map((a) => [a.ip, a.communityClass, a.answered]), [
    ["10.0.0.2", "custom", true],
    ["10.0.0.3", "public", false],
  ]);
  assert.equal(leaksSecret(meta, snmpSecrets(v2)), false);
  // No summary: the config's / resolved interface, and no gateway key at all.
  const plain = buildReportMeta({ ...ctx(config(v2)), summary: { gateway: undefined } as never });
  assert.equal(plain.interface, "en0");
  assert.equal("gateway" in plain, false);
  assert.equal("scannerHost" in plain, false);
  assert.equal("snmpAgents" in plain, false);
});

test("DHCP server / IPv6 RA badges and search", () => {
  assert.deepEqual(netServiceBadges({ dhcpServer: true, ipv6Router: null }).map((b) => b.label), ["DHCP server"]);
  assert.deepEqual(netServiceBadges({ dhcpServer: false, ipv6Router: true }).map((b) => b.label), ["IPv6 RA"]);
  assert.deepEqual(netServiceBadges({}), []);
  const row = buildRow("10.0.0.77", device("10.0.0.77", { dhcpServer: true, ipv6Router: true }), undefined);
  assert.ok(row.search.includes("dhcp server"));
  assert.ok(row.search.includes("ipv6 ra"));
  assert.ok(row.search.includes("router advertisement"));
  assert.equal(buildRow("10.0.0.5", device("10.0.0.5"), undefined).search.includes("dhcp server"), false);
  assert.equal(deviceKindLabel("media_player"), "Media Player");
});
