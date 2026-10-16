// Unit tests for the deeper-discovery and audit-report logic: Model/Firmware precedence, PoE
// tones, device kinds, RTSP candidates, service merging, column auto-show and the report input
// (secret stripping, chunked device conversion, SNMP results keyed by IP).

import { test } from "node:test";
import assert from "node:assert/strict";
import type { Device, OnvifInfo, PoeInfo, ScanConfig, SipInfo, SnmpConfig, SnmpDeviceInfo, SsdpInfo } from "../types.ts";
import {
  budgetUsage,
  deviceKindLabel,
  deviceKindOf,
  dhcpOsLabel,
  modelFirmware,
  modelSerialText,
  poeTone,
  portPoeTotal,
  rtspCandidates,
  safeHttpUrl,
  shortUrn,
  withServiceDiscovery,
} from "./services.ts";
import { detectAutoColumns, effectiveVisibility } from "./columns.ts";
import { buildRow } from "./store.ts";
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
