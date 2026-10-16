// Simulated deeper-discovery data for the mock backend: SIP phones on a voice VLAN drawing PoE,
// ONVIF cameras, a PBX per /24, printers / TVs / NAS / media servers via SSDP, Windows hosts via
// WS-Discovery and passive DHCP fingerprints, plus `discover_services` and a browser-side
// `generate_report` / `reveal_report`. Deterministic per IP so rescans look the same.

import type {
  Device,
  DhcpFingerprint,
  GenerateReportArgs,
  OnvifInfo,
  PoeInfo,
  ServiceDiscovery,
  SipInfo,
  SsdpInfo,
} from "./types.ts";
import { ipv4ToNumber } from "./lib/ip.ts";

export const MOCK_VOICE_VLAN = 30;

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

const round1 = (n: number): number => Math.round(n * 10) / 10;

function ssdp(patch: Partial<SsdpInfo>): SsdpInfo {
  return {
    location: null,
    server: null,
    searchTarget: "upnp:rootdevice",
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
    ...patch,
  };
}

function onvif(patch: Partial<OnvifInfo>): OnvifInfo {
  return {
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
    ...patch,
  };
}

function sip(patch: Partial<SipInfo>): SipInfo {
  return {
    status: "200 OK",
    server: null,
    userAgent: null,
    allow: "INVITE, ACK, CANCEL, BYE, NOTIFY, REFER, OPTIONS, INFO, SUBSCRIBE, UPDATE, MESSAGE",
    supported: "replaces, timer, norefersub",
    transport: "udp",
    vendor: null,
    model: null,
    firmware: null,
    kind: null,
    ...patch,
  };
}

function uuid(r: () => number): string {
  const hex = (n: number): string =>
    Array.from({ length: n }, () => Math.floor(r() * 16).toString(16)).join("");
  return `uuid:${hex(8)}-${hex(4)}-${hex(4)}-${hex(4)}-${hex(12)}`;
}

function serial(r: () => number, prefix: string, len = 9): string {
  return prefix + Array.from({ length: len }, () => "0123456789ABCDEFGHJKLMNPRSTUVWXYZ"[Math.floor(r() * 33)]).join("");
}

const PARAMS = {
  windows: [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252],
  macos: [1, 121, 3, 6, 15, 108, 114, 119, 252, 95, 44, 46],
  ios: [1, 121, 3, 6, 15, 108, 114, 119, 252],
  android: [1, 3, 6, 15, 26, 28, 51, 58, 59, 43, 114, 108],
  linux: [1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42],
  yealink: [1, 2, 3, 4, 6, 7, 12, 15, 28, 42, 43, 60, 66, 120, 125],
  embedded: [1, 3, 6, 12, 15, 28, 42],
};

function dhcp(os: string | null, confidence: DhcpFingerprint["confidence"], params: number[], vendorClass: string | null, hostname: string | null): DhcpFingerprint {
  return { os, confidence, vendorClass, hostname, paramList: params };
}

export interface MockServiceOptions {
  discoverServices: boolean;
  dhcpFingerprint: boolean;
  /** PoE / voice VLAN come from the switch (SNMP) or the endpoint's own LLDP-MED advert. */
  snmp: boolean;
  cdpLldp: boolean;
}

/** PoE drawn by an endpoint (switch name / port only from SNMP data). */
function poeFor(r: () => number, cls: number, min: number, max: number, dev: Device, snmp: boolean): PoeInfo {
  const budget = [15.4, 4, 7, 15.4, 30, 45, 60, 75, 90][cls] ?? 15.4;
  return {
    watts: round1(min + r() * (max - min)),
    maxWatts: snmp ? budget : null,
    class: cls,
    status: "delivering",
    source: snmp ? null : "pse",
    priority: snmp ? null : cls >= 4 ? "high" : "low",
    switchName: snmp ? (dev.switchPort?.switchName ?? null) : null,
    port: snmp ? (dev.switchPort?.portName ?? null) : null,
  };
}

/**
 * Service / PoE / DHCP data for one simulated host (mutates and returns `dev`). `label` is the
 * host's generated name, used for DHCP option 12.
 */
export function addMockServices(dev: Device, label: string, o: MockServiceOptions): Device {
  const ipNum = ipv4ToNumber(dev.ip);
  if (ipNum === null) return dev;
  const r = rng(hash(`svc${dev.ip}@${dev.vlanId ?? ""}`));
  const vendor = dev.vendor ?? "";
  const octet = ipNum & 255;
  const sources = new Set(dev.sources);
  const poeVisible = o.snmp || o.cdpLldp;

  if (dev.role === "host" && octet === 20) {
    // One PBX per network (a VM or appliance: the vendor stays whatever the MAC says).
    if (o.discoverServices) {
      dev.sip = sip({ server: "Asterisk PBX 20.9.2", vendor: "Asterisk", firmware: "20.9.2", kind: "pbx", userAgent: null });
      dev.deviceKind = "pbx";
      dev.openPorts = [...new Set([...dev.openPorts, 5060])].sort((a, b) => a - b);
      sources.add("sip");
    }
    if (o.dhcpFingerprint) dev.dhcpFingerprint = dhcp("Linux (Debian)", "medium", PARAMS.linux, null, "pbx01");
  } else if (vendor.startsWith("Yealink")) {
    const model = pick(r, ["SIP-T54W", "SIP-T46U", "SIP-T33G", "W70B"]);
    const fw = pick(r, ["96.86.0.5", "108.86.0.45", "124.86.0.40"]);
    if (o.discoverServices) {
      dev.sip = sip({ userAgent: `Yealink ${model} ${fw}`, vendor: "Yealink", model, firmware: fw, kind: "voip_phone" });
      dev.deviceKind = "voip_phone";
      sources.add("sip");
    }
    if (poeVisible) {
      dev.voiceVlan = MOCK_VOICE_VLAN;
      dev.poe = poeFor(r, model === "SIP-T54W" ? 3 : 2, 3.2, model === "SIP-T54W" ? 11.8 : 5.9, dev, o.snmp);
    }
    if (o.dhcpFingerprint) dev.dhcpFingerprint = dhcp("Yealink IP phone", "high", PARAMS.yealink, "yealink", label);
  } else if (vendor.startsWith("Hikvision")) {
    const ptz = r() < 0.25;
    const model = ptz ? "DS-2DE4425IW-DE" : pick(r, ["DS-2CD2143G2-I", "DS-2CD2387G2-LU", "DS-2CD2T47G2-L"]);
    const fw = pick(r, ["V5.7.3 build 220112", "V5.7.15 build 230619", "V5.8.4 build 240216"]);
    if (o.discoverServices) {
      const sn = serial(r, "DS-", 12);
      const real = r() < 0.5;
      dev.onvif = onvif({
        xaddrs: [`http://${dev.ip}/onvif/device_service`],
        types: "dn:NetworkVideoTransmitter tds:Device",
        scopes: [
          "onvif://www.onvif.org/type/video_encoder",
          "onvif://www.onvif.org/Profile/Streaming",
          `onvif://www.onvif.org/hardware/${model}`,
          `onvif://www.onvif.org/name/HIKVISION%20${model}`,
          "onvif://www.onvif.org/location/city/hangzhou",
        ],
        name: `HIKVISION ${model}`,
        location: "city/hangzhou",
        manufacturer: "HIKVISION",
        model,
        firmwareVersion: fw,
        serialNumber: sn,
        hardwareId: "88",
        isCamera: true,
        rtspUrl: real ? `rtsp://${dev.ip}:554/Streaming/Channels/101?transportmode=unicast&profile=Profile_1` : null,
        rtspHints: real
          ? []
          : [
              `rtsp://${dev.ip}:554/Streaming/Channels/101 (guess, no credentials tried)`,
              `rtsp://${dev.ip}:554/Streaming/Channels/102 (guess, no credentials tried)`,
            ],
      });
      dev.deviceKind = "camera";
      dev.openPorts = [...new Set([...dev.openPorts, 80, 554])].sort((a, b) => a - b);
      sources.add("wsd");
    }
    if (poeVisible) dev.poe = poeFor(r, ptz ? 4 : 3, ptz ? 18 : 4.1, ptz ? 25.2 : 9.7, dev, o.snmp);
    if (o.dhcpFingerprint) dev.dhcpFingerprint = dhcp("Linux (embedded)", "low", PARAMS.embedded, null, null);
  } else if (vendor.startsWith("HP") && /print|laserjet/i.test(label)) {
    if (o.discoverServices) {
      const model = pick(r, ["HP LaserJet Pro M404dn", "HP Color LaserJet MFP M479fdw", "HP LaserJet Enterprise M507"]);
      const sn = serial(r, "PHB", 7);
      dev.ssdp = ssdp({
        location: `http://${dev.ip}:8080/description.xml`,
        server: "HP HTTP Server; HP LaserJet - 1.0; UPnP/1.0",
        friendlyName: `${model} [${sn.slice(-6)}]`,
        manufacturer: "HP",
        modelName: model,
        modelNumber: null,
        modelDescription: "HP printer",
        serialNumber: sn,
        deviceType: "urn:schemas-upnp-org:device:Printer:1",
        udn: uuid(r),
        presentationUrl: `http://${dev.ip}/`,
        services: ["urn:schemas-upnp-org:service:PrintBasic:1", "urn:schemas-upnp-org:service:PrintEnhanced:1"],
      });
      dev.deviceKind = "printer";
      sources.add("ssdp");
    }
    if (o.dhcpFingerprint) dev.dhcpFingerprint = dhcp("HP printer (JetDirect)", "medium", PARAMS.embedded, "Hewlett-Packard JetDirect", label);
  } else if (vendor.startsWith("Samsung")) {
    const tv = /tv/i.test(label) || r() < 0.4;
    if (o.discoverServices && tv) {
      const model = pick(r, ["QE55Q80B", "UE50AU7172", "QE65S95C"]);
      dev.ssdp = ssdp({
        location: `http://${dev.ip}:9197/dmr`,
        server: "SHP, UPnP/1.0, Samsung UPnP SDK/1.0",
        friendlyName: `[TV] Samsung ${pick(r, ["Q80B", "AU7100", "S95C"])} 55`,
        manufacturer: "Samsung Electronics",
        modelName: model,
        modelNumber: "AllShare1.0",
        modelDescription: "Samsung TV DMR",
        serialNumber: null,
        deviceType: "urn:schemas-upnp-org:device:MediaRenderer:1",
        udn: uuid(r),
        presentationUrl: null,
        services: [
          "urn:schemas-upnp-org:service:RenderingControl:1",
          "urn:schemas-upnp-org:service:ConnectionManager:1",
          "urn:schemas-upnp-org:service:AVTransport:1",
          "urn:dial-multiscreen-org:service:dial:1",
        ],
      });
      dev.deviceKind = "tv";
      sources.add("ssdp");
    }
    if (o.dhcpFingerprint) {
      dev.dhcpFingerprint = tv
        ? dhcp("Tizen (Samsung TV)", "medium", PARAMS.linux, "udhcp 1.30.1", label)
        : dhcp("Android 14", "medium", PARAMS.android, "android-dhcp-14", label);
    }
  } else if (vendor.startsWith("Synology")) {
    if (o.discoverServices) {
      const model = pick(r, ["DS920+", "DS1522+", "RS1221+"]);
      dev.ssdp = ssdp({
        location: `http://${dev.ip}:5000/description.xml`,
        server: "Synology/DSM/7.2 UPnP/1.0",
        friendlyName: `${label} (${model})`,
        manufacturer: "Synology",
        modelName: model,
        modelNumber: model.replace("+", ""),
        modelDescription: "Synology NAS",
        serialNumber: serial(r, "21A0", 8),
        deviceType: "urn:schemas-upnp-org:device:Basic:1",
        udn: uuid(r),
        presentationUrl: `http://${dev.ip}:5000/`,
        services: [],
      });
      dev.deviceKind = "nas";
      dev.openPorts = [...new Set([...dev.openPorts, 5000, 5001])].sort((a, b) => a - b);
      sources.add("ssdp");
    }
    if (o.dhcpFingerprint) dev.dhcpFingerprint = dhcp("Linux (Synology DSM)", "medium", PARAMS.linux, null, label);
  } else if (vendor.startsWith("Raspberry")) {
    if (o.discoverServices && r() < 0.35) {
      dev.ssdp = ssdp({
        location: `http://${dev.ip}:32469/DeviceDescription.xml`,
        server: "Linux/6.6 UPnP/1.0 Plex Media Server/1.41.3",
        friendlyName: `Plex Media Server: ${label}`,
        manufacturer: "Plex, Inc.",
        modelName: "Plex Media Server",
        modelNumber: "1.41.3",
        deviceType: "urn:schemas-upnp-org:device:MediaServer:1",
        udn: uuid(r),
        presentationUrl: `http://${dev.ip}:32400/web`,
        services: ["urn:schemas-upnp-org:service:ContentDirectory:1", "urn:schemas-upnp-org:service:ConnectionManager:1"],
      });
      dev.deviceKind = "media_server";
      sources.add("ssdp");
    }
    if (o.dhcpFingerprint) dev.dhcpFingerprint = dhcp("Linux (Debian)", "medium", PARAMS.linux, null, label);
  } else if (vendor.startsWith("Apple")) {
    if (o.dhcpFingerprint) {
      const mobile = /iphone|ipad/i.test(label);
      dev.dhcpFingerprint = mobile ? dhcp("iOS / iPadOS", "high", PARAMS.ios, null, label) : dhcp("macOS", "high", PARAMS.macos, null, label);
    }
  } else if (vendor.startsWith("Dell") || vendor.startsWith("Lenovo")) {
    if (o.discoverServices && dev.smbName && r() < 0.6) {
      dev.onvif = onvif({
        xaddrs: [`http://${dev.ip}:5357/${uuid(r).slice(5)}/`],
        types: "wsdp:Device pub:Computer",
        name: dev.smbName,
        isWindows: true,
      });
      dev.deviceKind = "computer";
      sources.add("wsd");
    }
    if (o.dhcpFingerprint) dev.dhcpFingerprint = dhcp(r() < 0.7 ? "Windows 10/11" : "Windows", r() < 0.8 ? "high" : "medium", PARAMS.windows, "MSFT 5.0", label);
  } else if (o.dhcpFingerprint && r() < 0.5) {
    dev.dhcpFingerprint = dhcp(null, null, PARAMS.linux, null, label);
  }
  if (dev.dhcpFingerprint) sources.add("dhcp");
  dev.sources = [...sources];
  return dev;
}

/** UPnP Internet Gateway Device advertised by the simulated WAN router. */
export function addMockIgd(dev: Device): Device {
  const r = rng(hash(`igd${dev.ip}`));
  dev.ssdp = ssdp({
    location: `http://${dev.ip}:2828/rootDesc.xml`,
    server: "RouterOS/7.15.3 UPnP/1.1 MiniUPnPd/2.3.7",
    friendlyName: "MikroTik Router",
    manufacturer: "MikroTik",
    modelName: "CCR2004-16G-2S+",
    modelNumber: "7.15.3",
    serialNumber: serial(r, "HE90", 8),
    deviceType: "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    udn: uuid(r),
    presentationUrl: `http://${dev.ip}/`,
    services: [
      "urn:schemas-upnp-org:service:Layer3Forwarding:1",
      "urn:schemas-upnp-org:service:WANIPConnection:1",
      "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1",
    ],
  });
  dev.deviceKind = "igd_router";
  dev.sources = [...new Set([...dev.sources, "ssdp" as const])];
  return dev;
}

/** `discover_services` against the simulated device (what the scan would have found). */
export function mockDiscoverServices(dev: Device | null, ip: string): ServiceDiscovery {
  if (!dev) return { ip, deviceKind: null, ssdp: null, onvif: null, sip: null };
  const copy: Device = { ...dev, sources: [...dev.sources] };
  if (dev.role === "router") addMockIgd(copy);
  else addMockServices(copy, dev.dnsName?.split(".")[0] ?? dev.ip, { discoverServices: true, dhcpFingerprint: false, snmp: false, cdpLldp: false });
  return { ip, deviceKind: copy.deviceKind ?? null, ssdp: copy.ssdp ?? null, onvif: copy.onvif ?? null, sip: copy.sip ?? null };
}

// --- audit report (browser stand-in) ------------------------------------------------------------

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
}

/** A small stand-in for the real report: counts by kind / role and the metadata it was given. */
export function mockReportContent(args: GenerateReportArgs): { name: string; mime: string; text: string } {
  const kinds = new Map<string, number>();
  let poeW = 0;
  let phones = 0;
  let phonesOff = 0;
  for (const d of args.devices) {
    const k = d.deviceKind ?? d.role;
    kinds.set(k, (kinds.get(k) ?? 0) + 1);
    if (d.poe?.watts) poeW += d.poe.watts;
    if (d.deviceKind === "voip_phone") {
      phones++;
      if (d.voiceVlan == null) phonesOff++;
    }
  }
  const findings = [
    ...(phonesOff > 0 ? [{ id: "VOICE-001", severity: "medium", title: "Phones outside a voice VLAN", affected: phonesOff }] : []),
    { id: "INV-001", severity: "info", title: "Inventory", affected: args.devices.length },
  ];
  const title = args.title ?? "SweepR Network Audit Report";
  if (args.format === "json") {
    const text = JSON.stringify({ mock: true, title, org: args.org ?? null, meta: args.meta ?? {}, findings, stats: { devices: args.devices.length, phones, poeWatts: Math.round(poeW) } }, null, 2);
    return { name: "sweepr-audit-report.json", mime: "application/json", text };
  }
  const rows = [...kinds].sort((a, b) => b[1] - a[1]).map(([k, n]) => `<tr><td>${esc(k)}</td><td>${n}</td></tr>`).join("");
  const text = `<!doctype html><meta charset="utf-8"><title>${esc(title)}</title><h1>${esc(title)}</h1>${args.org ? `<p>${esc(args.org)}</p>` : ""}<p>Mock report: ${args.devices.length} devices, ${(args.vlans ?? []).length} VLANs, ${(args.neighbors ?? []).length} neighbors, ${Math.round(poeW)} W PoE.</p><table>${rows}</table><pre>${esc(JSON.stringify(args.meta ?? {}, null, 2))}</pre>`;
  return { name: "sweepr-audit-report.html", mime: "text/html", text };
}
