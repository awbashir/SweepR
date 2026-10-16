// Pure helpers for the deeper-discovery data (SSDP/UPnP, WSD/ONVIF, SIP, PoE, voice VLANs and
// DHCP fingerprints): labels, the Model/Firmware precedence used by the backend exports, PoE
// load tones and merging a `discover_services` result into a device. Framework-free for tests.

import type { Device, DeviceKind, DhcpFingerprint, OnvifInfo, PoeBudget, PoeInfo, ServiceDiscovery, SwitchPortMapping } from "../types.ts";
import type { Tone } from "./latency.ts";

// --- device kind --------------------------------------------------------------------------------

export const KIND_LABEL: Record<string, string> = {
  voip_phone: "IP Phone",
  pbx: "PBX",
  camera: "IP Camera",
  computer: "Computer",
  media_server: "Media Server",
  igd_router: "Internet Gateway",
  printer: "Printer",
  scanner: "Scanner",
  tv: "TV",
  nas: "NAS",
  media_player: "Media Player",
};

export interface NetBadge {
  id: "dhcp_server" | "ipv6_router";
  label: string;
  title: string;
}

/** Small badges for network services a device was seen offering (rogue DHCP / RA candidates). */
export function netServiceBadges(d: Pick<Device, "dhcpServer" | "ipv6Router">): NetBadge[] {
  const out: NetBadge[] = [];
  if (d.dhcpServer === true) out.push({ id: "dhcp_server", label: "DHCP server", title: "Seen answering as a DHCP server (OFFER / ACK / NAK) during the scan" });
  if (d.ipv6Router === true) out.push({ id: "ipv6_router", label: "IPv6 RA", title: "Sent an IPv6 router advertisement during the scan" });
  return out;
}

/** `voip_phone` -> "IP Phone"; unknown kinds are shown as-is (underscores as spaces). */
export function deviceKindLabel(kind: string | null | undefined): string {
  if (!kind) return "";
  return KIND_LABEL[kind] ?? kind.replace(/_/g, " ");
}

/**
 * The device's kind: the backend's `deviceKind`, else what its service data implies (an older
 * snapshot or a merged `discover_services` result may lack the field).
 */
export function deviceKindOf(d: Pick<Device, "deviceKind" | "sip" | "onvif">): DeviceKind | null {
  if (d.deviceKind) return d.deviceKind;
  if (d.sip?.kind) return d.sip.kind;
  if (d.onvif?.isCamera) return "camera";
  if (d.onvif?.isWindows) return "computer";
  return null;
}

// --- model / firmware -----------------------------------------------------------------------------

function nonEmpty(s: string | null | undefined): string | null {
  const t = s?.trim();
  return t ? t : null;
}

function pair(model: string | null, fw: string | null): string | null {
  if (model && fw) return `${model} / ${fw}`;
  if (model) return model;
  if (fw) return `fw ${fw}`;
  return null;
}

/**
 * "MODEL / FIRMWARE" from the most specific source: SIP, then ONVIF, then SSDP/UPnP (the same
 * precedence and format as the backend's Model/Firmware export column, `export.rs`).
 */
export function modelFirmware(d: Pick<Device, "sip" | "onvif" | "ssdp">): string {
  const sip = d.sip ? pair(nonEmpty(d.sip.model), nonEmpty(d.sip.firmware)) : null;
  if (sip) return sip;
  const onvif = d.onvif ? pair(nonEmpty(d.onvif.model), nonEmpty(d.onvif.firmwareVersion)) : null;
  if (onvif) return onvif;
  if (d.ssdp) {
    const name = nonEmpty(d.ssdp.modelName);
    const num = nonEmpty(d.ssdp.modelNumber);
    const model = name && num ? (name.includes(num) ? name : `${name} ${num}`) : (name ?? num);
    if (model) return model;
  }
  return "";
}

/** Manufacturer from the service data (SIP vendor, ONVIF, then UPnP). */
export function serviceVendor(d: Pick<Device, "sip" | "onvif" | "ssdp">): string | null {
  return nonEmpty(d.sip?.vendor) ?? nonEmpty(d.onvif?.manufacturer) ?? nonEmpty(d.ssdp?.manufacturer);
}

/** Serial number from ONVIF or UPnP. */
export function serialNumber(d: Pick<Device, "onvif" | "ssdp">): string | null {
  return nonEmpty(d.onvif?.serialNumber) ?? nonEmpty(d.ssdp?.serialNumber);
}

/** Text for "Copy model/serial" (empty when nothing is known). */
export function modelSerialText(d: Pick<Device, "sip" | "onvif" | "ssdp">): string {
  const vendor = serviceVendor(d);
  const mf = modelFirmware(d);
  const serial = serialNumber(d);
  const parts: string[] = [];
  if (vendor || mf) parts.push([vendor, mf].filter(Boolean).join(" "));
  if (serial) parts.push(`S/N ${serial}`);
  return parts.join(", ");
}

// --- RTSP -----------------------------------------------------------------------------------------

export const RTSP_GUESS_SUFFIX = /\s*\(guess[^)]*\)\s*$/i;

export interface RtspCandidate {
  url: string;
  /** A vendor template, never verified (no credentials are ever tried). */
  guess: boolean;
}

/** The URL the camera returned, else the backend's labelled guesses (suffix stripped). */
export function rtspCandidates(o: OnvifInfo | null | undefined): RtspCandidate[] {
  if (!o) return [];
  const out: RtspCandidate[] = [];
  const real = nonEmpty(o.rtspUrl);
  if (real && /^rtsps?:\/\//i.test(real)) out.push({ url: real, guess: false });
  for (const h of o.rtspHints ?? []) {
    const url = h.replace(RTSP_GUESS_SUFFIX, "").trim();
    if (/^rtsps?:\/\/\S+$/i.test(url) && !out.some((c) => c.url === url)) out.push({ url, guess: true });
  }
  return out;
}

// --- PoE ------------------------------------------------------------------------------------------

/** Maximum power a PD of each IEEE class may draw (W, at the PD). */
export const POE_CLASS_MAX_W = [12.95, 3.84, 6.49, 12.95, 25.5, 40, 51, 62, 71.3] as const;

/** Load at or above which PoE cells turn amber / red (fraction of the port's budget). */
export const POE_WARN_LOAD = 0.85;
export const POE_BAD_LOAD = 0.98;

/** Budget a port's draw is measured against: allocated watts, else the class maximum. */
export function poeLimit(p: PoeInfo): number | null {
  if (p.maxWatts !== null && p.maxWatts > 0) return p.maxWatts;
  if (p.class !== null && p.class >= 0 && p.class < POE_CLASS_MAX_W.length) return POE_CLASS_MAX_W[p.class] ?? null;
  return null;
}

/**
 * Colour of a PoE value by load: a fault is bad, searching / disabled ports are neutral, and a
 * port drawing >= 98 % (85 %) of its allocation / class budget is bad (warn). Without a budget,
 * absolute draw is used: above 802.3af (15.4 W) warn, above 802.3at (30 W) bad.
 */
export function poeTone(p: PoeInfo | null | undefined): Tone {
  if (!p) return "none";
  if (p.status === "fault") return "bad";
  if (p.watts === null || !Number.isFinite(p.watts)) return "none";
  const limit = poeLimit(p);
  if (limit !== null) {
    const load = p.watts / limit;
    return load >= POE_BAD_LOAD ? "bad" : load >= POE_WARN_LOAD ? "warn" : "ok";
  }
  return p.watts > 30 ? "bad" : p.watts > 15.4 ? "warn" : "ok";
}

export function formatWatts(w: number | null | undefined): string {
  if (w === null || w === undefined || !Number.isFinite(w)) return "—";
  return w >= 100 ? w.toFixed(0) : w.toFixed(1);
}

/** Tooltip / summary line: "5.2 W of 15.4 W · class 3 · delivering · ACC-SW01 Gi1/0/5". */
export function poeSummary(p: PoeInfo): string {
  const parts: string[] = [];
  if (p.watts !== null) parts.push(`${formatWatts(p.watts)} W${p.maxWatts !== null ? ` of ${formatWatts(p.maxWatts)} W` : ""}`);
  else if (p.maxWatts !== null) parts.push(`budget ${formatWatts(p.maxWatts)} W`);
  if (p.class !== null) parts.push(`class ${p.class}`);
  if (p.status) parts.push(p.status);
  if (p.priority) parts.push(`${p.priority} priority`);
  if (p.source) parts.push(`source ${p.source}`);
  const where = [p.switchName, p.port].filter(Boolean).join(" ");
  if (where) parts.push(where);
  return parts.join(" · ");
}

export interface BudgetUsage {
  consumed: number | null;
  nominal: number | null;
  /** 0-100, when both are known. */
  pct: number | null;
  tone: Tone;
  ports: number;
}

/** A switch's PoE budget usage; amber at its own threshold (else 80 %), red at 95 %. */
export function budgetUsage(b: PoeBudget | null | undefined): BudgetUsage | null {
  if (!b) return null;
  const consumed = b.consumedWatts !== null && Number.isFinite(b.consumedWatts) ? b.consumedWatts : null;
  const nominal = b.nominalWatts !== null && Number.isFinite(b.nominalWatts) && b.nominalWatts > 0 ? b.nominalWatts : null;
  const pct = consumed !== null && nominal !== null ? Math.min(100, Math.max(0, (consumed / nominal) * 100)) : null;
  const warnAt = b.usageThresholdPct !== null && b.usageThresholdPct > 0 ? Math.min(b.usageThresholdPct, 95) : 80;
  const tone: Tone = pct === null ? "none" : pct >= 95 ? "bad" : pct >= warnAt ? "warn" : "ok";
  if (consumed === null && nominal === null && b.portsDelivering === 0) return null;
  return { consumed, nominal, pct, tone, ports: b.portsDelivering };
}

/** PoE drawn on one switch according to its CAM / port entries (fallback when SNMP has no budget). */
export function portPoeTotal(mappings: readonly SwitchPortMapping[]): { watts: number; ports: number } | null {
  const perPort = new Map<string, number>();
  for (const m of mappings) {
    const w = m.poe?.watts;
    if (w === null || w === undefined || !Number.isFinite(w)) continue;
    perPort.set(m.portName, Math.max(perPort.get(m.portName) ?? 0, w));
  }
  if (perPort.size === 0) return null;
  let watts = 0;
  for (const w of perPort.values()) watts += w;
  return { watts, ports: perPort.size };
}

// --- DHCP -------------------------------------------------------------------------------------------

/** "Windows (high)" like the backend's OS (DHCP) column. */
export function dhcpOsLabel(f: DhcpFingerprint | null | undefined): string {
  if (!f?.os) return "";
  return f.confidence ? `${f.os} (${f.confidence})` : f.os;
}

/** Common DHCP option names for the parameter request list chips. */
export const DHCP_OPTION_NAMES: Record<number, string> = {
  1: "Subnet Mask",
  2: "Time Offset",
  3: "Router",
  4: "Time Server",
  6: "DNS",
  12: "Host Name",
  15: "Domain Name",
  26: "Interface MTU",
  28: "Broadcast",
  31: "Router Discovery",
  33: "Static Route",
  42: "NTP",
  43: "Vendor Specific",
  44: "NetBIOS NS",
  46: "NetBIOS Node Type",
  47: "NetBIOS Scope",
  51: "Lease Time",
  58: "Renewal T1",
  59: "Rebinding T2",
  66: "TFTP Server",
  67: "Bootfile",
  95: "LDAP",
  108: "IPv6-Only Preferred",
  114: "Captive Portal",
  119: "Domain Search",
  120: "SIP Servers",
  121: "Classless Route",
  150: "TFTP (Cisco)",
  249: "MS Classless Route",
  252: "WPAD",
};

// --- merging ------------------------------------------------------------------------------------------

/** A device with a `discover_services` result merged in (non-null parts win; local only). */
export function withServiceDiscovery(dev: Device, sd: ServiceDiscovery): Device {
  const sources = new Set(dev.sources);
  if (sd.ssdp) sources.add("ssdp");
  if (sd.onvif) sources.add("wsd");
  if (sd.sip) sources.add("sip");
  return {
    ...dev,
    ssdp: sd.ssdp ?? dev.ssdp ?? null,
    onvif: sd.onvif ?? dev.onvif ?? null,
    sip: sd.sip ?? dev.sip ?? null,
    deviceKind: sd.deviceKind ?? dev.deviceKind ?? null,
    sources: [...sources],
  };
}

/** Anything learned by service discovery. */
export function hasServiceData(d: Pick<Device, "ssdp" | "onvif" | "sip">): boolean {
  return Boolean(d.ssdp || d.onvif || d.sip);
}

/** Only http(s) URLs may be handed to the opener (its scope also allows ssh / telnet). */
export function safeHttpUrl(url: string | null | undefined): string | null {
  const u = url?.trim();
  if (!u) return null;
  try {
    const parsed = new URL(u);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.href : null;
  } catch {
    return null;
  }
}

/** "urn:schemas-upnp-org:service:AVTransport:1" -> "AVTransport:1". */
export function shortUrn(urn: string): string {
  const m = /:(?:service|device):([^:]+(?::\d+)?)$/i.exec(urn);
  return m?.[1] ?? urn;
}
