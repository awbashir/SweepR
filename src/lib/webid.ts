// Web identity / TLS helpers: certificate expiry classification and the web UIs a device
// offers (for "Open Web UI").

import type { Device, TlsCertInfo, WebScheme, WebService } from "../types.ts";
import { urlHost } from "./ip.ts";

/** Certificates expiring within this many days are flagged. */
export const CERT_WARN_DAYS = 30;
const DAY_MS = 86_400_000;

export type CertStatus = "expired" | "expiring" | "ok" | "unknown";

export interface CertClass {
  status: CertStatus;
  /** Whole days until `notAfter` (negative once expired), `null` when unknown. */
  days: number | null;
  selfSigned: boolean;
  /** "2026-11-01" (UTC date of notAfter) or "" when unknown. */
  date: string;
  /** Short human text: "expired 3 d ago", "expires in 12 d", "valid 340 d". */
  text: string;
}

function isoDate(cert: TlsCertInfo): string {
  if (cert.notAfterMs !== null && Number.isFinite(cert.notAfterMs)) return new Date(cert.notAfterMs).toISOString().slice(0, 10);
  if (cert.notAfter) return cert.notAfter.slice(0, 10);
  return "";
}

/** Expiry status of a certificate at `nowMs` (recomputed from `notAfterMs` when present). */
export function classifyCert(cert: TlsCertInfo | null | undefined, nowMs: number): CertClass | null {
  if (!cert) return null;
  let days: number | null = cert.daysRemaining;
  if (cert.notAfterMs !== null && Number.isFinite(cert.notAfterMs)) days = Math.floor((cert.notAfterMs - nowMs) / DAY_MS);
  const expired = days !== null ? days < 0 : cert.expired;
  const status: CertStatus = expired ? "expired" : days === null ? "unknown" : days < CERT_WARN_DAYS ? "expiring" : "ok";
  const text =
    status === "expired"
      ? days !== null
        ? `expired ${Math.abs(days)} d ago`
        : "expired"
      : status === "expiring"
        ? `expires in ${days} d`
        : status === "ok"
          ? `valid ${days} d`
          : "expiry unknown";
  return { status, days, selfSigned: cert.selfSigned, date: isoDate(cert), text };
}

/** Sort key for the "Cert Expires" column (soonest first; missing sorts last). */
export function certSortKey(cert: TlsCertInfo | null | undefined): number | undefined {
  if (!cert) return undefined;
  if (cert.notAfterMs !== null) return cert.notAfterMs;
  if (cert.daysRemaining !== null) return Date.now() + cert.daysRemaining * DAY_MS;
  return undefined;
}

export interface WebTarget {
  url: string;
  scheme: WebScheme;
  port: number;
  /** Page title when known. */
  title: string | null;
}

const HTTPS_PORTS = new Set([443, 8443, 10443, 4443, 8006, 5001, 9443, 7443]);
const HTTP_PORTS = new Set([80, 8080, 8000, 8008, 8081, 8888, 5000, 8090]);

export function webUrl(ip: string, scheme: WebScheme, port: number): string {
  const def = scheme === "https" ? 443 : 80;
  return `${scheme}://${urlHost(ip)}${port === def ? "" : `:${port}`}/`;
}

/**
 * Web UIs of a device, HTTPS first: from a `grab_web_identity` result when there is one,
 * otherwise from the TLS certificate's port and the open web ports found by scans.
 */
export function webTargets(device: Device, services?: readonly WebService[] | null): WebTarget[] {
  const out: WebTarget[] = [];
  const seen = new Set<string>();
  const add = (t: WebTarget): void => {
    const k = `${t.scheme}:${t.port}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push(t);
  };
  for (const s of services ?? []) {
    if (s.error !== null && s.status === null) continue;
    const sameHost = /^https?:\/\//i.test(s.url) ? s.url : webUrl(device.ip, s.scheme, s.port);
    add({ url: sameHost, scheme: s.scheme, port: s.port, title: s.title });
  }
  if (out.length === 0) {
    if (device.tlsCert) add({ url: webUrl(device.ip, "https", device.tlsCert.port), scheme: "https", port: device.tlsCert.port, title: device.webTitle });
    for (const p of device.openPorts) {
      if (HTTPS_PORTS.has(p)) add({ url: webUrl(device.ip, "https", p), scheme: "https", port: p, title: null });
    }
    for (const p of device.openPorts) {
      if (HTTP_PORTS.has(p)) add({ url: webUrl(device.ip, "http", p), scheme: "http", port: p, title: null });
    }
    if (out.length > 0 && out[0] && out[0].title === null && device.webTitle) out[0] = { ...out[0], title: device.webTitle };
  }
  return out.sort((a, b) => (a.scheme === b.scheme ? 0 : a.scheme === "https" ? -1 : 1));
}

/** Ports for `grab_web_identity`: the backend defaults plus the device's other open web ports (≤ 16). */
export function webProbePorts(device: Device): number[] | null {
  const defaults = [80, 443, 8443, 8080, 8000, 10443];
  const extra = device.openPorts.filter((p) => (HTTPS_PORTS.has(p) || HTTP_PORTS.has(p)) && !defaults.includes(p));
  if (extra.length === 0) return null;
  return [...defaults, ...extra].slice(0, 16);
}
