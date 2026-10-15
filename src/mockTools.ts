// Simulated network utilities for browser mock mode: Wake-on-LAN, latency monitors (random walk
// with occasional loss and dead hosts), MTR traces (a rate-limited hop, silent hops, async hop
// names), web identity / TLS certificates (self-signed, expired, expiring, plain HTTP) and
// iPerf3 runs. Limits and rejections follow the README contract.

import type {
  DeviceRole,
  IperfAvailability,
  IperfInterval,
  IperfOptions,
  IperfSummary,
  IperfUpdate,
  LatencySample,
  LatencyUpdate,
  TlsCertInfo,
  TraceHop,
  TraceUpdate,
  WakeOptions,
  WakeResult,
  WebIdentity,
  WebService,
} from "./types.ts";
import { ipv4ToNumber } from "./lib/ip.ts";
import { parseWolMac } from "./lib/wol.ts";
import { DEFAULT_IPERF, iperfProblem } from "./lib/iperf.ts";

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

const DAY = 86_400_000;
const round2 = (n: number): number => Math.round(n * 100) / 100;

function validIp(ip: string): boolean {
  if (ipv4ToNumber(ip) !== null) return true;
  return /^[0-9a-f:.]+(%[\w.]+)?$/i.test(ip) && ip.includes(":");
}

// --- web identity --------------------------------------------------------------------------------

function fingerprint(seed: string): string {
  const r = rng(hash(seed));
  return Array.from({ length: 32 }, () => Math.floor(r() * 256).toString(16).padStart(2, "0").toUpperCase()).join(":");
}

function cert(
  ip: string,
  port: number,
  cn: string,
  opts: { issuer?: string; issuerO?: string; ageDays: number; validDays: number; selfSigned?: boolean; key?: [string, number]; sans?: string[]; now: number },
): TlsCertInfo {
  const notBeforeMs = Math.floor((opts.now - opts.ageDays * DAY) / 1000) * 1000;
  const notAfterMs = notBeforeMs + opts.validDays * DAY;
  const sans = opts.sans ?? [cn, ip];
  const issuerCn = opts.selfSigned ? cn : (opts.issuer ?? "R11");
  const [keyType, keyBits] = opts.key ?? ["RSA", 2048];
  const days = Math.floor((notAfterMs - opts.now) / DAY);
  return {
    port,
    subjectCn: cn,
    subject: `CN=${cn}${opts.issuerO && opts.selfSigned ? `, O=${opts.issuerO}` : ""}`,
    sans: sans.slice(0, 8),
    sanCount: sans.length,
    issuerCn,
    issuer: opts.selfSigned ? `CN=${cn}${opts.issuerO ? `, O=${opts.issuerO}` : ""}` : `CN=${issuerCn}, O=${opts.issuerO ?? "Let's Encrypt"}, C=US`,
    notBefore: new Date(notBeforeMs).toISOString().replace(".000", ""),
    notAfter: new Date(notAfterMs).toISOString().replace(".000", ""),
    notBeforeMs,
    notAfterMs,
    daysRemaining: days,
    selfSigned: !!opts.selfSigned,
    expired: notAfterMs < opts.now,
    keyType,
    keyBits,
    signatureAlgorithm: keyType.startsWith("EC") ? "ecdsa-with-SHA256" : "sha256WithRSAEncryption",
    sha256: fingerprint(`${ip}:${port}:${cn}`),
  };
}

function certWarnings(c: TlsCertInfo | null, now: number): string[] {
  if (!c) return [];
  const out: string[] = [];
  const date = (c.notAfter ?? "").slice(0, 10);
  const days = c.notAfterMs !== null ? Math.floor((c.notAfterMs - now) / DAY) : null;
  if (c.expired) out.push(`TLS certificate on port ${c.port} expired ${days !== null ? `${-days} day(s) ago ` : ""}(${date})`);
  else if (days !== null && days < 30) out.push(`TLS certificate on port ${c.port} expires in ${days} day(s) (${date})`);
  if (c.selfSigned) out.push(`TLS certificate on port ${c.port} is self-signed`);
  return out;
}

interface WebProfile {
  identity: string | null;
  roleHint: DeviceRole | null;
  services: Array<{ port: number; scheme: "http" | "https"; title: string | null; server: string | null; status: number; path?: string }>;
  cert: ((ip: string, port: number, now: number) => TlsCertInfo) | null;
}

const PROFILES: Record<string, WebProfile> = {
  fortigate: {
    identity: "Fortinet FortiGate",
    roleHint: "firewall",
    services: [
      { port: 443, scheme: "https", title: "FortiGate - Login", server: "xxxxxxxx-xxxxx", status: 200, path: "/login" },
      { port: 80, scheme: "http", title: null, server: "xxxxxxxx-xxxxx", status: 301 },
    ],
    cert: (ip, port, now) => cert(ip, port, "FGT60FTK21000123", { selfSigned: true, issuerO: "Fortinet", ageDays: 353, validDays: 365, now }),
  },
  cisco: {
    identity: "Cisco IOS XE",
    roleHint: "switch",
    services: [{ port: 443, scheme: "https", title: "Cisco Catalyst 9200 - WebUI", server: "openresty", status: 200, path: "/webui/" }],
    cert: (ip, port, now) => cert(ip, port, "IOS-Self-Signed-Certificate-3129413712", { selfSigned: true, ageDays: 900, validDays: 3650, now }),
  },
  aruba: {
    identity: "Aruba Instant On",
    roleHint: "access_point",
    services: [{ port: 443, scheme: "https", title: "Aruba Instant On", server: null, status: 200 }],
    cert: (ip, port, now) => cert(ip, port, "instant-on.arubanetworks.com", { issuer: "DigiCert Global G2 TLS RSA SHA256 2020 CA1", issuerO: "DigiCert Inc", ageDays: 200, validDays: 395, now }),
  },
  mikrotik: {
    identity: "MikroTik RouterOS",
    roleHint: "router",
    services: [{ port: 80, scheme: "http", title: "RouterOS router configuration page", server: null, status: 200 }],
    cert: null,
  },
  proxmox: {
    identity: "Proxmox VE",
    roleHint: null,
    services: [{ port: 8006, scheme: "https", title: "pve01 - Proxmox Virtual Environment", server: "pve-api-daemon/3.0", status: 200 }],
    cert: (ip, port, now) => cert(ip, port, "pve01.corp.example", { selfSigned: true, issuerO: "PVE Cluster Node", ageDays: 400, validDays: 730, key: ["RSA", 2048], now }),
  },
  idrac: {
    identity: "Dell iDRAC",
    roleHint: null,
    services: [
      { port: 443, scheme: "https", title: "iDRAC9 - R740-SRV12", server: "Apache", status: 200, path: "/restgui/start.html" },
      { port: 80, scheme: "http", title: null, server: "Apache", status: 302 },
    ],
    cert: (ip, port, now) => cert(ip, port, "idrac-srv12.corp.example", { selfSigned: true, issuerO: "Dell Inc.", ageDays: 1866, validDays: 1826, now }),
  },
  grafana: {
    identity: "Grafana",
    roleHint: null,
    services: [{ port: 443, scheme: "https", title: "Grafana", server: "nginx/1.24.0", status: 200, path: "/login" }],
    cert: (ip, port, now) => cert(ip, port, "grafana.corp.example", { ageDays: 70, validDays: 90, key: ["EC P-256", 256], sans: ["grafana.corp.example", "metrics.corp.example", "prometheus.corp.example"], now }),
  },
  synology: {
    identity: "Synology DSM",
    roleHint: null,
    services: [{ port: 5001, scheme: "https", title: "NAS01 - Synology DiskStation", server: "nginx", status: 200 }],
    cert: (ip, port, now) => cert(ip, port, "synology.com", { selfSigned: true, issuerO: "Synology Inc.", ageDays: 120, validDays: 825, now }),
  },
  printer: {
    identity: "HP LaserJet",
    roleHint: null,
    services: [{ port: 80, scheme: "http", title: "HP LaserJet Pro M404dn", server: "HP HTTP Server; HP LaserJet Pro M404dn", status: 200 }],
    cert: null,
  },
  nginx: {
    identity: null,
    roleHint: null,
    services: [{ port: 80, scheme: "http", title: "Welcome to nginx!", server: "nginx/1.24.0", status: 200 }],
    cert: null,
  },
  intranet: {
    identity: null,
    roleHint: null,
    services: [
      { port: 443, scheme: "https", title: "Intranet - Corp Portal", server: "Microsoft-IIS/10.0", status: 200 },
      { port: 80, scheme: "http", title: null, server: "Microsoft-IIS/10.0", status: 301 },
    ],
    cert: (ip, port, now) => cert(ip, port, "intranet.corp.example", { issuer: "Corp Issuing CA 01", issuerO: "Corp", ageDays: 300, validDays: 397, sans: ["intranet.corp.example", "portal.corp.example", "www.corp.example", "sso.corp.example", "wiki.corp.example", "jira.corp.example", "git.corp.example", "ci.corp.example", "docs.corp.example", "status.corp.example"], now }),
  },
};

const HOST_PROFILES = ["proxmox", "idrac", "grafana", "synology", "printer", "nginx", "intranet", null, null, null] as const;

/** Simulated web identity of `ip` (`role` steers infrastructure toward vendor UIs). */
export function mockWebIdentity(ip: string, role: DeviceRole | null, now: number, ports?: readonly number[] | null): WebIdentity {
  const key =
    role === "firewall"
      ? "fortigate"
      : role === "switch"
        ? "cisco"
        : role === "access_point"
          ? "aruba"
          : role === "router"
            ? "mikrotik"
            : HOST_PROFILES[hash(`web${ip}`) % HOST_PROFILES.length];
  const prof = key ? PROFILES[key] : undefined;
  if (!prof) return { ip, services: [], title: null, server: null, tlsCert: null, identity: null, roleHint: null, warnings: [] };
  const host = ip.includes(":") ? `[${ip}]` : ip;
  const services: WebService[] = prof.services
    .filter((s) => !ports || ports.length === 0 || ports.includes(s.port) || s.port === 8006 || s.port === 5001)
    .map((s) => {
      const tlsCert = s.scheme === "https" && prof.cert ? prof.cert(ip, s.port, now) : null;
      const def = s.scheme === "https" ? 443 : 80;
      const base = `${s.scheme}://${host}${s.port === def ? "" : `:${s.port}`}`;
      return {
        port: s.port,
        scheme: s.scheme,
        url: `${base}${s.path ?? "/"}`,
        status: s.status,
        title: s.title,
        server: s.server,
        redirects: s.path ? 1 : 0,
        redirectTo: s.status === 301 || s.status === 302 ? `https://${host}/` : null,
        tlsCert,
        error: null,
      };
    });
  const main = services.find((s) => s.title !== null) ?? services[0];
  const tlsCert = services.find((s) => s.tlsCert)?.tlsCert ?? null;
  return {
    ip,
    services,
    title: main?.title ?? null,
    server: main?.server ?? null,
    tlsCert,
    identity: prof.identity,
    roleHint: prof.roleHint,
    warnings: certWarnings(tlsCert, now),
  };
}

// --- latency ---------------------------------------------------------------------------------------

interface HostSim {
  base: number;
  level: number;
  loss: number;
  dead: boolean;
  spiky: boolean;
  r: () => number;
  window: Array<number | null>;
}

function hostSim(ip: string, seed: number): HostSim {
  const r = rng(hash(`lat${ip}`) ^ seed);
  const kind = r();
  const local = ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("172.") || ip.startsWith("fe80");
  const base = kind < 0.06 ? 25 + r() * 60 : local ? 0.3 + r() * 4 : 8 + r() * 30;
  return {
    base,
    level: base,
    loss: kind > 0.96 ? 1 : kind > 0.82 ? 0.02 + r() * 0.15 : 0.002,
    dead: kind > 0.96,
    spiky: r() < 0.15,
    r: rng(hash(`walk${ip}`) ^ Date.now()),
    window: [],
  };
}

function nextRtt(h: HostSim): number | null {
  if (h.dead || h.r() < h.loss) return null;
  // Mean-reverting random walk with occasional spikes.
  h.level += (h.base - h.level) * 0.15 + (h.r() - 0.5) * h.base * 0.35;
  h.level = Math.max(h.base * 0.4, h.level);
  let v = h.level;
  if (h.spiky && h.r() < 0.06) v *= 3 + h.r() * 6;
  return round2(v);
}

function stats(win: Array<number | null>) {
  let rec = 0;
  let sum = 0;
  let min = Infinity;
  let max = -Infinity;
  let jit = 0;
  let jn = 0;
  let prev: number | null = null;
  for (const v of win) {
    if (v === null) continue;
    rec++;
    sum += v;
    min = Math.min(min, v);
    max = Math.max(max, v);
    if (prev !== null) {
      jit += Math.abs(v - prev);
      jn++;
    }
    prev = v;
  }
  return {
    sent: win.length,
    received: rec,
    lossPct: win.length ? round2(((win.length - rec) / win.length) * 100) : 0,
    avgMs: rec ? round2(sum / rec) : null,
    minMs: rec ? min : null,
    maxMs: rec ? max : null,
    jitterMs: jn ? round2(jit / jn) : null,
  };
}

// --- trace -------------------------------------------------------------------------------------------

interface HopSpec {
  ip: string | null;
  name: string | null;
  base: number;
  loss: number;
  other?: string[];
}

function tracePath(target: string): HopSpec[] {
  const n = ipv4ToNumber(target);
  const scanner = ipv4ToNumber("10.177.134.25") ?? 0;
  if (n !== null && (n & 0xffffff00) === (scanner & 0xffffff00)) {
    return [{ ip: target, name: null, base: 0.6, loss: 0.01 }];
  }
  const gw: HopSpec = { ip: "10.177.134.1", name: "fw01.corp.example", base: 0.5, loss: 0 };
  const core: HopSpec = { ip: "10.255.0.1", name: "core-rtr01.corp.example", base: 1.1, loss: 0 };
  const priv = n === null || target.startsWith("10.") || target.startsWith("192.168.") || target.startsWith("172.");
  if (priv) return [gw, core, { ip: target, name: null, base: 1.6, loss: 0.01 }];
  return [
    gw,
    core,
    { ip: "100.64.12.1", name: "cgnat-gw.isp.example", base: 6.5, loss: 0.3 },
    { ip: null, name: null, base: 0, loss: 1 },
    { ip: null, name: null, base: 0, loss: 1 },
    { ip: "203.0.113.9", name: "ae1.cr1.fra1.isp.example", base: 11.8, loss: 0, other: ["203.0.113.13"] },
    { ip: "198.51.100.20", name: "edge1.dc.example", base: 14.2, loss: 0.02 },
    { ip: target, name: null, base: 14.9, loss: 0 },
  ];
}

// --- iperf ---------------------------------------------------------------------------------------------

function parseBitrate(b: string | null): number | null {
  if (!b) return null;
  const m = /^(\d+(?:\.\d+)?)([KMGT]?)$/i.exec(b.trim());
  if (!m) return null;
  const mult: Record<string, number> = { "": 1, K: 1e3, M: 1e6, G: 1e9, T: 1e12 };
  return Number(m[1]) * (mult[(m[2] ?? "").toUpperCase()] ?? 1);
}

// --- backend subset ---------------------------------------------------------------------------------------

export interface MockTools {
  wakeDevice(mac: string, opts?: WakeOptions): Promise<WakeResult>;
  startLatencyMonitor(ips: string[], intervalMs?: number | null): Promise<number>;
  stopLatencyMonitor(id: number): Promise<boolean>;
  onLatencyUpdate(h: (u: LatencyUpdate) => void): Promise<() => void>;
  startTrace(ip: string, maxHops?: number | null, rounds?: number | null): Promise<number>;
  stopTrace(id: number): Promise<boolean>;
  onTraceUpdate(h: (u: TraceUpdate) => void): Promise<() => void>;
  grabWebIdentity(ip: string, ports?: number[] | null): Promise<WebIdentity>;
  iperfAvailable(): Promise<IperfAvailability>;
  startIperf(ip: string, options?: IperfOptions | null): Promise<number>;
  stopIperf(id: number): Promise<boolean>;
  onIperfUpdate(h: (u: IperfUpdate) => void): Promise<() => void>;
}

function hub<T>() {
  const ls = new Set<(v: T) => void>();
  return {
    emit: (v: T) => {
      for (const l of ls) l(v);
    },
    on: async (h: (v: T) => void) => {
      const l = (v: T) => h(v);
      ls.add(l);
      return () => {
        ls.delete(l);
      };
    },
  };
}

export function createMockTools(roleOf: (ip: string) => DeviceRole | null): MockTools {
  const search = typeof window !== "undefined" ? new URLSearchParams(window.location.search) : new URLSearchParams();
  const latencyHub = hub<LatencyUpdate>();
  const traceHub = hub<TraceUpdate>();
  const iperfHub = hub<IperfUpdate>();

  // Latency monitors.
  let monitorSeq = 0;
  const monitors = new Map<number, { timer: number; ips: string[] }>();
  const monitoredHosts = (): number => [...monitors.values()].reduce((n, m) => n + m.ips.length, 0);

  // Traces.
  let traceSeq = 0;
  const traces = new Map<number, { timers: number[]; stop: () => void }>();

  // Web lookups.
  let webRunning = 0;

  // iPerf runs.
  let iperfSeq = 0;
  const runs = new Map<number, { timers: number[]; stop: () => void }>();
  const iperfMissing = search.has("noiperf");

  return {
    wakeDevice: (mac, opts) =>
      new Promise((resolve, reject) => {
        const parsed = parseWolMac(mac);
        if (!parsed.ok) {
          reject(`invalid MAC address '${mac}': ${parsed.error}`);
          return;
        }
        if (opts?.broadcast && ipv4ToNumber(opts.broadcast) === null) {
          reject(`'${opts.broadcast}' is not an IPv4 address`);
          return;
        }
        if (opts?.port === 0) {
          reject("port must be between 1 and 65535");
          return;
        }
        const port = opts?.port ?? 9;
        const targets = opts?.broadcast ? [`${opts.broadcast}:${port}`] : [`10.177.134.255:${port}`, `255.255.255.255:${port}`];
        window.setTimeout(
          () =>
            resolve({
              mac: parsed.value,
              targets,
              packetsSent: targets.length * (opts?.repeat ?? 3),
              interface: opts?.interface ?? "en0",
              sourceIp: "10.177.134.25",
            }),
          150,
        );
      }),

    startLatencyMonitor: async (ips, intervalMs) => {
      const interval = intervalMs ?? 1000;
      if (ips.length === 0) throw "no hosts to monitor";
      const bad = ips.find((ip) => !validIp(ip));
      if (bad) throw `'${bad}' is not an IP address`;
      if (interval < 500 || interval > 10_000) throw "intervalMs must be between 500 and 10000";
      if (monitors.size >= 16) throw "16 latency monitors are already running; stop one first";
      const unique = [...new Set(ips)];
      if (monitoredHosts() + unique.length > 2000) throw `at most 2000 hosts can be monitored at once (${monitoredHosts()} already)`;
      const id = ++monitorSeq;
      const sims = new Map(unique.map((ip) => [ip, hostSim(ip, id)]));
      const tick = (): void => {
        const ts = Date.now();
        const samples: LatencySample[] = [];
        for (const [ip, h] of sims) {
          const rtt = nextRtt(h);
          h.window.push(rtt);
          if (h.window.length > 120) h.window.shift();
          samples.push({ ip, rttMs: rtt, ts, method: h.dead ? "tcp" : "icmp", ...stats(h.window), history: [...h.window] });
        }
        samples.sort((a, b) => (a.ip < b.ip ? -1 : 1));
        latencyHub.emit({ monitorId: id, samples });
      };
      const timer = window.setInterval(tick, interval);
      window.setTimeout(tick, 120);
      monitors.set(id, { timer, ips: unique });
      return id;
    },
    stopLatencyMonitor: async (id) => {
      const m = monitors.get(id);
      if (!m) return false;
      window.clearInterval(m.timer);
      monitors.delete(id);
      return true;
    },
    onLatencyUpdate: latencyHub.on,

    startTrace: async (ip, maxHopsArg, roundsArg) => {
      if (!validIp(ip)) throw `'${ip}' is not an IP address (host names are not resolved)`;
      if (ip === "0.0.0.0" || ip === "255.255.255.255" || ip === "::" || /^2(2[4-9]|3\d)\./.test(ip)) throw `${ip} cannot be traced`;
      const maxHops = maxHopsArg ?? 30;
      const rounds = roundsArg ?? 5;
      if (maxHops < 1 || maxHops > 64) throw "maxHops must be 1-64";
      if (rounds < 1 || rounds > 100) throw "rounds must be 1-100";
      if (traces.size >= 8) throw "8 traces are already running; stop one first";
      const id = ++traceSeq;
      const path = tracePath(ip);
      const reachable = path.length <= maxHops;
      const specs = path.slice(0, maxHops);
      const r = rng(hash(`trace${ip}${id}`));
      const hops: TraceHop[] = specs.map((_, i) => ({
        ttl: i + 1,
        ip: null,
        hostname: null,
        otherIps: [],
        sent: 0,
        received: 0,
        lossPct: 0,
        lastMs: null,
        avgMs: null,
        bestMs: null,
        worstMs: null,
      }));
      const sums = specs.map(() => 0);
      let round = 0;
      let reached = false;
      const timers: number[] = [];
      let finished = false;
      const snapshot = (done: boolean, error: string | null = null): void => {
        traceHub.emit({
          traceId: id,
          target: ip,
          method: "system",
          round,
          rounds,
          hops: hops.slice(0, reached ? hops.length : Math.max(1, hops.filter((h) => h.sent > 0).length)).map((h) => ({ ...h, otherIps: [...h.otherIps] })),
          reached,
          done,
          error,
        });
      };
      const finish = (error: string | null = null): void => {
        if (finished) return;
        finished = true;
        timers.forEach((t) => window.clearTimeout(t));
        traces.delete(id);
        snapshot(true, error);
      };
      const probeHop = (i: number): void => {
        const spec = specs[i]!;
        const h = hops[i]!;
        h.sent++;
        const lost = spec.ip === null || r() < spec.loss;
        if (!lost) {
          const rtt = round2(spec.base * (0.85 + r() * 0.4) + (r() < 0.05 ? spec.base * 2 : 0));
          h.received++;
          h.ip = spec.ip;
          if (spec.other && r() < 0.35) {
            h.ip = spec.other[0] ?? spec.ip;
            if (!h.otherIps.includes(spec.ip!)) h.otherIps = [spec.ip!];
          }
          h.lastMs = rtt;
          sums[i] = (sums[i] ?? 0) + rtt;
          h.avgMs = round2((sums[i] ?? 0) / h.received);
          h.bestMs = h.bestMs === null ? rtt : Math.min(h.bestMs, rtt);
          h.worstMs = h.worstMs === null ? rtt : Math.max(h.worstMs, rtt);
          if (i === specs.length - 1 && reachable) reached = true;
        } else {
          h.lastMs = null;
        }
        h.lossPct = round2(((h.sent - h.received) / h.sent) * 100);
        // Reverse DNS answers after the first round.
        if (round >= 1 && h.ip && spec.name) h.hostname = spec.name;
      };
      const runRound = (): void => {
        if (finished) return;
        specs.forEach((_, i) => {
          timers.push(
            window.setTimeout(() => {
              if (finished) return;
              probeHop(i);
              if (i === Math.floor(specs.length / 2)) snapshot(false);
            }, 40 + i * 45),
          );
        });
        timers.push(
          window.setTimeout(() => {
            if (finished) return;
            round++;
            for (let i = 0; i < specs.length; i++) {
              const spec = specs[i]!;
              if (hops[i]!.ip && spec.name) hops[i]!.hostname = spec.name;
            }
            if (round >= rounds) finish();
            else {
              snapshot(false);
              runRound();
            }
          }, 60 + specs.length * 45 + 300),
        );
      };
      traces.set(id, { timers, stop: () => finish() });
      timers.push(window.setTimeout(runRound, 100));
      return id;
    },
    stopTrace: async (id) => {
      const t = traces.get(id);
      if (!t) return false;
      window.setTimeout(t.stop, 30);
      return true;
    },
    onTraceUpdate: traceHub.on,

    grabWebIdentity: (ip, ports) =>
      new Promise((resolve, reject) => {
        if (!validIp(ip)) {
          reject(`'${ip}' is not an IP address`);
          return;
        }
        if (ports && ports.length > 16) {
          reject("at most 16 ports");
          return;
        }
        if (webRunning >= 4) {
          reject("4 web identity lookups are already running");
          return;
        }
        webRunning++;
        window.setTimeout(() => {
          webRunning--;
          resolve(mockWebIdentity(ip, roleOf(ip), Date.now(), ports));
        }, 500 + (hash(ip) % 700));
      }),

    iperfAvailable: async () =>
      iperfMissing
        ? { available: false, path: null, version: null, streaming: false, installHint: "iperf3 was not found; install it with `brew install iperf3`" }
        : { available: true, path: "/opt/homebrew/bin/iperf3", version: "3.17.1", streaming: true, installHint: null },
    startIperf: async (ip, options) => {
      if (iperfMissing) throw "iperf3 was not found; install it with `brew install iperf3`";
      if (!validIp(ip)) throw `'${ip}' is not an IP address`;
      const o: IperfOptions = { ...DEFAULT_IPERF, ...(options ?? {}) };
      const problem = iperfProblem(o);
      if (problem) throw problem;
      if (runs.size >= 2) throw "2 iperf3 runs are already active; stop one first";
      const id = ++iperfSeq;
      const timers: number[] = [];
      let finished = false;
      const r = rng(hash(`iperf${ip}`) ^ id);
      const refuses = hash(`iperf${ip}`) % 5 === 0;
      const wifi = hash(`wifi${ip}`) % 3 === 0;
      const lineRate = wifi ? 280e6 + r() * 250e6 : 935e6;
      const target = o.udp ? (parseBitrate(o.bitrate) ?? 1e6) : (parseBitrate(o.bitrate) || lineRate);
      const intervals: IperfInterval[] = [];
      const finish = (error: string | null): void => {
        if (finished) return;
        finished = true;
        timers.forEach((t) => window.clearTimeout(t));
        runs.delete(id);
        let summary: IperfSummary | null = null;
        if (!error) {
          const bytes = intervals.reduce((n, iv) => n + iv.bytes, 0);
          const secs = intervals.length || 1;
          const bps = (bytes * 8) / secs;
          const lost = intervals.reduce((n, iv) => n + (iv.lostPackets ?? 0), 0);
          const pkts = intervals.reduce((n, iv) => n + (iv.packets ?? 0), 0);
          summary = {
            protocol: o.udp ? "udp" : "tcp",
            reverse: o.reverse,
            streams: o.streams,
            durationSecs: o.durationSecs,
            sentBytes: Math.round(bytes * 1.002),
            sentBps: Math.round(bps * 1.002),
            receivedBytes: bytes,
            receivedBps: Math.round(bps),
            retransmits: o.udp ? null : intervals.reduce((n, iv) => n + (iv.retransmits ?? 0), 0),
            jitterMs: o.udp ? round2(0.02 + r() * 0.2) : null,
            lostPackets: o.udp ? lost : null,
            packets: o.udp ? pkts : null,
            lostPercent: o.udp ? (pkts ? round2((lost / pkts) * 100) : 0) : null,
            cpuLocalPct: round2(3 + r() * 20),
            cpuRemotePct: round2(5 + r() * 30),
            remoteHost: `${ip}:${o.port}`,
            version: "iperf 3.17.1",
          };
        }
        iperfHub.emit({ runId: id, interval: null, summary, done: true, error });
      };
      if (refuses) {
        timers.push(window.setTimeout(() => finish(`unable to connect to server ${ip}:${o.port}: Connection refused (is \`iperf3 -s\` running there?)`), 600));
      } else {
        for (let s = 0; s < o.durationSecs; s++) {
          timers.push(
            window.setTimeout(() => {
              if (finished) return;
              const ramp = s === 0 && !o.udp ? 0.55 + r() * 0.3 : 1;
              const bps = Math.max(0, target * ramp * (0.94 + r() * 0.08) * (wifi && r() < 0.15 ? 0.6 : 1));
              const packets = o.udp ? Math.round(bps / 8 / 1448) : null;
              const lostPackets = packets !== null ? Math.round(packets * (r() < 0.2 ? r() * 0.02 : 0)) : null;
              const iv: IperfInterval = {
                start: s,
                end: s + 1,
                bytes: Math.round(bps / 8),
                bitsPerSecond: Math.round(bps),
                retransmits: o.udp ? null : r() < 0.25 ? Math.floor(r() * 40) : 0,
                jitterMs: o.udp ? round2(0.02 + r() * 0.3) : null,
                lostPackets,
                packets,
                lostPercent: packets ? round2(((lostPackets ?? 0) / packets) * 100) : null,
                omitted: false,
              };
              intervals.push(iv);
              iperfHub.emit({ runId: id, interval: iv, summary: null, done: false, error: null });
              if (s === o.durationSecs - 1) timers.push(window.setTimeout(() => finish(null), 150));
            }, (s + 1) * 1000),
          );
        }
      }
      runs.set(id, { timers, stop: () => finish("iperf3 test stopped") });
      return id;
    },
    stopIperf: async (id) => {
      const run = runs.get(id);
      if (!run) return false;
      window.setTimeout(run.stop, 30);
      return true;
    },
    onIperfUpdate: iperfHub.on,
  };
}
