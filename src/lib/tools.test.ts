// Unit tests for the network-utility logic: latency ring / store / monitor selection,
// certificate classification, web targets, trace table, iPerf3 chart and Wake-on-LAN input.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  HISTORY_LEN,
  LatencyController,
  LatencyStore,
  applySample,
  computeStats,
  formatLoss,
  formatMs,
  latencyTone,
  lossTone,
  niceCeil,
  planMonitors,
  selectViewport,
  sparkline,
  tcpPortsFor,
  TCP_PORTS_PER_HOST,
  type LatencyEntry,
} from "./latency.ts";
import { CERT_WARN_DAYS, certSortKey, classifyCert, webProbePorts, webTargets } from "./webid.ts";
import { traceTable } from "./trace.ts";
import { formatBps, formatBytes, iperfForWire, iperfProblem, throughputChart, DEFAULT_IPERF } from "./iperf.ts";
import { parseSecureOn, parseWolMac } from "./wol.ts";
import { completeOrder, effectiveVisibility } from "./columns.ts";
import { parseIdList } from "./storage.ts";
import { buildRow, exportDevice, withWebIdentity } from "./store.ts";
import type { Device, IperfInterval, LatencySample, TlsCertInfo, TraceHop, WebIdentity, WebService } from "../types.ts";

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

function sample(ip: string, history: (number | null)[], ts = 1000): LatencySample {
  const s = computeStats(history, "icmp", ts);
  return {
    ip,
    rttMs: history[history.length - 1] ?? null,
    ts,
    method: "icmp",
    lossPct: s.lossPct,
    avgMs: s.avgMs,
    minMs: s.minMs,
    maxMs: s.maxMs,
    jitterMs: s.jitterMs,
    sent: s.sent,
    received: s.received,
    history,
  };
}

// --- latency ring ----------------------------------------------------------------------------------

test("latency stats: loss, min/avg/max and jitter over replies", () => {
  const s = computeStats([1, null, 3, 2, null], "icmp", 5);
  assert.equal(s.sent, 5);
  assert.equal(s.received, 3);
  assert.equal(s.lossPct, 40);
  assert.equal(s.minMs, 1);
  assert.equal(s.maxMs, 3);
  assert.equal(s.avgMs, 2);
  assert.equal(s.jitterMs, 1.5); // |3-1|, |2-3|
  assert.equal(s.lastMs, null);
  const empty = computeStats([], "tcp", 0);
  assert.equal(empty.lossPct, 0);
  assert.equal(empty.avgMs, null);
});

test("latency ring: same monitor replaces, new monitor carries the old window, stale monitors are ignored", () => {
  let e: LatencyEntry | null = applySample(undefined, sample("10.0.0.1", [1, 2]), 1);
  assert.ok(e);
  assert.deepEqual(e.history, [1, 2]);
  assert.equal(e.stats.avgMs, 1.5); // backend stats used while nothing is carried
  e = applySample(e, sample("10.0.0.1", [1, 2, 3]), 1);
  assert.deepEqual(e?.history, [1, 2, 3]);
  // The host moved to monitor 2 (selection changed): its new window starts empty.
  e = applySample(e!, sample("10.0.0.1", [null]), 2);
  assert.deepEqual(e?.history, [1, 2, 3, null]);
  assert.equal(e?.stats.sent, 4);
  assert.equal(e?.stats.lossPct, 25);
  assert.equal(e?.stats.lastMs, null);
  // A late batch of monitor 1 is dropped.
  assert.equal(applySample(e!, sample("10.0.0.1", [9, 9, 9, 9]), 1), null);
  // Carried samples are trimmed so the window never exceeds HISTORY_LEN.
  const long = Array.from({ length: HISTORY_LEN - 1 }, (_, i) => i + 1);
  const full = applySample(e!, sample("10.0.0.1", [null, ...long]), 2);
  assert.equal(full?.history.length, HISTORY_LEN);
  assert.equal(full?.carry.length, 0);
  const moved = applySample(full!, sample("10.0.0.1", [5, 6]), 3);
  assert.equal(moved?.history.length, HISTORY_LEN);
  assert.deepEqual(moved?.history.slice(-3), [HISTORY_LEN - 1, 5, 6]);
});

/** A live update in the delta shape: stats over `window`, `newSamples`, history only when asked. */
function delta(ip: string, window: (number | null)[], fresh: (number | null)[], ts: number, withHistory = false): LatencySample {
  const s = sample(ip, window, ts);
  const out: LatencySample = { ...s, newSamples: fresh };
  if (!withHistory) delete out.history;
  return out;
}

test("latency ring: newSamples append, history replaces, duplicates and stale updates are dropped", () => {
  let e = applySample(undefined, delta("10.0.0.1", [1, 2], [1, 2], 1000, true), 1);
  assert.deepEqual(e?.history, [1, 2]);
  e = applySample(e!, delta("10.0.0.1", [1, 2, 3], [3], 2000), 1);
  assert.deepEqual(e?.history, [1, 2, 3]);
  e = applySample(e!, delta("10.0.0.1", [1, 2, 3, null, 5], [null, 5], 3000), 1);
  assert.deepEqual(e?.history, [1, 2, 3, null, 5]);
  assert.equal(e?.stats.sent, 5, "stats come from the payload");
  assert.equal(e?.stats.lossPct, 20);
  // The same update again (same ts, no history) and an older one are ignored.
  assert.equal(applySample(e!, delta("10.0.0.1", [1, 2, 3, null, 5], [null, 5], 3000), 1), null);
  assert.equal(applySample(e!, delta("10.0.0.1", [1, 2, 3], [3], 2000), 1), null);
  // A history resend replaces the ring wholesale.
  e = applySample(e!, delta("10.0.0.1", [2, 3, null, 5, 6], [6], 4000, true), 1);
  assert.deepEqual(e?.history, [2, 3, null, 5, 6]);
  // The ring stays within HISTORY_LEN and the backend's window size.
  const win = Array.from({ length: HISTORY_LEN }, (_, i) => i);
  e = applySample(e!, delta("10.0.0.1", win, [7, 8], 5000), 1);
  assert.equal(e?.history.length, 7);
  e = applySample(e!, delta("10.0.0.1", win, win, 6000), 1);
  assert.equal(e?.history.length, HISTORY_LEN);
  const capped = applySample(e!, delta("10.0.0.1", [1, 2, 3], [9], 7000), 1);
  assert.deepEqual(capped?.history, [HISTORY_LEN - 2, HISTORY_LEN - 1, 9], "trimmed to `sent`");
});

test("latency ring: a dropped update leaves a gap until the next history resend", () => {
  let e = applySample(undefined, delta("10.0.0.2", [1], [1], 1000, true), 1);
  // The update carrying 2 never arrived.
  e = applySample(e!, delta("10.0.0.2", [1, 2, 3], [3], 3000), 1);
  assert.deepEqual(e?.history, [1, 3]);
  assert.equal(e?.stats.sent, 3, "stats still describe the backend window");
  assert.equal(e?.stats.avgMs, 2);
  e = applySample(e!, delta("10.0.0.2", [1, 2, 3, 4], [4], 4000, true), 1);
  assert.deepEqual(e?.history, [1, 2, 3, 4], "history resend repairs the ring");
  // A host first seen without history (its first update was missed) starts from newSamples.
  const late = applySample(undefined, delta("10.0.0.3", [1, 2, 3], [3], 3000), 1);
  assert.deepEqual(late?.history, [3]);
  // A new monitor's delta updates continue after the carried window.
  const moved = applySample(e!, delta("10.0.0.2", [9], [9], 5000), 2);
  assert.deepEqual(moved?.history, [1, 2, 3, 4, 9]);
  const next = applySample(moved!, delta("10.0.0.2", [9, 10], [10], 6000), 2);
  assert.deepEqual(next?.history, [1, 2, 3, 4, 9, 10]);
});

test("latency ring: older backends (history every update, or only rttMs) keep working", () => {
  let e = applySample(undefined, sample("10.0.0.4", [1, 2], 1000), 1);
  e = applySample(e!, sample("10.0.0.4", [1, 2, 3], 2000), 1);
  assert.deepEqual(e?.history, [1, 2, 3]);
  const bare = (rtt: number | null, ts: number, sent: number): LatencySample => {
    const s = sample("10.0.0.5", [rtt], ts);
    delete s.history;
    return { ...s, sent };
  };
  let b = applySample(undefined, bare(4, 1000, 1), 1);
  b = applySample(b!, bare(null, 2000, 2), 1);
  b = applySample(b!, bare(6, 3000, 3), 1);
  assert.deepEqual(b?.history, [4, null, 6]);
});

test("latency store: throttled notifications, monitor filter and bounded size", () => {
  const timers: Array<() => void> = [];
  const store = new LatencyStore({ schedule: (fn) => timers.push(fn), maxEntries: 3 });
  let notified = 0;
  store.subscribe(() => notified++);
  store.accept = (id) => id !== 7;
  for (let i = 0; i < 50; i++) store.handleUpdate({ monitorId: 1, samples: [sample("10.0.0.1", [i])] });
  assert.equal(timers.length, 1, "one pending flush for any number of updates");
  assert.equal(notified, 0);
  timers.shift()!();
  assert.equal(notified, 1);
  assert.deepEqual(store.get("10.0.0.1")?.history, [49]);
  store.handleUpdate({ monitorId: 7, samples: [sample("10.0.0.9", [1])] });
  assert.equal(store.get("10.0.0.9"), undefined);
  assert.equal(timers.length, 0, "ignored updates do not schedule renders");
  for (const ip of ["10.0.0.2", "10.0.0.3", "10.0.0.4"]) store.handleUpdate({ monitorId: 2, samples: [sample(ip, [1])] });
  assert.equal(store.size, 3);
  assert.equal(store.get("10.0.0.1"), undefined, "least recently updated host evicted");
});

// --- monitor selection -------------------------------------------------------------------------------

const ipOf = (i: number): string => `10.0.${Math.floor(i / 256)}.${i % 256}`;

test("viewport selection: visible rows, then margin, capped", () => {
  const opts = { margin: 2, keep: 10, cap: 100 };
  const sel = selectViewport(1000, ipOf, 100, 104, new Set(), opts);
  assert.deepEqual(sel.slice(0, 5), [100, 101, 102, 103, 104].map(ipOf));
  assert.deepEqual(new Set(sel), new Set([98, 99, 100, 101, 102, 103, 104, 105, 106].map(ipOf)));
  // Clamped at the ends.
  assert.deepEqual(selectViewport(3, ipOf, 0, 10, new Set(), opts), [0, 1, 2].map(ipOf));
  assert.equal(selectViewport(1000, ipOf, 0, 500, new Set(), { margin: 2, keep: 4, cap: 50 }).length, 50);
  assert.deepEqual(selectViewport(0, ipOf, 0, -1, new Set(), opts), []);
});

test("viewport selection: hysteresis keeps recently visible rows, never adds new far rows", () => {
  const opts = { margin: 2, keep: 10, cap: 100 };
  const first = new Set(selectViewport(1000, ipOf, 100, 104, new Set(), opts));
  // Scroll down by 5 rows: rows 98-102 are now 3-7 rows above the view, inside `keep`.
  const second = new Set(selectViewport(1000, ipOf, 105, 109, first, opts));
  for (const i of [98, 99, 100, 101, 102]) assert.ok(second.has(ipOf(i)), `row ${i} kept`);
  // Row 95 was never monitored and is outside the margin: not added.
  assert.ok(!second.has(ipOf(95)));
  // Scroll far away: everything old is dropped.
  const third = new Set(selectViewport(1000, ipOf, 500, 504, second, opts));
  assert.ok(![...first].some((ip) => third.has(ip)));
});

test("monitor plan: start new hosts, stop unneeded monitors, consolidate when fragmented", () => {
  const wanted = new Set(["a", "b", "c"]);
  assert.deepEqual(planMonitors([], wanted), { stop: [], start: [["a", "b", "c"]] });
  assert.deepEqual(planMonitors([{ id: 1, ips: ["a", "b"] }, { id: 2, ips: ["x"] }], wanted), { stop: [2], start: [["c"]] });
  assert.deepEqual(planMonitors([{ id: 1, ips: ["a", "b", "c"] }], wanted), { stop: [], start: [] });
  assert.deepEqual(planMonitors([{ id: 1, ips: ["a"] }], new Set()), { stop: [1], start: [] });
  const many = [1, 2, 3].map((id) => ({ id, ips: [["a", "b", "c"][id - 1]!] }));
  assert.deepEqual(planMonitors(many, new Set(["a", "b", "c", "d"]), { maxMonitors: 3, maxHosts: 100 }), {
    stop: [1, 2, 3],
    start: [["a", "b", "c", "d"]],
  });
  // Mostly unwanted hosts in kept monitors: consolidate.
  const wasteful = [{ id: 9, ips: ["a", ...Array.from({ length: 40 }, (_, i) => `old${i}`)] }];
  assert.deepEqual(planMonitors(wasteful, new Set(["a"])), { stop: [9], start: [["a"]] });
});

test("latency controller: debounced, incremental, restart on interval change, stop when off", async () => {
  const calls: string[] = [];
  let next = 1;
  const timers: Array<() => void> = [];
  let failNext: string | null = null;
  const errors: string[] = [];
  const ctl = new LatencyController(
    {
      start: async (ips, ms) => {
        if (failNext) {
          const f = failNext;
          failNext = null;
          throw f;
        }
        calls.push(`start ${ips.join(",")} @${ms}`);
        return next++;
      },
      stop: async (id) => {
        calls.push(`stop ${id}`);
        return true;
      },
    },
    { schedule: (fn) => timers.push(fn), cancel: () => undefined, maxHosts: 4, onError: (m) => errors.push(m) },
  );
  ctl.setSource("viewport", ["a", "b"]);
  ctl.setSource("selected", ["s"]);
  assert.equal(timers.length, 0, "nothing scheduled while off");
  ctl.setEnabled(true);
  await ctl.reconcileNow();
  assert.deepEqual(calls, ["start s,a,b @1000"]);
  calls.length = 0;
  ctl.setSource("viewport", ["b", "c"]);
  await ctl.reconcileNow();
  assert.deepEqual(calls, ["start c @1000"], "only new hosts start; the old monitor still has wanted hosts");
  assert.deepEqual([...ctl.wanted()], ["s", "b", "c"]);
  // Cap: selected first, then pinned, then viewport.
  ctl.setSource("pinned", ["p1", "p2", "p3"]);
  assert.deepEqual([...ctl.wanted()], ["s", "p1", "p2", "p3"]);
  ctl.setSource("pinned", []);
  calls.length = 0;
  ctl.setIntervalMs(2000);
  await ctl.reconcileNow();
  assert.deepEqual(calls, ["stop 1", "stop 2", "start s,b,c @2000"]);
  assert.equal(ctl.accepts(1), false);
  assert.equal(ctl.accepts(3), true);
  calls.length = 0;
  ctl.setEnabled(false);
  await ctl.reconcileNow();
  assert.deepEqual(calls, ["stop 3"]);
  assert.equal(ctl.monitors().length, 0);
  // While changes keep coming, a pending run is postponed at most `maxWaitMs`.
  let clock = 0;
  const pending: Array<() => void> = [];
  let scheduled = 0;
  const debounced = new LatencyController(
    { start: async () => 1, stop: async () => true },
    {
      schedule: (fn) => {
        scheduled++;
        return pending.push(fn);
      },
      cancel: () => pending.pop(),
      now: () => clock,
      debounceMs: 300,
      maxWaitMs: 1000,
    },
  );
  debounced.setEnabled(true);
  for (let i = 0; i < 10; i++) {
    clock += 200;
    debounced.setSource("viewport", [`h${i}`]);
  }
  assert.equal(pending.length, 1);
  assert.equal(scheduled, 5, "postponed by changes at 200-800 ms, kept from 1000 ms on");
  // A start failure is reported once.
  ctl.setEnabled(true);
  failNext = "more than 2000 hosts";
  await ctl.reconcileNow();
  assert.deepEqual(errors, ["more than 2000 hosts"]);
});

test("latency presentation: tones, formatting, nice scale and sparkline geometry", () => {
  assert.equal(lossTone(0), "ok");
  assert.equal(lossTone(2), "warn");
  assert.equal(lossTone(25), "bad");
  assert.equal(lossTone(100), "down");
  assert.equal(lossTone(null), "none");
  const s = computeStats([10, 12, 11], "icmp", 0);
  assert.equal(latencyTone(s), "ok");
  assert.equal(latencyTone(computeStats([null, null], "icmp", 0)), "down");
  assert.equal(latencyTone(computeStats([200, 210], "icmp", 0)), "bad");
  assert.equal(latencyTone(computeStats([1, null, 1, 1], "icmp", 0)), "bad");
  assert.equal(formatMs(0.456), "0.46");
  assert.equal(formatMs(4.56), "4.6");
  assert.equal(formatMs(45.6), "46");
  assert.equal(formatMs(null), "—");
  assert.equal(formatLoss(2.5), "2.5%");
  assert.equal(formatLoss(100), "100%");
  assert.equal(niceCeil(7), 10);
  assert.equal(niceCeil(1.2), 2);
  assert.equal(niceCeil(0.3), 0.5);
  assert.equal(niceCeil(230), 250);
  const g = sparkline([5, null, 10, 10], 119, 20, { pad: 0 });
  assert.equal(g.max, 10);
  assert.deepEqual(g.lost, [117]);
  // Newest sample on the right edge, one x unit per slot (width 119 / 119 slots).
  assert.equal(g.path, "M116 10h0.6M118 0L119 0");
});

// --- web identity / TLS ---------------------------------------------------------------------------------

const NOW = Date.UTC(2026, 9, 16);
const DAY = 86_400_000;

function tls(days: number, patch: Partial<TlsCertInfo> = {}): TlsCertInfo {
  return {
    port: 443,
    subjectCn: "x.example",
    subject: "CN=x.example",
    sans: [],
    sanCount: 0,
    issuerCn: "CA",
    issuer: "CN=CA",
    notBefore: null,
    notAfter: new Date(NOW + days * DAY).toISOString(),
    notBeforeMs: null,
    notAfterMs: NOW + days * DAY,
    daysRemaining: days,
    selfSigned: false,
    expired: days < 0,
    keyType: "RSA",
    keyBits: 2048,
    signatureAlgorithm: null,
    sha256: null,
    ...patch,
  };
}

test("certificate expiry classification", () => {
  assert.equal(classifyCert(null, NOW), null);
  const expired = classifyCert(tls(-3), NOW)!;
  assert.equal(expired.status, "expired");
  assert.equal(expired.text, "expired 3 d ago");
  assert.equal(expired.date, "2026-10-13");
  assert.equal(classifyCert(tls(12), NOW)?.status, "expiring");
  assert.equal(classifyCert(tls(CERT_WARN_DAYS), NOW)?.status, "ok");
  assert.equal(classifyCert(tls(CERT_WARN_DAYS - 1), NOW)?.status, "expiring");
  // Recomputed from notAfterMs (the scan may be days old): 40 days left then, 10 now.
  assert.equal(classifyCert(tls(40), NOW + 30 * DAY)?.status, "expiring");
  const ss = classifyCert(tls(400, { selfSigned: true }), NOW)!;
  assert.equal(ss.status, "ok");
  assert.equal(ss.selfSigned, true);
  const unknown = classifyCert(tls(0, { notAfterMs: null, notAfter: null, daysRemaining: null, expired: false }), NOW)!;
  assert.equal(unknown.status, "unknown");
  assert.equal(classifyCert(tls(0, { notAfterMs: null, daysRemaining: null, expired: true }), NOW)?.status, "expired");
  assert.equal(certSortKey(tls(5)), NOW + 5 * DAY);
  assert.equal(certSortKey(null), undefined);
});

test("web targets: services first (HTTPS first), else certificate port and open web ports", () => {
  const svc = (port: number, scheme: "http" | "https", patch: Partial<WebService> = {}): WebService => ({
    port,
    scheme,
    url: `${scheme}://10.0.0.5:${port}/`,
    status: 200,
    title: null,
    server: null,
    redirects: 0,
    redirectTo: null,
    tlsCert: null,
    error: null,
    ...patch,
  });
  const d = device("10.0.0.5", { openPorts: [22, 80, 8443], tlsCert: tls(100, { port: 8443 }), webTitle: "UI" });
  const fromScan = webTargets(d);
  assert.deepEqual(
    fromScan.map((t) => t.url),
    ["https://10.0.0.5:8443/", "http://10.0.0.5/"],
  );
  assert.equal(fromScan[0]?.title, "UI");
  const fromServices = webTargets(d, [svc(80, "http"), svc(8006, "https", { url: "https://10.0.0.5:8006/#v1" }), svc(81, "http", { status: null, error: "refused" })]);
  assert.deepEqual(
    fromServices.map((t) => t.url),
    ["https://10.0.0.5:8006/#v1", "http://10.0.0.5:80/"],
  );
  assert.deepEqual(webTargets(device("fe80::1", { openPorts: [443] })).map((t) => t.url), ["https://[fe80::1]/"]);
  assert.equal(webProbePorts(device("10.0.0.1", { openPorts: [443] })), null);
  assert.deepEqual(webProbePorts(device("10.0.0.1", { openPorts: [8006, 22] })), [80, 443, 8443, 8080, 8000, 10443, 8006]);
});

test("web identity merges into a device; exports carry live latency", () => {
  const wi: WebIdentity = {
    ip: "10.0.0.1",
    services: [
      { port: 443, scheme: "https", url: "https://10.0.0.1/", status: 200, title: "FortiGate", server: null, redirects: 0, redirectTo: null, tlsCert: null, error: null },
    ],
    title: "FortiGate",
    server: null,
    tlsCert: tls(5),
    identity: "Fortinet FortiGate",
    roleHint: "firewall",
    warnings: ["TLS certificate on port 443 expires in 5 day(s)", "old"],
  };
  const merged = withWebIdentity(device("10.0.0.1", { warnings: ["old"], webServer: "x" }), wi);
  assert.equal(merged.role, "firewall");
  assert.equal(merged.webIdentity, "Fortinet FortiGate");
  assert.equal(merged.webServer, "x", "missing values keep the scan's");
  assert.deepEqual(merged.warnings, ["old", "TLS certificate on port 443 expires in 5 day(s)"]);
  assert.deepEqual(merged.openPorts, [443]);
  assert.equal(withWebIdentity(device("10.0.0.2", { role: "switch" }), wi).role, "switch", "never re-roles infrastructure");
  const row = buildRow("10.0.0.1", merged, undefined);
  assert.ok(row.search.includes("fortigate"));
  assert.ok(row.search.includes("expires in 5"));
  const lat = computeStats([1, 2], "icmp", 9);
  assert.deepEqual(exportDevice(row, lat).latency, lat);
  assert.equal(exportDevice(row).latency, null);
});

// --- traceroute ---------------------------------------------------------------------------------------------

function hop(ttl: number, patch: Partial<TraceHop> = {}): TraceHop {
  return {
    ttl,
    ip: `10.0.${ttl}.1`,
    hostname: null,
    otherIps: [],
    sent: 5,
    received: 5,
    lossPct: 0,
    lastMs: ttl,
    avgMs: ttl,
    bestMs: ttl - 0.5,
    worstMs: ttl + 1,
    ...patch,
  };
}

const silentHop = (ttl: number): TraceHop =>
  hop(ttl, { ip: null, received: 0, lossPct: 100, lastMs: null, avgMs: null, bestMs: null, worstMs: null });

test("trace table: silent runs collapse, rate-limited loss is flagged, bars scale to the worst hop", () => {
  const t = traceTable([hop(3, { lossPct: 40, received: 3 }), hop(1), hop(2), silentHop(4), silentHop(5), hop(6, { worstMs: 18 }), silentHop(7)]);
  assert.equal(t.scaleMs, 20);
  assert.equal(t.answered, 4);
  assert.deepEqual(
    t.rows.map((r) => (r.kind === "gap" ? `gap ${r.fromTtl}-${r.toTtl}` : `hop ${r.ttl}`)),
    ["hop 1", "hop 2", "hop 3", "gap 4-5", "hop 6", "hop 7"],
    "a single silent hop stays a row",
  );
  const h3 = t.rows[2];
  assert.ok(h3 && h3.kind === "hop");
  assert.equal(h3.rateLimited, true);
  assert.equal(h3.tone, "bad");
  const h6 = t.rows[4];
  assert.ok(h6 && h6.kind === "hop" && h6.bar);
  assert.equal(h6.bar.to, 0.9);
  assert.equal(h6.bar.avg, 0.3);
  // Loss at the destination itself is real loss.
  const end = traceTable([hop(1), hop(2, { lossPct: 20, received: 4 })]);
  const last = end.rows[1];
  assert.ok(last && last.kind === "hop");
  assert.equal(last.rateLimited, false);
  assert.equal(last.tone, "bad");
  assert.deepEqual(traceTable([]).rows, []);
});

// --- iPerf3 ---------------------------------------------------------------------------------------------------

function iv(start: number, mbps: number, patch: Partial<IperfInterval> = {}): IperfInterval {
  return {
    start,
    end: start + 1,
    bytes: (mbps * 1e6) / 8,
    bitsPerSecond: mbps * 1e6,
    retransmits: 0,
    jitterMs: null,
    lostPackets: null,
    packets: null,
    lostPercent: null,
    omitted: false,
    ...patch,
  };
}

test("iperf chart: bars by time, nice scale, average of non-omitted intervals", () => {
  const c = throughputChart([iv(0, 400, { omitted: true }), iv(1, 900), iv(2, 940)], 100, 50, 10);
  assert.equal(c.maxMbps, 1000);
  assert.equal(c.spanSecs, 10);
  assert.deepEqual(c.ticks, [0, 500, 1000]);
  assert.equal(c.avgMbps, 920);
  assert.equal(c.avgY, 4);
  assert.equal(c.bars.length, 3);
  assert.deepEqual([c.bars[1]?.x, c.bars[1]?.w, c.bars[1]?.h, c.bars[1]?.y], [10, 9, 45, 5]);
  assert.equal(c.bars[0]?.omitted, true);
  const empty = throughputChart([], 100, 50, 5);
  assert.equal(empty.avgMbps, null);
  assert.equal(empty.maxMbps, 1);
  // Runs longer than requested widen the axis.
  assert.equal(throughputChart([iv(11, 10)], 100, 50, 10).spanSecs, 12);
});

test("iperf options and units", () => {
  assert.equal(iperfProblem(DEFAULT_IPERF), null);
  assert.match(iperfProblem({ ...DEFAULT_IPERF, durationSecs: 61 }) ?? "", /1-60/);
  assert.match(iperfProblem({ ...DEFAULT_IPERF, streams: 0 }) ?? "", /1-16/);
  assert.match(iperfProblem({ ...DEFAULT_IPERF, port: 0 }) ?? "", /Port/);
  for (const ok of ["100M", "2.5G", "0", "500k", " 1T "]) assert.equal(iperfProblem({ ...DEFAULT_IPERF, bitrate: ok }), null, ok);
  for (const bad of ["100Mbps", ".5M", "5.", "1.2.3M", "1234567890123M"]) assert.notEqual(iperfProblem({ ...DEFAULT_IPERF, bitrate: bad }), null, bad);
  assert.equal(iperfForWire({ ...DEFAULT_IPERF, bitrate: "  " }).bitrate, null);
  assert.equal(formatBps(941_000_000), "941 Mbit/s");
  assert.equal(formatBps(1_234_000_000), "1.23 Gbit/s");
  assert.equal(formatBps(12_500), "12.5 kbit/s");
  assert.equal(formatBytes(1_100_000_000), "1.10 GB");
});

// --- Wake-on-LAN / columns -------------------------------------------------------------------------------------

test("Wake-on-LAN MAC and SecureOn parsing", () => {
  assert.deepEqual(parseWolMac("AA-BB-CC-DD-EE-F0"), { ok: true, value: "aa:bb:cc:dd:ee:f0" });
  assert.deepEqual(parseWolMac("aabb.ccdd.eef0"), { ok: true, value: "aa:bb:cc:dd:ee:f0" });
  assert.equal(parseWolMac("ff:ff:ff:ff:ff:ff").ok, false);
  assert.equal(parseWolMac("01:00:5e:00:00:01").ok, false, "multicast");
  assert.equal(parseWolMac("00:00:00:00:00:00").ok, false);
  assert.equal(parseWolMac("aa:bb:cc").ok, false);
  assert.deepEqual(parseSecureOn(""), { ok: true, value: null });
  assert.deepEqual(parseSecureOn("010203040506"), { ok: true, value: "01:02:03:04:05:06" });
  assert.equal(parseSecureOn("01:02").ok, false);
});

test("column prefs: new columns slot in at their default position; auto visibility yields to explicit choices", () => {
  const all = ["ip", "mac", "ports", "latency", "loss", "comments"] as const;
  assert.deepEqual(completeOrder(["comments", "ip", "ports", "mac", "bogus", "ip"], all), ["comments", "ip", "ports", "latency", "loss", "mac"]);
  assert.deepEqual(completeOrder([], all), [...all]);
  const auto = { liveLatency: true, webTitle: false, certExpires: true };
  const v = effectiveVisibility({ mdns: false }, auto);
  assert.equal(v.latency, true);
  assert.equal(v.webTitle, false);
  assert.equal(v.certExpires, true);
  assert.equal(v.certCn, false);
  assert.equal(effectiveVisibility({ latency: false }, auto).latency, false);
  assert.equal(effectiveVisibility({ webTitle: true }, auto).webTitle, true);
});

test("latency monitor: known open ports feed the TCP fallback, common ports first", () => {
  const devs = [
    { ip: "10.0.0.1", openPorts: [9100, 22, 443, 8443, 515, 631] },
    { ip: "10.0.0.2", openPorts: [] },
    { ip: "10.0.0.3", openPorts: [5060] },
    { ip: "10.0.0.9", openPorts: [80] },
    { ip: "10.0.0.1", openPorts: [21] },
  ];
  assert.deepEqual(tcpPortsFor(["10.0.0.1", "10.0.0.2", "10.0.0.3"], devs), { "10.0.0.1": [443, 22, 8443, 515], "10.0.0.3": [5060] });
  assert.equal(tcpPortsFor(["10.0.0.1"], devs)?.["10.0.0.1"]?.length, TCP_PORTS_PER_HOST);
  assert.equal(tcpPortsFor(["10.0.0.2"], devs), null, "nothing known: the backend's default ports");
  assert.equal(tcpPortsFor([], devs), null);
  assert.deepEqual(tcpPortsFor(["10.0.0.4"], [{ ip: "10.0.0.4", openPorts: [0, 70000, 22, 22] }]), { "10.0.0.4": [22] });
});

test("reload cleanup: job ids saved for the session are parsed defensively", () => {
  assert.deepEqual(parseIdList(null), []);
  assert.deepEqual(parseIdList("[3, 7]"), [3, 7]);
  assert.deepEqual(parseIdList('[1, "2", -3, 4.5, null, 9]'), [1, 9]);
  assert.deepEqual(parseIdList("{}"), []);
  assert.deepEqual(parseIdList("not json"), []);
  assert.equal(parseIdList(JSON.stringify(Array.from({ length: 999 }, (_, i) => i + 1))).length, 256);
});
