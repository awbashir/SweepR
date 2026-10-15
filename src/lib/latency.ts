// Live latency: per-host ring of the last 120 samples, a throttled store for React, the
// "which hosts to monitor" selection (visible rows with hysteresis) and the reconciliation of
// that selection with backend monitors (`start_latency_monitor` takes a fixed host list, so a
// changed selection starts a monitor for the new hosts and stops monitors nobody needs).
// Framework-free so it can be unit tested.

import type { LatencySample, LatencyStats, LatencyUpdate, ProbeMethod } from "../types.ts";

/** Samples kept per host (the backend's window). */
export const HISTORY_LEN = 120;
/** Hosts whose latency the store remembers (least recently updated are dropped first). */
export const MAX_LATENCY_ENTRIES = 4000;
/** Hosts monitored at once by the GUI (the backend allows 2,000 in total). */
export const MAX_MONITORED = 300;
/** Concurrent monitors the GUI keeps (the backend allows 16). */
export const MAX_MONITORS = 6;
/** Choices offered for the probe interval (ms); the backend accepts 500-10000. */
export const LATENCY_INTERVALS = [500, 1000, 2000, 5000, 10000] as const;

export type History = readonly (number | null)[];

export interface LatencyEntry {
  ip: string;
  /** Monitor whose samples feed `live`. Samples of older monitors are ignored. */
  source: number;
  /** Window inherited from earlier monitors (frozen), oldest first. */
  carry: History;
  /** The current monitor's window (`sample.history`). */
  live: History;
  /** `carry` + `live`: at most `HISTORY_LEN`, oldest first, `null` = lost. */
  history: History;
  stats: LatencyStats;
}

/** Min / avg / max / jitter / loss over a window (jitter: mean |Δ| of consecutive replies). */
export function computeStats(history: History, method: ProbeMethod, updatedMs: number): LatencyStats {
  let received = 0;
  let sum = 0;
  let min = Infinity;
  let max = -Infinity;
  let jitterSum = 0;
  let jitterN = 0;
  let prev: number | null = null;
  for (const v of history) {
    if (v === null) continue;
    received++;
    sum += v;
    if (v < min) min = v;
    if (v > max) max = v;
    if (prev !== null) {
      jitterSum += Math.abs(v - prev);
      jitterN++;
    }
    prev = v;
  }
  const sent = history.length;
  return {
    lastMs: sent > 0 ? (history[sent - 1] ?? null) : null,
    avgMs: received > 0 ? sum / received : null,
    minMs: received > 0 ? min : null,
    maxMs: received > 0 ? max : null,
    jitterMs: jitterN > 0 ? jitterSum / jitterN : null,
    lossPct: sent > 0 ? ((sent - received) / sent) * 100 : 0,
    sent,
    received,
    method,
    updatedMs,
  };
}

function tail<T>(a: readonly T[], n: number): readonly T[] {
  return a.length > n ? a.slice(a.length - n) : a;
}

/**
 * Fold one backend sample into a host's entry. Within one monitor the backend's window is
 * authoritative; when a host moves to a newer monitor (the selection changed) the old window is
 * carried over so the sparkline continues. Returns `null` for a sample of an older monitor.
 */
export function applySample(prev: LatencyEntry | undefined, sample: LatencySample, monitorId: number): LatencyEntry | null {
  if (prev && monitorId < prev.source) return null;
  let carry: History = prev?.carry ?? [];
  if (prev && monitorId !== prev.source) carry = tail([...prev.carry, ...prev.live], HISTORY_LEN);
  const live: History = tail(sample.history.length > 0 ? sample.history : [sample.rttMs], HISTORY_LEN);
  carry = tail(carry, HISTORY_LEN - live.length);
  const history = carry.length === 0 ? live : [...carry, ...live];
  // Without carried samples the backend's statistics describe exactly this window.
  const stats: LatencyStats =
    carry.length === 0
      ? {
          lastMs: sample.rttMs,
          avgMs: sample.avgMs,
          minMs: sample.minMs,
          maxMs: sample.maxMs,
          jitterMs: sample.jitterMs,
          lossPct: sample.lossPct,
          sent: sample.sent,
          received: sample.received,
          method: sample.method,
          updatedMs: sample.ts,
        }
      : { ...computeStats(history, sample.method, sample.ts), lastMs: sample.rttMs };
  return { ip: sample.ip, source: monitorId, carry, live, history, stats };
}

// --- store -------------------------------------------------------------------------------------

type Scheduler = (fn: () => void, ms: number) => unknown;

/**
 * Latency entries by IP. Updates are applied at once; subscribers are notified at most once
 * per `throttleMs` (default 250 ms, i.e. ≤ 4 renders per second however many hosts update).
 */
export class LatencyStore {
  private entries = new Map<string, LatencyEntry>();
  private listeners = new Set<() => void>();
  private pending = false;
  private version = 0;
  /** Monitors whose updates are still wanted (stopped monitors may send one last batch). */
  accept: (monitorId: number) => boolean = () => true;
  throttleMs: number;
  private readonly schedule: Scheduler;
  private readonly maxEntries: number;

  constructor(opts: { schedule?: Scheduler; throttleMs?: number; maxEntries?: number } = {}) {
    this.schedule = opts.schedule ?? ((fn, ms) => setTimeout(fn, ms));
    this.throttleMs = opts.throttleMs ?? 250;
    this.maxEntries = opts.maxEntries ?? MAX_LATENCY_ENTRIES;
  }

  handleUpdate = (u: LatencyUpdate): void => {
    if (!this.accept(u.monitorId)) return;
    let changed = false;
    for (const s of u.samples) {
      const next = applySample(this.entries.get(s.ip), s, u.monitorId);
      if (!next) continue;
      // Re-insert so the Map's order is "least recently updated first" (eviction order).
      this.entries.delete(s.ip);
      this.entries.set(s.ip, next);
      changed = true;
    }
    while (this.entries.size > this.maxEntries) {
      const first = this.entries.keys().next();
      if (first.done) break;
      this.entries.delete(first.value);
    }
    if (changed) this.markDirty();
  };

  get = (ip: string): LatencyEntry | undefined => this.entries.get(ip);

  /** Bumped on every notification (cheap change detection for non-React consumers). */
  getVersion = (): number => this.version;

  get size(): number {
    return this.entries.size;
  }

  subscribe = (fn: () => void): (() => void) => {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  };

  clear(): void {
    this.entries.clear();
    this.markDirty();
  }

  /** Notify now (tests). */
  flush(): void {
    this.pending = false;
    this.version++;
    for (const fn of this.listeners) fn();
  }

  private markDirty(): void {
    if (this.pending) return;
    this.pending = true;
    this.schedule(() => {
      if (this.pending) this.flush();
    }, this.throttleMs);
  }
}

// --- which hosts to monitor ---------------------------------------------------------------------

export interface ViewportOptions {
  /** Rows above / below the visible ones that are monitored too. */
  margin: number;
  /** Already monitored rows stay monitored while within this distance (hysteresis). */
  keep: number;
  /** Most hosts returned. */
  cap: number;
}

export const DEFAULT_VIEWPORT: ViewportOptions = { margin: 8, keep: 40, cap: 160 };

/**
 * IPs to monitor for a virtualized table showing rows `start..end` (inclusive) of `count`.
 * Visible rows come first, then the margin (nearest first), then previously monitored rows
 * that are still near (so a row scrolling a little out of view keeps its monitor and does not
 * flap). `ipAt(i)` gives the IP of sorted row `i`.
 */
export function selectViewport(
  count: number,
  ipAt: (i: number) => string | undefined,
  start: number,
  end: number,
  prev: ReadonlySet<string>,
  opts: ViewportOptions = DEFAULT_VIEWPORT,
): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (i: number): boolean => {
    if (i < 0 || i >= count) return true;
    if (out.length >= opts.cap) return false;
    const ip = ipAt(i);
    if (ip !== undefined && !seen.has(ip)) {
      seen.add(ip);
      out.push(ip);
    }
    return true;
  };
  if (count <= 0 || end < start) return out;
  const s = Math.max(0, start);
  const e = Math.min(count - 1, end);
  for (let i = s; i <= e; i++) if (!add(i)) return out;
  for (let d = 1; d <= opts.margin; d++) {
    if (!add(s - d) || !add(e + d)) return out;
  }
  if (prev.size > 0) {
    for (let d = opts.margin + 1; d <= opts.keep; d++) {
      for (const i of [s - d, e + d]) {
        if (i < 0 || i >= count) continue;
        const ip = ipAt(i);
        if (ip !== undefined && prev.has(ip) && !seen.has(ip)) {
          if (out.length >= opts.cap) return out;
          seen.add(ip);
          out.push(ip);
        }
      }
    }
  }
  return out;
}

export interface ActiveMonitor {
  id: number;
  ips: readonly string[];
}

export interface MonitorPlan {
  /** Monitors to stop. */
  stop: number[];
  /** Host lists to start monitors for. */
  start: string[][];
}

/**
 * Reconcile running monitors with the wanted hosts: start one monitor for hosts nobody pings
 * yet, stop monitors none of whose hosts are wanted. When that would leave too many monitors,
 * too many hosts, or mostly unwanted hosts being pinged, consolidate into one fresh monitor.
 */
export function planMonitors(
  active: readonly ActiveMonitor[],
  wanted: ReadonlySet<string>,
  limits: { maxMonitors: number; maxHosts: number } = { maxMonitors: MAX_MONITORS, maxHosts: MAX_MONITORED * 2 },
): MonitorPlan {
  if (wanted.size === 0) return { stop: active.map((m) => m.id), start: [] };
  const covered = new Set<string>();
  const stop: number[] = [];
  const keep: ActiveMonitor[] = [];
  for (const m of active) {
    if (m.ips.some((ip) => wanted.has(ip))) {
      keep.push(m);
      for (const ip of m.ips) covered.add(ip);
    } else {
      stop.push(m.id);
    }
  }
  const added = [...wanted].filter((ip) => !covered.has(ip));
  let hosts = added.length;
  let wasted = 0;
  for (const m of keep) {
    hosts += m.ips.length;
    for (const ip of m.ips) if (!wanted.has(ip)) wasted++;
  }
  const monitors = keep.length + (added.length > 0 ? 1 : 0);
  if (monitors > limits.maxMonitors || hosts > limits.maxHosts || wasted > Math.max(wanted.size, 16)) {
    return { stop: active.map((m) => m.id), start: [[...wanted]] };
  }
  return { stop, start: added.length > 0 ? [added] : [] };
}

export interface MonitorBackend {
  start(ips: string[], intervalMs: number): Promise<number>;
  stop(monitorId: number): Promise<boolean>;
}

export interface ControllerOptions {
  debounceMs?: number;
  /** Longest a change waits while further changes keep postponing it (continuous scrolling). */
  maxWaitMs?: number;
  now?: () => number;
  maxHosts?: number;
  maxMonitors?: number;
  schedule?: (fn: () => void, ms: number) => unknown;
  cancel?: (handle: unknown) => void;
  onError?: (message: string) => void;
  /** Called with the running monitor ids after every change (to stop leftovers after a reload). */
  onActive?: (ids: number[]) => void;
}

/** Source priority when the wanted set exceeds the cap (first = kept first). */
const SOURCE_ORDER = ["selected", "pinned", "viewport", "infra"];

/**
 * Keeps backend monitors in line with what the UI wants monitored. Sources ("selected",
 * "pinned", "viewport", "infra") are merged in priority order and capped; changes are debounced
 * so scrolling does not churn monitors, and reconciliations never overlap.
 */
export class LatencyController {
  private sources = new Map<string, readonly string[]>();
  private enabled = false;
  private intervalMs = 1000;
  private active: ActiveMonitor[] = [];
  private stopped = new Set<number>();
  private timer: unknown = null;
  /** When the pending reconciliation was first requested. */
  private pendingSince = 0;
  private busy = false;
  private again = false;
  private restartAll = false;
  private lastError: string | null = null;
  private readonly o: Required<Omit<ControllerOptions, "onError" | "onActive">> & Pick<ControllerOptions, "onError" | "onActive">;

  private readonly api: MonitorBackend;

  constructor(api: MonitorBackend, opts: ControllerOptions = {}) {
    this.api = api;
    this.o = {
      debounceMs: opts.debounceMs ?? 350,
      maxWaitMs: opts.maxWaitMs ?? 1500,
      now: opts.now ?? (() => Date.now()),
      maxHosts: opts.maxHosts ?? MAX_MONITORED,
      maxMonitors: opts.maxMonitors ?? MAX_MONITORS,
      schedule: opts.schedule ?? ((fn, ms) => setTimeout(fn, ms)),
      cancel: opts.cancel ?? ((h) => clearTimeout(h as ReturnType<typeof setTimeout>)),
      onError: opts.onError,
      onActive: opts.onActive,
    };
  }

  /** Updates of these monitors are wanted (stopped monitors may still send a final batch). */
  accepts = (monitorId: number): boolean => !this.stopped.has(monitorId);

  setEnabled(on: boolean): void {
    if (on === this.enabled) return;
    this.enabled = on;
    this.lastError = null;
    this.kick(on ? this.o.debounceMs : 0);
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  setIntervalMs(ms: number): void {
    const v = Math.max(500, Math.min(10_000, Math.round(ms)));
    if (v === this.intervalMs) return;
    this.intervalMs = v;
    this.restartAll = true;
    if (this.enabled) this.kick(this.o.debounceMs);
  }

  setSource(name: string, ips: readonly string[]): void {
    const prev = this.sources.get(name);
    if (prev && prev.length === ips.length && prev.every((ip, i) => ip === ips[i])) return;
    if (ips.length === 0) this.sources.delete(name);
    else this.sources.set(name, ips);
    if (this.enabled) this.kick(this.o.debounceMs);
  }

  getSource(name: string): readonly string[] {
    return this.sources.get(name) ?? [];
  }

  /** Visible rows `start..end` of a sorted table (see `selectViewport`). */
  setViewport(count: number, ipAt: (i: number) => string | undefined, start: number, end: number, opts?: ViewportOptions): void {
    const prev = new Set(this.sources.get("viewport") ?? []);
    this.setSource("viewport", selectViewport(count, ipAt, start, end, prev, opts));
  }

  /** The capped, de-duplicated set the next reconciliation aims for. */
  wanted(): Set<string> {
    const out = new Set<string>();
    if (!this.enabled) return out;
    const names = [...SOURCE_ORDER, ...[...this.sources.keys()].filter((k) => !SOURCE_ORDER.includes(k))];
    for (const name of names) {
      for (const ip of this.sources.get(name) ?? []) {
        if (out.size >= this.o.maxHosts) return out;
        out.add(ip);
      }
    }
    return out;
  }

  monitored(): ReadonlySet<string> {
    const s = new Set<string>();
    for (const m of this.active) for (const ip of m.ips) s.add(ip);
    return s;
  }

  monitors(): readonly ActiveMonitor[] {
    return this.active;
  }

  /** Run a reconciliation now (tests; also used when turning off). */
  async reconcileNow(): Promise<void> {
    if (this.timer !== null) {
      this.o.cancel(this.timer);
      this.timer = null;
    }
    await this.reconcile();
  }

  private kick(ms: number): void {
    const now = this.o.now();
    if (this.timer !== null) {
      // Keep the pending run when it has already waited long enough (steady scrolling).
      if (ms > 0 && now - this.pendingSince >= this.o.maxWaitMs) return;
      this.o.cancel(this.timer);
    } else {
      this.pendingSince = now;
    }
    this.timer = this.o.schedule(() => {
      this.timer = null;
      void this.reconcile();
    }, ms);
  }

  private async reconcile(): Promise<void> {
    if (this.busy) {
      this.again = true;
      return;
    }
    this.busy = true;
    try {
      do {
        this.again = false;
        const wanted = this.wanted();
        const plan: MonitorPlan = this.restartAll
          ? { stop: this.active.map((m) => m.id), start: wanted.size > 0 ? [[...wanted]] : [] }
          : planMonitors(this.active, wanted, { maxMonitors: this.o.maxMonitors, maxHosts: this.o.maxHosts * 2 });
        this.restartAll = false;
        for (const id of plan.stop) {
          this.stopped.add(id);
          this.active = this.active.filter((m) => m.id !== id);
          try {
            await this.api.stop(id);
          } catch {
            /* already gone */
          }
        }
        if (this.stopped.size > 1000) this.stopped = new Set([...this.stopped].slice(-500));
        for (const ips of plan.start) {
          try {
            const id = await this.api.start(ips, this.intervalMs);
            if (!this.enabled) {
              // Turned off while starting.
              this.stopped.add(id);
              void this.api.stop(id).catch(() => undefined);
            } else {
              this.active.push({ id, ips });
            }
            this.lastError = null;
          } catch (e) {
            const msg = typeof e === "string" ? e : e instanceof Error ? e.message : String(e);
            // Report each distinct failure once; the next selection change retries.
            if (msg !== this.lastError) this.o.onError?.(msg);
            this.lastError = msg;
          }
        }
        if (plan.stop.length > 0 || plan.start.length > 0) this.o.onActive?.(this.active.map((m) => m.id));
      } while (this.again);
    } finally {
      this.busy = false;
    }
  }
}

// --- presentation helpers -------------------------------------------------------------------------

export type Tone = "ok" | "warn" | "bad" | "down" | "none";

/** 0 % ok, below 10 % warn, from 10 % bad, 100 % down. */
export function lossTone(pct: number | null | undefined): Tone {
  if (pct === null || pct === undefined || Number.isNaN(pct)) return "none";
  if (pct >= 100) return "down";
  if (pct >= 10) return "bad";
  if (pct > 0) return "warn";
  return "ok";
}

/** Colour accent for a host: down (no replies), bad (≥ 10 % loss or ≥ 150 ms), warn (any loss or ≥ 50 ms). */
export function latencyTone(s: LatencyStats | null | undefined): Tone {
  if (!s || s.sent === 0) return "none";
  if (s.received === 0) return "down";
  const avg = s.avgMs ?? 0;
  if (s.lossPct >= 10 || avg >= 150) return "bad";
  if (s.lossPct > 0 || avg >= 50) return "warn";
  return "ok";
}

export function formatMs(v: number | null | undefined): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return "—";
  if (v < 1) return v.toFixed(2);
  if (v < 10) return v.toFixed(1);
  return Math.round(v).toString();
}

export function formatLoss(pct: number | null | undefined): string {
  if (pct === null || pct === undefined || !Number.isFinite(pct)) return "—";
  if (pct === 0 || pct >= 100) return `${Math.round(pct)}%`;
  return pct < 10 ? `${pct.toFixed(1)}%` : `${Math.round(pct)}%`;
}

/** 1, 2, 5 × 10^k at or above `v` (chart scales). */
export function niceCeil(v: number): number {
  if (!(v > 0) || !Number.isFinite(v)) return 1;
  const exp = Math.floor(Math.log10(v));
  const base = 10 ** exp;
  for (const m of [1, 2, 2.5, 5, 10]) {
    if (v <= m * base * (1 + 1e-9)) return m * base;
  }
  return 10 * base;
}

export interface SparklineGeometry {
  /** SVG path of the replies (broken at lost probes). */
  path: string;
  /** x positions of lost probes. */
  lost: number[];
  /** Value at the top edge (ms). */
  max: number;
}

const r1 = (n: number): string => (Math.round(n * 10) / 10).toString();

/**
 * Sparkline of a window, newest sample at the right edge and a fixed time scale (a full window
 * spans the width), so partially filled windows grow from the right.
 */
export function sparkline(history: History, width: number, height: number, opts: { maxMs?: number; pad?: number; slots?: number } = {}): SparklineGeometry {
  const pad = opts.pad ?? 1.5;
  const slots = Math.max(2, opts.slots ?? HISTORY_LEN);
  let max = opts.maxMs ?? 0;
  if (opts.maxMs === undefined) for (const v of history) if (v !== null && v > max) max = v;
  max = niceCeil(Math.max(max, 1));
  const step = width / (slots - 1);
  const n = history.length;
  const usable = Math.max(1, height - 2 * pad);
  let path = "";
  let segLen = 0;
  const lost: number[] = [];
  for (let i = 0; i < n; i++) {
    const x = width - (n - 1 - i) * step;
    const v = history[i];
    if (v === null || v === undefined) {
      if (segLen === 1) path += "h0.6";
      segLen = 0;
      if (x >= 0) lost.push(Math.round(x * 10) / 10);
      continue;
    }
    if (x < -step) continue;
    const y = height - pad - (Math.min(v, max) / max) * usable;
    path += `${segLen === 0 ? "M" : "L"}${r1(x)} ${r1(y)}`;
    segLen++;
  }
  if (segLen === 1) path += "h0.6";
  return { path, lost, max };
}
