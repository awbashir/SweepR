// Network-utility state shared by the table, drawer and topology map: live latency (store +
// monitor controller), traceroutes, web identity lookups and iPerf3 runs. Kept outside React
// state so streamed updates re-render only the components that show them.

import { useSyncExternalStore } from "react";
import { backend, errorMessage } from "./api.ts";
import type { IperfAvailability, IperfInterval, IperfOptions, IperfSummary, IperfUpdate, TraceUpdate, WebIdentity } from "./types.ts";
import { LatencyController, LatencyStore, type LatencyEntry } from "./lib/latency.ts";
import { iperfForWire } from "./lib/iperf.ts";

// --- keyed external store ---------------------------------------------------------------------

export class KeyedStore<V> {
  private map = new Map<string, V>();
  private listeners = new Set<() => void>();

  get = (key: string): V | undefined => this.map.get(key);

  set(key: string, value: V | undefined): void {
    if (value === undefined) this.map.delete(key);
    else this.map.set(key, value);
    for (const fn of this.listeners) fn();
  }

  update(key: string, fn: (prev: V | undefined) => V | undefined): void {
    this.set(key, fn(this.map.get(key)));
  }

  values(): IterableIterator<V> {
    return this.map.values();
  }

  clear(): void {
    this.map.clear();
    for (const fn of this.listeners) fn();
  }

  subscribe = (fn: () => void): (() => void) => {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  };
}

export function useKeyed<V>(store: KeyedStore<V>, key: string | null): V | undefined {
  return useSyncExternalStore(store.subscribe, () => (key === null ? undefined : store.get(key)));
}

// --- live latency ---------------------------------------------------------------------------------

const reducedMotion = (): boolean => {
  try {
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  } catch {
    return false;
  }
};

/** Renders at most 4×/s (1×/s with reduced motion: the sparklines are moving graphics). */
export const latencyStore = new LatencyStore({ throttleMs: reducedMotion() ? 1000 : 250 });

const MONITORS_KEY = "sweepr.latency.monitors";
const errorListeners = new Set<(msg: string) => void>();

export const latencyCtl = new LatencyController(
  {
    start: (ips, intervalMs) => backend.startLatencyMonitor(ips, intervalMs),
    stop: (id) => backend.stopLatencyMonitor(id),
  },
  {
    onError: (msg) => {
      for (const fn of errorListeners) fn(msg);
    },
    // Monitors outlive a webview reload; remember them so the next load stops them.
    onActive: (ids) => {
      try {
        sessionStorage.setItem(MONITORS_KEY, JSON.stringify(ids));
      } catch {
        /* best effort */
      }
    },
  },
);
latencyStore.accept = latencyCtl.accepts;

export function onLatencyError(fn: (msg: string) => void): () => void {
  errorListeners.add(fn);
  return () => errorListeners.delete(fn);
}

export function useLatency(ip: string | null | undefined): LatencyEntry | undefined {
  return useSyncExternalStore(latencyStore.subscribe, () => (ip ? latencyStore.get(ip) : undefined));
}

// --- traceroute ---------------------------------------------------------------------------------------

export interface TraceJob {
  ip: string;
  traceId: number | null;
  update: TraceUpdate | null;
  running: boolean;
  error: string | null;
  startedAt: number;
}

export const traceStore = new KeyedStore<TraceJob>();
const traceKeys = new Map<number, string>();
const earlyTrace = new Map<number, TraceUpdate>();

function handleTrace(u: TraceUpdate): void {
  const key = traceKeys.get(u.traceId);
  if (key === undefined) {
    if (earlyTrace.size < 32) earlyTrace.set(u.traceId, u);
    return;
  }
  traceStore.update(key, (j) =>
    j && j.traceId === u.traceId ? { ...j, update: u, running: !u.done, error: u.done ? u.error : j.error } : j,
  );
  if (u.done) traceKeys.delete(u.traceId);
}

export async function startTrace(key: string, ip: string, maxHops: number, rounds: number): Promise<void> {
  const prev = traceStore.get(key);
  if (prev?.running && prev.traceId !== null) void backend.stopTrace(prev.traceId).catch(() => undefined);
  traceStore.set(key, { ip, traceId: null, update: null, running: true, error: null, startedAt: Date.now() });
  try {
    const id = await backend.startTrace(ip, maxHops, rounds);
    traceKeys.set(id, key);
    traceStore.update(key, (j) => (j ? { ...j, traceId: id } : j));
    const early = earlyTrace.get(id);
    if (early) {
      earlyTrace.delete(id);
      handleTrace(early);
    }
  } catch (e) {
    const msg = errorMessage(e);
    traceStore.update(key, (j) => (j ? { ...j, running: false, error: msg } : j));
    throw msg;
  }
}

export async function stopTrace(key: string): Promise<void> {
  const j = traceStore.get(key);
  if (!j || j.traceId === null) return;
  const was = await backend.stopTrace(j.traceId);
  if (!was) traceStore.update(key, (x) => (x ? { ...x, running: false } : x));
}

// --- web identity ---------------------------------------------------------------------------------------

export interface WebJob {
  status: "running" | "done" | "error";
  result: WebIdentity | null;
  error: string | null;
  at: number;
}

export const webStore = new KeyedStore<WebJob>();

export async function grabWebIdentity(key: string, ip: string, ports: number[] | null): Promise<WebIdentity> {
  webStore.update(key, (j) => ({ status: "running", result: j?.result ?? null, error: null, at: Date.now() }));
  try {
    const wi = await backend.grabWebIdentity(ip, ports);
    webStore.set(key, { status: "done", result: wi, error: null, at: Date.now() });
    return wi;
  } catch (e) {
    const msg = errorMessage(e);
    webStore.update(key, (j) => ({ status: "error", result: j?.result ?? null, error: msg, at: Date.now() }));
    throw msg;
  }
}

// --- iPerf3 ------------------------------------------------------------------------------------------------

export interface IperfJob {
  ip: string;
  runId: number | null;
  options: IperfOptions;
  intervals: IperfInterval[];
  summary: IperfSummary | null;
  running: boolean;
  error: string | null;
  startedAt: number;
}

export const iperfStore = new KeyedStore<IperfJob>();
const iperfKeys = new Map<number, string>();
const earlyIperf = new Map<number, IperfUpdate[]>();
/** Intervals kept per run (60 s at most per test, multiple streams summarized by iperf3). */
const MAX_INTERVALS = 600;

function handleIperf(u: IperfUpdate): void {
  const key = iperfKeys.get(u.runId);
  if (key === undefined) {
    const list = earlyIperf.get(u.runId) ?? [];
    if (list.length < 100 && earlyIperf.size < 8) earlyIperf.set(u.runId, [...list, u]);
    return;
  }
  iperfStore.update(key, (j) => {
    if (!j || j.runId !== u.runId) return j;
    const intervals = u.interval ? [...j.intervals, u.interval].slice(-MAX_INTERVALS) : j.intervals;
    return { ...j, intervals, summary: u.summary ?? j.summary, running: !u.done, error: u.done ? u.error : j.error };
  });
  if (u.done) iperfKeys.delete(u.runId);
}

let iperfAvail: Promise<IperfAvailability> | null = null;

/** Cached `iperf_available()` (pass `refresh` after installing iperf3). */
export function iperfAvailability(refresh = false): Promise<IperfAvailability> {
  if (!iperfAvail || refresh) {
    iperfAvail = backend.iperfAvailable().catch((e: unknown) => ({
      available: false,
      path: null,
      version: null,
      streaming: false,
      installHint: errorMessage(e),
    }));
  }
  return iperfAvail;
}

export async function startIperf(key: string, ip: string, options: IperfOptions): Promise<void> {
  const prev = iperfStore.get(key);
  if (prev?.running) throw "A test against this device is already running";
  const wire = iperfForWire(options);
  iperfStore.set(key, { ip, runId: null, options: wire, intervals: [], summary: null, running: true, error: null, startedAt: Date.now() });
  try {
    const id = await backend.startIperf(ip, wire);
    iperfKeys.set(id, key);
    iperfStore.update(key, (j) => (j ? { ...j, runId: id } : j));
    for (const u of earlyIperf.get(id) ?? []) handleIperf(u);
    earlyIperf.delete(id);
  } catch (e) {
    const msg = errorMessage(e);
    iperfStore.update(key, (j) => (j ? { ...j, running: false, error: msg } : j));
    throw msg;
  }
}

export async function stopIperf(key: string): Promise<void> {
  const j = iperfStore.get(key);
  if (!j || j.runId === null) return;
  const was = await backend.stopIperf(j.runId);
  if (!was) iperfStore.update(key, (x) => (x ? { ...x, running: false } : x));
}

// --- lifecycle ------------------------------------------------------------------------------------------------

let initialized: Promise<() => void> | null = null;

/** Subscribe to the utility events once (idempotent) and stop monitors left by a reload. */
export function initTools(): Promise<() => void> {
  if (initialized) return initialized;
  try {
    const raw = sessionStorage.getItem(MONITORS_KEY);
    const ids: unknown = raw ? JSON.parse(raw) : [];
    if (Array.isArray(ids)) for (const id of ids) if (typeof id === "number") void backend.stopLatencyMonitor(id).catch(() => undefined);
    sessionStorage.removeItem(MONITORS_KEY);
  } catch {
    /* ignore */
  }
  try {
    window.matchMedia("(prefers-reduced-motion: reduce)").addEventListener("change", (e) => {
      latencyStore.throttleMs = e.matches ? 1000 : 250;
    });
  } catch {
    /* ignore */
  }
  initialized = Promise.all([
    backend.onLatencyUpdate(latencyStore.handleUpdate),
    backend.onTraceUpdate(handleTrace),
    backend.onIperfUpdate(handleIperf),
  ]).then((uns) => () => uns.forEach((u) => u()));
  return initialized;
}

/** "Clear Results": stop running traces / tests and forget per-device utility data. */
export function clearTools(): void {
  for (const j of traceStore.values()) if (j.running && j.traceId !== null) void backend.stopTrace(j.traceId).catch(() => undefined);
  for (const j of iperfStore.values()) if (j.running && j.runId !== null) void backend.stopIperf(j.runId).catch(() => undefined);
  traceKeys.clear();
  iperfKeys.clear();
  traceStore.clear();
  iperfStore.clear();
  webStore.clear();
  latencyStore.clear();
}

// Dev builds expose the live-latency internals for performance checks.
if (import.meta.env.DEV && typeof window !== "undefined") {
  (window as unknown as { __sweeprTools?: unknown }).__sweeprTools = { latencyCtl, latencyStore };
}
