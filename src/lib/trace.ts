// Traceroute / MTR table: hop rows with latency bars, runs of silent hops collapsed, and loss
// that later hops do not show flagged as probable ICMP rate limiting.

import type { TraceHop } from "../types.ts";
import { lossTone, niceCeil, type Tone } from "./latency.ts";

export interface TraceHopRow {
  kind: "hop";
  ttl: number;
  ip: string | null;
  hostname: string | null;
  otherIps: string[];
  sent: number;
  received: number;
  lossPct: number;
  lastMs: number | null;
  avgMs: number | null;
  bestMs: number | null;
  worstMs: number | null;
  tone: Tone;
  /**
   * Loss here but a later hop answers more reliably: the router only rate-limits ICMP
   * replies to probes addressed to it; traffic through it is not lost.
   */
  rateLimited: boolean;
  /** Bar geometry as fractions of the scale: best..worst range and the average. */
  bar: { from: number; to: number; avg: number } | null;
}

export interface TraceGapRow {
  kind: "gap";
  fromTtl: number;
  toTtl: number;
  sent: number;
}

export type TraceRow = TraceHopRow | TraceGapRow;

export interface TraceTable {
  rows: TraceRow[];
  /** Bar scale in ms (nice-rounded worst time). */
  scaleMs: number;
  /** Hops that answered at least once. */
  answered: number;
}

const silent = (h: TraceHop): boolean => h.received === 0 && h.ip === null;

/** Build the hop table; runs of at least `collapseMin` silent hops become one gap row. */
export function traceTable(hops: readonly TraceHop[], collapseMin = 2): TraceTable {
  const sorted = [...hops].sort((a, b) => a.ttl - b.ttl);
  let worst = 0;
  for (const h of sorted) {
    const w = h.worstMs ?? h.avgMs ?? h.lastMs;
    if (w !== null && w > worst) worst = w;
  }
  const scaleMs = niceCeil(Math.max(worst, 1));
  // Lowest loss among the hops after each index (for the rate-limit hint).
  const minLossAfter = new Array<number>(sorted.length).fill(Infinity);
  for (let i = sorted.length - 2; i >= 0; i--) {
    const next = sorted[i + 1];
    const nextLoss = next && next.received > 0 ? next.lossPct : Infinity;
    minLossAfter[i] = Math.min(minLossAfter[i + 1] ?? Infinity, nextLoss);
  }
  const rows: TraceRow[] = [];
  let answered = 0;
  for (let i = 0; i < sorted.length; i++) {
    const h = sorted[i]!;
    if (silent(h)) {
      let j = i;
      while (j + 1 < sorted.length && silent(sorted[j + 1]!)) j++;
      if (j - i + 1 >= collapseMin) {
        rows.push({ kind: "gap", fromTtl: h.ttl, toTtl: sorted[j]!.ttl, sent: Math.max(...sorted.slice(i, j + 1).map((x) => x.sent)) });
        i = j;
        continue;
      }
    }
    if (h.received > 0) answered++;
    const best = h.bestMs ?? h.avgMs;
    const worstMs = h.worstMs ?? h.avgMs;
    rows.push({
      kind: "hop",
      ttl: h.ttl,
      ip: h.ip,
      hostname: h.hostname,
      otherIps: h.otherIps,
      sent: h.sent,
      received: h.received,
      lossPct: h.lossPct,
      lastMs: h.lastMs,
      avgMs: h.avgMs,
      bestMs: h.bestMs,
      worstMs: h.worstMs,
      tone: h.sent === 0 ? "none" : lossTone(h.lossPct),
      rateLimited: h.lossPct > 0 && h.received > 0 && (minLossAfter[i] ?? Infinity) < h.lossPct,
      bar:
        h.avgMs !== null && best !== null && worstMs !== null
          ? { from: best / scaleMs, to: Math.min(1, worstMs / scaleMs), avg: Math.min(1, h.avgMs / scaleMs) }
          : null,
    });
  }
  return { rows, scaleMs, answered };
}
