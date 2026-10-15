// iPerf3 helpers: option validation (mirrors `IperfOptions::validate`), unit formatting and
// the per-interval throughput chart geometry.

import type { IperfInterval, IperfOptions } from "../types.ts";
import { niceCeil } from "./latency.ts";

export const DEFAULT_IPERF: IperfOptions = {
  port: 5201,
  durationSecs: 10,
  reverse: false,
  streams: 1,
  udp: false,
  bitrate: null,
};

/** Why the backend would reject these options, or `null`. */
export function iperfProblem(o: IperfOptions): string | null {
  if (!Number.isInteger(o.port) || o.port < 1 || o.port > 65535) return "Port must be 1-65535";
  if (!Number.isInteger(o.durationSecs) || o.durationSecs < 1 || o.durationSecs > 60) return "Duration must be 1-60 s";
  if (!Number.isInteger(o.streams) || o.streams < 1 || o.streams > 16) return "Streams must be 1-16";
  const b = o.bitrate?.trim() ?? "";
  if (b !== "" && !/^(?=[\d.]{1,12}[KMGTkmgt]?$)\d+(\.\d+)?[KMGTkmgt]?$/.test(b)) {
    return "Bitrate: a number with an optional K/M/G/T suffix, e.g. 100M";
  }
  return null;
}

/** Options as sent to `start_iperf` (blank bitrate → null). */
export function iperfForWire(o: IperfOptions): IperfOptions {
  const b = o.bitrate?.trim() ?? "";
  return { ...o, bitrate: b === "" ? null : b };
}

export function formatBps(bps: number | null | undefined): string {
  if (bps === null || bps === undefined || !Number.isFinite(bps)) return "—";
  const units: Array<[number, string]> = [
    [1e9, "Gbit/s"],
    [1e6, "Mbit/s"],
    [1e3, "kbit/s"],
  ];
  for (const [div, unit] of units) {
    if (bps >= div) {
      const v = bps / div;
      return `${v >= 100 ? Math.round(v) : v.toFixed(v >= 10 ? 1 : 2)} ${unit}`;
    }
  }
  return `${Math.round(bps)} bit/s`;
}

export function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return "—";
  const units: Array<[number, string]> = [
    [1e9, "GB"],
    [1e6, "MB"],
    [1e3, "kB"],
  ];
  for (const [div, unit] of units) if (n >= div) return `${(n / div).toFixed(n / div >= 100 ? 0 : 2)} ${unit}`;
  return `${n} B`;
}

export interface ChartBar {
  x: number;
  w: number;
  y: number;
  h: number;
  mbps: number;
  omitted: boolean;
  /** UDP packets lost in this interval (%), for a loss marker. */
  lostPercent: number | null;
  label: string;
}

export interface ThroughputChart {
  bars: ChartBar[];
  /** Top of the y axis (Mbit/s). */
  maxMbps: number;
  /** y axis ticks (Mbit/s), bottom to top, including 0. */
  ticks: number[];
  /** Mean over non-omitted intervals (Mbit/s), `null` without data. */
  avgMbps: number | null;
  /** y of the average line. */
  avgY: number | null;
  /** Seconds the x axis spans. */
  spanSecs: number;
}

/**
 * Bars for per-interval throughput, x by time over max(duration, last interval end) so the
 * chart fills in from the left while the test runs.
 */
export function throughputChart(intervals: readonly IperfInterval[], width: number, height: number, durationSecs: number): ThroughputChart {
  let lastEnd = 0;
  let max = 0;
  let sum = 0;
  let n = 0;
  for (const iv of intervals) {
    if (iv.end > lastEnd) lastEnd = iv.end;
    const mbps = iv.bitsPerSecond / 1e6;
    if (mbps > max) max = mbps;
    if (!iv.omitted) {
      sum += mbps;
      n++;
    }
  }
  const spanSecs = Math.max(durationSecs, lastEnd, 1);
  const maxMbps = niceCeil(Math.max(max, 1));
  const sx = width / spanSecs;
  const bars: ChartBar[] = intervals.map((iv) => {
    const mbps = iv.bitsPerSecond / 1e6;
    const h = Math.max(mbps > 0 ? 1 : 0, (mbps / maxMbps) * height);
    const x = iv.start * sx;
    const w = Math.max(1, (iv.end - iv.start) * sx - 1);
    return {
      x: Math.round(x * 10) / 10,
      w: Math.round(w * 10) / 10,
      y: Math.round((height - h) * 10) / 10,
      h: Math.round(h * 10) / 10,
      mbps,
      omitted: iv.omitted,
      lostPercent: iv.lostPercent,
      label: `${iv.start.toFixed(0)}-${iv.end.toFixed(0)} s: ${formatBps(iv.bitsPerSecond)}${iv.omitted ? " (omitted)" : ""}`,
    };
  });
  const avgMbps = n > 0 ? sum / n : null;
  return {
    bars,
    maxMbps,
    ticks: [0, maxMbps / 2, maxMbps],
    avgMbps,
    avgY: avgMbps === null ? null : Math.round((height - (avgMbps / maxMbps) * height) * 10) / 10,
    spanSecs,
  };
}
