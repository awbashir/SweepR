// Small SVG charts: latency sparklines (table cells and the drawer) and the iPerf3
// per-interval throughput bars. Pure SVG, no animation (sparklines only move when data arrives).

import { memo } from "react";
import type { IperfInterval } from "../types.ts";
import { formatMs, sparkline, type History } from "../lib/latency.ts";
import { throughputChart } from "../lib/iperf.ts";

/** Inline sparkline; lost probes are red ticks on the baseline. Colour comes from `currentColor`. */
export const Sparkline = memo(function Sparkline({
  history,
  width,
  height,
  strokeWidth = 1.2,
  maxMs,
  slots,
}: {
  history: History;
  width: number;
  height: number;
  strokeWidth?: number;
  maxMs?: number;
  /** Samples the width spans (default: the full 120-sample window). */
  slots?: number;
}) {
  const g = sparkline(history, width, height, { maxMs, slots });
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden className="shrink-0 overflow-visible">
      <path d={g.path} fill="none" stroke="currentColor" strokeWidth={strokeWidth} strokeLinejoin="round" strokeLinecap="round" />
      {g.lost.length > 0 && (
        <path
          d={g.lost.map((x) => `M${x} ${height}v-${Math.max(3, height * 0.3)}`).join("")}
          stroke="var(--danger)"
          strokeWidth={1.2}
          strokeLinecap="round"
        />
      )}
    </svg>
  );
});

/** Drawer-sized latency chart with a scale and a mid gridline. */
export function LatencyChart({ history, width = 334, height = 64 }: { history: History; width?: number; height?: number }) {
  const g = sparkline(history, width, height, { pad: 3, slots: Math.max(60, Math.min(120, history.length)) });
  return (
    <div className="relative" style={{ width, height }}>
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`Latency over the last ${history.length} probes`}>
        <line x1={0} x2={width} y1={0.5} y2={0.5} stroke="var(--line)" strokeDasharray="2 3" />
        <line x1={0} x2={width} y1={height / 2} y2={height / 2} stroke="var(--line-soft)" strokeDasharray="2 3" />
        <line x1={0} x2={width} y1={height - 0.5} y2={height - 0.5} stroke="var(--line)" />
        <path d={g.path} fill="none" stroke="var(--accent)" strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
        {g.lost.length > 0 && (
          <path d={g.lost.map((x) => `M${x} ${height - 1}v-10`).join("")} stroke="var(--danger)" strokeWidth={1.5} strokeLinecap="round" />
        )}
      </svg>
      <span className="pointer-events-none absolute top-0.5 left-1 rounded bg-panel/80 px-0.5 text-[9.5px] text-muted tabular">{formatMs(g.max)} ms</span>
      <span className="pointer-events-none absolute top-[calc(50%-7px)] left-1 rounded bg-panel/80 px-0.5 text-[9.5px] text-faint tabular">
        {formatMs(g.max / 2)}
      </span>
    </div>
  );
}

/** Per-interval Mbit/s bars with the average as a dashed line. */
export function ThroughputChart({
  intervals,
  durationSecs,
  width = 334,
  height = 96,
}: {
  intervals: readonly IperfInterval[];
  durationSecs: number;
  width?: number;
  height?: number;
}) {
  const axis = 34;
  const plotW = width - axis;
  const plotH = height - 14;
  const c = throughputChart(intervals, plotW, plotH, durationSecs);
  const fmt = (v: number): string => (v >= 1000 ? `${(v / 1000).toFixed(v % 1000 === 0 ? 0 : 1)}G` : `${v % 1 === 0 ? v : v.toFixed(1)}M`);
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`Throughput per interval, ${intervals.length} intervals`} className="block">
      {c.ticks.map((t) => {
        const y = Math.round(plotH - (t / c.maxMbps) * plotH) + 0.5;
        return (
          <g key={t}>
            <line x1={axis} x2={width} y1={y} y2={y} stroke={t === 0 ? "var(--line)" : "var(--line-soft)"} strokeDasharray={t === 0 ? undefined : "2 3"} />
            <text x={axis - 4} y={y + 3} textAnchor="end" fontSize={9.5} fill="var(--muted)">
              {fmt(t)}
            </text>
          </g>
        );
      })}
      <g transform={`translate(${axis} 0)`}>
        {c.bars.map((b, i) => (
          <rect key={i} x={b.x} y={b.y} width={b.w} height={b.h} rx={1} fill={b.omitted ? "var(--faint)" : "var(--accent)"} opacity={b.omitted ? 0.5 : 0.85}>
            <title>{b.label}</title>
          </rect>
        ))}
        {c.bars.map((b, i) =>
          b.lostPercent !== null && b.lostPercent > 0 ? <rect key={`l${i}`} x={b.x} y={plotH - 3} width={b.w} height={3} fill="var(--danger)" /> : null,
        )}
        {c.avgY !== null && <line x1={0} x2={plotW} y1={c.avgY} y2={c.avgY} stroke="var(--fg)" strokeOpacity={0.55} strokeDasharray="4 3" />}
      </g>
      <text x={axis} y={height - 2} fontSize={9.5} fill="var(--muted)">
        0 s
      </text>
      <text x={width} y={height - 2} fontSize={9.5} fill="var(--muted)" textAnchor="end">
        {c.spanSecs} s
      </text>
    </svg>
  );
}
