// Details-drawer sections for the network utilities: live latency, web identity / TLS,
// traceroute (MTR) and iPerf3 throughput. Each section subscribes to its own external store,
// so streamed updates re-render only that section.

import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Activity,
  Copy,
  ExternalLink,
  Gauge,
  Globe,
  LoaderCircle,
  Pin,
  Play,
  Route,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Square,
  TriangleAlert,
} from "lucide-react";
import type { Device, IperfAvailability, IperfOptions, TlsCertInfo } from "../types.ts";
import type { DeviceRow } from "../lib/store.ts";
import { formatLoss, formatMs, latencyTone, lossTone } from "../lib/latency.ts";
import { traceTable, type TraceHopRow } from "../lib/trace.ts";
import { DEFAULT_IPERF, formatBps, formatBytes, iperfProblem } from "../lib/iperf.ts";
import { classifyCert, webTargets } from "../lib/webid.ts";
import { usePersistentState } from "../hooks/usePersistentState.ts";
import {
  iperfAvailability,
  iperfStore,
  startIperf,
  startTrace,
  stopIperf,
  stopTrace,
  traceStore,
  useKeyed,
  useLatency,
  webStore,
} from "../tools.ts";
import { LatencyChart, ThroughputChart } from "./Charts.tsx";
import { TONE_TEXT } from "./DeviceTable.tsx";
import { useToasts } from "./Toasts.tsx";
import { Button, SectionTitle, TextInput, Toggle, cx } from "./ui.tsx";

function Stat({ label, children, tone }: { label: string; children: ReactNode; tone?: string }) {
  return (
    <div className="min-w-0 rounded-[6px] border border-line-soft bg-field px-1.5 py-1">
      <div className="text-[10px] text-muted">{label}</div>
      <div className={cx("truncate font-mono text-[12px] tabular", tone)}>{children}</div>
    </div>
  );
}

function KV({ k, children }: { k: string; children: ReactNode }) {
  return (
    <>
      <dt className="py-[2px] pr-2 text-right whitespace-nowrap text-muted">{k}</dt>
      <dd className="selectable min-w-0 py-[2px] break-words">{children ?? <span className="text-faint">—</span>}</dd>
    </>
  );
}

function clampInt(v: string, min: number, max: number, fallback: number): number {
  const n = Math.round(Number(v));
  if (v.trim() === "" || !Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function NumberField({
  label,
  value,
  min,
  max,
  onChange,
  width = 52,
  disabled,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  onChange: (n: number) => void;
  width?: number;
  disabled?: boolean;
}) {
  return (
    <label className="flex items-center gap-1 text-muted">
      {label}
      <TextInput
        type="number"
        min={min}
        max={max}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(clampInt(e.target.value, min, max, value))}
        style={{ width }}
        className="text-fg"
      />
    </label>
  );
}

// --- live latency -----------------------------------------------------------------------------------

export function LatencySection({
  ip,
  live,
  pinned,
  onTogglePin,
  onEnableLive,
}: {
  ip: string;
  live: boolean;
  pinned: boolean;
  onTogglePin: () => void;
  onEnableLive: () => void;
}) {
  const e = useLatency(ip);
  const s = e?.stats;
  return (
    <section id="drawer-latency" aria-label="Live latency">
      <SectionTitle
        right={
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              icon={Pin}
              pressed={pinned}
              onClick={onTogglePin}
              title={pinned ? "Unpin: monitor only while visible or selected" : "Pin: keep monitoring this device while live latency is on"}
            >
              {pinned ? "Pinned" : "Pin"}
            </Button>
            {!live && (
              <Button icon={Activity} onClick={onEnableLive}>
                Turn On
              </Button>
            )}
          </div>
        }
      >
        Live Latency
      </SectionTitle>
      {s && e ? (
        <>
          <LatencyChart history={e.history} />
          <div className="mt-1.5 grid grid-cols-4 gap-1">
            <Stat label="Last" tone={s.lastMs === null ? "text-danger" : undefined}>
              {s.lastMs === null ? "lost" : `${formatMs(s.lastMs)} ms`}
            </Stat>
            <Stat label="Avg" tone={TONE_TEXT[latencyTone(s)] === "text-muted" ? undefined : TONE_TEXT[latencyTone(s)]}>
              {formatMs(s.avgMs)} ms
            </Stat>
            <Stat label="Min / Max">
              {formatMs(s.minMs)}/{formatMs(s.maxMs)}
            </Stat>
            <Stat label="Jitter">{formatMs(s.jitterMs)} ms</Stat>
            <Stat label="Loss" tone={TONE_TEXT[lossTone(s.lossPct)] === "text-muted" ? undefined : TONE_TEXT[lossTone(s.lossPct)]}>
              {formatLoss(s.lossPct)}
            </Stat>
            <Stat label="Replies">
              {s.received}/{s.sent}
            </Stat>
            <Stat label="Probe">{s.method.toUpperCase()}</Stat>
            <Stat label="Updated">{new Date(s.updatedMs).toLocaleTimeString([], { hour12: false })}</Stat>
          </div>
          {s.method === "tcp" && <p className="mt-1 text-[11px] text-muted">No ICMP replies: timing TCP connects (SYN → SYN-ACK / RST) instead.</p>}
        </>
      ) : (
        <p className="text-muted">
          {live ? "Waiting for the first replies…" : "Live latency is off. Turn it on in the toolbar to ping visible, selected and pinned devices."}
        </p>
      )}
    </section>
  );
}

// --- web identity / TLS -----------------------------------------------------------------------------------

function CertBlock({ cert, onCopy }: { cert: TlsCertInfo; onCopy: (text: string, what: string) => void }) {
  const c = classifyCert(cert, Date.now());
  const tone = c?.status === "expired" ? "text-danger" : c?.status === "expiring" ? "text-warn" : "text-ok";
  const Icon = c?.status === "expired" ? ShieldX : c?.status === "expiring" || cert.selfSigned ? ShieldAlert : ShieldCheck;
  const fmt = (iso: string | null): string => (iso ? iso.replace("T", " ").replace(/:\d\dZ$/, " UTC").replace("Z", " UTC") : "—");
  return (
    <div className="mt-1.5 rounded-[8px] border border-line bg-field px-2.5 py-2">
      <div className="flex items-center gap-1.5">
        <Icon size={14} aria-hidden className={cx("shrink-0", tone)} />
        <span className="selectable min-w-0 flex-1 truncate font-medium" title={cert.subject ?? undefined}>
          {cert.subjectCn ?? cert.subject ?? "Certificate"}
        </span>
        <span className="shrink-0 rounded bg-chrome-2 px-1 font-mono text-[10px] text-muted">:{cert.port}</span>
      </div>
      <div className="mt-1 flex flex-wrap gap-1">
        {c && (
          <span className={cx("rounded-full border px-1.5 text-[10.5px]", c.status === "expired" ? "border-danger/40 bg-danger-soft text-danger" : c.status === "expiring" ? "border-warn/40 bg-warn-soft text-warn" : "border-ok/40 bg-ok-soft text-ok")}>
            {c.text}
          </span>
        )}
        {cert.selfSigned && <span className="rounded-full border border-warn/40 bg-warn-soft px-1.5 text-[10.5px] text-warn">self-signed</span>}
      </div>
      <dl className="mt-1 grid grid-cols-[78px_1fr] text-[11.5px]">
        <KV k="Subject">{cert.subject}</KV>
        <KV k="Issuer">{cert.issuer ?? cert.issuerCn}</KV>
        <KV k="SANs">
          {cert.sans.length === 0 ? null : (
            <span className="font-mono text-[11px]">
              {cert.sans.join(", ")}
              {cert.sanCount > cert.sans.length && <span className="text-muted"> +{cert.sanCount - cert.sans.length} more</span>}
            </span>
          )}
        </KV>
        <KV k="Valid from">{fmt(cert.notBefore)}</KV>
        <KV k="Valid until">
          <span className={c?.status === "ok" ? undefined : tone}>{fmt(cert.notAfter)}</span>
        </KV>
        <KV k="Key">{cert.keyType ? `${cert.keyType}${cert.keyBits ? ` ${cert.keyBits} bit` : ""}` : null}</KV>
        <KV k="Signature">{cert.signatureAlgorithm}</KV>
        <KV k="SHA-256">
          {cert.sha256 ? (
            <button
              type="button"
              onClick={() => onCopy(cert.sha256 ?? "", "SHA-256 fingerprint")}
              title="Copy fingerprint"
              className="group flex w-full items-start gap-1 text-left"
            >
              <span className="min-w-0 font-mono text-[10px] leading-[13px] break-all">{cert.sha256}</span>
              <Copy size={11} aria-hidden className="mt-px shrink-0 text-muted group-hover:text-fg" />
            </button>
          ) : null}
        </KV>
      </dl>
    </div>
  );
}

export function WebSection({
  row,
  onGrab,
  onOpenUrl,
  onCopy,
}: {
  row: DeviceRow;
  onGrab: () => void;
  onOpenUrl: (url: string) => void;
  onCopy: (text: string, what: string) => void;
}) {
  const d: Device = row.device;
  const job = useKeyed(webStore, row.key);
  const running = job?.status === "running";
  const targets = useMemo(() => webTargets(d, job?.result?.services), [d, job?.result?.services]);
  const failed = job?.result?.services.filter((s) => s.error !== null) ?? [];
  const hasData = d.webTitle || d.webIdentity || d.webServer || d.tlsCert || targets.length > 0;
  return (
    <section id="drawer-web" aria-label="Web and TLS">
      <SectionTitle
        right={
          <Button
            icon={running ? LoaderCircle : Globe}
            onClick={onGrab}
            disabled={running}
            className={cx(running && "[&>svg]:animate-spin motion-reduce:[&>svg]:animate-none")}
            title="Read page titles, Server headers and TLS certificates of the web ports"
          >
            Grab Web Identity
          </Button>
        }
      >
        Web &amp; TLS
      </SectionTitle>
      {job?.status === "error" && <p className="text-danger">{job.error}</p>}
      {(d.warnings?.length ?? 0) > 0 && (
        <ul className="mb-1.5 flex flex-col gap-1" aria-label="Warnings">
          {d.warnings.map((w) => (
            <li key={w} className="flex items-start gap-1.5 rounded-[6px] border border-warn/40 bg-warn-soft px-2 py-1 text-[11.5px]">
              <TriangleAlert size={12} aria-hidden className="mt-px shrink-0 text-warn" />
              <span className="selectable">{w}</span>
            </li>
          ))}
        </ul>
      )}
      {!hasData && job?.status !== "running" && (
        <p className="text-muted">{job?.status === "done" ? "No web interface answered on the probed ports." : "No web data yet. Scans fill it for devices with web ports open."}</p>
      )}
      {hasData && (
        <dl className="grid grid-cols-[96px_1fr] text-[12px]">
          <KV k="Identity">{d.webIdentity}</KV>
          <KV k="Title">{d.webTitle}</KV>
          <KV k="Server">{d.webServer}</KV>
        </dl>
      )}
      {targets.length > 0 && (
        <div className="mt-1 flex flex-col gap-1">
          {targets.map((t) => (
            <button
              key={`${t.scheme}:${t.port}`}
              type="button"
              onClick={() => onOpenUrl(t.url)}
              title={`Open ${t.url}`}
              className="flex min-w-0 items-center gap-1.5 rounded-[6px] border border-line bg-field px-2 py-1 text-left hover:bg-row-hover"
            >
              <span className={cx("shrink-0 rounded px-1 text-[10px] font-semibold uppercase", t.scheme === "https" ? "bg-ok-soft text-ok" : "bg-chrome-2 text-muted")}>
                {t.scheme}
              </span>
              <span className="shrink-0 font-mono text-[11px]">{t.port}</span>
              <span className="min-w-0 flex-1 truncate text-muted">{t.title ?? t.url}</span>
              <ExternalLink size={11} aria-hidden className="shrink-0 text-muted" />
            </button>
          ))}
        </div>
      )}
      {failed.length > 0 && (
        <p className="mt-1 text-[11px] text-muted">
          {failed.map((s) => `${s.scheme}:${s.port} ${s.error}`).join(" · ")}
        </p>
      )}
      {d.tlsCert && <CertBlock cert={d.tlsCert} onCopy={onCopy} />}
    </section>
  );
}

// --- traceroute -------------------------------------------------------------------------------------------

interface TracePrefs {
  maxHops: number;
  rounds: number;
}

const DEFAULT_TRACE_PREFS: TracePrefs = { maxHops: 30, rounds: 5 };

export function useTracePrefs() {
  return usePersistentState<TracePrefs>("sweepr.trace.v1", DEFAULT_TRACE_PREFS);
}

export function useIperfPrefs() {
  return usePersistentState<IperfOptions>("sweepr.iperf.v1", DEFAULT_IPERF);
}

/**
 * Row-menu "Trace Route" / "iPerf3 Test" pass an increasing token; each token starts one run
 * (also across remounts and React StrictMode's double effects).
 */
const consumed = { trace: 0, iperf: 0 };
function takeToken(kind: keyof typeof consumed, token: number | undefined): boolean {
  if (!token || token <= consumed[kind]) return false;
  consumed[kind] = token;
  return true;
}

function HopBar({ bar, tone }: { bar: TraceHopRow["bar"]; tone: string }) {
  if (!bar) return null;
  return (
    <svg width="100%" height={8} viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden className="block">
      <rect x={0} y={3.5} width={100} height={1} fill="var(--line-soft)" />
      <rect x={bar.from * 100} y={2.5} width={Math.max(1, (bar.to - bar.from) * 100)} height={3} fill="var(--line)" />
      <rect x={Math.max(0, bar.avg * 100 - 1.5)} y={0.5} width={3} height={7} rx={1} fill={tone} />
    </svg>
  );
}

const BAR_TONE = { ok: "var(--accent)", warn: "var(--warn)", bad: "var(--danger)", down: "var(--danger)", none: "var(--faint)" } as const;

export function TraceSection({ row, autoStart }: { row: DeviceRow; autoStart?: number }) {
  const toast = useToasts();
  const [prefs, setPrefs] = useTracePrefs();
  const job = useKeyed(traceStore, row.key);
  const u = job?.update ?? null;
  const table = useMemo(() => (u ? traceTable(u.hops) : null), [u]);
  const running = job?.running ?? false;
  const start = (): void => {
    startTrace(row.key, row.device.ip, prefs.maxHops, prefs.rounds).catch((e: unknown) => toast.push("error", `Trace to ${row.device.ip} failed to start`, String(e)));
  };
  // Row-menu "Trace Route" asks the section to start (token changes per request).
  useEffect(() => {
    if (takeToken("trace", autoStart)) start();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoStart]);
  return (
    <section id="drawer-trace" aria-label="Traceroute">
      <SectionTitle
        right={
          running ? (
            <Button variant="danger" icon={Square} onClick={() => void stopTrace(row.key)}>
              Stop
            </Button>
          ) : (
            <Button variant="primary" icon={Route} onClick={start}>
              Trace
            </Button>
          )
        }
      >
        Trace Route
      </SectionTitle>
      <div className="flex flex-wrap items-center gap-2 text-[11.5px]">
        <NumberField label="Max hops" value={prefs.maxHops} min={1} max={64} disabled={running} onChange={(maxHops) => setPrefs((p) => ({ ...p, maxHops }))} />
        <NumberField label="Rounds" value={prefs.rounds} min={1} max={100} disabled={running} onChange={(rounds) => setPrefs((p) => ({ ...p, rounds }))} />
        {u && (
          <span
            className="rounded bg-chrome-2 px-1.5 font-mono text-[10px] text-muted uppercase"
            title={u.method === "raw" ? "Raw ICMP probes (privileged)" : "System traceroute (unprivileged)"}
          >
            {u.method}
          </span>
        )}
      </div>
      <div className="mt-1.5 min-h-[18px] text-[11.5px]" aria-live="polite">
        {job && !u && running && <span className="text-muted">Starting trace to {job.ip}…</span>}
        {u && (
          <span className="flex flex-wrap items-center gap-x-2">
            <span className="text-muted">
              Round {Math.min(u.round, u.rounds)}/{u.rounds}
            </span>
            {running && <LoaderCircle size={11} aria-hidden className="animate-spin text-muted motion-reduce:animate-none" />}
            {u.reached ? <span className="text-ok">reached {u.target}</span> : u.done ? <span className="text-warn">{u.target} did not answer</span> : null}
          </span>
        )}
        {job?.error && <p className="text-danger">{job.error}</p>}
      </div>
      {table && table.rows.length > 0 && (
        <div className="overflow-hidden rounded-[6px] border border-line bg-field">
          <table className="w-full table-fixed border-collapse text-[11px]">
            <colgroup>
              <col style={{ width: 18 }} />
              <col />
              <col style={{ width: 42 }} />
              <col style={{ width: 32 }} />
              <col style={{ width: 32 }} />
              <col style={{ width: 32 }} />
              <col style={{ width: 32 }} />
              <col style={{ width: 30 }} />
            </colgroup>
            <thead className="bg-chrome text-muted">
              <tr>
                {["#", "Host", "Loss", "Last", "Avg", "Best", "Wrst", ""].map((h, i) => (
                  <th key={i} scope="col" className={cx("border-b border-line px-[3px] py-[3px] font-medium", i >= 2 && i <= 6 ? "text-right" : "text-left")}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {table.rows.map((r, i) =>
                r.kind === "gap" ? (
                  <tr key={`g${r.fromTtl}`} className={cx(i % 2 === 1 && "bg-row-alt")}>
                    <td className="px-1 py-[2px] text-muted tabular">{r.fromTtl}</td>
                    <td colSpan={7} className="px-1 py-[2px] text-faint">
                      hops {r.fromTtl}–{r.toTtl}: no reply ({r.sent} probes each)
                    </td>
                  </tr>
                ) : (
                  <tr key={r.ttl} className={cx(i % 2 === 1 && "bg-row-alt")}>
                    <td className="px-1 py-[2px] text-muted tabular">{r.ttl}</td>
                    <td className="truncate px-1 py-[2px]" title={[r.hostname, r.ip, ...r.otherIps].filter(Boolean).join("\n") || "no reply"}>
                      {r.ip === null ? (
                        <span className="text-faint">* * *</span>
                      ) : (
                        <span className="selectable">
                          {r.hostname ?? <span className="font-mono">{r.ip}</span>}
                          {r.otherIps.length > 0 && <span className="text-muted"> +{r.otherIps.length}</span>}
                        </span>
                      )}
                    </td>
                    <td
                      className={cx("px-[3px] py-[2px] text-right font-mono tabular", r.rateLimited ? "text-muted" : TONE_TEXT[r.tone])}
                      title={r.rateLimited ? "Later hops answer more reliably: probably ICMP rate limiting on this router, not real loss" : undefined}
                    >
                      {formatLoss(r.lossPct)}
                      {r.rateLimited && "*"}
                    </td>
                    {[r.lastMs, r.avgMs, r.bestMs, r.worstMs].map((v, j) => (
                      <td key={j} className="px-[3px] py-[2px] text-right font-mono tabular">
                        {formatMs(v)}
                      </td>
                    ))}
                    <td className="px-1 py-[2px]">
                      <HopBar bar={r.bar} tone={BAR_TONE[r.rateLimited ? "ok" : r.tone]} />
                    </td>
                  </tr>
                ),
              )}
            </tbody>
          </table>
          <p className="border-t border-line-soft px-1.5 py-[2px] text-[10px] text-muted">
            ms · bar: best–worst range, mark = average (scale {formatMs(table.scaleMs)} ms)
            {table.rows.some((r) => r.kind === "hop" && r.rateLimited) && " · * likely ICMP rate limiting"}
          </p>
        </div>
      )}
    </section>
  );
}

// --- iPerf3 -----------------------------------------------------------------------------------------------

export function IperfSection({ row, autoStart }: { row: DeviceRow; autoStart?: number }) {
  const toast = useToasts();
  const [prefs, setPrefs] = useIperfPrefs();
  const o: IperfOptions = { ...DEFAULT_IPERF, ...prefs };
  const setO = (patch: Partial<IperfOptions>): void => setPrefs((p) => ({ ...DEFAULT_IPERF, ...p, ...patch }));
  const [avail, setAvail] = useState<IperfAvailability | null>(null);
  const job = useKeyed(iperfStore, row.key);
  const running = job?.running ?? false;
  const problem = iperfProblem(o);

  useEffect(() => {
    let alive = true;
    void iperfAvailability().then((a) => alive && setAvail(a));
    return () => {
      alive = false;
    };
  }, []);

  const start = (): void => {
    startIperf(row.key, row.device.ip, o).catch((e: unknown) => toast.push("error", `iPerf3 test to ${row.device.ip} failed to start`, String(e)));
  };
  useEffect(() => {
    if (takeToken("iperf", autoStart)) start();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoStart]);

  const last = job?.intervals[job.intervals.length - 1];
  const s = job?.summary ?? null;
  const missing = avail !== null && !avail.available;
  return (
    <section id="drawer-iperf" aria-label="Throughput (iPerf3)">
      <SectionTitle
        right={
          running ? (
            <Button variant="danger" icon={Square} onClick={() => void stopIperf(row.key)}>
              Stop
            </Button>
          ) : (
            <Button variant="primary" icon={Play} onClick={start} disabled={missing || problem !== null} title={problem ?? `Run iperf3 -c ${row.device.ip}`}>
              Run Test
            </Button>
          )
        }
      >
        Throughput (iPerf3)
      </SectionTitle>
      {missing ? (
        <div className="rounded-[8px] border border-warn/40 bg-warn-soft px-2.5 py-2">
          <p>{avail.installHint ?? "iperf3 was not found."}</p>
          <div className="mt-1.5 flex items-center gap-1.5">
            <code className="selectable rounded bg-field px-1.5 py-0.5 font-mono">brew install iperf3</code>
            <Button
              variant="ghost"
              onClick={() => void iperfAvailability(true).then(setAvail)}
              title="Check again after installing"
            >
              Check Again
            </Button>
          </div>
        </div>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[11.5px]">
            <NumberField label="Port" value={o.port} min={1} max={65535} width={62} disabled={running} onChange={(port) => setO({ port })} />
            <NumberField label="Secs" value={o.durationSecs} min={1} max={60} disabled={running} onChange={(durationSecs) => setO({ durationSecs })} />
            <NumberField label="Streams" value={o.streams} min={1} max={16} width={44} disabled={running} onChange={(streams) => setO({ streams })} />
            <Toggle checked={o.reverse} onChange={(reverse) => setO({ reverse })} label="Reverse" title="Server sends, this Mac receives (-R)" disabled={running} />
            <Toggle checked={o.udp} onChange={(udp) => setO({ udp })} label="UDP" title="UDP test (-u); jitter and loss instead of retransmits" disabled={running} />
            <label className="flex items-center gap-1 text-muted">
              Bitrate
              <TextInput
                value={o.bitrate ?? ""}
                onChange={(e) => setO({ bitrate: e.target.value })}
                placeholder={o.udp ? "1M" : "max"}
                invalid={problem !== null && problem.startsWith("Bitrate")}
                title="Target bitrate (-b): 100M, 1G, 500K, 0 = unlimited"
                disabled={running}
                className="w-[64px] text-fg"
              />
            </label>
          </div>
          {problem && <p className="mt-1 text-[11px] text-danger">{problem}</p>}
          {avail && !avail.streaming && avail.available && (
            <p className="mt-1 text-[11px] text-muted">iperf3 {avail.version ?? ""} reports intervals only at the end (live updates need 3.17+).</p>
          )}
          {job && (
            <div className="mt-2" aria-live="polite">
              <div className="mb-1 flex items-baseline justify-between gap-2">
                <span className="text-muted">
                  {job.options.udp ? "UDP" : "TCP"} · {job.options.reverse ? "receive" : "send"} · {job.options.streams} stream{job.options.streams === 1 ? "" : "s"}
                </span>
                {running && last && <span className="font-mono text-[13px] font-semibold tabular">{formatBps(last.bitsPerSecond)}</span>}
                {running && !last && <span className="text-muted">Connecting…</span>}
              </div>
              {(job.intervals.length > 0 || running) && <ThroughputChart intervals={job.intervals} durationSecs={job.options.durationSecs} />}
              {job.error && !running && <p className="mt-1 text-danger">{job.error}</p>}
              {s && (
                <div className="mt-1.5 grid grid-cols-3 gap-1">
                  <Stat label="Sent">{formatBps(s.sentBps)}</Stat>
                  <Stat label="Received">{formatBps(s.receivedBps)}</Stat>
                  <Stat label="Data">{formatBytes(s.receivedBytes ?? s.sentBytes)}</Stat>
                  {s.protocol === "tcp" ? (
                    <Stat label="Retransmits" tone={(s.retransmits ?? 0) > 0 ? "text-warn" : undefined}>
                      {s.retransmits ?? "—"}
                    </Stat>
                  ) : (
                    <>
                      <Stat label="Jitter">{formatMs(s.jitterMs)} ms</Stat>
                      <Stat label="Lost" tone={TONE_TEXT[lossTone(s.lostPercent)] === "text-muted" ? undefined : TONE_TEXT[lossTone(s.lostPercent)]}>
                        <span title={`${s.lostPackets ?? 0} of ${s.packets ?? 0} datagrams`}>
                          {formatLoss(s.lostPercent)} ({(s.lostPackets ?? 0).toLocaleString()})
                        </span>
                      </Stat>
                    </>
                  )}
                  <Stat label="CPU local/remote">
                    {s.cpuLocalPct !== null ? Math.round(s.cpuLocalPct) : "—"}/{s.cpuRemotePct !== null ? Math.round(s.cpuRemotePct) : "—"}%
                  </Stat>
                </div>
              )}
              {s && <p className="mt-1 text-[10.5px] text-muted">{[s.remoteHost, s.version].filter(Boolean).join(" · ")}</p>}
            </div>
          )}
          {!job && (
            <p className="mt-1.5 flex items-center gap-1 text-[11px] text-muted">
              <Gauge size={12} aria-hidden /> Needs <code className="font-mono">iperf3 -s</code> running on {row.device.ip}.
            </p>
          )}
        </>
      )}
    </section>
  );
}
