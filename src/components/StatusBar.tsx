// Bottom status bar (interface, VLAN, progress, device counter, last log) and the log panel.

import { useEffect, useRef } from "react";
import { ChevronDown, ChevronRight, CircleAlert, Info, Layers, ScrollText, Trash, TriangleAlert } from "lucide-react";
import type { InterfaceInfo, LogLevel, ScanProgress } from "../types.ts";
import type { JobKind, LogEntry } from "../lib/store.ts";
import { Select, cx } from "./ui.tsx";

const PHASE_LABEL: Record<ScanProgress["phase"], string> = {
  preparing: "Preparing",
  discovering: "Discovering",
  enriching: "Resolving names & ports",
  listening: "Listening",
  done: "Done",
};

const LEVEL_ICON = { info: Info, warn: TriangleAlert, error: CircleAlert } as const;
const LEVEL_TONE: Record<LogLevel, string> = { info: "text-muted", warn: "text-warn", error: "text-danger" };

interface StatusBarProps {
  interfaces: InterfaceInfo[];
  iface: string;
  onIface: (name: string) => void;
  vlanLabel: string;
  running: boolean;
  starting: boolean;
  jobKind: JobKind | null;
  progress: ScanProgress | null;
  devicesSeen: number;
  shown: number;
  lastLog: LogEntry | undefined;
  warnCount: number;
  logOpen: boolean;
  onToggleLog: () => void;
}

export function StatusBar(p: StatusBarProps) {
  const prog = p.progress;
  const pct = prog && prog.probesTotal > 0 ? Math.min(100, (prog.probesSent / prog.probesTotal) * 100) : null;
  const indeterminate = p.running && (pct === null || prog?.phase === "listening" || prog?.phase === "enriching");
  const LastIcon = p.lastLog ? LEVEL_ICON[p.lastLog.level] : null;

  return (
    <footer className="flex h-[26px] shrink-0 items-center gap-3 border-t border-line bg-chrome px-2 text-[11.5px]">
      <Select
        value={p.iface}
        onChange={(e) => p.onIface(e.target.value)}
        aria-label="Interface (quick select)"
        disabled={p.running}
        className="h-[20px] w-[110px] border-transparent bg-transparent text-[11.5px] hover:border-line"
      >
        <option value="">Default</option>
        {p.interfaces.map((i) => (
          <option key={i.name} value={i.name}>
            {i.name}
            {i.kind === "vlan" && i.vlanId !== null ? ` (VLAN ${i.vlanId})` : ""}
          </option>
        ))}
      </Select>
      <span className="flex items-center gap-1 whitespace-nowrap text-muted" title="Active VLAN selection">
        <Layers size={12} aria-hidden />
        {p.vlanLabel}
      </span>
      <div className="flex w-[300px] shrink-0 items-center gap-2" aria-live="off">
        <span className="w-[120px] truncate text-muted">
          {p.starting
            ? "Starting…"
            : p.running
              ? `${p.jobKind === "vlan_discovery" ? "VLAN discovery · " : ""}${prog ? PHASE_LABEL[prog.phase] : "Starting"}`
              : prog?.phase === "done"
                ? "Idle · last scan done"
                : "Idle"}
        </span>
        <div
          role="progressbar"
          aria-label="Scan progress"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={pct === null ? undefined : Math.round(pct)}
          className="relative h-[6px] flex-1 overflow-hidden rounded-full bg-line"
        >
          {indeterminate && pct === null ? (
            <div className="progress-indeterminate absolute inset-y-0 w-2/5 rounded-full bg-accent" />
          ) : (
            <div
              className={cx("absolute inset-y-0 left-0 rounded-full transition-[width] duration-200", p.running ? "bg-accent" : "bg-faint")}
              style={{ width: `${pct ?? 0}%` }}
            />
          )}
        </div>
        <span className="w-[86px] text-right whitespace-nowrap text-muted tabular">
          {prog && prog.probesTotal > 0 ? `${prog.probesSent.toLocaleString()}/${prog.probesTotal.toLocaleString()}` : ""}
        </span>
      </div>
      <span className="whitespace-nowrap tabular" aria-live="polite">
        Devices seen: <strong className="font-semibold">{p.devicesSeen.toLocaleString()}</strong>
        {p.shown !== p.devicesSeen && <span className="text-muted"> · {p.shown.toLocaleString()} shown</span>}
      </span>
      <div className="flex min-w-0 flex-1 items-center gap-1.5">
        {p.lastLog && LastIcon && (
          <>
            <LastIcon size={12} className={cx("shrink-0", LEVEL_TONE[p.lastLog.level])} aria-hidden />
            <span className={cx("truncate", p.lastLog.level === "info" ? "text-muted" : LEVEL_TONE[p.lastLog.level])} title={p.lastLog.message}>
              {p.lastLog.message}
            </span>
          </>
        )}
      </div>
      <button
        type="button"
        onClick={p.onToggleLog}
        aria-expanded={p.logOpen}
        aria-controls="log-panel"
        className="flex h-[20px] items-center gap-1 rounded px-1.5 text-muted hover:bg-chrome-2"
        title="Show log (⌘L)"
      >
        <ScrollText size={12} aria-hidden />
        Log
        {p.warnCount > 0 && <span className="rounded-full bg-warn-soft px-1.5 text-[10px] text-warn tabular">{p.warnCount}</span>}
        {p.logOpen ? <ChevronDown size={11} aria-hidden /> : <ChevronRight size={11} aria-hidden />}
      </button>
    </footer>
  );
}

export function LogPanel({ logs, onClear }: { logs: LogEntry[]; onClear: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const stick = useRef(true);
  useEffect(() => {
    const el = ref.current;
    if (el && stick.current) el.scrollTop = el.scrollHeight;
  }, [logs]);
  return (
    <section id="log-panel" aria-label="Log" className="flex h-[150px] shrink-0 flex-col border-t border-line bg-panel">
      <div className="flex h-[22px] items-center justify-between border-b border-line-soft px-2 text-[11px] text-muted">
        <span>Log · {logs.length} entries</span>
        <button type="button" onClick={onClear} className="flex items-center gap-1 rounded px-1 hover:bg-chrome-2">
          <Trash size={11} aria-hidden /> Clear
        </button>
      </div>
      <div
        ref={ref}
        role="log"
        tabIndex={0}
        onScroll={(e) => {
          const el = e.currentTarget;
          stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 8;
        }}
        className="selectable min-h-0 flex-1 overflow-y-auto px-2 py-1 font-mono text-[11px]"
      >
        {logs.length === 0 && <p className="font-sans text-muted">No messages yet.</p>}
        {logs.map((l) => (
          <div key={l.id} className="flex gap-2 leading-[17px]">
            <span className="shrink-0 text-faint">{new Date(l.ts).toLocaleTimeString()}</span>
            <span className={cx("w-[38px] shrink-0 uppercase", LEVEL_TONE[l.level])}>{l.level}</span>
            <span className={cx("min-w-0 break-words", l.level !== "info" && LEVEL_TONE[l.level])}>{l.message}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
