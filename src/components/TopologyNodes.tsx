// React Flow node and edge renderers for the topology map. Colors match the table's role pills
// (CSS `--role-*` tokens, light and dark); every color cue also has a text / shape cue.

import { createContext, memo, useContext } from "react";
import {
  BaseEdge,
  EdgeLabelRenderer,
  Handle,
  Position,
  getBezierPath,
  getSmoothStepPath,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import { AlertTriangle, ChevronDown, ChevronRight, CircleHelp, Globe, Laptop, ShieldAlert, Users, Wifi, Zap } from "lucide-react";
import { formatLoss, formatMs, latencyTone, type Tone } from "../lib/latency.ts";
import { useLatency } from "../tools.ts";
import type { DeviceRole } from "../types.ts";
import { ROLE_LABEL } from "../types.ts";
import type { TopoEdge, TopoMember, TopoNode } from "../lib/topology.ts";
import { CARD_GAP, CARD_H, CARD_W, CLUSTER_PAD, STACK_BUS, clusterCols, type LayoutDir } from "../lib/topologyLayout.ts";
import { KIND_ICON, ROLE_ICON, cx } from "./ui.tsx";
import { deviceKindLabel, formatWatts, poeSummary, poeTone } from "../lib/services.ts";

export interface TopoNodeData extends Record<string, unknown> {
  topo: TopoNode;
  dir: LayoutDir;
  selected: boolean;
  /** Search matches shown by this node (0 = none). */
  matches: number;
  /** A search is active and this node does not match: fade it. */
  dimmed: boolean;
  selectedKey: string | null;
  matchKeys: ReadonlySet<string> | null;
}

export interface TopoEdgeData extends Record<string, unknown> {
  topo: TopoEdge;
  dir: LayoutDir;
  highlight: boolean;
  dimmed: boolean;
  /** Target is a stacked leaf: draw along the column's bus. Its width / height. */
  bus: { w: number; h: number } | null;
}

export type TopoRfNode = Node<TopoNodeData>;
export type TopoRfEdge = Edge<TopoEdgeData>;

export interface TopoActions {
  openDevice: (key: string) => void;
  toggleCluster: (id: string) => void;
  showMore: (id: string) => void;
  deviceMenu: (key: string, x: number, y: number) => void;
}

export const TopoActionsContext = createContext<TopoActions | null>(null);

/** Live overlays: latency accents (while live latency is on) and device warnings by key. */
export interface TopoLive {
  live: boolean;
  warnings: ReadonlyMap<string, readonly string[]>;
}

export const TopoLiveContext = createContext<TopoLive>({ live: false, warnings: new Map() });

const TONE_VAR: Record<Tone, string> = {
  ok: "var(--ok)",
  warn: "var(--warn)",
  bad: "var(--danger)",
  down: "var(--danger)",
  none: "var(--faint)",
};

/** Small coloured dot + average ms; the text says the same as the colour. */
function LatencyAccent({ ip }: { ip: string }) {
  const e = useLatency(ip);
  if (!e) return null;
  const s = e.stats;
  const tone = latencyTone(s);
  return (
    <span
      className="flex shrink-0 items-center gap-0.5 font-mono text-[9.5px] text-muted"
      title={`avg ${formatMs(s.avgMs)} ms · loss ${formatLoss(s.lossPct)} · jitter ${formatMs(s.jitterMs)} ms`}
    >
      <span className="inline-block size-[7px] rounded-full" style={{ background: TONE_VAR[tone] }} aria-hidden />
      {tone === "down" ? "down" : `${formatMs(s.avgMs)} ms`}
      {s.lossPct > 0 && tone !== "down" && <span style={{ color: TONE_VAR[tone] }}>{formatLoss(s.lossPct)}</span>}
    </span>
  );
}

function useActions(): TopoActions {
  const a = useContext(TopoActionsContext);
  if (!a) throw new Error("TopoActionsContext missing");
  return a;
}

export const ROLE_VAR: Record<DeviceRole, string> = {
  switch: "var(--role-switch)",
  firewall: "var(--role-firewall)",
  access_point: "var(--role-ap)",
  router: "var(--role-router)",
  host: "var(--role-host)",
};

function Handles({ dir }: { dir: LayoutDir }) {
  return (
    <>
      <Handle type="target" position={dir === "TB" ? Position.Top : Position.Left} isConnectable={false} className="topo-handle" />
      <Handle type="source" position={dir === "TB" ? Position.Bottom : Position.Right} isConnectable={false} className="topo-handle" />
    </>
  );
}

function VlanBadges({ vlans, max = 4 }: { vlans: readonly number[]; max?: number }) {
  if (vlans.length === 0) return null;
  const shown = vlans.slice(0, max);
  return (
    <span className="flex shrink-0 items-center gap-0.5" aria-label={`VLANs ${vlans.join(", ")}`}>
      {shown.map((v) => (
        <span key={v} className="rounded-[3px] border border-line bg-chrome-2 px-1 font-mono text-[9.5px] leading-[13px] text-muted">
          {v}
        </span>
      ))}
      {vlans.length > max && <span className="text-[9.5px] text-muted">+{vlans.length - max}</span>}
    </span>
  );
}

function StatusMark({ node }: { node: TopoNode }) {
  if (node.status === "warn") {
    return (
      <span className="shrink-0 text-warn" title={node.note ?? "Warning"}>
        <AlertTriangle size={12} aria-hidden />
        <span className="sr-only">warning: {node.note}</span>
      </span>
    );
  }
  if (node.status === "unknown") {
    return (
      <span className="shrink-0 text-faint" title={node.note ?? "Unverified"}>
        <CircleHelp size={12} aria-hidden />
        <span className="sr-only">unverified: {node.note}</span>
      </span>
    );
  }
  return null;
}

function frameClass(d: TopoNodeData): string {
  return cx(
    "topo-card relative h-full w-full overflow-hidden rounded-[8px] border bg-field text-left shadow-[0_1px_2px_rgb(0_0_0/0.08)]",
    d.topo.status === "unknown" ? "border-dashed border-faint" : "border-line",
    d.selected && "topo-selected",
    d.matches > 0 && "topo-match",
    d.dimmed && "topo-dimmed",
  );
}

/** "⚡ 5.2 W" for an endpoint (coloured by load; the number says the same). */
function PoeBadge({ n }: { n: TopoNode }) {
  const p = n.poe;
  if (!p || p.watts === null) return null;
  const tone = poeTone(p);
  return (
    <span className="flex shrink-0 items-center gap-0.5 font-mono text-[9.5px]" style={{ color: TONE_VAR[tone] }} title={`PoE: ${poeSummary(p)}`}>
      <Zap size={9} aria-hidden />
      {formatWatts(p.watts)} W
    </span>
  );
}

/** Switch PoE: "PoE 412/740 W" (budget) or "PoE 123 W" (drawn on known ports). */
function PoeUsageBadge({ n }: { n: TopoNode }) {
  const u = n.poeUsage;
  if (!u || u.consumed === null) return null;
  const text = u.nominal !== null && u.pct !== null ? `${Math.round(u.pct)} %` : `${formatWatts(u.consumed)} W`;
  const title =
    u.nominal !== null
      ? `PoE budget: ${formatWatts(u.consumed)} of ${formatWatts(u.nominal)} W used${u.pct !== null ? ` (${Math.round(u.pct)} %)` : ""}, ${u.ports} port(s) delivering`
      : `PoE drawn on ${u.ports} known port(s) (no SNMP budget)`;
  return (
    <span
      className="flex shrink-0 items-center gap-0.5 rounded-[3px] border border-line px-1 font-mono text-[9.5px] leading-[13px]"
      style={{ color: u.nominal !== null ? TONE_VAR[u.tone] : "var(--muted)" }}
      title={title}
    >
      <Zap size={9} aria-hidden />
      {text}
    </span>
  );
}

/** Switches, firewalls, routers, APs and individual endpoints. */
export const DeviceNode = memo(function DeviceNode({ data }: NodeProps<TopoRfNode>) {
  const n = data.topo;
  const role = n.role ?? "host";
  // Endpoints with a known kind (phone, camera, printer, ...) show it instead of the generic host icon.
  const KindIcon = n.deviceKind ? KIND_ICON[n.deviceKind] : undefined;
  const Icon = role === "host" && KindIcon ? KindIcon : ROLE_ICON[role];
  const infra = n.kind === "infra";
  const live = useContext(TopoLiveContext);
  const warnings = n.deviceKey ? live.warnings.get(n.deviceKey) : undefined;
  return (
    <div className={frameClass(data)} style={{ borderLeft: `4px solid ${ROLE_VAR[role]}` }}>
      <Handles dir={data.dir} />
      <div className="flex h-full flex-col justify-center gap-[1px] py-1 pr-2 pl-2">
        <div className="flex min-w-0 items-center gap-1.5">
          <Icon size={infra ? 15 : 13} strokeWidth={1.9} aria-hidden className="shrink-0" style={{ color: ROLE_VAR[role] }} />
          <span className={cx("min-w-0 flex-1 truncate font-semibold", infra ? "text-[12.5px]" : "text-[12px]")}>{n.label}</span>
          {n.deviceKind && <span className="sr-only">{deviceKindLabel(n.deviceKind)}</span>}
          {infra && <span className="topo-detail shrink-0 text-[9.5px] tracking-wide text-muted uppercase">{ROLE_LABEL[role]}</span>}
          {warnings && warnings.length > 0 && (
            <span className="shrink-0 text-warn" title={warnings.join("\n")}>
              <ShieldAlert size={12} aria-hidden />
              <span className="sr-only">{warnings.length} warning(s): {warnings.join("; ")}</span>
            </span>
          )}
          <StatusMark node={n} />
        </div>
        <div className="topo-detail flex min-w-0 items-center gap-1 font-mono text-[10.5px] text-muted">
          <span className="truncate">{n.ip ?? n.mac ?? ""}</span>
          {n.port && <span className="shrink-0 truncate">· {n.port}</span>}
          {(live.live && n.ip) || n.poe ? <span className="flex-1" /> : null}
          {!live.live && <PoeBadge n={n} />}
          {live.live && n.ip && <LatencyAccent ip={n.ip} />}
        </div>
        {(n.detail || n.vlans.length > 0 || n.poeUsage || n.deviceKind) && (
          <div className="topo-detail flex min-w-0 items-center gap-1.5 text-[10.5px] text-muted">
            {(n.deviceKind || n.detail) && (
              <span className="min-w-0 truncate" title={n.deviceKind ? `${deviceKindLabel(n.deviceKind)}${n.detail ? ` · ${n.detail}` : ""}` : undefined}>
                {n.deviceKind && !infra ? deviceKindLabel(n.deviceKind) + (n.detail ? ` · ${n.detail}` : "") : n.detail}
              </span>
            )}
            <span className="flex-1" />
            <PoeUsageBadge n={n} />
            {live.live && <PoeBadge n={n} />}
            <VlanBadges vlans={n.vlans} max={infra ? (n.poeUsage ? 2 : 4) : 2} />
          </div>
        )}
      </div>
      {data.matches > 0 && <span className="sr-only">matches the search</span>}
    </div>
  );
});

/** Synthetic "Network" root and "This computer". */
export const SpecialNode = memo(function SpecialNode({ data }: NodeProps<TopoRfNode>) {
  const n = data.topo;
  const Icon = n.kind === "scanner" ? Laptop : Globe;
  return (
    <div className={cx(frameClass(data), "rounded-full")} style={{ borderLeft: undefined }}>
      <Handles dir={data.dir} />
      <div className="flex h-full items-center gap-2 px-4">
        <Icon size={16} strokeWidth={1.8} aria-hidden className={n.kind === "scanner" ? "text-accent" : "text-muted"} />
        <div className="min-w-0">
          <div className="truncate text-[12px] font-semibold">{n.label}</div>
          {n.detail && <div className="topo-detail truncate text-[10.5px] text-muted">{n.detail}</div>}
        </div>
      </div>
    </div>
  );
});

function MemberCard({ m, selected, match }: { m: TopoMember; selected: boolean; match: boolean }) {
  const a = useActions();
  return (
    <button
      type="button"
      className={cx(
        "nodrag nopan flex min-w-0 flex-col justify-center rounded-[6px] border px-1.5 text-left hover:bg-row-hover",
        selected ? "border-accent bg-accent-soft" : match ? "border-warn bg-warn-soft" : "border-line-soft bg-panel",
      )}
      style={{ width: CARD_W, height: CARD_H }}
      title={[m.label, m.ip, m.mac, m.vendor, m.port ? `port ${m.port}` : null, m.vlan !== null ? `VLAN ${m.vlan}` : null].filter(Boolean).join("\n")}
      aria-label={`${m.label}, ${m.ip}${m.port ? `, port ${m.port}` : ""}`}
      aria-pressed={selected}
      onClick={(e) => {
        e.stopPropagation();
        a.openDevice(m.key);
      }}
      onDoubleClick={(e) => e.stopPropagation()}
      onContextMenu={(e) => {
        e.preventDefault();
        e.stopPropagation();
        a.deviceMenu(m.key, e.clientX, e.clientY);
      }}
    >
      <span className="flex min-w-0 items-center gap-1">
        {m.deviceKind && KIND_ICON[m.deviceKind] && <MemberKindIcon kind={m.deviceKind} />}
        <span className="truncate text-[11px] font-medium">{m.label}</span>
      </span>
      <span className="flex min-w-0 items-center gap-1 font-mono text-[10px] text-muted">
        <span className="truncate">
          {m.ip}
          {m.port ? ` · ${m.port}` : ""}
        </span>
        {m.poeWatts !== null && (
          <span className="ml-auto flex shrink-0 items-center" title={`PoE ${formatWatts(m.poeWatts)} W`}>
            <Zap size={8} aria-hidden />
            {formatWatts(m.poeWatts)}
          </span>
        )}
      </span>
    </button>
  );
}

function MemberKindIcon({ kind }: { kind: string }) {
  const Icon = KIND_ICON[kind];
  if (!Icon) return null;
  return <Icon size={11} strokeWidth={1.9} aria-label={deviceKindLabel(kind)} className="shrink-0 text-accent" />;
}

/** Collapsible group of endpoints ("31 hosts on Gi1/0/1-43") or of unlinked infrastructure ("40 access points"). */
export const ClusterNode = memo(function ClusterNode({ data }: NodeProps<TopoRfNode>) {
  const a = useActions();
  const n = data.topo;
  const wireless = n.clusterKind === "wireless";
  // Unlinked infrastructure grouped by role: the role's icon and color.
  const infraRole = n.clusterKind === "infra" ? (n.role ?? "switch") : null;
  const Icon = wireless ? Wifi : infraRole ? ROLE_ICON[infraRole] : Users;
  const cols = clusterCols(n.members.length);
  const tone = wireless ? ROLE_VAR.access_point : infraRole ? ROLE_VAR[infraRole] : n.clusterKind === "unattached" ? "var(--faint)" : ROLE_VAR.host;
  return (
    <div className={cx(frameClass(data), "topo-cluster")} style={{ borderLeft: `4px double ${tone}` }}>
      <Handles dir={data.dir} />
      <div className="flex items-start gap-1.5 px-2 pt-1.5">
        <Icon size={14} strokeWidth={1.9} aria-hidden className="mt-px shrink-0" style={{ color: tone }} />
        <div className="min-w-0 flex-1">
          <div className="truncate text-[12px] font-semibold" title={n.note ?? undefined}>
            {n.label}
          </div>
          <div className="topo-detail flex min-w-0 items-center gap-1 text-[10.5px] text-muted">
            {n.portsLabel && <span className="truncate font-mono">{n.portsLabel}</span>}
            {!n.portsLabel && wireless && <span>Wi-Fi clients</span>}
            <span className="flex-1" />
            <VlanBadges vlans={n.vlans} max={3} />
          </div>
          {n.detail && <div className="topo-detail truncate text-[10px] text-faint">{n.detail}</div>}
        </div>
        <button
          type="button"
          className="nodrag nopan -mr-1 flex shrink-0 items-center rounded-[4px] p-0.5 text-muted hover:bg-chrome-2 hover:text-fg"
          aria-expanded={n.expanded}
          aria-label={n.expanded ? `Collapse ${n.label}` : `Expand ${n.label}`}
          title={n.expanded ? "Collapse" : "Expand (double-click)"}
          onClick={(e) => {
            e.stopPropagation();
            a.toggleCluster(n.id);
          }}
        >
          {n.expanded ? <ChevronDown size={14} aria-hidden /> : <ChevronRight size={14} aria-hidden />}
        </button>
      </div>
      {data.matches > 0 && !n.expanded && (
        <span className="absolute right-7 top-1.5 rounded-full bg-warn px-1.5 text-[9.5px] font-semibold text-white">
          {data.matches.toLocaleString()} match{data.matches === 1 ? "" : "es"}
        </span>
      )}
      {n.expanded && (
        <div className="px-[10px]" style={{ paddingTop: 6, paddingBottom: CLUSTER_PAD }}>
          <div className="grid" style={{ gridTemplateColumns: `repeat(${cols}, ${CARD_W}px)`, gap: CARD_GAP }}>
            {n.members.map((m) => (
              <MemberCard key={m.key} m={m} selected={data.selectedKey === m.key} match={data.matchKeys?.has(m.key) ?? false} />
            ))}
          </div>
          {n.more > 0 && (
            <button
              type="button"
              className="nodrag nopan mt-1.5 h-[24px] w-full rounded-[6px] border border-dashed border-line text-[11px] text-muted hover:bg-chrome-2 hover:text-fg"
              onClick={(e) => {
                e.stopPropagation();
                a.showMore(n.id);
              }}
            >
              +{n.more.toLocaleString()} more
            </button>
          )}
        </div>
      )}
    </div>
  );
});

export const nodeTypes = { device: DeviceNode, special: SpecialNode, cluster: ClusterNode };

const EDGE_STYLE: Record<TopoEdge["kind"], { stroke: string; width: number; dash?: string }> = {
  trunk: { stroke: "var(--edge-trunk)", width: 2.4 },
  access: { stroke: "var(--edge-access)", width: 1.3 },
  wireless: { stroke: "var(--role-ap)", width: 1.3, dash: "5 4" },
  inferred: { stroke: "var(--faint)", width: 1.2, dash: "2 4" },
};

export const TopoEdgeView = memo(function TopoEdgeView(p: EdgeProps<TopoRfEdge>) {
  const d = p.data;
  if (!d) return null;
  const e = d.topo;
  const tb = d.dir === "TB";
  const bus = e.tree && tb ? d.bus : null;
  let path: string;
  let midX: number;
  let midY: number;
  let lx: number;
  let ly: number;
  let transform: string;
  if (bus) {
    // Indented tree: down from the parent, along the column's bus, then into the leaf's side.
    const left = p.targetX - bus.w / 2;
    const busX = left - STACK_BUS;
    const ty = p.targetY + Math.min(bus.h / 2, 31);
    path = `M ${p.sourceX} ${p.sourceY} V ${p.sourceY + 22} H ${busX} V ${ty} H ${left}`;
    midX = left;
    midY = ty;
    lx = left - 4;
    ly = ty - 2;
    transform = `translate(-100%, -100%) translate(${lx}px, ${ly}px)`;
  } else {
    [path, midX, midY] = e.tree
    ? getSmoothStepPath({
        sourceX: p.sourceX,
        sourceY: p.sourceY,
        targetX: p.targetX,
        targetY: p.targetY,
        sourcePosition: p.sourcePosition,
        targetPosition: p.targetPosition,
        borderRadius: 10,
        offset: 18,
      })
    : getBezierPath({
        sourceX: p.sourceX,
        sourceY: p.sourceY,
        targetX: p.targetX,
        targetY: p.targetY,
        sourcePosition: p.sourcePosition,
        targetPosition: p.targetPosition,
      });
    // Labels sit just before the child (the only segment unique to this edge in a tree).
    lx = e.tree ? (tb ? p.targetX : p.targetX - 10) : midX;
    ly = e.tree ? (tb ? p.targetY - 8 : p.targetY - 4) : midY;
    transform = e.tree
      ? tb
        ? `translate(-50%, -100%) translate(${lx}px, ${ly}px)`
        : `translate(-100%, -100%) translate(${lx}px, ${ly}px)`
      : `translate(-50%, -50%) translate(${lx}px, ${ly}px)`;
  }
  const s = EDGE_STYLE[e.kind];
  const stroke = d.highlight ? "var(--accent)" : s.stroke;
  // A stacked leaf has little room left of it: long port ranges stay on the cluster card.
  const label = bus && e.label !== null && e.label.length > 10 ? null : e.label;
  const hasLabel = label !== null || e.sublabel !== null;
  return (
    <>
      <BaseEdge
        id={p.id}
        path={path}
        style={{
          stroke,
          strokeWidth: d.highlight ? s.width + 1 : s.width,
          strokeDasharray: e.tree ? s.dash : (s.dash ?? "7 4"),
          opacity: d.dimmed ? 0.3 : 1,
        }}
      />
      {hasLabel && (
        <EdgeLabelRenderer>
          <div
            className={cx("topo-edge-label nodrag nopan", d.dimmed && "opacity-30")}
            style={{ transform }}
            data-kind={e.kind}
          >
            {label && <div className="font-mono">{label}</div>}
            {e.sublabel && <div className="text-muted">{e.sublabel}</div>}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
});

export const edgeTypes = { topo: TopoEdgeView };
