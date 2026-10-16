// Interactive Layer-2/Layer-3 topology map (React Flow). The graph comes from the pure builder
// in lib/topology.ts; layout (dagre) runs in a Web Worker and keeps positions stable across
// streaming updates. Only visible nodes are rendered, endpoints are clustered, and relayout is
// throttled while a scan streams in.

import "@xyflow/react/dist/style.css";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
} from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  Panel,
  ReactFlow,
  ReactFlowProvider,
  applyNodeChanges,
  useReactFlow,
  type NodeChange,
  type Viewport,
} from "@xyflow/react";
import {
  ArrowDownFromLine,
  ArrowRightFromLine,
  ChevronLeft,
  ChevronRight,
  ClipboardCopy,
  Copy,
  Download,
  FileImage,
  ListCollapse,
  Maximize,
  Network,
  Radar,
  KeyRound,
  RefreshCw,
  Share2,
  X,
} from "lucide-react";
import type { CdpLldpNeighbor, DeviceRole, SnmpDeviceInfo, SwitchPortMapping, VlanInfo } from "../types.ts";
import { ROLE_LABEL } from "../types.ts";
import type { DeviceRow } from "../lib/store.ts";
import { loadJson, saveJson } from "../lib/storage.ts";
import { EXPAND_STEP, UNTAGGED, buildTopology, deviceVlan, type TopoNode, type TopologyGraph } from "../lib/topology.ts";
import {
  layoutInput,
  layoutSignature,
  stableLayout,
  stackedLeaves,
  type LayoutDir,
  type LayoutRequest,
  type LayoutResult,
  type Pos,
  type Size,
} from "../lib/topologyLayout.ts";
import { bytesToBase64, exportFileName, pngScale, svgDataUrl, topologySvg, type SvgPalette } from "../lib/topologySvg.ts";
import { backend, errorMessage } from "../api.ts";
import { ContextMenu, type MenuState } from "./Menu.tsx";
import { useToasts } from "./Toasts.tsx";
import {
  ROLE_VAR,
  TopoActionsContext,
  TopoLiveContext,
  type TopoLive,
  edgeTypes,
  nodeTypes,
  type TopoActions,
  type TopoRfEdge,
  type TopoRfNode,
} from "./TopologyNodes.tsx";
import { Button, Select, cx } from "./ui.tsx";

export interface TopologyViewProps {
  rows: DeviceRow[];
  neighbors: CdpLldpNeighbor[];
  vlans: VlanInfo[];
  portMappings: SwitchPortMapping[];
  snmp: Record<string, SnmpDeviceInfo>;
  running: boolean;
  roleFilter: "all" | DeviceRole;
  search: string;
  selectedKey: string | null;
  onOpenDetails: (key: string) => void;
  onDeviceMenu: (key: string, x: number, y: number) => void;
  onCopy: (text: string, what: string) => void;
  /** Empty-state actions. */
  onScanCdp: () => void;
  onOpenSnmp: () => void;
  onPassiveListen: () => void;
  cdpLldp: boolean;
  snmpEnabled: boolean;
  /** Show latency accents on device nodes. */
  liveLatency?: boolean;
}

interface TopoPrefs {
  dir: LayoutDir;
  minimap: boolean;
  bannerDismissed: boolean;
}

const PREFS_KEY = "sweepr.topology.v1";
const DEFAULT_PREFS: TopoPrefs = { dir: "TB", minimap: true, bannerDismissed: false };
/** Largest member count an expanded cluster grows to via "+N more". */
const MAX_EXPANDED = 480;

const prefersReducedMotion = (): boolean => {
  try {
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  } catch {
    return false;
  }
};

function createLayoutWorker(): Worker | null {
  try {
    return new Worker(new URL("../lib/topology.worker.ts", import.meta.url), { type: "module" });
  } catch {
    return null;
  }
}

const ARIA_CONFIG = { "node.a11yDescription.default": "Press Enter to open details or expand a group; Shift+F10 for actions." };
const MINIMAP_STYLE = { width: 180, height: 120 };
const minimapColor = (n: { data: unknown }): string => ROLE_VAR[(n.data as { topo: TopoNode }).topo.role ?? "host"];

interface HoverState {
  node: TopoNode;
  x: number;
  y: number;
}

/** Tiny external store for the hover tooltip (only the tooltip re-renders on mouse moves). */
function createHoverStore() {
  let state: HoverState | null = null;
  const listeners = new Set<() => void>();
  return {
    get: (): HoverState | null => state,
    set: (next: HoverState | null): void => {
      if (next === state) return;
      if (next && state && next.node.id === state.node.id && Math.abs(next.x - state.x) + Math.abs(next.y - state.y) < 6) return;
      state = next;
      for (const l of listeners) l();
    },
    subscribe: (l: () => void): (() => void) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
  };
}
type HoverStore = ReturnType<typeof createHoverStore>;

function HoverTooltip({ store, graph }: { store: HoverStore; graph: TopologyGraph | null }) {
  const hover = useSyncExternalStore(store.subscribe, store.get);
  return hover ? <Tooltip hover={hover} graph={graph} /> : null;
}

export default function TopologyView(p: TopologyViewProps) {
  return (
    <ReactFlowProvider>
      <TopologyCanvas {...p} />
    </ReactFlowProvider>
  );
}

function TopologyCanvas(p: TopologyViewProps) {
  const toast = useToasts();
  const rf = useReactFlow<TopoRfNode, TopoRfEdge>();
  const [prefs, setPrefsState] = useState<TopoPrefs>(() => loadJson(PREFS_KEY, DEFAULT_PREFS));
  const setPrefs = useCallback((patch: Partial<TopoPrefs>) => {
    setPrefsState((cur) => {
      const next = { ...cur, ...patch };
      saveJson(PREFS_KEY, next);
      return next;
    });
  }, []);
  const dir = prefs.dir;
  const [vlanFilter, setVlanFilter] = useState<number | null>(null);
  const [expanded, setExpanded] = useState<Map<string, number>>(() => new Map());
  const [graph, setGraph] = useState<TopologyGraph | null>(null);
  const [buildMs, setBuildMs] = useState(0);
  const [layout, setLayout] = useState<LayoutResult | null>(null);
  const [nodes, setNodes] = useState<TopoRfNode[]>([]);
  // Hover lives outside React state so mouse moves never re-render the canvas.
  const hover = useMemo(() => createHoverStore(), []);
  const pRef = useRef(p);
  // Device warnings by key; the map keeps its identity while the warnings do not change, so
  // streamed rows do not re-render every node.
  const warnSig = useRef("");
  const warnMap = useRef<ReadonlyMap<string, readonly string[]>>(new Map());
  const warnings = useMemo(() => {
    const m = new Map<string, readonly string[]>();
    let sig = "";
    for (const r of p.rows) {
      const w = r.device.warnings;
      if (w && w.length > 0) {
        m.set(r.key, w);
        sig += `${r.key}:${w.length};`;
      }
    }
    if (sig !== warnSig.current) {
      warnSig.current = sig;
      warnMap.current = m;
    }
    return warnMap.current;
  }, [p.rows]);
  const live = !!p.liveLatency;
  const liveCtx = useMemo<TopoLive>(() => ({ live, warnings }), [live, warnings]);
  pRef.current = p;
  const [menu, setMenu] = useState<MenuState | null>(null);
  const [farOut, setFarOut] = useState(false);
  const [matchIndex, setMatchIndex] = useState(0);
  const wrapRef = useRef<HTMLDivElement>(null);
  // A narrow map (small window, drawer open): the overview sits below the map toolbar.
  const [narrowMap, setNarrowMap] = useState(false);
  useEffect(() => {
    const el = wrapRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => setNarrowMap(el.clientWidth < 760));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const pinned = useRef<Record<string, Pos>>({});
  const prevLayout = useRef<{ positions: Record<string, Pos>; sizes: Record<string, Size> } | null>(null);
  const lastSig = useRef("");
  const seq = useRef(0);
  const forceFresh = useRef(true);
  const fitPending = useRef(true);
  const userMoved = useRef(false);
  const lastBuild = useRef(0);
  const workerRef = useRef<Worker | null | undefined>(undefined);

  // --- search ------------------------------------------------------------------------------------
  const terms = useMemo(() => p.search.trim().toLowerCase().split(/\s+/).filter(Boolean), [p.search]);
  const matchKeys = useMemo<ReadonlySet<string> | null>(() => {
    if (terms.length === 0) return null;
    const out = new Set<string>();
    for (const r of p.rows) if (terms.every((t) => r.search.includes(t))) out.add(r.key);
    return out;
  }, [p.rows, terms]);

  // --- graph (throttled while streaming) ----------------------------------------------------------
  const roles = useMemo(() => (p.roleFilter === "all" ? null : new Set<DeviceRole>([p.roleFilter])), [p.roleFilter]);
  const vlans = useMemo(() => (vlanFilter === null ? null : new Set([vlanFilter])), [vlanFilter]);
  // A real throttle (not a debounce): store snapshots arrive every 80-400 ms while scanning, so
  // a pending build is never pushed back; it reads the latest inputs when it fires.
  const buildInputs = { rows: p.rows, neighbors: p.neighbors, vlans: p.vlans, portMappings: p.portMappings, snmp: p.snmp, expanded, roles, vlanSet: vlans, matchKeys };
  const inputsRef = useRef(buildInputs);
  inputsRef.current = buildInputs;
  const buildTimer = useRef<{ id: number; at: number } | null>(null);
  useEffect(() => {
    const now = performance.now();
    // Bigger networks rebuild less often while a scan is streaming.
    const interval = p.rows.length > 20_000 ? 1500 : 500;
    const due = p.running ? Math.max(now + 100, lastBuild.current + interval) : now;
    const pending = buildTimer.current;
    if (pending && pending.at <= due) return;
    if (pending) window.clearTimeout(pending.id);
    const id = window.setTimeout(() => {
      buildTimer.current = null;
      const i = inputsRef.current;
      const t0 = performance.now();
      const g = buildTopology(
        { devices: i.rows, neighbors: i.neighbors, vlans: i.vlans, portMappings: i.portMappings, snmp: i.snmp },
        { expanded: i.expanded, roles: i.roles, vlans: i.vlanSet, priorityKeys: i.matchKeys },
      );
      const t1 = performance.now();
      lastBuild.current = t1;
      setBuildMs(Math.round(t1 - t0));
      setGraph(g);
    }, Math.max(0, due - now));
    buildTimer.current = { id, at: due };
  }, [p.rows, p.neighbors, p.vlans, p.portMappings, p.snmp, p.running, expanded, roles, vlans, matchKeys]);
  useEffect(
    () => () => {
      if (buildTimer.current) window.clearTimeout(buildTimer.current.id);
      buildTimer.current = null;
    },
    [],
  );

  // When a scan finishes, tidy the incrementally grown map once (unless the user is exploring it).
  const wasRunning = useRef(p.running);
  useEffect(() => {
    if (wasRunning.current && !p.running && !userMoved.current && Object.keys(pinned.current).length === 0) {
      forceFresh.current = true;
      fitPending.current = true;
    }
    wasRunning.current = p.running;
  }, [p.running]);

  // A filter change re-lays out compactly (positions of hidden nodes are meaningless) and refits.
  const firstFilter = useRef(true);
  useEffect(() => {
    if (firstFilter.current) {
      firstFilter.current = false;
      return;
    }
    forceFresh.current = true;
    fitPending.current = true;
  }, [roles, vlans]);

  // --- layout (Web Worker, main-thread fallback) ---------------------------------------------------
  const handleResult = useCallback((r: LayoutResult) => {
    if (r.seq !== seq.current) return; // stale
    // Keep the whole map in view while it grows, until the user pans or zooms.
    if (r.mode === "fresh" && !userMoved.current) fitPending.current = true;
    prevLayout.current = { positions: r.positions, sizes: r.sizes };
    setLayout(r);
  }, []);

  /** The newest layout request (the main-thread fallback lays out this one, never a stale one). */
  const lastReq = useRef<LayoutRequest | null>(null);
  const runLayout = useCallback(
    (req: LayoutRequest) => {
      lastReq.current = req;
      if (workerRef.current === undefined) {
        const w = createLayoutWorker();
        if (w) {
          w.onmessage = (e: MessageEvent<LayoutResult | { seq: number; error: string }>) => {
            if ("error" in e.data) {
              toast.push("error", "Topology layout failed", e.data.error);
              return;
            }
            handleResult(e.data);
          };
          w.onerror = () => {
            // Module workers unavailable: lay out on the main thread from now on.
            workerRef.current = null;
            w.terminate();
            const latest = lastReq.current;
            if (latest) window.setTimeout(() => handleResult(stableLayout(latest)), 0);
          };
        }
        workerRef.current = w;
      }
      const w = workerRef.current;
      if (w) w.postMessage(req);
      else window.setTimeout(() => handleResult(stableLayout(req)), 0);
    },
    [handleResult, toast],
  );

  useEffect(() => () => workerRef.current?.terminate(), []);

  const lin = useMemo(() => (graph ? layoutInput(graph.nodes, graph.edges) : null), [graph]);
  const sig = useMemo(() => (lin ? layoutSignature(lin.nodes, lin.edges, dir) : ""), [lin, dir]);
  useEffect(() => {
    if (!lin) return;
    if (sig === lastSig.current && !forceFresh.current) return;
    lastSig.current = sig;
    const fresh = forceFresh.current;
    forceFresh.current = false;
    const prev = fresh ? null : prevLayout.current;
    runLayout({
      seq: ++seq.current,
      nodes: lin.nodes,
      edges: lin.edges,
      dir,
      prev: prev?.positions ?? null,
      prevSizes: prev?.sizes ?? null,
      pinned: pinned.current,
      fresh,
    });
  }, [lin, sig, dir, runLayout]);

  // --- React Flow nodes / edges --------------------------------------------------------------------
  const selectedNodeId = useMemo(
    () => (graph && p.selectedKey !== null ? (graph.nodeOfKey.get(p.selectedKey) ?? null) : null),
    [graph, p.selectedKey],
  );
  const matchCounts = useMemo(() => {
    const m = new Map<string, number>();
    if (!graph || !matchKeys) return m;
    for (const k of matchKeys) {
      const id = graph.nodeOfKey.get(k);
      if (id) m.set(id, (m.get(id) ?? 0) + 1);
    }
    return m;
  }, [graph, matchKeys]);
  const matchOrder = useMemo(() => (graph ? graph.nodes.filter((n) => matchCounts.has(n.id)).map((n) => n.id) : []), [graph, matchCounts]);

  useEffect(() => {
    if (!graph || !layout) return;
    const pos = layout.positions;
    const byId = new Map(graph.nodes.map((n) => [n.id, n]));
    const out: TopoRfNode[] = [];
    for (const n of graph.nodes) {
      const at = pinned.current[n.id] ?? pos[n.id];
      const size = layout.sizes[n.id];
      if (!at || !size) continue; // laid out on the next pass
      out.push({
        id: n.id,
        type: n.kind === "cluster" ? "cluster" : n.kind === "root" || n.kind === "scanner" ? "special" : "device",
        position: at,
        width: size.w,
        height: size.h,
        data: {
          topo: n,
          dir,
          selected: n.id === selectedNodeId,
          matches: matchCounts.get(n.id) ?? 0,
          dimmed: matchKeys !== null && !matchCounts.has(n.id),
          selectedKey: p.selectedKey,
          matchKeys,
        },
        ariaLabel: nodeAria(n, byId),
        ariaRole: "button",
        domAttributes: { "aria-roledescription": n.kind === "cluster" ? "device group" : "network device" },
        selectable: false,
        connectable: false,
        deletable: false,
      });
    }
    setNodes(out);
  }, [graph, layout, dir, selectedNodeId, matchCounts, matchKeys, p.selectedKey]);

  const stacked = useMemo(() => {
    const set = new Set<string>();
    if (lin) for (const l of stackedLeaves(lin.nodes, dir).values()) for (const id of l) set.add(id);
    return set;
  }, [lin, dir]);

  const edges = useMemo<TopoRfEdge[]>(() => {
    if (!graph) return [];
    const sizes = layout?.sizes;
    return graph.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      type: "topo",
      data: {
        topo: e,
        dir,
        highlight: selectedNodeId !== null && (e.source === selectedNodeId || e.target === selectedNodeId),
        dimmed: matchKeys !== null && !(matchCounts.has(e.target) || matchCounts.has(e.source)),
        bus: stacked.has(e.target) && sizes?.[e.target] ? { w: sizes[e.target]!.w, h: sizes[e.target]!.h } : null,
      },
      selectable: false,
      focusable: false,
      deletable: false,
      ariaLabel: e.label ? `${e.kind} link ${e.label}` : `${e.kind} link`,
    }));
  }, [graph, layout, stacked, dir, selectedNodeId, matchKeys, matchCounts]);

  // Fit the view after a fresh layout (first view, re-layout, direction change).
  useEffect(() => {
    if (!layout || nodes.length === 0 || !fitPending.current) return;
    fitPending.current = false;
    const id = window.requestAnimationFrame(() => {
      void rf.fitView({ padding: 0.12, duration: prefersReducedMotion() ? 0 : 250, maxZoom: 1.1, minZoom: 0.02 });
    });
    return () => window.cancelAnimationFrame(id);
  }, [layout, nodes.length, rf]);

  const onNodesChange = useCallback((changes: NodeChange<TopoRfNode>[]) => {
    const relevant = changes.filter((c) => c.type === "position" || c.type === "dimensions");
    if (relevant.length === 0) return;
    for (const c of relevant) {
      if (c.type === "position" && c.position && c.dragging === false) pinned.current[c.id] = c.position;
    }
    setNodes((ns) => applyNodeChanges(relevant, ns));
  }, []);

  const onNodeDragStop = useCallback((_: unknown, node: TopoRfNode) => {
    pinned.current[node.id] = { ...node.position };
  }, []);

  // --- actions -----------------------------------------------------------------------------------------
  const toggleCluster = useCallback((id: string) => {
    setExpanded((m) => {
      const next = new Map(m);
      if (next.has(id)) next.delete(id);
      else next.set(id, EXPAND_STEP);
      return next;
    });
  }, []);
  const showMore = useCallback((id: string) => {
    setExpanded((m) => new Map(m).set(id, Math.min(MAX_EXPANDED, (m.get(id) ?? 0) + EXPAND_STEP)));
  }, []);

  const actions = useMemo<TopoActions>(
    () => ({
      openDevice: (k) => pRef.current.onOpenDetails(k),
      toggleCluster,
      showMore,
      deviceMenu: (k, x, y) => pRef.current.onDeviceMenu(k, x, y),
    }),
    [toggleCluster, showMore],
  );


  const clusterMenu = useCallback(
    (n: TopoNode, x: number, y: number) => {
      const byKey = new Map(pRef.current.rows.map((r) => [r.key, r.device.ip]));
      const ips = n.memberKeys.map((k) => byKey.get(k)).filter((v): v is string => !!v);
      setMenu({
        x,
        y,
        label: `Actions for ${n.label}`,
        items: [
          { kind: "header", label: n.label },
          { kind: "item", label: n.expanded ? "Collapse" : "Expand", icon: ListCollapse, onSelect: () => toggleCluster(n.id) },
          { kind: "item", label: `Copy ${ips.length.toLocaleString()} IP Addresses`, icon: Copy, onSelect: () => pRef.current.onCopy(ips.join("\n"), "IP addresses") },
        ],
      });
    },
    [toggleCluster],
  );

  const activate = useCallback(
    (n: TopoNode) => {
      if (n.kind === "cluster") toggleCluster(n.id);
      else if (n.deviceKey) pRef.current.onOpenDetails(n.deviceKey);
    },
    [toggleCluster],
  );

  const openMenuFor = useCallback(
    (n: TopoNode, x: number, y: number) => {
      if (n.kind === "cluster") clusterMenu(n, x, y);
      else if (n.deviceKey) pRef.current.onDeviceMenu(n.deviceKey, x, y);
    },
    [clusterMenu],
  );

  // Stable React Flow handlers: a new function identity re-renders every visible node.
  const onNodeClick = useCallback((_: unknown, node: TopoRfNode) => {
    const n = node.data.topo;
    if (n.kind !== "cluster" && n.deviceKey) pRef.current.onOpenDetails(n.deviceKey);
  }, []);
  const onNodeDoubleClick = useCallback(
    (_: unknown, node: TopoRfNode) => {
      if (node.data.topo.kind === "cluster") toggleCluster(node.id);
    },
    [toggleCluster],
  );
  const onNodeContextMenu = useCallback(
    (e: ReactMouseEvent, node: TopoRfNode) => {
      e.preventDefault();
      hover.set(null);
      openMenuFor(node.data.topo, e.clientX, e.clientY);
    },
    [hover, openMenuFor],
  );
  const onNodeMouseEnter = useCallback((e: ReactMouseEvent, node: TopoRfNode) => hover.set({ node: node.data.topo, x: e.clientX, y: e.clientY }), [hover]);
  const onNodeMouseMove = useCallback((e: ReactMouseEvent, node: TopoRfNode) => hover.set({ node: node.data.topo, x: e.clientX, y: e.clientY }), [hover]);
  const onNodeMouseLeave = useCallback(() => hover.set(null), [hover]);

  // Keyboard on focused nodes: Enter opens details / toggles a cluster, Space toggles a
  // cluster, Shift+F10 / the context-menu key opens the actions menu.
  const onKeyDown = useCallback(
    (e: ReactKeyboardEvent) => {
      const el = (e.target as HTMLElement).closest?.(".react-flow__node");
      if (!el || e.target !== el || !graph) return;
      const id = el.getAttribute("data-id");
      const n = graph.nodes.find((x) => x.id === id);
      if (!n) return;
      if (e.key === "Enter" || (e.key === " " && n.kind === "cluster")) {
        e.preventDefault();
        activate(n);
      } else if (e.key === "ContextMenu" || (e.key === "F10" && e.shiftKey)) {
        e.preventDefault();
        const r = el.getBoundingClientRect();
        openMenuFor(n, r.left + 12, r.bottom - 4);
      }
    },
    [graph, activate, openMenuFor],
  );

  const relayout = useCallback(() => {
    userMoved.current = false;
    pinned.current = {};
    forceFresh.current = true;
    fitPending.current = true;
    lastSig.current = "";
    setGraph((g) => (g ? { ...g } : g));
  }, []);

  const setDir = useCallback(
    (d: LayoutDir) => {
      if (d === dir) return;
      pinned.current = {};
      forceFresh.current = true;
      fitPending.current = true;
      setPrefs({ dir: d });
    },
    [dir, setPrefs],
  );

  const collapseAll = useCallback(() => setExpanded(new Map()), []);

  // Search navigation: centre the current match; a match inside a collapsed cluster expands it.
  const goToMatch = useCallback(
    (i: number) => {
      if (matchOrder.length === 0) return;
      const idx = ((i % matchOrder.length) + matchOrder.length) % matchOrder.length;
      setMatchIndex(idx);
      const id = matchOrder[idx]!;
      const n = graph?.nodes.find((x) => x.id === id);
      if (n?.kind === "cluster" && !n.expanded) toggleCluster(id);
      const node = rf.getNode(id);
      if (node) {
        const w = node.width ?? node.measured?.width ?? 200;
        const h = node.height ?? node.measured?.height ?? 60;
        void rf.setCenter(node.position.x + w / 2, node.position.y + Math.min(h, 160) / 2, {
          zoom: Math.max(rf.getZoom(), 0.9),
          duration: prefersReducedMotion() ? 0 : 300,
        });
      }
    },
    [matchOrder, graph, rf, toggleCluster],
  );
  // Jump to the first match when the search changes.
  const lastTerms = useRef("");
  useEffect(() => {
    const key = terms.join(" ");
    if (key === lastTerms.current || matchOrder.length === 0) return;
    lastTerms.current = key;
    const t = window.setTimeout(() => goToMatch(0), 50);
    return () => window.clearTimeout(t);
  }, [terms, matchOrder, goToMatch]);

  // --- export ----------------------------------------------------------------------------------------------
  // The map is exported as plain vector SVG built from the graph (no DOM capture, no
  // <foreignObject>), and PNG is that SVG rasterized on a canvas, which WebKit handles reliably.
  const renderSvg = useCallback((): { svg: string; width: number; height: number } => {
    if (!graph || !layout) throw new Error("the map is not laid out yet");
    const positions: Record<string, Pos> = {};
    for (const n of rf.getNodes()) positions[n.id] = n.position;
    return topologySvg({
      nodes: graph.nodes,
      edges: graph.edges,
      positions,
      sizes: layout.sizes,
      dir,
      stacked,
      palette: cssPalette(),
      title: "SweepR network topology",
    });
  }, [graph, layout, rf, dir, stacked]);

  // Rasterized from a data: URL: the CSP (`img-src 'self' data:`) blocks blob: images.
  const renderPng = useCallback(async (): Promise<Blob> => {
    const { svg, width, height } = renderSvg();
    const scale = pngScale(width, height);
    const img = new Image();
    img.decoding = "async";
    await new Promise<void>((resolve, reject) => {
      img.onload = () => resolve();
      img.onerror = () => reject(new Error("could not rasterize the SVG"));
      img.src = svgDataUrl(svg);
    });
    const canvas = document.createElement("canvas");
    canvas.width = Math.max(1, Math.floor(width * scale));
    canvas.height = Math.max(1, Math.floor(height * scale));
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("canvas unavailable");
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    return await new Promise<Blob>((resolve, reject) =>
      canvas.toBlob((b) => (b ? resolve(b) : reject(new Error("PNG encoding failed"))), "image/png"),
    );
  }, [renderSvg]);

  // Saved by the backend (`save_file` opens the native save dialog): WKWebView cancels
  // `<a download>` links, so only a returned path proves the file was written.
  const download = useCallback(
    async (kind: "png" | "svg") => {
      const label = kind.toUpperCase();
      try {
        const contents = kind === "svg" ? renderSvg().svg : bytesToBase64(new Uint8Array(await (await renderPng()).arrayBuffer()));
        const path = await backend.saveFile(kind, contents, exportFileName(kind));
        if (path === null) toast.push("info", "Map not saved", "The save dialog was cancelled.");
        else toast.push("success", `Saved the map as ${label}`, path);
      } catch (e) {
        toast.push("error", `${label} export failed`, errorMessage(e));
      }
    },
    [renderSvg, renderPng, toast],
  );

  const copyPng = useCallback(async () => {
    if (typeof ClipboardItem === "undefined" || !navigator.clipboard?.write) {
      toast.push("error", "Could not copy the map", "Image copying is not available here. Use Save as PNG instead.");
      return;
    }
    try {
      // Pass the promise straight to ClipboardItem so Safari / WKWebView keeps the user gesture.
      await navigator.clipboard.write([new ClipboardItem({ "image/png": renderPng() })]);
      toast.push("success", "Copied the map as PNG");
    } catch (e) {
      toast.push("error", "Could not copy the map", `${errorMessage(e).replace(/\.$/, "")}. Use Save as PNG instead.`);
    }
  }, [renderPng, toast]);

  const exportBtn = useRef<HTMLButtonElement>(null);
  const openExport = (): void => {
    const r = exportBtn.current?.getBoundingClientRect();
    setMenu({
      x: r ? r.left : 0,
      y: r ? r.bottom + 4 : 0,
      label: "Export map",
      items: [
        { kind: "header", label: "Export map" },
        { kind: "item", label: "Save as PNG…", icon: FileImage, onSelect: () => void download("png") },
        { kind: "item", label: "Save as SVG…", icon: Share2, onSelect: () => void download("svg") },
        { kind: "item", label: "Copy as PNG", icon: ClipboardCopy, onSelect: () => void copyPng() },
      ],
    });
  };

  // --- VLAN filter options --------------------------------------------------------------------------
  const vlanOptions = useMemo(() => {
    const ids = new Set<number>();
    let untagged = false;
    for (const r of p.rows) {
      const v = deviceVlan(r.device);
      if (v === null) untagged = true;
      else ids.add(v);
    }
    for (const v of p.vlans) ids.add(v.id);
    const names = new Map(p.vlans.map((v) => [v.id, v.name]));
    return { untagged, list: [...ids].sort((a, b) => a - b).map((id) => ({ id, name: names.get(id) ?? null })) };
  }, [p.rows, p.vlans]);

  const onMoveStart = useCallback((e: MouseEvent | TouchEvent | null) => {
    if (e) userMoved.current = true;
  }, []);

  const onMove = useCallback((_: unknown, vp: Viewport) => {
    const far = vp.zoom < 0.45;
    setFarOut((cur) => (cur === far ? cur : far));
  }, []);

  // --- render ----------------------------------------------------------------------------------------------
  if (p.rows.length === 0) {
    return (
      <EmptyState running={p.running} cdpLldp={p.cdpLldp} snmpEnabled={p.snmpEnabled} onScanCdp={p.onScanCdp} onOpenSnmp={p.onOpenSnmp} onPassiveListen={p.onPassiveListen} />
    );
  }

  const stats = graph?.stats;
  const showBanner = stats !== undefined && !stats.hasInfraData && !prefs.bannerDismissed;
  const filterActive = roles !== null || vlans !== null;

  return (
    <TopoActionsContext.Provider value={actions}>
      <TopoLiveContext.Provider value={liveCtx}>
      <div
        ref={wrapRef}
        className={cx("sweepr-topo relative min-h-0 flex-1", farOut && "topo-far")}
        onKeyDown={onKeyDown}
        role="region"
        aria-label="Network topology map"
      >
        <ReactFlow<TopoRfNode, TopoRfEdge>
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          onNodesChange={onNodesChange}
          onNodeDragStop={onNodeDragStop}
          onNodeClick={onNodeClick}
          onNodeDoubleClick={onNodeDoubleClick}
          onNodeContextMenu={onNodeContextMenu}
          onNodeMouseEnter={onNodeMouseEnter}
          onNodeMouseMove={onNodeMouseMove}
          onNodeMouseLeave={onNodeMouseLeave}
          onPaneClick={onNodeMouseLeave}
          onMoveStart={onMoveStart}
          onMove={onMove}
          onlyRenderVisibleElements
          nodesConnectable={false}
          elementsSelectable={false}
          nodesFocusable
          edgesFocusable={false}
          deleteKeyCode={null}
          selectionKeyCode={null}
          multiSelectionKeyCode={null}
          zoomOnDoubleClick={false}
          minZoom={0.02}
          maxZoom={2.5}
          colorMode="system"
          ariaLabelConfig={ARIA_CONFIG}
        >
          <Background variant={BackgroundVariant.Dots} gap={22} size={1} />
          <Controls showInteractive={false} position="bottom-right" className="!mb-8" aria-label="Zoom controls" />
          {prefs.minimap && (
            <MiniMap
              position="top-right"
              className={narrowMap ? "!mt-14" : undefined}
              pannable
              zoomable
              ariaLabel="Topology overview"
              nodeColor={minimapColor}
              nodeStrokeWidth={0}
              maskColor="color-mix(in srgb, var(--bg) 70%, transparent)"
              style={MINIMAP_STYLE}
            />
          )}
          <Panel position="top-left" className="!m-2">
            <div className="flex flex-wrap items-center gap-1 rounded-[8px] border border-line bg-panel/95 p-1 shadow-[0_1px_3px_rgb(0_0_0/0.12)] backdrop-blur">
              <div role="radiogroup" aria-label="Layout direction" className="flex rounded-[6px] border border-line bg-chrome-2 p-[2px]">
                <DirButton active={dir === "TB"} onClick={() => setDir("TB")} label="Top-down" icon={<ArrowDownFromLine size={13} aria-hidden />} />
                <DirButton active={dir === "LR"} onClick={() => setDir("LR")} label="Left-right" icon={<ArrowRightFromLine size={13} aria-hidden />} />
              </div>
              <Button variant="ghost" icon={RefreshCw} onClick={relayout} title="Re-layout (forget dragged positions)" aria-label="Re-layout" />
              <Button
                variant="ghost"
                icon={Maximize}
                onClick={() => {
                  userMoved.current = false;
                  void rf.fitView({ padding: 0.12, duration: prefersReducedMotion() ? 0 : 250, minZoom: 0.02 });
                }}
                title="Fit the whole map"
                aria-label="Fit view"
              />
              <Button variant="ghost" icon={ListCollapse} onClick={collapseAll} disabled={expanded.size === 0} title="Collapse all groups" aria-label="Collapse all groups" />
              <Select
                aria-label="Filter by VLAN"
                value={vlanFilter === null ? "all" : String(vlanFilter)}
                onChange={(e) => setVlanFilter(e.target.value === "all" ? null : Number(e.target.value))}
                className="w-[130px]"
              >
                <option value="all">All VLANs</option>
                {vlanOptions.untagged && <option value={String(UNTAGGED)}>Untagged</option>}
                {vlanOptions.list.map((v) => (
                  <option key={v.id} value={String(v.id)}>
                    VLAN {v.id}
                    {v.name ? ` · ${v.name}` : ""}
                  </option>
                ))}
              </Select>
              <Button ref={exportBtn} icon={Download} onClick={openExport} aria-haspopup="menu" title="Export the map as PNG or SVG">
                Export
              </Button>
              <Button variant="ghost" pressed={prefs.minimap} onClick={() => setPrefs({ minimap: !prefs.minimap })} title="Show the overview map" aria-label="Toggle overview map">
                <span className="text-[11px]">Overview</span>
              </Button>
              {matchKeys !== null && (
                <div className="flex items-center gap-0.5 border-l border-line pl-1.5" aria-live="polite">
                  <span className="text-[11.5px] text-muted tabular">
                    {matchKeys.size === 0 ? "No matches" : `${matchKeys.size.toLocaleString()} match${matchKeys.size === 1 ? "" : "es"}`}
                  </span>
                  <Button variant="ghost" icon={ChevronLeft} disabled={matchOrder.length === 0} onClick={() => goToMatch(matchIndex - 1)} aria-label="Previous match" />
                  <Button variant="ghost" icon={ChevronRight} disabled={matchOrder.length === 0} onClick={() => goToMatch(matchIndex + 1)} aria-label="Next match" />
                </div>
              )}
            </div>
          </Panel>
          {showBanner && (
            <Panel position="bottom-center" className="!mb-10">
              <div className="flex max-w-[640px] items-start gap-2 rounded-[8px] border border-warn/40 bg-warn-soft px-3 py-2 shadow-[0_1px_3px_rgb(0_0_0/0.12)]">
                <Network size={16} className="mt-0.5 shrink-0 text-warn" aria-hidden />
                <div className="min-w-0">
                  <p>
                    <strong>Flat map:</strong> no CDP/LLDP adverts or SNMP MAC tables yet, so devices are grouped per VLAN under a synthetic root.
                    Turn on CDP/LLDP (<code className="font-mono">--cdp-lldp</code>) and SNMP (community) for the switch / AP hierarchy.
                  </p>
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    <Button icon={Radar} onClick={p.onScanCdp} disabled={p.running}>
                      Scan with CDP/LLDP
                    </Button>
                    <Button icon={KeyRound} onClick={p.onOpenSnmp}>
                      SNMP Settings…
                    </Button>
                  </div>
                </div>
                <button type="button" aria-label="Dismiss" className="rounded p-0.5 text-muted hover:bg-chrome-2" onClick={() => setPrefs({ bannerDismissed: true })}>
                  <X size={13} aria-hidden />
                </button>
              </div>
            </Panel>
          )}
          {/* Legend and stats share one corner (stacked), so they never overlap on narrow maps. */}
          <Panel position="bottom-left" className="!m-2 flex max-w-[min(560px,calc(100%-80px))] flex-col items-start gap-1">
            <Legend />
            <div className="rounded-[6px] border border-line bg-panel/95 px-2 py-1 text-[11px] text-muted tabular shadow-[0_1px_2px_rgb(0_0_0/0.1)]" aria-live="off">
              {stats ? (
                <>
                  {stats.devices.toLocaleString()} devices · {stats.infra.toLocaleString()} infrastructure · {stats.clusters.toLocaleString()} groups ·{" "}
                  {nodes.length.toLocaleString()} nodes
                  {filterActive && " (filtered)"}
                  <span className="text-faint">
                    {" "}
                    · build {buildMs} ms · layout {layout?.ms ?? "…"} ms{layout ? ` (${layout.mode})` : ""}
                  </span>
                </>
              ) : (
                "Building map…"
              )}
            </div>
          </Panel>
        </ReactFlow>
        {!menu && <HoverTooltip store={hover} graph={graph} />}
        {menu && <ContextMenu menu={menu} onClose={() => setMenu(null)} />}
      </div>
      </TopoLiveContext.Provider>
    </TopoActionsContext.Provider>
  );
}

/** Export colors from the live theme tokens (so a dark-mode export is dark). */
function cssPalette(): SvgPalette {
  const cs = getComputedStyle(document.documentElement);
  const v = (name: string, fallback: string): string => cs.getPropertyValue(name).trim() || fallback;
  return {
    bg: v("--bg", "#ffffff"),
    card: v("--field", "#ffffff"),
    panel: v("--panel", "#f6f6f6"),
    border: v("--line", "#d4d4d4"),
    fg: v("--fg", "#1d1d1f"),
    muted: v("--muted", "#6e6e73"),
    faint: v("--faint", "#a1a1a6"),
    accent: v("--accent", "#0a64d8"),
    warn: v("--warn", "#b25f00"),
    role: {
      switch: v("--role-switch", "#0a7bd8"),
      firewall: v("--role-firewall", "#d6342c"),
      access_point: v("--role-ap", "#8a4fd8"),
      router: v("--role-router", "#c26a00"),
      host: v("--role-host", "#6e6e73"),
    },
    edge: {
      trunk: v("--edge-trunk", "#3b4a5c"),
      access: v("--edge-access", "#9aa3ad"),
      wireless: v("--role-ap", "#8a4fd8"),
      inferred: v("--faint", "#a1a1a6"),
    },
  };
}

function nodeAria(n: TopoNode, byId: ReadonlyMap<string, TopoNode>): string {
  const parent = n.parentId ? byId.get(n.parentId) : undefined;
  const where = parent ? `, connected to ${parent.label}${n.port ? ` port ${n.port}` : ""}` : "";
  if (n.kind === "cluster") {
    return `${n.label}${n.portsLabel ? ` on ${n.portsLabel}` : ""}${n.vlans.length ? `, VLAN ${n.vlans.join(", ")}` : ""}${where}, ${n.expanded ? "expanded" : "collapsed"}`;
  }
  if (n.kind === "root" || n.kind === "scanner") return `${n.label}${n.detail ? `, ${n.detail}` : ""}${where}`;
  const role = n.role ? ROLE_LABEL[n.role] : "Device";
  const status = n.status === "warn" ? ", warning" : n.status === "unknown" ? ", unverified" : "";
  return `${role} ${n.label}${n.ip ? `, ${n.ip}` : ""}${n.detail ? `, ${n.detail}` : ""}${where}${status}`;
}

function DirButton({ active, onClick, label, icon }: { active: boolean; onClick: () => void; label: string; icon: ReactNode }) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={active}
      title={label}
      aria-label={label}
      onClick={onClick}
      className={cx("flex h-[20px] items-center rounded-[4px] px-1.5", active ? "bg-field shadow-[0_0.5px_2px_rgb(0_0_0/0.18)]" : "text-muted hover:text-fg")}
    >
      {icon}
    </button>
  );
}

function Tooltip({ hover, graph }: { hover: { node: TopoNode; x: number; y: number }; graph: TopologyGraph | null }) {
  const n = hover.node;
  const parent = n.parentId && graph ? graph.nodes.find((x) => x.id === n.parentId) : undefined;
  const lines: Array<[string, string]> = [];
  if (n.kind === "cluster") {
    lines.push(["Devices", n.count.toLocaleString()]);
    if (n.portsLabel) lines.push(["Ports", n.portsLabel]);
    if (n.detail) lines.push(["Vendors", n.detail]);
  } else {
    if (n.role) lines.push(["Role", ROLE_LABEL[n.role]]);
    if (n.ip) lines.push(["IP", n.ip]);
    if (n.mac) lines.push(["MAC", n.mac]);
    if (n.detail) lines.push([n.kind === "scanner" ? "Interface" : "Model", n.detail]);
  }
  if (n.vlans.length > 0) lines.push(["VLAN", n.vlans.join(", ")]);
  if (parent) lines.push(["Uplink", `${parent.label}${n.port ? ` · ${n.port}` : ""}`]);
  const left = Math.min(hover.x + 14, window.innerWidth - 300);
  const top = Math.min(hover.y + 16, window.innerHeight - 40 - lines.length * 16);
  return (
    <div
      role="tooltip"
      className="pointer-events-none fixed z-40 max-w-[290px] rounded-[7px] border border-line bg-panel px-2.5 py-1.5 text-[11.5px] shadow-pop"
      style={{ left, top }}
    >
      <div className="mb-0.5 font-semibold">{n.label}</div>
      <dl className="grid grid-cols-[auto_1fr] gap-x-2">
        {lines.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-muted">{k}</dt>
            <dd className="min-w-0 break-words font-mono text-[11px]">{v}</dd>
          </div>
        ))}
      </dl>
      {n.note && <p className="mt-1 text-[11px] text-muted">{n.note}</p>}
      {n.kind === "cluster" && <p className="mt-1 text-[10.5px] text-faint">Double-click to {n.expanded ? "collapse" : "expand"}.</p>}
    </div>
  );
}

function Legend() {
  const [open, setOpen] = useState(false);
  return (
    <>
      {open ? (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-[6px] border border-line bg-panel/95 px-2 py-1 text-[11px] shadow-[0_1px_2px_rgb(0_0_0/0.1)]">
          <LegendLine label="Trunk / uplink" stroke="var(--edge-trunk)" width={2.4} />
          <LegendLine label="Access port" stroke="var(--edge-access)" width={1.3} />
          <LegendLine label="Wi-Fi" stroke="var(--role-ap)" width={1.3} dash="5 4" />
          <LegendLine label="Inferred (no link data)" stroke="var(--faint)" width={1.2} dash="2 4" />
          <LegendLine label="Redundant link" stroke="var(--edge-trunk)" width={2} dash="7 4" />
          <button type="button" className="rounded p-0.5 text-muted hover:bg-chrome-2" aria-label="Hide legend" onClick={() => setOpen(false)}>
            <X size={12} aria-hidden />
          </button>
        </div>
      ) : (
        <button type="button" className="rounded-[6px] border border-line bg-panel/95 px-2 py-0.5 text-[11px] text-muted hover:text-fg" onClick={() => setOpen(true)}>
          Legend
        </button>
      )}
    </>
  );
}

function LegendLine({ label, stroke, width, dash }: { label: string; stroke: string; width: number; dash?: string }) {
  return (
    <span className="flex items-center gap-1">
      <svg width="26" height="8" aria-hidden>
        <line x1="1" y1="4" x2="25" y2="4" stroke={stroke} strokeWidth={width} strokeDasharray={dash} />
      </svg>
      {label}
    </span>
  );
}

function EmptyState(p: {
  running: boolean;
  cdpLldp: boolean;
  snmpEnabled: boolean;
  onScanCdp: () => void;
  onOpenSnmp: () => void;
  onPassiveListen: () => void;
}) {
  return (
    <div className="flex min-h-0 flex-1 items-center justify-center p-6">
      <div className="flex max-w-[540px] flex-col items-center gap-3 text-center">
        <Network size={30} strokeWidth={1.5} className="text-muted" aria-hidden />
        <h2 className="text-[16px] font-semibold">{p.running ? "Scanning… the map fills in as devices answer" : "No topology yet"}</h2>
        <p className="text-muted">
          The map draws firewalls and routers on top, then core and access switches, access points and endpoints. The hierarchy comes from{" "}
          <strong className="text-fg">CDP/LLDP</strong> adverts (<code className="font-mono">--cdp-lldp</code> or a passive listen) and the switches'{" "}
          <strong className="text-fg">SNMP</strong> MAC address tables (an SNMP community). Without them devices are grouped per VLAN.
        </p>
        <ul className="text-left text-[12px] text-muted">
          <li>CDP/LLDP: {p.cdpLldp ? "on" : "off"}</li>
          <li>SNMP: {p.snmpEnabled ? "configured" : "not configured"}</li>
        </ul>
        <div className="flex flex-wrap justify-center gap-2">
          <Button variant="primary" icon={Radar} onClick={p.onScanCdp} disabled={p.running}>
            Scan with CDP/LLDP
          </Button>
          <Button icon={KeyRound} onClick={p.onOpenSnmp}>
            SNMP Settings…
          </Button>
          <Button icon={Radar} onClick={p.onPassiveListen} disabled={p.running}>
            Listen Passively
          </Button>
        </div>
      </div>
    </div>
  );
}
