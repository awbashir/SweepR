// Hierarchical layout (dagre) plus position stability: unchanged nodes keep their place across
// streaming updates, new nodes are placed relative to their parent and nudged off overlaps,
// grown nodes (an expanded cluster) push their neighbours aside, and user-dragged positions
// win. Pure: runs in the layout Web Worker, on the main thread as a fallback, and in tests.

import { Graph, layout } from "@dagrejs/dagre";
import type { TopoNode } from "./topology.ts";

export type LayoutDir = "TB" | "LR";

export interface Size {
  w: number;
  h: number;
}

export interface Pos {
  x: number;
  y: number;
}

export interface LayoutNode {
  id: string;
  w: number;
  h: number;
  parent: string | null;
}

export interface LayoutEdge {
  source: string;
  target: string;
  minlen: number;
}

export interface LayoutRequest {
  seq: number;
  nodes: LayoutNode[];
  edges: LayoutEdge[];
  dir: LayoutDir;
  /** Previous top-left positions and sizes (null for a fresh layout). */
  prev: Record<string, Pos> | null;
  prevSizes: Record<string, Size> | null;
  /** User-dragged positions; always kept. */
  pinned: Record<string, Pos>;
  fresh: boolean;
}

export type LayoutMode = "fresh" | "incremental" | "reuse";

export interface LayoutResult {
  seq: number;
  positions: Record<string, Pos>;
  sizes: Record<string, Size>;
  mode: LayoutMode;
  ms: number;
}

// --- node sizes ----------------------------------------------------------------------------------------

export const NODE_W = 212;
export const DEVICE_H = 62;
export const INFRA_H = 78;
export const CLUSTER_H = 70;
export const ROOT_W = 176;
export const ROOT_H = 52;
export const CARD_W = 168;
export const CARD_H = 38;
export const CARD_GAP = 6;
export const CLUSTER_HEADER_H = 64;
export const CLUSTER_PAD = 10;
export const MORE_H = 30;

/** Grid columns of an expanded cluster with `n` member cards. */
export function clusterCols(n: number): number {
  return Math.max(1, Math.min(6, Math.ceil(Math.sqrt(n * 1.6))));
}

export function nodeSize(n: Pick<TopoNode, "kind" | "expanded" | "members" | "more">): Size {
  switch (n.kind) {
    case "root":
      return { w: ROOT_W, h: ROOT_H };
    case "scanner":
      return { w: ROOT_W, h: ROOT_H };
    case "infra":
      return { w: NODE_W, h: INFRA_H };
    case "device":
      return { w: NODE_W, h: DEVICE_H };
    case "cluster": {
      if (!n.expanded || n.members.length === 0) return { w: NODE_W, h: CLUSTER_H };
      const cols = clusterCols(n.members.length);
      const rows = Math.ceil(n.members.length / cols);
      const w = Math.max(NODE_W, CLUSTER_PAD * 2 + cols * CARD_W + (cols - 1) * CARD_GAP);
      const h = CLUSTER_HEADER_H + rows * CARD_H + (rows - 1) * CARD_GAP + CLUSTER_PAD + (n.more > 0 ? MORE_H : 0);
      return { w, h };
    }
  }
}

// --- dagre ----------------------------------------------------------------------------------------------

/** Left indent of a stacked leaf column: room for the bus line and the port label. */
export const STACK_INDENT = 78;
/** The bus line runs this far left of a stacked leaf. */
export const STACK_BUS = 70;
const STACK_GAP_Y = 14;
const STACK_GAP_X = 24;
const STACK_MIN = 3;
const STACK_ROWS = 7;

/**
 * Leaves (nodes without children) of parents with at least `STACK_MIN` leaves. In top-down
 * layouts they are stacked in columns under the parent (an indented "bus" tree) instead of one
 * very wide row; the edge renderer draws those links along a bus.
 */
export function stackedLeaves(nodes: readonly LayoutNode[], dir: LayoutDir): Map<string, string[]> {
  const out = new Map<string, string[]>();
  if (dir !== "TB") return out;
  const hasKids = new Set<string>();
  for (const n of nodes) if (n.parent) hasKids.add(n.parent);
  const leaves = new Map<string, string[]>();
  for (const n of nodes) {
    if (!n.parent || hasKids.has(n.id)) continue;
    const l = leaves.get(n.parent);
    if (l) l.push(n.id);
    else leaves.set(n.parent, [n.id]);
  }
  for (const [p, l] of leaves) if (l.length >= STACK_MIN) out.set(p, l);
  return out;
}

/** Plain dagre layout (with stacked leaf columns in TB); returns top-left positions. */
export function dagreLayout(nodes: readonly LayoutNode[], edges: readonly LayoutEdge[], dir: LayoutDir): Record<string, Pos> {
  const g = new Graph({ multigraph: false, compound: false });
  const stacks = stackedLeaves(nodes, dir);
  const stackedIds = new Set<string>();
  for (const l of stacks.values()) for (const id of l) stackedIds.add(id);
  const big = nodes.length - stackedIds.size > 600;
  g.setGraph({
    rankdir: dir,
    nodesep: dir === "TB" ? 28 : 18,
    ranksep: dir === "TB" ? 96 : 150,
    edgesep: 12,
    marginx: 24,
    marginy: 24,
    // Network-simplex ranking is the slow part on big graphs; tight-tree is near-identical for trees.
    ranker: big ? "tight-tree" : "network-simplex",
  });
  g.setDefaultEdgeLabel(() => ({}));
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const ids = new Set<string>();
  for (const n of nodes) {
    if (stackedIds.has(n.id)) continue;
    g.setNode(n.id, { width: n.w, height: n.h });
    ids.add(n.id);
  }
  // One block per stack: columns of up to STACK_ROWS leaves.
  const blocks = new Map<string, { id: string; cols: Array<{ ids: string[]; w: number; h: number }>; w: number; h: number }>();
  for (const [p, leafIds] of stacks) {
    const cols: Array<{ ids: string[]; w: number; h: number }> = [];
    const perCol = Math.max(STACK_ROWS, Math.ceil(leafIds.length / 6));
    for (let i = 0; i < leafIds.length; i += perCol) {
      const colIds = leafIds.slice(i, i + perCol);
      let w = 0;
      let h = 0;
      for (const id of colIds) {
        const n = byId.get(id)!;
        w = Math.max(w, n.w);
        h += n.h + STACK_GAP_Y;
      }
      cols.push({ ids: colIds, w: STACK_INDENT + w, h: h - STACK_GAP_Y });
    }
    const w = cols.reduce((a, c) => a + c.w, 0) + STACK_GAP_X * (cols.length - 1);
    const h = Math.max(...cols.map((c) => c.h));
    const id = `stack:${p}`;
    blocks.set(p, { id, cols, w, h });
    g.setNode(id, { width: w, height: h });
    ids.add(id);
  }
  const blockMinlen = new Map<string, number>();
  for (const e of edges) {
    if (stackedIds.has(e.target)) {
      blockMinlen.set(e.source, Math.max(blockMinlen.get(e.source) ?? 1, e.minlen));
      continue;
    }
    if (ids.has(e.source) && ids.has(e.target) && e.source !== e.target) g.setEdge(e.source, e.target, { minlen: e.minlen, weight: 1 });
  }
  for (const [p, b] of blocks) if (ids.has(p)) g.setEdge(p, b.id, { minlen: blockMinlen.get(p) ?? 1, weight: 2 });
  layout(g);
  const out: Record<string, Pos> = {};
  for (const n of nodes) {
    if (stackedIds.has(n.id)) continue;
    const v = g.node(n.id) as { x: number; y: number } | undefined;
    out[n.id] = v ? { x: Math.round(v.x - n.w / 2), y: Math.round(v.y - n.h / 2) } : { x: 0, y: 0 };
  }
  for (const b of blocks.values()) {
    const v = g.node(b.id) as { x: number; y: number } | undefined;
    let x = Math.round((v?.x ?? 0) - b.w / 2);
    const y0 = Math.round((v?.y ?? 0) - b.h / 2);
    for (const col of b.cols) {
      let y = y0;
      for (const id of col.ids) {
        out[id] = { x: x + STACK_INDENT, y };
        y += byId.get(id)!.h + STACK_GAP_Y;
      }
      x += col.w + STACK_GAP_X;
    }
  }
  return out;
}

// --- stability ------------------------------------------------------------------------------------------

const MARGIN = 14;

interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

function overlaps(a: Rect, b: Rect, m = MARGIN): boolean {
  return a.x < b.x + b.w + m && b.x < a.x + a.w + m && a.y < b.y + b.h + m && b.y < a.y + a.h + m;
}

/** Layout keeping previous positions where possible (see the file comment). */
export function stableLayout(req: LayoutRequest): LayoutResult {
  const t0 = now();
  const sizes: Record<string, Size> = {};
  for (const n of req.nodes) sizes[n.id] = { w: n.w, h: n.h };
  const prev = req.prev;
  const prevSizes = req.prevSizes ?? {};
  const kept = prev ? req.nodes.filter((n) => prev[n.id] !== undefined) : [];
  const added = req.nodes.filter((n) => !prev || prev[n.id] === undefined);
  const resized = kept.filter((n) => {
    const s = prevSizes[n.id];
    return !s || s.w !== n.w || s.h !== n.h;
  });

  const finish = (positions: Record<string, Pos>, mode: LayoutMode): LayoutResult => {
    for (const [id, p] of Object.entries(req.pinned)) if (sizes[id]) positions[id] = { ...p };
    return { seq: req.seq, positions, sizes, mode, ms: Math.round(now() - t0) };
  };

  if (prev && !req.fresh && added.length === 0 && resized.length === 0) {
    const positions: Record<string, Pos> = {};
    for (const n of req.nodes) positions[n.id] = { ...prev[n.id]! };
    return finish(positions, "reuse");
  }

  const next = dagreLayout(req.nodes, req.edges, req.dir);
  if (!prev || req.fresh || kept.length === 0 || added.length > Math.max(8, kept.length * 0.3)) {
    return finish(next, "fresh");
  }

  const tb = req.dir === "TB";
  const positions: Record<string, Pos> = {};
  const parentOf = new Map<string, string | null>();
  const children = new Map<string, string[]>();
  for (const n of req.nodes) {
    parentOf.set(n.id, n.parent);
    if (n.parent) {
      const l = children.get(n.parent);
      if (l) l.push(n.id);
      else children.set(n.parent, [n.id]);
    }
  }
  // Kept nodes stay (a resized node keeps its top-left corner, so it grows away from the
  // nodes before it and only the ones after it have to move).
  for (const n of kept) positions[n.id] = { ...prev[n.id]! };
  // Average drift between the old layout and the fresh one, for nodes without a placed ancestor.
  let dx = 0;
  let dy = 0;
  for (const n of kept) {
    dx += prev[n.id]!.x - next[n.id]!.x;
    dy += prev[n.id]!.y - next[n.id]!.y;
  }
  dx = Math.round(dx / kept.length);
  dy = Math.round(dy / kept.length);
  // New nodes: keep their offset from the nearest placed ancestor in the fresh layout.
  const addedIds = new Set(added.map((n) => n.id));
  const order = orderParentsFirst(added.map((n) => n.id), parentOf, addedIds);
  for (const id of order) {
    let anc = parentOf.get(id) ?? null;
    while (anc && !positions[anc]) anc = parentOf.get(anc) ?? null;
    const q = next[id]!;
    if (anc) {
      const a = next[anc]!;
      const ap = positions[anc]!;
      positions[id] = { x: ap.x + (q.x - a.x), y: ap.y + (q.y - a.y) };
    } else positions[id] = { x: q.x + dx, y: q.y + dy };
  }

  const rect = (id: string): Rect => ({ ...positions[id]!, w: sizes[id]!.w, h: sizes[id]!.h });
  const pinned = new Set(Object.keys(req.pinned));
  const all = req.nodes.map((n) => n.id);
  const subtree = (id: string): string[] => {
    const out: string[] = [];
    const stack = [id];
    while (stack.length > 0) {
      const c = stack.pop()!;
      out.push(c);
      for (const k of children.get(c) ?? []) stack.push(k);
    }
    return out;
  };
  const shift = (ids: string[], by: number): void => {
    for (const s of ids) {
      if (pinned.has(s)) continue;
      const p = positions[s]!;
      positions[s] = tb ? { x: p.x + by, y: p.y } : { x: p.x, y: p.y + by };
    }
  };

  // New nodes slide along the rank (right in TB, down in LR) until they are free.
  for (const id of order) {
    if (pinned.has(id)) continue;
    for (let guard = 0; guard < 400; guard++) {
      const r = rect(id);
      const hit = all.find((o) => o !== id && overlaps(r, rect(o)));
      if (!hit) break;
      const h = rect(hit);
      const by = tb ? h.x + h.w + MARGIN - r.x : h.y + h.h + MARGIN - r.y;
      shift(subtree(id), Math.max(1, by));
    }
  }
  // Grown nodes (expanded clusters) make room: everything on each side of the node is shifted
  // uniformly, which keeps those nodes' arrangement (and non-overlap) intact.
  for (const n of resized) {
    const sub = new Set(subtree(n.id));
    const was = prevSizes[n.id] ?? { w: n.w, h: n.h };
    // First along the rank axis: what sits below (TB) / right of (LR) the node and overlaps its
    // span moves down / right by the growth, like inserting rows in a stacked column.
    const grow = tb ? n.h - was.h : n.w - was.w;
    if (grow > 0) {
      const r0 = rect(n.id);
      const below = all.filter((o) => {
        if (sub.has(o)) return false;
        const ro = rect(o);
        return tb
          ? ro.y >= r0.y + was.h - 1 && ro.x < r0.x + r0.w + MARGIN && r0.x < ro.x + ro.w + MARGIN
          : ro.x >= r0.x + was.w - 1 && ro.y < r0.y + r0.h + MARGIN && r0.y < ro.y + ro.h + MARGIN;
      });
      const ids = new Set<string>();
      for (const o of below) for (const x of subtree(o)) ids.add(x);
      for (const id of ids) {
        if (pinned.has(id)) continue;
        const p = positions[id]!;
        positions[id] = tb ? { x: p.x, y: p.y + grow } : { x: p.x + grow, y: p.y };
      }
    }
    const r = rect(n.id);
    // Then across: sides are split at the node's centre before it grew.
    const centre = tb ? r.x + was.w / 2 : r.y + was.h / 2;
    let after = 0;
    let before = 0;
    const afterIds: string[] = [];
    const beforeIds: string[] = [];
    for (const o of all) {
      if (sub.has(o)) continue;
      const ro = rect(o);
      const co = tb ? ro.x + ro.w / 2 : ro.y + ro.h / 2;
      if (co >= centre) afterIds.push(o);
      else beforeIds.push(o);
      if (!overlaps(r, ro)) continue;
      if (co >= centre) after = Math.max(after, tb ? r.x + r.w + MARGIN - ro.x : r.y + r.h + MARGIN - ro.y);
      else before = Math.max(before, tb ? ro.x + ro.w + MARGIN - r.x : ro.y + ro.h + MARGIN - r.y);
    }
    if (after > 0) shift(afterIds, Math.ceil(after));
    if (before > 0) shift(beforeIds, -Math.ceil(before));
  }
  return finish(positions, "incremental");
}

function orderParentsFirst(ids: string[], parentOf: Map<string, string | null>, within: Set<string>): string[] {
  const out: string[] = [];
  const done = new Set<string>();
  const visit = (id: string): void => {
    if (done.has(id)) return;
    done.add(id);
    const p = parentOf.get(id);
    if (p && within.has(p)) visit(p);
    out.push(id);
  };
  for (const id of ids) visit(id);
  return out;
}

function now(): number {
  return typeof performance !== "undefined" ? performance.now() : Date.now();
}

/** Layout input for a topology graph (tree edges only; cross links do not rank). */
export function layoutInput(
  nodes: readonly TopoNode[],
  edges: ReadonlyArray<{ source: string; target: string; tree: boolean; minlen: number }>,
): { nodes: LayoutNode[]; edges: LayoutEdge[] } {
  return {
    nodes: nodes.map((n) => {
      const s = nodeSize(n);
      return { id: n.id, w: s.w, h: s.h, parent: n.parentId };
    }),
    edges: edges.filter((e) => e.tree).map((e) => ({ source: e.source, target: e.target, minlen: e.minlen })),
  };
}

/** Structural signature: a new layout is needed only when this changes. */
export function layoutSignature(nodes: readonly LayoutNode[], edges: readonly LayoutEdge[], dir: LayoutDir): string {
  let h = 2166136261;
  const mix = (s: string): void => {
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
  };
  mix(dir);
  for (const n of nodes) mix(`${n.id}:${n.w}x${n.h};`);
  for (const e of edges) mix(`${e.source}>${e.target}/${e.minlen};`);
  return `${nodes.length}/${edges.length}/${(h >>> 0).toString(36)}`;
}
