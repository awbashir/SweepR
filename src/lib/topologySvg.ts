// Standalone vector export of the topology map: plain SVG shapes and text (no <foreignObject>),
// so it opens in any viewer and rasterizes reliably to PNG on a canvas in WebKit (WKWebView).

import type { DeviceRole } from "../types.ts";
import { ROLE_LABEL } from "../types.ts";
import type { TopoEdge, TopoEdgeKind, TopoNode } from "./topology.ts";
import { CARD_GAP, CARD_H, CARD_W, CLUSTER_HEADER_H, STACK_BUS, clusterCols, type LayoutDir, type Pos, type Size } from "./topologyLayout.ts";

export interface SvgPalette {
  bg: string;
  card: string;
  panel: string;
  border: string;
  fg: string;
  muted: string;
  faint: string;
  accent: string;
  warn: string;
  role: Record<DeviceRole, string>;
  edge: Record<TopoEdgeKind, string>;
}

export const LIGHT_PALETTE: SvgPalette = {
  bg: "#ffffff",
  card: "#ffffff",
  panel: "#f6f6f6",
  border: "#d4d4d4",
  fg: "#1d1d1f",
  muted: "#6e6e73",
  faint: "#a1a1a6",
  accent: "#0a64d8",
  warn: "#b25f00",
  role: { switch: "#0a7bd8", firewall: "#d6342c", access_point: "#8a4fd8", router: "#c26a00", host: "#6e6e73" },
  edge: { trunk: "#3b4a5c", access: "#9aa3ad", wireless: "#8a4fd8", inferred: "#a1a1a6" },
};

export interface SvgInput {
  nodes: readonly TopoNode[];
  edges: readonly TopoEdge[];
  positions: Readonly<Record<string, Pos>>;
  sizes: Readonly<Record<string, Size>>;
  dir: LayoutDir;
  /** Leaves drawn on a column bus (see `stackedLeaves`). */
  stacked: ReadonlySet<string>;
  palette?: SvgPalette;
  padding?: number;
  title?: string;
}

const esc = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** Fit text into `px` pixels using an average glyph width (no DOM measuring). */
function fit(s: string, px: number, charW: number): string {
  const max = Math.max(1, Math.floor(px / charW));
  return s.length <= max ? s : `${s.slice(0, Math.max(1, max - 1))}…`;
}

const EDGE_W: Record<TopoEdgeKind, number> = { trunk: 2.4, access: 1.3, wireless: 1.3, inferred: 1.2 };
const EDGE_DASH: Partial<Record<TopoEdgeKind, string>> = { wireless: "5 4", inferred: "2 4" };

export function topologySvg(input: SvgInput): { svg: string; width: number; height: number } {
  const pal = input.palette ?? LIGHT_PALETTE;
  const pad = input.padding ?? 32;
  const tb = input.dir === "TB";
  const placed = input.nodes.filter((n) => input.positions[n.id] && input.sizes[n.id]);
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const n of placed) {
    const p = input.positions[n.id]!;
    const s = input.sizes[n.id]!;
    minX = Math.min(minX, p.x - (input.stacked.has(n.id) ? STACK_BUS + 8 : 0));
    minY = Math.min(minY, p.y - 40);
    maxX = Math.max(maxX, p.x + s.w);
    maxY = Math.max(maxY, p.y + s.h);
  }
  if (placed.length === 0) {
    minX = minY = 0;
    maxX = maxY = 100;
  }
  const ox = pad - minX;
  const oy = pad - minY;
  const width = Math.ceil(maxX - minX + pad * 2);
  const height = Math.ceil(maxY - minY + pad * 2);
  const out: string[] = [];
  out.push(
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif">`,
  );
  if (input.title) out.push(`<title>${esc(input.title)}</title>`);
  out.push(`<rect width="100%" height="100%" fill="${pal.bg}"/>`);
  const box = (id: string): { x: number; y: number; w: number; h: number } | null => {
    const p = input.positions[id];
    const s = input.sizes[id];
    return p && s ? { x: p.x + ox, y: p.y + oy, w: s.w, h: s.h } : null;
  };

  // Edges first (under the nodes), labels after the nodes.
  const labels: string[] = [];
  out.push(`<g fill="none" stroke-linecap="round" stroke-linejoin="round">`);
  for (const e of input.edges) {
    const a = box(e.source);
    const b = box(e.target);
    if (!a || !b) continue;
    let d: string;
    let lx: number;
    let ly: number;
    let anchor: "middle" | "end" = "middle";
    let above = true;
    if (e.tree && tb && input.stacked.has(e.target)) {
      const sx = a.x + a.w / 2;
      const sy = a.y + a.h;
      const ty = b.y + Math.min(b.h / 2, 31);
      d = `M${sx} ${sy}V${sy + 22}H${b.x - STACK_BUS}V${ty}H${b.x}`;
      lx = b.x - 4;
      ly = ty - 3;
      anchor = "end";
    } else if (e.tree) {
      const [sx, sy, tx, ty] = tb ? [a.x + a.w / 2, a.y + a.h, b.x + b.w / 2, b.y] : [a.x + a.w, a.y + a.h / 2, b.x, b.y + b.h / 2];
      if (tb) {
        const my = Math.round((sy + ty) / 2);
        d = `M${sx} ${sy}V${my}H${tx}V${ty}`;
        lx = tx;
        ly = ty - 8;
      } else {
        const mx = Math.round((sx + tx) / 2);
        d = `M${sx} ${sy}H${mx}V${ty}H${tx}`;
        lx = tx - 10;
        ly = ty - 4;
        anchor = "end";
      }
    } else {
      const [sx, sy, tx, ty] = tb ? [a.x + a.w / 2, a.y + a.h, b.x + b.w / 2, b.y] : [a.x + a.w, a.y + a.h / 2, b.x, b.y + b.h / 2];
      const c = tb ? Math.abs(ty - sy) / 2 + 30 : Math.abs(tx - sx) / 2 + 30;
      d = tb ? `M${sx} ${sy}C${sx} ${sy + c} ${tx} ${ty - c} ${tx} ${ty}` : `M${sx} ${sy}C${sx + c} ${sy} ${tx - c} ${ty} ${tx} ${ty}`;
      lx = (sx + tx) / 2;
      ly = (sy + ty) / 2;
      above = false;
    }
    const dash = e.tree ? EDGE_DASH[e.kind] : (EDGE_DASH[e.kind] ?? "7 4");
    out.push(`<path d="${d}" stroke="${pal.edge[e.kind]}" stroke-width="${EDGE_W[e.kind]}"${dash ? ` stroke-dasharray="${dash}"` : ""}/>`);
    const busLeaf = e.tree && tb && input.stacked.has(e.target);
    const lines = [busLeaf && e.label && e.label.length > 10 ? null : e.label, e.sublabel].filter((x): x is string => !!x);
    if (lines.length > 0) {
      const w = Math.max(...lines.map((l) => l.length)) * 6.1 + 8;
      const h = lines.length * 13 + 3;
      const x0 = anchor === "end" ? lx - w : lx - w / 2;
      const y0 = above ? ly - h : ly - h / 2;
      labels.push(
        `<rect x="${x0.toFixed(1)}" y="${y0.toFixed(1)}" width="${w.toFixed(1)}" height="${h}" rx="4" fill="${pal.panel}" stroke="${e.kind === "trunk" ? pal.edge.trunk : pal.border}" stroke-width="0.8"/>`,
      );
      lines.forEach((l, i) => {
        const font = i === 0 ? `font-family="ui-monospace, Menlo, monospace"` : "";
        const fill = i === 0 ? (e.kind === "wireless" ? pal.role.access_point : pal.fg) : pal.muted;
        labels.push(`<text x="${(x0 + w / 2).toFixed(1)}" y="${(y0 + 12 + i * 13).toFixed(1)}" font-size="10" text-anchor="middle" fill="${fill}" ${font}>${esc(l)}</text>`);
      });
    }
  }
  out.push(`</g>`);

  for (const n of placed) {
    const b = box(n.id)!;
    const role = n.role ?? "host";
    const tone =
      n.kind === "cluster"
        ? n.clusterKind === "wireless"
          ? pal.role.access_point
          : n.clusterKind === "infra"
            ? pal.role[role]
            : n.clusterKind === "unattached"
              ? pal.faint
              : pal.role.host
        : pal.role[role];
    const round = n.kind === "root" || n.kind === "scanner" ? b.h / 2 : 8;
    out.push(`<g>`);
    out.push(
      `<rect x="${b.x}" y="${b.y}" width="${b.w}" height="${b.h}" rx="${round}" fill="${pal.card}" stroke="${n.status === "unknown" ? pal.faint : pal.border}"${n.status === "unknown" ? ` stroke-dasharray="4 3"` : ""}/>`,
    );
    if (n.kind !== "root" && n.kind !== "scanner") out.push(`<rect x="${b.x}" y="${b.y}" width="4" height="${b.h}" rx="2" fill="${tone}"/>`);
    const tx = b.x + (n.kind === "root" || n.kind === "scanner" ? 18 : 12);
    const tw = b.w - (tx - b.x) - 8;
    if (n.kind === "cluster") {
      out.push(`<text x="${tx}" y="${b.y + 18}" font-size="12" font-weight="600" fill="${pal.fg}">${esc(fit(n.label, tw - 30, 7))}</text>`);
      const sub = [n.portsLabel ?? (n.clusterKind === "wireless" ? "Wi-Fi clients" : null), n.vlans.length ? `VLAN ${n.vlans.join(",")}` : null].filter(Boolean).join(" · ");
      if (sub) out.push(`<text x="${tx}" y="${b.y + 33}" font-size="10.5" fill="${pal.muted}">${esc(fit(sub, tw, 6))}</text>`);
      if (n.detail) out.push(`<text x="${tx}" y="${b.y + 47}" font-size="10" fill="${pal.faint}">${esc(fit(n.detail, tw, 5.6))}</text>`);
      if (n.expanded) {
        const cols = clusterCols(n.members.length);
        n.members.forEach((m, i) => {
          const cx = b.x + 10 + (i % cols) * (CARD_W + CARD_GAP);
          const cy = b.y + CLUSTER_HEADER_H + 6 + Math.floor(i / cols) * (CARD_H + CARD_GAP);
          out.push(`<rect x="${cx}" y="${cy}" width="${CARD_W}" height="${CARD_H}" rx="6" fill="${pal.panel}" stroke="${pal.border}" stroke-width="0.8"/>`);
          out.push(`<text x="${cx + 6}" y="${cy + 15}" font-size="11" font-weight="500" fill="${pal.fg}">${esc(fit(m.label, CARD_W - 12, 6.2))}</text>`);
          out.push(
            `<text x="${cx + 6}" y="${cy + 29}" font-size="10" fill="${pal.muted}" font-family="ui-monospace, Menlo, monospace">${esc(fit(`${m.ip}${m.port ? ` · ${m.port}` : ""}`, CARD_W - 12, 6))}</text>`,
          );
        });
        if (n.more > 0) {
          out.push(`<text x="${b.x + b.w / 2}" y="${b.y + b.h - 10}" font-size="11" text-anchor="middle" fill="${pal.muted}">+${n.more.toLocaleString()} more</text>`);
        }
      }
    } else {
      const roleTag = n.kind === "infra" ? ROLE_LABEL[role].toUpperCase() : "";
      out.push(`<text x="${tx}" y="${b.y + (n.kind === "infra" ? 20 : 18)}" font-size="12" font-weight="600" fill="${pal.fg}">${esc(fit(n.label, tw - (roleTag ? 60 : 0), 7))}</text>`);
      if (roleTag) out.push(`<text x="${b.x + b.w - 8}" y="${b.y + 19}" font-size="9" text-anchor="end" fill="${pal.muted}" letter-spacing="0.5">${roleTag}</text>`);
      const line2 = n.kind === "root" || n.kind === "scanner" ? n.detail : [n.ip ?? n.mac, n.port].filter(Boolean).join(" · ");
      if (line2) {
        out.push(
          `<text x="${tx}" y="${b.y + (n.kind === "infra" ? 36 : 33)}" font-size="10.5" fill="${pal.muted}"${n.kind === "root" || n.kind === "scanner" ? "" : ` font-family="ui-monospace, Menlo, monospace"`}>${esc(fit(line2, tw, 6.3))}</text>`,
        );
      }
      if (n.kind === "infra" || n.kind === "device") {
        const line3 = [n.detail, n.vlans.length ? `VLAN ${n.vlans.slice(0, 6).join(",")}${n.vlans.length > 6 ? "…" : ""}` : null].filter(Boolean).join(" · ");
        if (line3) out.push(`<text x="${tx}" y="${b.y + (n.kind === "infra" ? 52 : 49)}" font-size="10.5" fill="${pal.muted}">${esc(fit(line3, tw, 6))}</text>`);
      }
      if (n.status === "warn") out.push(`<text x="${b.x + b.w - 10}" y="${b.y + b.h - 8}" font-size="11" text-anchor="end" fill="${pal.warn}">⚠</text>`);
    }
    out.push(`</g>`);
  }
  out.push(...labels);
  out.push(`</svg>`);
  return { svg: out.join(""), width, height };
}

// --- export helpers -----------------------------------------------------------------------------
// The app's CSP (`img-src 'self' data:`) has no `blob:`, so the SVG is rasterized from a data:
// URL, and files are saved by the backend (`save_file`), never through `<a download href=blob:>`
// (which WKWebView cancels).

/** Safari / WKWebView canvas limit (16.7 Mpx); larger PNG exports are scaled down. */
export const MAX_CANVAS_AREA = 16_000_000;
export const MAX_CANVAS_SIDE = 16_000;

/** Base64 of `bytes` (chunked, so large images never overflow the argument limit). */
export function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

/** A `data:image/svg+xml;base64,…` URL for `svg` (UTF-8 safe). */
export function svgDataUrl(svg: string): string {
  return `data:image/svg+xml;base64,${bytesToBase64(new TextEncoder().encode(svg))}`;
}

/** Raster scale for a `width` x `height` map: 2x for small maps, within the canvas limits. */
export function pngScale(width: number, height: number): number {
  const w = Math.max(1, width);
  const h = Math.max(1, height);
  const scale = Math.min(2, MAX_CANVAS_SIDE / w, MAX_CANVAS_SIDE / h, Math.sqrt(MAX_CANVAS_AREA / (w * h)));
  return Math.max(scale, 0.05);
}

/** "sweepr-topology-2026-10-16-14-03-22.png" */
export function exportFileName(kind: "png" | "svg", at: Date = new Date()): string {
  return `sweepr-topology-${at.toISOString().slice(0, 19).replace(/[:T]/g, "-")}.${kind}`;
}
