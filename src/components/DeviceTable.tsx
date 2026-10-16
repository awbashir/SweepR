// High-density, virtualized device table (TanStack Table v8 + TanStack Virtual).
// Only the ~40 visible rows are in the DOM, so 50k+ devices scroll smoothly.

import {
  memo,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type MouseEvent,
  type ReactNode,
} from "react";
import {
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type ColumnOrderState,
  type ColumnSizingState,
  type Row,
  type SortingState,
  type Updater,
  type VisibilityState,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowDown, ArrowUp, RotateCw, ShieldAlert, ShieldX, TriangleAlert } from "lucide-react";
import type { DeviceRow } from "../lib/store.ts";
import { MAX_OVERRIDE_LEN, ROLE_LABEL } from "../types.ts";
import { usePersistentState } from "../hooks/usePersistentState.ts";
import { formatLoss, formatMs, lossTone, type Tone } from "../lib/latency.ts";
import { certSortKey, classifyCert } from "../lib/webid.ts";
import { autoIpWidth, completeOrder, effectiveVisibility, type AutoColumns } from "../lib/columns.ts";
import { latencyStore, useLatency } from "../tools.ts";
import { Sparkline } from "./Charts.tsx";
import { ContextMenu, type MenuItem } from "./Menu.tsx";
import { KindIcon, MiniBadge, RoleIcon, TONE_TEXT_CLASS, cx } from "./ui.tsx";
import { deviceKindOf, formatWatts, netServiceBadges, poeSummary, poeTone, type NetBadge } from "../lib/services.ts";

export const ROW_H = 22;
const HEADER_H = 24;

export type ColId =
  | "ip"
  | "mac"
  | "vlan"
  | "role"
  | "hostname"
  | "vendor"
  | "switchPort"
  | "dns"
  | "mdns"
  | "smb"
  | "smbDomain"
  | "ports"
  | "latency"
  | "loss"
  | "webTitle"
  | "webIdentity"
  | "certCn"
  | "certExpires"
  | "deviceKind"
  | "modelFw"
  | "poe"
  | "voiceVlan"
  | "dhcpOs"
  | "comments";

export type EditField = "hostname" | "comments";
export type Align = "left" | "center" | "right";

interface ColMeta {
  label: string;
  size: number;
  align: Align;
  mono?: boolean;
}

export const COL_META: Record<ColId, ColMeta> = {
  ip: { label: "IP Address", size: 130, align: "left", mono: true },
  mac: { label: "MAC Address", size: 140, align: "left", mono: true },
  vlan: { label: "VLAN ID", size: 74, align: "right" },
  role: { label: "Device Role", size: 156, align: "left" },
  latency: { label: "Latency", size: 180, align: "left" },
  loss: { label: "Loss %", size: 64, align: "right" },
  hostname: { label: "Hostname", size: 150, align: "left" },
  vendor: { label: "Vendor", size: 160, align: "left" },
  switchPort: { label: "Switch / Port", size: 170, align: "left" },
  dns: { label: "DNS Name", size: 190, align: "left" },
  mdns: { label: "mDNS Name", size: 150, align: "left" },
  smb: { label: "SMB Name", size: 110, align: "left" },
  smbDomain: { label: "SMB Domain", size: 90, align: "left" },
  ports: { label: "TCP Ports", size: 120, align: "left" },
  webTitle: { label: "Web Title", size: 180, align: "left" },
  webIdentity: { label: "Web Identity", size: 140, align: "left" },
  certCn: { label: "Cert CN", size: 170, align: "left" },
  certExpires: { label: "Cert Expires", size: 130, align: "left" },
  deviceKind: { label: "Device Kind", size: 124, align: "left" },
  modelFw: { label: "Model/Firmware", size: 190, align: "left" },
  poe: { label: "PoE (W)", size: 70, align: "right" },
  voiceVlan: { label: "Voice VLAN", size: 80, align: "right" },
  dhcpOs: { label: "OS (DHCP)", size: 150, align: "left" },
  comments: { label: "Comments", size: 200, align: "left" },
};

/** Text colour per loss / latency tone (every colour also has a text cue). */
export const TONE_TEXT: Record<Tone, string> = {
  ok: "text-muted",
  warn: "text-warn",
  bad: "text-danger",
  down: "text-danger font-semibold",
  none: "text-faint",
};

const ALL_COLS = Object.keys(COL_META) as ColId[];

const isColId = (v: string): v is ColId => v in COL_META;

const blank = (s: string | null | undefined): string | undefined => (s === null || s === undefined || s === "" ? undefined : s);

/** Fast comparator over the accessor value (precomputed strings/numbers, no locale work). */
function basicSort(a: Row<DeviceRow>, b: Row<DeviceRow>, id: string): number {
  const x = a.getValue<string | number>(id);
  const y = b.getValue<string | number>(id);
  return x < y ? -1 : x > y ? 1 : 0;
}

function col(id: ColId, accessor: (r: DeviceRow) => string | number | undefined): ColumnDef<DeviceRow> {
  return {
    id,
    accessorFn: accessor,
    header: COL_META[id].label,
    size: COL_META[id].size,
    minSize: 40,
    maxSize: 800,
    sortingFn: basicSort,
    sortUndefined: "last",
    enableResizing: true,
  };
}

const COLUMNS: ColumnDef<DeviceRow>[] = [
  col("ip", (r) => r.ipSort),
  col("mac", (r) => blank(r.device.mac)),
  col("vlan", (r) => r.device.vlanId ?? undefined),
  col("role", (r) => ROLE_LABEL[r.device.role]),
  col("hostname", (r) => blank(r.hostname)),
  col("vendor", (r) => blank(r.device.vendor)),
  col("switchPort", (r) => blank(r.switchPort)),
  col("dns", (r) => blank(r.device.dnsName)),
  col("mdns", (r) => blank(r.device.mdnsName)),
  col("smb", (r) => blank(r.device.smbName)),
  col("smbDomain", (r) => blank(r.device.smbDomain)),
  // Sort by number of open ports, then by the lowest port.
  col("ports", (r) =>
    r.device.openPorts.length === 0
      ? undefined
      : `${String(r.device.openPorts.length).padStart(5, "0")}:${String(r.device.openPorts[0]).padStart(5, "0")}`,
  ),
  // Live values: sorted by the snapshot taken when the rows last changed.
  col("latency", (r) => latencyStore.get(r.device.ip)?.stats.avgMs ?? undefined),
  col("loss", (r) => latencyStore.get(r.device.ip)?.stats.lossPct ?? undefined),
  col("webTitle", (r) => blank(r.device.webTitle)),
  col("webIdentity", (r) => blank(r.device.webIdentity)),
  col("certCn", (r) => blank(r.device.tlsCert?.subjectCn)),
  col("certExpires", (r) => certSortKey(r.device.tlsCert)),
  col("deviceKind", (r) => blank(r.kind)),
  col("modelFw", (r) => blank(r.modelFw)),
  col("poe", (r) => r.device.poe?.watts ?? r.device.poe?.maxWatts ?? undefined),
  col("voiceVlan", (r) => r.device.voiceVlan ?? undefined),
  col("dhcpOs", (r) => blank(r.dhcpOs)),
  col("comments", (r) => blank(r.comments)),
];

interface ColumnPrefs {
  visibility: VisibilityState;
  order: ColumnOrderState;
  sizing: ColumnSizingState;
  align: Partial<Record<ColId, Align>>;
  sorting: SortingState;
}

const DEFAULT_PREFS: ColumnPrefs = {
  visibility: { mdns: false, smbDomain: false },
  order: ALL_COLS,
  sizing: {},
  align: {},
  sorting: [{ id: "ip", desc: false }],
};

function sanitizePrefs(p: ColumnPrefs): ColumnPrefs {
  const order = completeOrder(Array.isArray(p.order) ? p.order : [], ALL_COLS);
  const sorting = (Array.isArray(p.sorting) ? p.sorting : []).filter((s) => isColId(s.id));
  return {
    visibility: p.visibility && typeof p.visibility === "object" ? p.visibility : {},
    order: [...new Set(order)],
    sizing: p.sizing && typeof p.sizing === "object" ? p.sizing : {},
    align: p.align && typeof p.align === "object" ? p.align : {},
    sorting: sorting.length > 0 ? sorting : DEFAULT_PREFS.sorting,
  };
}

function resolve<T>(u: Updater<T>, prev: T): T {
  return typeof u === "function" ? (u as (p: T) => T)(prev) : u;
}

export interface DeviceTableProps {
  rows: DeviceRow[];
  selectedKey: string | null;
  onSelect: (key: string) => void;
  onOpenDetails: (key: string) => void;
  editing: { key: string; field: EditField } | null;
  onStartEdit: (key: string, field: EditField) => void;
  onCommitEdit: (key: string, field: EditField, value: string) => void;
  onCancelEdit: () => void;
  onRowMenu: (row: DeviceRow, x: number, y: number) => void;
  onDeleteRow: (key: string) => void;
  onCopyIp: (row: DeviceRow) => void;
  empty: ReactNode;
  /** Bumped by the parent to move keyboard focus into the grid. */
  focusToken: number;
  /** Drives the automatic visibility of the latency / web columns. */
  autoColumns: AutoColumns;
  /** Visible rows changed (for live latency): sorted row count, IP lookup and visible range. */
  onViewport?: (count: number, ipAt: (i: number) => string | undefined, start: number, end: number) => void;
}

interface VisibleCol {
  id: ColId;
  width: number;
  align: Align;
}

export function DeviceTable(props: DeviceTableProps) {
  const { rows, selectedKey, onSelect, onOpenDetails, editing, onStartEdit, onRowMenu, onDeleteRow, onCopyIp } = props;
  const [prefsRaw, setPrefs] = usePersistentState<ColumnPrefs>("sweepr.columns.v1", DEFAULT_PREFS);
  const prefs = useMemo(() => sanitizePrefs(prefsRaw), [prefsRaw]);
  const { liveLatency, webTitle: autoTitle, certExpires: autoCert, deviceKind: aKind, modelFw: aModel, poe: aPoe, voiceVlan: aVoice, dhcpOs: aDhcp } =
    props.autoColumns;
  const editField = editing?.field ?? null;
  const visibility = useMemo(() => {
    const v = effectiveVisibility(prefs.visibility, {
      liveLatency,
      webTitle: autoTitle,
      certExpires: autoCert,
      deviceKind: aKind,
      modelFw: aModel,
      poe: aPoe,
      voiceVlan: aVoice,
      dhcpOs: aDhcp,
    });
    // F2 / ⇧F2 on a hidden Hostname / Comments column: show it while the edit lasts.
    return editField !== null && v[editField] === false ? { ...v, [editField]: true } : v;
  }, [prefs.visibility, liveLatency, autoTitle, autoCert, aKind, aModel, aPoe, aVoice, aDhcp, editField]);
  const [headerMenu, setHeaderMenu] = useState<{ x: number; y: number; colId: ColId | null } | null>(null);
  const [dragOver, setDragOver] = useState<ColId | null>(null);

  // The IP column fits the longest address (IPv6) until the user resizes it.
  const ipAuto = useMemo(() => autoIpWidth(rows), [rows]);
  const sizing = useMemo(() => (prefs.sizing.ip !== undefined ? prefs.sizing : { ...prefs.sizing, ip: ipAuto }), [prefs.sizing, ipAuto]);
  const table = useReactTable<DeviceRow>({
    data: rows,
    columns: COLUMNS,
    getRowId: (r) => r.key,
    state: {
      sorting: prefs.sorting,
      columnVisibility: visibility,
      columnOrder: prefs.order,
      columnSizing: sizing,
    },
    onSortingChange: (u) => setPrefs((p) => ({ ...p, sorting: resolve(u, sanitizePrefs(p).sorting) })),
    onColumnVisibilityChange: (u) => setPrefs((p) => ({ ...p, visibility: resolve(u, p.visibility ?? {}) })),
    onColumnOrderChange: (u) => setPrefs((p) => ({ ...p, order: resolve(u, sanitizePrefs(p).order) })),
    onColumnSizingChange: (u) => setPrefs((p) => ({ ...p, sizing: resolve(u, p.sizing ?? {}) })),
    columnResizeMode: "onChange",
    enableColumnResizing: true,
    enableSortingRemoval: false,
    enableMultiSort: true,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  const sortedRows = table.getRowModel().rows;
  const visibleLeaf = table.getVisibleLeafColumns();
  const colLayout: VisibleCol[] = useMemo(
    () =>
      visibleLeaf.map((c) => {
        const id = c.id as ColId;
        return { id, width: c.getSize(), align: prefs.align[id] ?? COL_META[id].align };
      }),
    // getSize() depends on sizing; visibleLeaf identity changes with visibility/order.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [visibleLeaf, sizing, prefs.align, table.getState().columnSizingInfo],
  );
  const totalWidth = colLayout.reduce((n, c) => n + c.width, 0);

  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: sortedRows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_H,
    overscan: 16,
    paddingStart: HEADER_H,
    scrollPaddingStart: HEADER_H,
  });

  const selectedIndex = useMemo(() => {
    if (selectedKey === null) return -1;
    return sortedRows.findIndex((r) => r.id === selectedKey);
  }, [sortedRows, selectedKey]);

  // Bring a selection made elsewhere (neighbors view, search) into view, once per change.
  const lastScrolled = useRef<string | null>(null);
  useEffect(() => {
    if (selectedKey === null || selectedKey === lastScrolled.current || selectedIndex < 0) return;
    lastScrolled.current = selectedKey;
    virtualizer.scrollToIndex(selectedIndex, { align: "auto" });
  }, [selectedKey, selectedIndex, virtualizer]);

  useEffect(() => {
    if (props.focusToken > 0) scrollRef.current?.focus();
  }, [props.focusToken]);

  // Report the visible rows (live latency monitors follow them).
  const onViewport = props.onViewport;
  const rangeStart = virtualizer.range?.startIndex ?? 0;
  const rangeEnd = virtualizer.range?.endIndex ?? -1;
  useEffect(() => {
    if (!onViewport) return;
    onViewport(sortedRows.length, (i) => sortedRows[i]?.original.device.ip, rangeStart, rangeEnd);
  }, [onViewport, sortedRows, rangeStart, rangeEnd]);

  // An edit started from the toolbar must have its row rendered (virtualized) to show the editor.
  const editingKey = editing?.key ?? null;
  useEffect(() => {
    if (editingKey === null) return;
    const idx = sortedRows.findIndex((r) => r.id === editingKey);
    if (idx >= 0) virtualizer.scrollToIndex(idx, { align: "auto" });
    // Only when a new edit starts, not on every streamed update.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [editingKey]);

  const selectIndex = useCallback(
    (i: number) => {
      const idx = Math.max(0, Math.min(sortedRows.length - 1, i));
      const r = sortedRows[idx];
      if (!r) return;
      lastScrolled.current = r.id;
      onSelect(r.id);
      virtualizer.scrollToIndex(idx, { align: "auto" });
    },
    [sortedRows, onSelect, virtualizer],
  );

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>): void => {
    if (e.target !== e.currentTarget) return; // typing in an inline editor
    const page = Math.max(1, Math.floor((scrollRef.current?.clientHeight ?? 400) / ROW_H) - 2);
    const cur = selectedIndex;
    const sel = cur >= 0 ? sortedRows[cur] : undefined;
    const mod = e.metaKey || e.ctrlKey;
    switch (e.key) {
      case "ArrowDown":
        selectIndex(cur < 0 ? 0 : cur + 1);
        break;
      case "ArrowUp":
        selectIndex(cur < 0 ? 0 : cur - 1);
        break;
      case "PageDown":
        selectIndex(cur + page);
        break;
      case "PageUp":
        selectIndex(cur - page);
        break;
      case "Home":
        selectIndex(0);
        break;
      case "End":
        selectIndex(sortedRows.length - 1);
        break;
      case "Enter":
        if (sel) onOpenDetails(sel.id);
        break;
      case "F2":
        if (sel) onStartEdit(sel.id, e.shiftKey ? "comments" : "hostname");
        break;
      case "Delete":
      case "Backspace":
        if (sel) {
          onDeleteRow(sel.id);
          // Keep the cursor on the same visual position.
          const next = sortedRows[cur + 1] ?? sortedRows[cur - 1];
          if (next) onSelect(next.id);
        }
        break;
      case "ContextMenu":
      case "F10":
        if (e.key === "F10" && !e.shiftKey) return;
        if (sel) {
          const el = scrollRef.current?.querySelector<HTMLElement>(`[data-key="${CSS.escape(sel.id)}"]`);
          const r = el?.getBoundingClientRect();
          onRowMenu(sel.original, (r?.left ?? 100) + 40, (r?.bottom ?? 100) - 4);
        }
        break;
      case "c":
        if (mod && sel) onCopyIp(sel.original);
        else return;
        break;
      default:
        return;
    }
    e.preventDefault();
  };

  // --- header menu ------------------------------------------------------------------------------

  const openHeaderMenu = (e: MouseEvent, colId: ColId | null): void => {
    e.preventDefault();
    setHeaderMenu({ x: e.clientX, y: e.clientY, colId });
  };

  // Built on every render so check marks stay live while the menu is open.
  const headerMenuItems = (colId: ColId | null): MenuItem[] => {
    const items: MenuItem[] = [];
    if (colId) {
      const align = prefs.align[colId] ?? COL_META[colId].align;
      const setAlign = (a: Align) => () => setPrefs((p) => ({ ...p, align: { ...(p.align ?? {}), [colId]: a } }));
      items.push(
        { kind: "header", label: `“${COL_META[colId].label}” alignment` },
        { kind: "check", label: "Align Left", checked: align === "left", onSelect: setAlign("left") },
        { kind: "check", label: "Align Center", checked: align === "center", onSelect: setAlign("center") },
        { kind: "check", label: "Align Right", checked: align === "right", onSelect: setAlign("right") },
        { kind: "separator" },
      );
    }
    items.push({ kind: "header", label: "Columns" });
    const visibleCount = table.getVisibleLeafColumns().length;
    for (const id of prefs.order as ColId[]) {
      const column = table.getColumn(id);
      if (!column) continue;
      const visible = column.getIsVisible();
      items.push({
        kind: "check",
        label: COL_META[id].label,
        checked: visible,
        keepOpen: true,
        disabled: visible && visibleCount <= 1,
        // Stored explicitly so it overrides the automatic default.
        onSelect: () => setPrefs((p) => ({ ...p, visibility: { ...(p.visibility ?? {}), [id]: !visible } })),
      });
    }
    items.push(
      { kind: "separator" },
      { kind: "item", label: "Reset Columns", icon: RotateCw, onSelect: () => setPrefs({ ...DEFAULT_PREFS }) },
    );
    return items;
  };

  const closeHeaderMenu = useCallback(() => setHeaderMenu(null), []);

  const moveColumn = (from: ColId, to: ColId): void => {
    if (from === to) return;
    const order = [...prefs.order].filter((c) => c !== from);
    order.splice(order.indexOf(to), 0, from);
    table.setColumnOrder(order);
  };

  const headers = table.getHeaderGroups()[0]?.headers ?? [];
  const items = virtualizer.getVirtualItems();
  const sortState = prefs.sorting;

  return (
    <div className="relative flex min-h-0 min-w-0 flex-1 flex-col">
      <div
        ref={scrollRef}
        role="grid"
        aria-label="Discovered devices"
        aria-rowcount={sortedRows.length + 1}
        aria-colcount={colLayout.length}
        aria-multiselectable={false}
        aria-activedescendant={selectedKey !== null && selectedIndex >= 0 ? `row-${selectedIndex}` : undefined}
        tabIndex={0}
        onKeyDown={onKeyDown}
        className="group/grid relative min-h-0 flex-1 overflow-auto bg-bg focus-visible:outline-none"
      >
        <div style={{ width: totalWidth, minWidth: "100%", height: virtualizer.getTotalSize(), position: "relative" }}>
          {/* Sticky header */}
          <div
            role="row"
            aria-rowindex={1}
            className="sticky top-0 z-10 flex border-b border-line bg-chrome"
            style={{ height: HEADER_H }}
            onContextMenu={(e) => openHeaderMenu(e, null)}
          >
            {headers.map((h) => {
              const id = h.column.id as ColId;
              const meta = COL_META[id];
              const sorted = h.column.getIsSorted();
              const sortIdx = sortState.length > 1 ? sortState.findIndex((s) => s.id === id) : -1;
              const align = prefs.align[id] ?? meta.align;
              return (
                <div
                  key={h.id}
                  role="columnheader"
                  aria-sort={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : "none"}
                  title={`${meta.label} — click to sort, right-click for options, drag to reorder`}
                  draggable
                  onDragStart={(e) => {
                    e.dataTransfer.setData("text/x-sweepr-col", id);
                    e.dataTransfer.effectAllowed = "move";
                  }}
                  onDragOver={(e) => {
                    if (e.dataTransfer.types.includes("text/x-sweepr-col")) {
                      e.preventDefault();
                      setDragOver(id);
                    }
                  }}
                  onDragLeave={() => setDragOver((d) => (d === id ? null : d))}
                  onDrop={(e) => {
                    e.preventDefault();
                    setDragOver(null);
                    const from = e.dataTransfer.getData("text/x-sweepr-col");
                    if (isColId(from)) moveColumn(from, id);
                  }}
                  onContextMenu={(e) => {
                    e.stopPropagation();
                    openHeaderMenu(e, id);
                  }}
                  onClick={h.column.getToggleSortingHandler()}
                  className={cx(
                    "group/h relative flex shrink-0 items-center gap-1 border-r border-line-soft px-2 text-[11.5px] font-medium text-muted select-none hover:bg-chrome-2",
                    sorted && "text-fg",
                    dragOver === id && "shadow-[inset_2px_0_0_var(--accent)]",
                    align === "center" && "justify-center",
                    align === "right" && "flex-row-reverse",
                  )}
                  style={{ width: h.getSize() }}
                >
                  <span className="truncate">{meta.label}</span>
                  {sorted === "asc" && <ArrowUp size={11} strokeWidth={2} aria-hidden className="shrink-0" />}
                  {sorted === "desc" && <ArrowDown size={11} strokeWidth={2} aria-hidden className="shrink-0" />}
                  {sortIdx >= 0 && <span className="text-[9px] text-faint">{sortIdx + 1}</span>}
                  <div
                    role="separator"
                    aria-orientation="vertical"
                    aria-label={`Resize ${meta.label}`}
                    onMouseDown={(e) => {
                      e.stopPropagation();
                      h.getResizeHandler()(e);
                    }}
                    onTouchStart={h.getResizeHandler()}
                    onClick={(e) => e.stopPropagation()}
                    onDoubleClick={(e) => {
                      e.stopPropagation();
                      h.column.resetSize();
                    }}
                    draggable={false}
                    onDragStart={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                    }}
                    className={cx(
                      "absolute top-0 right-[-3px] z-10 h-full w-[6px] cursor-col-resize",
                      h.column.getIsResizing() ? "bg-accent/60" : "hover:bg-accent/30",
                    )}
                  />
                </div>
              );
            })}
            <div className="flex-1" />
          </div>

          {items.map((vi) => {
            const row = sortedRows[vi.index];
            if (!row) return null;
            return (
              <DeviceRowView
                key={row.id}
                index={vi.index}
                start={vi.start}
                row={row.original}
                cols={colLayout}
                width={totalWidth}
                selected={row.id === selectedKey}
                editingField={editing && editing.key === row.id ? editing.field : null}
                onSelect={onSelect}
                onOpenDetails={onOpenDetails}
                onStartEdit={onStartEdit}
                onCommitEdit={props.onCommitEdit}
                onCancelEdit={props.onCancelEdit}
                onRowMenu={onRowMenu}
              />
            );
          })}
        </div>
        {sortedRows.length === 0 && (
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center pt-6">
            <div className="pointer-events-auto">{props.empty}</div>
          </div>
        )}
      </div>
      {headerMenu && (
        <ContextMenu
          menu={{ x: headerMenu.x, y: headerMenu.y, items: headerMenuItems(headerMenu.colId), label: "Column options" }}
          onClose={closeHeaderMenu}
        />
      )}
    </div>
  );
}

// --- rows -----------------------------------------------------------------------------------------

interface RowViewProps {
  index: number;
  start: number;
  row: DeviceRow;
  cols: VisibleCol[];
  width: number;
  selected: boolean;
  editingField: EditField | null;
  onSelect: (key: string) => void;
  onOpenDetails: (key: string) => void;
  onStartEdit: (key: string, field: EditField) => void;
  onCommitEdit: (key: string, field: EditField, value: string) => void;
  onCancelEdit: () => void;
  onRowMenu: (row: DeviceRow, x: number, y: number) => void;
}

const DeviceRowView = memo(function DeviceRowView(p: RowViewProps) {
  const { row, selected } = p;
  return (
    <div
      role="row"
      id={`row-${p.index}`}
      data-key={row.key}
      aria-rowindex={p.index + 2}
      aria-selected={selected}
      onMouseDown={(e) => {
        if (e.button === 0 || e.button === 2) p.onSelect(row.key);
      }}
      onDoubleClick={() => p.onOpenDetails(row.key)}
      onContextMenu={(e) => {
        e.preventDefault();
        p.onSelect(row.key);
        p.onRowMenu(row, e.clientX, e.clientY);
      }}
      className={cx(
        "absolute top-0 left-0 flex items-center",
        selected
          ? "bg-row-sel-blur group-focus-within/grid:bg-row-sel group-focus-within/grid:text-row-sel-fg"
          : p.index % 2 === 1
            ? "bg-row-alt hover:bg-row-hover"
            : "bg-bg hover:bg-row-hover",
      )}
      style={{ height: ROW_H, width: p.width, minWidth: "100%", transform: `translateY(${p.start}px)` }}
    >
      {p.cols.map((c) => (
        <div
          key={c.id}
          role="gridcell"
          className={cx(
            "flex h-full shrink-0 items-center overflow-hidden px-2",
            c.align === "center" && "justify-center text-center",
            c.align === "right" && "justify-end text-right",
            COL_META[c.id].mono && "font-mono text-[11.5px] tabular",
          )}
          style={{ width: c.width }}
          onDoubleClick={
            c.id === "hostname" || c.id === "comments"
              ? (e) => {
                  e.stopPropagation();
                  p.onStartEdit(row.key, c.id as EditField);
                }
              : undefined
          }
        >
          {p.editingField !== null && c.id === p.editingField ? (
            <CellEditor
              initial={c.id === "hostname" ? row.hostname : row.comments}
              label={c.id === "hostname" ? "Hostname" : "Comments"}
              onCommit={(v) => p.onCommitEdit(row.key, p.editingField as EditField, v)}
              onCancel={p.onCancelEdit}
            />
          ) : (
            <CellContent id={c.id} row={row} selected={selected} width={c.width} />
          )}
        </div>
      ))}
    </div>
  );
});

/**
 * DHCP / IPv6 RA badges in the role cell: compact, the rest folded into "+N". A badge that
 * does not fit wraps onto a hidden second line instead of being cut in half (the cell's
 * tooltip lists them).
 */
function RoleBadges({ badges, selected }: { badges: NetBadge[]; selected: boolean }) {
  const first = badges[0];
  if (!first) return null;
  const rest = badges.slice(1);
  return (
    <span className="-ml-1 flex h-[16px] min-w-0 shrink flex-wrap items-center gap-x-1 overflow-hidden">
      {/* Zero-width first item: a lone badge that does not fit can still wrap out of view. */}
      <span className="h-[16px] w-0" aria-hidden />
      <MiniBadge label={first.short} title={first.title} inherit={selected} />
      {rest.length > 0 && <MiniBadge label={`+${rest.length}`} title={rest.map((b) => `${b.label}: ${b.title}`).join("\n")} inherit={selected} />}
    </span>
  );
}

function Faint({ selected, children }: { selected: boolean; children: ReactNode }) {
  return <span className={cx(!selected && "text-faint", selected && "opacity-60")}>{children}</span>;
}

function CellContent({ id, row, selected, width }: { id: ColId; row: DeviceRow; selected: boolean; width: number }) {
  const d = row.device;
  const text = (v: string | null | undefined) =>
    v ? (
      <span className="truncate" title={v}>
        {v}
      </span>
    ) : null;
  switch (id) {
    case "ip":
      return (
        <span className="flex min-w-0 items-center gap-1" title={[d.ip, ...d.extraIps].join("\n")}>
          {/* The address keeps its room: the "+N" badge gives way first (the tooltip lists all). */}
          <span className="min-w-0 truncate">{d.ip}</span>
          {d.extraIps.length > 0 && (
            <span
              className={cx(
                "min-w-0 shrink-[100] overflow-hidden rounded px-1 font-sans text-[9.5px] whitespace-nowrap",
                selected ? "bg-white/20" : "bg-chrome-2 text-muted",
              )}
            >
              +{d.extraIps.length}
            </span>
          )}
        </span>
      );
    case "mac":
      return d.mac ? text(d.mac) : <Faint selected={selected}>—</Faint>;
    case "vlan":
      return d.vlanId !== null ? <span className="tabular">{d.vlanId}</span> : <Faint selected={selected}>—</Faint>;
    case "role":
      return (
        <span
          className="flex min-w-0 flex-1 items-center gap-1.5"
          title={[ROLE_LABEL[d.role], ...netServiceBadges(d).map((b) => b.label)].join(" · ")}
        >
          <RoleIcon role={d.role} inherit={selected} />
          {/* The role label always stays; compact badges give way (clipped) before it. */}
          <span className="shrink-0">{ROLE_LABEL[d.role]}</span>
          <RoleBadges badges={netServiceBadges(d)} selected={selected} />
          {(d.warnings?.length ?? 0) > 0 && (
            <span
              className={cx("ml-auto flex shrink-0 items-center gap-0.5 text-[10px]", !selected && "text-warn")}
              title={d.warnings.join("\n")}
              aria-label={`${d.warnings.length} warning${d.warnings.length === 1 ? "" : "s"}: ${d.warnings.join("; ")}`}
            >
              <TriangleAlert size={11} strokeWidth={2} aria-hidden />
              {d.warnings.length > 1 && <span className="tabular">{d.warnings.length}</span>}
            </span>
          )}
        </span>
      );
    case "hostname":
      return text(row.hostname);
    case "vendor":
      return text(d.vendor);
    case "switchPort":
      return text(row.switchPort);
    case "dns":
      return text(d.dnsName);
    case "mdns":
      return text(d.mdnsName);
    case "smb":
      return text(d.smbName);
    case "smbDomain":
      return text(d.smbDomain);
    case "ports":
      return text(row.ports);
    case "latency":
      return <LatencyCell ip={d.ip} width={width} selected={selected} />;
    case "loss":
      return <LossCell ip={d.ip} selected={selected} />;
    case "webTitle":
      return text(d.webTitle);
    case "webIdentity":
      return text(d.webIdentity);
    case "certCn":
      return text(d.tlsCert?.subjectCn);
    case "certExpires":
      return <CertExpiresCell row={row} selected={selected} />;
    case "deviceKind": {
      const k = deviceKindOf(d);
      if (!k) return null;
      return (
        <span className="flex min-w-0 items-center gap-1.5" title={row.kind}>
          <KindIcon kind={k} inherit={selected} />
          <span className="truncate">{row.kind}</span>
        </span>
      );
    }
    case "modelFw":
      return text(row.modelFw);
    case "poe":
      return <PoeCell row={row} selected={selected} />;
    case "voiceVlan":
      return d.voiceVlan != null ? <span className="tabular">{d.voiceVlan}</span> : null;
    case "dhcpOs":
      return <DhcpCell row={row} selected={selected} />;
    case "comments":
      return text(row.comments);
  }
}

/** Renders whenever this host's entry changes (store notifications are throttled to ≤ 4/s). */
function LatencyCell({ ip, width, selected }: { ip: string; width: number; selected: boolean }) {
  const e = useLatency(ip);
  if (import.meta.env.DEV) countLatencyRender();
  if (!e) return <Faint selected={selected}>—</Faint>;
  const s = e.stats;
  // Room for "12.3 / 45.6" (about 76 px) plus the cell padding.
  const sparkW = Math.max(0, Math.min(120, width - 96));
  // Few samples yet: widen them instead of a sliver at the right edge (full window = 120 slots).
  const slots = Math.max(30, Math.min(120, e.history.length));
  const lost = s.lastMs === null;
  return (
    <span
      className="flex min-w-0 items-center gap-1.5"
      title={`last ${formatMs(s.lastMs)} ms · avg ${formatMs(s.avgMs)} · min ${formatMs(s.minMs)} · max ${formatMs(s.maxMs)} · jitter ${formatMs(s.jitterMs)} ms · loss ${formatLoss(s.lossPct)} (${s.received}/${s.sent}, ${s.method.toUpperCase()})`}
    >
      {sparkW >= 24 && (
        <span className={cx(!selected && "text-accent")}>
          <Sparkline history={e.history} width={sparkW} height={14} slots={slots} />
        </span>
      )}
      <span className="min-w-0 shrink-0 truncate font-mono text-[11px] tabular">
        {lost ? <span className={cx(!selected && "text-danger")}>lost</span> : formatMs(s.lastMs)}
        <span className={cx(selected ? "opacity-70" : "text-muted")}> / {formatMs(s.avgMs)}</span>
      </span>
    </span>
  );
}

function LossCell({ ip, selected }: { ip: string; selected: boolean }) {
  const e = useLatency(ip);
  if (!e) return <Faint selected={selected}>—</Faint>;
  const tone = lossTone(e.stats.lossPct);
  return <span className={cx("font-mono text-[11px] tabular", !selected && TONE_TEXT[tone])}>{formatLoss(e.stats.lossPct)}</span>;
}

function CertExpiresCell({ row, selected }: { row: DeviceRow; selected: boolean }) {
  const cert = row.device.tlsCert;
  const c = classifyCert(cert, Date.now());
  if (!cert || !c) return null;
  const tone = c.status === "expired" ? "text-danger" : c.status === "expiring" ? "text-warn" : "";
  const Icon = c.status === "expired" ? ShieldX : c.status === "expiring" ? TriangleAlert : null;
  return (
    <span
      className={cx("flex min-w-0 items-center gap-1", !selected && tone)}
      title={`${cert.subjectCn ?? ""} (port ${cert.port}): ${c.text}${c.selfSigned ? ", self-signed" : ""}`}
    >
      {Icon && <Icon size={12} strokeWidth={2} aria-hidden className="shrink-0" />}
      <span className="truncate tabular">{c.date || "—"}</span>
      {c.status !== "ok" && c.days !== null && <span className="shrink-0 text-[10.5px] opacity-80">({c.days < 0 ? "expired" : `${c.days} d`})</span>}
      {c.selfSigned && (
        <span className={cx("ml-auto shrink-0", !selected && "text-muted")} title="Self-signed certificate">
          <ShieldAlert size={12} strokeWidth={1.75} aria-label="self-signed" />
        </span>
      )}
    </span>
  );
}

function PoeCell({ row, selected }: { row: DeviceRow; selected: boolean }) {
  const p = row.device.poe;
  if (!p) return null;
  const w = p.watts ?? p.maxWatts;
  if (w === null) return p.status ? <Faint selected={selected}>{p.status}</Faint> : null;
  const tone = poeTone(p);
  return (
    <span
      className={cx("font-mono text-[11px] tabular", !selected && (p.watts === null ? "text-muted" : TONE_TEXT_CLASS[tone]))}
      title={`PoE: ${poeSummary(p)}${p.watts === null ? " (advertised budget)" : ""}`}
    >
      {p.watts === null ? "≤" : ""}
      {formatWatts(w)}
    </span>
  );
}

const CONF_DOT: Record<string, string> = { high: "bg-ok", medium: "bg-warn", low: "bg-faint" };

function DhcpCell({ row, selected }: { row: DeviceRow; selected: boolean }) {
  const f = row.device.dhcpFingerprint;
  if (!f?.os) return null;
  const conf = f.confidence ?? "";
  return (
    <span
      className="flex min-w-0 items-center gap-1.5"
      title={`${f.os} — ${conf || "unknown"} confidence (DHCP fingerprint, a best-effort guess)${f.vendorClass ? `\nVendor class: ${f.vendorClass}` : ""}`}
    >
      <span
        className={cx("inline-block size-[7px] shrink-0 rounded-full", selected ? "bg-current opacity-70" : (CONF_DOT[conf] ?? "bg-faint"))}
        aria-label={`${conf || "unknown"} confidence`}
      />
      <span className="truncate">{f.os}</span>
    </span>
  );
}

/** Dev-only render counter for performance checks (`window.__sweeprLatencyRenders`). */
function countLatencyRender(): void {
  const w = window as unknown as { __sweeprLatencyRenders?: number };
  w.__sweeprLatencyRenders = (w.__sweeprLatencyRenders ?? 0) + 1;
}

function CellEditor({
  initial,
  label,
  onCommit,
  onCancel,
}: {
  initial: string;
  label: string;
  onCommit: (v: string) => void;
  onCancel: () => void;
}) {
  const [value, setValue] = useState(initial);
  const done = useRef(false);
  return (
    <input
      aria-label={label}
      autoFocus
      value={value}
      maxLength={MAX_OVERRIDE_LEN}
      spellCheck={false}
      onFocus={(e) => e.currentTarget.select()}
      onChange={(e) => setValue(e.target.value)}
      onMouseDown={(e) => e.stopPropagation()}
      onDoubleClick={(e) => e.stopPropagation()}
      onKeyDown={(e) => {
        e.stopPropagation();
        if (e.key === "Enter") {
          done.current = true;
          onCommit(value);
        } else if (e.key === "Escape") {
          done.current = true;
          onCancel();
        }
      }}
      onBlur={() => {
        if (!done.current) onCommit(value);
      }}
      className="h-[19px] w-full min-w-0 rounded-[3px] border border-accent bg-field px-1 font-sans text-[12px] text-fg outline-none"
    />
  );
}
