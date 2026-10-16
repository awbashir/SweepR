// Top toolbar (scan controls) and filter bar (views, role pills, search, row actions).

import { forwardRef, useRef, useState } from "react";
import {
  Activity,
  ChevronDown,
  Download,
  FileChartColumn,
  ScanSearch,
  Ellipsis,
  Eraser,
  FileBraces,
  FileSpreadsheet,
  FileText,
  KeyRound,
  PanelRight,
  Pencil,
  Play,
  Radar,
  Search,
  Square,
  Table2,
  TriangleAlert,
  Network,
  Power,
  X,
} from "lucide-react";
import type { DeviceRole, ExportFormat, InterfaceInfo, ReportFormat } from "../types.ts";
import { ROLE_LABEL } from "../types.ts";
import { interfaceLabel, subnetHint, vlanSelectionFrom, type ScanSettings, type VlanMode } from "../settings.ts";
import { parsePorts, parseRange } from "../lib/parse.ts";
import { LATENCY_INTERVALS } from "../lib/latency.ts";
import { useMinWidth } from "../hooks/useMinWidth.ts";
import { ContextMenu, type MenuState } from "./Menu.tsx";
import { Button, RoleIcon, Select, Separator, TextInput, Toggle, cx } from "./ui.tsx";

export type RoleFilter = "all" | DeviceRole;
export type View = "devices" | "vlans" | "neighbors";
/** How the Devices view is drawn. */
export type DevicesMode = "table" | "topology";

interface ToolbarProps {
  settings: ScanSettings;
  onSettings: (patch: Partial<ScanSettings>) => void;
  interfaces: InterfaceInfo[];
  running: boolean;
  starting: boolean;
  onStart: () => void;
  onStop: () => void;
  onOpenSnmp: () => void;
  onExport: (format: ExportFormat) => void;
  exportCount: number;
  drawerOpen: boolean;
  onToggleDrawer: () => void;
  liveLatency: boolean;
  onLiveLatency: (on: boolean) => void;
  latencyIntervalMs: number;
  onLatencyInterval: (ms: number) => void;
  onWakeByMac: () => void;
  /** Audit report for all `reportCount` devices. */
  onReport: (format: ReportFormat) => void;
  reportCount: number;
  reportBusy: boolean;
}

/** Below this width the latency interval and the Export label fold away (one toolbar row at 1360). */
const COMPACT_MIN = 1440;
/** Below this width the IPv6 / CDP-LLDP toggles move into the "More" menu (one row at 980). */
const NARROW_MIN = 1200;

export function Toolbar(p: ToolbarProps) {
  const s = p.settings;
  const wide = useMinWidth(COMPACT_MIN);
  const roomy = useMinWidth(NARROW_MIN);
  const [exportMenu, setExportMenu] = useState<MenuState | null>(null);
  const exportBtn = useRef<HTMLButtonElement>(null);
  const moreBtn = useRef<HTMLButtonElement>(null);
  const discoveryBtn = useRef<HTMLButtonElement>(null);
  const reportBtn = useRef<HTMLButtonElement>(null);

  // Built on every render so the check marks follow the settings while the menu is open.
  const discoveryItems = (): MenuState["items"] => [
    { kind: "header", label: "Deeper discovery during scans" },
    {
      kind: "check",
      label: "Discover UPnP/WSD/ONVIF/SIP services",
      checked: s.discoverServices,
      keepOpen: true,
      disabled: p.running,
      onSelect: () => p.onSettings({ discoverServices: !s.discoverServices }),
    },
    {
      kind: "check",
      label: "Probe SIP on all hosts",
      checked: s.discoverServices && s.sipAll,
      keepOpen: true,
      disabled: p.running || !s.discoverServices,
      onSelect: () => p.onSettings({ sipAll: !s.sipAll }),
    },
    {
      kind: "check",
      label: "Passive DHCP fingerprinting (needs root)",
      checked: s.dhcpFingerprint,
      keepOpen: true,
      disabled: p.running,
      onSelect: () => p.onSettings({ dhcpFingerprint: !s.dhcpFingerprint }),
    },
    {
      kind: "check",
      label: "Resolve DNS / mDNS / NetBIOS names",
      checked: s.resolveNames,
      keepOpen: true,
      disabled: p.running,
      onSelect: () => p.onSettings({ resolveNames: !s.resolveNames }),
    },
  ];
  const [discoveryAt, setDiscoveryAt] = useState<{ x: number; y: number } | null>(null);
  const openDiscovery = (): void => {
    const r = discoveryBtn.current?.getBoundingClientRect();
    setDiscoveryAt({ x: r ? r.left : 0, y: r ? r.bottom + 4 : 0 });
  };

  const openReport = (): void => {
    const r = reportBtn.current?.getBoundingClientRect();
    setExportMenu({
      x: r ? r.left : 0,
      y: r ? r.bottom + 4 : 0,
      label: "Audit report",
      items: [
        { kind: "header", label: `Audit report · ${p.reportCount.toLocaleString()} device${p.reportCount === 1 ? "" : "s"}` },
        { kind: "item", label: "HTML Report…", icon: FileChartColumn, onSelect: () => p.onReport("html") },
        { kind: "item", label: "PDF Summary…", icon: FileText, onSelect: () => p.onReport("pdf") },
        { kind: "item", label: "JSON Findings…", icon: FileBraces, onSelect: () => p.onReport("json") },
      ],
    });
  };

  const openMore = (): void => {
    const r = moreBtn.current?.getBoundingClientRect();
    setExportMenu({
      x: r ? r.right - 200 : 0,
      y: r ? r.bottom + 4 : 0,
      label: "More actions",
      items: [
        // Controls the toolbar folds away on narrower windows live here instead.
        ...(roomy
          ? []
          : ([
              { kind: "header", label: "Scan" },
              { kind: "check", label: "IPv6 (ICMPv6 / NDP)", checked: s.ipv6, disabled: p.running, onSelect: () => p.onSettings({ ipv6: !s.ipv6 }) },
              {
                kind: "check",
                label: "CDP/LLDP listening",
                checked: s.cdpLldp,
                disabled: p.running,
                onSelect: () => p.onSettings({ cdpLldp: !s.cdpLldp }),
              },
              { kind: "separator" },
            ] satisfies MenuState["items"])),
        ...(wide
          ? []
          : ([
              { kind: "header", label: "Live latency interval" },
              ...LATENCY_INTERVALS.map(
                (ms): MenuState["items"][number] => ({
                  kind: "check",
                  label: `Every ${ms / 1000} s`,
                  checked: p.latencyIntervalMs === ms,
                  onSelect: () => p.onLatencyInterval(ms),
                }),
              ),
              { kind: "separator" },
            ] satisfies MenuState["items"])),
        { kind: "item", label: "Wake by MAC…", icon: Power, onSelect: p.onWakeByMac },
      ],
    });
  };
  const iface = p.interfaces.find((i) => i.name === s.iface) ?? p.interfaces.find((i) => i.isDefault);
  const hint = subnetHint(iface);
  const range = parseRange(s.range);
  const vlan = vlanSelectionFrom(s);
  const ports = parsePorts(s.ports);
  const listMode = s.vlanMode === "list" || s.vlanMode === "untagged_and_list";

  const openExport = (): void => {
    const r = exportBtn.current?.getBoundingClientRect();
    setExportMenu({
      x: r ? r.left : 0,
      y: r ? r.bottom + 4 : 0,
      label: "Export",
      items: [
        { kind: "header", label: `Export ${p.exportCount.toLocaleString()} device${p.exportCount === 1 ? "" : "s"}` },
        { kind: "item", label: "CSV…", icon: FileText, onSelect: () => p.onExport("csv"), disabled: p.exportCount === 0 },
        {
          kind: "item",
          label: "Excel Workbook (XLSX)…",
          icon: FileSpreadsheet,
          onSelect: () => p.onExport("xlsx"),
          disabled: p.exportCount === 0,
        },
        { kind: "item", label: "JSON…", icon: FileBraces, onSelect: () => p.onExport("json"), disabled: p.exportCount === 0 },
      ],
    });
  };

  return (
    <div className="flex flex-wrap items-center gap-1.5 border-b border-line bg-chrome px-2 py-1.5">
      {p.running ? (
        <Button variant="danger" icon={Square} onClick={p.onStop} className={cx(roomy ? "w-[114px]" : "w-[104px]", "justify-center")} title="Stop the running job (⌘.)">
          Stop
        </Button>
      ) : (
        <Button
          variant="primary"
          icon={Play}
          onClick={p.onStart}
          disabled={p.starting}
          className={cx(roomy ? "w-[114px]" : "w-[104px]", "justify-center")}
          title="Start scanning (⌘R)"
        >
          Start SweepR
        </Button>
      )}
      <Separator />
      <label className="sr-only" htmlFor="tb-iface">
        Interface
      </label>
      <Select
        id="tb-iface"
        value={s.iface}
        onChange={(e) => p.onSettings({ iface: e.target.value })}
        className={roomy ? "w-[180px]" : "w-[140px]"}
        title="Network interface"
        disabled={p.running}
      >
        <option value="">Default interface{iface && iface.isDefault ? ` (${iface.name})` : ""}</option>
        {p.interfaces.map((i) => (
          <option key={i.name} value={i.name}>
            {interfaceLabel(i)}
          </option>
        ))}
      </Select>
      <label
        className={cx("flex flex-1 items-center gap-1.5", roomy ? "min-w-[130px]" : "min-w-[88px]")}
        title="CIDR, start-end range or comma list; empty scans the interface subnet"
      >
        <span className="hidden whitespace-nowrap text-muted min-[1680px]:inline">Scan from</span>
        <TextInput
          value={s.range}
          onChange={(e) => p.onSettings({ range: e.target.value })}
          placeholder={hint ? `${hint} (interface subnet)` : "10.0.0.1 to 10.0.0.254 or 10.0.0.0/24"}
          invalid={!range.ok}
          aria-label="IP range"
          className="flex-1"
          disabled={p.running}
          title={!range.ok ? range.error : range.value.count > 0 ? `${range.value.count.toLocaleString()} addresses` : undefined}
        />
      </label>
      <Select
        value={s.vlanMode}
        onChange={(e) => p.onSettings({ vlanMode: e.target.value as VlanMode })}
        aria-label="VLAN selection"
        className={roomy ? "w-[150px]" : "w-[120px]"}
        disabled={p.running}
      >
        <option value="untagged">Untagged</option>
        <option value="list">VLAN list (802.1Q)</option>
        <option value="untagged_and_list">Untagged + VLANs</option>
        <option value="auto_detect">Auto-Detect VLANs</option>
      </Select>
      {listMode && (
        <TextInput
          value={s.vlanIds}
          onChange={(e) => p.onSettings({ vlanIds: e.target.value })}
          placeholder="VLAN 10, 20, 30-35"
          aria-label="VLAN IDs"
          invalid={!vlan.ok}
          title={!vlan.ok ? vlan.error : undefined}
          className="w-[100px]"
          disabled={p.running}
        />
      )}
      <TextInput
        value={s.ports}
        onChange={(e) => p.onSettings({ ports: e.target.value })}
        placeholder="TCP ports"
        aria-label="TCP ports to probe"
        invalid={!ports.ok}
        title={!ports.ok ? ports.error : `TCP ports probed per device (${ports.value.length})`}
        className={roomy ? "w-[100px]" : "w-[84px]"}
        disabled={p.running}
      />
      {roomy && (
        <>
          <Toggle checked={s.ipv6} onChange={(v) => p.onSettings({ ipv6: v })} label="IPv6" title="ICMPv6 / NDP neighbor discovery" disabled={p.running} />
          <Toggle
            checked={s.cdpLldp}
            onChange={(v) => p.onSettings({ cdpLldp: v })}
            label="CDP/LLDP"
            title="Listen for CDP and LLDP advertisements while scanning"
            disabled={p.running}
          />
        </>
      )}
      {s.snmpEnabled && s.snmpCredentialsMissing ? (
        <Button
          icon={TriangleAlert}
          onClick={p.onOpenSnmp}
          className="text-warn"
          title="SNMP credentials are not stored between sessions: re-enter them. Until then scans run without SNMP."
          aria-label="SNMP settings: re-enter credentials"
        >
          SNMP<span className="hidden min-[1500px]:inline">: re-enter credentials</span>
        </Button>
      ) : (
        <Button icon={KeyRound} onClick={p.onOpenSnmp} pressed={s.snmpEnabled} title="SNMP settings">
          SNMP{s.snmpEnabled ? ` ${s.snmp.version}` : ""}
        </Button>
      )}
      <Button
        ref={discoveryBtn}
        icon={ScanSearch}
        onClick={openDiscovery}
        aria-haspopup="menu"
        aria-expanded={discoveryAt !== null}
        aria-label="Discovery options"
        title={`Discovery options: services ${s.discoverServices ? "on" : "off"}${s.discoverServices && s.sipAll ? " (SIP on all hosts)" : ""}, DHCP fingerprinting ${s.dhcpFingerprint ? "on" : "off"}`}
      >
        <span className="hidden min-[1760px]:inline">Discovery</span>
        <ChevronDown size={11} aria-hidden className="-ml-0.5 text-muted" />
      </Button>
      {roomy && <Separator />}
      <div
        className="flex items-center rounded-[6px]"
        title={`Ping the visible, selected and pinned devices continuously (every ${p.latencyIntervalMs / 1000} s)`}
      >
        <Toggle
          checked={p.liveLatency}
          onChange={p.onLiveLatency}
          label={
            <span className="flex items-center gap-1">
              <Activity size={13} strokeWidth={1.75} aria-hidden className={p.liveLatency ? "text-accent" : "text-muted"} />
              <span className={roomy ? undefined : "sr-only"}>Live latency</span>
            </span>
          }
        />
        {wide && (
          <Select
            value={p.latencyIntervalMs}
            onChange={(e) => p.onLatencyInterval(Number(e.target.value))}
            aria-label="Latency probe interval"
            title="Probe interval"
            disabled={!p.liveLatency}
            className="w-[64px]"
          >
            {LATENCY_INTERVALS.map((ms) => (
              <option key={ms} value={ms}>
                {ms / 1000} s
              </option>
            ))}
          </Select>
        )}
      </div>
      <Separator />
      <Button
        ref={exportBtn}
        icon={Download}
        onClick={openExport}
        aria-haspopup="menu"
        aria-expanded={exportMenu?.label === "Export"}
        aria-label="Export"
        title="Export results"
      >
        {wide && "Export"}
      </Button>
      <span
        className="inline-flex"
        title={p.reportCount === 0 ? "Scan first: the audit report needs discovered devices" : "Audit report (HTML, PDF or JSON)"}
      >
        <Button
          ref={reportBtn}
          icon={FileChartColumn}
          onClick={openReport}
          disabled={p.reportCount === 0 || p.reportBusy}
          aria-haspopup="menu"
          aria-expanded={exportMenu?.label === "Audit report"}
          aria-label="Report…"
        >
          <span className="hidden min-[1680px]:inline">Report…</span>
        </Button>
      </span>
      <Button
        ref={moreBtn}
        variant="ghost"
        icon={Ellipsis}
        onClick={openMore}
        aria-haspopup="menu"
        aria-label="More actions"
        title="More actions"
      />
      <Button
        variant="ghost"
        icon={PanelRight}
        pressed={p.drawerOpen}
        onClick={p.onToggleDrawer}
        aria-label="Toggle details drawer"
        title="Details drawer (⌘I)"
      />
      {exportMenu && <ContextMenu menu={exportMenu} onClose={() => setExportMenu(null)} />}
      {discoveryAt && (
        <ContextMenu
          menu={{ x: discoveryAt.x, y: discoveryAt.y, label: "Discovery options", items: discoveryItems() }}
          onClose={() => setDiscoveryAt(null)}
        />
      )}
    </div>
  );
}

interface FilterBarProps {
  view: View;
  onView: (v: View) => void;
  devicesMode: DevicesMode;
  onDevicesMode: (m: DevicesMode) => void;
  counts: { devices: number; vlans: number; neighbors: number };
  roleFilter: RoleFilter;
  onRoleFilter: (r: RoleFilter) => void;
  roleCounts: Record<DeviceRole, number>;
  search: string;
  onSearch: (s: string) => void;
  canEdit: boolean;
  onEditHostname: () => void;
  onClear: () => void;
  canClear: boolean;
  onPassiveDiscovery: () => void;
  running: boolean;
}

const PILLS: Array<{ id: RoleFilter; label: string }> = [
  { id: "all", label: "All" },
  { id: "switch", label: "Switches" },
  { id: "firewall", label: "Firewalls" },
  { id: "access_point", label: "APs" },
  { id: "router", label: "Routers" },
  { id: "host", label: "Hosts" },
];

export const FilterBar = forwardRef<HTMLInputElement, FilterBarProps>(function FilterBar(p, searchRef) {
  const total = Object.values(p.roleCounts).reduce((a, b) => a + b, 0);
  return (
    <div className="flex flex-wrap items-center gap-1.5 border-b border-line bg-panel px-2 py-1">
      <div role="tablist" aria-label="Views" className="flex rounded-[7px] border border-line bg-chrome-2 p-[2px]">
        {(
          [
            ["devices", "Devices", p.counts.devices],
            ["vlans", "VLANs", p.counts.vlans],
            ["neighbors", "Neighbors", p.counts.neighbors],
          ] as const
        ).map(([id, label, n]) => (
          <button
            key={id}
            role="tab"
            type="button"
            aria-selected={p.view === id}
            onClick={() => p.onView(id)}
            className={cx(
              "h-[20px] rounded-[5px] px-2.5 text-[12px] whitespace-nowrap",
              p.view === id ? "bg-field font-medium shadow-[0_0.5px_2px_rgb(0_0_0/0.18)]" : "text-muted hover:text-fg",
            )}
          >
            {label} <span className="tabular text-muted">{n.toLocaleString()}</span>
          </button>
        ))}
      </div>
      {p.view === "devices" && (
        <div role="radiogroup" aria-label="Devices layout" className="flex rounded-[7px] border border-line bg-chrome-2 p-[2px]">
          {(
            [
              ["table", "Table", Table2],
              ["topology", "Topology", Network],
            ] as const
          ).map(([id, label, Icon]) => (
            <button
              key={id}
              type="button"
              role="radio"
              aria-checked={p.devicesMode === id}
              onClick={() => p.onDevicesMode(id)}
              title={`${label} (⌘T toggles)`}
              aria-label={label}
              className={cx(
                "flex h-[20px] items-center gap-1 rounded-[5px] px-2 text-[12px] whitespace-nowrap",
                p.devicesMode === id ? "bg-field font-medium shadow-[0_0.5px_2px_rgb(0_0_0/0.18)]" : "text-muted hover:text-fg",
              )}
            >
              <Icon size={13} strokeWidth={1.75} aria-hidden />
              <span className="hidden min-[1600px]:inline">{label}</span>
            </button>
          ))}
        </div>
      )}
      {p.view === "devices" && (
        <div role="radiogroup" aria-label="Filter by device role" className="flex flex-wrap items-center gap-1">
          {PILLS.map((pill) => {
            const n = pill.id === "all" ? total : p.roleCounts[pill.id];
            const active = p.roleFilter === pill.id;
            return (
              <button
                key={pill.id}
                type="button"
                role="radio"
                aria-checked={active}
                onClick={() => p.onRoleFilter(pill.id)}
                title={pill.id === "all" ? "All devices" : ROLE_LABEL[pill.id]}
                aria-label={`${pill.label} ${n.toLocaleString()}`}
                className={cx(
                  "flex h-[22px] items-center gap-1 rounded-full border px-2 text-[11.5px] whitespace-nowrap",
                  active ? "border-accent bg-accent text-accent-fg" : "border-line bg-field hover:bg-chrome-2",
                  !active && n === 0 && pill.id !== "all" && "text-faint",
                )}
              >
                {pill.id !== "all" && <RoleIcon role={pill.id} size={12} inherit={active} />}
                {/* Narrow windows: the role icon stands for the label (one filter row at 980 px). */}
                <span className={pill.id === "all" ? undefined : "hidden min-[1200px]:inline"}>{pill.label}</span>
                <span className={cx("tabular", active ? "text-accent-fg/80" : "text-muted")}>{n.toLocaleString()}</span>
              </button>
            );
          })}
        </div>
      )}
      {p.view === "vlans" && (
        <Button icon={Radar} onClick={p.onPassiveDiscovery} disabled={p.running} title="Listen passively for 802.1Q tags, VTP, DTP, CDP and LLDP">
          Passive VLAN Discovery
        </Button>
      )}
      <div className="flex-1" />
      <div className="relative flex items-center">
        <Search size={13} className="pointer-events-none absolute left-2 text-muted" aria-hidden />
        <TextInput
          ref={searchRef}
          type="search"
          value={p.search}
          onChange={(e) => p.onSearch(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape" && p.search !== "") {
              e.stopPropagation();
              p.onSearch("");
            }
          }}
          placeholder="Search (⌘F)"
          aria-label="Search devices"
          className="w-[180px] pr-6 pl-7"
        />
        {p.search !== "" && (
          <button
            type="button"
            aria-label="Clear search"
            onClick={() => p.onSearch("")}
            className="absolute right-1.5 rounded-full p-0.5 text-muted hover:bg-chrome-2"
          >
            <X size={11} aria-hidden />
          </button>
        )}
      </div>
      <Button
        icon={Pencil}
        onClick={p.onEditHostname}
        disabled={!p.canEdit}
        aria-label="Edit Hostname"
        title="Edit the selected device's hostname (F2)"
      >
        <span className="hidden min-[1440px]:inline">Edit Hostname</span>
      </Button>
      <Button icon={Eraser} onClick={p.onClear} disabled={!p.canClear} aria-label="Clear Results" title="Clear all results">
        <span className="hidden min-[1440px]:inline">Clear Results</span>
      </Button>
    </div>
  );
});
