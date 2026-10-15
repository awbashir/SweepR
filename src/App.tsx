import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import {
  Copy,
  ExternalLink,
  Globe,
  MessageSquare,
  Pencil,
  ScanLine,
  Server,
  ShieldAlert,
  Terminal,
  Trash,
} from "lucide-react";
import { backend, errorMessage } from "./api.ts";
import type { DeviceOverride, ExportFormat, InterfaceInfo } from "./types.ts";
import { ScanStore, exportDevice, type DeviceRow } from "./lib/store.ts";
import { urlHost } from "./lib/ip.ts";
import { formatPorts, parsePorts, vlanSelectionLabel } from "./lib/parse.ts";
import { PORT_PRESETS } from "./lib/ports.ts";
import {
  DEFAULT_SETTINGS,
  DEFAULT_SNMP,
  buildScanConfig,
  persistableSettings,
  snmpForWire,
  subnetHint,
  vlanSelectionFrom,
  type ScanSettings,
} from "./settings.ts";
import { usePersistentState } from "./hooks/usePersistentState.ts";
import { DeviceTable, type EditField } from "./components/DeviceTable.tsx";
import { DetailsDrawer, type PortScanState, type SnmpQueryState } from "./components/DetailsDrawer.tsx";
import { CustomUrlDialog, SnmpDialog } from "./components/Dialogs.tsx";
import { NeighborView, VlanView } from "./components/InfraViews.tsx";
import { ContextMenu, type MenuState } from "./components/Menu.tsx";
import { LogPanel, StatusBar } from "./components/StatusBar.tsx";
import { ToastProvider, useToasts } from "./components/Toasts.tsx";
import { FilterBar, Toolbar, type RoleFilter, type View } from "./components/Toolbar.tsx";
import { Button, Kbd } from "./components/ui.tsx";

/** One store for the app's lifetime; React reads throttled snapshots of it. */
const store = new ScanStore();
let mockNoticeShown = false;

interface UiPrefs {
  drawerOpen: boolean;
  logOpen: boolean;
  portPreset: string;
  customPorts: string;
  discoveryTimeout: number;
  view: View;
  urlTemplate: string;
}

const DEFAULT_UI: UiPrefs = {
  drawerOpen: true,
  logOpen: false,
  portPreset: "common",
  customPorts: "22,80,443,8080,8443",
  discoveryTimeout: 30,
  view: "devices",
  urlTemplate: "http://{ip}:8080/",
};

export default function App() {
  return (
    <ToastProvider>
      <Main />
    </ToastProvider>
  );
}

function Main() {
  const toast = useToasts();
  const snap = useSyncExternalStore(store.subscribe, store.getSnapshot);

  const [rawSettings, setRawSettings] = usePersistentState<ScanSettings>("sweepr.settings.v1", DEFAULT_SETTINGS, persistableSettings);
  const settings = useMemo<ScanSettings>(
    () => ({ ...DEFAULT_SETTINGS, ...rawSettings, snmp: { ...DEFAULT_SNMP, ...rawSettings.snmp } }),
    [rawSettings],
  );
  const patchSettings = useCallback((patch: Partial<ScanSettings>) => setRawSettings((s) => ({ ...s, ...patch })), [setRawSettings]);
  const [ui, setUi] = usePersistentState<UiPrefs>("sweepr.ui.v1", DEFAULT_UI);
  const patchUi = useCallback((patch: Partial<UiPrefs>) => setUi((u) => ({ ...u, ...patch })), [setUi]);

  const [interfaces, setInterfaces] = useState<InterfaceInfo[]>([]);
  const [search, setSearch] = useState("");
  const deferredSearch = useDeferredValue(search);
  const [roleFilter, setRoleFilter] = useState<RoleFilter>("all");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [editing, setEditing] = useState<{ key: string; field: EditField } | null>(null);
  const [rowMenu, setRowMenu] = useState<MenuState | null>(null);
  const [snmpOpen, setSnmpOpen] = useState(false);
  const [customUrlFor, setCustomUrlFor] = useState<DeviceRow | null>(null);
  const [portScans, setPortScans] = useState<Record<string, PortScanState>>({});
  const [snmpQueries, setSnmpQueries] = useState<Record<string, SnmpQueryState>>({});
  const [focusToken, setFocusToken] = useState(0);
  const searchRef = useRef<HTMLInputElement>(null);

  // --- startup: event subscription, interfaces, overrides ---------------------------------------

  useEffect(() => {
    let unlisten: (() => void) | null = null;
    let cancelled = false;
    backend
      .onScanEvent(store.handlePayload)
      .then((un) => {
        if (cancelled) un();
        else unlisten = un;
      })
      .catch((e: unknown) => toast.push("error", "Could not subscribe to scan events", errorMessage(e)));
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [toast]);

  useEffect(() => {
    backend
      .listInterfaces()
      .then((list) => {
        setInterfaces(list);
        setRawSettings((s) => (s.iface !== "" && !list.some((i) => i.name === s.iface) ? { ...s, iface: "" } : s));
      })
      .catch((e: unknown) => toast.push("error", "Could not list network interfaces", errorMessage(e)));
    backend
      .loadOverrides()
      .then((o) => store.setOverrides(o))
      .catch((e: unknown) => toast.push("warn", "Could not load saved hostnames and comments", errorMessage(e)));
    if (backend.isMock && !mockNoticeShown) {
      mockNoticeShown = true;
      store.log("warn", "Running in a browser without the Tauri backend: all data is simulated (mock mode).");
    }
  }, [toast, setRawSettings]);

  // --- derived data -----------------------------------------------------------------------------

  const filtered = useMemo(() => {
    const terms = deferredSearch.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (roleFilter === "all" && terms.length === 0) return snap.rows;
    return snap.rows.filter(
      (r) => (roleFilter === "all" || r.device.role === roleFilter) && terms.every((t) => r.search.includes(t)),
    );
  }, [snap.rows, deferredSearch, roleFilter]);

  const selectedRow = useMemo(
    () => (selectedKey === null ? undefined : snap.rows.find((r) => r.key === selectedKey)),
    [snap.rows, selectedKey],
  );
  const vlanSel = vlanSelectionFrom(settings);
  const vlanLabel = vlanSel.ok ? vlanSelectionLabel(vlanSel.value) : "Invalid VLANs";
  const warnCount = useMemo(() => snap.logs.filter((l) => l.level !== "info").length, [snap.logs]);
  const currentIface = interfaces.find((i) => i.name === settings.iface) ?? interfaces.find((i) => i.isDefault);

  // --- actions -----------------------------------------------------------------------------------

  const startWith = useCallback(
    async (s: ScanSettings) => {
      const built = buildScanConfig(s);
      if (!built.ok) {
        toast.push("error", "Cannot start scan", built.error);
        return;
      }
      store.beginStart("scan");
      store.log(
        "info",
        `Starting scan on ${built.value.config.interface ?? "default interface"}: ${built.value.config.range ?? "interface subnet"}, ${vlanSelectionLabel(built.value.config.vlans)}`,
      );
      try {
        const id = await backend.startScan(built.value.config);
        store.startResolved(id);
      } catch (e) {
        const msg = errorMessage(e);
        store.startFailed(`Scan failed to start: ${msg}`);
        toast.push("error", "Scan failed to start", msg);
      }
    },
    [toast],
  );

  const start = useCallback(() => void startWith(settings), [startWith, settings]);

  const stop = useCallback(async () => {
    try {
      const signalled = await backend.stopScan(snap.scanId ?? undefined);
      if (!signalled) store.log("info", "No running job to stop.");
    } catch (e) {
      toast.push("error", "Could not stop the scan", errorMessage(e));
    }
  }, [snap.scanId, toast]);

  const passiveDiscovery = useCallback(async () => {
    store.beginStart("vlan_discovery");
    try {
      const id = await backend.startVlanDiscovery(settings.iface === "" ? null : settings.iface, ui.discoveryTimeout);
      store.startResolved(id);
    } catch (e) {
      const msg = errorMessage(e);
      store.startFailed(`VLAN discovery failed to start: ${msg}`);
      toast.push("error", "VLAN discovery failed to start", msg);
    }
  }, [settings.iface, ui.discoveryTimeout, toast]);

  const scanVlans = useCallback(
    (ids: number[]) => {
      const next: ScanSettings = { ...settings, vlanMode: "untagged_and_list", vlanIds: formatPorts(ids) };
      patchSettings({ vlanMode: next.vlanMode, vlanIds: next.vlanIds });
      patchUi({ view: "devices" });
      void startWith(next);
    },
    [settings, patchSettings, patchUi, startWith],
  );

  const exportAs = useCallback(
    async (format: ExportFormat) => {
      const devices = filtered.map(exportDevice);
      if (devices.length === 0) return;
      try {
        const path = await backend.exportDevices(devices, format);
        if (path) toast.push("success", `Exported ${devices.length.toLocaleString()} devices`, path);
      } catch (e) {
        toast.push("error", `${format.toUpperCase()} export failed`, errorMessage(e));
      }
    },
    [filtered, toast],
  );

  const commitEdit = useCallback(
    (key: string, field: EditField, value: string) => {
      setEditing(null);
      setFocusToken((n) => n + 1);
      const row = snap.rows.find((r) => r.key === key);
      if (!row) return;
      const v = value.trim();
      if (v === (field === "hostname" ? row.hostname : row.comments)) return;
      const prev: DeviceOverride = snap.overrides[key] ?? {};
      const next = {
        hostname: field === "hostname" ? v || null : (prev.hostname ?? null),
        comments: field === "comments" ? v || null : (prev.comments ?? null),
      };
      store.setOverride(key, next);
      backend.saveOverride(key, next.hostname, next.comments).catch((e: unknown) => {
        toast.push("error", `Could not save the ${field}`, errorMessage(e));
      });
    },
    [snap.rows, snap.overrides, toast],
  );

  const cancelEdit = useCallback(() => {
    setEditing(null);
    setFocusToken((n) => n + 1);
  }, []);

  const startEdit = useCallback(
    (key: string, field: EditField) => {
      setSelectedKey(key);
      if (ui.view !== "devices") patchUi({ view: "devices" });
      setEditing({ key, field });
    },
    [ui.view, patchUi],
  );

  const copy = useCallback(
    async (text: string, what: string) => {
      try {
        await navigator.clipboard.writeText(text);
        toast.push("success", `Copied ${what}`, text);
      } catch {
        // Clipboard API unavailable: fall back to a hidden textarea.
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand("copy");
        ta.remove();
        toast.push(ok ? "success" : "error", ok ? `Copied ${what}` : `Could not copy ${what}`, text);
      }
    },
    [toast],
  );

  const openUrl = useCallback(
    async (url: string) => {
      try {
        await backend.openUrl(url);
      } catch (e) {
        toast.push("error", `Could not open ${url}`, errorMessage(e));
      }
    },
    [toast],
  );

  const openScheme = useCallback(
    (row: DeviceRow, scheme: "http" | "https" | "ssh" | "telnet", port?: number) => {
      const host = urlHost(row.device.ip);
      void openUrl(`${scheme}://${host}${port ? `:${port}` : ""}${scheme.startsWith("http") ? "/" : ""}`);
    },
    [openUrl],
  );

  const presetPorts = useCallback((): number[] => {
    const preset = PORT_PRESETS.find((p) => p.id === ui.portPreset);
    if (preset) return preset.ports;
    const custom = parsePorts(ui.customPorts);
    return custom.ok ? custom.value : [];
  }, [ui.portPreset, ui.customPorts]);

  const runPortScan = useCallback(
    async (row: DeviceRow) => {
      const ports = presetPorts();
      if (ports.length === 0) {
        toast.push("error", "No ports to scan", "Pick a preset or enter custom ports in the Details drawer.");
        return;
      }
      const key = row.key;
      setPortScans((s) => ({ ...s, [key]: { status: "running", scanned: ports.length, open: [], at: Date.now() } }));
      try {
        const open = await backend.scanPorts(row.device.ip, ports);
        const sorted = [...open].sort((a, b) => a - b);
        setPortScans((s) => ({ ...s, [key]: { status: "done", scanned: ports.length, open: sorted, at: Date.now() } }));
        store.setOpenPorts(key, sorted);
        store.log("info", `Port scan ${row.device.ip}: ${sorted.length} open of ${ports.length} (${sorted.join(", ") || "none"})`);
      } catch (e) {
        const msg = errorMessage(e);
        setPortScans((s) => ({ ...s, [key]: { status: "error", scanned: ports.length, open: [], error: msg, at: Date.now() } }));
        toast.push("error", `Port scan of ${row.device.ip} failed`, msg);
      }
    },
    [presetPorts, toast],
  );

  const querySnmp = useCallback(
    async (row: DeviceRow) => {
      const key = row.key;
      setSnmpQueries((s) => ({ ...s, [key]: { status: "running" } }));
      try {
        const info = await backend.querySnmp(row.device.ip, snmpForWire(settings.snmp));
        store.setSnmpResult(key, info);
        setSnmpQueries((s) => {
          const next = { ...s };
          delete next[key];
          return next;
        });
      } catch (e) {
        const msg = errorMessage(e);
        setSnmpQueries((s) => ({ ...s, [key]: { status: "error", error: msg } }));
        toast.push("error", `SNMP query of ${row.device.ip} failed`, msg);
      }
    },
    [settings.snmp, toast],
  );

  const removeRow = useCallback((key: string) => {
    store.removeDevices([key]);
  }, []);

  const clearResults = useCallback(() => {
    store.clearResults();
    setSelectedKey(null);
    setEditing(null);
    setPortScans({});
    setSnmpQueries({});
  }, []);

  const openDetails = useCallback(
    (key: string) => {
      setSelectedKey(key);
      patchUi({ drawerOpen: true });
    },
    [patchUi],
  );

  const selectIp = useCallback(
    (ip: string) => {
      const row = snap.rows.find((r) => r.device.ip === ip || r.device.extraIps.includes(ip));
      if (!row) {
        toast.push("info", `${ip} is not in the results`, "Scan its subnet or VLAN to add it.");
        return;
      }
      setRoleFilter("all");
      setSearch("");
      setSelectedKey(row.key);
      patchUi({ view: "devices", drawerOpen: true });
    },
    [snap.rows, patchUi, toast],
  );

  const openRowMenu = useCallback(
    (row: DeviceRow, x: number, y: number) => {
      const ip = row.device.ip;
      const host = urlHost(ip);
      setRowMenu({
        x,
        y,
        label: `Actions for ${ip}`,
        items: [
          { kind: "header", label: row.hostname || ip },
          { kind: "item", label: `Open http://${host}`, icon: Globe, onSelect: () => openScheme(row, "http") },
          { kind: "item", label: `Open https://${host}`, icon: Globe, onSelect: () => openScheme(row, "https") },
          { kind: "item", label: "Open Custom URL…", icon: ExternalLink, onSelect: () => setCustomUrlFor(row) },
          { kind: "separator" },
          { kind: "item", label: "SSH", icon: Terminal, onSelect: () => openScheme(row, "ssh") },
          { kind: "item", label: "Telnet", icon: Terminal, onSelect: () => openScheme(row, "telnet") },
          { kind: "separator" },
          {
            kind: "item",
            label: "Run Port Scan",
            icon: ScanLine,
            onSelect: () => {
              openDetails(row.key);
              void runPortScan(row);
            },
          },
          {
            kind: "item",
            label: "Query SNMP Details",
            icon: Server,
            onSelect: () => {
              openDetails(row.key);
              void querySnmp(row);
            },
          },
          { kind: "separator" },
          { kind: "item", label: "Edit Hostname", icon: Pencil, shortcut: "F2", onSelect: () => startEdit(row.key, "hostname") },
          { kind: "item", label: "Edit Comments", icon: MessageSquare, shortcut: "⇧F2", onSelect: () => startEdit(row.key, "comments") },
          { kind: "separator" },
          { kind: "item", label: "Copy IP Address", icon: Copy, shortcut: "⌘C", onSelect: () => void copy(ip, "IP address") },
          {
            kind: "item",
            label: "Copy MAC Address",
            icon: Copy,
            disabled: !row.device.mac,
            onSelect: () => void copy(row.device.mac ?? "", "MAC address"),
          },
          { kind: "separator" },
          { kind: "item", label: "Remove from Results", icon: Trash, shortcut: "⌫", onSelect: () => removeRow(row.key) },
        ],
      });
    },
    [openScheme, openDetails, runPortScan, querySnmp, startEdit, copy, removeRow],
  );

  // --- global shortcuts --------------------------------------------------------------------------

  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      const mod = e.metaKey || e.ctrlKey;
      if (!mod) return;
      const k = e.key.toLowerCase();
      if (k === "f") {
        e.preventDefault();
        if (ui.view !== "devices") patchUi({ view: "devices" });
        searchRef.current?.focus();
        searchRef.current?.select();
      } else if (k === "r" && !e.shiftKey) {
        e.preventDefault(); // also suppresses the webview reload
        if (!snap.running) start();
      } else if (k === ".") {
        e.preventDefault();
        if (snap.running) void stop();
      } else if (k === "i") {
        e.preventDefault();
        patchUi({ drawerOpen: !ui.drawerOpen });
      } else if (k === "l") {
        e.preventDefault();
        patchUi({ logOpen: !ui.logOpen });
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [ui.view, ui.drawerOpen, ui.logOpen, snap.running, start, stop, patchUi]);

  // Mock mode convenience: `?autoscan=10.0.0.0/16` starts a scan on load (stress testing).
  const autoscanDone = useRef(false);
  useEffect(() => {
    if (!backend.isMock || autoscanDone.current) return;
    autoscanDone.current = true;
    const range = new URLSearchParams(window.location.search).get("autoscan");
    if (range !== null) {
      patchSettings({ range });
      void startWith({ ...settings, range });
    }
  }, [settings, patchSettings, startWith]);

  // --- render -------------------------------------------------------------------------------------

  const hasFilter = roleFilter !== "all" || deferredSearch.trim() !== "";
  const empty =
    snap.rows.length === 0 ? (
      snap.running ? (
        <div className="text-center text-muted">Scanning… devices appear here as they answer.</div>
      ) : (
        <Welcome subnet={subnetHint(currentIface)} iface={currentIface?.name} isMock={backend.isMock} onStart={start} />
      )
    ) : hasFilter ? (
      <div className="flex flex-col items-center gap-2 text-center text-muted">
        <p>
          No devices match{deferredSearch.trim() ? ` “${deferredSearch.trim()}”` : ""}
          {roleFilter !== "all" ? " in this role" : ""}.
        </p>
        <Button
          onClick={() => {
            setSearch("");
            setRoleFilter("all");
          }}
        >
          Clear Filters
        </Button>
      </div>
    ) : null;

  return (
    <div className="flex h-full flex-col">
      <Toolbar
        settings={settings}
        onSettings={patchSettings}
        interfaces={interfaces}
        running={snap.running}
        starting={snap.starting}
        onStart={start}
        onStop={() => void stop()}
        onOpenSnmp={() => setSnmpOpen(true)}
        onExport={(f) => void exportAs(f)}
        exportCount={filtered.length}
        drawerOpen={ui.drawerOpen}
        onToggleDrawer={() => patchUi({ drawerOpen: !ui.drawerOpen })}
      />
      <FilterBar
        ref={searchRef}
        view={ui.view}
        onView={(view) => patchUi({ view })}
        counts={{ devices: snap.rows.length, vlans: snap.vlans.length, neighbors: snap.neighbors.length }}
        roleFilter={roleFilter}
        onRoleFilter={setRoleFilter}
        roleCounts={snap.roleCounts}
        search={search}
        onSearch={(v) => {
          setSearch(v);
          if (ui.view !== "devices") patchUi({ view: "devices" });
        }}
        canEdit={selectedRow !== undefined}
        onEditHostname={() => selectedRow && startEdit(selectedRow.key, "hostname")}
        onClear={clearResults}
        canClear={snap.rows.length > 0 || snap.vlans.length > 0 || snap.neighbors.length > 0}
        onPassiveDiscovery={() => void passiveDiscovery()}
        running={snap.running}
      />
      <div className="flex min-h-0 flex-1">
        <main className="flex min-w-0 flex-1 flex-col">
          {ui.view === "devices" && (
            <DeviceTable
              rows={filtered}
              selectedKey={selectedKey}
              onSelect={setSelectedKey}
              onOpenDetails={openDetails}
              editing={editing}
              onStartEdit={startEdit}
              onCommitEdit={commitEdit}
              onCancelEdit={cancelEdit}
              onRowMenu={openRowMenu}
              onDeleteRow={removeRow}
              onCopyIp={(row) => void copy(row.device.ip, "IP address")}
              empty={empty}
              focusToken={focusToken}
            />
          )}
          {ui.view === "vlans" && (
            <VlanView
              vlans={snap.vlans}
              rows={snap.rows}
              running={snap.running}
              discoveryTimeout={ui.discoveryTimeout}
              onDiscoveryTimeout={(n) => patchUi({ discoveryTimeout: n })}
              onPassiveDiscovery={() => void passiveDiscovery()}
              onScanVlans={scanVlans}
            />
          )}
          {ui.view === "neighbors" && <NeighborView neighbors={snap.neighbors} onSelectIp={selectIp} />}
        </main>
        {ui.drawerOpen && (
          <DetailsDrawer
            row={selectedRow}
            rows={snap.rows}
            neighbors={snap.neighbors}
            vlans={snap.vlans}
            portMappings={snap.portMappings}
            snmp={selectedKey !== null ? snap.snmp[selectedKey] : undefined}
            snmpQuery={selectedKey !== null ? snmpQueries[selectedKey] : undefined}
            portScan={selectedKey !== null ? portScans[selectedKey] : undefined}
            portPreset={ui.portPreset}
            customPorts={ui.customPorts}
            onPortPreset={(portPreset) => patchUi({ portPreset })}
            onCustomPorts={(customPorts) => patchUi({ customPorts })}
            onRunPortScan={() => selectedRow && void runPortScan(selectedRow)}
            onQuerySnmp={() => selectedRow && void querySnmp(selectedRow)}
            onOpenUrl={(scheme, port) => selectedRow && openScheme(selectedRow, scheme, port)}
            onCopy={(text, what) => void copy(text, what)}
            onSelectIp={selectIp}
            onClose={() => patchUi({ drawerOpen: false })}
          />
        )}
      </div>
      {ui.logOpen && <LogPanel logs={snap.logs} onClear={() => store.clearLogs()} />}
      <StatusBar
        interfaces={interfaces}
        iface={settings.iface}
        onIface={(iface) => patchSettings({ iface })}
        vlanLabel={vlanLabel}
        running={snap.running}
        starting={snap.starting}
        jobKind={snap.jobKind}
        progress={snap.progress}
        devicesSeen={snap.rows.length}
        shown={filtered.length}
        lastLog={snap.logs[snap.logs.length - 1]}
        warnCount={warnCount}
        logOpen={ui.logOpen}
        onToggleLog={() => patchUi({ logOpen: !ui.logOpen })}
      />
      {rowMenu && <ContextMenu menu={rowMenu} onClose={() => setRowMenu(null)} />}
      {snmpOpen && (
        <SnmpDialog
          enabled={settings.snmpEnabled}
          config={settings.snmp}
          onSave={(snmpEnabled, snmp) => patchSettings({ snmpEnabled, snmp })}
          onClose={() => setSnmpOpen(false)}
        />
      )}
      {customUrlFor && (
        <CustomUrlDialog
          ip={customUrlFor.device.ip}
          initial={ui.urlTemplate}
          onOpen={(template) => {
            patchUi({ urlTemplate: template });
            void openUrl(template.replaceAll("{ip}", urlHost(customUrlFor.device.ip)));
          }}
          onClose={() => setCustomUrlFor(null)}
        />
      )}
    </div>
  );
}

function Welcome({
  subnet,
  iface,
  isMock,
  onStart,
}: {
  subnet: string | null;
  iface: string | undefined;
  isMock: boolean;
  onStart: () => void;
}) {
  return (
    <div className="flex max-w-[520px] flex-col items-center gap-3 px-6 text-center">
      <h2 className="text-[16px] font-semibold">No devices yet</h2>
      <p className="text-muted">
        Choose an interface and press <strong className="text-fg">Start SweepR</strong>. Leave the range empty to sweep{" "}
        {subnet ? (
          <>
            the {iface} subnet (<span className="font-mono">{subnet}</span>)
          </>
        ) : (
          "the interface's subnet"
        )}
        . Add VLAN IDs to probe 802.1Q-tagged networks, or turn on CDP/LLDP to find switches, firewalls and access points.
      </p>
      <Button variant="primary" onClick={onStart}>
        Start SweepR
      </Button>
      <div className="mt-1 flex items-start gap-2 rounded-[8px] border border-warn/40 bg-warn-soft px-3 py-2 text-left">
        <ShieldAlert size={16} className="mt-px shrink-0 text-warn" aria-hidden />
        <p>
          Raw ARP, 802.1Q VLAN tagging, IPv6 NDP and CDP/LLDP capture need raw packet access. Without it SweepR falls back to an ICMP
          sweep and can miss hosts. On macOS run SweepR via <code className="font-mono">sudo</code>, e.g.{" "}
          <code className="selectable font-mono">sudo /Applications/SweepR.app/Contents/MacOS/sweepr --gui</code>.
        </p>
      </div>
      <p className="text-[11px] text-muted">
        <Kbd>⌘R</Kbd> start · <Kbd>⌘.</Kbd> stop · <Kbd>⌘F</Kbd> search · <Kbd>↑↓</Kbd> select · <Kbd>↩</Kbd> details · <Kbd>F2</Kbd> edit
        hostname · right-click for actions
      </p>
      {isMock && (
        <p className="text-[11px] text-muted">
          Browser mock mode: data is simulated. Try range <code className="font-mono">10.0.0.0/16</code> for a ~50k-device stress test.
        </p>
      )}
    </div>
  );
}
