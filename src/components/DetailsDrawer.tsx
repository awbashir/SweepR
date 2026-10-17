// Right-hand details drawer: device summary, port scanner, SNMP, CDP/LLDP neighbors and,
// for infrastructure roles, configured VLANs and the MAC → switch-port table.

import { useEffect, useMemo, useRef, type ReactNode } from "react";
import { Copy, ExternalLink, Globe, LoaderCircle, Power, ScanLine, Server, Terminal, X } from "lucide-react";
import type { CdpLldpNeighbor, SwitchPortMapping, VlanInfo } from "../types.ts";
import type { SnmpView } from "../lib/snmpAgents.ts";
import { ROLE_LABEL } from "../types.ts";
import { isRoleGuess, roleSummary, roleTooltip } from "../lib/roles.ts";
import type { DeviceRow } from "../lib/store.ts";
import {
  deviceNames,
  formatUptime,
  mappingsForSwitch,
  neighborsForDevice,
  normMac,
  normalizePortMacCounts,
  vlansForSwitch,
} from "../lib/infra.ts";
import { PORT_PRESETS, serviceName } from "../lib/ports.ts";
import { parsePorts } from "../lib/parse.ts";
import { Button, MiniBadge, RoleIcon, SectionTitle, Select, TextInput, cx } from "./ui.tsx";
import { IperfSection, LatencySection, TraceSection, WebSection } from "./DrawerTools.tsx";
import { DhcpSection, PoeVoiceSection, ServicesSection, type ServiceQueryState } from "./DrawerServices.tsx";
import { formatWatts, netServiceBadges, poeSummary } from "../lib/services.ts";

export type DrawerSection = "latency" | "web" | "trace" | "iperf" | "services";

export interface PortScanState {
  status: "running" | "done" | "error";
  scanned: number;
  open: number[];
  error?: string;
  at: number;
}

export interface SnmpQueryState {
  status: "running" | "error";
  error?: string;
}

interface DrawerProps {
  row: DeviceRow | undefined;
  rows: DeviceRow[];
  neighbors: CdpLldpNeighbor[];
  vlans: VlanInfo[];
  portMappings: SwitchPortMapping[];
  /** A `query_snmp` result, or what the scan's SNMP poll returned (`fromScan`). */
  snmp: SnmpView | undefined;
  snmpQuery: SnmpQueryState | undefined;
  portScan: PortScanState | undefined;
  portPreset: string;
  customPorts: string;
  onPortPreset: (id: string) => void;
  onCustomPorts: (v: string) => void;
  onRunPortScan: () => void;
  onQuerySnmp: () => void;
  onOpenUrl: (scheme: "http" | "https" | "ssh" | "telnet", port?: number) => void;
  onCopy: (text: string, what: string) => void;
  onSelectIp: (ip: string) => void;
  onClose: () => void;
  liveLatency: boolean;
  onEnableLive: () => void;
  pinned: boolean;
  onTogglePin: () => void;
  onWake: () => void;
  onGrabWeb: () => void;
  onOpenWebUrl: (url: string) => void;
  serviceQuery: ServiceQueryState | undefined;
  onDiscoverServices: () => void;
  /** Start requests from the row menu (increasing tokens). */
  traceToken: number;
  iperfToken: number;
  /** Scroll a section into view (token changes per request). */
  focus: { section: DrawerSection; token: number } | null;
}

function KV({ k, children }: { k: string; children: ReactNode }) {
  return (
    <>
      <dt className="py-[3px] pr-2 text-right whitespace-nowrap text-muted">{k}</dt>
      <dd className="selectable min-w-0 py-[3px] break-words">{children ?? <span className="text-faint">—</span>}</dd>
    </>
  );
}

function orDash(v: string | number | null | undefined): ReactNode {
  return v === null || v === undefined || v === "" ? null : v;
}

const time = (ms: number): string => (ms > 0 ? new Date(ms).toLocaleTimeString() : "—");

export function DetailsDrawer(p: DrawerProps) {
  const row = p.row;
  return (
    <aside
      aria-label="Device details"
      className="flex w-[360px] shrink-0 flex-col border-l border-line bg-panel"
    >
      <div className="flex h-[30px] shrink-0 items-center gap-2 border-b border-line px-3">
        <h2 className="flex-1 truncate text-[12px] font-semibold">Details</h2>
        <button type="button" aria-label="Close details" onClick={p.onClose} className="rounded p-0.5 text-muted hover:bg-chrome-2">
          <X size={13} aria-hidden />
        </button>
      </div>
      {row ? (
        <DrawerBody {...p} row={row} />
      ) : (
        <div className="flex flex-1 flex-col items-center justify-center gap-2 px-6 text-center text-muted">
          <Server size={28} strokeWidth={1.25} aria-hidden />
          <p>Select a device to see its details, run a port scan or query SNMP.</p>
        </div>
      )}
    </aside>
  );
}

function DrawerBody(p: DrawerProps & { row: DeviceRow }) {
  const { row } = p;
  const d = row.device;
  const isInfra = d.role === "switch" || d.role === "firewall" || d.role === "access_point" || d.role === "router";
  const names = useMemo(() => deviceNames(d, row.hostname, p.snmp), [d, row.hostname, p.snmp]);
  const neighbors = useMemo(() => neighborsForDevice(d, p.neighbors), [d, p.neighbors]);
  const swVlans = useMemo(() => {
    const byId = new Map<number, VlanInfo>();
    for (const v of vlansForSwitch(names, p.vlans)) byId.set(v.id, v);
    for (const v of p.snmp?.vlans ?? []) byId.set(v.id, { ...byId.get(v.id), ...v });
    return [...byId.values()].sort((a, b) => a.id - b.id);
  }, [names, p.vlans, p.snmp]);
  const mappings = useMemo(() => {
    if (!isInfra) return [];
    const all = mappingsForSwitch(d, names, p.portMappings);
    const seen = new Set<string>();
    return all
      .filter((m) => {
        const k = `${m.portName}|${normMac(m.mac)}|${m.vlanId ?? ""}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      })
      .sort((a, b) => (a.portIndex ?? 0) - (b.portIndex ?? 0) || a.portName.localeCompare(b.portName, undefined, { numeric: true }));
  }, [isInfra, d, names, p.portMappings]);
  // MAC → IP lookup for the CAM table (only built when there is a CAM table to show).
  const macToIp = useMemo(() => {
    const m = new Map<string, string>();
    if (mappings.length === 0) return m;
    const wanted = new Set(mappings.map((x) => normMac(x.mac)));
    for (const r of p.rows) {
      const mac = normMac(r.device.mac);
      if (mac && wanted.has(mac) && !m.has(mac)) m.set(mac, r.device.ip);
    }
    return m;
  }, [mappings, p.rows]);
  const macCounts = normalizePortMacCounts(p.snmp?.portMacCounts);
  // PoE / voice VLAN columns only when some port reported them.
  const camPoe = useMemo(() => mappings.some((m) => m.poe != null || m.voiceVlan != null), [mappings]);

  const preset = PORT_PRESETS.find((x) => x.id === p.portPreset);
  const custom = parsePorts(p.customPorts);
  const scanPorts = preset ? preset.ports : custom.ok ? custom.value : [];
  const scan = p.portScan;
  // Row-menu actions scroll their section into view.
  const bodyRef = useRef<HTMLDivElement>(null);
  const focusToken = p.focus?.token ?? 0;
  const focusSection = p.focus?.section;
  useEffect(() => {
    if (!focusToken || !focusSection) return;
    const body = bodyRef.current;
    const el = body?.querySelector<HTMLElement>(`#drawer-${focusSection}`);
    if (!body || !el) return;
    // Scroll only the drawer (scrollIntoView would also shift overflow-hidden ancestors).
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
    const top = el.getBoundingClientRect().top - body.getBoundingClientRect().top + body.scrollTop - 4;
    body.scrollTo({ top, behavior: reduce ? "auto" : "smooth" });
  }, [focusToken, focusSection]);
  const httpish = (port: number): "http" | "https" | null =>
    [443, 8443, 10443, 4443].includes(port) ? "https" : [80, 8080, 8000, 8008, 8081, 8888].includes(port) ? "http" : null;

  return (
    <div ref={bodyRef} className="min-h-0 flex-1 overflow-y-auto px-3 pb-6">
      <div className="flex items-start gap-2.5 pt-3">
        <div className="mt-0.5 rounded-[8px] border border-line bg-field p-1.5">
          <RoleIcon role={d.role} size={20} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="selectable truncate text-[14px] font-semibold" title={row.hostname || d.dnsName || d.ip}>
            {row.hostname || d.dnsName || d.mdnsName || d.smbName || d.ip}
          </div>
          <div className="flex flex-wrap items-center gap-1 text-muted">
            <span title={roleTooltip(d)}>
              <span className={cx(isRoleGuess(d) && "underline decoration-dashed decoration-1 underline-offset-[3px]")}>
                {roleSummary(d)}
              </span>
              {d.vendor ? ` · ${d.vendor}` : ""}
            </span>
            {netServiceBadges(d).map((b) => (
              <MiniBadge key={b.id} label={b.label} title={b.title} />
            ))}
          </div>
        </div>
      </div>
      <div className="mt-2 flex flex-wrap gap-1">
        <Button icon={Globe} onClick={() => p.onOpenUrl("http")} title={`Open http://${d.ip}`}>
          HTTP
        </Button>
        <Button icon={Globe} onClick={() => p.onOpenUrl("https")} title={`Open https://${d.ip}`}>
          HTTPS
        </Button>
        <Button icon={Terminal} onClick={() => p.onOpenUrl("ssh")} title={`ssh://${d.ip}`}>
          SSH
        </Button>
        <Button icon={Copy} onClick={() => p.onCopy(d.ip, "IP address")} title="Copy IP address">
          IP
        </Button>
        {d.mac && (
          <Button icon={Copy} onClick={() => p.onCopy(d.mac ?? "", "MAC address")} title="Copy MAC address">
            MAC
          </Button>
        )}
        <Button
          icon={Power}
          onClick={p.onWake}
          disabled={!d.mac}
          title={d.mac ? `Send a Wake-on-LAN magic packet to ${d.mac}` : "Wake-on-LAN needs the device's MAC address (only known on the local subnet)"}
        >
          Wake
        </Button>
      </div>

      <SectionTitle>Summary</SectionTitle>
      <dl className="grid grid-cols-[96px_1fr] text-[12px]">
        <KV k="IP address">
          <span className="font-mono">{d.ip}</span>
          {d.extraIps.map((ip) => (
            <div key={ip} className="font-mono text-muted">
              {ip}
            </div>
          ))}
        </KV>
        <KV k="MAC address">{d.mac ? <span className="font-mono">{d.mac}</span> : null}</KV>
        <KV k="VLAN">{d.vlanId ?? "Untagged"}</KV>
        <KV k="Hostname">{orDash(row.hostname)}</KV>
        <KV k="Vendor">{orDash(d.vendor)}</KV>
        {(d.roleEvidence?.length ?? 0) > 0 && (
          <KV k="Role evidence">
            <ul className="list-disc space-y-0.5 pl-3.5">
              {d.roleEvidence!.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          </KV>
        )}
        <KV k="Switch / Port">{orDash(row.switchPort)}</KV>
        <KV k="DNS name">{orDash(d.dnsName)}</KV>
        <KV k="mDNS name">{orDash(d.mdnsName)}</KV>
        {(d.mdnsServices?.length ?? 0) > 0 && <KV k="mDNS services">{d.mdnsServices!.join(", ")}</KV>}
        <KV k="SMB name">{orDash(d.smbName && (d.smbDomain ? `${d.smbDomain}\\${d.smbName}` : d.smbName))}</KV>
        <KV k="Open ports">{orDash(row.ports)}</KV>
        <KV k="Interface">{orDash(d.interface)}</KV>
        <KV k="Discovery RTT">{d.rttMs !== null ? `${d.rttMs.toFixed(2)} ms` : null}</KV>
        <KV k="Learned via">{orDash(d.sources.join(", ").toUpperCase())}</KV>
        <KV k="First / last">
          {time(d.firstSeenMs)} / {time(d.lastSeenMs)}
        </KV>
        <KV k="Comments">{orDash(row.comments)}</KV>
      </dl>

      <LatencySection ip={d.ip} live={p.liveLatency} pinned={p.pinned} onTogglePin={p.onTogglePin} onEnableLive={p.onEnableLive} />
      <WebSection row={row} onGrab={p.onGrabWeb} onOpenUrl={p.onOpenWebUrl} onCopy={p.onCopy} />
      <ServicesSection row={row} query={p.serviceQuery} onDiscover={p.onDiscoverServices} onOpenUrl={p.onOpenWebUrl} onCopy={p.onCopy} />
      <PoeVoiceSection row={row} budget={p.snmp?.poeBudget} mappings={mappings} />
      <DhcpSection fp={d.dhcpFingerprint} />

      <SectionTitle>Port Scanner</SectionTitle>
      <div className="flex items-center gap-1.5">
        <Select value={p.portPreset} onChange={(e) => p.onPortPreset(e.target.value)} aria-label="Port preset" className="flex-1">
          {PORT_PRESETS.map((x) => (
            <option key={x.id} value={x.id}>
              {x.label} ({x.ports.length})
            </option>
          ))}
          <option value="custom">Custom…</option>
        </Select>
        <Button
          variant="primary"
          icon={scan?.status === "running" ? LoaderCircle : ScanLine}
          onClick={p.onRunPortScan}
          disabled={scan?.status === "running" || scanPorts.length === 0}
          className={cx(scan?.status === "running" && "[&>svg]:animate-spin")}
        >
          Scan
        </Button>
      </div>
      {p.portPreset === "custom" && (
        <TextInput
          value={p.customPorts}
          onChange={(e) => p.onCustomPorts(e.target.value)}
          placeholder="22,80,443,8000-8100"
          aria-label="Custom ports"
          invalid={!custom.ok || scanPorts.length === 0}
          title={!custom.ok ? custom.error : undefined}
          className="mt-1.5 w-full"
        />
      )}
      <div className="mt-2 min-h-[22px]" aria-live="polite">
        {scan?.status === "running" && <p className="text-muted">Scanning {scan.scanned} ports…</p>}
        {scan?.status === "error" && <p className="text-danger">{scan.error}</p>}
        {scan?.status === "done" &&
          (scan.open.length === 0 ? (
            <p className="text-muted">No open ports among {scan.scanned} scanned.</p>
          ) : (
            <div className="flex flex-wrap gap-1">
              {scan.open.map((port) => {
                const scheme = httpish(port);
                return (
                  <button
                    key={port}
                    type="button"
                    onClick={scheme ? () => p.onOpenUrl(scheme, port) : port === 22 ? () => p.onOpenUrl("ssh") : undefined}
                    title={scheme ? `Open ${scheme}://${d.ip}:${port}` : serviceName(port)}
                    className={cx(
                      "inline-flex h-[20px] items-center gap-1 rounded-full border border-ok/40 bg-ok-soft px-2 text-[11px] text-ok",
                      (scheme || port === 22) && "hover:brightness-95",
                    )}
                  >
                    <span className="font-mono font-medium">{port}</span>
                    {serviceName(port) && <span className="opacity-80">{serviceName(port)}</span>}
                    {scheme && <ExternalLink size={10} aria-hidden />}
                  </button>
                );
              })}
              <span className="self-center text-[11px] text-muted">of {scan.scanned} scanned</span>
            </div>
          ))}
      </div>

      <TraceSection row={row} autoStart={p.traceToken} />
      <IperfSection row={row} autoStart={p.iperfToken} />

      <SectionTitle
        right={
          <Button
            icon={p.snmpQuery?.status === "running" ? LoaderCircle : Server}
            onClick={p.onQuerySnmp}
            disabled={p.snmpQuery?.status === "running"}
            className={cx(p.snmpQuery?.status === "running" && "[&>svg]:animate-spin")}
          >
            Query SNMP
          </Button>
        }
      >
        SNMP
      </SectionTitle>
      {p.snmpQuery?.status === "error" && <p className="text-danger">{p.snmpQuery.error}</p>}
      {p.snmp ? (
        <dl className="grid grid-cols-[96px_1fr] text-[12px]">
          <KV k="sysName">{orDash(p.snmp.sysName)}</KV>
          <KV k="sysDescr">{orDash(p.snmp.sysDescr)}</KV>
          <KV k="Uptime">{formatUptime(p.snmp.sysUptimeTicks)}</KV>
          <KV k="sysObjectID">{p.snmp.sysObjectId ? <span className="font-mono">{p.snmp.sysObjectId}</span> : null}</KV>
          <KV k="Role">{ROLE_LABEL[p.snmp.role] ?? p.snmp.role}</KV>
          {p.snmp.partial && (
            <KV k="Partial">
              <span className="text-warn" title={(p.snmp.warnings ?? []).join("\n")}>
                Some tables could not be read completely: {(p.snmp.warnings ?? []).join("; ")}
              </span>
            </KV>
          )}
          {p.snmp.fromScan && (
            <KV k="Source">
              <span className="text-muted">The scan's SNMP poll. Query SNMP for uptime, VLANs and the MAC table.</span>
            </KV>
          )}
        </dl>
      ) : (
        p.snmpQuery?.status !== "error" && <p className="text-muted">Not queried yet.</p>
      )}

      <SectionTitle>CDP / LLDP</SectionTitle>
      {neighbors.length === 0 ? (
        <p className="text-muted">No CDP or LLDP advertisement from this device. Enable CDP/LLDP in the toolbar to listen during scans.</p>
      ) : (
        neighbors.map((n) => <NeighborCard key={`${n.protocol}|${n.deviceId}|${n.portId ?? ""}`} n={n} onSelectIp={p.onSelectIp} />)
      )}

      {isInfra && (
        <>
          <SectionTitle>Configured VLANs</SectionTitle>
          {swVlans.length === 0 ? (
            <p className="text-muted">No VLANs known for this device yet. Query SNMP or run passive VLAN discovery.</p>
          ) : (
            <MiniTable
              head={["VLAN", "Name", "Source"]}
              rows={swVlans.map((v) => [String(v.id), v.name ?? "", v.sources.join(", ")])}
            />
          )}
          <SectionTitle>Connected MACs</SectionTitle>
          {mappings.length === 0 ? (
            <p className="text-muted">No MAC → port mappings for this device yet. Query SNMP to read its bridge table.</p>
          ) : (
            <MiniTable
              head={camPoe ? ["Port", "VLAN", "MAC", "IP", "PoE W", "Voice"] : ["Port", "VLAN", "MAC", "IP"]}
              mono={[false, false, true, true, true, false]}
              rows={mappings.map((m) => {
                const base = [m.portName, m.vlanId !== null ? String(m.vlanId) : "", m.mac, macToIp.get(normMac(m.mac)) ?? ""];
                return camPoe ? [...base, m.poe?.watts != null ? formatWatts(m.poe.watts) : "", m.voiceVlan != null ? String(m.voiceVlan) : ""] : base;
              })}
              onRowClick={(i) => {
                const ip = macToIp.get(normMac(mappings[i]?.mac));
                if (ip) p.onSelectIp(ip);
              }}
            />
          )}
          {macCounts.length > 0 && (
            <>
              <SectionTitle>MACs per Port</SectionTitle>
              <MiniTable head={["Port", "MACs"]} rows={macCounts.map(([port, n]) => [port, String(n)])} />
            </>
          )}
        </>
      )}
    </div>
  );
}

function NeighborCard({ n, onSelectIp }: { n: CdpLldpNeighbor; onSelectIp: (ip: string) => void }) {
  return (
    <div className="mb-2 rounded-[8px] border border-line bg-field px-2.5 py-2">
      <div className="flex items-center gap-2">
        <span className="rounded bg-accent-soft px-1.5 text-[10px] font-semibold text-accent uppercase">{n.protocol}</span>
        <span className="selectable truncate font-medium">{n.systemName || n.deviceId}</span>
      </div>
      <dl className="mt-1 grid grid-cols-[88px_1fr] text-[11.5px]">
        <KV k="Device ID">{orDash(n.deviceId)}</KV>
        <KV k="Platform">{orDash(n.platform)}</KV>
        <KV k="Software">{orDash(n.softwareVersion ?? n.systemDescription)}</KV>
        <KV k="Remote port">{orDash(n.portId && (n.portDescription ? `${n.portId} (${n.portDescription})` : n.portId))}</KV>
        <KV k="Local port">{orDash(n.localInterface)}</KV>
        <KV k="Management">
          {n.managementAddrs.length === 0
            ? null
            : n.managementAddrs.map((a) => (
                <button key={a} type="button" onClick={() => onSelectIp(a)} className="mr-1.5 font-mono text-accent hover:underline">
                  {a}
                </button>
              ))}
        </KV>
        <KV k="Native VLAN">{orDash(n.nativeVlan)}</KV>
        <KV k="Voice VLAN">{orDash(n.voiceVlan)}</KV>
        {(n.poeWatts != null || n.poeInfo) && (
          <KV k="PoE">{n.poeInfo ? poeSummary(n.poeInfo) || `${formatWatts(n.poeWatts)} W` : `${formatWatts(n.poeWatts)} W`}</KV>
        )}
        <KV k="Capabilities">{orDash(n.capabilities.join(", ").replace(/_/g, " "))}</KV>
        <KV k="VTP domain">{orDash(n.vtpDomain)}</KV>
        <KV k="TTL">{n.ttlSecs} s</KV>
      </dl>
    </div>
  );
}

function MiniTable({
  head,
  rows,
  mono,
  onRowClick,
}: {
  head: string[];
  rows: string[][];
  mono?: boolean[];
  onRowClick?: (i: number) => void;
}) {
  const shown = rows.slice(0, 500);
  return (
    <div className="max-h-[260px] overflow-auto rounded-[6px] border border-line bg-field">
      <table className="w-full border-collapse text-[11.5px]">
        <thead className="sticky top-0 bg-chrome">
          <tr>
            {head.map((h) => (
              <th key={h} scope="col" className="border-b border-line px-2 py-[3px] text-left font-medium whitespace-nowrap text-muted">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {shown.map((r, i) => (
            <tr
              key={i}
              onClick={onRowClick ? () => onRowClick(i) : undefined}
              className={cx(i % 2 === 1 && "bg-row-alt", onRowClick && "hover:bg-row-hover")}
            >
              {r.map((c, j) => (
                <td key={j} className={cx("selectable px-2 py-[2px] whitespace-nowrap", mono?.[j] && "font-mono")}>
                  {c}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > shown.length && <p className="px-2 py-1 text-muted">… {rows.length - shown.length} more</p>}
    </div>
  );
}
