// "VLANs" and "Neighbors" views (small lists, no virtualization needed).

import { useMemo, type ReactNode } from "react";
import { Layers, Radar, Share2 } from "lucide-react";
import type { CdpLldpNeighbor, SwitchPortMapping, VlanInfo } from "../types.ts";
import { formatWatts, poeSummary, poeTone } from "../lib/services.ts";
import type { DeviceRow } from "../lib/store.ts";
import { Button, TONE_TEXT_CLASS, TextInput, cx } from "./ui.tsx";

function Table({ head, children, label }: { head: string[]; children: ReactNode; label: string }) {
  return (
    <div className="min-h-0 flex-1 overflow-auto bg-bg">
      <table className="w-full border-collapse text-[12px]" aria-label={label}>
        <thead className="sticky top-0 z-10 bg-chrome">
          <tr>
            {head.map((h) => (
              <th key={h} scope="col" className="h-[24px] border-r border-b border-line border-r-line-soft px-2 text-left text-[11.5px] font-medium whitespace-nowrap text-muted">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

const td = "h-[22px] px-2 whitespace-nowrap";
const ago = (ms: number): string => {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : new Date(ms).toLocaleTimeString();
};

function Empty({ icon, title, children }: { icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-2 px-8 text-center">
      <div className="text-faint">{icon}</div>
      <h2 className="text-[14px] font-semibold">{title}</h2>
      <div className="max-w-[480px] text-muted">{children}</div>
    </div>
  );
}

export function VlanView({
  vlans,
  rows,
  neighbors,
  portMappings,
  running,
  discoveryTimeout,
  onDiscoveryTimeout,
  onPassiveDiscovery,
  onScanVlans,
}: {
  vlans: VlanInfo[];
  rows: DeviceRow[];
  neighbors: CdpLldpNeighbor[];
  portMappings: SwitchPortMapping[];
  running: boolean;
  discoveryTimeout: number;
  onDiscoveryTimeout: (n: number) => void;
  onPassiveDiscovery: () => void;
  onScanVlans: (ids: number[]) => void;
}) {
  const perVlan = useMemo(() => {
    const m = new Map<number, number>();
    for (const r of rows) if (r.device.vlanId !== null) m.set(r.device.vlanId, (m.get(r.device.vlanId) ?? 0) + 1);
    return m;
  }, [rows]);
  // Voice VLAN use (devices / switch ports / neighbor adverts naming it) and PoE drawn by the
  // devices on it (their data VLAN or their voice VLAN).
  const voice = useMemo(() => {
    const m = new Map<number, { phones: number; ports: number; adverts: number; watts: number; powered: number }>();
    const get = (id: number) => {
      let e = m.get(id);
      if (!e) m.set(id, (e = { phones: 0, ports: 0, adverts: 0, watts: 0, powered: 0 }));
      return e;
    };
    for (const r of rows) {
      const d = r.device;
      if (d.voiceVlan != null) get(d.voiceVlan).phones++;
      const w = d.poe?.watts;
      if (w != null) {
        const id = d.voiceVlan ?? d.vlanId;
        if (id != null) {
          const e = get(id);
          e.watts += w;
          e.powered++;
        }
      }
    }
    const seenPorts = new Set<string>();
    for (const pm of portMappings) {
      if (pm.voiceVlan == null) continue;
      const k = `${pm.switchName}|${pm.portName}`;
      if (seenPorts.has(k)) continue;
      seenPorts.add(k);
      get(pm.voiceVlan).ports++;
    }
    for (const n of neighbors) if (n.voiceVlan != null) get(n.voiceVlan).adverts++;
    return m;
  }, [rows, portMappings, neighbors]);
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex items-center gap-2 border-b border-line-soft bg-bg px-3 py-1.5">
        <span className="text-muted">Listen for</span>
        <TextInput
          type="number"
          min={1}
          max={3600}
          aria-label="Passive discovery duration in seconds"
          value={discoveryTimeout}
          onChange={(e) => onDiscoveryTimeout(Math.max(1, Math.min(3600, Math.round(Number(e.target.value) || 30))))}
          className="w-[64px]"
        />
        <span className="text-muted">seconds</span>
        <Button icon={Radar} onClick={onPassiveDiscovery} disabled={running}>
          Start Passive Discovery
        </Button>
        <div className="flex-1" />
        <Button
          icon={Layers}
          disabled={vlans.length === 0 || running}
          onClick={() => onScanVlans(vlans.map((v) => v.id))}
          title="Probe every discovered VLAN with 802.1Q-tagged ARP"
        >
          Scan Discovered VLANs
        </Button>
      </div>
      {vlans.length === 0 ? (
        <Empty icon={<Layers size={32} strokeWidth={1.25} />} title="No VLANs discovered yet">
          Run passive discovery on a trunk port to collect 802.1Q tags, Cisco VTP and DTP, or scan with “Auto-Detect VLANs”. Packet capture
          needs raw access: run SweepR via <code className="font-mono">sudo</code>.
        </Empty>
      ) : (
        <Table label="Discovered VLANs" head={["VLAN ID", "Name", "Sources", "Interface", "Switch", "Frames", "Devices", "Voice", "PoE (W)", "Last seen"]}>
          {vlans.map((v, i) => (
            <tr key={v.id} className={cx(i % 2 === 1 && "bg-row-alt")}>
              <td className={cx(td, "font-medium tabular")}>{v.id}</td>
              <td className={td}>{v.name ?? <span className="text-faint">—</span>}</td>
              <td className={td}>
                <span className="flex gap-1">
                  {v.sources.map((s) => (
                    <span key={s} className="rounded bg-chrome-2 px-1.5 text-[10.5px] text-muted">
                      {s.replace("tagged8021q", "802.1Q").replace("os_interface", "OS").replace("user_configured", "user").toUpperCase()}
                    </span>
                  ))}
                </span>
              </td>
              <td className={td}>{v.interface ?? ""}</td>
              <td className={td}>{v.switchName ?? ""}</td>
              <td className={cx(td, "tabular")}>{v.framesSeen.toLocaleString()}</td>
              <td className={cx(td, "tabular")}>{perVlan.get(v.id)?.toLocaleString() ?? ""}</td>
              <td className={td}>
                <VoiceCell v={voice.get(v.id)} />
              </td>
              <td className={cx(td, "font-mono text-[11.5px] tabular")}>
                {(() => {
                  const e = voice.get(v.id);
                  return e && e.powered > 0 ? (
                    <span title={`${e.powered.toLocaleString()} powered device${e.powered === 1 ? "" : "s"} on this VLAN (data or voice)`}>{formatWatts(e.watts)}</span>
                  ) : (
                    ""
                  );
                })()}
              </td>
              <td className={cx(td, "text-muted")}>{ago(v.lastSeenMs)}</td>
            </tr>
          ))}
        </Table>
      )}
    </div>
  );
}

function VoiceCell({ v }: { v: { phones: number; ports: number; adverts: number } | undefined }) {
  if (!v || v.phones + v.ports + v.adverts === 0) return null;
  const parts = [
    v.phones > 0 ? `${v.phones.toLocaleString()} device${v.phones === 1 ? "" : "s"}` : null,
    v.ports > 0 ? `${v.ports.toLocaleString()} switch port${v.ports === 1 ? "" : "s"}` : null,
    v.adverts > 0 ? `${v.adverts} CDP/LLDP advert${v.adverts === 1 ? "" : "s"}` : null,
  ].filter(Boolean);
  return (
    <span className="flex items-center gap-1.5" title={`Voice VLAN for ${parts.join(", ")}`}>
      <span className="rounded bg-accent-soft px-1.5 text-[10px] font-semibold text-accent uppercase">Voice</span>
      {v.phones > 0 && <span className="tabular text-muted">{v.phones.toLocaleString()}</span>}
    </span>
  );
}

export function NeighborView({
  neighbors,
  onSelectIp,
}: {
  neighbors: CdpLldpNeighbor[];
  onSelectIp: (ip: string) => void;
}) {
  const sorted = useMemo(
    () => [...neighbors].sort((a, b) => (a.systemName ?? a.deviceId).localeCompare(b.systemName ?? b.deviceId, undefined, { numeric: true })),
    [neighbors],
  );
  if (sorted.length === 0) {
    return (
      <Empty icon={<Share2 size={32} strokeWidth={1.25} />} title="No CDP / LLDP neighbors yet">
        Turn on <strong>CDP/LLDP</strong> in the toolbar and start a scan, or run passive discovery from the VLANs view. Switches typically
        advertise every 30–60 seconds. Capturing needs raw packet access: run SweepR via <code className="font-mono">sudo</code>.
      </Empty>
    );
  }
  return (
    <Table
      label="CDP and LLDP neighbors"
      head={["Protocol", "System Name", "Platform", "Remote Port", "Management IP", "Native VLAN", "Voice VLAN", "PoE (W)", "Capabilities", "Local Port", "Software", "Last seen"]}
    >
      {sorted.map((n, i) => (
        <tr key={`${n.protocol}|${n.deviceId}|${n.portId ?? ""}`} className={cx(i % 2 === 1 && "bg-row-alt")}>
          <td className={td}>
            <span className="rounded bg-accent-soft px-1.5 text-[10px] font-semibold text-accent uppercase">{n.protocol}</span>
          </td>
          <td className={cx(td, "font-medium")} title={n.deviceId}>
            {n.systemName || n.deviceId}
          </td>
          <td className={td}>{n.platform ?? ""}</td>
          <td className={td}>{n.portId ?? ""}</td>
          <td className={td}>
            {n.managementAddrs.map((a) => (
              <button key={a} type="button" onClick={() => onSelectIp(a)} className="mr-1.5 font-mono text-accent hover:underline">
                {a}
              </button>
            ))}
          </td>
          <td className={cx(td, "tabular")}>{n.nativeVlan ?? ""}</td>
          <td className={cx(td, "tabular")}>{n.voiceVlan ?? ""}</td>
          <td className={cx(td, "font-mono text-[11.5px] tabular")}>
            <NeighborPoe n={n} />
          </td>
          <td className={td}>{n.capabilities.join(", ").replace(/_/g, " ")}</td>
          <td className={td}>{n.localInterface}</td>
          <td className={cx(td, "max-w-[280px] truncate")} title={n.softwareVersion ?? n.systemDescription ?? ""}>
            {n.softwareVersion ?? n.systemDescription ?? ""}
          </td>
          <td className={cx(td, "text-muted")}>{ago(n.lastSeenMs)}</td>
        </tr>
      ))}
    </Table>
  );
}

/** Headline PoE of an advert: drawn power (coloured by load), else the budget it offers. */
function NeighborPoe({ n }: { n: CdpLldpNeighbor }) {
  const info = n.poeInfo ?? null;
  const w = n.poeWatts ?? info?.watts ?? info?.maxWatts ?? null;
  if (w === null) return null;
  const drawn = info?.watts != null;
  const tone = drawn ? poeTone(info) : "none";
  return (
    <span className={cx(drawn ? TONE_TEXT_CLASS[tone] : "text-muted")} title={info ? poeSummary(info) : `${formatWatts(w)} W`}>
      {!drawn && info?.maxWatts != null ? "≤" : ""}
      {formatWatts(w)}
    </span>
  );
}
