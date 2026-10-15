// "VLANs" and "Neighbors" views (small lists, no virtualization needed).

import { useMemo, type ReactNode } from "react";
import { Layers, Radar, Share2 } from "lucide-react";
import type { CdpLldpNeighbor, VlanInfo } from "../types.ts";
import type { DeviceRow } from "../lib/store.ts";
import { Button, TextInput, cx } from "./ui.tsx";

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
  running,
  discoveryTimeout,
  onDiscoveryTimeout,
  onPassiveDiscovery,
  onScanVlans,
}: {
  vlans: VlanInfo[];
  rows: DeviceRow[];
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
        <Table label="Discovered VLANs" head={["VLAN ID", "Name", "Sources", "Interface", "Switch", "Frames", "Devices", "Last seen"]}>
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
              <td className={cx(td, "text-muted")}>{ago(v.lastSeenMs)}</td>
            </tr>
          ))}
        </Table>
      )}
    </div>
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
      head={["Protocol", "System Name", "Platform", "Remote Port", "Management IP", "Native VLAN", "Voice VLAN", "Capabilities", "Local Port", "Software", "Last seen"]}
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
