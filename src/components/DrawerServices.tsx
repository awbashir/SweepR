// Details-drawer sections for deeper discovery: UPnP / ONVIF / SIP services (with an on-demand
// `discover_services` probe), PoE & voice VLAN (switch PoE budget for switches) and the passive
// DHCP fingerprint. Data sections render only when the device has that data.

import type { ReactNode } from "react";
import { Copy, ExternalLink, LoaderCircle, Radar } from "lucide-react";
import type { DhcpFingerprint, OnvifInfo, PoeBudget, SipInfo, SsdpInfo, SwitchPortMapping } from "../types.ts";
import type { DeviceRow } from "../lib/store.ts";
import {
  DHCP_OPTION_NAMES,
  budgetUsage,
  deviceKindLabel,
  deviceKindOf,
  formatWatts,
  poeSummary,
  poeTone,
  portPoeTotal,
  rtspCandidates,
  safeHttpUrl,
  shortUrn,
} from "../lib/services.ts";
import { Button, KindIcon, SectionTitle, TONE_TEXT_CLASS, cx } from "./ui.tsx";

export interface ServiceQueryState {
  status: "running" | "error" | "done";
  error?: string;
  /** The probe answered with nothing. */
  empty?: boolean;
}

function KV({ k, children }: { k: string; children: ReactNode }) {
  if (children === null || children === undefined || children === "" || children === false) return null;
  return (
    <>
      <dt className="py-[3px] pr-2 text-right whitespace-nowrap text-muted">{k}</dt>
      <dd className="selectable min-w-0 py-[3px] break-words">{children}</dd>
    </>
  );
}

function SubTitle({ children, badge }: { children: ReactNode; badge?: ReactNode }) {
  return (
    <div className="mt-2 mb-0.5 flex items-center gap-1.5">
      <h4 className="text-[11.5px] font-semibold">{children}</h4>
      {badge}
    </div>
  );
}

function Chip({ children, title, mono }: { children: ReactNode; title?: string; mono?: boolean }) {
  return (
    <span title={title} className={cx("inline-block rounded-[4px] border border-line bg-chrome-2 px-1.5 text-[10.5px] leading-[16px] text-muted", mono && "font-mono")}>
      {children}
    </span>
  );
}

function Badge({ children, tone = "accent" }: { children: ReactNode; tone?: "accent" | "warn" | "muted" }) {
  return (
    <span
      className={cx(
        "rounded px-1.5 text-[10px] font-semibold uppercase",
        tone === "accent" && "bg-accent-soft text-accent",
        tone === "warn" && "bg-warn-soft text-warn",
        tone === "muted" && "bg-chrome-2 text-muted",
      )}
    >
      {children}
    </span>
  );
}

function IconBtn({ label, onClick, icon: Icon }: { label: string; onClick: () => void; icon: typeof Copy }) {
  return (
    <button type="button" aria-label={label} title={label} onClick={onClick} className="ml-1 inline-flex rounded p-0.5 align-middle text-muted hover:bg-chrome-2 hover:text-fg">
      <Icon size={11} aria-hidden />
    </button>
  );
}

// --- services -------------------------------------------------------------------------------------

export function ServicesSection({
  row,
  query,
  onDiscover,
  onOpenUrl,
  onCopy,
}: {
  row: DeviceRow;
  query: ServiceQueryState | undefined;
  onDiscover: () => void;
  onOpenUrl: (url: string) => void;
  onCopy: (text: string, what: string) => void;
}) {
  const d = row.device;
  const kind = deviceKindOf(d);
  const running = query?.status === "running";
  const any = Boolean(d.ssdp || d.onvif || d.sip);
  return (
    <section id="drawer-services" aria-label="Services">
      <SectionTitle
        right={
          <Button
            icon={running ? LoaderCircle : Radar}
            onClick={onDiscover}
            disabled={running}
            className={cx(running && "[&>svg]:animate-spin")}
            title="Unicast SSDP/UPnP, WS-Discovery/ONVIF and SIP OPTIONS to this host (no credentials are ever sent)"
          >
            Discover Services
          </Button>
        }
      >
        Services
      </SectionTitle>
      {kind && (
        <div className="mb-1 flex items-center gap-1.5">
          <KindIcon kind={kind} size={14} />
          <span className="font-medium">{deviceKindLabel(kind)}</span>
        </div>
      )}
      {query?.status === "error" && <p className="text-danger">{query.error}</p>}
      {!any && query?.status !== "error" && (
        <p className="text-muted">
          {running
            ? "Probing UPnP, WS-Discovery and SIP…"
            : query?.status === "done"
              ? "No UPnP, WS-Discovery/ONVIF or SIP answer from this host."
              : "No UPnP, ONVIF or SIP data yet. Scans probe services during enrichment; Discover Services asks this host directly."}
        </p>
      )}
      {d.ssdp && <SsdpBlock s={d.ssdp} onOpenUrl={onOpenUrl} onCopy={onCopy} />}
      {d.onvif && <OnvifBlock o={d.onvif} onCopy={onCopy} />}
      {d.sip && <SipBlock s={d.sip} />}
    </section>
  );
}

function SsdpBlock({ s, onOpenUrl, onCopy }: { s: SsdpInfo; onOpenUrl: (url: string) => void; onCopy: (text: string, what: string) => void }) {
  const pres = safeHttpUrl(s.presentationUrl);
  const model = [s.modelName, s.modelNumber && !(s.modelName ?? "").includes(s.modelNumber) ? s.modelNumber : null].filter(Boolean).join(" ");
  return (
    <div>
      <SubTitle badge={<Badge>UPnP</Badge>}>{s.friendlyName ?? "SSDP / UPnP device"}</SubTitle>
      <dl className="grid grid-cols-[96px_1fr] text-[12px]">
        <KV k="Manufacturer">{s.manufacturer}</KV>
        <KV k="Model">{model}</KV>
        <KV k="Description">{s.modelDescription}</KV>
        <KV k="Serial">
          {s.serialNumber && (
            <>
              <span className="font-mono">{s.serialNumber}</span>
              <IconBtn label="Copy serial number" icon={Copy} onClick={() => onCopy(s.serialNumber ?? "", "serial number")} />
            </>
          )}
        </KV>
        <KV k="Device type">{s.deviceType && <span title={s.deviceType}>{shortUrn(s.deviceType)}</span>}</KV>
        <KV k="UDN">{s.udn && <span className="font-mono text-[11px]">{s.udn}</span>}</KV>
        <KV k="Web UI">
          {s.presentationUrl &&
            (pres ? (
              <button type="button" onClick={() => onOpenUrl(pres)} className="inline-flex items-center gap-1 text-left text-accent hover:underline" title={`Open ${pres}`}>
                <span className="break-all">{pres}</span>
                <ExternalLink size={10} aria-hidden className="shrink-0" />
              </button>
            ) : (
              <span className="break-all text-muted" title="Not an http(s) URL: not opened">
                {s.presentationUrl}
              </span>
            ))}
        </KV>
        <KV k="Server">{s.server}</KV>
        <KV k="Location">{s.location && <span className="font-mono text-[11px] break-all">{s.location}</span>}</KV>
      </dl>
      {s.services.length > 0 && (
        <div className="mt-1 flex flex-wrap gap-1" aria-label="UPnP services">
          {s.services.map((u) => (
            <Chip key={u} title={u}>
              {shortUrn(u)}
            </Chip>
          ))}
        </div>
      )}
    </div>
  );
}

/** ONVIF profiles / capabilities implied by the WS-Discovery scopes. */
function onvifNotes(o: OnvifInfo): string[] {
  const notes = new Set<string>();
  for (const sc of o.scopes) {
    const m = /onvif:\/\/www\.onvif\.org\/(Profile|type)\/([^/\s]+)/i.exec(sc);
    if (!m) continue;
    const v = decodeURIComponent(m[2] ?? "");
    if (/^profile$/i.test(m[1] ?? "")) notes.add(v === "Streaming" ? "Profile S (streaming)" : `Profile ${v}`);
    else notes.add(v.replace(/_/g, " "));
  }
  return [...notes];
}

function OnvifBlock({ o, onCopy }: { o: OnvifInfo; onCopy: (text: string, what: string) => void }) {
  const rtsp = rtspCandidates(o);
  const notes = onvifNotes(o);
  const title = o.isCamera ? "ONVIF camera" : o.isWindows ? "WS-Discovery (Windows)" : "WS-Discovery device";
  return (
    <div>
      <SubTitle badge={<Badge>{o.isCamera ? "ONVIF" : "WSD"}</Badge>}>{o.name ?? title}</SubTitle>
      <dl className="grid grid-cols-[96px_1fr] text-[12px]">
        <KV k="Manufacturer">{o.manufacturer}</KV>
        <KV k="Model">{o.model}</KV>
        <KV k="Firmware">{o.firmwareVersion}</KV>
        <KV k="Serial">
          {o.serialNumber && (
            <>
              <span className="font-mono">{o.serialNumber}</span>
              <IconBtn label="Copy serial number" icon={Copy} onClick={() => onCopy(o.serialNumber ?? "", "serial number")} />
            </>
          )}
        </KV>
        <KV k="Hardware ID">{o.hardwareId}</KV>
        <KV k="Location">{o.location}</KV>
        <KV k="Types">{o.types && <span className="font-mono text-[11px]">{o.types}</span>}</KV>
        <KV k="Endpoints">
          {o.xaddrs.length > 0 &&
            o.xaddrs.map((x) => (
              <div key={x} className="font-mono text-[11px] break-all">
                {x}
              </div>
            ))}
        </KV>
        <KV k="RTSP">
          {rtsp.length > 0 &&
            rtsp.map((c) => (
              <div key={c.url} className="flex items-start gap-1">
                <span className="font-mono text-[11px] break-all">{c.url}</span>
                {c.guess && <Badge tone="warn">guess</Badge>}
                <IconBtn label={`Copy RTSP URL${c.guess ? " (guess)" : ""}`} icon={Copy} onClick={() => onCopy(c.url, c.guess ? "RTSP URL (guess)" : "RTSP URL")} />
              </div>
            ))}
        </KV>
      </dl>
      {notes.length > 0 && (
        <div className="mt-1 flex flex-wrap gap-1" aria-label="ONVIF capabilities">
          {notes.map((n) => (
            <Chip key={n}>{n}</Chip>
          ))}
        </div>
      )}
      {o.isCamera && (
        <p className="mt-1 text-[11px] text-muted">
          {rtsp.some((c) => !c.guess)
            ? "The stream URL was reported by the camera without credentials."
            : rtsp.length > 0
              ? "Guesses are common vendor URL templates; they were never verified and no credentials were tried."
              : "The camera did not report a stream URL without credentials."}
        </p>
      )}
    </div>
  );
}

function SipBlock({ s }: { s: SipInfo }) {
  const allow = (s.allow ?? "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
  return (
    <div>
      <SubTitle badge={<Badge>{s.kind === "pbx" ? "PBX" : s.kind === "voip_phone" ? "Phone" : "SIP"}</Badge>}>
        {[s.vendor, s.model].filter(Boolean).join(" ") || "SIP endpoint"}
      </SubTitle>
      <dl className="grid grid-cols-[96px_1fr] text-[12px]">
        <KV k="Kind">{s.kind ? deviceKindLabel(s.kind) : null}</KV>
        <KV k="Vendor">{s.vendor}</KV>
        <KV k="Model">{s.model}</KV>
        <KV k="Firmware">{s.firmware}</KV>
        <KV k="Status">{s.status && `${s.status}${s.transport ? ` (${s.transport.toUpperCase()})` : ""}`}</KV>
        <KV k="User-Agent">{s.userAgent && <span className="font-mono text-[11px]">{s.userAgent}</span>}</KV>
        <KV k="Server">{s.server && <span className="font-mono text-[11px]">{s.server}</span>}</KV>
        <KV k="Supported">{s.supported}</KV>
      </dl>
      {allow.length > 0 && (
        <div className="mt-1 flex flex-wrap gap-1" aria-label="SIP methods allowed">
          {allow.map((m) => (
            <Chip key={m} mono>
              {m}
            </Chip>
          ))}
        </div>
      )}
    </div>
  );
}

// --- PoE & voice -------------------------------------------------------------------------------------

export function PoeVoiceSection({
  row,
  budget,
  mappings,
}: {
  row: DeviceRow;
  /** The switch's own budget (SNMP), when this device is a switch that reported one. */
  budget: PoeBudget | null | undefined;
  /** CAM entries of this switch (for the per-port PoE total). */
  mappings: readonly SwitchPortMapping[];
}) {
  const d = row.device;
  const p = d.poe;
  const usage = budgetUsage(budget);
  const portTotal = d.role === "switch" ? portPoeTotal(mappings) : null;
  if (!p && d.voiceVlan == null && !usage && !portTotal) return null;
  const tone = poeTone(p);
  return (
    <section id="drawer-poe" aria-label="PoE and voice VLAN">
      <SectionTitle>PoE &amp; Voice</SectionTitle>
      <dl className="grid grid-cols-[96px_1fr] text-[12px]">
        <KV k="Power">
          {p && (p.watts !== null || p.maxWatts !== null) && (
            <span>
              <span className={cx("font-mono font-medium tabular", p.watts !== null && TONE_TEXT_CLASS[tone])}>
                {p.watts !== null ? `${formatWatts(p.watts)} W` : `up to ${formatWatts(p.maxWatts)} W`}
              </span>
              {p.watts !== null && p.maxWatts !== null && <span className="text-muted"> of {formatWatts(p.maxWatts)} W allocated</span>}
              {tone === "warn" && <span className="text-warn"> · high load</span>}
              {tone === "bad" && <span className="text-danger"> · {p.status === "fault" ? "fault" : "near limit"}</span>}
            </span>
          )}
        </KV>
        <KV k="Class">{p?.class != null ? `${p.class}${p.class >= 5 ? " (802.3bt)" : p.class === 4 ? " (802.3at)" : ""}` : null}</KV>
        <KV k="Status">{p?.status}</KV>
        <KV k="Priority">{p?.priority}</KV>
        <KV k="Source">{p?.source}</KV>
        <KV k="Switch port">{p && (p.switchName || p.port) ? [p.switchName, p.port].filter(Boolean).join(" ") : null}</KV>
        <KV k="Voice VLAN">{d.voiceVlan != null ? String(d.voiceVlan) : null}</KV>
      </dl>
      {usage && (
        <div className="mt-1.5 rounded-[6px] border border-line bg-field px-2.5 py-2" aria-label="Switch PoE budget">
          <div className="flex items-baseline justify-between gap-2">
            <span className="font-medium">PoE budget</span>
            <span className={cx("font-mono text-[11.5px] tabular", TONE_TEXT_CLASS[usage.tone])}>
              {formatWatts(usage.consumed)} / {formatWatts(usage.nominal)} W{usage.pct !== null ? ` · ${Math.round(usage.pct)} %` : ""}
            </span>
          </div>
          {usage.pct !== null && (
            <div
              className="mt-1 h-[6px] overflow-hidden rounded-full bg-chrome-2"
              role="meter"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.round(usage.pct)}
              aria-label="PoE budget used"
            >
              <div
                className={cx("h-full rounded-full", usage.tone === "bad" ? "bg-danger" : usage.tone === "warn" ? "bg-warn" : "bg-ok")}
                style={{ width: `${usage.pct}%` }}
              />
            </div>
          )}
          <div className="mt-1 text-[11px] text-muted">
            {usage.ports} port{usage.ports === 1 ? "" : "s"} delivering
            {usage.nominal !== null && usage.consumed !== null && ` · ${formatWatts(Math.max(0, usage.nominal - usage.consumed))} W available`}
            {budget?.usageThresholdPct != null && ` · warns at ${budget.usageThresholdPct} %`}
          </div>
        </div>
      )}
      {!usage && portTotal && (
        <p className="mt-1 text-muted">
          {formatWatts(portTotal.watts)} W drawn on {portTotal.ports} port{portTotal.ports === 1 ? "" : "s"} (from its port table). Query SNMP for the
          switch's PoE budget.
        </p>
      )}
      {p && <p className="sr-only">{poeSummary(p)}</p>}
    </section>
  );
}

// --- DHCP fingerprint -------------------------------------------------------------------------------

const CONF_TONE: Record<string, string> = { high: "bg-ok", medium: "bg-warn", low: "bg-faint" };

export function DhcpSection({ fp }: { fp: DhcpFingerprint | null | undefined }) {
  if (!fp || (!fp.os && !fp.vendorClass && !fp.hostname && fp.paramList.length === 0)) return null;
  return (
    <section id="drawer-dhcp" aria-label="DHCP fingerprint">
      <SectionTitle>DHCP Fingerprint</SectionTitle>
      <dl className="grid grid-cols-[96px_1fr] text-[12px]">
        <KV k="OS guess">
          {fp.os ? (
            <span>
              <span className={cx("mr-1.5 inline-block size-[7px] rounded-full align-middle", CONF_TONE[fp.confidence ?? ""] ?? "bg-faint")} aria-hidden />
              {fp.os}
              {fp.confidence && <span className="text-muted"> ({fp.confidence} confidence)</span>}
            </span>
          ) : (
            <span className="text-muted">No signature matched</span>
          )}
        </KV>
        <KV k="Vendor class">{fp.vendorClass && <span className="font-mono text-[11px]">{fp.vendorClass}</span>}</KV>
        <KV k="DHCP hostname">{fp.hostname}</KV>
      </dl>
      {fp.paramList.length > 0 && (
        <>
          <div className="mt-1 text-[11px] text-muted">Parameter request list (option 55)</div>
          <div className="mt-0.5 flex flex-wrap gap-1" aria-label="DHCP parameter request list">
            {fp.paramList.map((o, i) => (
              <Chip key={`${o}-${i}`} mono title={DHCP_OPTION_NAMES[o] ?? `Option ${o}`}>
                {o}
              </Chip>
            ))}
          </div>
        </>
      )}
      <p className="mt-1 text-[11px] text-muted">A best-effort guess from the DHCP request options, never authoritative.</p>
    </section>
  );
}
