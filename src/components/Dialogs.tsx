// SNMP settings and "Open custom URL" dialogs.

import { useState, type ReactNode } from "react";
import { LoaderCircle, TriangleAlert } from "lucide-react";
import type { InterfaceInfo, ReportFormat, SnmpAuthProtocol, SnmpConfig, SnmpPrivProtocol, SnmpV3Credentials, SnmpVersion, WakeOptions } from "../types.ts";
import { DEFAULT_SNMP, interfaceLabel, snmpV3Problem } from "../settings.ts";
import { ipv4ToNumber } from "../lib/ip.ts";
import { withoutUrlPassword } from "../lib/parse.ts";
import { parseSecureOn, parseWolMac } from "../lib/wol.ts";
import { DEFAULT_REPORT_TITLE } from "../lib/report.ts";
import { Modal } from "./Modal.tsx";
import { Button, Select, TextInput, Toggle } from "./ui.tsx";

function Row({ label, children, htmlFor }: { label: string; children: ReactNode; htmlFor?: string }) {
  return (
    <div className="grid grid-cols-[130px_1fr] items-center gap-x-3 gap-y-1 py-1">
      <label htmlFor={htmlFor} className="text-right text-muted">
        {label}
      </label>
      <div className="flex min-w-0 items-center gap-2">{children}</div>
    </div>
  );
}

const EMPTY_V3: SnmpV3Credentials = {
  username: "",
  authProtocol: "sha1",
  authPassword: null,
  privProtocol: "aes128",
  privPassword: null,
};

export function SnmpDialog({
  enabled,
  pollAll,
  config,
  credentialsMissing = false,
  onSave,
  onClose,
}: {
  enabled: boolean;
  pollAll: boolean;
  config: SnmpConfig;
  /** The community / v3 passwords were not kept from an earlier session. */
  credentialsMissing?: boolean;
  onSave: (enabled: boolean, pollAll: boolean, config: SnmpConfig) => void;
  onClose: () => void;
}) {
  const [on, setOn] = useState(enabled);
  const [all, setAll] = useState(pollAll);
  const [c, setC] = useState<SnmpConfig>(config);
  const [showSecrets, setShowSecrets] = useState(false);
  const v3 = c.v3 ?? EMPTY_V3;
  const setV3 = (patch: Partial<SnmpV3Credentials>): void => setC({ ...c, v3: { ...v3, ...patch } });
  const v3Invalid = on && c.version === "v3" && v3.username.trim() === "";
  const authLen = (v3.authPassword ?? "").length;
  const privLen = (v3.privPassword ?? "").length;
  const pwInvalid = (n: number): boolean => n > 0 && n < 8;
  const privWithoutAuth = c.version === "v3" && authLen === 0 && privLen > 0;
  const problem = snmpV3Problem({ ...c, v3 });
  // A v3 profile without a username may be saved while polling is off; anything else the
  // backend would reject blocks saving.
  const invalid = v3Invalid || (problem !== null && !(problem.includes("username") && !on));
  const secretType = showSecrets ? "text" : "password";

  return (
    <Modal
      title="SNMP Settings"
      onClose={onClose}
      width={480}
      footer={
        <>
          <Button onClick={() => setC(DEFAULT_SNMP)} className="mr-auto">
            Defaults
          </Button>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={invalid}
            onClick={() => {
              onSave(on, all, { ...c, v3: c.version === "v3" ? v3 : c.v3 });
              onClose();
            }}
          >
            Save
          </Button>
        </>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
        }}
      >
        {credentialsMissing && (
          <div role="alert" className="mb-2 flex items-start gap-2 rounded-[8px] border border-warn/40 bg-warn-soft px-3 py-2">
            <TriangleAlert size={15} className="mt-px shrink-0 text-warn" aria-hidden />
            <p>
              <strong>Re-enter the credentials.</strong> SweepR does not store SNMP communities or SNMPv3 passwords between sessions.
              Until you save them here, scans run without SNMP.
            </p>
          </div>
        )}
        <Row label="">
          <Toggle checked={on} onChange={setOn} label="Poll infrastructure over SNMP during scans" />
        </Row>
        <Row label="">
          <label className="flex items-center gap-1.5 text-muted">
            <input
              type="checkbox"
              checked={all}
              disabled={!on}
              onChange={(e) => setAll(e.target.checked)}
              className="accent-[var(--accent)]"
            />
            Poll all hosts (slow; default: gateway, CDP/LLDP neighbors and likely network gear only)
          </label>
        </Row>
        <fieldset className="contents">
          <Row label="Version" htmlFor="snmp-version">
            <Select id="snmp-version" value={c.version} onChange={(e) => setC({ ...c, version: e.target.value as SnmpVersion })}>
              <option value="v1">v1</option>
              <option value="v2c">v2c</option>
              <option value="v3">v3</option>
            </Select>
            <label className="ml-auto flex items-center gap-1.5 text-muted">
              <input type="checkbox" checked={showSecrets} onChange={(e) => setShowSecrets(e.target.checked)} className="accent-[var(--accent)]" />
              Show secrets
            </label>
          </Row>
          {c.version !== "v3" ? (
            <Row label="Community" htmlFor="snmp-community">
              <TextInput
                id="snmp-community"
                type={secretType}
                autoComplete="off"
                value={c.community}
                onChange={(e) => setC({ ...c, community: e.target.value })}
                className="flex-1"
              />
            </Row>
          ) : (
            <>
              <Row label="Username" htmlFor="snmp-user">
                <TextInput
                  id="snmp-user"
                  autoComplete="off"
                  value={v3.username}
                  invalid={v3Invalid}
                  onChange={(e) => setV3({ username: e.target.value })}
                  className="flex-1"
                />
              </Row>
              <Row label="Authentication" htmlFor="snmp-auth">
                <Select id="snmp-auth" value={v3.authProtocol} onChange={(e) => setV3({ authProtocol: e.target.value as SnmpAuthProtocol })}>
                  {(["md5", "sha1", "sha224", "sha256", "sha384", "sha512"] as const).map((a) => (
                    <option key={a} value={a}>
                      {a === "sha1" ? "SHA-1" : a.toUpperCase().replace("SHA", "SHA-")}
                    </option>
                  ))}
                </Select>
                <TextInput
                  type={secretType}
                  autoComplete="off"
                  placeholder="Auth password (blank = noAuth)"
                  aria-label="Authentication password"
                  value={v3.authPassword ?? ""}
                  invalid={pwInvalid(authLen)}
                  onChange={(e) => setV3({ authPassword: e.target.value })}
                  className="flex-1"
                />
              </Row>
              <Row label="Privacy" htmlFor="snmp-priv">
                <Select id="snmp-priv" value={v3.privProtocol} onChange={(e) => setV3({ privProtocol: e.target.value as SnmpPrivProtocol })}>
                  {(["des", "aes128", "aes192", "aes256"] as const).map((a) => (
                    <option key={a} value={a}>
                      {a === "des" ? "DES" : `AES-${a.slice(3)}`}
                    </option>
                  ))}
                </Select>
                <TextInput
                  type={secretType}
                  autoComplete="off"
                  placeholder="Privacy password (blank = noPriv)"
                  aria-label="Privacy password"
                  value={v3.privPassword ?? ""}
                  invalid={pwInvalid(privLen)}
                  onChange={(e) => setV3({ privPassword: e.target.value })}
                  className="flex-1"
                />
              </Row>
              {(pwInvalid(authLen) || pwInvalid(privLen)) && (
                <p className="pl-[142px] text-[11px] text-danger">SNMPv3 passwords must be at least 8 characters.</p>
              )}
              {privWithoutAuth && (
                <p className="pl-[142px] text-[11px] text-danger">A privacy password needs an authentication password.</p>
              )}
            </>
          )}
          <Row label="Port" htmlFor="snmp-port">
            <TextInput
              id="snmp-port"
              type="number"
              min={1}
              max={65535}
              value={c.port}
              onChange={(e) => setC({ ...c, port: clampInt(e.target.value, 1, 65535, 161) })}
              className="w-[80px]"
            />
            <span className="text-muted">Timeout</span>
            <TextInput
              type="number"
              min={100}
              max={600000}
              step={100}
              aria-label="Timeout in milliseconds"
              value={c.timeoutMs}
              onChange={(e) => setC({ ...c, timeoutMs: clampInt(e.target.value, 1, 600000, 2000) })}
              className="w-[80px]"
            />
            <span className="text-muted">ms</span>
            <span className="text-muted">Retries</span>
            <TextInput
              type="number"
              min={0}
              max={10}
              aria-label="Retries"
              value={c.retries}
              onChange={(e) => setC({ ...c, retries: clampInt(e.target.value, 0, 10, 1) })}
              className="w-[52px]"
            />
          </Row>
        </fieldset>
        <p className="mt-2 text-[11px] text-muted">
          Credentials are kept in memory only and are never written to disk by the GUI. “Query SNMP Details” on a device uses these
          settings even when polling during scans is off.
        </p>
      </form>
    </Modal>
  );
}

function clampInt(v: string, min: number, max: number, fallback: number): number {
  const n = Math.round(Number(v));
  if (!Number.isFinite(n) || v.trim() === "") return fallback;
  return Math.max(min, Math.min(max, n));
}

export function CustomUrlDialog({
  ip,
  initial,
  onOpen,
  onClose,
}: {
  ip: string;
  initial: string;
  onOpen: (template: string) => void;
  onClose: () => void;
}) {
  const [value, setValue] = useState(initial);
  const valid = /^(https?|ssh|telnet):\/\//i.test(value.trim());
  return (
    <Modal
      title={`Open URL for ${ip}`}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={!valid}
            onClick={() => {
              onOpen(value.trim());
              onClose();
            }}
          >
            Open
          </Button>
        </>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) {
            onOpen(value.trim());
            onClose();
          }
        }}
      >
        <TextInput
          value={value}
          onChange={(e) => setValue(e.target.value)}
          aria-label="URL template"
          invalid={!valid}
          className="w-full"
        />
        {withoutUrlPassword(value).stripped && (
          <p className="mt-2 text-[11px] text-warn">The password in this URL is used for this session only; it is not saved.</p>
        )}
        <p className="mt-2 text-[11px] text-muted">
          <code className="font-mono">{"{ip}"}</code> is replaced with the device address. Allowed schemes: http, https, ssh, telnet.
        </p>
      </form>
    </Modal>
  );
}

/** "Wake by MAC…": send a magic packet to a host that is not in the results. */
export function WakeDialog({
  interfaces,
  initialMac,
  onWake,
  onClose,
}: {
  interfaces: InterfaceInfo[];
  initialMac?: string;
  onWake: (mac: string, opts: WakeOptions) => Promise<boolean>;
  onClose: () => void;
}) {
  const [mac, setMac] = useState(initialMac ?? "");
  const [iface, setIface] = useState("");
  const [broadcast, setBroadcast] = useState("");
  const [port, setPort] = useState(9);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const m = parseWolMac(mac);
  const pw = parseSecureOn(password);
  const bcastOk = broadcast.trim() === "" || ipv4ToNumber(broadcast.trim()) !== null;
  const valid = m.ok && pw.ok && bcastOk;
  const submit = async (): Promise<void> => {
    if (!valid || busy || !m.ok || !pw.ok) return;
    setBusy(true);
    const ok = await onWake(m.value, {
      interface: iface === "" ? null : iface,
      broadcast: broadcast.trim() === "" ? null : broadcast.trim(),
      port,
      password: pw.value,
    });
    setBusy(false);
    if (ok) onClose();
  };
  const usable = interfaces.filter((i) => i.kind !== "loopback" && i.addrs.some((a) => !a.ip.includes(":")));
  return (
    <Modal
      title="Wake on LAN"
      onClose={onClose}
      width={460}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!valid || busy} onClick={() => void submit()}>
            Send Magic Packet
          </Button>
        </>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Row label="MAC address" htmlFor="wol-mac">
          <TextInput
            id="wol-mac"
            value={mac}
            onChange={(e) => setMac(e.target.value)}
            placeholder="aa:bb:cc:dd:ee:ff"
            invalid={mac.trim() !== "" && !m.ok}
            title={!m.ok ? m.error : undefined}
            className="flex-1 font-mono"
          />
        </Row>
        {mac.trim() !== "" && !m.ok && <p className="pb-1 pl-[142px] text-[11px] text-danger">{m.error}</p>}
        <Row label="Interface" htmlFor="wol-iface">
          <Select id="wol-iface" value={iface} onChange={(e) => setIface(e.target.value)} className="flex-1">
            <option value="">Default interface</option>
            {usable.map((i) => (
              <option key={i.name} value={i.name}>
                {interfaceLabel(i)}
              </option>
            ))}
          </Select>
        </Row>
        <Row label="Broadcast" htmlFor="wol-bcast">
          <TextInput
            id="wol-bcast"
            value={broadcast}
            onChange={(e) => setBroadcast(e.target.value)}
            placeholder="subnet broadcast + 255.255.255.255"
            invalid={!bcastOk}
            className="flex-1 font-mono"
          />
        </Row>
        <Row label="UDP port" htmlFor="wol-port">
          <Select id="wol-port" value={port} onChange={(e) => setPort(Number(e.target.value))}>
            <option value={9}>9 (discard)</option>
            <option value={7}>7 (echo)</option>
          </Select>
        </Row>
        <Row label="SecureOn" htmlFor="wol-pw">
          <TextInput
            id="wol-pw"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="optional, e.g. 01:02:03:04:05:06"
            invalid={!pw.ok}
            title={!pw.ok ? pw.error : undefined}
            className="flex-1 font-mono"
          />
        </Row>
        <p className="mt-2 text-[11px] text-muted">
          A directed broadcast (e.g. <code className="font-mono">10.20.0.255</code>) reaches a remote subnet only if its router forwards
          directed broadcasts.
        </p>
      </form>
    </Modal>
  );
}

export interface ReportDialogValues {
  title: string;
  org: string;
  onlyShown: boolean;
}

const REPORT_FORMAT_LABEL: Record<ReportFormat, string> = {
  html: "HTML report",
  pdf: "PDF summary",
  json: "JSON findings",
};

/** Title / organization for the audit report, then the backend's save dialog. */
export function ReportDialog({
  format,
  total,
  shown,
  initial,
  busy,
  error,
  onGenerate,
  onClose,
}: {
  format: ReportFormat;
  total: number;
  /** Devices matching the current search / role filter. */
  shown: number;
  initial: { title: string; org: string };
  /** Status text while building / saving (`null` when idle). */
  busy: string | null;
  error: string | null;
  onGenerate: (v: ReportDialogValues) => void;
  onClose: () => void;
}) {
  const [title, setTitle] = useState(initial.title);
  const [org, setOrg] = useState(initial.org);
  const [onlyShown, setOnlyShown] = useState(false);
  const filtered = shown !== total;
  const count = onlyShown && filtered ? shown : total;
  const submit = (): void => {
    if (busy === null) onGenerate({ title, org, onlyShown: onlyShown && filtered });
  };
  return (
    <Modal
      title={`Audit Report · ${REPORT_FORMAT_LABEL[format]}`}
      onClose={busy === null ? onClose : () => undefined}
      width={460}
      footer={
        <>
          {busy !== null && (
            <span className="mr-auto flex items-center gap-1.5 text-muted" aria-live="polite">
              <LoaderCircle size={13} className="animate-spin" aria-hidden />
              {busy}
            </span>
          )}
          <Button onClick={onClose} disabled={busy !== null}>
            Cancel
          </Button>
          <Button variant="primary" onClick={submit} disabled={busy !== null || count === 0}>
            Save Report…
          </Button>
        </>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <Row label="Title" htmlFor="report-title">
          <TextInput
            id="report-title"
            value={title}
            maxLength={200}
            placeholder={DEFAULT_REPORT_TITLE}
            onChange={(e) => setTitle(e.target.value)}
            className="flex-1"
          />
        </Row>
        <Row label="Organization" htmlFor="report-org">
          <TextInput
            id="report-org"
            value={org}
            maxLength={200}
            placeholder="Customer or site (optional)"
            onChange={(e) => setOrg(e.target.value)}
            className="flex-1"
          />
        </Row>
        {filtered && (
          <Row label="">
            <label className="flex items-center gap-1.5 text-muted">
              <input
                type="checkbox"
                checked={onlyShown}
                onChange={(e) => setOnlyShown(e.target.checked)}
                className="accent-[var(--accent)]"
              />
              Only the {shown.toLocaleString()} devices matching the current filter
            </label>
          </Row>
        )}
        <p className="mt-2 text-[11px] text-muted">
          {count.toLocaleString()} device{count === 1 ? "" : "s"}, VLANs, CDP/LLDP neighbors, MAC-to-port entries and SNMP results go into the
          report with your hostnames, comments and live latency. SNMP communities and SNMPv3 passwords are never included. You choose where
          to save it next.
        </p>
        <p className="mt-1 text-[11px] text-muted">
          A logo in the header can be added with the command line:{" "}
          <code className="selectable font-mono">sweepr report --input audit.json -o audit.html --logo logo.png</code> (from the JSON findings saved here).
        </p>
        {error && <p className="selectable mt-2 text-danger">{error}</p>}
      </form>
    </Modal>
  );
}
