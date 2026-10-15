// SNMP settings and "Open custom URL" dialogs.

import { useState, type ReactNode } from "react";
import type { SnmpAuthProtocol, SnmpConfig, SnmpPrivProtocol, SnmpV3Credentials, SnmpVersion } from "../types.ts";
import { DEFAULT_SNMP } from "../settings.ts";
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
  config,
  onSave,
  onClose,
}: {
  enabled: boolean;
  config: SnmpConfig;
  onSave: (enabled: boolean, config: SnmpConfig) => void;
  onClose: () => void;
}) {
  const [on, setOn] = useState(enabled);
  const [c, setC] = useState<SnmpConfig>(config);
  const [showSecrets, setShowSecrets] = useState(false);
  const v3 = c.v3 ?? EMPTY_V3;
  const setV3 = (patch: Partial<SnmpV3Credentials>): void => setC({ ...c, v3: { ...v3, ...patch } });
  const v3Invalid = on && c.version === "v3" && v3.username.trim() === "";
  const authLen = (v3.authPassword ?? "").length;
  const privLen = (v3.privPassword ?? "").length;
  const pwInvalid = (n: number): boolean => n > 0 && n < 8;
  const invalid = v3Invalid || (c.version === "v3" && (pwInvalid(authLen) || pwInvalid(privLen)));
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
              onSave(on, { ...c, v3: c.version === "v3" ? v3 : c.v3 });
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
        <Row label="">
          <Toggle checked={on} onChange={setOn} label="Poll infrastructure over SNMP during scans" />
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
        <p className="mt-2 text-[11px] text-muted">
          <code className="font-mono">{"{ip}"}</code> is replaced with the device address. Allowed schemes: http, https, ssh, telnet.
        </p>
      </form>
    </Modal>
  );
}
