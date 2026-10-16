// Unit tests for the persisted scan settings: SNMP secrets are never stored, and a restart
// with SNMP enabled asks for them again instead of polling with "public" / noAuthNoPriv.

import { test } from "node:test";
import assert from "node:assert/strict";
import type { SnmpConfig } from "../types.ts";
import { DEFAULT_SETTINGS, DEFAULT_SNMP, buildScanConfig, normalizeSettings, persistableSettings, snmpHasSecret, type ScanSettings } from "../settings.ts";

/** What a restart sees: the persisted JSON, read back and normalized. */
const restart = (s: ScanSettings): ScanSettings => normalizeSettings(JSON.parse(JSON.stringify(persistableSettings(s))) as Partial<ScanSettings>);

const v3: SnmpConfig = {
  ...DEFAULT_SNMP,
  version: "v3",
  v3: { username: "monitor", authProtocol: "sha256", authPassword: "auth-pass-1", privProtocol: "aes128", privPassword: "priv-pass-1" },
};

test("settings: a custom community is never stored and must be re-entered after a restart", () => {
  const s: ScanSettings = { ...DEFAULT_SETTINGS, snmpEnabled: true, snmp: { ...DEFAULT_SNMP, community: "n0c-r3ad" } };
  assert.equal(snmpHasSecret(s.snmp), true);
  const stored = JSON.stringify(persistableSettings(s));
  assert.equal(stored.includes("n0c-r3ad"), false);
  const after = restart(s);
  assert.equal(after.snmpCredentialsMissing, true);
  assert.equal(after.snmp.community, "", "never silently replaced by public");
  const built = buildScanConfig(after);
  assert.ok(built.ok);
  assert.equal(built.value.config.snmp, null, "the scan runs without SNMP");
  assert.equal(built.value.config.snmpAll, false);
  assert.equal(built.value.snmpSkipped, true);
  // Re-entered this session (the SNMP dialog clears the flag): polling uses it again, and the
  // next restart asks again.
  const fixed: ScanSettings = { ...after, snmp: { ...after.snmp, community: "n0c-r3ad" }, snmpCredentialsMissing: false };
  const b2 = buildScanConfig(fixed);
  assert.ok(b2.ok);
  assert.equal(b2.value.config.snmp?.community, "n0c-r3ad");
  assert.equal(b2.value.snmpSkipped, false);
  assert.equal(restart(fixed).snmpCredentialsMissing, true);
});

test("settings: SNMPv3 passwords are never stored; a restart does not fall back to noAuthNoPriv", () => {
  const s: ScanSettings = { ...DEFAULT_SETTINGS, snmpEnabled: true, snmp: v3 };
  const stored = JSON.stringify(persistableSettings(s));
  for (const secret of ["auth-pass-1", "priv-pass-1"]) assert.equal(stored.includes(secret), false, secret);
  const after = restart(s);
  assert.equal(after.snmp.v3?.username, "monitor", "the user name is kept");
  assert.equal(after.snmp.v3?.authPassword, null);
  assert.equal(after.snmpCredentialsMissing, true);
  const built = buildScanConfig(after);
  assert.ok(built.ok);
  assert.equal(built.value.config.snmp, null);
  // A v3 profile without passwords (noAuthNoPriv by choice) has nothing to re-enter.
  const noAuth: ScanSettings = { ...s, snmp: { ...v3, v3: { ...v3.v3!, authPassword: null, privPassword: null } } };
  assert.equal(restart(noAuth).snmpCredentialsMissing, false);
});

test("settings: the public community (chosen by the user) survives a restart", () => {
  const s: ScanSettings = { ...DEFAULT_SETTINGS, snmpEnabled: true };
  const after = restart(s);
  assert.equal(after.snmpCredentialsMissing, false);
  assert.equal(after.snmp.community, "public");
  const built = buildScanConfig(after);
  assert.ok(built.ok);
  assert.equal(built.value.config.snmp?.community, "public");
  // SNMP off: nothing to ask for, but the flag still remembers a dropped secret.
  const off = restart({ ...DEFAULT_SETTINGS, snmp: { ...DEFAULT_SNMP, community: "x-secret" } });
  assert.equal(off.snmpCredentialsMissing, true);
  const b = buildScanConfig(off);
  assert.ok(b.ok);
  assert.equal(b.value.snmpSkipped, false, "SNMP is off anyway");
});

test("settings: settings stored before the flag existed ask for credentials when SNMP was on", () => {
  const legacy = { ...DEFAULT_SETTINGS, snmpEnabled: true } as Partial<ScanSettings>;
  delete legacy.snmpCredentialsMissing;
  assert.equal(normalizeSettings(legacy).snmpCredentialsMissing, true);
  assert.equal(persistableSettings(legacy as ScanSettings).snmpCredentialsMissing, true);
  const legacyOff = { ...legacy, snmpEnabled: false };
  assert.equal(normalizeSettings(legacyOff).snmpCredentialsMissing, false);
  assert.deepEqual(normalizeSettings(null), DEFAULT_SETTINGS);
});
