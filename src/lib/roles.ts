// Role provenance helpers (pure, framework-free): confidence, the one-line summary shown in
// the Device Role tooltip and the Details drawer header, and the guess marker.

import { ROLE_LABEL, ROLE_SOURCE_LABEL, type Device, type RoleConfidence } from "../types.ts";

type RoleFields = Pick<Device, "role" | "roleSource" | "roleConfidence" | "roleEvidence">;

/** Confidence of the role: null for a plain host; an infrastructure role without one is "medium". */
export function effectiveConfidence(d: RoleFields): RoleConfidence | null {
  if (d.role === "host") return null;
  return d.roleConfidence ?? "medium";
}

/** A low-confidence guess (host name / OUI hints), as opposed to a role the device reported. */
export function isRoleGuess(d: RoleFields): boolean {
  return effectiveConfidence(d) === "low";
}

/** "mDNS name" from "mDNS name 'switch375bc6.local': ..." (the name source of a name hint). */
function nameSourceOf(evidence: readonly string[]): string | null {
  for (const e of evidence) {
    const m = /^(user label|mDNS name|DNS name|NetBIOS name|TLS certificate CN) '/.exec(e);
    if (m) return m[1]!;
  }
  return null;
}

/** "Cisco OUI" from "Cisco OUI (network vendor)" / "TP-Link OUI (also makes end devices)". */
function vendorOf(evidence: readonly string[]): string | null {
  for (const e of evidence) {
    const m = /^(.+ OUI) \((network vendor|also makes end devices)\)$/.exec(e);
    if (m) return m[1]!;
  }
  return null;
}

/**
 * One line describing the role and where it came from, e.g.
 * "Switch — from mDNS name + Cisco OUI (low confidence)", "Switch — from SNMP (high confidence)",
 * "Host — possible network device: Ruijie OUI", or just "Host".
 */
export function roleSummary(d: RoleFields): string {
  const label = ROLE_LABEL[d.role] ?? d.role;
  const evidence = d.roleEvidence ?? [];
  if (d.role === "host") {
    const hint = evidence.find((e) => e.startsWith("possible "));
    return hint ? `${label} — ${hint}` : label;
  }
  const conf = effectiveConfidence(d);
  if (!d.roleSource) return conf && d.roleConfidence ? `${label} (${conf} confidence)` : label;
  let from = ROLE_SOURCE_LABEL[d.roleSource] ?? d.roleSource;
  if (d.roleSource === "name") from = nameSourceOf(evidence) ?? from;
  const vendor = vendorOf(evidence);
  if (vendor && ["name", "mdns_service", "oui_ports", "web"].includes(d.roleSource)) from += ` + ${vendor}`;
  return `${label} — from ${from} (${conf} confidence)`;
}

/** Tooltip text: the summary, then each piece of evidence on its own line. */
export function roleTooltip(d: RoleFields, extra: readonly string[] = []): string {
  const head = [roleSummary(d), ...extra].join(" · ");
  const evidence = (d.roleEvidence ?? []).filter((e) => !e.startsWith("possible "));
  return evidence.length > 0 ? `${head}\n${evidence.map((e) => `• ${e}`).join("\n")}` : head;
}
