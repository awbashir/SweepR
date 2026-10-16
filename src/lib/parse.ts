// User-input parsers that mirror the Rust `FromStr` impls in models.rs, so the GUI can
// validate as you type. The backend re-validates everything.

import type { VlanSelection } from "../types.ts";
import { ipv4ToNumber, numberToIpv4 } from "./ip.ts";

export const MAX_VLAN_ID = 4094;

export type Parsed<T> = { ok: true; value: T } | { ok: false; error: string };

const ok = <T>(value: T): Parsed<T> => ({ ok: true, value });
const err = <T>(error: string): Parsed<T> => ({ ok: false, error });

const UNTAGGED_WORDS = new Set(["untagged", "none", "native"]);

/** Mirror of `VlanSelection::from_str`: `untagged`, `auto`, `10,20,30`, `1-100`, `untagged,10`. */
export function parseVlanSelection(input: string): Parsed<VlanSelection> {
  const s = input.trim();
  const lower = s.toLowerCase();
  if (lower === "" || UNTAGGED_WORDS.has(lower)) return ok({ mode: "untagged" });
  if (lower === "auto" || lower === "auto-detect" || lower === "autodetect") {
    return ok({ mode: "auto_detect" });
  }

  const ids = new Set<number>();
  let untagged = false;
  for (const raw of s.split(/[\s,]+/).filter((p) => p !== "")) {
    if (UNTAGGED_WORDS.has(raw.toLowerCase())) {
      untagged = true;
      continue;
    }
    if (raw.toLowerCase() === "auto") {
      return err("'auto' cannot be combined with other VLAN IDs");
    }
    // Tolerate a leading "VLAN"/"vlan" label ("VLAN 10, 20").
    const part = raw.replace(/^[A-Za-z]+/, "");
    if (part === "") continue;
    const parseId = (t: string): number | string => {
      if (!/^\d+$/.test(t.trim())) return `'${t}' is not a number`;
      const id = Number(t.trim());
      if (id < 1 || id > MAX_VLAN_ID) return `VLAN ID ${id} out of range (1-${MAX_VLAN_ID})`;
      return id;
    };
    const dash = part.indexOf("-");
    if (dash >= 0) {
      const lo = parseId(part.slice(0, dash));
      const hi = parseId(part.slice(dash + 1));
      if (typeof lo === "string") return err(lo);
      if (typeof hi === "string") return err(hi);
      if (lo > hi) return err(`descending range '${part}'`);
      for (let i = lo; i <= hi; i++) ids.add(i);
    } else {
      const id = parseId(part);
      if (typeof id === "string") return err(id);
      ids.add(id);
    }
  }
  const sorted = [...ids].sort((a, b) => a - b);
  if (sorted.length === 0) {
    return untagged ? ok({ mode: "untagged" }) : err(`no VLAN IDs in '${s}'`);
  }
  return ok(untagged ? { mode: "untagged_and_list", ids: sorted } : { mode: "list", ids: sorted });
}

/** Short human label for a selection (status bar / toolbar). */
export function vlanSelectionLabel(sel: VlanSelection): string {
  const list = (ids: number[]): string =>
    ids.length > 6 ? `${ids.slice(0, 5).join(", ")}… (${ids.length})` : ids.join(", ");
  switch (sel.mode) {
    case "untagged":
      return "Untagged";
    case "auto_detect":
      return "Auto-detect";
    case "list":
      return `VLAN ${list(sel.ids)}`;
    case "untagged_and_list":
      return `Untagged + VLAN ${list(sel.ids)}`;
  }
}

/** Mirror of `parse_ports`: `22,80,443` or `1-1024,8443`. Empty input is an empty list. */
export function parsePorts(input: string): Parsed<number[]> {
  const ports = new Set<number>();
  for (const part of input.split(",").map((p) => p.trim()).filter((p) => p !== "")) {
    const parse = (t: string): number | null => {
      if (!/^\d+$/.test(t.trim())) return null;
      const v = Number(t.trim());
      return v >= 1 && v <= 65535 ? v : null;
    };
    const dash = part.indexOf("-");
    if (dash >= 0) {
      const lo = parse(part.slice(0, dash));
      const hi = parse(part.slice(dash + 1));
      if (lo === null || hi === null) return err(`invalid port range '${part}'`);
      if (lo > hi) return err(`descending range '${part}'`);
      if (hi - lo > 65535) return err(`range too large '${part}'`);
      for (let p = lo; p <= hi; p++) ports.add(p);
    } else {
      const v = parse(part);
      if (v === null) return err(`invalid port '${part}'`);
      ports.add(v);
    }
  }
  return ok([...ports].sort((a, b) => a - b));
}

/** Compact a sorted port list back into `22,80,8000-8010` form. */
export function formatPorts(ports: readonly number[]): string {
  const out: string[] = [];
  let i = 0;
  while (i < ports.length) {
    const start = ports[i] as number;
    let end = start;
    while (i + 1 < ports.length && ports[i + 1] === end + 1) {
      end += 1;
      i += 1;
    }
    out.push(end - start >= 2 ? `${start}-${end}` : end === start ? `${start}` : `${start},${end}`);
    i += 1;
  }
  return out.join(",");
}

export interface Ipv4Span {
  start: number;
  end: number;
}

function parseOneTarget(raw: string): Parsed<Ipv4Span> {
  const s = raw.trim();
  const slash = s.indexOf("/");
  if (slash >= 0) {
    const addr = ipv4ToNumber(s.slice(0, slash));
    const prefixText = s.slice(slash + 1);
    if (addr === null) return err(`'${s}': bad address`);
    if (!/^\d{1,2}$/.test(prefixText) || Number(prefixText) > 32) {
      return err(`'${s}': bad prefix length`);
    }
    const prefix = Number(prefixText);
    const size = 2 ** (32 - prefix);
    const net = Math.floor(addr / size) * size;
    const bcast = net + size - 1;
    return prefix >= 31 ? ok({ start: net, end: bcast }) : ok({ start: net + 1, end: bcast - 1 });
  }
  const dash = s.indexOf("-");
  if (dash >= 0) {
    const start = ipv4ToNumber(s.slice(0, dash).trim());
    if (start === null) return err(`'${s}': bad start address`);
    const b = s.slice(dash + 1).trim();
    let end = ipv4ToNumber(b);
    if (end === null) {
      if (!/^\d{1,3}$/.test(b) || Number(b) > 255) return err(`'${s}': bad end address`);
      end = Math.floor(start / 256) * 256 + Number(b);
    }
    if (start > end) return err(`'${s}': descending range`);
    return ok({ start, end });
  }
  const ip = ipv4ToNumber(s);
  if (ip === null) return err(`'${s}': not an IPv4 address, range or CIDR`);
  return ok({ start: ip, end: ip });
}

/**
 * Normalize the range box into the backend syntax and count its addresses.
 * Accepts `10.0.0.1 to 10.0.0.50` / `from X to Y` as well as the CLI syntax
 * (`10.0.0.0/24`, `10.0.0.1-10.0.3.254`, `10.0.0.1-50`, comma lists).
 * Empty input means "the interface's subnet" (`spec: null`).
 */
export function parseRange(input: string): Parsed<{ spec: string | null; spans: Ipv4Span[]; count: number }> {
  let s = input.trim();
  if (s === "") return ok({ spec: null, spans: [], count: 0 });
  s = s
    .replace(/^\s*(scan\s+)?from\s+/i, "")
    .replace(/\s+to\s+/gi, "-")
    .replace(/\s*-\s*/g, "-");
  const parts = s.split(/[\s,]+/).filter((p) => p !== "");
  const spans: Ipv4Span[] = [];
  let count = 0;
  for (const p of parts) {
    const r = parseOneTarget(p);
    if (!r.ok) return r;
    spans.push(r.value);
    count += r.value.end - r.value.start + 1;
  }
  if (spans.length === 0) return err("empty target list");
  return ok({ spec: parts.join(","), spans, count });
}

export function spanLabel(span: Ipv4Span): string {
  return span.start === span.end
    ? numberToIpv4(span.start)
    : `${numberToIpv4(span.start)} – ${numberToIpv4(span.end)}`;
}

/**
 * The URL template without a password in its userinfo (`https://admin:pw@{ip}/` ->
 * `https://admin@{ip}/`), for persisting: credentials typed into the template are used for
 * the session only. `stripped` tells whether anything was removed.
 */
export function withoutUrlPassword(template: string): { value: string; stripped: boolean } {
  const re = /^(\s*[a-z][a-z0-9+.-]*:\/\/)([^/?#@:]*):[^/?#@]*@/i;
  if (!re.test(template)) return { value: template, stripped: false };
  return { value: template.replace(re, (_m, scheme: string, user: string) => (user ? `${scheme}${user}@` : scheme)), stripped: true };
}
