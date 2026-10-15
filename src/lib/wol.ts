// Wake-on-LAN input validation (mirrors `wol::parse_wol_mac` / `parse_secureon`).

import type { Parsed } from "./parse.ts";

/**
 * Accepts `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff` and `aabbccddeeff`.
 * Rejects broadcast, multicast and all-zero addresses (they cannot identify one NIC).
 */
export function parseWolMac(input: string): Parsed<string> {
  const hex = input.trim().replace(/[:\-.\s]/g, "").toLowerCase();
  if (!/^[0-9a-f]{12}$/.test(hex)) return { ok: false, error: "enter a MAC address like aa:bb:cc:dd:ee:ff" };
  if (/^0{12}$/.test(hex)) return { ok: false, error: "the all-zero MAC address cannot be woken" };
  if (/^f{12}$/.test(hex)) return { ok: false, error: "the broadcast MAC address cannot be woken" };
  if (parseInt(hex.slice(0, 2), 16) & 1) return { ok: false, error: "that is a multicast MAC address" };
  return { ok: true, value: hex.match(/../g)!.join(":") };
}

/** SecureOn password: blank (none) or 6 bytes written like a MAC address. */
export function parseSecureOn(input: string): Parsed<string | null> {
  const s = input.trim();
  if (s === "") return { ok: true, value: null };
  const hex = s.replace(/[:\-.\s]/g, "").toLowerCase();
  if (!/^[0-9a-f]{12}$/.test(hex)) return { ok: false, error: "a SecureOn password is 6 bytes, e.g. 01:02:03:04:05:06" };
  return { ok: true, value: hex.match(/../g)!.join(":") };
}
