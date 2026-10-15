// IP helpers: sort keys (numeric IPv4 then IPv6), IPv4 ranges, URL formatting.

/** Parse dotted IPv4 into an unsigned 32-bit number, or `null`. */
export function ipv4ToNumber(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

export function numberToIpv4(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

/** Expand an IPv6 address (optionally with `%zone` / embedded IPv4) to 8 x 16-bit groups. */
export function ipv6Groups(ip: string): number[] | null {
  let s = ip.trim();
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  if (!s.includes(":")) return null;

  // Embedded IPv4 tail (::ffff:10.0.0.1).
  let tail: number[] = [];
  const lastColon = s.lastIndexOf(":");
  const maybeV4 = s.slice(lastColon + 1);
  if (maybeV4.includes(".")) {
    const n = ipv4ToNumber(maybeV4);
    if (n === null) return null;
    tail = [(n >>> 16) & 0xffff, n & 0xffff];
    s = s.slice(0, lastColon + 1); // "::ffff:" or "::"
    if (!s.endsWith("::")) s = s.slice(0, -1);
  }

  const halves = s.split("::");
  if (halves.length > 2) return null;
  const parse = (part: string): number[] | null => {
    if (part === "") return [];
    const out: number[] = [];
    for (const g of part.split(":")) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = parse(halves[0] ?? "");
  if (head === null) return null;
  const want = 8 - tail.length;
  if (halves.length === 2) {
    const rest = parse(halves[1] ?? "");
    if (rest === null) return null;
    const fill = want - head.length - rest.length;
    if (fill < 0) return null;
    return [...head, ...new Array<number>(fill).fill(0), ...rest, ...tail];
  }
  if (head.length !== want) return null;
  return [...head, ...tail];
}

export function isIpv6(ip: string): boolean {
  return ip.includes(":");
}

/**
 * Fixed-width string that sorts addresses numerically: all IPv4 (prefix `4`) before IPv6
 * (prefix `6`), unparsable text last. Plain string comparison is then correct and cheap,
 * which matters when sorting 50k+ rows.
 */
export function ipSortKey(ip: string): string {
  const v4 = ipv4ToNumber(ip);
  if (v4 !== null) return "4" + v4.toString(16).padStart(8, "0");
  const g = ipv6Groups(ip);
  if (g !== null) return "6" + g.map((x) => x.toString(16).padStart(4, "0")).join("");
  return "9" + ip;
}

/** Device identity, mirroring `Device::key()` in models.rs. */
export function deviceKey(ip: string, vlanId: number | null): string {
  return vlanId === null ? ip : `${ip}@${vlanId}`;
}

/** Host part for a URL: IPv6 literals need brackets (and an escaped zone id). */
export function urlHost(ip: string): string {
  if (!isIpv6(ip)) return ip;
  return `[${ip.replace("%", "%25")}]`;
}
