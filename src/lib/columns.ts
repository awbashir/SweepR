// Column-preference helpers for the device table (kept framework-free for tests).

/**
 * Stored column order completed with columns added in later versions: each missing column is
 * inserted right after its nearest default predecessor that is present (else first).
 */
export function completeOrder<T extends string>(stored: readonly string[], all: readonly T[]): T[] {
  const known = new Set<string>(all);
  const order = [...new Set(stored.filter((c): c is T => known.has(c)))];
  for (let i = 0; i < all.length; i++) {
    const c = all[i]!;
    if (order.includes(c)) continue;
    let at = 0;
    for (let j = i - 1; j >= 0; j--) {
      const k = order.indexOf(all[j]!);
      if (k >= 0) {
        at = k + 1;
        break;
      }
    }
    order.splice(at, 0, c);
  }
  return order;
}

/**
 * Columns whose default visibility follows the data: Latency / Loss % while live latency is
 * on, Web Title / Cert Expires once some device has one; Web Identity / Cert CN start hidden.
 * An explicit choice from the header menu (`stored`) always wins.
 */
export interface AutoColumns {
  liveLatency: boolean;
  webTitle: boolean;
  certExpires: boolean;
  /** Device Kind / Model/Firmware / PoE / Voice VLAN / OS (DHCP) once some device has one. */
  deviceKind?: boolean;
  modelFw?: boolean;
  poe?: boolean;
  voiceVlan?: boolean;
  dhcpOs?: boolean;
}

/** Which auto columns have data in `devices` (stops early once every flag is set). */
export function detectAutoColumns(
  devices: Iterable<{ device: { webTitle: string | null; tlsCert: unknown; voiceVlan?: number | null; poe?: { watts: number | null; maxWatts: number | null } | null; dhcpFingerprint?: { os: string | null } | null }; kind: string; modelFw: string }>,
): Omit<AutoColumns, "liveLatency"> {
  const a = { webTitle: false, certExpires: false, deviceKind: false, modelFw: false, poe: false, voiceVlan: false, dhcpOs: false };
  let left = 7;
  const set = (k: keyof typeof a): void => {
    if (!a[k]) {
      a[k] = true;
      left--;
    }
  };
  for (const r of devices) {
    const d = r.device;
    if (d.webTitle) set("webTitle");
    if (d.tlsCert) set("certExpires");
    if (r.kind) set("deviceKind");
    if (r.modelFw) set("modelFw");
    if (d.poe && (d.poe.watts !== null || d.poe.maxWatts !== null)) set("poe");
    if (d.voiceVlan !== null && d.voiceVlan !== undefined) set("voiceVlan");
    if (d.dhcpFingerprint?.os) set("dhcpOs");
    if (left === 0) break;
  }
  return a;
}

export function effectiveVisibility(stored: Readonly<Record<string, boolean>>, auto: AutoColumns): Record<string, boolean> {
  return {
    webIdentity: false,
    certCn: false,
    latency: auto.liveLatency,
    loss: auto.liveLatency,
    webTitle: auto.webTitle,
    certExpires: auto.certExpires,
    deviceKind: auto.deviceKind ?? false,
    modelFw: auto.modelFw ?? false,
    poe: auto.poe ?? false,
    voiceVlan: auto.voiceVlan ?? false,
    dhcpOs: auto.dhcpOs ?? false,
    ...stored,
  };
}
