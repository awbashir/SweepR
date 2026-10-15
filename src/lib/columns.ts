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
}

export function effectiveVisibility(stored: Readonly<Record<string, boolean>>, auto: AutoColumns): Record<string, boolean> {
  return {
    webIdentity: false,
    certCn: false,
    latency: auto.liveLatency,
    loss: auto.liveLatency,
    webTitle: auto.webTitle,
    certExpires: auto.certExpires,
    ...stored,
  };
}
