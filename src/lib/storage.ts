// localStorage helpers. Storage may be unavailable (private mode, quota, sandbox), so every
// access is guarded and the app works with in-memory defaults.

export function loadJson<T>(key: string, fallback: T, validate?: (v: unknown) => v is T): T {
  try {
    const raw = localStorage.getItem(key);
    if (raw === null) return fallback;
    const parsed: unknown = JSON.parse(raw);
    if (validate) return validate(parsed) ? parsed : fallback;
    if (parsed && typeof parsed === "object" && fallback && typeof fallback === "object" && !Array.isArray(fallback)) {
      // Shallow-merge so new settings get their defaults.
      return { ...fallback, ...(parsed as Partial<T>) };
    }
    return parsed as T;
  } catch {
    return fallback;
  }
}

export function saveJson(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* ignore: persistence is best effort */
  }
}

export function removeKey(key: string): void {
  try {
    localStorage.removeItem(key);
  } catch {
    /* ignore */
  }
}

/** Job ids saved in sessionStorage (positive integers; anything else is dropped; at most 256). */
export function parseIdList(raw: string | null): number[] {
  if (raw === null) return [];
  try {
    const v: unknown = JSON.parse(raw);
    if (!Array.isArray(v)) return [];
    return v.filter((x): x is number => typeof x === "number" && Number.isSafeInteger(x) && x > 0).slice(0, 256);
  } catch {
    return [];
  }
}
