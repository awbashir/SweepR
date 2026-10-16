// What an error boundary tells the user about a crash. Framework-free for tests.

export interface CrashInfo {
  title: string;
  detail: string;
  /** A lazily loaded chunk failed to load (a retry may fix it; Reload certainly does). */
  chunk: boolean;
}

const CHUNK_PATTERNS = [
  /failed to fetch dynamically imported module/i,
  /importing a module script failed/i,
  /error loading dynamically imported module/i,
  /loading (css )?chunk \S+ failed/i,
  /unable to preload css/i,
];

export function isChunkLoadError(e: unknown): boolean {
  const msg = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
  return CHUNK_PATTERNS.some((re) => re.test(msg));
}

/** `what` names the area, e.g. "The topology map". */
export function describeCrash(what: string, e: unknown): CrashInfo {
  const raw = e instanceof Error ? e.message : typeof e === "string" ? e : "unknown error";
  const detail = raw.length > 300 ? `${raw.slice(0, 300)}…` : raw;
  if (isChunkLoadError(e)) {
    return { title: `${what} could not be loaded`, detail, chunk: true };
  }
  return { title: `${what} ran into a problem`, detail, chunk: false };
}

/** `?crash=<area>` (mock mode only): the area that throws until "Try Again" (headless checks). */
export function crashTestArea(search: string): string | null {
  return new URLSearchParams(search).get("crash");
}

/** Armed test crashes (see `crashTestArea`); a boundary's Try Again disarms them. */
const armed = new Set<string>();
export function armCrashTest(area: string | null): void {
  if (area) armed.add(area);
}
export function crashTestArmed(area: string): boolean {
  return armed.has(area);
}
export function disarmCrashTests(): void {
  armed.clear();
}
