// Backend access. Inside Tauri this wraps `invoke` / `listen`; in a plain browser (`npm run dev`)
// it falls back to a simulated backend so the UI can be developed and demoed without Rust.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { openUrl as tauriOpenUrl } from "@tauri-apps/plugin-opener";
import { getVersion } from "@tauri-apps/api/app";
import type {
  Device,
  ExportFormat,
  GenerateReportArgs,
  InterfaceInfo,
  IperfAvailability,
  IperfOptions,
  IperfUpdate,
  LatencyUpdate,
  Overrides,
  ScanConfig,
  ScanEventPayload,
  ServiceDiscovery,
  SnmpConfig,
  SnmpDeviceInfo,
  TraceUpdate,
  WakeOptions,
  WakeResult,
  WebIdentity,
} from "./types.ts";

export interface Backend {
  readonly isMock: boolean;
  listInterfaces(): Promise<InterfaceInfo[]>;
  startScan(config: ScanConfig): Promise<number>;
  stopScan(scanId?: number): Promise<boolean>;
  startVlanDiscovery(iface: string | null, timeoutSecs?: number, dhcpFingerprint?: boolean): Promise<number>;
  /** Opens the native save dialog in the backend; `null` when the user cancelled. */
  exportDevices(devices: Device[], format: ExportFormat): Promise<string | null>;
  loadOverrides(): Promise<Overrides>;
  saveOverride(key: string, hostname: string | null, comments: string | null): Promise<void>;
  scanPorts(ip: string, ports: number[]): Promise<number[]>;
  querySnmp(ip: string, snmp: SnmpConfig | null): Promise<SnmpDeviceInfo>;
  /** Subscribe to `scan-event`; resolves to an unsubscribe function. */
  onScanEvent(handler: (payload: ScanEventPayload) => void): Promise<() => void>;
  openUrl(url: string): Promise<void>;

  // Network utilities (independent of scans).
  wakeDevice(mac: string, opts?: WakeOptions): Promise<WakeResult>;
  startLatencyMonitor(ips: string[], intervalMs?: number | null, tcpPorts?: Record<string, number[]> | null): Promise<number>;
  stopLatencyMonitor(monitorId: number): Promise<boolean>;
  onLatencyUpdate(handler: (u: LatencyUpdate) => void): Promise<() => void>;
  startTrace(ip: string, maxHops?: number | null, rounds?: number | null): Promise<number>;
  stopTrace(traceId: number): Promise<boolean>;
  onTraceUpdate(handler: (u: TraceUpdate) => void): Promise<() => void>;
  grabWebIdentity(ip: string, ports?: number[] | null): Promise<WebIdentity>;
  iperfAvailable(): Promise<IperfAvailability>;
  startIperf(ip: string, options?: IperfOptions | null): Promise<number>;
  stopIperf(runId: number): Promise<boolean>;
  onIperfUpdate(handler: (u: IperfUpdate) => void): Promise<() => void>;

  // Deeper discovery and the audit report.
  /** Unicast SSDP + WS-Discovery + SIP OPTIONS to one host (`timeoutMs` 500-5000, default 2500). */
  discoverServices(ip: string, timeoutMs?: number | null): Promise<ServiceDiscovery>;
  /** Builds the report and opens the native save dialog in the backend; `null` when cancelled. */
  generateReport(args: GenerateReportArgs): Promise<string | null>;
  /** Reveals the report last written by `generateReport`; `false` when none was written. */
  revealReport(): Promise<boolean>;
  /** Application version ("0.1.0"). */
  appVersion(): Promise<string>;
}

/** Tauri command errors are plain strings; everything else is normalized to one. */
export function errorMessage(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  if (e && typeof e === "object" && "message" in e && typeof e.message === "string") {
    return e.message;
  }
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}

function createTauriBackend(): Backend {
  return {
    isMock: false,
    listInterfaces: () => invoke<InterfaceInfo[]>("list_interfaces"),
    startScan: (config) => invoke<number>("start_scan", { config }),
    stopScan: (scanId) => invoke<boolean>("stop_scan", { scanId: scanId ?? null }),
    startVlanDiscovery: (iface, timeoutSecs, dhcpFingerprint) =>
      invoke<number>("start_vlan_discovery", {
        interface: iface,
        timeoutSecs: timeoutSecs ?? null,
        dhcpFingerprint: dhcpFingerprint ?? null,
      }),
    exportDevices: (devices, format) => invoke<string | null>("export_devices", { devices, format }),
    loadOverrides: async () => (await invoke<Overrides | null>("load_overrides")) ?? {},
    saveOverride: (key, hostname, comments) =>
      invoke<void>("save_override", { key, hostname, comments }),
    scanPorts: (ip, ports) => invoke<number[]>("scan_ports", { ip, ports }),
    querySnmp: (ip, snmp) => invoke<SnmpDeviceInfo>("query_snmp", { ip, snmp }),
    onScanEvent: (handler) => listen<ScanEventPayload>("scan-event", (e) => handler(e.payload)),
    openUrl: (url) => tauriOpenUrl(url),
    wakeDevice: (mac, o) =>
      invoke<WakeResult>("wake_device", {
        mac,
        interface: o?.interface ?? null,
        broadcast: o?.broadcast ?? null,
        port: o?.port ?? null,
        repeat: o?.repeat ?? null,
        password: o?.password ?? null,
      }),
    startLatencyMonitor: (ips, intervalMs, tcpPorts) =>
      invoke<number>("start_latency_monitor", { ips, intervalMs: intervalMs ?? null, tcpPorts: tcpPorts ?? null }),
    stopLatencyMonitor: (monitorId) => invoke<boolean>("stop_latency_monitor", { monitorId }),
    onLatencyUpdate: (handler) => listen<LatencyUpdate>("latency-update", (e) => handler(e.payload)),
    startTrace: (ip, maxHops, rounds) => invoke<number>("start_trace", { ip, maxHops: maxHops ?? null, rounds: rounds ?? null }),
    stopTrace: (traceId) => invoke<boolean>("stop_trace", { traceId }),
    onTraceUpdate: (handler) => listen<TraceUpdate>("trace-update", (e) => handler(e.payload)),
    grabWebIdentity: (ip, ports) => invoke<WebIdentity>("grab_web_identity", { ip, ports: ports ?? null }),
    iperfAvailable: () => invoke<IperfAvailability>("iperf_available"),
    startIperf: (ip, options) => invoke<number>("start_iperf", { ip, options: options ?? null }),
    stopIperf: (runId) => invoke<boolean>("stop_iperf", { runId }),
    onIperfUpdate: (handler) => listen<IperfUpdate>("iperf-update", (e) => handler(e.payload)),
    discoverServices: (ip, timeoutMs) => invoke<ServiceDiscovery>("discover_services", { ip, timeoutMs: timeoutMs ?? null }),
    // Tauri maps the top-level keys onto the command's (camelCase) arguments.
    generateReport: (args) => invoke<string | null>("generate_report", { ...args }),
    revealReport: () => invoke<boolean>("reveal_report"),
    appVersion: () => getVersion(),
  };
}

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
  }
}

export const isTauri = typeof window !== "undefined" && window.__TAURI_INTERNALS__ !== undefined;

/**
 * The simulated backend, loaded on first use so the desktop build does not carry it in the
 * main chunk. Every `Backend` method is async, so each call simply waits for the module.
 */
function createLazyMockBackend(): Backend {
  let loaded: Promise<Backend> | null = null;
  const load = (): Promise<Backend> => (loaded ??= import("./mock.ts").then((m) => m.createMockBackend()));
  return new Proxy({} as Backend, {
    get(_target, key) {
      if (key === "isMock") return true;
      if (typeof key !== "string" || key === "then") return undefined;
      return (...args: unknown[]) =>
        load().then((b) => (b[key as keyof Backend] as unknown as (...a: unknown[]) => Promise<unknown>)(...args));
    },
  });
}

export const backend: Backend = isTauri ? createTauriBackend() : createLazyMockBackend();
