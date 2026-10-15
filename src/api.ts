// Backend access. Inside Tauri this wraps `invoke` / `listen`; in a plain browser (`npm run dev`)
// it falls back to a simulated backend so the UI can be developed and demoed without Rust.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { openUrl as tauriOpenUrl } from "@tauri-apps/plugin-opener";
import type {
  Device,
  ExportFormat,
  InterfaceInfo,
  Overrides,
  ScanConfig,
  ScanEventPayload,
  SnmpConfig,
  SnmpDeviceInfo,
} from "./types.ts";
import { createMockBackend } from "./mock.ts";

export interface Backend {
  readonly isMock: boolean;
  listInterfaces(): Promise<InterfaceInfo[]>;
  startScan(config: ScanConfig): Promise<number>;
  stopScan(scanId?: number): Promise<boolean>;
  startVlanDiscovery(iface: string | null, timeoutSecs?: number): Promise<number>;
  /** Opens the native save dialog in the backend; `null` when the user cancelled. */
  exportDevices(devices: Device[], format: ExportFormat): Promise<string | null>;
  loadOverrides(): Promise<Overrides>;
  saveOverride(key: string, hostname: string | null, comments: string | null): Promise<void>;
  scanPorts(ip: string, ports: number[]): Promise<number[]>;
  querySnmp(ip: string, snmp: SnmpConfig | null): Promise<SnmpDeviceInfo>;
  /** Subscribe to `scan-event`; resolves to an unsubscribe function. */
  onScanEvent(handler: (payload: ScanEventPayload) => void): Promise<() => void>;
  openUrl(url: string): Promise<void>;
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
    startVlanDiscovery: (iface, timeoutSecs) =>
      invoke<number>("start_vlan_discovery", { interface: iface, timeoutSecs: timeoutSecs ?? null }),
    exportDevices: (devices, format) => invoke<string | null>("export_devices", { devices, format }),
    loadOverrides: async () => (await invoke<Overrides | null>("load_overrides")) ?? {},
    saveOverride: (key, hostname, comments) =>
      invoke<void>("save_override", { key, hostname, comments }),
    scanPorts: (ip, ports) => invoke<number[]>("scan_ports", { ip, ports }),
    querySnmp: (ip, snmp) => invoke<SnmpDeviceInfo>("query_snmp", { ip, snmp }),
    onScanEvent: (handler) => listen<ScanEventPayload>("scan-event", (e) => handler(e.payload)),
    openUrl: (url) => tauriOpenUrl(url),
  };
}

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
  }
}

export const isTauri = typeof window !== "undefined" && window.__TAURI_INTERNALS__ !== undefined;

export const backend: Backend = isTauri ? createTauriBackend() : createMockBackend();
