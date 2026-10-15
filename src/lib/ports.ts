// Port-scanner presets for the Details drawer.

export interface PortPreset {
  id: string;
  label: string;
  ports: number[];
}

/** `DEFAULT_PORTS` in models.rs (management-plane fingerprinting). */
export const DEFAULT_SCAN_PORTS = [22, 23, 80, 161, 443, 445, 8291, 8443, 10443];

const MANAGEMENT = [
  22, 23, 80, 161, 443, 830, 2000, 4786, 5000, 5001, 8080, 8291, 8443, 8728, 8729, 10443,
];

const COMMON = [
  21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587, 631, 993, 995, 1433,
  1723, 3306, 3389, 5060, 5432, 5900, 8080, 8443,
];

// nmap's top TCP ports (first 100).
const TOP_100 = [
  7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143,
  144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646,
  873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
  2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190,
  5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
  8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
];

export const PORT_PRESETS: readonly PortPreset[] = [
  { id: "common", label: "Common services", ports: COMMON },
  { id: "management", label: "Network management", ports: MANAGEMENT },
  { id: "top100", label: "Top 100", ports: TOP_100 },
  { id: "default", label: "SweepR defaults", ports: DEFAULT_SCAN_PORTS },
];

const SERVICE_NAMES: Record<number, string> = {
  21: "ftp",
  22: "ssh",
  23: "telnet",
  25: "smtp",
  53: "dns",
  80: "http",
  110: "pop3",
  135: "msrpc",
  139: "netbios",
  143: "imap",
  161: "snmp",
  389: "ldap",
  443: "https",
  445: "smb",
  548: "afp",
  554: "rtsp",
  631: "ipp",
  830: "netconf",
  1433: "mssql",
  1723: "pptp",
  1900: "upnp",
  3306: "mysql",
  3389: "rdp",
  4786: "smart-install",
  5060: "sip",
  5432: "postgres",
  5900: "vnc",
  8080: "http-alt",
  8291: "winbox",
  8443: "https-alt",
  8728: "routeros-api",
  9100: "jetdirect",
  10443: "fortigate",
};

export function serviceName(port: number): string | undefined {
  return SERVICE_NAMES[port];
}
