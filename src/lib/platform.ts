/** The OS the app runs on, from the webview's user agent (WebView2 / WKWebView / WebKitGTK). */
export type Platform = "windows" | "macos" | "linux";

export function detectPlatform(userAgent: string): Platform {
  if (/Windows/i.test(userAgent)) return "windows";
  if (/Macintosh|Mac OS X/i.test(userAgent)) return "macos";
  return "linux";
}

export const PLATFORM: Platform = detectPlatform(typeof navigator === "undefined" ? "" : navigator.userAgent);

/** How to give SweepR raw packet access on this OS (shown where a feature needs it). */
export function rawAccessHint(platform: Platform = PLATFORM): { lead: string; command: string | null; tail: string } {
  switch (platform) {
    case "windows":
      return {
        lead: "On Windows install Npcap (npcap.com); if Npcap is restricted to Administrators, start SweepR from an elevated terminal:",
        command: "sweepr --gui",
        tail: ".",
      };
    case "macos":
      return { lead: "On macOS start SweepR with sudo:", command: "sudo sweepr --gui", tail: "." };
    case "linux":
      return {
        lead: "On Linux grant the binary raw-socket capabilities once:",
        command: "sudo setcap cap_net_raw,cap_net_admin=eip $(command -v sweepr)",
        tail: ", or start it with sudo.",
      };
  }
}
