// Unit tests for the per-OS raw-access hint (Windows: Npcap, macOS: sudo, Linux: setcap).

import { test } from "node:test";
import assert from "node:assert/strict";
import { detectPlatform, rawAccessHint } from "./platform.ts";

test("platform: detected from the webview user agent", () => {
  assert.equal(detectPlatform("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/141.0"), "windows");
  assert.equal(detectPlatform("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"), "macos");
  assert.equal(detectPlatform("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15"), "linux");
  assert.equal(detectPlatform(""), "linux");
});

test("platform: raw-access hints name each OS's mechanism", () => {
  assert.match(rawAccessHint("windows").lead, /Npcap/);
  assert.equal(rawAccessHint("macos").command, "sudo sweepr --gui");
  assert.match(rawAccessHint("linux").command ?? "", /setcap cap_net_raw,cap_net_admin=eip/);
});
