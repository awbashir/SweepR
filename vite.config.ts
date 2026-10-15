import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// https://v2.tauri.app/start/frontend/vite/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Keep Rust compiler output visible in `tauri dev`.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      // The Rust side is rebuilt by `tauri dev`; never reload the webview for it.
      ignored: ["**/src-tauri/**"],
    },
  },
  envPrefix: ["VITE_", "TAURI_ENV_"],
  build: {
    // Tauri v2 on macOS 11+ uses WKWebView (Safari 15+); Tailwind v4 itself needs Safari 16.4.
    target: ["es2022", "safari16"],
    outDir: "dist",
    emptyOutDir: true,
  },
});
