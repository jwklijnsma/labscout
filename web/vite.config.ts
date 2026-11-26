import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Builds straight into the Python package, with fixed file names (no hashes): the
// server serves a short whitelist of files and nothing comes from a CDN.
export default defineConfig({
  plugins: [react()],
  base: "/",
  build: {
    outDir: "../src/labscout/web/static",
    emptyOutDir: true,
    assetsDir: "",
    cssCodeSplit: false,
    modulePreload: { polyfill: false },
    sourcemap: false,
    rollupOptions: {
      output: {
        entryFileNames: "app.js",
        chunkFileNames: "app-[name].js",
        assetFileNames: (info) => (info.names?.[0] ?? info.name ?? "").endsWith(".css") ? "app.css" : "[name][extname]",
      },
    },
  },
  server: {
    // `npm run dev` next to `labscout serve --port 8766`
    proxy: { "/api": "http://127.0.0.1:8766" },
  },
});
