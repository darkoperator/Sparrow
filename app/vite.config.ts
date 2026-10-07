import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The Tauri dev server URL (tauri.conf.json `build.devUrl`) expects port 5173.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 5173, strictPort: true },
  build: { outDir: "dist", emptyOutDir: true },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
  },
});
