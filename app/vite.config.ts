import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The Tauri dev server URL (tauri.conf.json `build.devUrl`) expects port 5173.
// `__SPARROW_MOCK__` is a compile-time constant: true only for the dev server started in `mock` mode (`npm run
// dev:mock`). Every other command and mode (`vite build` in any env, `vite` with the default mode, Vitest) compiles it
// to `false`, so the mock backend can neither run nor be bundled outside that one dev server.
export default defineConfig(({ command, mode }) => ({
  plugins: [react()],
  clearScreen: false,
  define: { __SPARROW_MOCK__: JSON.stringify(command === "serve" && mode === "mock") },
  server: { port: 5173, strictPort: true },
  build: { outDir: "dist", emptyOutDir: true },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    // The slowest tests take a few seconds: Vitest's default 5 s fails them when a build is using the CPU.
    testTimeout: 20_000,
  },
}));
