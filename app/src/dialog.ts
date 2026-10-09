// The two file dialogs behind one module so the dev-only mock backend can answer them in a plain browser. In
// production this is a pass-through to the Tauri dialog plugin.
// `__SPARROW_MOCK__` is a compile-time constant (vite.config.ts): false everywhere but `npm run dev:mock`, so Rollup
// drops the dynamic import and the mock with it.
import { open as tauriOpen, save as tauriSave } from "@tauri-apps/plugin-dialog";
import type { OpenDialogOptions, SaveDialogOptions } from "@tauri-apps/plugin-dialog";

export async function open(options?: OpenDialogOptions): Promise<string | string[] | null> {
  if (__SPARROW_MOCK__) return (await import("./mock/backend")).mockOpen(options);
  return tauriOpen(options);
}

export async function save(options?: SaveDialogOptions): Promise<string | null> {
  if (__SPARROW_MOCK__) return (await import("./mock/backend")).mockSave(options);
  return tauriSave(options);
}
