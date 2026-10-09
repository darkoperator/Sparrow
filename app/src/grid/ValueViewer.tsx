import { useEffect, useRef } from "react";
import { displaySafe, displaySafeMultiline } from "../text";
import { rawText } from "../value";

/** The complete value as text: objects and JSON text pretty-printed, everything escaped through displaySafe. */
export function fullValueText(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "object") return displaySafeMultiline(JSON.stringify(v, null, 2));
  if (typeof v === "string") {
    const t = v.trim();
    if (t.startsWith("{") || t.startsWith("[")) {
      try {
        const parsed: unknown = JSON.parse(t);
        if (typeof parsed === "object" && parsed !== null) return displaySafeMultiline(JSON.stringify(parsed, null, 2));
      } catch {
        // Not JSON: shown as it is.
      }
    }
    return displaySafeMultiline(v);
  }
  return displaySafe(String(v));
}

/** A dialog with one cell's whole value. Escape or Close dismisses it; the caller returns focus. */
export default function ValueViewer({ column, value, onClose }: { column: string; value: unknown; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const focusable = () => Array.from(ref.current?.querySelectorAll<HTMLElement>("button, [href], input, [tabindex]:not([tabindex='-1'])") ?? []);
  useEffect(() => {
    focusable()[0]?.focus();
    // A modal keeps focus: anything that takes it from outside the dialog is pulled back, and Escape works from
    // wherever the key lands.
    const back = (e: FocusEvent) => {
      if (ref.current && e.target instanceof Node && !ref.current.contains(e.target)) focusable()[0]?.focus();
    };
    const esc = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
    };
    document.addEventListener("focusin", back);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("focusin", back);
      document.removeEventListener("keydown", esc);
    };
  }, [onClose]);
  return (
    <div
      ref={ref}
      role="dialog"
      aria-modal="true"
      aria-label={`Value of ${displaySafe(column)}`}
      className="value-viewer"
      onKeyDown={(e) => {
        if (e.key !== "Tab") return;
        // Tab and Shift+Tab wrap inside the dialog.
        const els = focusable();
        const at = els.indexOf(document.activeElement as HTMLElement);
        if (els.length === 0) return;
        e.preventDefault();
        els[e.shiftKey ? (at <= 0 ? els.length - 1 : at - 1) : (at + 1) % els.length]?.focus();
      }}
    >
      <div className="value-viewer-head">
        <strong>{displaySafe(column)}</strong>
        <button onClick={() => void navigator.clipboard.writeText(rawText(value))}>Copy</button>
        <button onClick={onClose}>Close</button>
      </div>
      <pre className="value-viewer-body">{fullValueText(value)}</pre>
    </div>
  );
}
