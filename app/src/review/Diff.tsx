// before → after for the keys that changed. Values are shown as safe text, never interpreted.
import { displaySafe } from "../text";

function show(v: unknown): string {
  if (v === null || v === undefined) return "∅";
  return displaySafe(typeof v === "string" ? v : JSON.stringify(v));
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export default function Diff({ before, after }: { before: unknown; after: unknown }) {
  const b = isObject(before) ? before : null;
  const a = isObject(after) ? after : null;
  // Not both records (a bare value, or nothing on one side): show the two values whole.
  if (!(b ?? a) || (before != null && !b) || (after != null && !a)) {
    if (JSON.stringify(before ?? null) === JSON.stringify(after ?? null)) return <span>no change</span>;
    return (
      <span className="diff" title={`${show(before)} → ${show(after)}`}>
        {show(before)} → {show(after)}
      </span>
    );
  }
  const keys = [...new Set([...Object.keys(b ?? {}), ...Object.keys(a ?? {})])].sort();
  const changed = keys.filter((k) => JSON.stringify((b ?? {})[k] ?? null) !== JSON.stringify((a ?? {})[k] ?? null));
  if (changed.length === 0) return <span>no change</span>;
  return (
    <dl className="diff">
      {changed.map((k) => (
        <div key={k} className="diff-line">
          <dt>{displaySafe(k)}</dt>
          <dd title={`${show((b ?? {})[k])} → ${show((a ?? {})[k])}`}>
            {show((b ?? {})[k])} → {show((a ?? {})[k])}
          </dd>
        </div>
      ))}
    </dl>
  );
}
