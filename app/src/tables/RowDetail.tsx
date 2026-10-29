import { displaySafe, displaySafeMultiline } from "../text";
import { rawText } from "../value";

/** JSON text is pretty-printed for reading (still shown as text); anything else is shown as it is. */
function pretty(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "object") return JSON.stringify(v, null, 2);
  if (typeof v === "string") {
    const t = v.trim();
    if (t.startsWith("{") || t.startsWith("[")) {
      try {
        return JSON.stringify(JSON.parse(t) as unknown, null, 2);
      } catch {
        return v;
      }
    }
  }
  return rawText(v);
}

/** Every column of one row, in full: the grid shows a cell on one line, this pane shows all of it. */
export default function RowDetail({ columns, row }: { columns: string[]; row: unknown[] }) {
  return (
    <aside className="row-detail" aria-label="Row detail">
      <h3 className="label">Row</h3>
      <dl>
        {columns.map((c, i) => (
          <div key={`${i}:${c}`} className="row-detail-field">
            <dt className="mono">{displaySafe(c)}</dt>
            <dd>
              <pre className="prose">{displaySafeMultiline(pretty(row[i]))}</pre>
            </dd>
          </div>
        ))}
      </dl>
    </aside>
  );
}
