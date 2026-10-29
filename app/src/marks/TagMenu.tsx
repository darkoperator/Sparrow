// The Tag submenu: every tag in the case as a tick box over the target rows (checked: all carry it, mixed: some do),
// a filter box above `FILTER_MIN` tags, and "New tag…" pinned at the end. A pure builder, so it is tested without a DOM.
import { useState } from "react";
import type { EventRow, RowRef, TagInfo } from "../api";
import type { MenuItem } from "../grid/CellMenu";
import { displaySafe } from "../text";

export const NEW_TAG = "New tag…";

export function tagItems(
  tags: TagInfo[],
  targets: EventRow[],
  act: { tagRows: (rows: RowRef[], tag: string, add: boolean) => void; newTag: (rows: RowRef[]) => void },
): MenuItem[] {
  const refs: RowRef[] = targets.map((r) => ({ source_table: r.source_table, record_key: r.record_key }));
  const items: MenuItem[] = [...tags]
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((t) => {
      const have = targets.filter((r) => r.tags.some((x) => x.name === t.name)).length;
      const state: boolean | "mixed" = have === 0 ? false : have === targets.length ? true : "mixed";
      // All carry it: the click removes it. Some or none: the click adds it to the rest.
      return { label: displaySafe(t.name), checked: state, keepOpen: true, run: () => act.tagRows(refs, t.name, state !== true) };
    });
  items.push({ label: NEW_TAG, pinned: true, run: () => act.newTag(refs) });
  return items;
}

/** A small dialog asking for the name of a new tag; the case's tag names are offered as it is typed. */
export function NewTagDialog({
  count,
  existing,
  onAdd,
  onClose,
  busy,
  error,
}: {
  count: number;
  existing: string[];
  onAdd: (name: string) => void;
  onClose: () => void;
  busy: boolean;
  error: string | null;
}) {
  const [name, setName] = useState("");
  const ok = name.trim() !== "";
  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="New tag"
      className="entity-dialog mark-dialog"
      onKeyDown={(e) => {
        if (e.key === "Escape") onClose();
      }}
    >
      <h4>Tag {count === 1 ? "this event" : `${count} events`}</h4>
      <label>
        Tag name
        <input
          autoFocus
          list="new-tag-names"
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && ok && !busy) onAdd(name.trim());
          }}
        />
      </label>
      <datalist id="new-tag-names">
        {existing.map((t) => (
          <option key={t} value={t} />
        ))}
      </datalist>
      {error && <p role="alert">{displaySafe(error)}</p>}
      <div className="entity-dialog-buttons">
        <button type="button" disabled={!ok || busy} onClick={() => onAdd(name.trim())}>
          Add tag
        </button>
        <button type="button" onClick={onClose}>
          Cancel
        </button>
      </div>
    </div>
  );
}
