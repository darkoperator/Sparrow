import type { QueueItem, ProposalItem } from "../api";
import { displaySafe } from "../text";
import Diff from "./Diff";

/** The object a queue item is about, stable across reloads (a new decision on it gets a new seq). */
export function identity(q: QueueItem): string {
  return q.source === "decision" ? `${q.object_type}:${q.object_id}` : `${q.bundle_sha256}:${q.item_key}`;
}

export function itemKey(q: QueueItem): string {
  return q.source === "decision" ? `${q.object_type}:${q.object_id}:${q.decision_seq}` : `${q.bundle_sha256}:${q.item_key}`;
}

function proposalTitle(item: ProposalItem): string {
  switch (item.kind) {
    case "finding":
      return `finding ${item.finding_id}`;
    case "indicator":
      return `${item.ioc_type} ${item.value}`;
    case "timeline_entry":
      return item.title;
    case "note":
      return `note on ${item.target}`;
  }
}

interface Props {
  item: QueueItem;
  selected: boolean;
  onSelect: () => void;
}

export default function QueueItemRow({ item, selected, onSelect }: Props) {
  return (
    <li
      role="option"
      aria-selected={selected}
      data-testid={`item-${itemKey(item)}`}
      className={selected ? "queue-item selected" : "queue-item"}
      onClick={onSelect}
    >
      {item.source === "decision" ? (
        <>
          <div>
            <strong>{displaySafe(item.title)}</strong> <span className="tag">{displaySafe(item.action)}</span>
          </div>
          <Diff before={item.before} after={item.after} />
          <div className="meta">
            {displaySafe(
              `${item.actor}${item.on_behalf_of ? ` on behalf of ${item.on_behalf_of}` : ""} · ${item.decided_at}`,
            )}
          </div>
          {item.reason && <div className="reason">{displaySafe(item.reason)}</div>}
        </>
      ) : (
        <>
          <div>
            <strong>{displaySafe(proposalTitle(item.item))}</strong>{" "}
            <span className="tag">{displaySafe(item.classification)}</span>
          </div>
          <div className="meta">{displaySafe(`from ${item.source_analyst}`)}</div>
          <Diff before={item.current} after={item.item} />
        </>
      )}
    </li>
  );
}
