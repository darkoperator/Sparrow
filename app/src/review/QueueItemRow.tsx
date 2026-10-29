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

export function proposalTitle(item: ProposalItem): string {
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

/** The row's colour, always beside its text tag: an agent decision is AI-violet, a proposal follows how it compares. */
export function tone(q: QueueItem): string {
  if (q.source === "decision") return q.actor.startsWith("agent:") ? "ai" : "accent";
  return { new: "new", agrees: "ok", conflict: "sus", missing: "mal" }[q.classification] ?? "muted";
}

/** The title a queue item is listed under. */
export function itemTitle(q: QueueItem): string {
  return q.source === "decision" ? q.title : proposalTitle(q.item);
}

interface Props {
  item: QueueItem;
  selected: boolean;
  onSelect: () => void;
}

export default function QueueItemRow({ item, selected, onSelect }: Props) {
  const t = tone(item);
  const meta =
    item.source === "decision"
      ? displaySafe(`${item.actor}${item.on_behalf_of ? ` on behalf of ${item.on_behalf_of}` : ""} · ${item.decided_at}`)
      : "";
  return (
    <li
      role="option"
      aria-selected={selected}
      data-testid={`item-${itemKey(item)}`}
      className={`queue-item rq-tone-${t}${selected ? " selected" : ""}`}
      onClick={onSelect}
    >
      <span className="rq-bar" aria-hidden="true" />
      <div className="rq-body">
        <div className="rq-row-head">
          <strong className="rq-title" title={displaySafe(itemTitle(item))}>
            {displaySafe(itemTitle(item))}
          </strong>{" "}
          <span className="tag rq-tag">{displaySafe(item.source === "decision" ? item.action : item.classification)}</span>
        </div>
        {item.source === "decision" ? (
          <>
            <Diff before={item.before} after={item.after} />
            <div className="meta" title={meta}>
              {meta}
            </div>
            {item.reason && (
              <div className="reason" title={displaySafe(item.reason)}>
                {displaySafe(item.reason)}
              </div>
            )}
          </>
        ) : (
          <>
            <div className="meta" title={displaySafe(`from ${item.source_analyst}`)}>
              {displaySafe(`from ${item.source_analyst}`)}
            </div>
            <Diff before={item.current} after={item.item} />
          </>
        )}
      </div>
    </li>
  );
}
