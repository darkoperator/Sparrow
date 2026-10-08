// The review queue: the agent's pending decisions (grouped by account) and imported proposals. Accept and discard go
// through the backend, which checks the decision seq we show; after any write the queue is reloaded.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  isCmdError,
  proposalAccept,
  proposalDiscard,
  reviewAccept,
  reviewDiscard,
  reviewQueue,
  type Proposal,
  type QueueItem,
} from "../api";
import { displaySafe } from "../text";
import FindingDetail from "./FindingDetail";
import QueueItemRow, { identity, itemKey } from "./QueueItemRow";

const OTHER = "Other";

/** Why an item cannot be accepted, or null. One rule for the buttons and the keyboard. */
function cannotAccept(q: QueueItem): string | null {
  if (q.source === "proposal" && q.classification === "missing") {
    return "This proposal cannot be accepted: the object is missing from this case. Discard it.";
  }
  return null;
}

interface Group {
  name: string;
  items: QueueItem[];
}

function group(items: QueueItem[]): Group[] {
  const by = new Map<string, QueueItem[]>();
  for (const q of items) {
    // Proposals have no account of their own here (the frontend has no finding actor for them): they go to Other.
    const name = (q.source === "decision" ? q.account : null) ?? OTHER;
    by.set(name, [...(by.get(name) ?? []), q]);
  }
  return [...by.entries()]
    .sort(([a], [b]) => (a === OTHER ? 1 : b === OTHER ? -1 : a.localeCompare(b)))
    .map(([name, items]) => ({ name, items }));
}

function findingIdOf(q: QueueItem): string | null {
  if (q.source === "decision") return q.object_type === "finding" ? q.object_id : null;
  return q.item.kind === "finding" ? q.item.finding_id : null;
}

type Notice = { kind: "error" | "info"; text: string };

function errorText(e: unknown): string {
  return isCmdError(e) ? e.message : String(e);
}

interface Props {
  canWrite: boolean;
  /** Show only the decisions about this account (case-insensitive); the shell owns it. */
  accountFilter?: string | null;
  onClearFilter?: () => void;
}

export default function ReviewQueue({ canWrite, accountFilter = null, onClearFilter }: Props) {
  const [all, setItems] = useState<QueueItem[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [comment, setComment] = useState("");
  const [notice, setNotice] = useState<Notice | null>(null);
  const busy = useRef(false);
  const [working, setWorking] = useState(false);
  const setBusy = useCallback((v: boolean) => {
    busy.current = v;
    setWorking(v);
  }, []);
  const itemsRef = useRef<QueueItem[]>([]);
  const selectedRef = useRef<string | null>(null);

  const select = useCallback((key: string | null) => {
    selectedRef.current = key;
    setSelected(key);
    setComment("");
  }, []);

  // A filtered queue shows decisions about the account only: proposals have no account here, so they are hidden, and
  // "Accept all" never acts on items that are not on screen.
  const items = useMemo(() => {
    if (accountFilter === null) return all;
    const want = accountFilter.toLowerCase();
    return all.filter((q) => q.source === "decision" && q.account?.toLowerCase() === want);
  }, [all, accountFilter]);

  const groups = useMemo(() => group(items), [items]);
  const flat = useMemo(() => groups.flatMap((g) => g.items), [groups]);

  const apply = useCallback(
    (next: QueueItem[]) => {
      const keys = group(next).flatMap((g) => g.items).map(identity);
      const before = group(itemsRef.current).flatMap((g) => g.items).map(identity);
      itemsRef.current = next;
      setItems(next);
      setLoaded(true);
      const cur = selectedRef.current;
      if (cur !== null && !keys.includes(cur)) {
        // The selected item is gone (decided, or changed under us): move to its neighbour.
        const at = Math.min(Math.max(before.indexOf(cur), 0), keys.length - 1);
        select(keys[at] ?? null);
      }
    },
    [select],
  );

  const fail = useCallback((e: unknown) => setNotice({ kind: "error", text: errorText(e) }), []);

  const load = useCallback(() => reviewQueue().then(apply, fail), [apply, fail]);

  useEffect(() => {
    let live = true;
    reviewQueue().then(
      (next) => live && apply(next),
      (e: unknown) => live && fail(e),
    );
    return () => {
      live = false;
    };
  }, [apply, fail]);

  const current = flat.find((q) => identity(q) === selected) ?? null;

  const act = useCallback(
    async (q: QueueItem, verb: "accept" | "discard", why: string) => {
      if (!canWrite || busy.current) return;
      const why_not = verb === "accept" ? cannotAccept(q) : null;
      if (why_not) {
        setNotice({ kind: "error", text: why_not });
        return;
      }
      setBusy(true);
      setNotice(null);
      const c = why.trim() === "" ? undefined : why;
      try {
        if (q.source === "decision") {
          await (verb === "accept" ? reviewAccept : reviewDiscard)(q.object_type, q.object_id, q.decision_seq, c);
        } else if (verb === "accept") {
          await proposalAccept(q.bundle_sha256, q.item_key);
        } else {
          await proposalDiscard(q.bundle_sha256, q.item_key, c);
        }
        setComment("");
      } catch (e) {
        // A `decision` error is a stale item ("changed since …"): say so, and the reload below shows what is current.
        setNotice({ kind: "error", text: errorText(e) });
      }
      // Stay busy through the reload: the controls must not act on the list we are about to replace.
      await load();
      setBusy(false);
    },
    [canWrite, load, setBusy],
  );

  const acceptAll = async (analyst: string) => {
    if (!canWrite || busy.current) return;
    const targets = items.filter(
      (q): q is { source: "proposal" } & Proposal =>
        q.source === "proposal" && q.source_analyst === analyst && q.state === "open" && q.classification !== "missing",
    );
    setBusy(true);
    setNotice(null);
    let applied = 0;
    try {
      for (const p of targets) {
        await proposalAccept(p.bundle_sha256, p.item_key);
        applied += 1;
      }
      setNotice({ kind: "info", text: `Applied ${applied} of ${targets.length} from ${analyst}.` });
    } catch (e) {
      setNotice({
        kind: "error",
        text: `Applied ${applied} of ${targets.length} from ${analyst}; stopped: ${errorText(e)}`,
      });
    }
    await load();
    setBusy(false);
  };

  // j/k move, a accept, d discard; never while typing, never with a modifier.
  useEffect(() => {
    const onKey = (ev: KeyboardEvent) => {
      if (ev.ctrlKey || ev.metaKey || ev.altKey) return;
      const t = ev.target;
      if (
        t instanceof HTMLElement &&
        (t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName))
      ) {
        return;
      }
      const keys = flat.map(identity);
      const at = selectedRef.current === null ? -1 : keys.indexOf(selectedRef.current);
      if (ev.key === "j") {
        select(keys[Math.min(at + 1, keys.length - 1)] ?? null);
      } else if (ev.key === "k") {
        select(keys[Math.max(at - 1, 0)] ?? null);
      } else if ((ev.key === "a" || ev.key === "d") && at >= 0) {
        void act(flat[at], ev.key === "a" ? "accept" : "discard", "");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [flat, act, select]);

  const bundleAnalysts = [
    ...new Set(items.flatMap((q) => (q.source === "proposal" && q.state === "open" ? [q.source_analyst] : []))),
  ].sort();
  const findingId = current ? findingIdOf(current) : null;

  return (
    <section className="review-queue">
      <h2>Review queue</h2>
      {accountFilter !== null && (
        <div className="filter-chip">
          <span>
            Account: {displaySafe(accountFilter)} ({items.length} of {all.length})
          </span>
          <button onClick={onClearFilter}>Show all</button>
        </div>
      )}
      {notice && <div role={notice.kind === "error" ? "alert" : "status"}>{displaySafe(notice.text)}</div>}
      {bundleAnalysts.length > 0 && (
        <div className="bundles">
          {bundleAnalysts.map((a) => (
            <button key={a} disabled={!canWrite || working} onClick={() => void acceptAll(a)}>
              {`Accept all from ${displaySafe(a)}`}
            </button>
          ))}
        </div>
      )}
      <div className="queue-layout">
        <div className="queue-list">
          {loaded && items.length === 0 && (
            <p>{accountFilter === null ? "Nothing to review." : "Nothing to review for this account."}</p>
          )}
          {groups.map((g) => (
            <div key={g.name}>
              <h3>{displaySafe(g.name)}</h3>
              <ul role="listbox" aria-label={displaySafe(g.name)}>
                {g.items.map((q) => (
                  <QueueItemRow
                    key={itemKey(q)}
                    item={q}
                    selected={identity(q) === selected}
                    onSelect={() => select(identity(q))}
                  />
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="queue-detail">
          {current ? (
            <>
              <div className="actions">
                <label>
                  Comment <input value={comment} onChange={(e) => setComment(e.target.value)} />
                </label>{" "}
                <button disabled={!canWrite || working || cannotAccept(current) !== null} onClick={() => void act(current, "accept", comment)}>
                  Accept
                </button>{" "}
                <button disabled={!canWrite || working} onClick={() => void act(current, "discard", comment)}>
                  Discard
                </button>
              </div>
              {findingId !== null && <FindingDetail findingId={findingId} />}
            </>
          ) : (
            <p>Select an item (j/k), then a to accept or d to discard.</p>
          )}
        </div>
      </div>
    </section>
  );
}
