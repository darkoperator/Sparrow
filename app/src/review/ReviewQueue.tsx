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
import { useFocusAnalyst, useOnDataChanged, useRefreshBadges, useWriteBlocked } from "../shell/nav";
import { displaySafe } from "../text";
import FindingDetail from "./FindingDetail";
import QueueItemDetail, { findingIdOf } from "./QueueItemDetail";
import QueueItemRow, { identity, itemKey, itemTitle } from "./QueueItemRow";
import "./review.css";

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

type Notice = { kind: "error" | "info"; text: string };

function errorText(e: unknown): string {
  return isCmdError(e) ? e.message : String(e);
}

interface Props {
  canWrite: boolean;
  /** Show only the decisions about this account (case-insensitive); the shell owns it. */
  accountFilter?: string | null;
  onClearFilter?: () => void;
  /** Select the queue item about this finding (a request from elsewhere, e.g. the events chart); `nonce` is new per request. */
  focusFinding?: { id: string; nonce: number } | null;
}

export default function ReviewQueue({ canWrite, accountFilter = null, onClearFilter, focusFinding = null }: Props) {
  const [all, setItems] = useState<QueueItem[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [comment, setComment] = useState("");
  // The queue changed under the analyst (an agent's write) while they typed a comment; cleared by any reload.
  const [stale, setStale] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);
  const busy = useRef(false);
  const [working, setWorking] = useState(false);
  // Why Accept and Discard are off (a read-only case, or no analyst name): on the buttons and under them.
  const writeBlocked = useWriteBlocked();
  const blocked = canWrite ? null : (writeBlocked ?? "Changes are not possible in this case now");
  const focusAnalyst = useFocusAnalyst();
  const setBusy = useCallback((v: boolean) => {
    busy.current = v;
    setWorking(v);
  }, []);
  const itemsRef = useRef<QueueItem[]>([]);
  const selectedRef = useRef<string | null>(null);
  // A finding shown on request that has no queue item (already decided): read-only, nothing to accept or discard.
  const [standalone, setStandalone] = useState<string | null>(null);

  const select = useCallback((key: string | null) => {
    selectedRef.current = key;
    setSelected(key);
    setStandalone(null);
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
      setStale(false);
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
  // An agent wrote through the bridge: the queue again, keeping the selection. While the analyst types a comment the
  // reload waits for them (it could move the selection and so drop the draft): a button offers it.
  const commentRef = useRef("");
  useEffect(() => {
    commentRef.current = comment;
  }, [comment]);
  useOnDataChanged(() => {
    if (commentRef.current.trim() !== "") setStale(true);
    else void load();
  });
  const reloadStale = () => void load();

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

  // A request to show one finding, once the queue is loaded: select its item, or say it is not waiting for review.
  const handled = useRef<number | null>(null);
  useEffect(() => {
    if (!focusFinding || !loaded || handled.current === focusFinding.nonce) return;
    handled.current = focusFinding.nonce;
    const hit = flat.find((q) => findingIdOf(q) === focusFinding.id);
    // Applied just after this effect, as a reaction to the request rather than part of rendering it.
    queueMicrotask(() => {
      if (hit) {
        select(identity(hit));
        setNotice(null);
      } else {
        select(null);
        setStandalone(focusFinding.id);
        setNotice({ kind: "info", text: `Finding ${focusFinding.id} is not waiting for review: it has no pending decision or proposal. Shown read-only.` });
      }
    });
  }, [focusFinding, loaded, flat, select]);

  const refreshBadges = useRefreshBadges();
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
      refreshBadges();
      setBusy(false);
    },
    [canWrite, load, setBusy, refreshBadges],
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
    refreshBadges();
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
      // Not while a dialog or menu is open, or focus is inside one: a, d and j/k belong to that widget then.
      if (document.querySelector('[role="dialog"], [role="menu"]')) return;
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

  return (
    <section className="review-queue">
      <div className="rq-pane">
        <div className="rq-head">
          <h2>Review queue</h2>
          {loaded && <span className="rq-count">{`${items.length} pending`}</span>}
        </div>
        {accountFilter !== null && (
          <div className="filter-chip">
            <span title={`Account: ${displaySafe(accountFilter)} (${items.length} of ${all.length})`}>
              Account: {displaySafe(accountFilter)} ({items.length} of {all.length})
            </span>
            <button onClick={onClearFilter}>Show all</button>
          </div>
        )}
        {notice && <div role={notice.kind === "error" ? "alert" : "status"}>{displaySafe(notice.text)}</div>}
        {stale && (
          <div role="status">
            An agent changed the queue while you were typing.{" "}
            <button className="btn" onClick={reloadStale}>
              Reload the queue
            </button>
          </div>
        )}
        {bundleAnalysts.length > 0 && (
          <div className="bundles">
            {bundleAnalysts.map((a) => (
              <button key={a} disabled={!canWrite || working} title={blocked ?? undefined} onClick={() => void acceptAll(a)}>
                {`Accept all from ${displaySafe(a)}`}
              </button>
            ))}
          </div>
        )}
        <div className="queue-list">
          {loaded && items.length === 0 && (
            <p className="rq-empty">{accountFilter === null ? "Nothing to review." : "Nothing to review for this account."}</p>
          )}
          {groups.map((g) => (
            <div key={g.name} className="rq-group">
              <h3 title={displaySafe(g.name)}>{displaySafe(g.name)}</h3>
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
        {/* Only the keys the queue handles (see the keydown handler above). */}
        <div className="rq-keys">
          <span><kbd>j</kbd> <kbd>k</kbd> move</span>
          <span><kbd>a</kbd> accept</span>
          <span><kbd>d</kbd> discard</span>
        </div>
      </div>
      <div className="queue-detail">
        {current ? (
          <>
            <div className="rq-detail-head">
              <div className="rq-detail-title" title={displaySafe(itemTitle(current))}>
                {displaySafe(itemTitle(current))}
              </div>
              <div className="actions">
                <label>
                  Comment <input value={comment} onChange={(e) => setComment(e.target.value)} />
                </label>{" "}
                <button
                  className="btn btn-primary"
                  disabled={!canWrite || working || cannotAccept(current) !== null}
                  title={blocked ?? cannotAccept(current) ?? undefined}
                  onClick={() => void act(current, "accept", comment)}
                >
                  Accept
                </button>{" "}
                <button
                  className="btn"
                  disabled={!canWrite || working}
                  title={blocked ?? undefined}
                  onClick={() => void act(current, "discard", comment)}
                >
                  Discard
                </button>
              </div>
            </div>
            {blocked !== null && (
              <p className="rq-blocked" role="note">
                {displaySafe(blocked)}
                {focusAnalyst && (
                  <>
                    {" "}
                    <button type="button" className="link" onClick={focusAnalyst}>
                      Enter the name
                    </button>
                  </>
                )}
              </p>
            )}
            <QueueItemDetail item={current} />
          </>
        ) : standalone !== null ? (
          <FindingDetail findingId={standalone} />
        ) : (
          <p className="rq-empty">Select an item (j/k), then a to accept or d to discard.</p>
        )}
      </div>
    </section>
  );
}
