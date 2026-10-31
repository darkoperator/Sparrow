// The tab strip: the fixed tabs in order, then one closable tab per open entity or Access tab. Selecting, closing and the
// keyboard are handled here; what the tabs mean is in tabs.ts.
import { useRef } from "react";
import { displaySafe } from "../text";
import Icon, { type IconName } from "../ui/Icon";
import { FIXED_TABS, isAccessRef, tabKey, tabName, tabText, type EntityKind, type FixedTab, type OpenTab, type TabsState } from "./tabs";

const ICON: Record<EntityKind, IconName> = { account: "user", ip: "globe", device: "monitor", session: "key" };
const iconOf = (t: OpenTab): IconName => (!isAccessRef(t) ? ICON[t.kind] : t.access === "case" ? "flag" : ICON[t.access]);

export interface TabBadges {
  /** Items waiting in the review queue. */
  review: number;
  /** Timeline entries proposed and not yet verified. */
  timeline: number;
}

export default function TabStrip({
  state,
  badges,
  onShow,
  onClose,
}: {
  state: TabsState;
  badges: TabBadges;
  onShow: (t: FixedTab | OpenTab) => void;
  onClose: (key: string) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const activeKey = tabKey(state.active);

  const onKeyDown = (e: React.KeyboardEvent, key: string | null) => {
    if (key !== null && (e.key === "Delete" || e.key === "Backspace")) {
      e.preventDefault();
      onClose(key);
      return;
    }
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    e.preventDefault();
    const tabs = Array.from(ref.current?.querySelectorAll<HTMLElement>('[role="tab"]') ?? []);
    const at = tabs.indexOf(e.currentTarget as HTMLElement);
    tabs[(at + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length]?.focus();
  };

  return (
    <div ref={ref} className="tabstrip" role="tablist" aria-label="Tabs">
      {FIXED_TABS.map((t) => {
        const badge = t.id === "review" ? badges.review : t.id === "timeline" ? badges.timeline : 0;
        return (
          <button
            key={t.id}
            role="tab"
            className="tab"
            aria-selected={activeKey === t.id}
            aria-label={badge > 0 ? `${t.label}, ${badge} ${t.id === "review" ? "pending" : "proposed"}` : undefined}
            onClick={() => onShow(t.id)}
            onKeyDown={(e) => onKeyDown(e, null)}
          >
            {t.label}
            {badge > 0 && (
              <span className="tab-badge" aria-hidden="true">
                {badge}
              </span>
            )}
          </button>
        );
      })}
      {state.open.map((e) => {
        const key = tabKey(e);
        const full = displaySafe(tabName(e));
        return (
          <span key={key} className={activeKey === key ? "tab-entity tab-entity-active" : "tab-entity"}>
            <button
              role="tab"
              className="tab"
              aria-selected={activeKey === key}
              aria-label={full}
              title={full}
              onClick={() => onShow(e)}
              onMouseDown={(ev) => {
                if (ev.button === 1) ev.preventDefault(); // no autoscroll cursor on a middle-click
              }}
              onAuxClick={(ev) => {
                if (ev.button === 1) {
                  ev.preventDefault();
                  onClose(key);
                }
              }}
              onKeyDown={(ev) => onKeyDown(ev, key)}
            >
              <Icon name={iconOf(e)} size={13} />
              <span className="tab-value">{displaySafe(tabText(e))}</span>
            </button>
            <button className="tab-close" aria-label={`Close ${full}`} onClick={() => onClose(key)}>
              <Icon name="x" size={12} />
            </button>
          </span>
        );
      })}
    </div>
  );
}

