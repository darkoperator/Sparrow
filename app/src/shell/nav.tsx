// Navigation the shell offers to any screen or grid below it. Absent (null) outside a shell, e.g. in a unit test:
// components then simply do not offer the actions.
import { createContext, useContext, useEffect, useRef } from "react";
import type { Filter } from "../api";
import type { EntityRef } from "./tabs";

export interface Nav {
  /** Open (or switch to) the tab for an account, IP, device or Entra session. */
  openEntity: (e: EntityRef) => void;
  openTable: (table: string, filters: Filter[]) => void;
  /** Switch to the Events tab, limited to this entity. */
  showInEvents: (e: EntityRef) => void;
  /** Switch to Review with this finding selected, when it is in the queue. */
  openFinding: (findingId: string) => void;
}

export const NavContext = createContext<Nav | null>(null);

export const useNav = () => useContext(NavContext);

/**
 * Tells the shell that something the tab badges count may have changed (a review decision, a timeline write). Screens
 * call it after a write; outside a shell it does nothing.
 */
export const RefreshBadgesContext = createContext<() => void>(() => {});

export const useRefreshBadges = () => useContext(RefreshBadgesContext);

/**
 * Why the analyst cannot write now, or null when they can: "This case is open read-only: …" for a read-only case, or the
 * analyst name not being set. Every screen that disables a write shows this as the reason.
 */
export const WriteBlockedContext = createContext<string | null>(null);

export const useWriteBlocked = () => useContext(WriteBlockedContext);

/** The reason for the shell: a read-only case first, else a missing analyst name. */
export function writeBlockedReason(readOnlyReason: string | null, analyst: string | null): string | null {
  if (readOnlyReason !== null) return `Read-only case: ${readOnlyReason}`;
  return analyst === null ? "The analyst name is not set: enter it to make changes" : null;
}

/**
 * Moves the focus to the analyst-name prompt and highlights it briefly. Provided only while the missing analyst name is
 * what blocks writes (null otherwise: a read-only case cannot be fixed by typing a name).
 */
export const FocusAnalystContext = createContext<(() => void) | null>(null);

export const useFocusAnalyst = () => useContext(FocusAnalystContext);

/**
 * Bumped by the shell each time the case's data changed under the screens (an agent wrote through the agent bridge).
 * Screens read their data again on a change, keeping their filters, range and selection.
 */
export const DataVersionContext = createContext(0);

export const useDataVersion = () => useContext(DataVersionContext);

/** Calls `reload` each time the data version changes (not on mount: the screen's first load does that). */
export function useOnDataChanged(reload: () => void) {
  const version = useDataVersion();
  const seen = useRef(version);
  const latest = useRef(reload);
  useEffect(() => {
    latest.current = reload;
  });
  useEffect(() => {
    if (seen.current === version) return;
    seen.current = version;
    latest.current();
  }, [version]);
}
