// Navigation the shell offers to any screen or grid below it. Absent (null) outside a shell, e.g. in a unit test:
// components then simply do not offer the actions.
import { createContext, useContext } from "react";
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
