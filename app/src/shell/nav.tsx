// Navigation the shell offers to any screen or grid below it. Absent (null) outside a shell, e.g. in a unit test:
// components then simply do not offer the actions.
import { createContext, useContext } from "react";
import type { PivotKind } from "../value";

export interface Nav {
  openPivot: (kind: PivotKind, value: string) => void;
}

export const NavContext = createContext<Nav | null>(null);

export const useNav = () => useContext(NavContext);
