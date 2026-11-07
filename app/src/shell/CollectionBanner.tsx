import { useState } from "react";
import type { IncompleteCollection } from "../api";
import { displaySafe } from "../text";

/** POSIX single-quotes `s` unless it holds only safe characters (`'` becomes `'\''`). */
export function shellQuote(s: string): string {
  return /^[A-Za-z0-9@%_+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}

/** The status query failed: say so rather than look like a case with no gaps. */
export function CollectionError({ message }: { message: string }) {
  return (
    <div role="alert" className="banner collection-banner">
      <p>Could not check collection completeness: {displaySafe(message)}</p>
    </div>
  );
}

/**
 * Shown under the header while the case has open collector gaps. No dismissal: the banner goes when a later
 * collection covers the gaps. The command lists what to re-collect.
 */
export default function CollectionBanner({ status, command }: { status: IncompleteCollection; command: string }) {
  const [notice, setNotice] = useState<string | null>(null);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setNotice("Copied");
    } catch {
      setNotice("Could not copy to the clipboard");
    }
  };
  return (
    <div role="alert" className="banner collection-banner">
      <p>{displaySafe(status.text)}</p>
      <p className="collection-banner-cmd">
        <code className="mono">{displaySafe(command)}</code>
        <button className="btn" onClick={() => void copy()}>
          Copy
        </button>
        {notice && <span className="meta">{notice}</span>}
      </p>
    </div>
  );
}
