// The header chip that shows an agent working on this case through the app's agent bridge: the agent id of the last
// request (else just "Agent"), lit while a request runs and for ten minutes after the last one. Purely informative.
import { useEffect, useState } from "react";
import type { AgentActivity } from "../api";
import { displaySafe } from "../text";

/** How long the chip stays lit after the last request. */
export const LIT_MS = 10 * 60 * 1000;

export default function AgentChip({ activity }: { activity: AgentActivity | null }) {
  const at = activity ? Date.parse(activity.at) : NaN;
  // The request (its `at`) whose ten minutes are over.
  const [dimmed, setDimmed] = useState<string | null>(null);
  useEffect(() => {
    if (!activity || activity.running || Number.isNaN(at)) return;
    const t = setTimeout(() => setDimmed(activity.at), Math.max(0, at + LIT_MS - Date.now()) + 1);
    return () => clearTimeout(t);
  }, [activity, at]);
  if (!activity) return null;
  const lit = activity.running || dimmed !== activity.at;
  const name = activity.agent ? displaySafe(activity.agent) : null;
  const when = Number.isNaN(at) ? "" : ` at ${new Date(at).toLocaleTimeString()}`;
  const title = `${activity.running ? "Running" : "Last request"}: sparrow ${displaySafe(activity.command)}${when}`;
  return (
    <span
      role="status"
      aria-label={name ? `Agent ${name}` : "Agent"}
      className="agent-chip"
      data-lit={String(lit)}
      data-running={String(activity.running)}
      title={title}
    >
      <span className="agent-dot" aria-hidden="true" />
      {name ?? "Agent"}
    </span>
  );
}
