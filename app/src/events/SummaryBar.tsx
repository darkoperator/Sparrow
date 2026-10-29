// The counts above the grid: every event the filters match, how many are flagged, and one count per source. A count
// is a button that sets the filter; message trace events (hidden until the Source filter names them) are greyed.
import type { EventsSummary, FlagFilter } from "../api";
import { displaySafe } from "../text";

interface Props {
  summary: EventsSummary | null;
  /** The source filter text and flag toggle now in effect, to show what is pressed. */
  sourceText: string;
  flag: FlagFilter;
  onAll: () => void;
  onSource: (source: string) => void;
  onFlag: (level: "suspicious" | "malicious") => void;
  onIncludeTrace: () => void;
}

const count = (n: number) => n.toLocaleString("en-US");

export default function SummaryBar({ summary, sourceText, flag, onAll, onSource, onFlag, onIncludeTrace }: Props) {
  if (!summary) return <div className="ev-summary" aria-busy="true" />;
  return (
    <div className="ev-summary" role="group" aria-label="Summary">
      <button type="button" className="ev-total" onClick={onAll} title="Show every source and every flag level">
        <strong>{count(summary.total)}</strong> events
      </button>
      <button type="button" className="ev-count-suspicious pill pill-sus" aria-pressed={flag === "suspicious"} onClick={() => onFlag("suspicious")}>
        <strong>{count(summary.suspicious)}</strong> suspicious
      </button>
      <button type="button" className="ev-count-malicious pill pill-mal" aria-pressed={flag === "malicious"} onClick={() => onFlag("malicious")}>
        <strong>{count(summary.malicious)}</strong> malicious
      </button>
      <span className="ev-sources">
        {summary.per_source.map(([source, n]) => (
          <button key={source} type="button" className="chip" aria-pressed={sourceText.trim() === source} onClick={() => onSource(source)}>
            {displaySafe(source)} <strong>{count(n)}</strong>
          </button>
        ))}
      </span>
      {summary.hidden_trace_events > 0 && (
        <button
          type="button"
          className="ev-count-hidden chip"
          title="Message trace events are many per message, so they are left out until you ask for them"
          onClick={onIncludeTrace}
        >
          {`${count(summary.hidden_trace_events)} message trace events hidden — include`}
        </button>
      )}
    </div>
  );
}
