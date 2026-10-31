// The calendar beside a From/To box: a small popover with the browser's own date and time controls (minutes, UTC) that
// writes `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM` into the box. The box stays the source of truth, so typing and pasting keep
// working. The controls' values are plain strings and are never read through local-time APIs: what is picked is UTC.
import { useEffect, useRef, useState } from "react";
import Icon from "../ui/Icon";
import { parseUtc } from "./time";

export default function RangePicker({ end, value, onPick }: { end: "from" | "to"; value: string; onPick: (text: string) => void }) {
  const name = end === "from" ? "From" : "To";
  const [open, setOpen] = useState(false);
  const [day, setDay] = useState("");
  const [clock, setClock] = useState("");
  // What the popover opened on: applying it untouched leaves the box alone, so a range with seconds (a pivot's, the
  // histogram's) is not rounded to the minute.
  const [opened, setOpened] = useState({ day: "", clock: "" });
  const ref = useRef<HTMLSpanElement>(null);
  const button = useRef<HTMLButtonElement>(null);

  const show = () => {
    // The box's canonical text is `YYYY-MM-DDTHH:MM…Z`: slice it rather than parse it as a Date.
    const r = parseUtc(value, end);
    const text = r.ok ? (r.value ?? "") : "";
    // A whole day reads back without a time: its start (From) or last instant (To) is not something picked.
    const wholeDay = text.endsWith(end === "from" ? "T00:00:00Z" : "T23:59:59.999999Z");
    const at = { day: text.slice(0, 10), clock: wholeDay ? "" : text.slice(11, 16) };
    setDay(at.day);
    setClock(at.clock);
    setOpened(at);
    setOpen(true);
  };

  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);

  const apply = () => {
    if (day === "") return;
    if (day !== opened.day || clock !== opened.clock) onPick(clock === "" ? day : `${day}T${clock}`);
    setOpen(false);
  };

  return (
    <span ref={ref} className="ev-picker">
      <button
        type="button"
        ref={button}
        className="btn btn-ghost ev-picker-button"
        aria-label={`Pick ${name} date`}
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => (open ? setOpen(false) : show())}
      >
        <Icon name="calendar" />
      </button>
      {open && (
        <div
          role="dialog"
          aria-label={`${name} (UTC)`}
          className="ev-picker-pop card"
          onKeyDown={(e) => {
            if (e.key === "Escape") {
              e.stopPropagation();
              setOpen(false);
              button.current?.focus();
            } else if (e.key === "Enter" && e.target instanceof HTMLInputElement) {
              // Only in the date and time boxes: a focused button's Enter is its own click.
              e.preventDefault();
              apply();
            }
          }}
        >
          <label>
            <span>{`${name} date (UTC)`}</span>
            <input type="date" value={day} onChange={(e) => setDay(e.target.value)} autoFocus />
          </label>
          <label>
            <span>{`${name} time (UTC)`}</span>
            <input type="time" step={60} value={clock} onChange={(e) => setClock(e.target.value)} />
          </label>
          <p className="meta">{end === "from" ? "No time: from the start of the day." : "No time: to the end of the day."}</p>
          <div className="ev-picker-actions">
            {clock !== "" && (
              <button type="button" className="btn btn-ghost" onClick={() => setClock("")}>
                Clear time
              </button>
            )}
            <button type="button" className="btn btn-primary" onClick={apply} disabled={day === ""}>
              Apply
            </button>
          </div>
        </div>
      )}
    </span>
  );
}
