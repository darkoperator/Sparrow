// The calendar beside a From/To box: a small popover with the browser's own date control and a 24-hour `HH:MM` box
// (minutes, UTC; a native time control would show the system's 12-hour clock), that writes `YYYY-MM-DD` or
// `YYYY-MM-DDTHH:MM` into the box. The box stays the source of truth, so typing and pasting keep
// working. The controls' values are plain strings and are never read through local-time APIs: what is picked is UTC.
import { useEffect, useId, useRef, useState } from "react";
import Icon from "../ui/Icon";
import { parseUtc } from "./time";

/** `H:MM` or `HH:MM`, 00:00 to 23:59, as `HH:MM`; anything else is null. */
function readClock(text: string): string | null {
  const m = /^(\d{1,2}):(\d{2})$/.exec(text.trim());
  if (!m || Number(m[1]) > 23 || Number(m[2]) > 59) return null;
  return `${m[1].padStart(2, "0")}:${m[2]}`;
}

export default function RangePicker({ end, value, onPick }: { end: "from" | "to"; value: string; onPick: (text: string) => void }) {
  const name = end === "from" ? "From" : "To";
  const [open, setOpen] = useState(false);
  const [day, setDay] = useState("");
  const [clock, setClock] = useState("");
  const [badClock, setBadClock] = useState(false);
  // What the popover opened on: applying it untouched leaves the box alone, so a range with seconds (a pivot's, the
  // histogram's) is not rounded to the minute.
  const [opened, setOpened] = useState({ day: "", clock: "" });
  const ref = useRef<HTMLSpanElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const dateId = useId();
  const dialog = useRef<HTMLDivElement>(null);
  // On opening only: an empty date is not focused (WebKit would show today's date in it, greyed, like a value), so the
  // dialog takes focus instead; later renders leave focus where the user put it.
  useEffect(() => {
    if (open && opened.day === "") dialog.current?.focus();
  }, [open, opened.day]);

  const show = () => {
    // The box's canonical text is `YYYY-MM-DDTHH:MM…Z`: slice it rather than parse it as a Date.
    const r = parseUtc(value, end);
    const text = r.ok ? (r.value ?? "") : "";
    // A whole day reads back without a time: its start (From) or last instant (To) is not something picked.
    const wholeDay = text.endsWith(end === "from" ? "T00:00:00Z" : "T23:59:59.999999Z");
    const at = { day: text.slice(0, 10), clock: wholeDay ? "" : text.slice(11, 16) };
    setDay(at.day);
    setClock(at.clock);
    setBadClock(false);
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
    const at = clock.trim() === "" ? "" : readClock(clock);
    if (at === null) {
      setBadClock(true);
      return;
    }
    if (day !== opened.day || at !== opened.clock) onPick(at === "" ? day : `${day}T${at}`);
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
          tabIndex={-1}
          ref={dialog}
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
          <div className="ev-picker-field">
            <label htmlFor={dateId}>{`${name} date (UTC)`}</label>
            <span className="ev-picker-date">
              <input id={dateId} type="date" className={day === "" ? "ev-picker-empty" : undefined} value={day} onChange={(e) => setDay(e.target.value)} autoFocus={opened.day !== ""} />
              {/* WebKit shows today's date, greyed, in an empty date control: it reads as a value. */}
              {day === "" && (
                <span className="ev-picker-none" aria-hidden="true">
                  No date yet
                </span>
              )}
            </span>
          </div>
          <label>
            <span>{`${name} time (UTC)`}</span>
            <input
              type="text"
              inputMode="numeric"
              placeholder="HH:MM (24 h)"
              spellCheck={false}
              value={clock}
              aria-invalid={badClock ? true : undefined}
              onChange={(e) => {
                setClock(e.target.value);
                setBadClock(false);
              }}
            />
          </label>
          {badClock ? (
            <p role="alert" className="ev-error">
              Time is HH:MM, 00:00 to 23:59 (UTC)
            </p>
          ) : (
            <p className="meta">{end === "from" ? "No time: from the start of the day." : "No time: to the end of the day."}</p>
          )}
          <div className="ev-picker-actions">
            {clock !== "" && (
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => {
                  setClock("");
                  setBadClock(false);
                }}
              >
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
