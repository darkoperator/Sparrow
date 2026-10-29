// The events-over-time chart: plain SVG, one stacked bar per bucket, coloured by source or by operation (the ten most
// frequent operations, the rest stacked as "Other"). Drag across bars (or click one) to set From/To to those buckets;
// double-click or "Reset range" clears it. A legend entry hides its series.
// Under the bars a lane marks the open findings; a marker opens the finding in Review. All text drawn comes from
// `displaySafe`; nothing from the data is ever a class, a style or markup.
import { useCallback, useEffect, useRef, useState } from "react";
import type { FindingMark, Histogram as HistogramData, HistogramGroup } from "../api";
import { displaySafe } from "../text";

/** Known sources in grid order; a source gets the colour of its place, so it keeps it when others are hidden. */
const SOURCE_ORDER = [
  "ual", "signin_interactive", "signin_noninteractive", "signin_service", "mail_items_accessed", "message_trace",
  "message_trace_event", "entra_audit", "mailbox_audit", "admin_audit", "risk_detection", "azure_activity", "security_alert",
];
export function sourceColour(source: string): string {
  const at = SOURCE_ORDER.indexOf(source);
  // Unknown sources share a neutral grey; known ones are spread round the hue wheel.
  return at < 0 ? "hsl(0 0% 55%)" : `hsl(${Math.round((at * 360) / SOURCE_ORDER.length + 210) % 360} 55% 52%)`;
}

/** Operation colours by rank (most frequent first), spread so that neighbours in the legend differ most. */
const OPERATION_HUES = [210, 30, 140, 330, 50, 260, 180, 0, 90, 290];
export const operationColour = (rank: number) => `hsl(${OPERATION_HUES[rank % OPERATION_HUES.length]} 60% 55%)`;
/** "Other" is the unknown-source grey: it is never one operation. */
export const OTHER_COLOUR = "hsl(0 0% 55%)";

const SEVERITY: Record<string, { glyph: string; colour: string }> = {
  critical: { glyph: "◆", colour: "var(--mal)" },
  high: { glyph: "▲", colour: "var(--sus)" },
  medium: { glyph: "●", colour: "var(--sus)" },
  low: { glyph: "○", colour: "var(--faint)" },
  info: { glyph: "○", colour: "var(--faint)" },
};
const severity = (s: string) => SEVERITY[s] ?? SEVERITY.info;

const M = { left: 44, right: 12, top: 8 };
const PLOT_H = 90;
const AXIS_H = 18;
const LANE_H = 20;
const HEIGHT = M.top + PLOT_H + AXIS_H + LANE_H + 4;
const FALLBACK_WIDTH = 800;
const MAX_BAR = 24;
const GAP = 1;
const HIT_MIN = 20;
const STORAGE_KEY = "sparrow.events.histogram.collapsed";
const GROUP_KEY = "sparrow.events.histogram.group";

/** `2026-09-10T01:55:00Z` for a time in ms (whole seconds). */
export const isoZ = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
/** The last instant of a bucket that ends at `ms`: one microsecond before it, so no event of the next bucket is taken. */
export const isoJustBefore = (ms: number) => new Date(ms - 1).toISOString().replace(/\.(\d{3})Z$/, ".$1999Z");

function width(bucketSeconds: number): string {
  if (bucketSeconds < 3600) return `${bucketSeconds / 60} min`;
  if (bucketSeconds < 86400) return `${bucketSeconds / 3600} h`;
  return bucketSeconds === 86400 ? "1 day" : `${bucketSeconds / 86400} days`;
}

function tick(ms: number, bucketSeconds: number): string {
  const iso = new Date(ms).toISOString();
  return bucketSeconds >= 86400 ? iso.slice(0, 10) : `${iso.slice(5, 10)} ${iso.slice(11, 16)}`;
}

function niceMax(max: number): number {
  if (max <= 1) return 1;
  const mag = 10 ** Math.floor(Math.log10(max));
  return ([1, 2, 5, 10].find((m) => m * mag >= max) ?? 10) * mag;
}

function readCollapsed(): boolean {
  try {
    return localStorage.getItem(STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}
function writeCollapsed(v: boolean) {
  try {
    localStorage.setItem(STORAGE_KEY, v ? "1" : "0");
  } catch {
    /* storage unavailable: the chart just opens expanded next time */
  }
}

/** The remembered colouring (this computer only); Operation unless Source was chosen. */
export function readGroup(): HistogramGroup {
  try {
    return localStorage.getItem(GROUP_KEY) === "source" ? "source" : "operation";
  } catch {
    return "operation";
  }
}
function writeGroup(g: HistogramGroup) {
  try {
    localStorage.setItem(GROUP_KEY, g);
  } catch {
    /* storage unavailable: the choice lasts until the app closes */
  }
}

/** The chart's colouring, remembered across runs. */
export function useHistogramGroup(): [HistogramGroup, (g: HistogramGroup) => void] {
  const [group, setGroup] = useState<HistogramGroup>(readGroup);
  const choose = useCallback((g: HistogramGroup) => {
    writeGroup(g);
    setGroup(g);
  }, []);
  return [group, choose];
}

/** One stacked series: `key` is unique across groupings (an operation named "Other" is not the Other series). */
interface Series {
  key: string;
  label: string;
  other: boolean;
  colour: string;
  counts: number[];
}

function seriesOf(data: HistogramData | null): Series[] {
  if (!data) return [];
  if (data.group === "source") {
    return data.series.map(([name, counts]) => ({ key: `source:${name}`, label: name, other: false, colour: sourceColour(name), counts }));
  }
  const named = data.series.map(([name, counts], rank) => ({
    key: `operation:${name}`,
    label: name,
    other: false,
    colour: operationColour(rank),
    counts,
  }));
  return data.other ? [...named, { key: "other", label: "Other", other: true, colour: OTHER_COLOUR, counts: data.other }] : named;
}

interface Props {
  data: HistogramData | null;
  /** What the bars are coloured by, and a change of it (the parent refetches). */
  group: HistogramGroup;
  onGroup: (g: HistogramGroup) => void;
  /** A From or To is applied (shows "Reset range"). */
  hasRange: boolean;
  onRange: (from: string, to: string) => void;
  onReset: () => void;
  /** A click on a finding marker. */
  onFinding: (findingId: string) => void;
}

export default function Histogram({ data, group, onGroup, hasRange, onRange, onReset, onFinding }: Props) {
  const [collapsed, setCollapsed] = useState(readCollapsed);
  const [hidden, setHidden] = useState<ReadonlySet<string>>(new Set());
  const [drag, setDragState] = useState<{ a: number; b: number } | null>(null);
  // The drag also lives in a ref, so the window's mouseup reads it without a state updater doing the work.
  const dragRef = useRef<{ a: number; b: number } | null>(null);
  const setDrag = (d: { a: number; b: number } | null) => {
    dragRef.current = d;
    setDragState(d);
  };
  const [w, setW] = useState(FALLBACK_WIDTH);
  const box = useRef<HTMLDivElement | null>(null);
  const svg = useRef<SVGSVGElement | null>(null);

  const measure = useCallback((el: HTMLDivElement | null) => {
    box.current = el;
  }, []);
  useEffect(() => {
    const el = box.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((entries) => {
      const next = entries[0]?.contentRect.width;
      if (next && next > 0) setW(Math.round(next));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [collapsed]);

  // The data is in another colouring than the one chosen: a refetch is on its way.
  const pending = data !== null && data.group !== group;
  const series = seriesOf(data);
  const n = series[0]?.counts.length ?? 0;
  const t0 = data ? Date.parse(data.start) : 0;
  const bucketMs = (data?.bucket_seconds ?? 60) * 1000;
  const visible = series.filter((s) => !hidden.has(s.key));
  const totals = Array.from({ length: n }, (_, i) => visible.reduce((a, s) => a + s.counts[i], 0));
  const yMax = niceMax(Math.max(0, ...totals));
  const plotW = Math.max(40, w - M.left - M.right);
  const band = n > 0 ? plotW / n : plotW;
  const barW = Math.max(1, Math.min(MAX_BAR, band - GAP));
  const base = M.top + PLOT_H;
  const labelEvery = Math.max(1, Math.ceil(110 / band));

  const bucketAt = (clientX: number): number => {
    const left = svg.current?.getBoundingClientRect().left ?? 0;
    const i = Math.floor((clientX - left - M.left) / band);
    return Math.min(Math.max(i, 0), n - 1);
  };

  // While the button is down the pointer may leave the chart: follow it on the window.
  const dragging = drag !== null;
  useEffect(() => {
    if (!dragging) return;
    const move = (e: MouseEvent) => {
      const d = dragRef.current;
      if (d) setDrag({ ...d, b: bucketAt(e.clientX) });
    };
    const up = (e: MouseEvent) => {
      const d = dragRef.current;
      setDrag(null);
      if (!d) return;
      const b = bucketAt(e.clientX);
      onRange(isoZ(t0 + Math.min(d.a, b) * bucketMs), isoJustBefore(t0 + (Math.max(d.a, b) + 1) * bucketMs));
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
    return () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
    };
    // bucketAt closes over layout that only changes with the data; the handlers are rebuilt when a drag starts.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dragging, band, n, t0, bucketMs, onRange]);

  const toggle = (key: string) =>
    setHidden((h) => {
      const next = new Set(h);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const marks: FindingMark[] = data?.findings ?? [];
  const markX = (m: FindingMark) => {
    const f = (Date.parse(m.first_seen) - t0) / (Math.max(n, 1) * bucketMs);
    return M.left + Math.min(Math.max(f, 0), 1) * plotW;
  };

  return (
    <section className="ev-histogram" aria-label="Events over time">
      <div className="ev-histogram-head">
        <button
          type="button"
          aria-expanded={!collapsed}
          onClick={() => {
            writeCollapsed(!collapsed);
            setCollapsed(!collapsed);
          }}
        >
          {collapsed ? "▸ Show timeline" : "▾ Hide timeline"}
        </button>
        {!collapsed && data && n > 0 && <span className="meta">{`${width(data.bucket_seconds)} per bar`}</span>}
        {!collapsed && (
          <div className="ev-toggle ev-histogram-group" role="group" aria-label="Colour bars by">
            {(["operation", "source"] as const).map((g) => (
              <button
                key={g}
                type="button"
                aria-pressed={group === g}
                aria-label={`Colour by ${g}`}
                onClick={() => {
                  if (g === group) return;
                  setHidden(new Set());
                  onGroup(g);
                }}
              >
                {g === "operation" ? "Operation" : "Source"}
              </button>
            ))}
          </div>
        )}
        {hasRange && (
          <button type="button" onClick={onReset}>
            Reset range
          </button>
        )}
      </div>
      {!collapsed && (
        <div ref={measure}>
          {data === null ? (
            <p className="meta">Loading…</p>
          ) : n === 0 && !pending ? (
            <p className="meta">No events in this range.</p>
          ) : (
            // While the chart of a new colouring is on its way, the old one keeps the space but is not shown.
            <div className="ev-histogram-body" aria-busy={pending}>
              {pending && (
                <p className="meta ev-histogram-pending" role="status">
                  Loading…
                </p>
              )}
              <div style={pending ? { visibility: "hidden" } : undefined} aria-hidden={pending || undefined}>
              <svg
                ref={svg}
                width={w}
                height={HEIGHT}
                role="img"
                aria-label={`Events over time, ${n} bars of ${width(data.bucket_seconds)}`}
                className="ev-chart"
              >
                {[0, 0.5, 1].map((f) => (
                  <g key={f}>
                    <line x1={M.left} x2={M.left + plotW} y1={base - f * PLOT_H} y2={base - f * PLOT_H} className="ev-grid-line" />
                    <text x={M.left - 4} y={base - f * PLOT_H + 3} textAnchor="end" className="ev-axis">
                      {Math.round(f * yMax)}
                    </text>
                  </g>
                ))}
                {totals.map((total, i) => {
                  const x = M.left + i * band + (band - barW) / 2;
                  let y = base;
                  const at = isoZ(t0 + i * bucketMs);
                  return (
                    <g key={i} data-bucket={i}>
                      <title>{`${at} · ${total} event${total === 1 ? "" : "s"}`}</title>
                      {visible.map((s) => {
                        const h = (s.counts[i] / yMax) * PLOT_H;
                        if (s.counts[i] === 0) return null;
                        y -= h;
                        return <rect key={s.key} x={x} y={y} width={barW} height={h} fill={s.colour} />;
                      })}
                      {i % labelEvery === 0 && (
                        <text x={x + barW / 2} y={base + 12} textAnchor="middle" className="ev-axis">
                          {tick(t0 + i * bucketMs, data.bucket_seconds)}
                        </text>
                      )}
                    </g>
                  );
                })}
                {drag && (
                  <rect
                    className="ev-brush"
                    x={M.left + Math.min(drag.a, drag.b) * band}
                    y={M.top}
                    width={(Math.abs(drag.b - drag.a) + 1) * band}
                    height={PLOT_H}
                  />
                )}
                <rect
                  data-testid="histogram-plot"
                  className="ev-plot"
                  x={M.left}
                  y={M.top}
                  width={plotW}
                  height={PLOT_H}
                  fill="transparent"
                  onMouseDown={(e) => {
                    if (e.button !== 0) return;
                    e.preventDefault();
                    const i = bucketAt(e.clientX);
                    setDrag({ a: i, b: i });
                  }}
                  onDoubleClick={onReset}
                />
                <g aria-label="Findings">
                  {marks.map((m) => {
                    const sev = severity(m.severity);
                    const x = markX(m);
                    const cy = base + AXIS_H + LANE_H / 2;
                    const label = `Open finding ${displaySafe(m.finding_id)} (${displaySafe(m.severity)})`;
                    return (
                      <g
                        key={m.finding_id}
                        role="button"
                        tabIndex={0}
                        aria-label={label}
                        className="ev-finding"
                        onClick={() => onFinding(m.finding_id)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            onFinding(m.finding_id);
                          }
                        }}
                      >
                        <title>{`${displaySafe(m.severity)} finding · ${m.first_seen} → ${m.last_seen}`}</title>
                        <rect x={x - HIT_MIN / 2} y={cy - HIT_MIN / 2} width={HIT_MIN} height={HIT_MIN} fill="transparent" />
                        <text x={x} y={cy + 4} textAnchor="middle" fill={sev.colour} className="ev-finding-glyph">
                          {sev.glyph}
                        </text>
                      </g>
                    );
                  })}
                </g>
              </svg>
              <div
                className="ev-legend"
                role="group"
                aria-label={data.group === "source" ? "Sources in the chart" : "Operations in the chart"}
              >
                {series.map((s) => {
                  const label = s.other ? "Other operations" : displaySafe(s.label);
                  return (
                    <button
                      key={s.key}
                      type="button"
                      aria-pressed={!hidden.has(s.key)}
                      title={label}
                      onClick={() => toggle(s.key)}
                    >
                      <span className="ev-swatch" style={{ background: s.colour }} aria-hidden="true" />
                      <span className={s.other ? "ev-legend-name ev-legend-other" : "ev-legend-name"}>
                        {s.other ? "Other" : displaySafe(s.label)}
                      </span>{" "}
                      {s.counts.reduce((a, b) => a + b, 0)}
                    </button>
                  );
                })}
              </div>
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
