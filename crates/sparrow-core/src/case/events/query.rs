//! Reading `events`: pages, the summary bar, the histogram, one event's detail, autocomplete and the CSV export.
//! The filters come from [`super::filter`]; nothing here writes.

use super::filter::{self, SEARCH_TABLES, Where};
use super::marksql;
use super::{
    EventDetail, EventQuery, EventRow, EventsPage, EventsSummary, Field, FieldValues, FindingMark,
    Histogram, HistogramGroup, SOURCES, TagRef, ValueCount,
};
use crate::case::browse::{COUNT_CAP, MAX_PAGE, Sort};
use crate::case::marks::{self, FlagLevel};
use crate::case::notes::{self, NoteTarget};
use crate::export::timeline_csv::neutralise;
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use duckdb::types::Value;
use duckdb::{Connection, Row, params_from_iter};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The query behind [`EventRow`]s: `rows` (a select of `events` rows, with their order and limit) is taken once as the
/// page, and everything beyond the `events` columns is computed for those rows only: finding and note counts, the
/// effective flag (built once by `marksql::flagged` over the page) and the tags as JSON. `tail` follows the select.
fn row_query(rows: &str, tail: &str) -> String {
    let page = "SELECT source_table, record_key FROM page";
    format!(
        "WITH page AS MATERIALIZED ({rows}) \
         SELECT e.source_table, e.record_key, e.source, epoch_us(e.event_time), e.time_tz_assumed, \
         e.tenant_key, e.workload, CAST(e.category AS VARCHAR), e.operation, e.result, e.actor_upn, e.owner_upn, \
         e.target, e.ip, e.ip_prefix, e.ip_country, e.asn, e.asn_org, e.ip_kind, e.device_id, e.device_name, \
         e.device_object_id, e.entra_session_id, e.user_agent, e.app_id, e.summary, \
         coalesce(fc.n, 0), coalesce(nt.n, 0), nt.latest, {flags}, tg.tags, \
         (coalesce(fl.agent_pend, false) OR coalesce(tg.pend, false)) \
         FROM page e \
         LEFT JOIN (SELECT source_table, record_key, count(DISTINCT finding_id) AS n FROM finding_evidence \
                    WHERE (source_table, record_key) IN ({page}) GROUP BY 1, 2) fc \
                ON fc.source_table = e.source_table AND fc.record_key = e.record_key \
         LEFT JOIN (SELECT source_table, object_id, count(*) AS n, \
                           arg_max(text, struct_pack(c := created_at, i := annotation_id)) AS latest \
                    FROM annotations WHERE CAST(object_type AS VARCHAR) = 'evidence' \
                    AND (source_table, object_id) IN ({page}) GROUP BY 1, 2) nt \
                ON nt.source_table = e.source_table AND nt.object_id = e.record_key \
         LEFT JOIN (SELECT et.source_table, et.record_key, \
                    CAST(to_json(list({{'name': t.name, 'ai': et.decided_by LIKE 'agent:%' \
                        AND et.review_state = 'pending_review'}} ORDER BY t.name)) AS VARCHAR) AS tags, \
                    bool_or(et.decided_by LIKE 'agent:%' AND et.review_state = 'pending_review') AS pend \
                    FROM event_tags et JOIN tags t ON t.tag_id = et.tag_id \
                    WHERE (et.source_table, et.record_key) IN ({page}) GROUP BY 1, 2) tg \
                ON tg.source_table = e.source_table AND tg.record_key = e.record_key \
         LEFT JOIN ({flagged}) fl ON fl.source_table = e.source_table AND fl.record_key = e.record_key{tail}",
        flags = marksql::FLAG_COLUMNS,
        flagged = marksql::flagged("page", true),
    )
}

fn row_of(r: &Row) -> Result<EventRow> {
    let time: Option<i64> = r.get(3)?;
    Ok(EventRow {
        source_table: r.get(0)?,
        record_key: r.get(1)?,
        source: r.get(2)?,
        event_time: time.and_then(DateTime::from_timestamp_micros),
        time_tz_assumed: r.get(4)?,
        tenant_key: r.get(5)?,
        workload: r.get(6)?,
        category: r.get(7)?,
        operation: r.get(8)?,
        result: r.get(9)?,
        actor_upn: r.get(10)?,
        owner_upn: r.get(11)?,
        target: r.get(12)?,
        ip: r.get(13)?,
        ip_prefix: r.get(14)?,
        ip_country: r.get(15)?,
        asn: r.get(16)?,
        asn_org: r.get(17)?,
        ip_kind: r.get(18)?,
        device_id: r.get(19)?,
        device_name: r.get(20)?,
        device_object_id: r.get(21)?,
        entra_session_id: r.get(22)?,
        user_agent: r.get(23)?,
        app_id: r.get(24)?,
        summary: r.get(25)?,
        finding_count: r.get::<_, i64>(26)? as u32,
        note_count: r.get::<_, i64>(27)? as u32,
        latest_note: r.get(28)?,
        flag: r
            .get::<_, Option<String>>(29)?
            .map(|l| FlagLevel::parse(&l))
            .transpose()?,
        flag_ai: r.get::<_, Option<bool>>(30)?.unwrap_or(false),
        tags: match r.get::<_, Option<String>>(31)? {
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| Error::Invalid(format!("tags of an event are not JSON: {e}")))?,
            None => Vec::new(),
        },
        ai_pending: r.get::<_, Option<bool>>(32)?.unwrap_or(false),
    })
}

/// The sortable columns: the `events` columns of the grid.
const SORTABLE: &[&str] = &[
    "event_time",
    "source",
    "operation",
    "result",
    "actor_upn",
    "owner_upn",
    "target",
    "ip",
    "ip_country",
    "asn",
    "asn_org",
    "ip_kind",
    "device_id",
    "device_name",
    "entra_session_id",
    "user_agent",
    "app_id",
    "summary",
    "workload",
    "tenant_key",
    "category",
    "source_table",
    "record_key",
];

/// `ORDER BY` over `e`: the sort column (NULLs last), then a total order so pages never overlap or skip. The default
/// is newest first.
fn order_by(sort: Option<&Sort>) -> Result<String> {
    let mut keys = Vec::new();
    match sort {
        Some(s) => {
            if !SORTABLE.contains(&s.column.as_str()) {
                return Err(Error::Invalid(format!(
                    "events have no column {:?} to sort by",
                    s.column
                )));
            }
            let col = if s.column == "category" {
                "CAST(e.category AS VARCHAR)".to_string()
            } else {
                format!("e.{}", s.column)
            };
            let dir = if s.descending { "DESC" } else { "ASC" };
            keys.push(format!("{col} {dir} NULLS LAST"));
            if s.column != "event_time" {
                keys.push("e.event_time DESC NULLS LAST".into());
            }
        }
        None => keys.push("e.event_time DESC NULLS LAST".into()),
    }
    keys.push("e.source_table".into());
    keys.push("e.record_key".into());
    Ok(format!(" ORDER BY {}", keys.join(", ")))
}

/// A filter value the database cannot use (a malformed time, say) is the caller's mistake, not a database fault.
fn bad_query(e: duckdb::Error) -> Error {
    match Error::from(e) {
        Error::Db(e) => Error::Invalid(format!("events filter: {e}")),
        other => other,
    }
}

fn bound(w: &Where) -> impl Iterator<Item = &Value> {
    w.params.iter()
}

/// One page of the events `q` matches, sorted by `sort` (default: newest first). `limit` is capped at `MAX_PAGE`.
pub fn page(
    conn: &Connection,
    q: &EventQuery,
    sort: Option<&Sort>,
    offset: usize,
    limit: usize,
) -> Result<EventsPage> {
    let w = filter::build(q, false)?;
    let order = order_by(sort)?;
    let limit = limit.min(MAX_PAGE);

    let counted: u64 = conn
        .query_row(
            &format!(
                "SELECT count(*) FROM (SELECT 1 FROM events e{} LIMIT {})",
                w.sql(),
                COUNT_CAP + 1
            ),
            params_from_iter(bound(&w)),
            |r| r.get::<_, i64>(0),
        )
        .map_err(bad_query)? as u64;

    let rows_sql = format!(
        "SELECT e.* FROM events e{}{order} LIMIT {limit} OFFSET {offset}",
        w.sql()
    );
    let mut stmt = conn.prepare(&row_query(&rows_sql, &order))?;
    let mut rows = Vec::new();
    let mut result = stmt.query(params_from_iter(bound(&w)))?;
    while let Some(r) = result.next()? {
        rows.push(row_of(r)?);
    }
    Ok(EventsPage {
        rows,
        offset,
        total: counted.min(COUNT_CAP),
        total_capped: counted > COUNT_CAP,
    })
}

/// The keys of the events `q` matches, oldest first (events without a time last), then by table and key, in one
/// scan: at most `cap` of them, and `true` when more matched. For callers that act on every match (add them to the
/// timeline); the grid pages with [`page`].
pub fn matching_rows(
    conn: &Connection,
    q: &EventQuery,
    cap: usize,
) -> Result<(Vec<marks::RowRef>, bool)> {
    let w = filter::build(q, false)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT e.source_table, e.record_key FROM events e{} \
         ORDER BY e.event_time ASC NULLS LAST, e.source_table, e.record_key LIMIT {}",
        w.sql(),
        cap.saturating_add(1)
    ))?;
    let mut rows = Vec::new();
    let mut result = stmt.query(params_from_iter(bound(&w)))?;
    while let Some(r) = result.next()? {
        rows.push(marks::RowRef {
            source_table: r.get(0)?,
            record_key: r.get(1)?,
        });
    }
    let capped = rows.len() > cap;
    rows.truncate(cap);
    Ok((rows, capped))
}

/// The summary bar: the total and the rows per source of what `q` matches.
pub fn summary(conn: &Connection, q: &EventQuery) -> Result<EventsSummary> {
    let w = filter::build(q, false)?;
    let mut by_source: BTreeMap<String, u64> = BTreeMap::new();
    {
        let mut stmt = conn.prepare(&format!(
            "SELECT e.source, count(*) FROM events e{} GROUP BY 1",
            w.sql()
        ))?;
        let mut result = stmt.query(params_from_iter(bound(&w)))?;
        while let Some(r) = result.next()? {
            by_source.insert(r.get(0)?, r.get::<_, i64>(1)? as u64);
        }
    }
    let total = by_source.values().sum();
    let mut per_source = Vec::new();
    for s in SOURCES {
        if let Some(n) = by_source.remove(*s) {
            per_source.push((s.to_string(), n));
        }
    }
    // A source this build does not list (an older case file) still counts.
    per_source.extend(by_source);

    let hidden_trace_events = if filter::hides_trace_events(q)? {
        let mut all = filter::build(q, true)?;
        all.clauses
            .push(format!("e.source = '{}'", filter::HIDDEN_SOURCE));
        conn.query_row(
            &format!("SELECT count(*) FROM events e{}", all.sql()),
            params_from_iter(bound(&all)),
            |r| r.get::<_, i64>(0),
        )? as u64
    } else {
        0
    };
    let (suspicious, malicious) = flag_counts(conn, q)?;
    Ok(EventsSummary {
        total,
        suspicious,
        malicious,
        per_source,
        hidden_trace_events,
    })
}

/// The rows of `q` (ignoring its flag toggle) whose effective flag is Suspicious, and those whose is Malicious. Both are
/// 0 without a query when the case has no flag at all.
fn flag_counts(conn: &Connection, q: &EventQuery) -> Result<(u64, u64)> {
    let any: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM event_flags) OR EXISTS (SELECT 1 FROM value_flags WHERE removed_at IS NULL)",
        [],
        |r| r.get(0),
    )?;
    if !any {
        return Ok((0, 0));
    }
    // The flagged rows of everything else the query selects, counted by their effective flag.
    let w = filter::build_with(q, false, false)?;
    let counts = conn.query_row(
        &format!(
            "WITH base AS (SELECT {} FROM events e{}) \
             SELECT count(*) FILTER (WHERE sus AND NOT mal), count(*) FILTER (WHERE mal) FROM ({})",
            marksql::BASE_COLUMNS,
            w.sql(),
            marksql::flagged("base", !w.clauses.is_empty())
        ),
        params_from_iter(bound(&w)),
        |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
    )?;
    Ok(counts)
}

/// Bucket sizes in seconds: 1m, 5m, 15m, 1h, 3h, 6h, 12h, 1d.
const BUCKET_SECONDS: [i64; 8] = [60, 300, 900, 3_600, 10_800, 21_600, 43_200, 86_400];

/// The most buckets a histogram ever has, whatever `max_buckets` asks for and however wide the range is.
pub const MAX_HISTOGRAM_BUCKETS: usize = 2_000;

/// How many operations a by-operation histogram names; the rest stack as its `other` series.
pub const HISTOGRAM_TOP_OPERATIONS: usize = 10;

/// [`histogram_by`] stacked by source.
pub fn histogram(conn: &Connection, q: &EventQuery, max_buckets: usize) -> Result<Histogram> {
    histogram_by(conn, q, max_buckets, HistogramGroup::Source)
}

/// Event counts per time bucket, stacked by `group`, over the range `q` selects (its own `from` and `to`, else the
/// first and last matching event). The bucket is the smallest of 1m ... 1d that gives at most `max_buckets` buckets
/// (1d when even that gives more). Never more than [`MAX_HISTOGRAM_BUCKETS`] buckets: when a day is still too small
/// for that, the bucket is widened to the fewest whole days that fit. A range with no event gives no series. An event exactly at the range end is
/// counted, in the last bucket.
///
/// Two edges to know. With no `from`, the first bucket starts at the first event's time rounded down to a multiple of
/// the bucket size (so `start` can precede the first event); a `from` is used as is. With a `to` after the last
/// event, the range runs to `to`, so the tail buckets are empty. The findings lane holds findings with evidence among
/// the matching events, minus those closed as `false_positive` or `benign`.
///
/// By operation, one grouped pass counts every (operation, bucket); the top [`HISTOGRAM_TOP_OPERATIONS`] are ranked
/// on their totals in range, so the cut is over exactly the events drawn. Operations compare as stored (no case
/// folding); an event with no operation always counts as `other`.
pub fn histogram_by(
    conn: &Connection,
    q: &EventQuery,
    max_buckets: usize,
    group: HistogramGroup,
) -> Result<Histogram> {
    if max_buckets == 0 {
        return Err(Error::Invalid("a histogram needs at least 1 bucket".into()));
    }
    let w = filter::build(q, false)?;
    let timed = format!(
        "{} {} e.event_time IS NOT NULL",
        w.sql(),
        if w.clauses.is_empty() { "WHERE" } else { "AND" }
    );
    let (min_us, max_us): (Option<i64>, Option<i64>) = conn
        .query_row(
            &format!(
                "SELECT min(epoch_us(e.event_time)), max(epoch_us(e.event_time)) FROM events e{timed}"
            ),
            params_from_iter(bound(&w)),
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(bad_query)?;
    let at = |us: i64| DateTime::from_timestamp_micros(us).unwrap_or_default();
    let (Some(min_us), Some(max_us)) = (min_us, max_us) else {
        return Ok(Histogram {
            start: q.from.or(q.to).unwrap_or_default(),
            bucket_seconds: BUCKET_SECONDS[0],
            group,
            series: Vec::new(),
            other: None,
            findings: Vec::new(),
        });
    };

    // The range: the query's own bounds, else the data. Only the data-derived start is moved to a bucket boundary.
    let end_us = q.to.map_or(max_us, |t| t.timestamp_micros());
    let layout = |size: i64| -> (i64, usize) {
        let step = size * 1_000_000;
        let start = q
            .from
            .map_or_else(|| min_us.div_euclid(step) * step, |t| t.timestamp_micros());
        (start, ((end_us - start).max(0) / step) as usize + 1)
    };
    let limit = max_buckets.min(MAX_HISTOGRAM_BUCKETS);
    let day = BUCKET_SECONDS[BUCKET_SECONDS.len() - 1];
    let size = BUCKET_SECONDS
        .iter()
        .copied()
        .find(|s| layout(*s).1 <= limit)
        .unwrap_or_else(|| {
            let per_day = layout(day).1;
            if per_day <= MAX_HISTOGRAM_BUCKETS {
                return day;
            }
            // Past a day: the fewest whole days that fit the hard cap (the estimate, then up until it does).
            let mut days = (per_day / (MAX_HISTOGRAM_BUCKETS - 1)).max(2) as i64;
            while layout(days * day).1 > MAX_HISTOGRAM_BUCKETS {
                days += 1;
            }
            days * day
        });
    let (start_us, buckets) = layout(size);

    let mut params = vec![Value::BigInt(start_us), Value::BigInt(size * 1_000_000)];
    params.extend(w.params.iter().cloned());
    // The grouping column is one of two fixed names, never caller text.
    let column = match group {
        HistogramGroup::Source => "e.source",
        HistogramGroup::Operation => "e.operation",
    };
    let mut stmt = conn.prepare(&format!(
        "SELECT {column}, CAST((epoch_us(e.event_time) - ?) // ? AS BIGINT), count(*) FROM events e{timed} \
         GROUP BY 1, 2"
    ))?;
    let mut per_name: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    let mut unnamed = vec![0; buckets];
    let mut result = stmt.query(params_from_iter(params.iter()))?;
    while let Some(r) = result.next()? {
        let (name, b, n): (Option<String>, i64, i64) = (r.get(0)?, r.get(1)?, r.get(2)?);
        if !(0..buckets as i64).contains(&b) {
            continue;
        }
        match name {
            Some(name) => {
                per_name.entry(name).or_insert_with(|| vec![0; buckets])[b as usize] += n as u64
            }
            None => unnamed[b as usize] += n as u64,
        }
    }
    let mut series = Vec::new();
    let mut other = None;
    match group {
        HistogramGroup::Source => {
            for s in SOURCES {
                if let Some(v) = per_name.remove(*s) {
                    series.push((s.to_string(), v));
                }
            }
            series.extend(per_name);
        }
        HistogramGroup::Operation => {
            let mut ranked: Vec<(String, Vec<u64>)> = per_name.into_iter().collect();
            // Most events first; the map's name order breaks ties (the sort is stable).
            ranked.sort_by_key(|(_, v)| std::cmp::Reverse(v.iter().sum::<u64>()));
            let rest = ranked.split_off(ranked.len().min(HISTOGRAM_TOP_OPERATIONS));
            series = ranked;
            for (_, v) in rest {
                for (o, n) in unnamed.iter_mut().zip(v) {
                    *o += n;
                }
            }
            if unnamed.iter().any(|n| *n > 0) {
                other = Some(unnamed);
            }
        }
    }

    let mut stmt = conn.prepare(&format!(
        "SELECT f.finding_id, f.severity, epoch_us(coalesce(f.first_seen, m.mn)), epoch_us(coalesce(f.last_seen, m.mx)) \
         FROM findings f \
         JOIN (SELECT fe.finding_id, min(e.event_time) AS mn, max(e.event_time) AS mx FROM finding_evidence fe \
               JOIN events e ON e.source_table = fe.source_table AND e.record_key = fe.record_key{} \
               GROUP BY 1) m ON m.finding_id = f.finding_id \
         WHERE f.status NOT IN ('false_positive', 'benign') ORDER BY 3, f.finding_id",
        w.sql()
    ))?;
    let mut findings = Vec::new();
    let mut result = stmt.query(params_from_iter(bound(&w)))?;
    while let Some(r) = result.next()? {
        let (first, last): (Option<i64>, Option<i64>) = (r.get(2)?, r.get(3)?);
        // A finding with no time at all cannot sit on a time axis.
        if let (Some(first), Some(last)) = (first, last) {
            findings.push(FindingMark {
                finding_id: r.get(0)?,
                severity: r.get(1)?,
                first_seen: at(first),
                last_seen: at(last),
            });
        }
    }
    Ok(Histogram {
        start: at(start_us),
        bucket_seconds: size,
        group,
        series,
        other,
        findings,
    })
}

/// One event: its row, the stored evidence record, where it came from, and its marks and notes.
pub fn detail(conn: &Connection, source_table: &str, record_key: &str) -> Result<EventDetail> {
    let (_, key_expr) = SEARCH_TABLES
        .iter()
        .find(|(t, _)| *t == source_table)
        .ok_or_else(|| Error::Invalid(format!("{source_table:?} is not an event table")))?;
    let mut stmt = conn.prepare(&row_query(
        "SELECT * FROM events WHERE source_table = ? AND record_key = ?",
        "",
    ))?;
    let mut result = stmt.query([source_table, record_key])?;
    let row = match result.next()? {
        Some(r) => row_of(r)?,
        None => {
            return Err(Error::NotFound(format!(
                "event {source_table}:{record_key}"
            )));
        }
    };
    let raw_text: Option<String> = conn
        .query_row(
            &format!(
                "SELECT CAST(to_json(t) AS VARCHAR) FROM {source_table} t WHERE {key_expr} = ?"
            ),
            [record_key],
            |r| r.get(0),
        )
        .ok();
    let raw = match raw_text {
        Some(t) => serde_json::from_str(&t)
            .map_err(|e| Error::Invalid(format!("row of {source_table} is not JSON: {e}")))?,
        None => serde_json::Value::Null,
    };
    let key = (source_table.to_string(), record_key.to_string());
    let source_refs = crate::case::read::source_refs_of(conn, &BTreeSet::from([key.clone()]))?
        .remove(&key)
        .unwrap_or_default();
    let notes = notes::notes_for(
        conn,
        &NoteTarget::Evidence {
            table: key.0,
            key: key.1,
        },
    )?;
    Ok(EventDetail {
        tags: row.tags.clone(),
        flag: row.flag,
        flag_sources: marks::flag_sources(conn, source_table, record_key)?,
        row,
        raw,
        source_refs,
        notes,
    })
}

/// Distinct case values of `field` that start with `prefix` (case-insensitively), sorted, at most `limit` (200). Tag
/// suggests the tag names in use.
pub fn suggest(conn: &Connection, field: Field, prefix: &str, limit: usize) -> Result<Vec<String>> {
    if field == Field::Tag {
        let mut stmt = conn.prepare(&format!(
            "SELECT name FROM tags WHERE name ILIKE ? ESCAPE '\\' ORDER BY name LIMIT {}",
            limit.min(200)
        ))?;
        let pattern = format!("{}%", filter::like_pattern(prefix.trim()));
        let rows = stmt.query_map([pattern], |r| r.get::<_, String>(0))?;
        return Ok(rows.collect::<std::result::Result<_, _>>()?);
    }
    let exprs: &[&str] = match field {
        Field::Source => &["e.source"],
        Field::Operation => &["e.operation"],
        Field::Account => &["e.actor_upn", "e.owner_upn"],
        Field::Ip => &["e.ip"],
        Field::Country => &["e.ip_country"],
        Field::Asn => &["CAST(e.asn AS VARCHAR)"],
        Field::Device => &["e.device_name", "e.device_id"],
        Field::Session => &["e.entra_session_id"],
        Field::Tag => unreachable!("handled above"),
    };
    let pattern = format!("{}%", filter::like_pattern(prefix.trim()));
    let parts: Vec<String> = exprs
        .iter()
        .map(|x| format!("SELECT DISTINCT {x} AS v FROM events e WHERE {x} ILIKE ? ESCAPE '\\'"))
        .collect();
    let mut stmt = conn.prepare(&format!(
        "SELECT v FROM ({}) ORDER BY v LIMIT {}",
        parts.join(" UNION "),
        limit.min(200)
    ))?;
    let params: Vec<Value> = exprs.iter().map(|_| Value::Text(pattern.clone())).collect();
    let rows = stmt.query_map(params_from_iter(params.iter()), |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// The most values one [`values`] call returns.
pub const MAX_VALUES: usize = 200;

/// The values of `field` among the events `q` matches with `field`'s own filter left out, each with its event count,
/// most events first (then by value), at most `limit` (capped at [`MAX_VALUES`]) of them; `total` counts every distinct
/// value. `prefix` keeps the values that start with it, case-insensitively (`*` is a wildcard, so `*x` finds any value
/// holding `x`). Blank values are left out. A value is what the field's filter compares: an event with an actor and
/// another mailbox owner counts for both accounts; Account, Device, Session and Tag values that differ only in case
/// are one value (shown in one of their spellings), as their filter compares them lower-cased. A device is its display
/// name, else its device id, else its object id. For Source the `message_trace_event` rows are counted even though the
/// grid hides them until the Source filter names them, so they can be ticked. A `limit` below 1 is refused.
pub fn values(
    conn: &Connection,
    q: &EventQuery,
    field: Field,
    prefix: &str,
    limit: usize,
) -> Result<FieldValues> {
    if limit == 0 {
        return Err(Error::Invalid(
            "a values list needs a limit of at least 1".into(),
        ));
    }
    let mut rest = q.clone();
    rest.fields.retain(|(f, _)| *f != field);
    let w = filter::build(&rest, field == Field::Source)?;
    // One row per (event, value): `v` the value as stored.
    let per_event = match field {
        Field::Tag => format!(
            "SELECT t.name AS v FROM events e JOIN event_tags et \
             ON et.source_table = e.source_table AND et.record_key = e.record_key \
             JOIN tags t ON t.tag_id = et.tag_id{}",
            w.sql()
        ),
        Field::Account => format!(
            "SELECT unnest(list_distinct([e.actor_upn, e.owner_upn])) AS v FROM events e{}",
            w.sql()
        ),
        _ => {
            let expr = match field {
                Field::Source => "e.source",
                Field::Operation => "e.operation",
                Field::Ip => "e.ip",
                Field::Country => "e.ip_country",
                Field::Asn => "CAST(e.asn AS VARCHAR)",
                Field::Device => "coalesce(e.device_name, e.device_id, e.device_object_id)",
                Field::Session => "e.entra_session_id",
                Field::Account | Field::Tag => unreachable!("handled above"),
            };
            format!("SELECT {expr} AS v FROM events e{}", w.sql())
        }
    };
    let group = if matches!(
        field,
        Field::Account | Field::Device | Field::Session | Field::Tag
    ) {
        "lower(v)"
    } else {
        "v"
    };
    let pattern = format!("{}%", filter::like_pattern(prefix.trim()));
    let sql = format!(
        "SELECT min(v), count(*) AS n, count(*) OVER () FROM ({per_event}) \
         WHERE v IS NOT NULL AND trim(v) <> '' AND v ILIKE ? ESCAPE '\\' \
         GROUP BY {group} ORDER BY n DESC, min(v) LIMIT {}",
        limit.min(MAX_VALUES)
    );
    let mut params = w.params.clone();
    params.push(Value::Text(pattern));
    let mut stmt = conn.prepare(&sql)?;
    let mut result = stmt
        .query(params_from_iter(params.iter()))
        .map_err(bad_query)?;
    let mut out = FieldValues {
        values: Vec::new(),
        total: 0,
    };
    while let Some(r) = result.next()? {
        out.values.push(ValueCount {
            value: r.get(0)?,
            count: r.get::<_, i64>(1)? as u64,
        });
        out.total = r.get::<_, i64>(2)? as u64;
    }
    Ok(out)
}

/// The CSV columns, in order.
pub const CSV_COLUMNS: [&str; 20] = [
    "event_time",
    "source",
    "operation",
    "actor_upn",
    "owner_upn",
    "target",
    "ip",
    "ip_country",
    "asn",
    "asn_org",
    "device_id",
    "device_name",
    "entra_session_id",
    "result",
    "user_agent",
    "flag",
    "tags",
    "latest_note",
    "source_table",
    "record_key",
];

/// `YYYY-MM-DDTHH:MM:SSZ`, with the fraction (`.250`) only when the event time has one.
fn csv_time(t: &DateTime<Utc>) -> String {
    format!("{}Z", t.format("%Y-%m-%dT%H:%M:%S%.f"))
}

/// Writes every event `q` matches (not a page) to `out`, newest first, and returns the rows written. Streamed, so a
/// million rows are never held. The file starts with a UTF-8 BOM. Text cells that a spreadsheet would read as a formula are prefixed with `'`, as in
/// the timeline CSV.
pub fn export_csv(conn: &Connection, q: &EventQuery, out: &Path) -> Result<u64> {
    let w = filter::build(q, false)?;
    let order = order_by(None)?;
    let file = std::fs::File::create(out).map_err(|e| Error::io(out, e))?;
    let mut buf = std::io::BufWriter::new(file);
    // A UTF-8 BOM, like the timeline CSV, so Excel reads non-ASCII text right.
    std::io::Write::write_all(&mut buf, "\u{feff}".as_bytes()).map_err(|e| Error::io(out, e))?;
    let mut csv = csv::Writer::from_writer(buf);
    let csv_err = |e: csv::Error| Error::Invalid(format!("csv: {e}"));
    csv.write_record(CSV_COLUMNS).map_err(csv_err)?;

    let mut stmt = conn.prepare(&row_query(
        &format!("SELECT * FROM events e{}", w.sql()),
        &order,
    ))?;
    let mut result = stmt.query(params_from_iter(bound(&w)))?;
    let mut n = 0;
    while let Some(r) = result.next()? {
        let e = row_of(r)?;
        let text = |v: &Option<String>| neutralise(v.as_deref().unwrap_or(""));
        let cells = [
            e.event_time.as_ref().map(csv_time).unwrap_or_default(),
            e.source.clone(),
            text(&e.operation),
            text(&e.actor_upn),
            text(&e.owner_upn),
            text(&e.target),
            text(&e.ip),
            text(&e.ip_country),
            e.asn.map(|a| a.to_string()).unwrap_or_default(),
            text(&e.asn_org),
            text(&e.device_id),
            text(&e.device_name),
            text(&e.entra_session_id),
            text(&e.result),
            text(&e.user_agent),
            match e.flag {
                Some(FlagLevel::Suspicious) => "suspicious".into(),
                Some(FlagLevel::Malicious) => "malicious".into(),
                None => String::new(),
            },
            e.tags
                .iter()
                .map(|t: &TagRef| t.name.as_str())
                .collect::<Vec<_>>()
                .join("|"),
            text(&e.latest_note),
            e.source_table.clone(),
            e.record_key.clone(),
        ];
        csv.write_record(&cells).map_err(csv_err)?;
        n += 1;
    }
    csv.flush().map_err(|e| Error::io(out, e))?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn csv_time_keeps_a_fraction_only_when_there_is_one() {
        let whole = Utc.with_ymd_and_hms(2026, 9, 1, 10, 0, 5).unwrap();
        assert_eq!(csv_time(&whole), "2026-09-01T10:00:05Z");
        let frac = whole + chrono::Duration::microseconds(250_000);
        assert_eq!(csv_time(&frac), "2026-09-01T10:00:05.250Z");
    }
}
