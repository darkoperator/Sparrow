//! Microsoft-Extractor-Suite collection manifests, `CollectionManifest-<GUID>.mesmanifest` (`inv.collection_manifest`):
//! one JSON document per cmdlet run recording each requested work unit (sources x scope x time range), its outcome
//! and its gaps. Stored in `manifest_runs`, `manifest_units` and `manifest_gaps`.
//!
//! The file is collector output and is not trusted: every field is optional (a missing one is NULL), an unknown
//! value is stored as written, and nothing in it can fail the file except text that is not a JSON object. Only
//! schema major version 1 is read; another major version keeps its run row (`supported = false`) and nothing more.

use crate::Result;
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, InputMode, ParserRegistry};
use crate::readers::text::Span;
use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};
use duckdb::params;
use serde_json::Value;

pub struct CollectionManifestParser;

pub fn register(r: &mut ParserRegistry) {
    r.register(
        "inv.collection_manifest",
        Box::new(CollectionManifestParser),
    );
}

/// A manifest time: RFC 3339, or the same without a zone (read as UTC, flagged).
struct Time {
    utc: DateTime<Utc>,
    zoneless: bool,
}

fn parse_time(v: Option<&Value>) -> Option<Time> {
    let s = v?.as_str()?.trim();
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Some(Time {
            utc: t.with_timezone(&Utc),
            zoneless: false,
        });
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(t) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Time {
                utc: t.and_utc(),
                zoneless: true,
            });
        }
    }
    None
}

fn rfc3339(t: &DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::AutoSi, false)
}

/// A range [start, end) with `end > start`, as stored text. Warnings about zone-less times go to `zoneless`.
fn parse_range(
    start: Option<&Value>,
    end: Option<&Value>,
    zoneless: &mut bool,
) -> Option<(String, String)> {
    let (s, e) = (parse_time(start)?, parse_time(end)?);
    if e.utc <= s.utc {
        return None;
    }
    *zoneless |= s.zoneless || e.zoneless;
    Some((rfc3339(&s.utc), rfc3339(&e.utc)))
}

fn text(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

fn int(v: Option<&Value>) -> Option<i64> {
    let v = v?;
    v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))
}

fn json_text(v: Option<&Value>) -> Option<String> {
    match v {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.to_string()),
    }
}

/// The schema's major version when the text is `mes-collection-manifest/<major>[.minor]`.
fn schema_major(schema: Option<&str>) -> Option<u64> {
    let rest = schema?.trim().strip_prefix("mes-collection-manifest/")?;
    rest.split('.').next()?.parse().ok()
}

/// A scope list that narrows: present and not empty (a bare value narrows too).
fn narrows(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::String(s)) => !s.trim().is_empty(),
        Some(_) => true,
    }
}

/// `(narrowed, mia_only)` of a scope (R3).
fn derive_scope(scope: Option<&Value>) -> (bool, bool) {
    let get = |k: &str| scope.and_then(|s| s.get(k));
    let other_filters = match get("other_filters") {
        None | Some(Value::Null) => false,
        Some(Value::Object(o)) => !o.is_empty(),
        Some(_) => true,
    };
    let narrowing = narrows(get("record_types"))
        || narrows(get("ip_addresses"))
        || narrows(get("session_ids"))
        || other_filters;
    let ops = get("operations");
    let mia = matches!(ops, Some(Value::Array(a)) if a.len() == 1
        && a[0].as_str().is_some_and(|s| s.trim().eq_ignore_ascii_case("MailItemsAccessed")));
    if mia && !narrowing {
        (false, true)
    } else {
        (narrowing || narrows(ops), false)
    }
}

/// `scope.user_ids` as a JSON array of trimmed, lower-cased text, and a warning when the value was malformed.
/// `None` (every account) only when the key is absent or null. Any other non-array value is stored as `[]`, which
/// vouches nobody; non-text array elements are dropped.
fn user_ids(scope: Option<&Value>) -> (Option<String>, Option<&'static str>) {
    let Some(v) = scope.and_then(|s| s.get("user_ids")) else {
        return (None, None);
    };
    match v {
        Value::Null => (None, None),
        Value::Array(a) => {
            let list: Vec<Value> = a
                .iter()
                .filter_map(|x| x.as_str())
                .map(|s| Value::String(s.trim().to_lowercase()))
                .collect();
            let warn = (list.len() != a.len())
                .then_some("user_ids has entries that are not text; they were dropped");
            (Some(Value::Array(list).to_string()), warn)
        }
        _ => (
            Some("[]".to_string()),
            Some(
                "user_ids is not a list; stored as an empty list, so the unit vouches for no account",
            ),
        ),
    }
}

/// A manifest-derived string for a warning: shortened and escaped for one line of output (the manifest is not trusted).
fn shown(s: &str) -> String {
    let t: String = s.chars().take(80).collect();
    crate::case::text::display_safe_line(&t)
}

impl ArtifactParser for CollectionManifestParser {
    fn input(&self) -> InputMode {
        InputMode::Whole
    }

    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let decoded = ctx
            .whole()
            .expect("manifest parser reads the whole text")
            .text;
        let src: &str = &decoded.text;
        let doc: Value = serde_json::from_str(src.trim_start_matches('\u{feff}')).map_err(|e| {
            crate::Error::UnsupportedShape(format!("collection manifest is not valid JSON: {e}"))
        })?;
        let Some(root) = doc.as_object() else {
            return Err(crate::Error::UnsupportedShape(
                "collection manifest is not a JSON object".into(),
            ));
        };
        let whole_span = Span {
            start: 0,
            end: src.len(),
        };

        let Some(run_id) = text(root.get("run_id"))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        else {
            return Err(crate::Error::UnsupportedShape(
                "collection manifest has no run_id".into(),
            ));
        };

        // R7: the run's key. The first copy wins; a copy with other content is only a sighting.
        let existing: Option<String> = ctx
            .conn
            .query_row(
                "SELECT CAST(raw AS VARCHAR) FROM manifest_runs WHERE run_id = ?",
                params![run_id],
                |r| r.get(0),
            )
            .ok();
        let sight = ctx.sighting(whole_span);
        if let Some(first) = existing {
            let same = serde_json::from_str::<Value>(&first).is_ok_and(|v| v == doc);
            ctx.queue_source("manifest_runs", &run_id, 0, &sight);
            if same {
                let units: Vec<String> = {
                    let mut st = ctx.conn.prepare(
                        "SELECT unit_key FROM manifest_units WHERE run_id = ? ORDER BY unit_key",
                    )?;
                    st.query_map(params![run_id], |r| r.get(0))?
                        .collect::<std::result::Result<_, _>>()?
                };
                let mut rows = 1u64;
                for (i, u) in units.iter().enumerate() {
                    rows += 1;
                    ctx.queue_source("manifest_units", u, i as u64, &sight);
                    let gaps: Vec<(String, i32)> = {
                        let mut st = ctx.conn.prepare(
                            "SELECT gap_key, ordinal FROM manifest_gaps WHERE unit_key = ? ORDER BY ordinal",
                        )?;
                        st.query_map(params![u], |r| Ok((r.get(0)?, r.get(1)?)))?
                            .collect::<std::result::Result<_, _>>()?
                    };
                    for (g, ord) in gaps {
                        rows += 1;
                        ctx.queue_source("manifest_gaps", &g, ord as u64, &sight);
                    }
                }
                ctx.stats.read += rows;
                ctx.stats.duplicate += rows;
            } else {
                ctx.warn(format!(
                    "run {} was already loaded from another file with different content; this file is only a sighting",
                    shown(&run_id)
                ));
                ctx.stats.read += 1;
                ctx.stats.duplicate += 1;
            }
            return ctx.flush_sources();
        }

        let schema = text(root.get("schema"));
        let major = schema_major(schema.as_deref());
        let supported = major == Some(1);
        if !supported {
            ctx.warn(format!(
                "unsupported manifest schema {:?}: the run is recorded without its units",
                shown(schema.as_deref().unwrap_or(""))
            ));
        }

        let mut zoneless = false;
        let mut time_col = |name: &str, ctx: &mut ParseContext<'_>| -> Option<String> {
            let v = root.get(name).filter(|v| !v.is_null())?;
            match parse_time(Some(v)) {
                Some(t) => {
                    zoneless |= t.zoneless;
                    Some(rfc3339(&t.utc))
                }
                None => {
                    ctx.warn(format!("{name} is not a valid time; stored as NULL"));
                    None
                }
            }
        };
        let started = time_col("started_utc", ctx);
        let finished = time_col("finished_utc", ctx);
        let throttle = root.get("throttle_waits");
        ctx.conn
            .prepare_cached(
                "INSERT INTO manifest_runs (run_id, collection_id, file_id, schema, supported, tool, tool_version, fork,
                     cmdlet, parameters, started_at, finished_at, status, throttle_wait_count, throttle_wait_seconds, raw)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS JSON), CAST(? AS TIMESTAMPTZ), CAST(? AS TIMESTAMPTZ), ?, ?, ?, CAST(? AS JSON))",
            )?
            .execute(params![
                run_id,
                ctx.collection_id,
                ctx.file_id,
                schema,
                supported,
                text(root.get("tool")),
                text(root.get("tool_version")),
                text(root.get("fork")),
                text(root.get("cmdlet")),
                json_text(root.get("parameters")),
                started,
                finished,
                text(root.get("status")),
                int(throttle.and_then(|t| t.get("count"))),
                throttle.and_then(|t| t.get("total_seconds")).and_then(Value::as_f64),
                doc.to_string(),
            ])?;
        ctx.queue_source("manifest_runs", &run_id, 0, &sight);
        ctx.stats.read += 1;
        ctx.stats.loaded += 1;

        if supported {
            let units: &[Value] = root
                .get("units")
                .and_then(Value::as_array)
                .map_or(&[], Vec::as_slice);
            let mut seen = std::collections::HashSet::new();
            for (i, u) in units.iter().enumerate() {
                let unit_id = text(u.get("unit_id"))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| format!("u-{:04}", i + 1));
                if !seen.insert(unit_id.clone()) {
                    ctx.warn(format!(
                        "unit {} appears twice in the run; the repeat is skipped",
                        shown(&unit_id)
                    ));
                    continue;
                }
                let unit_key = format!("{run_id}/{unit_id}");
                let range = parse_range(u.get("start_utc"), u.get("end_utc"), &mut zoneless);
                if range.is_none() {
                    ctx.warn(format!(
                        "unit {} has a time range that is not valid (not RFC 3339, or end not after start); stored without times and it vouches nothing",
                        shown(&unit_id)
                    ));
                }
                let scope = u.get("scope").filter(|s| !s.is_null());
                let (user_ids, user_ids_warning) = user_ids(scope);
                if let Some(w) = user_ids_warning {
                    ctx.warn(format!("unit {}: {w}", shown(&unit_id)));
                }
                let output_written = match u.get("output_written") {
                    None => {
                        ctx.warn(format!(
                            "unit {}: output_written is missing; treated as false",
                            shown(&unit_id)
                        ));
                        false
                    }
                    Some(Value::Bool(b)) => *b,
                    Some(_) => {
                        ctx.warn(format!(
                            "unit {}: output_written is not true or false; treated as false",
                            shown(&unit_id)
                        ));
                        false
                    }
                };
                let (narrowed, mia_only) = derive_scope(scope);
                let sources: Vec<Value> = u
                    .get("sources")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|s| s.as_str())
                            .map(|s| Value::String(s.trim().to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                ctx.conn
                    .prepare_cached(
                        "INSERT INTO manifest_units (unit_key, run_id, unit_id, sources, scope, user_ids, narrowed, mia_only,
                             direction, start_at, end_at, state, records_written, output_written, files)
                         VALUES (?, ?, ?, CAST(? AS JSON), CAST(? AS JSON), CAST(? AS JSON), ?, ?, ?,
                             CAST(? AS TIMESTAMPTZ), CAST(? AS TIMESTAMPTZ), ?, ?, ?, CAST(? AS JSON))",
                    )?
                    .execute(params![
                        unit_key,
                        run_id,
                        unit_id,
                        Value::Array(sources).to_string(),
                        json_text(scope),
                        user_ids,
                        narrowed,
                        mia_only,
                        text(scope.and_then(|s| s.get("direction"))),
                        range.as_ref().map(|r| r.0.clone()),
                        range.as_ref().map(|r| r.1.clone()),
                        text(u.get("state")),
                        int(u.get("records_written")),
                        output_written,
                        json_text(u.get("files")),
                    ])?;
                ctx.queue_source("manifest_units", &unit_key, i as u64, &sight);
                ctx.stats.read += 1;
                ctx.stats.loaded += 1;

                let gaps: &[Value] = u
                    .get("gaps")
                    .and_then(Value::as_array)
                    .map_or(&[], Vec::as_slice);
                for (ordinal, g) in gaps.iter().enumerate() {
                    let own = parse_range(g.get("start_utc"), g.get("end_utc"), &mut zoneless);
                    let (gap_range, widened) = match own {
                        Some(r) => (Some(r), false),
                        None => {
                            ctx.warn(format!(
                                "a gap of unit {} has a time range that is not valid; it is widened to the unit's range",
                                shown(&unit_id)
                            ));
                            (range.clone(), range.is_some())
                        }
                    };
                    let gap_key = format!("{unit_key}/{ordinal}");
                    ctx.conn
                        .prepare_cached(
                            "INSERT INTO manifest_gaps (gap_key, unit_key, ordinal, start_at, end_at, reason, detail,
                                 attempts, records_in_window, search_id, widened)
                             VALUES (?, ?, ?, CAST(? AS TIMESTAMPTZ), CAST(? AS TIMESTAMPTZ), ?, ?, ?, ?, ?, ?)",
                        )?
                        .execute(params![
                            gap_key,
                            unit_key,
                            ordinal as i32,
                            gap_range.as_ref().map(|r| r.0.clone()),
                            gap_range.as_ref().map(|r| r.1.clone()),
                            text(g.get("reason")),
                            text(g.get("detail")),
                            int(g.get("attempts")),
                            int(g.get("records_in_window")),
                            text(g.get("search_id")),
                            widened,
                        ])?;
                    ctx.queue_source("manifest_gaps", &gap_key, ordinal as u64, &sight);
                    ctx.stats.read += 1;
                    ctx.stats.loaded += 1;
                }
            }
        }
        if zoneless {
            ctx.warn("some times have no zone and were read as UTC");
        }
        ctx.flush_sources()
    }
}
