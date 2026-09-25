//! Collector run logs: Hawk `Hawk.log` (4.x UTC times; 3.x culture-formatted local times,
//! `## Tag ##` section lines and a `*** Version X ***` line), the PSFramework log export Hawk 3
//! wrote (`<date>_logs.csv`) and Microsoft-Extractor-Suite `LogFile.txt`.

use crate::db::state_tables::LICENSES;
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::Cell;
use crate::normalize::ual_shape::get_ci;
use crate::parsers::stage::{RowDraft, TableRows, load_tables};
use crate::readers::csv_scan::read_csv;
use crate::readers::text::{Span, line_spans};
use crate::readers::time::{DateOrder, DateOrderDetector, parse_timestamp};
use crate::{Error, Result};
use duckdb::params;
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

pub struct HawkLogParser;
pub struct InvictusLogParser;
pub struct PsFrameworkLogParser;

pub fn register(r: &mut ParserRegistry) {
    r.register("hawk.log", Box::new(HawkLogParser));
    r.register("inv.logfile", Box::new(InvictusLogParser));
    r.register("hawk.psframework_log", Box::new(PsFrameworkLogParser));
}

struct Entry {
    span: Span,
    ts_raw: Option<String>,
    level: Option<String>,
    message: String,
}

fn cached(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid regex"))
}

/// `[yyyy-MM-dd HH:mm:ssZ]` (Hawk 4, UTC) or the collecting machine's culture `G` format
/// (Hawk 3, local time): `[M/d/yyyy h:mm:ss tt]`, `[d.M.yyyy HH:mm:ss]`, year-first
/// `[yyyy-MM-dd HH:mm:ss]` (sv-SE, en-CA) or `[yyyy/MM/dd HH:mm:ss]` (ja-JP, zh-CN); then an
/// optional `[LEVEL]` tag padded with spaces.
fn re_hawk() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    cached(
        &R,
        r"^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\dZ?|\d{4}/\d{1,2}/\d{1,2} \d{1,2}:\d{2}(?::\d{2})?|\d{1,2}[/.\-]\d{1,2}[/.\-]\d{4} \d{1,2}:\d{2}(?::\d{2})?(?:\s*[AaPp]\.?[Mm]\.?)?)\] - (?:\[(ACTION|ERROR|INVESTIGATE|INFO|WARNING|PROMPT|NOTICE)\]\s+-\s+)?(.*)$",
    )
}

fn re_invictus() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    cached(&R, r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d): (.*)$")
}

fn re_level_prefix() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    cached(&R, r"^\[(\w+)\]\s*(.*)$")
}

/// Split `text` into entries using `head`, which returns (ts_raw, level, message) for entry lines.
fn entries(
    text: &str,
    head: impl Fn(&str) -> Option<(String, Option<String>, String)>,
) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();
    for span in line_spans(text) {
        let line = &text[span.start..span.end];
        if let Some((ts, level, message)) = head(line) {
            out.push(Entry {
                span,
                ts_raw: Some(ts),
                level,
                message,
            });
        } else if let Some(last) = out.last_mut() {
            if line.is_empty() {
                continue;
            }
            last.message.push('\n');
            last.message.push_str(line);
            last.span.end = span.end;
        } else if !line.is_empty() {
            out.push(Entry {
                span,
                ts_raw: None,
                level: None,
                message: line.to_string(),
            });
        }
    }
    out
}

/// Store `entries`. `order` resolves culture-formatted times; an entry whose time cannot be
/// parsed keeps `ts` NULL and gets `untimed_tz_assumed`.
fn store(
    ctx: &mut ParseContext<'_>,
    entries: &[Entry],
    order: Option<DateOrder>,
    untimed_tz_assumed: bool,
) -> Result<()> {
    let mut bad = 0u64;
    for (ordinal, e) in entries.iter().enumerate() {
        let key = format!("{}:{}", ctx.file_id, ordinal);
        let parsed = e
            .ts_raw
            .as_deref()
            .and_then(|s| parse_timestamp(s, order).ok());
        if e.ts_raw.is_some() && parsed.is_none() {
            bad += 1;
        }
        let ts = parsed.map(|t| t.rfc3339());
        let tz_assumed = parsed.map_or(untimed_tz_assumed, |t| t.tz_assumed);
        ctx.conn
            .prepare_cached(
                "INSERT INTO collection_log (log_key, collection_id, file_id, record_ordinal, ts, ts_raw, tz_assumed, level, message)
                 VALUES (?, ?, ?, ?, CAST(? AS TIMESTAMPTZ), ?, ?, ?, ?)",
            )?
            .execute(params![key, ctx.collection_id, ctx.file_id, ordinal as i64, ts, e.ts_raw, tz_assumed, e.level, e.message])?;
        ctx.record_source("collection_log", &key, ordinal as u64, e.span)?;
        ctx.stats.read += 1;
        ctx.stats.loaded += 1;
    }
    if bad > 0 {
        ctx.warn(format!(
            "{bad} log entries have timestamps that could not be parsed (ts is NULL)"
        ));
    }
    Ok(())
}

impl ArtifactParser for HawkLogParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let text = ctx.text;
        let list = entries(&text.text, |line| {
            re_hawk().captures(line).map(|c| {
                (
                    c[1].to_string(),
                    c.get(2).map(|m| m.as_str().to_string()),
                    c[3].to_string(),
                )
            })
        });
        if !list.is_empty() && list.iter().all(|e| e.ts_raw.is_none()) {
            ctx.warn(
                "no line matched a known Hawk log format; the log was stored as one untimed entry",
            );
        }
        let meta = HawkMeta::read(&list);
        let mut detector = DateOrderDetector::default();
        for s in list
            .iter()
            .filter_map(|e| e.ts_raw.as_deref())
            .chain(meta.window())
        {
            detector.observe(s);
        }
        let order = match ctx.resolve_date_order(&detector) {
            Ok(order) => order,
            Err(Error::DateOrderDeferred) => return Err(Error::DateOrderDeferred),
            Err(reason) => {
                if meta.window().next().is_some() {
                    ctx.warn(format!("collection window not parsed: {reason}"));
                }
                if list
                    .iter()
                    .filter_map(|e| e.ts_raw.as_deref())
                    .any(|s| !s.ends_with('Z'))
                {
                    ctx.warn(format!("log entry times not parsed (ts is NULL): {reason}"));
                }
                None
            }
        };
        store(ctx, &list, order, false)?;
        meta.apply(ctx, order)
    }
}

impl ArtifactParser for InvictusLogParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let text = ctx.text;
        let list = entries(&text.text, |line| {
            re_invictus().captures(line).map(|c| {
                let rest = c[2].to_string();
                match re_level_prefix().captures(&rest) {
                    Some(l) => (
                        c[1].to_string(),
                        Some(l[1].to_ascii_uppercase()),
                        l[2].to_string(),
                    ),
                    None => (c[1].to_string(), None, rest),
                }
            })
        });
        store(ctx, &list, None, true)
    }
}

/// Hawk 3 `<date>_logs.csv`: PSFramework's log export, one entry per row. Timestamp is the
/// local time of the collecting machine (`yyyy-MM-dd HH:mm:ss.fff`).
impl ArtifactParser for PsFrameworkLogParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let table = read_csv(&ctx.text.text);
        let has = |h: &str| table.headers.iter().any(|x| x.eq_ignore_ascii_case(h));
        if !(has("Timestamp") && has("Message")) {
            return Err(Error::UnsupportedShape(format!(
                "no PSFramework log columns (Timestamp, Message) in [{}]",
                table.headers.join(", ")
            )));
        }
        for e in &table.errors {
            ctx.stats.read += 1;
            ctx.parse_error(e.ordinal, e.span, &e.message)?;
        }
        let text_of = |map: &serde_json::Map<String, Value>, k: &str| {
            get_ci(map, k)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        let list: Vec<Entry> = table
            .rows
            .iter()
            .map(|row| {
                let map = table.row_map(row);
                Entry {
                    span: row.span,
                    ts_raw: text_of(&map, "Timestamp"),
                    level: text_of(&map, "Level").map(|l| l.to_ascii_uppercase()),
                    message: text_of(&map, "Message").unwrap_or_default(),
                }
            })
            .collect();
        store(ctx, &list, None, true)
    }
}

fn capture(re: &Regex, message: &str) -> Option<String> {
    re.captures(message).map(|c| c[1].trim().to_string())
}

fn re_meta_version() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    cached(&R, r"(?i)^Hawk Version\s*:\s*(\S+)")
}

/// Hawk 3: `*** Version 3.1.0 ***`.
fn re_meta_h3_version() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    cached(&R, r"(?i)^\*{3}\s*Version\s+(\S+)\s*\*{3}$")
}

fn re_meta_tenant() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    cached(&R, r"(?i)^Tenant Name\s*:\s*(.+)$")
}

fn re_meta_start() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    cached(&R, r"(?i)^Start Date\s*:\s*(.+)$")
}

fn re_meta_start_set() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    cached(&R, r"(?i)^Start date set to:\s*(.+)$")
}

fn re_meta_end() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    cached(&R, r"(?i)^End Date\s*:\s*(.+)$")
}

fn re_meta_license() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    cached(&R, r"(?i)^M365 License type detected:\s*(\S+)")
}

/// Collection facts Hawk writes into its log.
#[derive(Debug, Default)]
struct HawkMeta {
    version: Option<String>,
    tenant: Option<String>,
    start_raw: Option<String>,
    end_raw: Option<String>,
    /// The licence tier and the span of the log entry it came from.
    license: Option<(String, Span)>,
}

impl HawkMeta {
    fn read(list: &[Entry]) -> HawkMeta {
        let mut m = HawkMeta::default();
        for e in list {
            let msg = e.message.trim();
            m.version = m
                .version
                .or_else(|| capture(re_meta_version(), msg))
                .or_else(|| capture(re_meta_h3_version(), msg));
            m.tenant = m.tenant.or_else(|| capture(re_meta_tenant(), msg));
            m.start_raw = m
                .start_raw
                .or_else(|| capture(re_meta_start(), msg))
                .or_else(|| capture(re_meta_start_set(), msg));
            m.end_raw = m.end_raw.or_else(|| capture(re_meta_end(), msg));
            if m.license.is_none() {
                if let Some(tier) = capture(re_meta_license(), msg) {
                    m.license = Some((tier, e.span));
                }
            }
        }
        let strip = |s: String| s.trim_end_matches(['Z', 'z']).trim().to_string();
        m.start_raw = m.start_raw.map(strip);
        m.end_raw = m.end_raw.map(strip);
        m
    }

    /// Culture-formatted window dates, for day/month order resolution.
    fn window(&self) -> impl Iterator<Item = &str> {
        self.start_raw
            .as_deref()
            .into_iter()
            .chain(self.end_raw.as_deref())
    }

    fn apply(&self, ctx: &mut ParseContext<'_>, order: Option<DateOrder>) -> Result<()> {
        let parse = |s: &Option<String>| {
            s.as_deref()
                .and_then(|v| parse_timestamp(v, order).ok())
                .map(|t| t.rfc3339())
        };
        let (window_start, window_end) = (parse(&self.start_raw), parse(&self.end_raw));
        ctx.conn.execute(
            "UPDATE collections SET
                tool_version = coalesce(?, tool_version),
                tenant_name_reported = coalesce(?, tenant_name_reported),
                window_start = coalesce(CAST(? AS TIMESTAMPTZ), window_start),
                window_end = coalesce(CAST(? AS TIMESTAMPTZ), window_end)
             WHERE collection_id = ?",
            params![
                self.version,
                self.tenant,
                window_start,
                window_end,
                ctx.collection_id
            ],
        )?;
        if let Some((tier, span)) = &self.license {
            let tier = tier.trim_end_matches('.').to_string();
            let mut rows = TableRows::new(&LICENSES, &["source", "license_tier", "confidence"]);
            rows.push_draft(RowDraft {
                ordinal: 0,
                span: *span,
                record_key: format!("{}|hawk_log|{}", ctx.collection_id, tier.to_lowercase()),
                cells: vec![
                    Cell::text(Some("hawk_log".into())),
                    Cell::text(Some(tier)),
                    Cell::text(Some("low".into())),
                ],
                raw: None,
                sheet_row: None,
            });
            load_tables(ctx, vec![rows])?;
            // The licence row is a second view of the log entry already counted by `store`;
            // undo the extra read/loaded count `load_tables` added for it.
            ctx.stats.read -= 1;
            ctx.stats.loaded -= 1;
        }
        Ok(())
    }
}
