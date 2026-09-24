//! Collector run logs: Hawk `Hawk.log` and Microsoft-Extractor-Suite `LogFile.txt`.

use crate::Result;
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::readers::text::{Span, line_spans};
use crate::readers::time::{DateOrderDetector, parse_timestamp};
use duckdb::params;
use regex::Regex;
use std::sync::OnceLock;

pub struct HawkLogParser;
pub struct InvictusLogParser;

pub fn register(r: &mut ParserRegistry) {
    r.register("hawk.log", Box::new(HawkLogParser));
    r.register("inv.logfile", Box::new(InvictusLogParser));
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

fn re_hawk() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    cached(
        &R,
        r"^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\dZ)\] - (?:\[(ACTION|ERROR|INVESTIGATE|INFO|WARNING|PROMPT)\]\s+-\s+)?(.*)$",
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

fn store(ctx: &mut ParseContext<'_>, entries: &[Entry], tz_assumed: bool) -> Result<()> {
    let mut bad = 0u64;
    for (ordinal, e) in entries.iter().enumerate() {
        let key = format!("{}:{}", ctx.file_id, ordinal);
        let ts = e
            .ts_raw
            .as_deref()
            .and_then(|s| parse_timestamp(s, None).ok())
            .map(|t| t.rfc3339());
        if e.ts_raw.is_some() && ts.is_none() {
            bad += 1;
        }
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
        store(ctx, &list, false)?;
        apply_hawk_metadata(ctx, &list)
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
        store(ctx, &list, true)
    }
}

fn capture(re: &Regex, message: &str) -> Option<String> {
    re.captures(message).map(|c| c[1].trim().to_string())
}

fn re_meta_version() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    cached(&R, r"(?i)^Hawk Version\s*:\s*(\S+)")
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

fn apply_hawk_metadata(ctx: &mut ParseContext<'_>, list: &[Entry]) -> Result<()> {
    let mut version = None;
    let mut tenant = None;
    let mut start_raw = None;
    let mut end_raw = None;
    for e in list {
        let m = e.message.trim();
        version = version.or_else(|| capture(re_meta_version(), m));
        tenant = tenant.or_else(|| capture(re_meta_tenant(), m));
        start_raw = start_raw
            .or_else(|| capture(re_meta_start(), m))
            .or_else(|| capture(re_meta_start_set(), m));
        end_raw = end_raw.or_else(|| capture(re_meta_end(), m));
    }
    let strip = |s: &String| s.trim_end_matches(['Z', 'z']).trim().to_string();
    let start_raw = start_raw.as_ref().map(strip);
    let end_raw = end_raw.as_ref().map(strip);

    let mut detector = DateOrderDetector::default();
    for s in [&start_raw, &end_raw].into_iter().flatten() {
        detector.observe(s);
    }
    let (mut window_start, mut window_end) = (None, None);
    match detector.resolve(ctx.options.date_order) {
        Ok(order) => {
            let parse = |s: &Option<String>| {
                s.as_deref()
                    .and_then(|v| parse_timestamp(v, order).ok())
                    .map(|t| t.rfc3339())
            };
            window_start = parse(&start_raw);
            window_end = parse(&end_raw);
        }
        Err(reason) => ctx.warn(format!("collection window not parsed: {reason}")),
    }
    ctx.conn.execute(
        "UPDATE collections SET
            tool_version = coalesce(?, tool_version),
            tenant_name_reported = coalesce(?, tenant_name_reported),
            window_start = coalesce(CAST(? AS TIMESTAMPTZ), window_start),
            window_end = coalesce(CAST(? AS TIMESTAMPTZ), window_end)
         WHERE collection_id = ?",
        params![version, tenant, window_start, window_end, ctx.collection_id],
    )?;
    Ok(())
}
