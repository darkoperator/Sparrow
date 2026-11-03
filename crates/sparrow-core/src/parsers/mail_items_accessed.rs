//! Microsoft-Extractor-Suite Get-Sessions and Get-MessageIDs
//! (`MailItemsAccessed/<ts>/<ts>-Sessions*.csv`, `<ts>-MessageIDs*.csv`). Both are derived
//! from the UAL MailItemsAccessed records. A row whose raw record (or raw item) is already
//! loaded, complete or partial, adds a sighting to that `ual_events` record (spec §6: the raw
//! record supersedes it). Other rows load on their own: a Sessions row as a `partial`
//! MailItemsAccessed record, a MessageIDs row as a parent-less `mail_items_accessed` row.

use crate::Result;
use crate::ingest::bulk::{StagedUal, load_ual_batch};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::Rec;
use crate::normalize::net::{normalize_ip, normalize_upn};
use crate::normalize::ual::{SPARROW_UAL_NAMESPACE, normalize_audit};
use crate::normalize::ual_shape::{AuditInput, Completeness};
use crate::parsers::records::RecordFormat;
use crate::parsers::records::SourceRecord;
use crate::parsers::stage::{
    file_date_order, read_state_records, reject, reject_at, require_any_key,
};
use crate::readers::stream::Sight;
use crate::readers::time::{DateOrder, parse_timestamp};
use duckdb::params;
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use uuid::Uuid;

pub fn register(r: &mut ParserRegistry) {
    r.register("inv.mia.sessions", Box::new(SessionsParser));
    r.register("inv.mia.message_ids", Box::new(MessageIdsParser));
}

/// One row's access, normalized.
struct Access {
    /// UTC `YYYY-MM-DDTHH:MM:SS`, the form of AuditData CreationTime.
    creation_time: String,
    /// The same instant as RFC 3339, for SQL.
    rfc3339: String,
    /// True when the time carried no zone and UTC was assumed.
    tz_assumed: bool,
    user: String,
    ip: Option<String>,
    session: Option<String>,
    access_type: Option<&'static str>,
}

fn access(
    rec: &Rec,
    time_keys: &[&str],
    ip_keys: &[&str],
    session_keys: &[&str],
    order: Option<DateOrder>,
) -> std::result::Result<Access, String> {
    let text = rec.first_text(time_keys).ok_or("row has no timestamp")?;
    let t = parse_timestamp(&text, order).map_err(|e| format!("timestamp: {e}"))?;
    let user = rec
        .text("User")
        .and_then(|u| normalize_upn(&u))
        .ok_or("row has no User")?;
    let access_type = match rec
        .text("MailAccessType")
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("bind") => Some("bind"),
        Some("sync") => Some("sync"),
        _ => None,
    };
    Ok(Access {
        creation_time: t.utc.format("%Y-%m-%dT%H:%M:%S").to_string(),
        rfc3339: t.rfc3339(),
        tz_assumed: t.tz_assumed,
        user,
        ip: rec.first_text(ip_keys).and_then(|s| normalize_ip(&s)),
        session: rec.first_text(session_keys),
        access_type,
    })
}

/// Day/month order of the file's culture-formatted times.
fn times_order(
    ctx: &mut ParseContext<'_>,
    records: &[SourceRecord],
    time_keys: &[&str],
) -> Result<Option<DateOrder>> {
    let times: Vec<String> = records
        .iter()
        .filter_map(|r| Rec::new(&r.map, true).first_text(time_keys))
        .collect();
    file_date_order(ctx, times.iter().map(String::as_str))
}

/// AuditData standing in for a Sessions row whose raw record was not loaded. The row's own
/// values only, so the same row from another run gets the same content-derived id.
fn session_audit(a: &Access, count: Option<i64>, throttled: Option<bool>) -> Map<String, Value> {
    let mut props = Vec::new();
    if let Some(t) = a.access_type {
        props.push(
            json!({"Name": "MailAccessType", "Value": if t == "bind" { "Bind" } else { "Sync" }}),
        );
    }
    if let Some(t) = throttled {
        props.push(json!({"Name": "IsThrottled", "Value": if t { "True" } else { "False" }}));
    }
    let v = json!({
        "CreationTime": a.creation_time, "Operation": "MailItemsAccessed", "RecordType": 50,
        "Workload": "Exchange", "UserId": a.user, "MailboxOwnerUPN": a.user,
        "ClientIPAddress": a.ip, "SessionId": a.session, "OperationCount": count,
        "OperationProperties": props,
        "SparrowDerivedFrom": "Microsoft-Extractor-Suite Get-Sessions row; no raw MailItemsAccessed record was loaded"
    });
    let mut map = v.as_object().cloned().unwrap_or_default();
    map.retain(|_, v| !v.is_null());
    map
}

const SESSION_TIME: &[&str] = &["TimeStamp", "Timestamp"];

/// One parsed Sessions row, staged for the set-based match.
struct SessionInput {
    ordinal: u64,
    sight: Sight,
    snippet: String,
    access: Access,
    count: Option<i64>,
    throttled: Option<bool>,
}

/// Stage the parsed Sessions rows so the candidates can be joined in one query. `op_count` is
/// the row's OperationCount, or -1 when the column is absent.
fn stage_sessions(conn: &duckdb::Connection, rows: &[SessionInput]) -> Result<()> {
    conn.execute_batch(
        "CREATE OR REPLACE TEMP TABLE mia_sessions_stage (
             ordinal BIGINT, user_name VARCHAR, event_rfc VARCHAR, ip VARCHAR, op_count BIGINT);",
    )?;
    let mut app = conn.appender("mia_sessions_stage")?;
    for r in rows {
        app.append_row(params![
            r.ordinal as i64,
            r.access.user,
            r.access.rfc3339,
            r.access.ip,
            r.count.unwrap_or(-1)
        ])?;
    }
    app.flush()?;
    Ok(())
}

pub struct SessionsParser;

impl ArtifactParser for SessionsParser {
    /// Per-row rules being replaced (spec §6; must stay identical):
    /// 1. Parse the row's timestamp/user/ip/session/access type; a row without either a
    ///    timestamp or a User is a parse error.
    /// 2. Raw candidates are the non-derived `MailItemsAccessed` `ual_events` of the row's
    ///    user and exact event time whose client IP is the row's (or NULL on a `partial`
    ///    record), and whose `OperationCount` equals the row's (or is NULL on a `partial`
    ///    record); with the row's count absent, a -1 sentinel means records with no count.
    ///    Ordered by `(data_completeness = 'full') DESC, CAST(record_id AS VARCHAR)`.
    /// 3. Each row claims the first candidate not already claimed by an earlier row of the
    ///    SAME file (the `used` set) and adds a `ual_events` sighting; a row with none loads
    ///    as a `partial` MailItemsAccessed record built from its own values (content-derived
    ///    id, so a repeated run dedups).
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let records = read_state_records(ctx, RecordFormat::Csv)?;
        require_any_key(&records, &["OperationCount"], "MailItemsAccessed sessions")?;
        let order = times_order(ctx, &records, SESSION_TIME)?;
        let mut parsed: Vec<SessionInput> = Vec::new();
        for r in &records {
            let rec = Rec::new(&r.map, true);
            match access(&rec, SESSION_TIME, &["ClientIP"], &["SessionId"], order) {
                Ok(a) => parsed.push(SessionInput {
                    ordinal: r.ordinal,
                    sight: r.sight.clone(),
                    snippet: r.snippet.clone(),
                    access: a,
                    count: rec.int("OperationCount"),
                    throttled: rec.bool("IsThrottled"),
                }),
                Err(m) => reject(ctx, r, &m)?,
            }
        }
        ctx.stats.read += parsed.len() as u64;
        stage_sessions(ctx.conn, &parsed)?;
        // All (row, candidate) pairs in the per-row order, in one join.
        let mut stmt = ctx.conn.prepare(
            "SELECT r.ordinal, CAST(e.record_id AS VARCHAR) AS rec
             FROM mia_sessions_stage r
             JOIN ual_events e
               ON e.operation = 'MailItemsAccessed'
              AND json_extract_string(e.audit_data, '$.SparrowDerivedFrom') IS NULL
              AND e.user_upn = r.user_name
              AND e.event_time = CAST(r.event_rfc AS TIMESTAMPTZ)
              AND (e.client_ip IS NOT DISTINCT FROM r.ip
                   OR (e.data_completeness = 'partial' AND e.client_ip IS NULL))
              AND (coalesce(TRY_CAST(json_extract_string(e.audit_data, '$.OperationCount') AS BIGINT), -1) = r.op_count
                   OR (e.data_completeness = 'partial'
                       AND json_extract(e.audit_data, '$.OperationCount') IS NULL))
             ORDER BY r.ordinal, (e.data_completeness = 'full') DESC, CAST(e.record_id AS VARCHAR)",
        )?;
        let pairs = stmt
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let by_ordinal: std::collections::HashMap<u64, &SessionInput> =
            parsed.iter().map(|r| (r.ordinal, r)).collect();
        let mut used: HashSet<String> = HashSet::new();
        let mut matched: HashSet<u64> = HashSet::new();
        for (ord, rec) in pairs {
            let ord = ord as u64;
            if matched.contains(&ord) || used.contains(&rec) {
                continue;
            }
            if let Some(row) = by_ordinal.get(&ord) {
                ctx.queue_source("ual_events", &rec, row.ordinal, &row.sight);
                ctx.stats.duplicate += 1;
                used.insert(rec);
                matched.insert(ord);
            }
        }
        // The matched rows' sightings go in before the partial records load, as when each was written at once.
        ctx.flush_sources()?;
        let mut staged = Vec::new();
        for row in &parsed {
            if matched.contains(&row.ordinal) {
                continue;
            }
            let input = AuditInput {
                audit: session_audit(&row.access, row.count, row.throttled),
                completeness: Completeness::Partial,
                outer_record_type: None,
                outer_time: None,
                flat_params: Vec::new(),
            };
            match normalize_audit(&input, None) {
                Ok(rec) => {
                    staged.push(StagedUal {
                        ordinal: row.ordinal,
                        pos: row.sight.pos,
                        raw_sha256: row.sight.raw_sha256.clone(),
                        rec,
                    });
                }
                Err(m) => reject_at(ctx, row.ordinal, &row.sight.pos, &row.snippet, &m)?,
            }
        }
        let out = load_ual_batch(ctx.conn, ctx.collection_id, ctx.file_id, &staged)?;
        ctx.stats.loaded += out.inserted + out.upgraded;
        ctx.stats.duplicate += out.duplicate();
        if !used.is_empty() {
            ctx.warn(format!(
                "{} rows match raw MailItemsAccessed records loaded from the unified audit log; each adds a sighting to its record",
                used.len()
            ));
        }
        if out.inserted > 0 {
            ctx.warn(format!(
                "{} rows have no raw MailItemsAccessed record and load as partial records",
                out.inserted
            ));
        }
        Ok(())
    }
}

const ID_TIME: &[&str] = &["Timestamp", "TimeStamp"];

/// One parsed MessageIDs row, staged for the set-based match.
struct MessageIdInput {
    ordinal: u64,
    sight: Sight,
    access: Access,
    message_id: Option<String>,
    access_type: Option<&'static str>,
    folder: Option<String>,
    size: Option<i64>,
}

fn stage_ids(conn: &duckdb::Connection, rows: &[MessageIdInput]) -> Result<()> {
    conn.execute_batch(
        "CREATE OR REPLACE TEMP TABLE mia_ids_stage (
             ordinal BIGINT, user_name VARCHAR, event_rfc VARCHAR, ip VARCHAR,
             message_id VARCHAR, access_type VARCHAR, folder VARCHAR);",
    )?;
    let mut app = conn.appender("mia_ids_stage")?;
    for r in rows {
        app.append_row(params![
            r.ordinal as i64,
            r.access.user,
            r.access.rfc3339,
            r.access.ip,
            r.message_id,
            r.access_type,
            r.folder
        ])?;
    }
    app.flush()?;
    Ok(())
}

/// Key of a parent-less MessageIDs row: UUIDv5 of its normalized values.
fn item_key(a: &Access, message_id: Option<&str>, folder: Option<&str>) -> String {
    let basis = format!(
        "mia-item|{}|{}|{}|{}|{}|{}|{}",
        a.user,
        a.creation_time,
        a.ip.as_deref().unwrap_or(""),
        a.session.as_deref().unwrap_or(""),
        a.access_type.unwrap_or(""),
        folder.unwrap_or(""),
        message_id.unwrap_or("")
    );
    Uuid::new_v5(&SPARROW_UAL_NAMESPACE, basis.as_bytes())
        .hyphenated()
        .to_string()
}

pub struct MessageIdsParser;

impl ArtifactParser for MessageIdsParser {
    /// Per-row rules being replaced (spec §6; must stay identical):
    /// 1. Parse the row; a Sync row's `InternetMessageId` is the literal
    ///    `N/A (Sync - entire folder)` and its access type is Sync.
    /// 2. The first candidate is the lowest-id `ual_events` record of the row's user and exact
    ///    event time (matching RAW_MATCH: not derived, client IP equal or NULL on a `partial`
    ///    record) joined to a `mail_items_accessed` item: by message id; else a Bind item
    ///    without a message id; else a Sync item of the row's folder; else any item of the
    ///    row's folder without a message id.
    /// 3. Else a partial raw record whose file kept no item (no message id or folder): the
    ///    lowest-id. There is no `used` set: identical rows sight the same record.
    /// 4. Else the row becomes a parent-less `mail_items_accessed` row keyed by its values
    ///    (an existing key adds only a sighting).
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let records = read_state_records(ctx, RecordFormat::Csv)?;
        require_any_key(
            &records,
            &["InternetMessageId"],
            "MailItemsAccessed message ids",
        )?;
        let order = times_order(ctx, &records, ID_TIME)?;
        let mut parsed: Vec<MessageIdInput> = Vec::new();
        for r in &records {
            let rec = Rec::new(&r.map, true);
            let a = match access(
                &rec,
                ID_TIME,
                &["IPaddress", "ClientIP"],
                &["SessionID", "SessionId"],
                order,
            ) {
                Ok(a) => a,
                Err(m) => {
                    reject(ctx, r, &m)?;
                    continue;
                }
            };
            // Sync rows carry "N/A (Sync - entire folder)" instead of a message id.
            let id_text = rec.text("InternetMessageId");
            let message_id = id_text.clone().filter(|m| !m.starts_with("N/A"));
            let access_type = a.access_type.or_else(|| {
                id_text
                    .as_deref()
                    .is_some_and(|m| m.to_ascii_lowercase().starts_with("n/a (sync"))
                    .then_some("sync")
            });
            parsed.push(MessageIdInput {
                ordinal: r.ordinal,
                sight: r.sight.clone(),
                access: a,
                message_id,
                access_type,
                folder: rec.text("FolderPath"),
                size: rec.int("SizeInBytes"),
            });
        }
        ctx.stats.read += parsed.len() as u64;
        stage_ids(ctx.conn, &parsed)?;
        // Item matches: lowest record id per row.
        let mut stmt = ctx.conn.prepare(
            "SELECT r.ordinal, min(CAST(e.record_id AS VARCHAR)) AS rec
             FROM mia_ids_stage r
             JOIN ual_events e
               ON e.operation = 'MailItemsAccessed'
              AND json_extract_string(e.audit_data, '$.SparrowDerivedFrom') IS NULL
              AND e.user_upn = r.user_name
              AND e.event_time = CAST(r.event_rfc AS TIMESTAMPTZ)
              AND (e.client_ip IS NOT DISTINCT FROM r.ip
                   OR (e.data_completeness = 'partial' AND e.client_ip IS NULL))
             JOIN mail_items_accessed m ON m.record_id = e.record_id
             WHERE (r.message_id IS NOT NULL AND m.internet_message_id = r.message_id)
                OR (r.message_id IS NULL AND r.access_type = 'bind'
                    AND m.internet_message_id IS NULL AND m.access_type = 'bind')
                OR (r.message_id IS NULL AND r.access_type = 'sync'
                    AND m.internet_message_id IS NULL AND m.access_type = 'sync'
                    AND m.folder_path IS NOT DISTINCT FROM r.folder)
                OR (r.message_id IS NULL AND r.access_type IS NULL
                    AND m.internet_message_id IS NULL AND m.folder_path IS NOT DISTINCT FROM r.folder)
             GROUP BY r.ordinal",
        )?;
        let mut matched: std::collections::HashMap<u64, String> = stmt
            .query_map([], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<_, _>>()?;
        // Fallback: a partial raw record whose file kept no item, lowest record id per row.
        let mut stmt = ctx.conn.prepare(
            "SELECT r.ordinal, min(CAST(e.record_id AS VARCHAR)) AS rec
             FROM mia_ids_stage r
             JOIN ual_events e
               ON e.operation = 'MailItemsAccessed'
              AND json_extract_string(e.audit_data, '$.SparrowDerivedFrom') IS NULL
              AND e.user_upn = r.user_name
              AND e.event_time = CAST(r.event_rfc AS TIMESTAMPTZ)
              AND (e.client_ip IS NOT DISTINCT FROM r.ip
                   OR (e.data_completeness = 'partial' AND e.client_ip IS NULL))
             WHERE e.data_completeness = 'partial'
               AND NOT EXISTS (SELECT 1 FROM mail_items_accessed m WHERE m.record_id = e.record_id
                                 AND (m.internet_message_id IS NOT NULL OR m.folder_path IS NOT NULL))
             GROUP BY r.ordinal",
        )?;
        for row in stmt.query_map([], |r| {
            Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
        })? {
            let (ord, rec) = row?;
            matched.entry(ord).or_insert(rec);
        }
        let mut matched_count = 0u64;
        for row in &parsed {
            if let Some(rec) = matched.get(&row.ordinal) {
                ctx.queue_source("ual_events", rec, row.ordinal, &row.sight);
                ctx.stats.duplicate += 1;
                matched_count += 1;
                continue;
            }
            let key = item_key(
                &row.access,
                row.message_id.as_deref(),
                row.folder.as_deref(),
            );
            let exists: bool = ctx.conn.query_row(
                "SELECT count(*) > 0 FROM mail_items_accessed WHERE item_key = ?",
                params![key],
                |r| r.get(0),
            )?;
            ctx.queue_source("mail_items_accessed", &key, row.ordinal, &row.sight);
            if exists {
                ctx.stats.duplicate += 1;
                continue;
            }
            ctx.conn.execute(
                "INSERT INTO mail_items_accessed (record_id, item_ordinal, collection_id, access_type, folder_path,
                     internet_message_id, size_bytes, item_key, event_time, time_tz_assumed, user_upn,
                     client_ip, session_id)
                 VALUES (NULL, 0, ?, CAST(? AS mail_access_type), ?, ?, ?, ?, CAST(? AS TIMESTAMPTZ), ?, ?, ?, ?)",
                params![
                    ctx.collection_id,
                    row.access.access_type,
                    row.folder,
                    row.message_id,
                    row.size,
                    key,
                    row.access.rfc3339,
                    row.access.tz_assumed,
                    row.access.user,
                    row.access.ip,
                    row.access.session
                ],
            )?;
            ctx.stats.loaded += 1;
        }
        ctx.flush_sources()?;
        if matched_count > 0 {
            ctx.warn(format!(
                "{matched_count} rows match items of raw MailItemsAccessed records loaded from the unified audit log; each adds a sighting to its record"
            ));
        }
        Ok(())
    }
}
