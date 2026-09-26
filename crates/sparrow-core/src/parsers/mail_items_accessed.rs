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
use crate::parsers::stage::{file_date_order, read_state_records, reject, require_any_key};
use crate::readers::time::{DateOrder, parse_timestamp};
use duckdb::{OptionalExt, params, params_from_iter};
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

/// A raw MailItemsAccessed record of the row's user, time and address. Raw records loaded
/// `partial` count too (Get-UAL `-AuditDataOnly` CSV keeps only the first record's columns, so
/// a partial record may lack the address); records a Sessions row stood in for do not.
const RAW_MATCH: &str = "e.operation = 'MailItemsAccessed'
    AND json_extract_string(e.audit_data, '$.SparrowDerivedFrom') IS NULL
    AND e.user_upn = ? AND e.event_time = CAST(? AS TIMESTAMPTZ)
    AND (e.client_ip IS NOT DISTINCT FROM ? OR (e.data_completeness = 'partial' AND e.client_ip IS NULL))";

/// Raw MailItemsAccessed records a Sessions row may stand for, not yet used by this file
/// (complete records first; a partial record without OperationCount matches any count).
fn raw_session_match(
    ctx: &ParseContext<'_>,
    a: &Access,
    count: Option<i64>,
    used: &HashSet<String>,
) -> Result<Option<String>> {
    let mut stmt = ctx.conn.prepare_cached(&format!(
        "SELECT CAST(e.record_id AS VARCHAR) FROM ual_events e WHERE {RAW_MATCH}
           AND (coalesce(TRY_CAST(json_extract_string(e.audit_data, '$.OperationCount') AS BIGINT), -1) = ?
                OR (e.data_completeness = 'partial'
                    AND json_extract(e.audit_data, '$.OperationCount') IS NULL))
         ORDER BY e.data_completeness = 'full' DESC, 1"
    ))?;
    let ids = stmt
        .query_map(params![a.user, a.rfc3339, a.ip, count.unwrap_or(-1)], |r| {
            r.get::<_, String>(0)
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(ids.into_iter().find(|id| !used.contains(id)))
}

/// The raw record holding the item a MessageIDs row names: by message id, else by access
/// type (a Bind item without a message id; a Sync of the row's folder; with the type
/// unknown, an item of the row's folder without a message id); else a partial raw record of
/// the row's access whose items were not kept.
fn raw_item_match(
    ctx: &ParseContext<'_>,
    a: &Access,
    access_type: Option<&str>,
    message_id: Option<&str>,
    folder: Option<&str>,
) -> Result<Option<String>> {
    // The item condition, and whether it binds a value (a message id or folder path).
    let (item, value): (&str, Option<Option<&str>>) = match (message_id, access_type) {
        (Some(m), _) => ("m.internet_message_id = ?", Some(Some(m))),
        (None, Some("bind")) => (
            "m.internet_message_id IS NULL AND m.access_type = 'bind'",
            None,
        ),
        (None, Some(_)) => (
            "m.internet_message_id IS NULL AND m.access_type = 'sync' AND m.folder_path IS NOT DISTINCT FROM ?",
            Some(folder),
        ),
        (None, None) => (
            "m.internet_message_id IS NULL AND m.folder_path IS NOT DISTINCT FROM ?",
            Some(folder),
        ),
    };
    let mut values: Vec<Option<&str>> = vec![
        Some(a.user.as_str()),
        Some(a.rfc3339.as_str()),
        a.ip.as_deref(),
    ];
    values.extend(value);
    let found = ctx
        .conn
        .prepare_cached(&format!(
            "SELECT CAST(e.record_id AS VARCHAR) FROM mail_items_accessed m
             JOIN ual_events e ON e.record_id = m.record_id
             WHERE {RAW_MATCH} AND {item} ORDER BY 1 LIMIT 1"
        ))?
        .query_row(params_from_iter(values), |r| r.get::<_, String>(0))
        .optional()?;
    if found.is_some() {
        return Ok(found);
    }
    // A partial raw record whose file did not keep its items (`Folders` exported as
    // `System.Object[]`) still holds the row's access; the first by id when several match.
    let found = ctx
        .conn
        .prepare_cached(&format!(
            "SELECT CAST(e.record_id AS VARCHAR) FROM ual_events e
             WHERE {RAW_MATCH} AND e.data_completeness = 'partial'
               AND NOT EXISTS (SELECT 1 FROM mail_items_accessed m WHERE m.record_id = e.record_id
                                 AND (m.internet_message_id IS NOT NULL OR m.folder_path IS NOT NULL))
             ORDER BY 1 LIMIT 1"
        ))?
        .query_row(
            params![a.user.as_str(), a.rfc3339.as_str(), a.ip.as_deref()],
            |r| r.get::<_, String>(0),
        )
        .optional()?;
    Ok(found)
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

pub struct SessionsParser;

impl ArtifactParser for SessionsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let records = read_state_records(ctx, RecordFormat::Csv)?;
        require_any_key(&records, &["OperationCount"], "MailItemsAccessed sessions")?;
        let order = times_order(ctx, &records, SESSION_TIME)?;
        let mut used: HashSet<String> = HashSet::new();
        let mut staged = Vec::new();
        for r in &records {
            let rec = Rec::new(&r.map, true);
            let a = match access(&rec, SESSION_TIME, &["ClientIP"], &["SessionId"], order) {
                Ok(a) => a,
                Err(m) => {
                    reject(ctx, r, &m)?;
                    continue;
                }
            };
            let count = rec.int("OperationCount");
            if let Some(id) = raw_session_match(ctx, &a, count, &used)? {
                ctx.record_source("ual_events", &id, r.ordinal, r.span)?;
                ctx.stats.read += 1;
                ctx.stats.duplicate += 1;
                used.insert(id);
                continue;
            }
            let input = AuditInput {
                audit: session_audit(&a, count, rec.bool("IsThrottled")),
                completeness: Completeness::Partial,
                outer_record_type: None,
                outer_time: None,
                flat_params: Vec::new(),
            };
            match normalize_audit(&input, None) {
                Ok(rec) => {
                    let (pos, raw_sha256) = ctx.sighting(r.span);
                    staged.push(StagedUal {
                        ordinal: r.ordinal,
                        pos,
                        raw_sha256,
                        rec,
                    });
                }
                Err(m) => reject(ctx, r, &m)?,
            }
        }
        ctx.stats.read += staged.len() as u64;
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
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let records = read_state_records(ctx, RecordFormat::Csv)?;
        require_any_key(
            &records,
            &["InternetMessageId"],
            "MailItemsAccessed message ids",
        )?;
        let order = times_order(ctx, &records, ID_TIME)?;
        let mut matched = 0u64;
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
            let folder = rec.text("FolderPath");
            ctx.stats.read += 1;
            if let Some(id) = raw_item_match(
                ctx,
                &a,
                access_type,
                message_id.as_deref(),
                folder.as_deref(),
            )? {
                ctx.record_source("ual_events", &id, r.ordinal, r.span)?;
                ctx.stats.duplicate += 1;
                matched += 1;
                continue;
            }
            let key = item_key(&a, message_id.as_deref(), folder.as_deref());
            let exists: bool = ctx.conn.query_row(
                "SELECT count(*) > 0 FROM mail_items_accessed WHERE item_key = ?",
                params![key],
                |r| r.get(0),
            )?;
            ctx.record_source("mail_items_accessed", &key, r.ordinal, r.span)?;
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
                    a.access_type,
                    folder,
                    message_id,
                    rec.int("SizeInBytes"),
                    key,
                    a.rfc3339,
                    a.tz_assumed,
                    a.user,
                    a.ip,
                    a.session
                ],
            )?;
            ctx.stats.loaded += 1;
        }
        if matched > 0 {
            ctx.warn(format!(
                "{matched} rows match items of raw MailItemsAccessed records loaded from the unified audit log; each adds a sighting to its record"
            ));
        }
        Ok(())
    }
}
