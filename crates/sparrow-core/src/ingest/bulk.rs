//! Bulk loading of normalized UAL records (Phase 1 follow-up: no per-row INSERT ... ON
//! CONFLICT). Rows go through DuckDB appenders into TEMP staging tables and are merged with
//! set-based SQL inside the caller's transaction.

use crate::Result;
use crate::normalize::ual::UalRecord;
use crate::readers::text::SourcePos;
use duckdb::{Connection, params};

/// One normalized record plus where it was read.
#[derive(Debug, Clone)]
pub struct StagedUal {
    pub ordinal: u64,
    pub pos: SourcePos,
    pub raw_sha256: String,
    pub rec: UalRecord,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoadOutcome {
    /// Records in the batch.
    pub staged: u64,
    /// New `ual_events` rows.
    pub inserted: u64,
    /// Existing `partial` rows replaced by a `full` copy from this batch.
    pub upgraded: u64,
}

impl LoadOutcome {
    /// Records that added only a sighting.
    pub fn duplicate(&self) -> u64 {
        self.staged - self.inserted - self.upgraded
    }
}

const STAGE_DDL: &str = "
CREATE TEMP TABLE IF NOT EXISTS stage_ual (
    ord BIGINT, record_id VARCHAR, synthetic_id BOOLEAN, event_time VARCHAR, time_tz_assumed BOOLEAN,
    time_precision VARCHAR, record_type SMALLINT, record_type_name VARCHAR, workload VARCHAR,
    operation VARCHAR, result_status VARCHAR, user_upn VARCHAR, user_type SMALLINT, user_key VARCHAR,
    client_ip VARCHAR, user_agent VARCHAR, session_id VARCHAR, app_id VARCHAR, client_app_id VARCHAR,
    object_id VARCHAR, organization_id VARCHAR, mailbox_upn VARCHAR, parameters VARCHAR,
    audit_data VARCHAR, completeness VARCHAR, line_start BIGINT, line_end BIGINT, byte_offset BIGINT,
    byte_length BIGINT, raw_sha256 VARCHAR);
CREATE TEMP TABLE IF NOT EXISTS stage_mia (
    ord BIGINT, record_id VARCHAR, item_ordinal INTEGER, access_type VARCHAR, folder_path VARCHAR,
    internet_message_id VARCHAR, size_bytes BIGINT, is_throttled BOOLEAN, operation_count INTEGER);
CREATE TEMP TABLE IF NOT EXISTS stage_file (
    ord BIGINT, record_id VARCHAR, workload VARCHAR, site_url VARCHAR, relative_url VARCHAR,
    file_name VARCHAR, file_ext VARCHAR, item_type VARCHAR, is_onenote BOOLEAN,
    application_name VARCHAR, platform VARCHAR, device_name VARCHAR, list_id VARCHAR,
    list_item_id VARCHAR);
CREATE TEMP TABLE IF NOT EXISTS stage_sharing (
    ord BIGINT, record_id VARCHAR, link_type VARCHAR, target_user VARCHAR, target_email VARCHAR,
    permission VARCHAR, is_external BOOLEAN);
CREATE TEMP TABLE IF NOT EXISTS stage_search (
    ord BIGINT, record_id VARCHAR, workload VARCHAR, query_text VARCHAR, scope VARCHAR);
DELETE FROM stage_ual;
DELETE FROM stage_mia;
DELETE FROM stage_file;
DELETE FROM stage_sharing;
DELETE FROM stage_search;
";

/// Pick one staged copy per record (full before partial, then first in file) and split the
/// chosen copies into new records and upgrades of stored partial rows.
const MERGE_SETUP: &str = "
CREATE OR REPLACE TEMP TABLE stage_chosen AS
    SELECT * FROM stage_ual
    QUALIFY row_number() OVER (PARTITION BY record_id ORDER BY (completeness = 'full') DESC, ord) = 1;
CREATE OR REPLACE TEMP TABLE stage_upgrade AS
    SELECT c.record_id, c.ord FROM stage_chosen c
    JOIN ual_events e ON e.record_id = CAST(c.record_id AS UUID)
    WHERE e.data_completeness = 'partial' AND c.completeness = 'full';
CREATE OR REPLACE TEMP TABLE stage_fresh AS
    SELECT c.record_id, c.ord FROM stage_chosen c
    WHERE NOT EXISTS (SELECT 1 FROM ual_events e WHERE e.record_id = CAST(c.record_id AS UUID));
CREATE OR REPLACE TEMP TABLE stage_written AS
    SELECT record_id, ord FROM stage_fresh UNION ALL SELECT record_id, ord FROM stage_upgrade;
";

const PARAMETERS_EXPR: &str = "CASE WHEN c.parameters IS NULL THEN NULL
    ELSE map_from_entries(CAST(CAST(c.parameters AS JSON) AS STRUCT(k VARCHAR, v VARCHAR)[])) END";

const DELETE_UPGRADED_CHILDREN: &str = "
DELETE FROM mail_items_accessed WHERE record_id IN (SELECT CAST(record_id AS UUID) FROM stage_upgrade);
DELETE FROM file_events WHERE record_id IN (SELECT CAST(record_id AS UUID) FROM stage_upgrade);
DELETE FROM sharing_events WHERE record_id IN (SELECT CAST(record_id AS UUID) FROM stage_upgrade);
DELETE FROM search_queries WHERE record_id IN (SELECT CAST(record_id AS UUID) FROM stage_upgrade);
";

const INSERT_CHILDREN: &str = "
INSERT INTO mail_items_accessed (record_id, item_ordinal, collection_id, access_type, folder_path,
    internet_message_id, size_bytes, is_throttled, operation_count)
SELECT CAST(s.record_id AS UUID), s.item_ordinal, e.collection_id, CAST(s.access_type AS mail_access_type),
    s.folder_path, s.internet_message_id, s.size_bytes, s.is_throttled, s.operation_count
FROM stage_mia s JOIN stage_written w ON w.record_id = s.record_id AND w.ord = s.ord
JOIN ual_events e ON e.record_id = CAST(s.record_id AS UUID);
INSERT INTO file_events (record_id, collection_id, workload, site_url, relative_url, file_name, file_ext,
    item_type, is_onenote, application_name, platform, device_name, list_id, list_item_id)
SELECT CAST(s.record_id AS UUID), e.collection_id, s.workload, s.site_url, s.relative_url, s.file_name,
    s.file_ext, CAST(s.item_type AS file_item_type), s.is_onenote, s.application_name, s.platform,
    s.device_name, s.list_id, s.list_item_id
FROM stage_file s JOIN stage_written w ON w.record_id = s.record_id AND w.ord = s.ord
JOIN ual_events e ON e.record_id = CAST(s.record_id AS UUID);
INSERT INTO sharing_events (record_id, collection_id, link_type, target_user, target_email, permission, is_external)
SELECT CAST(s.record_id AS UUID), e.collection_id, CAST(s.link_type AS link_type), s.target_user,
    s.target_email, CAST(s.permission AS share_permission), s.is_external
FROM stage_sharing s JOIN stage_written w ON w.record_id = s.record_id AND w.ord = s.ord
JOIN ual_events e ON e.record_id = CAST(s.record_id AS UUID);
INSERT INTO search_queries (record_id, collection_id, workload, query_text, scope)
SELECT CAST(s.record_id AS UUID), e.collection_id, CAST(s.workload AS search_workload), s.query_text, s.scope
FROM stage_search s JOIN stage_written w ON w.record_id = s.record_id AND w.ord = s.ord
JOIN ual_events e ON e.record_id = CAST(s.record_id AS UUID);
";

fn upgrade_sql() -> String {
    format!(
        "UPDATE ual_events SET
            event_time = CAST(c.event_time AS TIMESTAMPTZ), time_tz_assumed = c.time_tz_assumed,
            time_precision = CAST(c.time_precision AS time_precision), record_type = c.record_type,
            record_type_name = c.record_type_name, workload = c.workload, operation = c.operation,
            result_status = c.result_status, user_upn = c.user_upn, user_type = c.user_type,
            user_key = c.user_key, client_ip = c.client_ip, user_agent = c.user_agent,
            session_id = c.session_id, app_id = c.app_id, client_app_id = c.client_app_id,
            object_id = c.object_id, organization_id = CAST(c.organization_id AS UUID),
            mailbox_upn = c.mailbox_upn, parameters = {PARAMETERS_EXPR},
            audit_data = CAST(c.audit_data AS JSON), data_completeness = 'full',
            synthetic_id = c.synthetic_id
         FROM stage_chosen c JOIN stage_upgrade u ON u.record_id = c.record_id AND u.ord = c.ord
         WHERE ual_events.record_id = CAST(c.record_id AS UUID)"
    )
}

fn insert_fresh_sql() -> String {
    format!(
        "INSERT INTO ual_events (record_id, collection_id, event_time, time_tz_assumed, time_precision,
            record_type, record_type_name, workload, operation, result_status, user_upn, user_type,
            user_key, client_ip, user_agent, session_id, app_id, client_app_id, object_id,
            organization_id, mailbox_upn, parameters, audit_data, data_completeness, synthetic_id)
         SELECT CAST(c.record_id AS UUID), ?, CAST(c.event_time AS TIMESTAMPTZ), c.time_tz_assumed,
            CAST(c.time_precision AS time_precision), c.record_type, c.record_type_name, c.workload,
            c.operation, c.result_status, c.user_upn, c.user_type, c.user_key, c.client_ip,
            c.user_agent, c.session_id, c.app_id, c.client_app_id, c.object_id,
            CAST(c.organization_id AS UUID), c.mailbox_upn, {PARAMETERS_EXPR},
            CAST(c.audit_data AS JSON), CAST(c.completeness AS data_completeness), c.synthetic_id
         FROM stage_chosen c JOIN stage_fresh f ON f.record_id = c.record_id AND f.ord = c.ord"
    )
}

const INSERT_SOURCES: &str = "
INSERT INTO record_sources (table_name, record_key, file_id, record_ordinal, line_start, line_end,
                            byte_offset, byte_length, raw_sha256)
SELECT 'ual_events', record_id, ?, ord, line_start, line_end, byte_offset, byte_length, raw_sha256
FROM stage_ual
ON CONFLICT DO NOTHING";

/// `[{"k": name, "v": value}]` for `map_from_entries`; `None` when there are no parameters.
fn parameters_json(p: &[(String, String)]) -> Option<String> {
    if p.is_empty() {
        return None;
    }
    let entries: Vec<serde_json::Value> = p
        .iter()
        .map(|(k, v)| serde_json::json!({ "k": k, "v": v }))
        .collect();
    Some(serde_json::Value::Array(entries).to_string())
}

pub fn load_ual_batch(
    conn: &Connection,
    collection_id: i64,
    file_id: i64,
    rows: &[StagedUal],
) -> Result<LoadOutcome> {
    if rows.is_empty() {
        return Ok(LoadOutcome::default());
    }
    conn.execute_batch(STAGE_DDL)?;
    {
        let mut ual = conn.appender("stage_ual")?;
        let mut mia = conn.appender("stage_mia")?;
        let mut file = conn.appender("stage_file")?;
        let mut sharing = conn.appender("stage_sharing")?;
        let mut search = conn.appender("stage_search")?;
        for s in rows {
            let r = &s.rec;
            let ord = s.ordinal as i64;
            ual.append_row(params![
                ord,
                r.record_id,
                r.synthetic_id,
                r.event_time,
                r.time_tz_assumed,
                r.time_precision.as_str(),
                r.record_type,
                r.record_type_name,
                r.workload,
                r.operation,
                r.result_status,
                r.user_upn,
                r.user_type,
                r.user_key,
                r.client_ip,
                r.user_agent,
                r.session_id,
                r.app_id,
                r.client_app_id,
                r.object_id,
                r.organization_id,
                r.mailbox_upn,
                parameters_json(&r.parameters),
                r.audit_data,
                r.completeness.as_str(),
                s.pos.line_start as i64,
                s.pos.line_end as i64,
                s.pos.byte_offset as i64,
                s.pos.byte_length as i64,
                s.raw_sha256
            ])?;
            for m in &r.mail_items {
                mia.append_row(params![
                    ord,
                    r.record_id,
                    m.item_ordinal,
                    m.access_type,
                    m.folder_path,
                    m.internet_message_id,
                    m.size_bytes,
                    m.is_throttled,
                    m.operation_count
                ])?;
            }
            if let Some(f) = &r.file_event {
                file.append_row(params![
                    ord,
                    r.record_id,
                    f.workload,
                    f.site_url,
                    f.relative_url,
                    f.file_name,
                    f.file_ext,
                    f.item_type,
                    f.is_onenote,
                    f.application_name,
                    f.platform,
                    f.device_name,
                    f.list_id,
                    f.list_item_id
                ])?;
            }
            if let Some(sh) = &r.sharing {
                sharing.append_row(params![
                    ord,
                    r.record_id,
                    sh.link_type,
                    sh.target_user,
                    sh.target_email,
                    sh.permission,
                    sh.is_external
                ])?;
            }
            if let Some(q) = &r.search {
                search.append_row(params![ord, r.record_id, q.workload, q.query_text, q.scope])?;
            }
        }
        ual.flush()?;
        mia.flush()?;
        file.flush()?;
        sharing.flush()?;
        search.flush()?;
    }
    conn.execute_batch(MERGE_SETUP)?;
    let (inserted, upgraded): (i64, i64) = conn.query_row(
        "SELECT (SELECT count(*) FROM stage_fresh), (SELECT count(*) FROM stage_upgrade)",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    conn.execute(&upgrade_sql(), [])?;
    conn.execute_batch(DELETE_UPGRADED_CHILDREN)?;
    conn.execute(&insert_fresh_sql(), params![collection_id])?;
    conn.execute_batch(INSERT_CHILDREN)?;
    conn.execute(INSERT_SOURCES, params![file_id])?;
    Ok(LoadOutcome {
        staged: rows.len() as u64,
        inserted: inserted as u64,
        upgraded: upgraded as u64,
    })
}
