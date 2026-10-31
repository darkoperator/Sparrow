//! The items of the attributed records, per category. Each category is one `SELECT` over the `attributed` relation of
//! `scope` and the evidence tables, producing the columns of [`Item`]; the queries are joined by `UNION ALL` and read
//! once. A read or sent message is one item per account and InternetMessageId, from its direct sighting if it has one
//! (else its time-attributed one), earliest first.

use super::scope::{Attributed, attributed_with, ctes};
use super::{Attribution, Basis, Category, ScopeSource};
use crate::Result;
use chrono::{DateTime, Utc};
use duckdb::Connection;
use serde::Serialize;

/// One thing the attacker reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Item {
    /// The compromised account the item was reached through.
    pub account: String,
    pub category: Category,
    pub attribution: Attribution,
    pub accessed: DateTime<Utc>,
    /// read, synced, sent, sent as, accessed, the operation, ...
    pub action: String,
    /// Subject, file name, chat or resource name.
    pub item: Option<String>,
    /// Folder, site and path, chat thread, workload.
    pub location: Option<String>,
    pub from: Option<String>,
    /// Recipients, `; `-joined and sorted.
    pub to: Option<String>,
    pub size_bytes: Option<i64>,
    /// When the message was sent or received (message trace).
    pub item_time: Option<DateTime<Utc>>,
    pub app: Option<String>,
    pub ip: Option<String>,
    pub session_id: Option<String>,
    /// The owner of the data when it is not the account (a shared or delegated mailbox, send as, ...).
    pub owner: Option<String>,
    pub note: Option<String>,
    /// `<table>:<operation>`.
    pub source: String,
    pub source_table: String,
    pub record_key: String,
    /// What ties the record to the attacker: an accepted flag, a pending one, or an ad-hoc value.
    pub basis: Basis,
}

/// `attributed a` joined to its UAL record `u` in `access_ual` (see [`stage_ual`]).
const UAL: &str = "attributed_ual a JOIN access_ual u ON u.record_id = a.rid";

/// The item columns, in [`Item`] order after `category`: account, category, attribution, accessed (epoch us), action,
/// item, location, from, to, size_bytes, item_time (epoch us), app, ip, session_id, owner, note, source, source_table,
/// record_key, basis (rank; a message kept once takes the strongest basis of all its sightings).
fn mail_sql() -> String {
    format!(
        "attributed_ual AS MATERIALIZED (SELECT *, TRY_CAST(record_key AS UUID) AS rid FROM attributed \
           WHERE source_table = 'ual_events'), \
         reads_raw AS ( \
           SELECT a.account, a.attribution, a.event_time, CAST(m.access_type AS VARCHAR) AS access, m.folder_path, \
               m.internet_message_id AS imid, m.size_bytes, u.app_id AS app, u.client_ip AS ip, u.session_id, \
               lower(u.mailbox_upn) AS mailbox, 'ual_events:MailItemsAccessed' AS source, a.source_table, \
               a.record_key, m.item_ordinal AS ord, a.basis \
             FROM {UAL} JOIN mail_items_accessed m ON m.record_id = u.record_id \
           UNION ALL \
           SELECT a.account, a.attribution, a.event_time, CAST(m.access_type AS VARCHAR), m.folder_path, \
               m.internet_message_id, m.size_bytes, NULL, m.client_ip, m.session_id, lower(m.user_upn), \
               'mail_items_accessed:MailItemsAccessed', a.source_table, a.record_key, m.item_ordinal, a.basis \
             FROM attributed a JOIN mail_items_accessed m ON a.source_table = 'mail_items_accessed' \
               AND a.record_key = m.item_key \
           UNION ALL \
           SELECT a.account, a.attribution, a.event_time, 'bind', l.folder_path, l.internet_message_ids[x.i], NULL, \
               l.app_id, l.client_ip, \
               l.session_id, lower(l.mailbox_upn), 'mailbox_audit_legacy:' || l.operation, a.source_table, \
               a.record_key, x.i - 1, a.basis \
             FROM attributed a JOIN mailbox_audit_legacy l ON a.source_table = 'mailbox_audit_legacy' \
               AND a.record_key = l.record_key \
               AND l.operation IN ('MailItemsAccessed', 'MessageBind') \
             CROSS JOIN LATERAL (SELECT unnest(range(1, greatest(len(coalesce(l.internet_message_ids, [])), 1) \
               + 1)) AS i) x), \
         reads AS ( \
           SELECT * EXCLUDE (rn) FROM ( \
             SELECT *, CASE WHEN imid IS NULL OR access = 'sync' THEN 1 ELSE row_number() OVER ( \
               PARTITION BY account, imid, access = 'sync' \
               ORDER BY attribution = 'time', event_time, source_table, record_key, ord) END AS rn, \
               CASE WHEN imid IS NULL OR access = 'sync' THEN basis ELSE min(basis) OVER ( \
               PARTITION BY account, imid, access = 'sync') END AS gbasis \
             FROM reads_raw) WHERE rn = 1), \
         sent_raw AS ( \
           SELECT a.account, a.attribution, a.event_time, u.operation AS op, \
               json_extract_string(u.audit_data, '$.Item.Subject') AS subject, \
               json_extract_string(u.audit_data, '$.Item.InternetMessageId') AS imid, u.app_id AS app, \
               u.client_ip AS ip, u.session_id, \
               lower(coalesce(CASE u.operation WHEN 'SendAs' THEN json_extract_string(u.audit_data, '$.SendAsUserSmtp') \
                 WHEN 'SendOnBehalf' THEN json_extract_string(u.audit_data, '$.SendOnBehalfOfUserSmtp') END, \
                 u.mailbox_upn)) AS mailbox, \
               'ual_events:' || u.operation AS source, a.source_table, a.record_key, a.basis \
             FROM {UAL} WHERE u.operation IN ('Send', 'SendAs', 'SendOnBehalf') \
           UNION ALL \
           SELECT a.account, a.attribution, a.event_time, l.operation, l.subjects[x.i], l.internet_message_ids[x.i], \
               l.app_id, l.client_ip, l.session_id, lower(l.mailbox_upn), 'mailbox_audit_legacy:' || l.operation, \
               a.source_table, a.record_key, a.basis \
             FROM attributed a JOIN mailbox_audit_legacy l ON a.source_table = 'mailbox_audit_legacy' \
               AND a.record_key = l.record_key AND l.operation IN ('Send', 'SendAs', 'SendOnBehalf') \
             CROSS JOIN LATERAL (SELECT unnest(range(1, greatest(len(coalesce(l.internet_message_ids, [])), \
               len(coalesce(l.subjects, [])), 1) + 1)) AS i) x), \
         sent AS ( \
           SELECT * EXCLUDE (rn) FROM ( \
             SELECT *, CASE WHEN imid IS NULL THEN 1 ELSE row_number() OVER (PARTITION BY account, imid \
               ORDER BY attribution = 'time', event_time, source_table, record_key) END AS rn, \
               CASE WHEN imid IS NULL THEN basis ELSE min(basis) OVER (PARTITION BY account, imid) END AS gbasis \
               FROM sent_raw) \
           WHERE rn = 1), \
         trace AS ( \
           SELECT internet_message_id AS imid, arg_min(subject, received) AS subject, \
               arg_min(sender, received) AS sender, \
               string_agg(DISTINCT lower(recipient), '; ' ORDER BY lower(recipient)) AS rcpts, min(received) AS received \
             FROM message_trace WHERE internet_message_id IN (SELECT imid FROM reads UNION SELECT imid FROM sent) \
             GROUP BY 1), \
         mail AS ( \
           SELECT r.account, 'mail_read' AS category, r.attribution, epoch_us(r.event_time) AS accessed, \
               CASE WHEN r.access = 'sync' THEN 'synced' WHEN r.imid IS NULL THEN 'read (no message id)' ELSE 'read' END AS action, \
               CASE WHEN r.access = 'sync' THEN NULL ELSE t.subject END AS item, r.folder_path AS location, \
               t.sender AS \"from\", t.rcpts AS \"to\", r.size_bytes, epoch_us(t.received) AS item_time, r.app, r.ip, \
               r.session_id, CASE WHEN r.mailbox <> r.account THEN r.mailbox END AS owner, \
               CASE WHEN r.mailbox <> r.account THEN 'in mailbox ' || r.mailbox END AS note, r.source, \
               r.source_table, r.record_key, r.gbasis AS basis \
             FROM reads r LEFT JOIN trace t ON t.imid = r.imid AND r.access <> 'sync' \
           UNION ALL \
           SELECT s.account, 'mail_sent', s.attribution, epoch_us(s.event_time), \
               CASE s.op WHEN 'SendAs' THEN 'sent as' WHEN 'SendOnBehalf' THEN 'sent on behalf of' ELSE 'sent' END, \
               coalesce(s.subject, t.subject), NULL, coalesce(t.sender, s.mailbox), t.rcpts, NULL, \
               epoch_us(t.received), s.app, s.ip, s.session_id, \
               CASE WHEN s.mailbox <> s.account THEN s.mailbox END, \
               CASE WHEN s.mailbox <> s.account THEN \
                 CASE s.op WHEN 'SendAs' THEN 'sent as ' WHEN 'SendOnBehalf' THEN 'sent on behalf of ' \
                   ELSE 'in mailbox ' END || s.mailbox END, \
               s.source, s.source_table, s.record_key, s.gbasis \
             FROM sent s LEFT JOIN trace t ON t.imid = s.imid)"
    )
}

/// The other categories, as `rest` with the columns of `mail`. A UAL record is in exactly one: attachment
/// (AttachmentAccess), file (it has a `file_events` or `sharing_events` child), teams (workload MicrosoftTeams), copilot
/// (CopilotInteraction), else other. Mail operations, sign-ins (`auth`) and mail flow (message trace) are never other.
fn rest_sql() -> String {
    let j = |path: &str| format!("json_extract_string(u.audit_data, '{path}')");
    let (chat, item_name, msg_id, thread) = (
        j("$.ChatName"),
        j("$.ItemName"),
        j("$.MessageId"),
        j("$.ChatThreadId"),
    );
    let (att_name, att_id, att_size) = (
        j("$.AttachmentName"),
        j("$.AttachmentId"),
        j("$.AttachmentSizeInBytes"),
    );
    let host = j("$.CopilotEventData.AppHost");
    let common = "a.attribution, epoch_us(a.event_time)";
    let tail = "u.client_ip, u.session_id, NULL, NULL";
    let src = "'ual_events:' || u.operation, a.source_table, a.record_key, a.basis";
    format!(
        "shares AS ( \
           SELECT sh.record_id, string_agg(DISTINCT coalesce(sh.target_email, sh.target_user, 'someone') \
               || CASE WHEN sh.is_external THEN ' (external)' ELSE '' END, '; ') AS targets \
             FROM sharing_events sh WHERE sh.record_id IN (SELECT rid FROM attributed_ual) GROUP BY 1), \
         files AS ( \
           SELECT a.account, 'file' AS category, {common} AS accessed, u.operation AS action, f.file_name AS item, \
               f.site_url || coalesce(f.relative_url, '') AS location, NULL AS \"from\", NULL AS \"to\", \
               NULL::BIGINT AS size_bytes, NULL::BIGINT AS item_time, f.application_name AS app, u.client_ip AS ip, \
               u.session_id, NULL AS owner, 'shared with ' || sh.targets AS note, {src} \
             FROM {UAL} JOIN file_events f ON f.record_id = u.record_id LEFT JOIN shares sh ON sh.record_id = u.record_id \
           UNION ALL \
           SELECT a.account, 'file', {common}, u.operation, NULL, NULL, NULL, NULL, NULL, NULL, u.app_id, {tail_ip}, \
               NULL, 'shared with ' || sh.targets, {src} \
             FROM {UAL} JOIN shares sh ON sh.record_id = u.record_id \
               WHERE u.record_id NOT IN (SELECT record_id FROM file_events)), \
         rest AS ( \
           SELECT * FROM files \
           UNION ALL \
           SELECT a.account, 'attachment', {common}, 'accessed', coalesce({att_name}, {att_id}), NULL, NULL, NULL, \
               TRY_CAST({att_size} AS BIGINT), NULL, u.app_id, {tail}, {src} \
             FROM {UAL} WHERE u.operation = 'AttachmentAccess' \
           UNION ALL \
           SELECT a.account, 'teams', {common}, u.operation, coalesce({chat}, {item_name}, {msg_id}), {thread}, NULL, \
               NULL, NULL, NULL, u.app_id, {tail}, {src} \
             FROM {UAL} WHERE u.workload = 'MicrosoftTeams' AND u.operation IS DISTINCT FROM 'CopilotInteraction' \
           UNION ALL \
           SELECT a.account, 'copilot', {common}, coalesce(json_extract_string(r.res, '$.Action'), 'read'), \
               json_extract_string(r.res, '$.Name'), json_extract_string(r.res, '$.SiteUrl'), NULL, NULL, NULL, NULL, \
               u.app_id, u.client_ip, u.session_id, NULL, 'via Copilot in ' || coalesce({host}, 'an app'), {src} \
             FROM {UAL} CROSS JOIN LATERAL (SELECT unnest(json_extract(u.audit_data, \
               '$.CopilotEventData.AccessedResources[*]')) AS res) r WHERE u.operation = 'CopilotInteraction' \
           UNION ALL \
           SELECT a.account, 'copilot', {common}, 'prompt', NULL, NULL, NULL, NULL, NULL, NULL, u.app_id, {tail_ip}, \
               NULL, 'Copilot in ' || coalesce({host}, 'an app'), {src} \
             FROM {UAL} WHERE u.operation = 'CopilotInteraction' AND coalesce(json_array_length(u.audit_data, \
               '$.CopilotEventData.AccessedResources'), 0) = 0 \
           UNION ALL \
           SELECT a.account, 'other', {common}, coalesce(e.operation, a.source_table), \
               coalesce(q.query_text, u.object_id, e.target), coalesce(e.workload, a.source_table), NULL, NULL, NULL, NULL, \
               coalesce(u.app_id, e.app_id), e.ip, u.session_id, NULL, NULL, \
               a.source_table || ':' || coalesce(e.operation, ''), a.source_table, a.record_key, a.basis \
             FROM attributed a JOIN events e USING (source_table, record_key) \
             LEFT JOIN attributed_ual au ON au.source_table = a.source_table AND au.record_key = a.record_key \
             LEFT JOIN access_ual u ON u.record_id = au.rid \
             LEFT JOIN search_queries q ON q.record_id = u.record_id \
             WHERE e.category NOT IN ('auth', 'mail_flow') \
               AND a.source_table NOT IN ('mail_items_accessed', 'message_trace', 'message_trace_events', 'signins') \
               AND NOT (a.source_table = 'mailbox_audit_legacy' AND coalesce(e.operation, '') IN \
                 ('MailItemsAccessed', 'MessageBind', 'Send', 'SendAs', 'SendOnBehalf')) \
               AND (u.record_id IS NULL OR ( \
                 coalesce(u.operation, '') NOT IN ('MailItemsAccessed', 'Send', 'SendAs', 'SendOnBehalf', \
                   'AttachmentAccess', 'CopilotInteraction') \
                 AND coalesce(u.workload, '') <> 'MicrosoftTeams' \
                 AND u.record_id NOT IN (SELECT record_id FROM file_events) \
                 AND u.record_id NOT IN (SELECT record_id FROM sharing_events))))",
        tail_ip = "u.client_ip, u.session_id"
    )
}

fn ts(us: Option<i64>) -> Option<DateTime<Utc>> {
    us.and_then(DateTime::from_timestamp_micros)
}

/// The attributed UAL records, copied into the connection's temp table `access_ual`. The item queries read their
/// AuditData; joined straight to `ual_events`, DuckDB scans the whole AuditData column before the join filters it (a
/// minute on a tenant-wide case), while a lookup by constant record ids uses the table's primary-key index.
fn stage_ual(conn: &Connection, attributed: &[Attributed]) -> Result<()> {
    conn.execute_batch(
        "CREATE OR REPLACE TEMP TABLE access_ual AS SELECT * FROM ual_events WHERE FALSE",
    )?;
    // Parsed as UUIDs (a record id is one; anything else is never inlined) and de-duplicated.
    let ids: std::collections::BTreeSet<uuid::Uuid> = attributed
        .iter()
        .filter(|a| a.source_table == "ual_events")
        .filter_map(|a| uuid::Uuid::parse_str(&a.record_key).ok())
        .collect();
    let ids: Vec<String> = ids.into_iter().map(|u| format!("'{u}'")).collect();
    for chunk in ids.chunks(1000) {
        conn.execute_batch(&format!(
            "INSERT INTO access_ual SELECT * FROM ual_events WHERE record_id IN ({})",
            chunk.join(", ")
        ))?;
    }
    Ok(())
}

/// Every item of one account (any case) or of every attributed account, by account, time, category and record.
pub fn items(conn: &Connection, account: Option<&str>) -> Result<Vec<Item>> {
    items_with(conn, account, &ScopeSource::accepted())
}

/// [`items`] with the flags `src` puts in play, each item with its record's [`Basis`].
pub fn items_with(
    conn: &Connection,
    account: Option<&str>,
    src: &ScopeSource,
) -> Result<Vec<Item>> {
    let (ctes, mut params) = ctes(src);
    let sql = format!(
        "WITH {ctes}, {}, {} SELECT * FROM (SELECT * FROM mail UNION ALL SELECT * FROM rest) \
         WHERE ? IS NULL OR account = lower(?) ORDER BY account, accessed, category, source_table, record_key, item",
        mail_sql(),
        rest_sql()
    );
    let attributed = attributed_with(conn, account, src)?;
    stage_ual(conn, &attributed)?;
    let acc = account.map_or(duckdb::types::Value::Null, |a| {
        duckdb::types::Value::Text(a.to_string())
    });
    params.push(acc.clone());
    params.push(acc);
    let mut st = conn.prepare(&sql)?;
    let rows = st.query_map(duckdb::params_from_iter(params.iter()), |r| {
        let category: String = r.get(1)?;
        let attribution: String = r.get(2)?;
        Ok(Item {
            account: r.get(0)?,
            category: Category::parse(&category).unwrap_or(Category::Other),
            attribution: Attribution::parse(&attribution).unwrap_or(Attribution::Time),
            accessed: ts(r.get(3)?).unwrap_or_default(),
            action: r.get(4)?,
            item: r.get(5)?,
            location: r.get(6)?,
            from: r.get(7)?,
            to: r.get(8)?,
            size_bytes: r.get(9)?,
            item_time: ts(r.get(10)?),
            app: r.get(11)?,
            ip: r.get(12)?,
            session_id: r.get(13)?,
            owner: r.get(14)?,
            note: r.get(15)?,
            source: r.get(16)?,
            source_table: r.get(17)?,
            record_key: r.get(18)?,
            basis: Basis::from_rank(r.get(19)?),
        })
    })?;
    let out: Vec<Item> = rows.collect::<std::result::Result<_, _>>()?;
    // The staged AuditData is only needed for this query: free it.
    conn.execute_batch("DROP TABLE IF EXISTS access_ual")?;
    Ok(out)
}
