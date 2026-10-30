//! The items of the attributed records, per category. Each category is one `SELECT` over the `attributed` relation of
//! `scope` and the evidence tables, producing the columns of [`Item`]; the queries are joined by `UNION ALL` and read
//! once. A read or sent message is one item per account and InternetMessageId, from its direct sighting if it has one
//! (else its time-attributed one), earliest first.

use super::scope::ctes;
use super::{Attribution, Category};
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
}

/// `attributed a` joined to its UAL record `u`.
const UAL: &str = "attributed a JOIN ual_events u ON a.source_table = 'ual_events' \
     AND a.record_key = CAST(u.record_id AS VARCHAR)";

/// The item columns, in [`Item`] order after `category`: account, category, attribution, accessed (epoch us), action,
/// item, location, from, to, size_bytes, item_time (epoch us), app, ip, session_id, owner, note, source, source_table,
/// record_key.
fn mail_sql() -> String {
    format!(
        "reads_raw AS ( \
           SELECT a.account, a.attribution, a.event_time, CAST(m.access_type AS VARCHAR) AS access, m.folder_path, \
               m.internet_message_id AS imid, m.size_bytes, u.app_id AS app, u.client_ip AS ip, u.session_id, \
               lower(u.mailbox_upn) AS mailbox, 'ual_events:MailItemsAccessed' AS source, a.source_table, \
               a.record_key, m.item_ordinal AS ord \
             FROM {UAL} JOIN mail_items_accessed m ON m.record_id = u.record_id \
           UNION ALL \
           SELECT a.account, a.attribution, a.event_time, CAST(m.access_type AS VARCHAR), m.folder_path, \
               m.internet_message_id, m.size_bytes, NULL, m.client_ip, m.session_id, lower(m.user_upn), \
               'mail_items_accessed:MailItemsAccessed', a.source_table, a.record_key, m.item_ordinal \
             FROM attributed a JOIN mail_items_accessed m ON a.source_table = 'mail_items_accessed' \
               AND a.record_key = m.item_key \
           UNION ALL \
           SELECT a.account, a.attribution, a.event_time, 'bind', l.folder_path, x.imid, NULL, l.app_id, l.client_ip, \
               l.session_id, lower(l.mailbox_upn), 'mailbox_audit_legacy:' || l.operation, a.source_table, \
               a.record_key, x.ord \
             FROM attributed a JOIN mailbox_audit_legacy l ON a.source_table = 'mailbox_audit_legacy' \
               AND a.record_key = l.record_key \
               AND l.operation IN ('MailItemsAccessed', 'MessageBind') \
             CROSS JOIN LATERAL (SELECT unnest(l.internet_message_ids) AS imid, \
               generate_subscripts(l.internet_message_ids, 1) - 1 AS ord) x), \
         reads AS ( \
           SELECT * EXCLUDE (rn) FROM ( \
             SELECT *, CASE WHEN imid IS NULL OR access = 'sync' THEN 1 ELSE row_number() OVER ( \
               PARTITION BY account, imid, access = 'sync' \
               ORDER BY attribution = 'time', event_time, source_table, record_key, ord) END AS rn \
             FROM reads_raw) WHERE rn = 1), \
         sent_raw AS ( \
           SELECT a.account, a.attribution, a.event_time, u.operation AS op, \
               json_extract_string(u.audit_data, '$.Item.Subject') AS subject, \
               json_extract_string(u.audit_data, '$.Item.InternetMessageId') AS imid, u.app_id AS app, \
               u.client_ip AS ip, u.session_id, \
               lower(coalesce(CASE u.operation WHEN 'SendAs' THEN json_extract_string(u.audit_data, '$.SendAsUserSmtp') \
                 WHEN 'SendOnBehalf' THEN json_extract_string(u.audit_data, '$.SendOnBehalfOfUserSmtp') END, \
                 u.mailbox_upn)) AS mailbox, \
               'ual_events:' || u.operation AS source, a.source_table, a.record_key \
             FROM {UAL} WHERE u.operation IN ('Send', 'SendAs', 'SendOnBehalf') \
           UNION ALL \
           SELECT a.account, a.attribution, a.event_time, l.operation, l.subjects[x.i], l.internet_message_ids[x.i], \
               l.app_id, l.client_ip, l.session_id, lower(l.mailbox_upn), 'mailbox_audit_legacy:' || l.operation, \
               a.source_table, a.record_key \
             FROM attributed a JOIN mailbox_audit_legacy l ON a.source_table = 'mailbox_audit_legacy' \
               AND a.record_key = l.record_key AND l.operation IN ('Send', 'SendAs', 'SendOnBehalf') \
             CROSS JOIN LATERAL (SELECT unnest(range(1, greatest(len(coalesce(l.internet_message_ids, [])), \
               len(coalesce(l.subjects, [])), 1) + 1)) AS i) x), \
         sent AS ( \
           SELECT * EXCLUDE (rn) FROM ( \
             SELECT *, CASE WHEN imid IS NULL THEN 1 ELSE row_number() OVER (PARTITION BY account, imid \
               ORDER BY attribution = 'time', event_time, source_table, record_key) END AS rn FROM sent_raw) \
           WHERE rn = 1), \
         trace AS ( \
           SELECT internet_message_id AS imid, arg_min(subject, received) AS subject, \
               arg_min(sender, received) AS sender, \
               string_agg(DISTINCT lower(recipient), '; ' ORDER BY lower(recipient)) AS rcpts, min(received) AS received \
             FROM message_trace WHERE internet_message_id IN (SELECT imid FROM reads UNION SELECT imid FROM sent) \
             GROUP BY 1), \
         mail AS ( \
           SELECT r.account, 'mail_read' AS category, r.attribution, epoch_us(r.event_time) AS accessed, \
               CASE WHEN r.access = 'sync' THEN 'synced' ELSE 'read' END AS action, \
               CASE WHEN r.access = 'sync' THEN NULL ELSE t.subject END AS item, r.folder_path AS location, \
               t.sender AS \"from\", t.rcpts AS \"to\", r.size_bytes, epoch_us(t.received) AS item_time, r.app, r.ip, \
               r.session_id, CASE WHEN r.mailbox <> r.account THEN r.mailbox END AS owner, \
               CASE WHEN r.mailbox <> r.account THEN 'in mailbox ' || r.mailbox END AS note, r.source, \
               r.source_table, r.record_key \
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
               s.source, s.source_table, s.record_key \
             FROM sent s LEFT JOIN trace t ON t.imid = s.imid)"
    )
}

fn ts(us: Option<i64>) -> Option<DateTime<Utc>> {
    us.and_then(DateTime::from_timestamp_micros)
}

/// Every item of one account (any case) or of every attributed account, by account, time, category and record.
pub fn items(conn: &Connection, account: Option<&str>) -> Result<Vec<Item>> {
    let sql = format!(
        "WITH {}, {} SELECT * FROM mail WHERE ? IS NULL OR account = lower(?) \
         ORDER BY account, accessed, category, source_table, record_key, item",
        ctes(),
        mail_sql()
    );
    let mut st = conn.prepare(&sql)?;
    let rows = st.query_map(duckdb::params![account, account], |r| {
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
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}
