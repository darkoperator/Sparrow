//! `events` rebuild: `DELETE`, then one `INSERT ... SELECT` per source table. Every insert shares one tail (tenant,
//! category, IP normalization and intel, finding count); only the `ev` select that maps a table's columns differs.

use crate::Result;
use crate::normalize::net::normalize_ip;
use duckdb::Connection;
use std::net::IpAddr;

/// `NULL` typed as text, so `lower(...)` and the tail's joins bind in an `ev` select that has no value for a column.
const NV: &str = "CAST(NULL AS VARCHAR)";
const ZERO_GUID: &str = "00000000-0000-0000-0000-000000000000";

/// TEMP copy of `events` the per-source inserts fill before one sorted insert into `events`.
const STAGE: &str = "events_stage";

/// `events` has no key or index (migration 31: DuckDB kept both in memory and the rebuild ran out at about 8M rows).
/// Each (source_table, record_key) is written once: there is one insert per evidence table (the sign-in source is a
/// CASE in the one `signins` select), each selecting one row per record, every join is one-to-one (`cat` matches the
/// raw workload and operation with `IS NOT DISTINCT FROM`, so NULL and '' are separate pairs), and the rows are
/// written after the DELETE. This relies on the evidence tables keeping their keys unique (`ual_events.record_id`,
/// each loader's `record_key`, `mail_items_accessed.item_key`); nothing at this layer checks it. The rows are stored
/// in event_time order (then table and key), so zone maps prune the grid's time ranges and its default time sort
/// reads them in order.
pub(super) fn rebuild(conn: &Connection) -> Result<u64> {
    build_ip_map(conn)?;
    build_audit_device_map(conn)?;
    conn.execute_batch(&format!(
        "CREATE OR REPLACE TEMP TABLE {STAGE} AS SELECT * FROM events LIMIT 0"
    ))?;
    let mut rows = 0;
    for s in sources() {
        rows += conn.execute(&insert_sql(&s), [])? as u64;
    }
    conn.execute_batch(&format!(
        "DELETE FROM events;
         INSERT INTO events SELECT * FROM {STAGE} ORDER BY event_time ASC NULLS LAST, source_table, record_key;
         DROP TABLE {STAGE};"
    ))?;
    conn.execute_batch(
        "DROP TABLE IF EXISTS events_ip_map; DROP TABLE IF EXISTS events_audit_device;
         -- A new generation: a search's cached hits (any connection's) are of the rows before this rebuild.
         INSERT OR REPLACE INTO case_meta VALUES ('events_generation', CAST(gen_random_uuid() AS VARCHAR));",
    )?;
    Ok(rows)
}

/// `events_ip_map(ip, norm_ip, prefix)`: each distinct raw IP text of the event tables, its `normalize_ip` form and its
/// /24 (IPv4) or /48 (IPv6) network. Built in Rust once, so the inserts only join it.
fn build_ip_map(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE OR REPLACE TEMP TABLE events_ip_map (ip VARCHAR, norm_ip VARCHAR, prefix VARCHAR)",
    )?;
    let mut ips: Vec<String> = Vec::new();
    {
        let mut st = conn.prepare(
            "SELECT DISTINCT ip FROM (
                SELECT client_ip AS ip FROM ual_events UNION ALL SELECT client_ip FROM mail_items_accessed
                UNION ALL SELECT ip FROM signins UNION ALL SELECT initiated_by_ip FROM directory_audits
                UNION ALL SELECT from_ip FROM message_trace UNION ALL SELECT client_ip FROM message_trace_events
                UNION ALL SELECT client_ip FROM mailbox_audit_legacy UNION ALL SELECT client_ip FROM admin_audit_events
                UNION ALL SELECT ip FROM risk_detections UNION ALL SELECT ip FROM azure_activity
                UNION ALL SELECT affected_ips[1] FROM security_alerts
             ) WHERE ip IS NOT NULL",
        )?;
        for ip in st.query_map([], |r| r.get::<_, String>(0))? {
            ips.push(ip?);
        }
    }
    let mut app = conn.appender("events_ip_map")?;
    for raw in &ips {
        let norm = normalize_ip(raw);
        let prefix = norm.as_deref().and_then(prefix_of);
        app.append_row(duckdb::params![raw, norm, prefix])?;
    }
    app.flush()?;
    Ok(())
}

/// `events_audit_device(record_key, device_id, object_id, name, ambiguous)`: the device each directory audit row is about,
/// read in Rust with the same logic `case::devices` uses for its lifecycle events (modified-property `DeviceId`, target
/// ids with or without `Device_`, several different device targets are ambiguous).
fn build_audit_device_map(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE OR REPLACE TEMP TABLE events_audit_device
            (record_key VARCHAR, device_id VARCHAR, object_id VARCHAR, name VARCHAR, ambiguous BOOLEAN)",
    )?;
    let mut rows = Vec::new();
    {
        let mut st = conn.prepare(
            "SELECT record_key, CAST(modified_properties AS VARCHAR), CAST(targets AS VARCHAR) FROM directory_audits
             WHERE contains(lower(coalesce(CAST(targets AS VARCHAR), '') || coalesce(CAST(modified_properties AS VARCHAR), '')), 'device')",
        )?;
        for r in st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })? {
            rows.push(r?);
        }
    }
    let mut app = conn.appender("events_audit_device")?;
    for (key, props, targets) in rows {
        let d = crate::case::devices::audit_device(props, targets);
        if d.device_id.is_some() || d.object_id.is_some() || d.ambiguous {
            app.append_row(duckdb::params![
                key,
                d.device_id,
                d.object_id,
                d.name,
                d.ambiguous
            ])?;
        }
    }
    app.flush()?;
    Ok(())
}

/// `a.b.c.0/24` for an IPv4 address, the `/48` network text for an IPv6 address, `None` for anything else.
pub(crate) fn prefix_of(norm_ip: &str) -> Option<String> {
    match norm_ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.{}.0/24", o[0], o[1], o[2]))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            Some(format!(
                "{}/48",
                std::net::Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0)
            ))
        }
    }
}

struct Source {
    /// Category when `operation_catalog` has no match (same fallback as the `timeline` view).
    fallback: &'static str,
    /// Extra CTEs for `ev`, each followed by a comma (empty when there are none).
    ctes: String,
    /// A select of the `ev` columns; see [`insert_sql`].
    ev: String,
}

/// `lower(trim(x))` unless empty or the all-zero GUID: the way device ids are kept (`case::devices::clean_device_id`).
fn clean_id(x: &str) -> String {
    format!("CASE WHEN lower(trim({x})) IN ('', '{ZERO_GUID}') THEN NULL ELSE lower(trim({x})) END")
}

/// The first entry of a `[{Name, Value}]` JSON array whose name is `name` (any case; keys Name/name), as a JSON object.
/// `arr` must be a JSON array.
fn pick(arr: &str, name: &str) -> String {
    format!(
        "list_filter(json_transform({arr}, '[\"JSON\"]'), lambda e: \
         lower(coalesce(json_extract_string(e, '$.Name'), json_extract_string(e, '$.name'), '')) = '{name}')[1]"
    )
}

/// The value of an entry from [`pick`], as text.
fn val(entry: &str) -> String {
    format!(
        "coalesce(json_extract_string({entry}, '$.Value'), json_extract_string({entry}, '$.value'))"
    )
}

fn sources() -> Vec<Source> {
    // DeviceProperties of AzureActiveDirectory UAL records, found case-insensitively and read as an array or as a
    // string holding one (as `case::devices::device_sightings` does). The id, display name and STS session id.
    let ual_dev = format!(
        "ual_dev AS (
            SELECT record_id, {id} AS dev_id, {name} AS dev_name, {sid} AS dev_session
            FROM (
                SELECT record_id, {pick_id} AS e_id, {pick_name} AS e_name, {pick_sid} AS e_sid
                FROM (
                    SELECT record_id,
                           CASE json_type(dp) WHEN 'ARRAY' THEN dp
                                WHEN 'VARCHAR' THEN TRY_CAST(json_extract_string(dp, '$') AS JSON) END AS arr
                    FROM (
                        SELECT record_id, json_extract(audit_data, '$.\"' || dk || '\"') AS dp
                        FROM (
                            SELECT u.record_id, u.audit_data,
                                   CASE WHEN json_type(u.audit_data) = 'OBJECT' THEN
                                        list_filter(json_keys(u.audit_data), lambda k: lower(k) = 'deviceproperties')[1] END AS dk
                            FROM ual_events u WHERE u.workload = 'AzureActiveDirectory'
                        ) WHERE dk IS NOT NULL
                    )
                ) WHERE json_type(arr) = 'ARRAY'
            )
        ),",
        pick_id = pick("arr", "id"),
        pick_name = pick("arr", "displayname"),
        pick_sid = pick("arr", "sessionid"),
        id = val("e_id"),
        name = val("e_name"),
        sid = val("e_sid"),
    );
    let ual = format!(
        "SELECT 'ual' AS source, 'ual_events' AS source_table, CAST(u.record_id AS VARCHAR) AS record_key,
                u.event_time, u.time_tz_assumed, u.collection_id, u.workload, u.operation, u.result_status AS result,
                u.user_upn AS actor_upn,
                CASE WHEN lower(u.operation) = 'mailitemsaccessed' THEN u.mailbox_upn END AS owner_upn,
                coalesce(u.mailbox_upn, u.object_id) AS target, u.client_ip AS ip, u.user_agent,
                {dev_id} AS device_id, nullif(trim(d.dev_name), '') AS device_name, {NV} AS device_object_id,
                lower(nullif(trim(coalesce(
                    json_extract_string(u.audit_data, '$.AppAccessContext.AADSessionId'), d.dev_session)), '')) AS entra_session_id,
                u.app_id,
                concat_ws(' ', u.workload, u.operation, CASE WHEN u.object_id IS NOT NULL THEN 'on ' || u.object_id END) AS summary
         FROM ual_events u LEFT JOIN ual_dev d ON d.record_id = u.record_id",
        dev_id = clean_id("d.dev_id"),
    );
    // Sessions-report rows (no raw record): the report is per mailbox, so the user owns the mailbox. Its SessionId is the
    // AuditData top-level SessionId (Exchange), never an Entra session, and the report has no device.
    let mia = format!(
        "SELECT 'mail_items_accessed', 'mail_items_accessed', m.item_key, m.event_time, m.time_tz_assumed, m.collection_id,
                'Exchange', 'MailItemsAccessed', {NV}, m.user_upn, m.user_upn, coalesce(m.internet_message_id, m.folder_path),
                m.client_ip, {NV}, {NV}, {NV}, {NV}, {NV}, {NV},
                concat_ws(' ', 'MailItemsAccessed', CAST(m.access_type AS VARCHAR), m.folder_path)
         FROM mail_items_accessed m WHERE m.record_id IS NULL"
    );
    let signins = format!(
        "SELECT CASE WHEN s.event_type IN ('service_principal', 'managed_identity') THEN 'signin_service'
                     WHEN coalesce(s.event_type = 'interactive', s.is_interactive, false) THEN 'signin_interactive'
                     ELSE 'signin_noninteractive' END,
                'signins', s.record_key, s.event_time, s.time_tz_assumed, s.collection_id, 'AzureActiveDirectory',
                CASE WHEN coalesce(s.error_code, 0) = 0 THEN 'SignInSucceeded' ELSE 'SignInFailed' END, s.status,
                coalesce(s.user_upn, s.app_name), {NV}, coalesce(s.resource_name, s.app_name), s.ip, s.user_agent,
                {dev_id}, nullif(trim(s.device.display_name), ''), {NV}, lower(nullif(trim(s.session_id), '')), s.app_id,
                concat_ws(' ', CAST(s.event_type AS VARCHAR), 'sign-in to', s.app_name,
                          CASE WHEN coalesce(s.error_code, 0) <> 0 THEN 'failed ' || s.error_code END)
         FROM signins s",
        dev_id = clean_id("s.device.device_id"),
    );
    // Directory audit device: see `build_audit_device_map`. The Entra device id is the row's own `DeviceId` modified
    // property, else the `devices` row of the target's object id, else NULL.
    let entra_dt =
        "dm AS (SELECT lower(object_id) AS oid, min(lower(device_id)) AS did FROM devices
                WHERE object_id IS NOT NULL AND device_id IS NOT NULL GROUP BY 1),"
            .to_string();
    let entra = format!(
        "SELECT 'entra_audit', 'directory_audits', d.record_key, d.event_time, d.time_tz_assumed, d.collection_id,
                'AzureActiveDirectory', d.activity, d.result, coalesce(d.initiated_by_upn, d.initiated_by_app_name), {NV},
                coalesce(d.targets->>'$[0].UserPrincipalName', d.targets->>'$[0].userPrincipalName',
                         d.targets->>'$[0].DisplayName', d.targets->>'$[0].displayName'),
                d.initiated_by_ip, {NV},
                CASE WHEN ad.ambiguous THEN NULL ELSE coalesce({prop_id}, dm.did) END,
                nullif(trim(ad.name), ''), ad.object_id, {NV}, d.initiated_by_app_id,
                concat_ws(' ', d.category, d.activity, d.result)
         FROM directory_audits d LEFT JOIN events_audit_device ad ON ad.record_key = d.record_key
         LEFT JOIN dm ON dm.oid = ad.object_id",
        prop_id = clean_id("ad.device_id"),
    );
    let trace = format!(
        "SELECT 'message_trace', 'message_trace', t.record_key, t.received, t.time_tz_assumed, t.collection_id, 'Exchange',
                'MessageTrace', t.status, t.sender, t.recipient, t.recipient, t.from_ip, {NV}, {NV}, {NV}, {NV}, {NV}, {NV},
                concat_ws(' ', t.status, t.subject)
         FROM message_trace t"
    );
    let trace_events = format!(
        "SELECT 'message_trace_event', 'message_trace_events', e.record_key, e.event_time, e.time_tz_assumed, e.collection_id,
                'Exchange', e.event_id, e.recipient_status, e.sender, json_extract_string(e.recipients, '$[0]'),
                json_extract_string(e.recipients, '$[0]'), e.client_ip, {NV}, {NV}, {NV}, {NV}, {NV}, {NV},
                concat_ws(' ', e.event_id, e.source_context, e.subject)
         FROM message_trace_events e"
    );
    let mailbox = format!(
        "SELECT 'mailbox_audit', 'mailbox_audit_legacy', l.record_key, l.event_time, l.time_tz_assumed, l.collection_id,
                'Exchange', l.operation, l.operation_result, l.logon_user, l.mailbox_upn, l.mailbox_upn, l.client_ip,
                l.client_info, {NV}, {NV}, {NV}, {NV}, l.app_id, concat_ws(' ', l.logon_type, l.operation, l.folder_path)
         FROM mailbox_audit_legacy l"
    );
    let admin = format!(
        "SELECT 'admin_audit', 'admin_audit_events', a.record_key, a.run_time, a.time_tz_assumed, a.collection_id, 'Exchange',
                a.cmdlet, CASE a.succeeded WHEN true THEN 'Succeeded' WHEN false THEN 'Failed' END, a.caller, {NV},
                a.object_modified, a.client_ip, {NV}, {NV}, {NV}, {NV}, {NV}, a.app_id,
                concat_ws(' ', a.cmdlet, a.object_modified)
         FROM admin_audit_events a"
    );
    let risk = format!(
        "SELECT 'risk_detection', 'risk_detections', r.record_key, coalesce(r.activity_time, r.detected_time), false,
                r.collection_id, 'AzureActiveDirectory', r.risk_event_type, r.risk_state, r.user_upn, {NV}, {NV}, r.ip,
                {NV}, {NV}, {NV}, {NV}, {NV}, {NV}, concat_ws(' ', 'risk', r.risk_level, r.risk_event_type)
         FROM risk_detections r"
    );
    let azure = format!(
        "SELECT 'azure_activity', 'azure_activity', a.record_key, a.event_time, a.time_tz_assumed, a.collection_id, 'Azure',
                a.operation_name, a.status, a.caller, {NV}, a.resource_id, a.ip, {NV}, {NV}, {NV}, {NV}, {NV}, {NV},
                a.operation_name || ' ' || a.status
         FROM azure_activity a"
    );
    let alerts = format!(
        "SELECT 'security_alert', 'security_alerts', s.record_key, coalesce(s.event_time, s.created_time), false,
                s.collection_id, {NV}, s.title, s.status, s.affected_users[1], {NV}, {NV}, s.affected_ips[1],
                {NV}, {NV}, {NV}, {NV}, {NV}, {NV}, s.severity || ': ' || s.title
         FROM security_alerts s"
    );
    let s = |_table: &str, fallback, ctes: &str, ev| Source {
        fallback,
        ctes: ctes.to_string(),
        ev,
    };
    vec![
        s("ual_events", "other", &ual_dev, ual),
        s("mail_items_accessed", "other", "", mia),
        s("signins", "auth", "", signins),
        s("directory_audits", "other", &entra_dt, entra),
        s("message_trace", "mail_flow", "", trace),
        s("message_trace_events", "mail_flow", "", trace_events),
        s("mailbox_audit_legacy", "other", "", mailbox),
        s("admin_audit_events", "other", "", admin),
        s("risk_detections", "auth", "", risk),
        s("azure_activity", "config_change", "", azure),
        s("security_alerts", "other", "", alerts),
    ]
}

/// The insert for one source. `ev` must select, in this order: source, source_table, record_key, event_time,
/// time_tz_assumed, collection_id, workload, operation, result, actor_upn, owner_upn, target, ip, user_agent,
/// device_id, device_name, device_object_id, entra_session_id, app_id, summary. Everything derived is added here: tenant from the
/// collection, category once per distinct (workload, operation), the normalized IP and its prefix, `ip_intel` columns
/// kind.
fn insert_sql(src: &Source) -> String {
    let Source {
        fallback, ctes, ev, ..
    } = src;
    format!(
        "INSERT INTO {STAGE}
         WITH {ctes}
         ev AS (SELECT * FROM ({ev}) t(source, source_table, record_key, event_time, time_tz_assumed, collection_id,
                workload, operation, result, actor_upn, owner_upn, target, ip, user_agent, device_id, device_name,
                device_object_id, entra_session_id, app_id, summary)),
         cat AS (
             SELECT d.workload, d.operation,
                    coalesce((SELECT o.category FROM operation_catalog o
                              WHERE o.operation_key = lower(trim(rtrim(trim(d.operation), '.')))
                                AND (o.workload IS NULL OR lower(o.workload) = lower(d.workload))
                              ORDER BY o.workload NULLS LAST LIMIT 1),
                             CAST('{fallback}' AS event_category)) AS category
             FROM (SELECT DISTINCT workload, operation FROM ev) d)
         SELECT ev.source_table, ev.record_key, ev.source, ev.event_time, ev.time_tz_assumed, c.tenant_key, ev.workload,
                cat.category, ev.operation, ev.result, lower(ev.actor_upn), lower(ev.owner_upn), ev.target,
                coalesce(m.norm_ip, ev.ip), m.prefix, i.country_iso, i.asn, i.asn_org,
                CASE WHEN i.is_private THEN 'private' WHEN i.is_microsoft THEN 'microsoft' WHEN i.is_hosting THEN 'hosting' END,
                ev.device_id, ev.device_name, ev.device_object_id, ev.entra_session_id, ev.user_agent, ev.app_id, ev.summary
         FROM ev
         LEFT JOIN collections c ON c.collection_id = ev.collection_id
         LEFT JOIN cat ON cat.workload IS NOT DISTINCT FROM ev.workload
                      AND cat.operation IS NOT DISTINCT FROM ev.operation
         LEFT JOIN events_ip_map m ON m.ip = ev.ip
         LEFT JOIN ip_intel i ON i.ip = ev.ip"
    )
}
