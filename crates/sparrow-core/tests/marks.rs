//! Task 4 of the investigate tabs: marks on events. Row flags, standing value flags, tags, the review of an agent's
//! marks through `case::review`, the indicator a malicious flag makes, and the survival of marks across an events
//! rebuild and a re-ingest. Most cases insert `events` rows directly; the ingest cases use the synthetic UAL fixtures.

use chrono::{DateTime, Duration, TimeZone, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sparrow_core::Case;
use sparrow_core::Error;
use sparrow_core::case::actor::{Actor, Reviewer};
use sparrow_core::case::audit::{self, AuditEntry};
use sparrow_core::case::events::{self, AiFilter, Entity, EventQuery, EventRow, Field, FlagFilter};
use sparrow_core::case::indicators;
use sparrow_core::case::marks::{
    self, FlagLevel, MAX_AGENT_ROWS, RowRef, ValueKind, flag_rows, flag_value,
    flag_value_with_indicators, list_tags, review_marks, tag_rows,
};
use sparrow_core::case::notes::{self, NoteTarget};
use sparrow_core::case::review;
use sparrow_core::fixtures::ual;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, ingest_path};
use sparrow_core::profile::{ProfileOptions, refresh};

const IP: &str = "203.0.113.45";
const SESSION_S: &str = "2222aaaa-2222-4222-8222-22222222bbbb";
const SESSION_T: &str = "3333aaaa-3333-4333-8333-33333333cccc";
const DEVICE: &str = "d3d3d3d3-0000-4000-8000-00000000abcd";

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 1, 10, 0, 0).unwrap()
}

fn analyst() -> Actor {
    Actor::analyst("carlos").unwrap()
}

fn agent() -> Actor {
    Actor::agent("triage", Some("carlos")).unwrap()
}

fn reviewer() -> Reviewer {
    Reviewer::analyst("carlos").unwrap()
}

fn r(table: &str, key: &str) -> RowRef {
    RowRef::new(table, key)
}

/// One `events` row; unset columns are NULL.
#[derive(Default, Clone)]
struct Ev {
    table: &'static str,
    key: &'static str,
    source: &'static str,
    tenant: Option<&'static str>,
    actor: Option<&'static str>,
    owner: Option<&'static str>,
    ip: Option<&'static str>,
    prefix: Option<&'static str>,
    asn: Option<i32>,
    device: Option<&'static str>,
    session: Option<&'static str>,
}

fn put(case: &Case, i: i64, e: &Ev) {
    case.conn()
        .execute(
            "INSERT INTO events (source_table, record_key, source, event_time, category, tenant_key, actor_upn, owner_upn, \
             ip, ip_prefix, asn, device_id, entra_session_id) \
             VALUES (?, ?, ?, CAST(? AS TIMESTAMPTZ), 'other', ?, ?, ?, ?, ?, ?, ?, ?)",
            duckdb::params![
                e.table,
                e.key,
                e.source,
                (t0() + Duration::seconds(i)).format("%Y-%m-%dT%H:%M:%S%.6f+00").to_string(),
                e.tenant,
                e.actor,
                e.owner,
                e.ip,
                e.prefix,
                e.asn,
                e.device,
                e.session
            ],
        )
        .unwrap();
}

/// Six events:
/// u1 jdoe, IP, /24, AS 64500, session S, tenant contoso
/// u2 jdoe, IP, /24, AS 64500, session T, tenant contoso
/// u3 other, IP+1 (same /24), AS 64500, device D, tenant fabrikam
/// s1 jdoe, 2001:db8:abcd::1 (a /48), session S, tenant contoso
/// m1 bob (actor and owner), no IP
/// t1 sender@ext.example sends to jdoe (owner), IP+2, tenant contoso
fn events_case() -> Case {
    let case = Case::in_memory().unwrap();
    let rows = [
        Ev {
            table: "ual_events",
            key: "u1",
            source: "ual",
            tenant: Some("contoso"),
            actor: Some("jdoe@contoso.example"),
            ip: Some(IP),
            prefix: Some("203.0.113.0/24"),
            asn: Some(64500),
            session: Some(SESSION_S),
            ..Ev::default()
        },
        Ev {
            table: "ual_events",
            key: "u2",
            source: "ual",
            tenant: Some("contoso"),
            actor: Some("jdoe@contoso.example"),
            ip: Some(IP),
            prefix: Some("203.0.113.0/24"),
            asn: Some(64500),
            session: Some(SESSION_T),
            ..Ev::default()
        },
        Ev {
            table: "ual_events",
            key: "u3",
            source: "ual",
            tenant: Some("fabrikam"),
            actor: Some("other@fabrikam.example"),
            ip: Some("203.0.113.46"),
            prefix: Some("203.0.113.0/24"),
            asn: Some(64500),
            device: Some(DEVICE),
            ..Ev::default()
        },
        Ev {
            table: "signins",
            key: "s1",
            source: "signin_interactive",
            tenant: Some("contoso"),
            actor: Some("jdoe@contoso.example"),
            ip: Some("2001:db8:abcd::1"),
            prefix: Some("2001:db8:abcd::/48"),
            session: Some(SESSION_S),
            ..Ev::default()
        },
        Ev {
            table: "mail_items_accessed",
            key: "m1",
            source: "mail_items_accessed",
            tenant: Some("contoso"),
            actor: Some("bob@contoso.example"),
            owner: Some("bob@contoso.example"),
            ..Ev::default()
        },
        Ev {
            table: "message_trace",
            key: "t1",
            source: "message_trace",
            tenant: Some("contoso"),
            actor: Some("sender@ext.example"),
            owner: Some("jdoe@contoso.example"),
            ip: Some("203.0.113.47"),
            prefix: Some("203.0.113.0/24"),
            ..Ev::default()
        },
    ];
    for (i, e) in rows.iter().enumerate() {
        put(&case, i as i64, e);
    }
    case
}

fn all_rows(case: &Case) -> Vec<EventRow> {
    events::page(case.conn(), &EventQuery::default(), None, 0, 500)
        .unwrap()
        .rows
}

/// `record_key -> effective flag` of every row.
fn flags(case: &Case) -> Vec<(String, Option<FlagLevel>)> {
    let mut v: Vec<_> = all_rows(case)
        .into_iter()
        .map(|r| (r.record_key, r.flag))
        .collect();
    v.sort();
    v
}

fn flagged(case: &Case) -> Vec<(String, FlagLevel)> {
    flags(case)
        .into_iter()
        .filter_map(|(k, f)| f.map(|f| (k, f)))
        .collect()
}

fn row(case: &Case, key: &str) -> EventRow {
    all_rows(case)
        .into_iter()
        .find(|r| r.record_key == key)
        .unwrap()
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn audits(case: &Case, object_type: &str) -> Vec<AuditEntry> {
    audit::log(case.conn(), None)
        .unwrap()
        .into_iter()
        .filter(|e| e.object_type == object_type)
        .collect()
}

fn audit_total(case: &Case) -> usize {
    audit::log(case.conn(), None).unwrap().len()
}

fn keys(case: &Case, q: &EventQuery) -> Vec<String> {
    let mut k: Vec<String> = events::page(case.conn(), q, None, 0, 500)
        .unwrap()
        .rows
        .into_iter()
        .map(|r| r.record_key)
        .collect();
    k.sort();
    k
}

fn sorted(keys: &[&str]) -> Vec<String> {
    let mut k: Vec<String> = keys.iter().map(|k| k.to_string()).collect();
    k.sort();
    k
}

/// Every `case_indicators` row: (tenant, type, value, verdict, review_state).
type IndicatorRow = (Option<String>, String, String, String, Option<String>);

fn indicator_rows(case: &Case) -> Vec<IndicatorRow> {
    let mut stmt = case
        .conn()
        .prepare(
            "SELECT tenant_key, CAST(type AS VARCHAR), value, CAST(verdict AS VARCHAR), CAST(review_state AS VARCHAR) \
             FROM case_indicators WHERE removed_at IS NULL ORDER BY type, value, tenant_key",
        )
        .unwrap();
    stmt.query_map([], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
    })
    .unwrap()
    .map(|r| r.unwrap())
    .collect()
}

// ---------------------------------------------------------------------------------------------------------------

#[test]
fn row_flag_set_change_clear_audited_once() {
    let case = events_case();
    let c = case.conn();
    let three = [
        r("ual_events", "u1"),
        r("ual_events", "u2"),
        r("ual_events", "u3"),
    ];
    assert_eq!(audit_total(&case), 0);

    // Set: 3 rows, 1 audit row.
    let e = flag_rows(c, &analyst(), &three, Some(FlagLevel::Suspicious)).unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM event_flags"), 3);
    assert_eq!(audit_total(&case), 1);
    assert_eq!(
        (e.action.as_str(), e.object_type.as_str(), e.actor.as_str()),
        ("flag_rows", "event_flag", "analyst:carlos")
    );
    assert_eq!(e.before, None);
    let after = e.after.clone().unwrap();
    assert_eq!(after["level"], "suspicious");
    assert_eq!(
        after["rows"],
        json!([
            ["ual_events", "u1"],
            ["ual_events", "u2"],
            ["ual_events", "u3"]
        ])
    );
    // An analyst's flag is accepted, reviewed by themselves when made, and carries the batch the audit row names.
    let (state, by, reviewed_by, batch): (String, String, String, String) = c
        .query_row(
            "SELECT CAST(review_state AS VARCHAR), decided_by, reviewed_by, batch_id FROM event_flags LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        (
            state.as_str(),
            by.as_str(),
            reviewed_by.as_str(),
            batch.as_str()
        ),
        (
            "accepted",
            "analyst:carlos",
            "analyst:carlos",
            e.object_id.as_str()
        )
    );
    assert_eq!(
        flagged(&case),
        vec![
            ("u1".to_string(), FlagLevel::Suspicious),
            ("u2".to_string(), FlagLevel::Suspicious),
            ("u3".to_string(), FlagLevel::Suspicious)
        ]
    );

    // Change two of them: still one row per event, one more audit row, the prior levels in `before`.
    let e = flag_rows(c, &analyst(), &three[..2], Some(FlagLevel::Malicious)).unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM event_flags"), 3);
    assert_eq!(audit_total(&case), 2);
    let before = e.before.unwrap();
    assert_eq!(before["marks"].as_array().unwrap().len(), 2);
    assert!(
        before["marks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["level"] == "suspicious")
    );
    assert_eq!(
        flagged(&case),
        vec![
            ("u1".to_string(), FlagLevel::Malicious),
            ("u2".to_string(), FlagLevel::Malicious),
            ("u3".to_string(), FlagLevel::Suspicious)
        ]
    );

    // Setting what is already set (and confirmed) changes nothing and is refused, with no audit row.
    let err = flag_rows(c, &analyst(), &three[..2], Some(FlagLevel::Malicious)).unwrap_err();
    assert!(matches!(err, Error::Decision(_)), "{err:?}");
    assert_eq!(audit_total(&case), 2);

    // Clear all three: the rows go, and `before` keeps what was removed.
    let e = flag_rows(c, &analyst(), &three, None).unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM event_flags"), 0);
    assert_eq!(audit_total(&case), 3);
    let removed: Vec<(String, String)> = e.before.unwrap()["marks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                m["record_key"].as_str().unwrap().to_string(),
                m["level"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        removed,
        vec![
            ("u1".to_string(), "malicious".to_string()),
            ("u2".to_string(), "malicious".to_string()),
            ("u3".to_string(), "suspicious".to_string())
        ]
    );
    assert_eq!(e.after.unwrap()["level"], Value::Null);
    assert!(flagged(&case).is_empty());

    // Clearing rows that carry no flag, an unknown row and no rows at all are refused and write nothing.
    assert!(matches!(
        flag_rows(c, &analyst(), &three, None),
        Err(Error::Decision(_))
    ));
    assert!(matches!(
        flag_rows(c, &analyst(), &[r("ual_events", "nope")], Some(FlagLevel::Suspicious)),
        Err(Error::Decision(m)) if m.contains("unknown event ual_events:nope")
    ));
    assert!(matches!(
        flag_rows(c, &analyst(), &[], Some(FlagLevel::Suspicious)),
        Err(Error::Invalid(_))
    ));
    assert_eq!(audit_total(&case), 3);
    assert_eq!(count(&case, "SELECT count(*) FROM event_flags"), 0);
}

fn ingest_purview(case: &mut Case, rows: &[Value]) {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("exports");
    let text = ual::PURVIEW_HEADER.to_string()
        + &rows
            .iter()
            .map(|a| ual::purview_row("2026-09-01T10:00:00.0000000Z", a))
            .collect::<String>();
    sparrow_core::fixtures::write(
        &root,
        &format!(
            "9b2e6f1a-3c4d-4e5f-8a9b-{:012}.csv",
            NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ),
        text.as_bytes(),
    );
    let report = ingest_path(
        case,
        dir.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    assert!(!report.has_errors(), "{report:#?}");
}

fn login_from(id: &str, ip: &str) -> Value {
    let mut v = ual::login();
    v["Id"] = json!(id);
    v["ClientIP"] = json!(ip);
    v
}

const LOGIN_1: &str = "c0000001-0000-4000-8000-000000000001";
const LOGIN_2: &str = "c0000002-0000-4000-8000-000000000002";
const LOGIN_3: &str = "c0000003-0000-4000-8000-000000000003";

#[test]
fn value_flag_covers_later_ingest() {
    let mut case = Case::in_memory().unwrap();
    ingest_purview(
        &mut case,
        &[login_from(LOGIN_1, IP), login_from(LOGIN_2, "203.0.113.99")],
    );
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM events"), 2);
    assert!(flagged(&case).is_empty());

    flag_value(
        case.conn(),
        &analyst(),
        ValueKind::Ip,
        IP,
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    assert_eq!(
        flagged(&case),
        vec![(LOGIN_1.to_string(), FlagLevel::Malicious)]
    );

    // More evidence with the same IP arrives, in the other spelling a log may use; nothing is re-flagged by hand.
    ingest_purview(&mut case, &[login_from(LOGIN_3, "203.0.113.45")]);
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM events"), 3);
    assert_eq!(count(&case, "SELECT count(*) FROM value_flags"), 1);
    assert_eq!(count(&case, "SELECT count(*) FROM event_flags"), 0);
    assert_eq!(
        flagged(&case),
        vec![
            (LOGIN_1.to_string(), FlagLevel::Malicious),
            (LOGIN_3.to_string(), FlagLevel::Malicious)
        ]
    );
    // The summary and the toggle count the covered rows.
    let q = EventQuery::default();
    let s = events::summary(case.conn(), &q).unwrap();
    assert_eq!((s.total, s.suspicious, s.malicious), (3, 0, 2));
    let q = EventQuery {
        flag: FlagFilter::Malicious,
        ..EventQuery::default()
    };
    assert_eq!(keys(&case, &q), sorted(&[LOGIN_1, LOGIN_3]));
}

#[test]
fn scoped_value_flag_only_inside_entity() {
    let case = events_case();
    // The IP flagged inside session S: u1 is in S, u2 has the same IP in session T.
    flag_value(
        case.conn(),
        &analyst(),
        ValueKind::Ip,
        IP,
        Some(&Entity::Session(SESSION_S.to_uppercase())),
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    assert_eq!(
        flagged(&case),
        vec![("u1".to_string(), FlagLevel::Suspicious)]
    );
    let (kind, value): (String, String) = case
        .conn()
        .query_row("SELECT scope_kind, scope_value FROM value_flags", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((kind.as_str(), value.as_str()), ("session", SESSION_S));

    // The same IP flagged case-wide is a different flag and covers both.
    flag_value(
        case.conn(),
        &analyst(),
        ValueKind::Ip,
        IP,
        None,
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM value_flags"), 2);
    assert_eq!(
        flagged(&case),
        vec![
            ("u1".to_string(), FlagLevel::Suspicious),
            ("u2".to_string(), FlagLevel::Suspicious)
        ]
    );

    // A scope by account uses the entity rule: actor OR mailbox owner. jdoe owns the mailbox of t1.
    flag_value(
        case.conn(),
        &analyst(),
        ValueKind::Ip,
        "203.0.113.47",
        Some(&Entity::Account("JDoe@Contoso.Example".into())),
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    assert_eq!(row(&case, "t1").flag, Some(FlagLevel::Malicious));
    // And a scope the row is not in leaves it alone.
    flag_value(
        case.conn(),
        &analyst(),
        ValueKind::Ip,
        "203.0.113.46",
        Some(&Entity::Account("bob@contoso.example".into())),
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    assert_eq!(row(&case, "u3").flag, None);
}

#[test]
fn strongest_flag_wins_and_clearing_value_keeps_row_flag() {
    let case = events_case();
    let c = case.conn();
    flag_rows(
        c,
        &analyst(),
        &[r("ual_events", "u1")],
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    flag_value(
        c,
        &analyst(),
        ValueKind::Ip,
        IP,
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    flag_value(
        c,
        &analyst(),
        ValueKind::Account,
        "jdoe@contoso.example",
        None,
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    // u1: own suspicious + malicious IP + suspicious account -> malicious. u2: malicious IP. s1: suspicious account.
    // t1: jdoe owns its mailbox -> suspicious. u3 has a different IP.
    assert_eq!(
        flagged(&case),
        vec![
            ("s1".to_string(), FlagLevel::Suspicious),
            ("t1".to_string(), FlagLevel::Suspicious),
            ("u1".to_string(), FlagLevel::Malicious),
            ("u2".to_string(), FlagLevel::Malicious)
        ]
    );
    let s = events::summary(c, &EventQuery::default()).unwrap();
    assert_eq!((s.suspicious, s.malicious), (2, 2));

    // Clearing the value flags leaves the direct row flag alone.
    flag_value(c, &analyst(), ValueKind::Ip, IP, None, None).unwrap();
    assert_eq!(
        flagged(&case),
        vec![
            ("s1".to_string(), FlagLevel::Suspicious),
            ("t1".to_string(), FlagLevel::Suspicious),
            ("u1".to_string(), FlagLevel::Suspicious),
            ("u2".to_string(), FlagLevel::Suspicious)
        ]
    );
    flag_value(
        c,
        &analyst(),
        ValueKind::Account,
        "jdoe@contoso.example",
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        flagged(&case),
        vec![("u1".to_string(), FlagLevel::Suspicious)]
    );
    assert_eq!(count(&case, "SELECT count(*) FROM event_flags"), 1);
    // The cleared flags are kept, soft-removed.
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM value_flags WHERE removed_at IS NOT NULL"
        ),
        2
    );
    // Clearing what is not flagged is refused; flagging it again brings the same row back.
    assert!(matches!(
        flag_value(c, &analyst(), ValueKind::Ip, IP, None, None),
        Err(Error::Decision(_))
    ));
    flag_value(
        c,
        &analyst(),
        ValueKind::Ip,
        IP,
        None,
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM value_flags"), 2);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM value_flags WHERE removed_at IS NULL"
        ),
        1
    );
    assert_eq!(row(&case, "u2").flag, Some(FlagLevel::Suspicious));
}

#[test]
fn ip_prefix_flag_v4_and_v6() {
    let case = events_case();
    let c = case.conn();
    // Any spelling of the /24 (an address in it, or its network text) is the same flag.
    flag_value(
        c,
        &analyst(),
        ValueKind::IpPrefix,
        "203.0.113.200",
        None,
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    flag_value(
        c,
        &analyst(),
        ValueKind::IpPrefix,
        "203.0.113.0/24",
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM value_flags"), 1);
    let (value, level): (String, String) = c
        .query_row(
            "SELECT value, CAST(level AS VARCHAR) FROM value_flags",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (value.as_str(), level.as_str()),
        ("203.0.113.0/24", "malicious")
    );
    assert_eq!(
        flagged(&case),
        vec![
            ("t1".to_string(), FlagLevel::Malicious),
            ("u1".to_string(), FlagLevel::Malicious),
            ("u2".to_string(), FlagLevel::Malicious),
            ("u3".to_string(), FlagLevel::Malicious)
        ]
    );
    // IPv6: a /48, in any spelling of an address inside it.
    flag_value(
        c,
        &analyst(),
        ValueKind::IpPrefix,
        "2001:DB8:ABCD:12::1",
        None,
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    let v6: String = c
        .query_row(
            "SELECT value FROM value_flags WHERE value LIKE '2001%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(v6, "2001:db8:abcd::/48");
    assert_eq!(row(&case, "s1").flag, Some(FlagLevel::Suspicious));
    // Not an address: refused.
    assert!(matches!(
        flag_value(
            c,
            &analyst(),
            ValueKind::IpPrefix,
            "not an ip",
            None,
            Some(FlagLevel::Suspicious)
        ),
        Err(Error::Invalid(_))
    ));
    // A prefix flag makes no indicator.
    assert!(indicator_rows(&case).is_empty());
}

#[test]
fn malicious_ip_and_account_create_indicators_suspicious_does_not() {
    let case = events_case();
    let c = case.conn();
    // Suspicious on an IP and on an account: no indicator.
    flag_value(
        c,
        &analyst(),
        ValueKind::Ip,
        IP,
        None,
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    flag_value(
        c,
        &analyst(),
        ValueKind::Account,
        "jdoe@contoso.example",
        None,
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    assert!(indicator_rows(&case).is_empty());

    // Malicious on the IP (all its events are in tenant contoso) and on the account (jdoe: contoso only).
    flag_value(
        c,
        &analyst(),
        ValueKind::Ip,
        IP,
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    flag_value(
        c,
        &analyst(),
        ValueKind::Account,
        "JDoe@Contoso.Example",
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    assert_eq!(
        indicator_rows(&case),
        vec![
            (
                Some("contoso".to_string()),
                "ip".to_string(),
                IP.to_string(),
                "malicious".to_string(),
                Some("accepted".to_string())
            ),
            (
                Some("contoso".to_string()),
                "upn".to_string(),
                "jdoe@contoso.example".to_string(),
                "malicious".to_string(),
                Some("accepted".to_string())
            )
        ]
    );
    // Each flag action is one audit row of its own, next to the add_ioc rows of the indicators it made.
    let actions: Vec<(String, String)> = audit::log(c, None)
        .unwrap()
        .into_iter()
        .map(|e| (e.action, e.object_type))
        .collect();
    assert_eq!(
        actions,
        vec![
            ("flag_value".to_string(), "value_flag".to_string()),
            ("flag_value".to_string(), "value_flag".to_string()),
            ("add_ioc".to_string(), "indicator".to_string()),
            ("flag_value".to_string(), "value_flag".to_string()),
            ("add_ioc".to_string(), "indicator".to_string()),
            ("flag_value".to_string(), "value_flag".to_string()),
        ]
    );

    // An IP seen in two tenants makes one indicator per tenant; an event with no tenant makes a case-wide one.
    let shared = "198.51.100.7";
    for (i, (key, tenant)) in [
        ("x1", Some("contoso")),
        ("x2", Some("fabrikam")),
        ("x3", None),
    ]
    .into_iter()
    .enumerate()
    {
        put(
            &case,
            10 + i as i64,
            &Ev {
                table: "ual_events",
                key,
                source: "ual",
                tenant,
                ip: Some(shared),
                ..Ev::default()
            },
        );
    }
    flag_value(
        c,
        &analyst(),
        ValueKind::Ip,
        shared,
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    let ips: Vec<_> = indicator_rows(&case)
        .into_iter()
        .filter(|i| i.1 == "ip" && i.2 == shared)
        .collect();
    assert_eq!(
        ips.iter().map(|i| i.0.clone()).collect::<Vec<_>>(),
        vec![
            Some("contoso".to_string()),
            Some("fabrikam".to_string()),
            None
        ]
    );

    // Clearing a flag never removes an indicator.
    let before = indicator_rows(&case);
    flag_value(c, &analyst(), ValueKind::Ip, IP, None, None).unwrap();
    flag_value(
        c,
        &analyst(),
        ValueKind::Account,
        "jdoe@contoso.example",
        None,
        None,
    )
    .unwrap();
    assert_eq!(indicator_rows(&case), before);
    // Flagging an indicator's value malicious again (after a clear) keeps one indicator, not two.
    flag_value(
        c,
        &analyst(),
        ValueKind::Ip,
        IP,
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    assert_eq!(indicator_rows(&case), before);
}

#[test]
fn asn_device_session_flags_make_no_indicator() {
    let case = events_case();
    let c = case.conn();
    flag_value(
        c,
        &analyst(),
        ValueKind::Asn,
        "AS64500",
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    flag_value(
        c,
        &analyst(),
        ValueKind::Device,
        &DEVICE.to_uppercase(),
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    flag_value(
        c,
        &analyst(),
        ValueKind::Session,
        &SESSION_S.to_uppercase(),
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM case_indicators"), 0);
    assert!(audits(&case, "indicator").is_empty());
    // They still flag: AS 64500 is u1, u2 and u3; the device is u3; session S is u1 and s1.
    assert_eq!(
        flagged(&case),
        vec![
            ("s1".to_string(), FlagLevel::Malicious),
            ("u1".to_string(), FlagLevel::Malicious),
            ("u2".to_string(), FlagLevel::Malicious),
            ("u3".to_string(), FlagLevel::Malicious)
        ]
    );
    let values: Vec<(String, String)> = {
        let mut stmt = c
            .prepare("SELECT CAST(kind AS VARCHAR), value FROM value_flags ORDER BY 1")
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    };
    assert_eq!(
        values,
        vec![
            ("asn".to_string(), "64500".to_string()),
            ("device".to_string(), DEVICE.to_string()),
            ("session".to_string(), SESSION_S.to_string())
        ]
    );
}

#[test]
fn agent_marks_pending_then_confirm_or_discard_and_revert() {
    let case = events_case();
    let c = case.conn();
    let rev = reviewer();

    // The analyst's own Suspicious flag on s1 (accepted) is the state the agent will change.
    flag_rows(
        c,
        &analyst(),
        &[r("signins", "s1")],
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    let a = agent();
    let e_flags = flag_rows(
        c,
        &a,
        &[
            r("ual_events", "u1"),
            r("ual_events", "u2"),
            r("ual_events", "u3"),
            r("signins", "s1"),
        ],
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    let e_tags = tag_rows(
        c,
        &a,
        &[r("ual_events", "u1"), r("ual_events", "u2")],
        "ai:phish",
        true,
    )
    .unwrap();
    let state = |t: &str, k: &str| -> (String, String, Option<String>) {
        c.query_row(
            &format!(
                "SELECT CAST(level AS VARCHAR), CAST(review_state AS VARCHAR), on_behalf_of FROM event_flags \
                 WHERE source_table = '{t}' AND record_key = '{k}'"
            ),
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
    };
    // Pending, on behalf of the named analyst; the changed flag keeps its analyst-made state in the audit entry.
    assert_eq!(
        state("ual_events", "u1"),
        (
            "malicious".into(),
            "pending_review".into(),
            Some("analyst:carlos".into())
        )
    );
    assert_eq!(state("signins", "s1").1, "pending_review");
    assert_eq!(e_flags.actor, "agent:triage");
    let prior = &e_flags.before.as_ref().unwrap()["marks"];
    assert_eq!(prior.as_array().unwrap().len(), 1);
    assert_eq!(
        (
            prior[0]["record_key"].as_str(),
            prior[0]["level"].as_str(),
            prior[0]["review_state"].as_str()
        ),
        (Some("s1"), Some("suspicious"), Some("accepted"))
    );
    // The grid shows them as the agent's: AI flag, AI tags.
    let u1 = row(&case, "u1");
    assert_eq!((u1.flag, u1.flag_ai), (Some(FlagLevel::Malicious), true));
    assert_eq!(
        u1.tags
            .iter()
            .map(|t| (t.name.as_str(), t.ai))
            .collect::<Vec<_>>(),
        [("ai:phish", true)]
    );

    // An agent value flag over the IP of u1 and u2, with the indicator it makes (pending, as the agent's).
    let e_value = flag_value(c, &a, ValueKind::Ip, IP, None, Some(FlagLevel::Malicious)).unwrap();
    assert_eq!(
        indicator_rows(&case),
        vec![(
            Some("contoso".to_string()),
            "ip".to_string(),
            IP.to_string(),
            "malicious".to_string(),
            Some("pending_review".to_string())
        )]
    );
    // The filters: marked and unreviewed see u1, u2 (flag, tag, value), u3 and s1 (flags); m1, t1 have no agent mark.
    for ai in [AiFilter::Marked, AiFilter::Unreviewed] {
        let q = EventQuery {
            ai,
            ..EventQuery::default()
        };
        assert_eq!(keys(&case, &q), sorted(&["s1", "u1", "u2", "u3"]), "{ai:?}");
    }

    // An agent cannot confirm: review takes a Reviewer. Only the pending marks of the selection are reviewed:
    // u1's flag, u1's tag, and the value flag that covers u1. u2 and u3 stay pending.
    let done = review_marks(c, &rev, &[r("ual_events", "u1")], true).unwrap();
    let kinds: Vec<(&str, &str)> = done
        .iter()
        .map(|e| (e.action.as_str(), e.object_type.as_str()))
        .collect();
    assert_eq!(
        kinds,
        [
            ("review_accept", "event_flag"),
            ("review_accept", "event_tag"),
            ("review_accept", "value_flag")
        ]
    );
    assert!(done.iter().all(|e| e.actor == "analyst:carlos"));
    assert_eq!(done[0].after.as_ref().unwrap()["decision_seq"], e_flags.seq);
    assert_eq!(
        done[0].after.as_ref().unwrap()["rows"],
        json!([["ual_events", "u1"]])
    );
    assert_eq!(done[1].after.as_ref().unwrap()["decision_seq"], e_tags.seq);
    assert_eq!(done[2].after.as_ref().unwrap()["decision_seq"], e_value.seq);
    assert_eq!(state("ual_events", "u1").1, "accepted");
    assert_eq!(state("ual_events", "u2").1, "pending_review");
    let (rs, rb): (String, String) = c
        .query_row(
            "SELECT CAST(review_state AS VARCHAR), reviewed_by FROM value_flags",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((rs.as_str(), rb.as_str()), ("accepted", "analyst:carlos"));
    let u1 = row(&case, "u1");
    assert!(!u1.flag_ai);
    assert!(u1.tags.iter().all(|t| !t.ai));
    // Reviewing the same row again finds nothing pending.
    assert!(
        review_marks(c, &rev, &[r("ual_events", "u1")], true)
            .unwrap()
            .is_empty()
    );

    // Remove the rest: u2's flag and tag go, u3's flag goes, s1's flag is put back to the analyst's Suspicious.
    let done = review_marks(
        c,
        &rev,
        &[
            r("ual_events", "u2"),
            r("ual_events", "u3"),
            r("signins", "s1"),
        ],
        false,
    )
    .unwrap();
    let kinds: Vec<(&str, &str)> = done
        .iter()
        .map(|e| (e.action.as_str(), e.object_type.as_str()))
        .collect();
    // One audit row per decision touched: the one flag call (u2, u3, s1) and the one tag call (u2). The value flag was
    // already reviewed.
    assert_eq!(
        kinds,
        [
            ("review_discard", "event_flag"),
            ("review_discard", "event_tag")
        ]
    );
    let restored = &done[0].after.as_ref().unwrap()["restored"];
    assert_eq!(
        restored["removed"],
        json!([["ual_events", "u2"], ["ual_events", "u3"]])
    );
    assert_eq!(
        restored["restored"],
        json!([["signins", "s1", "suspicious"]])
    );
    assert_eq!(done[0].after.as_ref().unwrap()["decision_seq"], e_flags.seq);
    assert_eq!(
        count(&case, "SELECT count(*) FROM event_flags"),
        2,
        "u1 (confirmed) and s1 (restored)"
    );
    let s1 = c
        .query_row(
            "SELECT CAST(level AS VARCHAR), decided_by, CAST(review_state AS VARCHAR) FROM event_flags WHERE record_key = 's1'",
            [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
        )
        .unwrap();
    assert_eq!(
        s1,
        (
            "suspicious".to_string(),
            "analyst:carlos".to_string(),
            "accepted".to_string()
        )
    );
    assert_eq!(
        count(&case, "SELECT count(*) FROM event_tags"),
        1,
        "only u1's tag is left"
    );
    assert_eq!(
        list_tags(c).unwrap(),
        vec![marks::TagInfo {
            name: "ai:phish".into(),
            count: 1,
            agent_unreviewed: 0
        }]
    );
    // The audit trail keeps the history: both agent decisions and all the reviews are there.
    assert_eq!(
        audits(&case, "event_flag").len(),
        1 + 1 + 1 + 1,
        "analyst flag, agent flag, accept, discard"
    );

    // A discard of an agent value flag soft-removes it; its indicator is a separate decision and stays.
    let e2 = flag_value(
        c,
        &a,
        ValueKind::Account,
        "other@fabrikam.example",
        None,
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    assert_eq!(row(&case, "u3").flag, Some(FlagLevel::Suspicious));
    let d = review::review_discard(
        c,
        &rev,
        "value_flag",
        &e2.object_id,
        e2.seq,
        Some("not related"),
    )
    .unwrap();
    assert_eq!(d.action, "review_discard");
    assert_eq!(row(&case, "u3").flag, None);
    let (removed, by, st): (bool, String, String) = c
        .query_row(
            "SELECT removed_at IS NOT NULL, removed_by, CAST(review_state AS VARCHAR) FROM value_flags WHERE flag_id = ?",
            [&e2.object_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (removed, by.as_str(), st.as_str()),
        (true, "analyst:carlos", "discarded")
    );
    assert_eq!(indicator_rows(&case).len(), 1);

    // An agent that changes an analyst's value flag is undone to the analyst's level.
    flag_value(
        c,
        &analyst(),
        ValueKind::Device,
        DEVICE,
        None,
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    let e3 = flag_value(
        c,
        &a,
        ValueKind::Device,
        DEVICE,
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    assert_eq!(row(&case, "u3").flag, Some(FlagLevel::Malicious));
    review::review_discard(c, &rev, "value_flag", &e3.object_id, e3.seq, None).unwrap();
    assert_eq!(row(&case, "u3").flag, Some(FlagLevel::Suspicious));

    // A review must name the latest decision: the first agent flag call is long superseded for u1 only by review, but a
    // stale seq on a value flag is refused.
    let stale = review::review_accept(c, &rev, "value_flag", &e3.object_id, e3.seq - 1, None);
    assert!(matches!(stale, Err(Error::Decision(_))), "{stale:?}");
}

#[test]
fn agent_clears_only_its_own_pending_marks() {
    let case = events_case();
    let c = case.conn();
    let a = agent();
    flag_rows(
        c,
        &analyst(),
        &[r("ual_events", "u1")],
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    flag_rows(c, &a, &[r("ual_events", "u2")], Some(FlagLevel::Suspicious)).unwrap();
    // An analyst's flag, and a mix with one, are refused for the agent and nothing is removed.
    let n = audit_total(&case);
    assert!(matches!(
        flag_rows(c, &a, &[r("ual_events", "u1")], None),
        Err(Error::Decision(_))
    ));
    assert!(matches!(
        flag_rows(c, &a, &[r("ual_events", "u1"), r("ual_events", "u2")], None),
        Err(Error::Decision(_))
    ));
    assert_eq!(count(&case, "SELECT count(*) FROM event_flags"), 2);
    assert_eq!(audit_total(&case), n);
    // Its own pending flag goes.
    flag_rows(c, &a, &[r("ual_events", "u2")], None).unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM event_flags"), 1);
    // Another agent's pending flag is not its own.
    flag_rows(c, &a, &[r("ual_events", "u3")], Some(FlagLevel::Suspicious)).unwrap();
    let other = Actor::agent("other", None).unwrap();
    assert!(matches!(
        flag_rows(c, &other, &[r("ual_events", "u3")], None),
        Err(Error::Decision(_))
    ));
    // The same for tags.
    tag_rows(c, &analyst(), &[r("ual_events", "u1")], "persistence", true).unwrap();
    tag_rows(c, &a, &[r("ual_events", "u2")], "ai:x", true).unwrap();
    assert!(matches!(
        tag_rows(c, &a, &[r("ual_events", "u1")], "persistence", false),
        Err(Error::Decision(_))
    ));
    tag_rows(c, &a, &[r("ual_events", "u2")], "ai:x", false).unwrap();
    assert_eq!(
        list_tags(c)
            .unwrap()
            .iter()
            .map(|t| t.name.as_str())
            .collect::<Vec<_>>(),
        ["persistence"]
    );
    // An analyst replaces an agent's pending flag and confirms an agent's pending tag by applying it.
    tag_rows(c, &a, &[r("ual_events", "u3")], "persistence", true).unwrap();
    assert_eq!(list_tags(c).unwrap()[0].agent_unreviewed, 1);
    flag_rows(
        c,
        &analyst(),
        &[r("ual_events", "u3")],
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    tag_rows(c, &analyst(), &[r("ual_events", "u3")], "persistence", true).unwrap();
    assert_eq!(
        list_tags(c).unwrap(),
        vec![marks::TagInfo {
            name: "persistence".into(),
            count: 2,
            agent_unreviewed: 0
        }]
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM event_flags WHERE review_state = 'pending_review'"
        ),
        0
    );
}

#[test]
fn agent_marks_are_not_review_queue_items() {
    let case = events_case();
    let c = case.conn();
    let a = agent();
    assert!(review::pending(c).unwrap().is_empty());
    flag_rows(c, &a, &[r("ual_events", "u1")], Some(FlagLevel::Malicious)).unwrap();
    tag_rows(
        c,
        &a,
        &[r("ual_events", "u1"), r("ual_events", "u2")],
        "ai:phish",
        true,
    )
    .unwrap();
    flag_value(
        c,
        &a,
        ValueKind::Asn,
        "64500",
        None,
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    flag_value(
        c,
        &a,
        ValueKind::Session,
        SESSION_S,
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    // Four pending agent decisions on marks, none in the queue (and so none in its badge).
    assert_eq!(
        count(
            &case,
            "SELECT (SELECT count(*) FROM event_flags WHERE review_state = 'pending_review') \
                  + (SELECT count(*) FROM event_tags WHERE review_state = 'pending_review') \
                  + (SELECT count(*) FROM value_flags WHERE review_state = 'pending_review')"
        ),
        1 + 2 + 2
    );
    assert!(review::pending(c).unwrap().is_empty());
    // An agent's malicious flag on an IP is a Review-queue item because of its indicator, and only that.
    flag_value(c, &a, ValueKind::Ip, IP, None, Some(FlagLevel::Malicious)).unwrap();
    let queue = review::pending(c).unwrap();
    assert_eq!(
        queue
            .iter()
            .map(|p| (p.object_type.as_str(), p.title.as_str()))
            .collect::<Vec<_>>(),
        [("indicator", "ip 203.0.113.45")]
    );
    // Reviewing the indicator is its own decision.
    assert_eq!(
        indicators::list_indicators(c, None, false).unwrap().len(),
        1
    );
}

#[test]
fn agent_tag_rules() {
    let case = events_case();
    let c = case.conn();
    let a = agent();
    let rows = [r("ual_events", "u1")];
    // ai: is allowed, whatever its case.
    tag_rows(c, &a, &rows, " AI:Phish ", true).unwrap();
    assert_eq!(list_tags(c).unwrap()[0].name, "ai:phish");
    // A new plain tag is refused, with nothing written and no audit row.
    let n = audit_total(&case);
    let err = tag_rows(c, &a, &rows, "foo", true).unwrap_err();
    assert!(
        matches!(err, Error::Decision(ref m) if m.contains("ai:")),
        "{err:?}"
    );
    assert_eq!(audit_total(&case), n);
    assert_eq!(
        count(&case, "SELECT count(*) FROM tags WHERE name = 'foo'"),
        0
    );
    // An existing tag may be used: the analyst made `persistence` on another row.
    tag_rows(c, &analyst(), &[r("ual_events", "u2")], "Persistence", true).unwrap();
    tag_rows(c, &a, &rows, "persistence", true).unwrap();
    assert_eq!(
        list_tags(c).unwrap(),
        vec![
            marks::TagInfo {
                name: "ai:phish".into(),
                count: 1,
                agent_unreviewed: 1
            },
            marks::TagInfo {
                name: "persistence".into(),
                count: 2,
                agent_unreviewed: 1
            },
        ]
    );
    // The analyst may create any name. Names are 1 to 64 characters without control characters.
    tag_rows(c, &analyst(), &rows, "foo", true).unwrap();
    for bad in ["", "   ", &"x".repeat(65), "a\nb", "a\u{7}b"] {
        assert!(
            matches!(
                tag_rows(c, &analyst(), &rows, bad, true),
                Err(Error::Invalid(_))
            ),
            "{bad:?}"
        );
    }
    tag_rows(c, &analyst(), &rows, &"x".repeat(64), true).unwrap();
    // Adding what a row already carries fails; so does removing what it does not.
    assert!(matches!(
        tag_rows(c, &analyst(), &rows, "foo", true),
        Err(Error::Decision(_))
    ));
    assert!(matches!(
        tag_rows(c, &analyst(), &[r("ual_events", "u3")], "foo", false),
        Err(Error::Decision(_))
    ));
    // Removing the last use of a name drops the name.
    tag_rows(c, &analyst(), &rows, "foo", false).unwrap();
    assert!(list_tags(c).unwrap().iter().all(|t| t.name != "foo"));
}

#[test]
fn flag_tag_and_agent_filters_with_suggest_and_csv() {
    let case = events_case();
    let c = case.conn();
    flag_rows(
        c,
        &analyst(),
        &[r("ual_events", "u1"), r("ual_events", "u2")],
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    flag_rows(
        c,
        &analyst(),
        &[r("ual_events", "u2"), r("signins", "s1")],
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    flag_value(
        c,
        &analyst(),
        ValueKind::Account,
        "bob@contoso.example",
        None,
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    tag_rows(
        c,
        &analyst(),
        &[r("ual_events", "u1"), r("ual_events", "u3")],
        "persistence",
        true,
    )
    .unwrap();
    tag_rows(c, &analyst(), &[r("ual_events", "u1")], "exfil-test", true).unwrap();
    tag_rows(
        c,
        &agent(),
        &[r("ual_events", "u2"), r("ual_events", "u3")],
        "ai:phish",
        true,
    )
    .unwrap();
    let flag = |f| EventQuery {
        flag: f,
        ..EventQuery::default()
    };
    let tag = |t: &str| EventQuery {
        fields: vec![(Field::Tag, t.into())],
        ..EventQuery::default()
    };

    assert_eq!(
        keys(&case, &flag(FlagFilter::Suspicious)),
        sorted(&["m1", "u1"])
    );
    assert_eq!(
        keys(&case, &flag(FlagFilter::Malicious)),
        sorted(&["s1", "u2"])
    );
    assert_eq!(keys(&case, &flag(FlagFilter::All)).len(), 6);
    let s = events::summary(c, &EventQuery::default()).unwrap();
    assert_eq!((s.total, s.suspicious, s.malicious), (6, 2, 2));
    // With the toggle on, the total follows it and the two counts still describe the rest of the query.
    let s = events::summary(c, &flag(FlagFilter::Malicious)).unwrap();
    assert_eq!((s.total, s.suspicious, s.malicious), (2, 2, 2));
    assert_eq!(
        s.per_source,
        vec![
            ("ual".to_string(), 1),
            ("signin_interactive".to_string(), 1)
        ]
    );

    // Tag: exact (case-insensitive), wildcard, list, and exclusions (rows without the tag, untagged rows included).
    assert_eq!(keys(&case, &tag("persistence")), sorted(&["u1", "u3"]));
    assert_eq!(keys(&case, &tag("PERSISTENCE")), sorted(&["u1", "u3"]));
    assert_eq!(keys(&case, &tag("ai:*")), sorted(&["u2", "u3"]));
    assert_eq!(
        keys(&case, &tag("persistence, ai:phish")),
        sorted(&["u1", "u2", "u3"])
    );
    assert_eq!(
        keys(&case, &tag("*e*")),
        sorted(&["u1", "u3"]),
        "persistence, exfil-test; ai:phish has no e"
    );
    assert_eq!(
        keys(&case, &tag("!persistence")),
        sorted(&["m1", "s1", "t1", "u2"])
    );
    assert_eq!(
        keys(&case, &tag("!ai:*")),
        sorted(&["m1", "s1", "t1", "u1"])
    );
    assert_eq!(
        keys(&case, &tag("persistence, !exfil-test")),
        sorted(&["u3"])
    );
    assert_eq!(keys(&case, &tag("nothing")), Vec::<String>::new());
    // The tags column carries names in order, with the agent's marked.
    let u3 = row(&case, "u3");
    assert_eq!(
        u3.tags
            .iter()
            .map(|t| (t.name.as_str(), t.ai))
            .collect::<Vec<_>>(),
        [("ai:phish", true), ("persistence", false)]
    );
    // Autocomplete offers the tag names in use.
    assert_eq!(
        events::suggest(c, Field::Tag, "p", 10).unwrap(),
        ["persistence"]
    );
    assert_eq!(
        events::suggest(c, Field::Tag, "", 10).unwrap(),
        ["ai:phish", "exfil-test", "persistence"]
    );

    // The agent filter: marked = an agent's flag or tag (even confirmed), unreviewed = still pending.
    let ai = |a| EventQuery {
        ai: a,
        ..EventQuery::default()
    };
    assert_eq!(keys(&case, &ai(AiFilter::Marked)), sorted(&["u2", "u3"]));
    assert_eq!(
        keys(&case, &ai(AiFilter::Unreviewed)),
        sorted(&["u2", "u3"])
    );
    review_marks(c, &reviewer(), &[r("ual_events", "u3")], true).unwrap();
    assert_eq!(keys(&case, &ai(AiFilter::Marked)), sorted(&["u2", "u3"]));
    assert_eq!(keys(&case, &ai(AiFilter::Unreviewed)), sorted(&["u2"]));
    // Filters combine (AND), and the CSV carries the flag and tags.
    let q = EventQuery {
        flag: FlagFilter::Suspicious,
        fields: vec![(Field::Tag, "persistence".into())],
        ..EventQuery::default()
    };
    assert_eq!(keys(&case, &q), sorted(&["u1"]));
    let out = tempfile::tempdir().unwrap().keep().join("e.csv");
    assert_eq!(events::export_csv(c, &q, &out).unwrap(), 1);
    let text = std::fs::read_to_string(&out).unwrap();
    let line = text.lines().nth(1).unwrap();
    assert!(
        line.contains(",suspicious,exfil-test|persistence,"),
        "{line}"
    );
    // A malformed tag filter is refused like any other field.
    let q = tag("!");
    assert!(matches!(
        events::page(c, &q, None, 0, 10),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn detail_says_why_a_row_is_flagged() {
    let case = events_case();
    let c = case.conn();
    flag_rows(
        c,
        &analyst(),
        &[r("ual_events", "u1")],
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    flag_value(
        c,
        &agent(),
        ValueKind::Ip,
        IP,
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    flag_value(
        c,
        &analyst(),
        ValueKind::Session,
        SESSION_T,
        None,
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    let src = marks::flag_sources(c, "ual_events", "u1").unwrap();
    assert_eq!(
        src.iter()
            .map(|s| (
                s.origin.as_str(),
                s.level,
                s.kind.as_deref(),
                s.value.as_deref(),
                s.review_state.as_str()
            ))
            .collect::<Vec<_>>(),
        [
            (
                "value",
                FlagLevel::Malicious,
                Some("ip"),
                Some(IP),
                "pending_review"
            ),
            ("row", FlagLevel::Suspicious, None, None, "accepted")
        ]
    );
    // u2 is in session T (a case-wide suspicious flag) and has the malicious IP.
    let src = marks::flag_sources(c, "ual_events", "u2").unwrap();
    assert_eq!(src.len(), 2);
    assert_eq!(src[0].level, FlagLevel::Malicious);
    assert_eq!(src[1].value.as_deref(), Some(SESSION_T));
    assert!(
        marks::flag_sources(c, "ual_events", "u3")
            .unwrap()
            .is_empty()
    );
    // And the badge: u1's effective flag is the agent's malicious one, unconfirmed.
    let u1 = row(&case, "u1");
    assert_eq!((u1.flag, u1.flag_ai), (Some(FlagLevel::Malicious), true));
    // An analyst's own malicious flag at that level makes it confirmed.
    flag_rows(
        c,
        &analyst(),
        &[r("ual_events", "u1")],
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    assert!(!row(&case, "u1").flag_ai);
}

#[test]
fn event_detail_carries_the_flag_sources_and_tags() {
    let mut case = Case::in_memory().unwrap();
    ingest_purview(&mut case, &[login_from(LOGIN_1, IP)]);
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    let c = case.conn();
    flag_value(
        c,
        &analyst(),
        ValueKind::Ip,
        IP,
        None,
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    tag_rows(c, &agent(), &[r("ual_events", LOGIN_1)], "ai:odd", true).unwrap();
    let d = events::detail(c, "ual_events", LOGIN_1).unwrap();
    assert_eq!(d.flag, Some(FlagLevel::Suspicious));
    assert_eq!(d.flag_sources.len(), 1);
    assert_eq!(
        (
            d.flag_sources[0].origin.as_str(),
            d.flag_sources[0].value.as_deref()
        ),
        ("value", Some(IP))
    );
    assert_eq!(
        d.tags,
        vec![marks::TagRef {
            name: "ai:odd".into(),
            ai: true
        }]
    );
    assert_eq!(d.row.tags, d.tags);
}

#[test]
fn audit_lists_rows_up_to_a_thousand_then_counts_and_hashes() {
    let case = Case::in_memory().unwrap();
    let c = case.conn();
    let n = 1001;
    for i in 0..n {
        put(
            &case,
            i,
            &Ev {
                table: "ual_events",
                key: Box::leak(format!("k{i:04}").into_boxed_str()),
                source: "ual",
                ..Ev::default()
            },
        );
    }
    let all: Vec<RowRef> = (0..n)
        .rev()
        .map(|i| r("ual_events", &format!("k{i:04}")))
        .collect();
    // An analyst may flag them all in one call: one audit row, with the count and a hash of the sorted keys.
    let e = flag_rows(c, &analyst(), &all, Some(FlagLevel::Suspicious)).unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM event_flags"), 1001);
    assert_eq!(audit_total(&case), 1);
    let after = e.after.unwrap();
    let mut h = Sha256::new();
    for i in 0..n {
        h.update(format!("ual_events\x1fk{i:04}\n").as_bytes());
    }
    assert_eq!(after["row_count"], 1001);
    assert_eq!(after["rows_sha256"], hex::encode(h.finalize()));
    assert!(after.get("rows").is_none());
    // Exactly 1000 are listed.
    let thousand = &all[1..];
    let e = flag_rows(c, &analyst(), thousand, Some(FlagLevel::Malicious)).unwrap();
    assert_eq!(
        e.after.as_ref().unwrap()["rows"].as_array().unwrap().len(),
        1000
    );
    // The before of the second call (1000 replaced flags) is listed too; the first call's clear of 1001 is hashed.
    assert_eq!(e.before.unwrap()["marks"].as_array().unwrap().len(), 1000);
    let e = flag_rows(c, &analyst(), &all, None).unwrap();
    let before = e.before.unwrap();
    assert_eq!(before["mark_count"], 1001);
    assert!(before["marks_sha256"].as_str().unwrap().len() == 64);
    assert_eq!(audit_total(&case), 3);
    // An agent is limited to 1000 rows per call, because a discard restores from the audit entry.
    let err = flag_rows(c, &agent(), &all, Some(FlagLevel::Suspicious)).unwrap_err();
    assert!(
        matches!(err, Error::Invalid(ref m) if m.contains("1000")),
        "{err:?}"
    );
    assert_eq!(audit_total(&case), 3);
    assert_eq!(MAX_AGENT_ROWS, 1000);
    flag_rows(c, &agent(), thousand, Some(FlagLevel::Suspicious)).unwrap();
    // Reviewing them all removes them with one audit row.
    let done = review_marks(c, &reviewer(), &all, false).unwrap();
    assert_eq!(done.len(), 1);
    assert_eq!(count(&case, "SELECT count(*) FROM event_flags"), 0);
}

#[test]
fn marks_survive_events_rebuild() {
    let mut case = Case::in_memory().unwrap();
    ingest_purview(
        &mut case,
        &[login_from(LOGIN_1, IP), login_from(LOGIN_2, "203.0.113.99")],
    );
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    let c = case.conn();
    let me = r("ual_events", LOGIN_1);
    flag_rows(
        c,
        &analyst(),
        std::slice::from_ref(&me),
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    tag_rows(c, &analyst(), std::slice::from_ref(&me), "keep", true).unwrap();
    notes::add_note(
        c,
        &analyst(),
        NoteTarget::Evidence {
            table: "ual_events".into(),
            key: LOGIN_1.into(),
        },
        "seen from a hosting range",
    )
    .unwrap();
    flag_value(
        c,
        &analyst(),
        ValueKind::Ip,
        "203.0.113.99",
        None,
        Some(FlagLevel::Suspicious),
    )
    .unwrap();

    let check = |case: &Case| {
        let a = row(case, LOGIN_1);
        assert_eq!(a.flag, Some(FlagLevel::Malicious));
        assert_eq!(
            a.tags.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
            ["keep"]
        );
        assert_eq!(
            (a.note_count, a.latest_note.as_deref()),
            (1, Some("seen from a hosting range"))
        );
        assert_eq!(row(case, LOGIN_2).flag, Some(FlagLevel::Suspicious));
    };
    check(&case);
    // A rebuild by hand, a profile run, and a profile run after more evidence is ingested.
    events::rebuild(case.conn()).unwrap();
    check(&case);
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    check(&case);
    ingest_purview(&mut case, &[login_from(LOGIN_3, "198.51.100.1")]);
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM events"), 3);
    check(&case);
    // Ingesting the same file again changes nothing about the marks either.
    ingest_purview(&mut case, &[login_from(LOGIN_1, IP)]);
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    check(&case);
    assert_eq!(count(&case, "SELECT count(*) FROM event_flags"), 1);
    assert_eq!(count(&case, "SELECT count(*) FROM event_tags"), 1);
}

#[test]
fn value_normalization_refuses_bad_input() {
    let case = events_case();
    let c = case.conn();
    for (kind, bad) in [
        (ValueKind::Ip, "not an ip"),
        (ValueKind::Ip, ""),
        (ValueKind::Asn, "abc"),
        (ValueKind::Asn, "-5"),
        (ValueKind::Account, "   "),
        (ValueKind::Device, ""),
        (ValueKind::Session, ""),
    ] {
        let r = flag_value(c, &analyst(), kind, bad, None, Some(FlagLevel::Suspicious));
        assert!(
            matches!(r, Err(Error::Invalid(_))),
            "{kind:?} {bad:?}: {r:?}"
        );
    }
    // A scope that is not a valid entity is refused too.
    let r = flag_value(
        c,
        &analyst(),
        ValueKind::Ip,
        IP,
        Some(&Entity::Ip("nope".into())),
        Some(FlagLevel::Suspicious),
    );
    assert!(matches!(r, Err(Error::Invalid(_))));
    assert_eq!(audit_total(&case), 0);
    assert_eq!(count(&case, "SELECT count(*) FROM value_flags"), 0);
}

#[test]
fn repeating_a_confirmed_value_flag_is_refused_and_an_analyst_confirms_a_pending_one_by_flagging() {
    let case = events_case();
    let c = case.conn();
    flag_value(
        c,
        &analyst(),
        ValueKind::Asn,
        "64500",
        None,
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    let n = audit_total(&case);
    // Neither the analyst nor an agent can re-stamp a confirmed flag: an agent would turn it back into a pending one.
    for who in [analyst(), agent()] {
        let r = flag_value(
            c,
            &who,
            ValueKind::Asn,
            "AS64500",
            None,
            Some(FlagLevel::Suspicious),
        );
        assert!(
            matches!(r, Err(Error::Decision(ref m)) if m.contains("already flagged")),
            "{r:?}"
        );
    }
    assert_eq!(audit_total(&case), n);
    assert!(!row(&case, "u1").flag_ai);
    // An agent's pending flag becomes the analyst's by flagging the same value at the same level.
    flag_value(
        c,
        &agent(),
        ValueKind::Session,
        SESSION_S,
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    assert!(row(&case, "u1").flag_ai);
    flag_value(
        c,
        &analyst(),
        ValueKind::Session,
        SESSION_S,
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    assert!(!row(&case, "u1").flag_ai);
    let (by, state): (String, String) = c
        .query_row(
            "SELECT decided_by, CAST(review_state AS VARCHAR) FROM value_flags WHERE kind = 'session'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (by.as_str(), state.as_str()),
        ("analyst:carlos", "accepted")
    );
    // The agent's decision is no longer the latest, so it cannot be reviewed any more.
    assert!(
        review_marks(c, &reviewer(), &[r("ual_events", "u1")], true)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn reviewing_one_call_by_object_id_reviews_all_its_pending_rows() {
    let case = events_case();
    let c = case.conn();
    let rev = reviewer();
    let three = [
        r("ual_events", "u1"),
        r("ual_events", "u2"),
        r("ual_events", "u3"),
    ];
    let e = flag_rows(c, &agent(), &three, Some(FlagLevel::Suspicious)).unwrap();
    let t = tag_rows(c, &agent(), &three, "ai:x", true).unwrap();
    // The same API as every other decision: object type, object id, the decision's audit seq.
    let a = review::review_accept(
        c,
        &rev,
        "event_flag",
        &e.object_id,
        e.seq,
        Some("looks right"),
    )
    .unwrap();
    assert_eq!(
        (a.action.as_str(), a.object_type.as_str()),
        ("review_accept", "event_flag")
    );
    assert_eq!(a.reason.as_deref(), Some("looks right"));
    assert_eq!(
        a.after.as_ref().unwrap()["rows"],
        json!([
            ["ual_events", "u1"],
            ["ual_events", "u2"],
            ["ual_events", "u3"]
        ]),
        "the rows the review touched are recorded"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM event_flags WHERE review_state = 'accepted' AND reviewed_by = 'analyst:carlos'"
        ),
        3
    );
    // It cannot be accepted twice.
    assert!(matches!(
        review::review_accept(c, &rev, "event_flag", &e.object_id, e.seq, None),
        Err(Error::Decision(_))
    ));
    // A confirmed call cannot be discarded as a review either: the rows are the analyst's now; clear them instead.
    assert!(matches!(
        review::review_discard(c, &rev, "event_flag", &e.object_id, e.seq, None),
        Err(Error::Decision(_))
    ));
    assert_eq!(count(&case, "SELECT count(*) FROM event_flags"), 3);
    // Discarding the tag call removes the three tags it applied and the name with them.
    let d = review::review_discard(c, &rev, "event_tag", &t.object_id, t.seq, None).unwrap();
    assert_eq!(
        d.after.as_ref().unwrap()["rows"],
        json!([
            ["ual_events", "u1"],
            ["ual_events", "u2"],
            ["ual_events", "u3"]
        ])
    );
    assert_eq!(
        d.after.unwrap()["restored"]["removed"],
        json!([
            ["ual_events", "u1"],
            ["ual_events", "u2"],
            ["ual_events", "u3"]
        ])
    );
    assert_eq!(count(&case, "SELECT count(*) FROM event_tags"), 0);
    assert!(list_tags(c).unwrap().is_empty());
    // Unknown objects and types are refused.
    assert!(matches!(
        review::review_accept(c, &rev, "event_flag", "nope", 1, None),
        Err(Error::Decision(_))
    ));
    assert!(matches!(
        review::review_accept(c, &rev, "event_row", "x", 1, None),
        Err(Error::Decision(_))
    ));
    assert!(review::pending(c).unwrap().is_empty());
}

#[test]
fn agent_clearing_its_pending_change_restores_the_analysts_flag() {
    let case = events_case();
    let c = case.conn();
    let u1 = [r("ual_events", "u1")];
    let u2 = [r("ual_events", "u2")];
    flag_rows(c, &analyst(), &u1, Some(FlagLevel::Suspicious)).unwrap();
    // The agent changes the analyst's flag and also flags a fresh row in the same call.
    let both = [r("ual_events", "u1"), r("ual_events", "u2")];
    flag_rows(c, &agent(), &both, Some(FlagLevel::Malicious)).unwrap();
    assert_eq!(row(&case, "u1").flag, Some(FlagLevel::Malicious));
    // It clears its own pending flags: u1 goes back to the analyst's confirmed Suspicious, u2 (added) is removed.
    let e = flag_rows(c, &agent(), &both, None).unwrap();
    assert_eq!(
        e.after.as_ref().unwrap()["restored"],
        json!([["ual_events", "u1", "suspicious"]])
    );
    assert_eq!(
        flagged(&case),
        vec![("u1".to_string(), FlagLevel::Suspicious)]
    );
    let (by, state, reviewer): (String, String, String) = c
        .query_row(
            "SELECT decided_by, CAST(review_state AS VARCHAR), reviewed_by FROM event_flags WHERE record_key = 'u1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (by.as_str(), state.as_str(), reviewer.as_str()),
        ("analyst:carlos", "accepted", "analyst:carlos")
    );
    assert!(!row(&case, "u1").flag_ai);
    assert_eq!(count(&case, "SELECT count(*) FROM event_flags"), 1);
    // Clearing again finds nothing of the agent's to clear (u1 is the analyst's now).
    assert!(matches!(
        flag_rows(c, &agent(), &u1, None),
        Err(Error::Decision(_))
    ));
    assert!(matches!(
        flag_rows(c, &agent(), &u2, None),
        Err(Error::Decision(_))
    ));
    let report = audit::verify(c).unwrap();
    assert!(report.ok, "{report:?}");
    // An analyst's clear still removes the flag.
    flag_rows(c, &analyst(), &u1, None).unwrap();
    assert!(flagged(&case).is_empty());
    assert!(audit::verify(c).unwrap().ok);
}

#[test]
fn no_matching_events_means_no_indicator_and_a_null_tenant_means_a_case_wide_one() {
    let case = events_case();
    let c = case.conn();
    // An IP and an account nothing has seen, case-wide and scoped to an empty entity tab: flags, but no indicator.
    flag_value(
        c,
        &analyst(),
        ValueKind::Ip,
        "198.51.100.200",
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    flag_value(
        c,
        &analyst(),
        ValueKind::Account,
        "ghost@contoso.example",
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    flag_value(
        c,
        &analyst(),
        ValueKind::Ip,
        IP,
        Some(&Entity::Session(
            "00000000-0000-4000-8000-000000000000".into(),
        )),
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM value_flags"), 3);
    assert!(indicator_rows(&case).is_empty());
    // Matching events with no tenant: one case-wide indicator.
    put(
        &case,
        20,
        &Ev {
            table: "ual_events",
            key: "n1",
            source: "ual",
            ip: Some("198.51.100.201"),
            ..Ev::default()
        },
    );
    flag_value(
        c,
        &analyst(),
        ValueKind::Ip,
        "198.51.100.201",
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    assert_eq!(
        indicator_rows(&case),
        vec![(
            None,
            "ip".to_string(),
            "198.51.100.201".to_string(),
            "malicious".to_string(),
            Some("accepted".to_string())
        )]
    );
}

#[test]
fn ai_pending_sees_a_pending_agent_mark_that_a_stronger_confirmed_flag_hides() {
    let case = events_case();
    let c = case.conn();
    let rev = reviewer();
    // Nothing marked: nothing to review.
    assert!(!row(&case, "u1").ai_pending);
    // The analyst's accepted Malicious flag on u1; an agent's pending Suspicious flag on the IP u1 and u2 share.
    flag_rows(
        c,
        &analyst(),
        &[r("ual_events", "u1")],
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    assert!(!row(&case, "u1").ai_pending);
    flag_value(
        c,
        &agent(),
        ValueKind::Ip,
        IP,
        None,
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    // u1: the effective flag is the confirmed Malicious one, so `flag_ai` is false, but a pending mark covers it.
    let u1 = row(&case, "u1");
    assert_eq!(
        (u1.flag, u1.flag_ai, u1.ai_pending),
        (Some(FlagLevel::Malicious), false, true)
    );
    // u2: only the pending flag shows, and it is pending.
    let u2 = row(&case, "u2");
    assert_eq!(
        (u2.flag, u2.flag_ai, u2.ai_pending),
        (Some(FlagLevel::Suspicious), true, true)
    );
    // u3 has another IP: untouched.
    assert!(!row(&case, "u3").ai_pending);
    // An agent's tag counts too, with no flag at all.
    tag_rows(c, &agent(), &[r("ual_events", "u3")], "ai:relay", true).unwrap();
    let u3 = row(&case, "u3");
    assert_eq!((u3.flag, u3.flag_ai, u3.ai_pending), (None, false, true));
    // Reviewing the one selection that the grid can now send (u1) confirms the value flag for every row it covers.
    let done = review_marks(c, &rev, &[r("ual_events", "u1")], true).unwrap();
    assert!(!done.is_empty());
    assert!(!row(&case, "u1").ai_pending);
    assert!(!row(&case, "u2").ai_pending);
    assert!(!row(&case, "u2").flag_ai);
    // The tag on u3 is still waiting.
    assert!(row(&case, "u3").ai_pending);
}

#[test]
fn flag_value_reports_the_indicators_it_added_or_updated() {
    let case = events_case();
    let c = case.conn();
    let go = |kind, value: &str, level| {
        flag_value_with_indicators(c, &analyst(), kind, value, None, level).unwrap()
    };
    // Suspicious, a kind that makes none, and a clear: nothing reported.
    assert!(
        go(ValueKind::Ip, IP, Some(FlagLevel::Suspicious))
            .1
            .is_empty()
    );
    assert!(
        go(ValueKind::Asn, "64496", Some(FlagLevel::Malicious))
            .1
            .is_empty()
    );
    // New: Malicious on the IP adds its indicator, one per tenant of the events, and says so.
    let (entry, made) = go(ValueKind::Ip, IP, Some(FlagLevel::Malicious));
    assert_eq!(entry.action, "flag_value");
    assert_eq!(made.len(), 1);
    assert!(made[0].created);
    assert!(made[0].tenant_key.is_some());
    let rows = indicator_rows(&case);
    assert_eq!(rows.len(), 1);
    // Updated: clear it, flag it again; the indicator exists now, so it is reported as updated, same id.
    assert!(go(ValueKind::Ip, IP, None).1.is_empty());
    let (_, again) = go(ValueKind::Ip, IP, Some(FlagLevel::Malicious));
    assert_eq!(again.len(), 1);
    assert!(!again[0].created);
    assert_eq!(again[0].indicator_id, made[0].indicator_id);
    assert_eq!(indicator_rows(&case).len(), 1);
    // None because no event matches: the flag is made, no indicator, nothing reported.
    let (_, none) = go(ValueKind::Ip, "198.51.100.200", Some(FlagLevel::Malicious));
    assert!(none.is_empty());
    assert_eq!(indicator_rows(&case).len(), 1);
    // `flag_value` keeps returning just the audit row.
    let plain = flag_value(
        c,
        &analyst(),
        ValueKind::Account,
        "jdoe@contoso.example",
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    assert_eq!(
        (plain.action.as_str(), plain.object_type.as_str()),
        ("flag_value", "value_flag")
    );
}

/// Times a page with flags and tags joined on a big kept case, with about 1,000 value flags, 10,000 row flags and
/// 10,000 tags. Marks are written to the kept case (use a scratch copy):
/// SPARROW_PERF_KEEP=<dir> cargo test -p sparrow-core --release --test marks marks_timing -- --ignored --nocapture
#[test]
#[ignore = "heavy, wall-clock"]
fn marks_timing_on_kept_case() {
    use sparrow_core::case::browse::Sort;
    use std::time::Instant;
    let Some(keep) = std::env::var_os("SPARROW_PERF_KEEP") else {
        println!("SPARROW_PERF_KEEP is not set; nothing to time");
        return;
    };
    let case = Case::create_or_open(&std::path::Path::new(&keep).join("case.duckdb")).unwrap();
    let c = case.conn();
    let col = |sql: &str, n: usize| -> Vec<String> {
        let mut stmt = c.prepare(sql).unwrap();
        stmt.query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .take(n)
            .collect()
    };
    let busiest = col(
        "SELECT actor_upn FROM events WHERE actor_upn IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC LIMIT 1",
        1,
    )
    .remove(0);
    let busiest_ip = col(
        "SELECT ip FROM events WHERE ip IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC LIMIT 1",
        1,
    )
    .remove(0);
    let total: i64 = count(&case, "SELECT count(*) FROM events");
    println!("events: {total}; busiest account {busiest}; busiest ip {busiest_ip}");
    let time = |label: &str, f: &dyn Fn() -> String| {
        let t = Instant::now();
        let out = f();
        println!("{label}: {:.3}s  {out}", t.elapsed().as_secs_f64());
    };
    let scopes: [(&str, EventQuery); 3] = [
        ("whole case", EventQuery::default()),
        (
            "busiest account",
            EventQuery {
                entity: Some(Entity::Account(busiest.clone())),
                ..EventQuery::default()
            },
        ),
        (
            "busiest ip",
            EventQuery {
                entity: Some(Entity::Ip(busiest_ip.clone())),
                ..EventQuery::default()
            },
        ),
    ];
    let measure = |tag: &str| {
        for (name, q) in &scopes {
            time(&format!("[{tag}] {name} page"), &|| {
                let p = events::page(c, q, None, 0, 100).unwrap();
                format!(
                    "{} rows, {} flagged, {} tagged",
                    p.rows.len(),
                    p.rows.iter().filter(|r| r.flag.is_some()).count(),
                    p.rows.iter().filter(|r| !r.tags.is_empty()).count()
                )
            });
            time(
                &format!("[{tag}] {name} page sorted by operation, offset 1000"),
                &|| {
                    let s = Sort {
                        column: "operation".into(),
                        descending: false,
                    };
                    format!(
                        "{} rows",
                        events::page(c, q, Some(&s), 1000, 100).unwrap().rows.len()
                    )
                },
            );
            time(&format!("[{tag}] {name} summary"), &|| {
                let s = events::summary(c, q).unwrap();
                format!(
                    "total {} suspicious {} malicious {}",
                    s.total, s.suspicious, s.malicious
                )
            });
            time(&format!("[{tag}] {name} histogram"), &|| {
                format!(
                    "{} series",
                    events::histogram(c, q, 60).unwrap().series.len()
                )
            });
        }
    };
    measure("no marks");

    // 10,000 row flags (analyst), half on the newest rows and half on the busiest account's; 10,000 tags likewise.
    let newest: Vec<RowRef> = {
        let mut stmt = c
            .prepare("SELECT source_table, record_key FROM events ORDER BY event_time DESC NULLS LAST LIMIT 5000")
            .unwrap();
        stmt.query_map([], |r| {
            Ok(RowRef {
                source_table: r.get(0)?,
                record_key: r.get(1)?,
            })
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    };
    let account_rows: Vec<RowRef> = {
        let mut stmt = c
            .prepare(
                "SELECT source_table, record_key FROM events WHERE actor_upn = ? ORDER BY event_time DESC LIMIT 5000",
            )
            .unwrap();
        stmt.query_map([&busiest], |r| {
            Ok(RowRef {
                source_table: r.get(0)?,
                record_key: r.get(1)?,
            })
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    };
    let rows: Vec<RowRef> = newest.iter().chain(account_rows.iter()).cloned().collect();
    time("write: flag 10,000 rows suspicious (one call)", &|| {
        flag_rows(c, &analyst(), &rows, Some(FlagLevel::Suspicious)).unwrap();
        format!("{} rows", rows.len())
    });
    time("write: flag every 4th malicious (one call)", &|| {
        let every4: Vec<RowRef> = rows.iter().step_by(4).cloned().collect();
        flag_rows(c, &analyst(), &every4, Some(FlagLevel::Malicious)).unwrap();
        format!("{} rows", every4.len())
    });
    time("write: tag 10,000 rows (one call)", &|| {
        tag_rows(c, &analyst(), &rows, "timing", true).unwrap();
        "ok".to_string()
    });
    time("write: agent tags 1,000 rows", &|| {
        tag_rows(c, &agent(), &rows[..1000], "ai:timing", true).unwrap();
        "ok".to_string()
    });
    measure("10,000 row flags + tags");

    // About 1,000 value flags of every kind, some scoped to the busiest account.
    let ips = col(
        "SELECT ip FROM events WHERE ip IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC LIMIT 400",
        400,
    );
    let accounts = col(
        "SELECT actor_upn FROM events WHERE actor_upn IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC LIMIT 200",
        200,
    );
    let prefixes = col(
        "SELECT ip_prefix FROM events WHERE ip_prefix IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC LIMIT 100",
        100,
    );
    let asns = col(
        "SELECT CAST(asn AS VARCHAR) FROM events WHERE asn IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC LIMIT 100",
        100,
    );
    let devices = col(
        "SELECT device_id FROM events WHERE device_id IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC LIMIT 100",
        100,
    );
    let sessions = col(
        "SELECT entra_session_id FROM events WHERE entra_session_id IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC LIMIT 100",
        100,
    );
    println!(
        "value candidates: {} ips, {} accounts, {} prefixes, {} asns, {} devices, {} sessions",
        ips.len(),
        accounts.len(),
        prefixes.len(),
        asns.len(),
        devices.len(),
        sessions.len()
    );
    time(
        "write: ~1,000 value flags (one call each, malicious ip/account make indicators)",
        &|| {
            let mut n = 0;
            let scope = Entity::Account(busiest.clone());
            for (kind, values) in [
                (ValueKind::Ip, &ips),
                (ValueKind::Account, &accounts),
                (ValueKind::IpPrefix, &prefixes),
                (ValueKind::Asn, &asns),
                (ValueKind::Device, &devices),
                (ValueKind::Session, &sessions),
            ] {
                for (i, v) in values.iter().enumerate() {
                    let level = if i % 5 == 0 {
                        FlagLevel::Malicious
                    } else {
                        FlagLevel::Suspicious
                    };
                    // Every tenth is scoped to the busiest account.
                    let sc = (i % 10 == 3).then_some(&scope);
                    flag_value(c, &analyst(), kind, v, sc, Some(level)).unwrap();
                    n += 1;
                }
            }
            format!("{n} flags")
        },
    );
    println!(
        "value_flags {} (active {}); event_flags {}; event_tags {}",
        count(&case, "SELECT count(*) FROM value_flags"),
        count(
            &case,
            "SELECT count(*) FROM value_flags WHERE removed_at IS NULL"
        ),
        count(&case, "SELECT count(*) FROM event_flags"),
        count(&case, "SELECT count(*) FROM event_tags")
    );
    measure("10,000 row flags + tags + ~1,000 value flags");

    let flagged = |f| EventQuery {
        flag: f,
        ..EventQuery::default()
    };
    for (name, q) in [
        ("flag=Malicious", flagged(FlagFilter::Malicious)),
        ("flag=Suspicious", flagged(FlagFilter::Suspicious)),
        (
            "ai=Unreviewed",
            EventQuery {
                ai: AiFilter::Unreviewed,
                ..EventQuery::default()
            },
        ),
        (
            "tag=timing",
            EventQuery {
                fields: vec![(Field::Tag, "timing".into())],
                ..EventQuery::default()
            },
        ),
        (
            "tag=!timing",
            EventQuery {
                fields: vec![(Field::Tag, "!timing".into())],
                ..EventQuery::default()
            },
        ),
        (
            "busiest account, flag=Malicious",
            EventQuery {
                entity: Some(Entity::Account(busiest.clone())),
                flag: FlagFilter::Malicious,
                ..EventQuery::default()
            },
        ),
    ] {
        time(&format!("filter {name} page"), &|| {
            let p = events::page(c, &q, None, 0, 100).unwrap();
            format!("total {} capped {}", p.total, p.total_capped)
        });
        time(&format!("filter {name} summary"), &|| {
            let s = events::summary(c, &q).unwrap();
            format!(
                "total {} suspicious {} malicious {}",
                s.total, s.suspicious, s.malicious
            )
        });
    }
    let out = std::path::Path::new(&keep).join("marks-timing.csv");
    time("csv export of the busiest account with flags", &|| {
        format!(
            "{} rows",
            events::export_csv(c, &scopes[1].1, &out).unwrap()
        )
    });
    time("detail of a flagged row", &|| {
        let r = &rows[0];
        let d = events::detail(c, &r.source_table, &r.record_key).unwrap();
        format!("{} flag sources", d.flag_sources.len())
    });
    time("review_marks: confirm the 1,000 agent tags", &|| {
        let done = review_marks(c, &reviewer(), &rows[..1000], true).unwrap();
        format!("{} audit rows", done.len())
    });
}

// ---- list_marks ----

use sparrow_core::case::marks::{MarkFilter, list_marks};

#[test]
fn list_marks_shows_flags_and_tags_with_their_review_state() {
    let case = events_case();
    let c = case.conn();
    flag_value(
        c,
        &agent(),
        ValueKind::Ip,
        "203.0.113.45",
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    flag_rows(
        c,
        &analyst(),
        &[r("ual_events", "u1")],
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    tag_rows(c, &agent(), &[r("ual_events", "u1")], "ai:lure", true).unwrap();
    // A removed value flag is not listed.
    flag_value(
        c,
        &analyst(),
        ValueKind::Ip,
        "198.51.100.7",
        None,
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    flag_value(c, &analyst(), ValueKind::Ip, "198.51.100.7", None, None).unwrap();
    let all = list_marks(c, &MarkFilter::default()).unwrap();
    let got: Vec<_> = all
        .iter()
        .map(|m| {
            (
                m.mark.as_str(),
                m.level_or_tag.as_str(),
                m.review_state.as_str(),
                m.decided_by.as_str(),
            )
        })
        .collect();
    assert_eq!(
        got,
        vec![
            ("value_flag", "malicious", "pending_review", "agent:triage"),
            ("row_flag", "suspicious", "accepted", "analyst:carlos"),
            ("tag", "ai:lure", "pending_review", "agent:triage"),
        ]
    );
    assert_eq!(all[0].kind.as_deref(), Some("ip"));
    assert_eq!(all[0].value.as_deref(), Some("203.0.113.45"));
    assert_eq!(all[1].row.as_deref(), Some("ual_events:u1"));
    let pending = list_marks(
        c,
        &MarkFilter {
            pending_only: true,
            ..MarkFilter::default()
        },
    )
    .unwrap();
    assert_eq!(pending.len(), 2);
    let tags = list_marks(
        c,
        &MarkFilter {
            kind: Some("tag".into()),
            ..MarkFilter::default()
        },
    )
    .unwrap();
    assert_eq!(
        tags.iter().map(|m| m.mark.as_str()).collect::<Vec<_>>(),
        ["tag"]
    );
    let flags = list_marks(
        c,
        &MarkFilter {
            kind: Some("flag".into()),
            ..MarkFilter::default()
        },
    )
    .unwrap();
    assert_eq!(flags.len(), 2);
    let mine = list_marks(
        c,
        &MarkFilter {
            agent: Some("triage".into()),
            ..MarkFilter::default()
        },
    )
    .unwrap();
    assert!(mine.iter().all(|m| m.decided_by == "agent:triage") && mine.len() == 2);
    assert!(
        list_marks(
            c,
            &MarkFilter {
                kind: Some("nope".into()),
                ..MarkFilter::default()
            }
        )
        .is_err()
    );
}
