//! Task 3 of the investigate tabs: the entity summary, the pivot tables and the findings of an account, IP, device or
//! Entra session. The cases insert `events` rows directly (the module reads that table only), plus findings, one
//! `ip_intel` row and one sign-in for the device struct.

use chrono::{DateTime, TimeZone, Utc};
use serde_json::json;
use sparrow_core::Case;
use sparrow_core::Error;
use sparrow_core::case::entity::{
    self, PIVOT_DEFAULT_LIMIT, PIVOT_MAX_LIMIT, PivotOf, PivotPage, PivotRow,
};
use sparrow_core::case::events::Entity;
use sparrow_core::detect::test::insert_record;

fn at(day: u32, h: u32, m: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, day, h, m, 0).unwrap()
}

/// One `events` row; unset columns are NULL.
#[derive(Default, Clone)]
struct Ev {
    table: &'static str,
    key: &'static str,
    source: &'static str,
    time: Option<DateTime<Utc>>,
    op: Option<&'static str>,
    actor: Option<&'static str>,
    owner: Option<&'static str>,
    ip: Option<&'static str>,
    country: Option<&'static str>,
    asn: Option<i32>,
    asn_org: Option<&'static str>,
    kind: Option<&'static str>,
    device_id: Option<&'static str>,
    device_object_id: Option<&'static str>,
    device_name: Option<&'static str>,
    session: Option<&'static str>,
}

fn put(case: &Case, e: &Ev) {
    case.conn()
        .execute(
            "INSERT INTO events (source_table, record_key, source, event_time, category, operation, actor_upn, \
             owner_upn, target, ip, ip_country, asn, asn_org, ip_kind, device_id, device_object_id, device_name, \
             entra_session_id, summary) \
             VALUES (?, ?, ?, CAST(? AS TIMESTAMPTZ), 'other', ?, ?, ?, 'target-' || ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
                     'summary of ' || ?)",
            duckdb::params![
                e.table,
                e.key,
                e.source,
                e.time.map(|t| t.format("%Y-%m-%dT%H:%M:%S%.6f+00").to_string()),
                e.op,
                e.actor,
                e.owner,
                e.key,
                e.ip,
                e.country,
                e.asn,
                e.asn_org,
                e.kind,
                e.device_id,
                e.device_object_id,
                e.device_name,
                e.session,
                e.key,
            ],
        )
        .unwrap();
}

const JDOE: &str = "jdoe@contoso.example";
const LAPTOP: &str = "JDOE-LAPTOP";

fn finding(case: &Case, id: &str, severity: &str, status: &str, rows: &[(&str, &str)]) {
    case.conn()
        .execute(
            "INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, rule_version, rule_sha256, severity, \
             title, status, created_by, created_at, updated_at) \
             VALUES (?, ?, 'contoso', 'SPW-X', 1, 'x', ?, 'title ' || ?, CAST(? AS finding_status), 'rule', now(), now())",
            duckdb::params![id, id, severity, id, status],
        )
        .unwrap();
    for (table, key) in rows {
        case.conn()
            .execute(
                "INSERT INTO finding_evidence (finding_id, source_table, record_key, role, added_run_id) \
                 VALUES (?, ?, ?, 'trigger', 1)",
                [id, table, key],
            )
            .unwrap();
    }
}

/// The case of the tests: one account on two days, 2 sessions, 3 IPs (one first seen on day 2), one device, mail
/// events in both directions, a hidden message trace event, another account on the same IP and findings in every
/// status.
fn fixture() -> Case {
    let case = Case::in_memory().unwrap();
    let ual = |key, time, actor, ip, country, asn, session| Ev {
        table: "ual_events",
        key,
        source: "ual",
        time: Some(time),
        op: Some("UserLoggedIn"),
        actor: Some(actor),
        ip,
        country,
        asn,
        asn_org: if ip == Some("203.0.113.10") {
            Some("Example ISP")
        } else {
            None
        },
        kind: if ip == Some("203.0.113.10") {
            Some("hosting")
        } else {
            None
        },
        session,
        ..Ev::default()
    };
    let laptop = |mut e: Ev| {
        e.device_id = Some("d1");
        e.device_name = Some(LAPTOP);
        e
    };
    let rows = [
        laptop(ual(
            "u1",
            at(1, 10, 0),
            JDOE,
            Some("203.0.113.10"),
            Some("US"),
            Some(64500),
            Some("s1"),
        )),
        laptop(Ev {
            table: "signins",
            key: "s1",
            source: "signin_interactive",
            op: Some("SignInSucceeded"),
            ..ual(
                "s1",
                at(1, 10, 5),
                JDOE,
                Some("203.0.113.10"),
                Some("US"),
                Some(64500),
                Some("s1"),
            )
        }),
        laptop(ual(
            "u2",
            at(1, 11, 0),
            JDOE,
            Some("198.51.100.7"),
            Some("GB"),
            Some(64501),
            Some("s2"),
        )),
        // The attacker reads jdoe's mailbox.
        Ev {
            op: Some("MailItemsAccessed"),
            owner: Some(JDOE),
            ..ual(
                "u4",
                at(1, 12, 0),
                "attacker@contoso.example",
                Some("198.51.100.7"),
                Some("GB"),
                Some(64501),
                None,
            )
        },
        // A Sessions-report row: the user owns the mailbox.
        Ev {
            table: "mail_items_accessed",
            source: "mail_items_accessed",
            owner: Some(JDOE),
            ..ual(
                "m1",
                at(1, 12, 30),
                JDOE,
                Some("198.51.100.7"),
                Some("GB"),
                Some(64501),
                None,
            )
        },
        // Day 2: a new IP, in the same session s2.
        laptop(ual(
            "u3",
            at(2, 9, 0),
            JDOE,
            Some("192.0.2.99"),
            Some("NL"),
            Some(64502),
            Some("s2"),
        )),
        // Message trace: jdoe sends on day 1, receives on day 2; the per-message event is hidden by default.
        Ev {
            table: "message_trace",
            key: "mt1",
            source: "message_trace",
            time: Some(at(1, 13, 0)),
            op: Some("MessageTrace"),
            actor: Some(JDOE),
            owner: Some("other@contoso.example"),
            ..Ev::default()
        },
        Ev {
            table: "message_trace",
            key: "mt2",
            source: "message_trace",
            time: Some(at(2, 10, 0)),
            op: Some("MessageTrace"),
            actor: Some("outsider@contoso.example"),
            owner: Some(JDOE),
            ..Ev::default()
        },
        Ev {
            table: "message_trace_events",
            key: "te1",
            source: "message_trace_event",
            time: Some(at(1, 13, 1)),
            op: Some("RECEIVE"),
            actor: Some(JDOE),
            owner: Some("other@contoso.example"),
            ..Ev::default()
        },
        // Another account on jdoe's day-1 IP, and a v6 one.
        ual(
            "u9",
            at(1, 14, 0),
            "other@contoso.example",
            Some("203.0.113.10"),
            Some("US"),
            Some(64500),
            None,
        ),
        ual(
            "u10",
            at(1, 15, 0),
            "v6user@contoso.example",
            Some("2001:db8::1"),
            None,
            None,
            None,
        ),
        // The same record key as jdoe's u1, in another table, on another account.
        Ev {
            table: "directory_audits",
            key: "u1",
            source: "entra_audit",
            time: Some(at(1, 10, 0)),
            op: Some("Update user"),
            actor: Some("other@contoso.example"),
            ..Ev::default()
        },
        // Directory audit rows that name devices.
        Ev {
            table: "directory_audits",
            key: "a1",
            source: "entra_audit",
            time: Some(at(1, 9, 0)),
            op: Some("Register device"),
            actor: Some("admin@contoso.example"),
            device_id: Some("d1"),
            device_object_id: Some("o1"),
            device_name: Some(LAPTOP),
            ..Ev::default()
        },
        Ev {
            table: "directory_audits",
            key: "a2",
            source: "entra_audit",
            time: Some(at(2, 8, 0)),
            op: Some("Add Windows Hello for Business key"),
            actor: Some("admin@contoso.example"),
            device_id: Some("d1"),
            device_object_id: Some("o1"),
            device_name: Some(LAPTOP),
            ..Ev::default()
        },
        Ev {
            table: "directory_audits",
            key: "a3",
            source: "entra_audit",
            time: Some(at(1, 9, 30)),
            op: Some("Register device"),
            actor: Some("admin@contoso.example"),
            device_id: Some("d2"),
            device_object_id: Some("o2"),
            device_name: Some("OTHER-PC"),
            ..Ev::default()
        },
    ];
    for r in &rows {
        put(&case, r);
    }

    finding(
        &case,
        "F1",
        "high",
        "new",
        &[("ual_events", "u1"), ("signins", "s1")],
    );
    finding(
        &case,
        "F2",
        "high",
        "false_positive",
        &[("ual_events", "u2")],
    );
    finding(&case, "F3", "medium", "benign", &[("ual_events", "u3")]);
    finding(&case, "F5", "high", "confirmed", &[("ual_events", "u9")]);
    // Cites key u1 of directory_audits, not of ual_events: it belongs to other@, never to jdoe.
    finding(&case, "F6", "high", "new", &[("directory_audits", "u1")]);

    case.conn()
        .execute_batch(
            "INSERT INTO ip_intel (ip, country_iso, country, asn, asn_org, is_hosting, is_microsoft, is_private) \
             VALUES ('203.0.113.10', 'US', 'United States', 64500, 'Example ISP', true, false, false)",
        )
        .unwrap();
    insert_record(
        &case,
        "contoso",
        "signins",
        &json!({"record_key": "s1", "device": {
            "device_id": "d1", "display_name": LAPTOP, "os": "Windows 11", "browser": "Edge",
            "is_compliant": true, "is_managed": false, "trust_type": "AzureAD joined"}}),
        "s1",
    )
    .unwrap();
    case
}

fn account(v: &str) -> Entity {
    Entity::Account(v.into())
}

fn texts(rows: &[PivotRow]) -> Vec<(String, u64, bool)> {
    rows.iter()
        .map(|r| (r.value.clone(), r.count, r.is_new))
        .collect()
}

fn distinct(s: &entity::EntitySummary) -> Vec<(&str, u64)> {
    s.distinct.iter().map(|(k, v)| (k.as_str(), *v)).collect()
}

#[test]
fn account_summary_tiles_exact() {
    let case = fixture();
    // Spelled in capitals: the tab is the same one.
    let s = entity::summary(case.conn(), &account("JDoe@Contoso.Example"), None, None).unwrap();
    assert_eq!(s.entity, account(JDOE));
    // u1, s1, u2, u4, m1, u3, mt1, mt2; the message trace event te1 is hidden, as in the grid.
    assert_eq!(s.events, 8);
    assert_eq!(s.first_seen, Some(at(1, 10, 0)));
    assert_eq!(s.last_seen, Some(at(2, 10, 0)));
    assert_eq!(
        distinct(&s),
        [
            // jdoe, attacker, outsider, other
            ("accounts", 4),
            ("asns", 3),
            ("countries", 3),
            ("devices", 1),
            ("ips", 3),
            ("sessions", 2),
        ]
    );
    // F1 cites two of the events and counts once; F2 is a false positive and F3 benign; F5 is on another account.
    assert_eq!(
        s.open_findings.iter().collect::<Vec<_>>(),
        [(&"high".to_string(), &1)]
    );
    assert_eq!(
        s.roles_matched,
        [
            "actor",
            "mailbox owner",
            "message sender",
            "message recipient"
        ]
    );
    assert!(s.ip_intel.is_none() && s.device.is_none());

    let f = entity::findings(case.conn(), &account(JDOE), None, None).unwrap();
    assert_eq!(
        f.iter()
            .map(|f| {
                (
                    f.finding_id.as_str(),
                    f.rule_id.as_deref(),
                    f.title.as_str(),
                    f.severity.as_str(),
                    f.status.as_str(),
                    f.first_seen,
                )
            })
            .collect::<Vec<_>>(),
        [(
            "F1",
            Some("SPW-X"),
            "title F1",
            "high",
            "new",
            Some(at(1, 10, 0))
        )]
    );
}

#[test]
fn a_finding_on_the_same_key_in_another_table_is_not_confused() {
    let case = fixture();
    // F6 cites directory_audits:u1, a different record from ual_events:u1 that F1 cites.
    let ids = |who: &str| {
        entity::findings(case.conn(), &account(who), None, None)
            .unwrap()
            .into_iter()
            .map(|f| f.finding_id)
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(JDOE), ["F1"]);
    assert_eq!(ids("other@contoso.example"), ["F6", "F5"]);
    let other =
        entity::summary(case.conn(), &account("other@contoso.example"), None, None).unwrap();
    assert_eq!(other.open_findings["high"], 2);
    let jdoe = entity::summary(case.conn(), &account(JDOE), None, None).unwrap();
    assert_eq!(jdoe.open_findings["high"], 1);
}

#[test]
fn roles_matched_per_role() {
    let case = fixture();
    let roles = |who: &str| {
        entity::summary(case.conn(), &account(who), None, None)
            .unwrap()
            .roles_matched
    };
    // The attacker only acted; an outside sender only sent; other@ is a recipient and acted in u9.
    assert_eq!(roles("attacker@contoso.example"), ["actor"]);
    assert_eq!(roles("outsider@contoso.example"), ["message sender"]);
    assert_eq!(
        roles("other@contoso.example"),
        ["actor", "message recipient"]
    );
    // Only jdoe's day-2 events: acting in u3 and receiving mt2.
    let day2 = entity::summary(case.conn(), &account(JDOE), Some(at(2, 0, 0)), None).unwrap();
    assert_eq!(day2.roles_matched, ["actor", "message recipient"]);
    // Other kinds have no roles.
    let ip = entity::summary(case.conn(), &Entity::Ip("203.0.113.10".into()), None, None).unwrap();
    assert!(ip.roles_matched.is_empty());
}

#[test]
fn ip_pivot_marks_new() {
    let case = fixture();
    let rows = entity::pivot(case.conn(), &account(JDOE), PivotOf::Ips, None, None, None)
        .unwrap()
        .rows;
    assert_eq!(
        texts(&rows),
        [
            // u2, u4 and m1; the sessions-report row counts once. Most events first.
            ("198.51.100.7".to_string(), 3, false),
            ("203.0.113.10".to_string(), 2, false),
            ("192.0.2.99".to_string(), 1, true),
        ]
    );
    assert_eq!(
        (rows[0].first_seen, rows[0].last_seen),
        (at(1, 11, 0), at(1, 12, 30))
    );
    let first = &rows[1];
    assert_eq!(
        (first.first_seen, first.last_seen),
        (at(1, 10, 0), at(1, 10, 5))
    );
    assert_eq!(first.label, None);
    assert_eq!(
        serde_json::Value::Object(first.extra.clone()),
        json!({"country": "US", "asn": 64500, "asn_org": "Example ISP", "ip_kind": "hosting"})
    );
    assert_eq!(
        serde_json::Value::Object(rows[0].extra.clone()),
        json!({"country": "GB", "asn": 64501})
    );

    // "new" ignores the range: the day-2 IP is still new when the range starts on day 2, and is alone in it.
    let day2 = entity::pivot(
        case.conn(),
        &account(JDOE),
        PivotOf::Ips,
        Some(at(2, 0, 0)),
        None,
        None,
    )
    .unwrap()
    .rows;
    assert_eq!(texts(&day2), [("192.0.2.99".to_string(), 1, true)]);
    // And an old IP stays not-new when the range leaves out day 1.
    let late = entity::pivot(
        case.conn(),
        &account(JDOE),
        PivotOf::Ips,
        Some(at(1, 11, 30)),
        None,
        None,
    )
    .unwrap()
    .rows;
    assert_eq!(
        texts(&late),
        [
            ("198.51.100.7".to_string(), 2, false),
            ("192.0.2.99".to_string(), 1, true),
        ]
    );
}

#[test]
fn session_tab_ips_and_first_ip() {
    let case = fixture();
    // The account's session table: first IP of each session.
    let rows = entity::pivot(
        case.conn(),
        &account(JDOE),
        PivotOf::Sessions,
        None,
        None,
        None,
    )
    .unwrap()
    .rows;
    assert_eq!(
        texts(&rows),
        [("s1".to_string(), 2, false), ("s2".to_string(), 2, false)]
    );
    assert_eq!(rows[0].extra["first_ip"], "203.0.113.10");
    assert_eq!(
        (rows[1].first_seen, rows[1].last_seen),
        (at(1, 11, 0), at(2, 9, 0))
    );
    assert_eq!(rows[1].extra["first_ip"], "198.51.100.7");

    // s2 began on day 1: with the range on day 2 it is still not new (its first day is judged over the whole case), and
    // its first IP is the first one in range.
    let day2 = entity::pivot(
        case.conn(),
        &account(JDOE),
        PivotOf::Sessions,
        Some(at(2, 0, 0)),
        None,
        None,
    )
    .unwrap()
    .rows;
    assert_eq!(texts(&day2), [("s2".to_string(), 1, false)]);
    assert_eq!(day2[0].extra["first_ip"], "192.0.2.99");

    // The session tab itself, opened with an upper-case id: its IPs, the day-2 one is new.
    let s2 = Entity::Session("S2".into());
    let s = entity::summary(case.conn(), &s2, None, None).unwrap();
    assert_eq!(s.entity, Entity::Session("s2".into()));
    assert_eq!(s.events, 2);
    assert_eq!(
        distinct(&s),
        [
            ("accounts", 1),
            ("asns", 2),
            ("countries", 2),
            ("devices", 1),
            ("ips", 2),
            ("sessions", 1),
        ]
    );
    let ips = entity::pivot(case.conn(), &s2, PivotOf::Ips, None, None, None)
        .unwrap()
        .rows;
    assert_eq!(
        texts(&ips),
        [
            // Equal counts: by value.
            ("192.0.2.99".to_string(), 1, true),
            ("198.51.100.7".to_string(), 1, false)
        ]
    );
    let accounts = entity::pivot(case.conn(), &s2, PivotOf::Accounts, None, None, None)
        .unwrap()
        .rows;
    assert_eq!(texts(&accounts), [(JDOE.to_string(), 2, false)]);
    let devices = entity::pivot(case.conn(), &s2, PivotOf::Devices, None, None, None)
        .unwrap()
        .rows;
    assert_eq!(texts(&devices), [("d1".to_string(), 2, false)]);
    assert_eq!(devices[0].label.as_deref(), Some(LAPTOP));
    assert_eq!(devices[0].extra["device_name"], LAPTOP);
}

#[test]
fn ip_tab_has_intel_and_pivots() {
    let case = fixture();
    let ip = Entity::Ip("203.0.113.10".into());
    let s = entity::summary(case.conn(), &ip, None, None).unwrap();
    assert_eq!(s.events, 3);
    assert_eq!(
        distinct(&s),
        [
            ("accounts", 2),
            ("asns", 1),
            ("countries", 1),
            ("devices", 1),
            ("ips", 1),
            ("sessions", 1),
        ]
    );
    // F1 (two events of the IP, once) and F5 are open.
    assert_eq!(
        s.open_findings.iter().collect::<Vec<_>>(),
        [(&"high".to_string(), &2)]
    );
    let intel = s.ip_intel.unwrap();
    assert_eq!(intel["country_iso"], "US");
    assert_eq!(intel["asn"], 64500);
    assert_eq!(intel["asn_org"], "Example ISP");
    assert_eq!(intel["ip_kind"], "hosting");
    // An address with no ip_intel row has none.
    let none =
        entity::summary(case.conn(), &Entity::Ip("198.51.100.7".into()), None, None).unwrap();
    assert!(none.ip_intel.is_none());

    let accounts = entity::pivot(case.conn(), &ip, PivotOf::Accounts, None, None, None)
        .unwrap()
        .rows;
    assert_eq!(
        texts(&accounts),
        [
            (JDOE.to_string(), 2, false),
            ("other@contoso.example".to_string(), 1, false)
        ]
    );
    // An event counts for its actor and for its owner: u2 (jdoe), u4 (attacker acts, jdoe owns), m1 (both jdoe, once).
    let shared = Entity::Ip("198.51.100.7".into());
    let accounts = entity::pivot(case.conn(), &shared, PivotOf::Accounts, None, None, None)
        .unwrap()
        .rows;
    assert_eq!(
        texts(&accounts),
        [
            (JDOE.to_string(), 3, false),
            ("attacker@contoso.example".to_string(), 1, false)
        ]
    );
    let sessions = entity::pivot(case.conn(), &ip, PivotOf::Sessions, None, None, None)
        .unwrap()
        .rows;
    assert_eq!(texts(&sessions), [("s1".to_string(), 2, false)]);

    // Every spelling of an IPv6 address is one tab.
    let v6 = entity::summary(case.conn(), &Entity::Ip("2001:DB8::1".into()), None, None).unwrap();
    assert_eq!(v6.entity, Entity::Ip("2001:db8::1".into()));
    assert_eq!(v6.events, 1);
}

#[test]
fn device_tab_struct_and_changes() {
    let case = fixture();
    let d = Entity::Device("D1".into());
    let s = entity::summary(case.conn(), &d, None, None).unwrap();
    assert_eq!(s.entity, Entity::Device("d1".into()));
    // u1, s1, u2, u3 and the two directory audit rows.
    assert_eq!(s.events, 6);
    assert_eq!(
        distinct(&s),
        [
            // jdoe, admin
            ("accounts", 2),
            ("asns", 3),
            ("countries", 3),
            ("devices", 1),
            ("ips", 3),
            ("sessions", 2),
        ]
    );
    assert_eq!(
        s.device.unwrap(),
        json!({"device_id": "d1", "display_name": LAPTOP, "os": "Windows 11", "browser": "Edge",
               "is_compliant": true, "is_managed": false, "trust_type": "AzureAD joined"})
    );
    let accounts = entity::pivot(case.conn(), &d, PivotOf::Accounts, None, None, None)
        .unwrap()
        .rows;
    assert_eq!(
        texts(&accounts),
        [
            (JDOE.to_string(), 4, false),
            ("admin@contoso.example".to_string(), 2, false)
        ]
    );
}

#[test]
fn device_changes_lists_directory_audit_targets() {
    let case = fixture();
    // The device id and the directory object id open the same tab content; the other device's audit is not in it.
    for e in [Entity::Device("d1".into()), Entity::Device("O1".into())] {
        let rows = entity::pivot(case.conn(), &e, PivotOf::DeviceChanges, None, None, None)
            .unwrap()
            .rows;
        assert_eq!(
            rows.iter()
                .map(|r| {
                    (
                        r.value.as_str(),
                        r.label.as_deref(),
                        r.count,
                        r.first_seen,
                        r.last_seen,
                        r.is_new,
                        serde_json::Value::Object(r.extra.clone()),
                    )
                })
                .collect::<Vec<_>>(),
            [
                (
                    "Register device",
                    Some("summary of a1"),
                    1,
                    at(1, 9, 0),
                    at(1, 9, 0),
                    false,
                    json!({"source_table": "directory_audits", "record_key": "a1",
                           "actor": "admin@contoso.example", "target": "target-a1"})
                ),
                (
                    "Add Windows Hello for Business key",
                    Some("summary of a2"),
                    1,
                    at(2, 8, 0),
                    at(2, 8, 0),
                    false,
                    json!({"source_table": "directory_audits", "record_key": "a2",
                           "actor": "admin@contoso.example", "target": "target-a2"})
                ),
            ],
            "{e:?}"
        );
    }
    // Narrowed to day 2.
    let day2 = entity::pivot(
        case.conn(),
        &Entity::Device("d1".into()),
        PivotOf::DeviceChanges,
        Some(at(2, 0, 0)),
        None,
        None,
    )
    .unwrap()
    .rows;
    assert_eq!(day2.len(), 1);
    assert_eq!(day2[0].extra["record_key"], "a2");
}

#[test]
fn pivots_a_tab_does_not_have_are_refused() {
    let case = fixture();
    for (e, of) in [
        (account(JDOE), PivotOf::Accounts),
        (account(JDOE), PivotOf::DeviceChanges),
        (Entity::Ip("203.0.113.10".into()), PivotOf::Ips),
        (Entity::Ip("203.0.113.10".into()), PivotOf::DeviceChanges),
        (Entity::Device("d1".into()), PivotOf::Devices),
        (Entity::Session("s1".into()), PivotOf::Sessions),
        (Entity::Session("s1".into()), PivotOf::DeviceChanges),
    ] {
        assert!(
            matches!(
                entity::pivot(case.conn(), &e, of, None, None, None),
                Err(Error::Invalid(_))
            ),
            "{e:?} {of:?}"
        );
    }
}

#[test]
fn range_narrows_summary_pivots_and_findings() {
    let case = fixture();
    let e = account(JDOE);
    let day2 = Some(at(2, 0, 0));
    let s = entity::summary(case.conn(), &e, day2, None).unwrap();
    // u3 and mt2.
    assert_eq!(s.events, 2);
    assert_eq!(
        (s.first_seen, s.last_seen),
        (Some(at(2, 9, 0)), Some(at(2, 10, 0)))
    );
    assert_eq!(
        distinct(&s),
        [
            ("accounts", 2),
            ("asns", 1),
            ("countries", 1),
            ("devices", 1),
            ("ips", 1),
            ("sessions", 1),
        ]
    );
    // F1 is on day 1; F3 (day 2) is benign.
    assert!(s.open_findings.is_empty());
    assert!(
        entity::findings(case.conn(), &e, day2, None)
            .unwrap()
            .is_empty()
    );
    for of in [PivotOf::Ips, PivotOf::Devices, PivotOf::Sessions] {
        let rows = entity::pivot(case.conn(), &e, of, day2, None, None)
            .unwrap()
            .rows;
        assert_eq!(rows.len(), 1, "{of:?}");
        assert_eq!(rows[0].count, 1, "{of:?}");
    }

    // `to` is inclusive: the sign-in at exactly 10:05 is in, and so is F1 (through both of its events).
    let upto = entity::summary(case.conn(), &e, None, Some(at(1, 10, 5))).unwrap();
    assert_eq!(upto.events, 2);
    assert_eq!(upto.last_seen, Some(at(1, 10, 5)));
    assert_eq!(upto.open_findings["high"], 1);
    let f = entity::findings(case.conn(), &e, None, Some(at(1, 10, 0))).unwrap();
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].finding_id, "F1");
    // Before any event.
    let before = entity::summary(case.conn(), &e, None, Some(at(1, 9, 59))).unwrap();
    assert_eq!(before.events, 0);
}

#[test]
fn unknown_entity_is_empty_not_error() {
    let case = fixture();
    let e = account("nobody@contoso.example");
    let s = entity::summary(case.conn(), &e, None, None).unwrap();
    assert_eq!(s.events, 0);
    assert_eq!((s.first_seen, s.last_seen), (None, None));
    assert_eq!(distinct(&s).iter().map(|d| d.1).sum::<u64>(), 0);
    assert_eq!(s.distinct.len(), 6);
    assert!(s.open_findings.is_empty() && s.roles_matched.is_empty());
    assert!(s.ip_intel.is_none() && s.device.is_none());
    for of in [PivotOf::Ips, PivotOf::Devices, PivotOf::Sessions] {
        assert!(
            entity::pivot(case.conn(), &e, of, None, None, None).unwrap()
                == PivotPage {
                    rows: vec![],
                    total: 0
                }
        );
    }
    assert!(
        entity::findings(case.conn(), &e, None, None)
            .unwrap()
            .is_empty()
    );
    let d = entity::summary(case.conn(), &Entity::Device("zz".into()), None, None).unwrap();
    assert!(d.events == 0 && d.device.is_none());

    // A thing that cannot be an entity is refused, not empty.
    for bad in [Entity::Ip("not an ip".into()), Entity::Account("  ".into())] {
        assert!(matches!(
            entity::summary(case.conn(), &bad, None, None),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            entity::pivot(case.conn(), &bad, PivotOf::Devices, None, None, None),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            entity::findings(case.conn(), &bad, None, None),
            Err(Error::Invalid(_))
        ));
    }
}

/// 12 distinct IPs for one account, 3 events on the first (so it sorts first) and 1 on each of the rest.
fn many_ips() -> Case {
    let case = Case::in_memory().unwrap();
    for n in 0..12u32 {
        let events = if n == 0 { 3 } else { 1 };
        for k in 0..events {
            let key: &'static str = Box::leak(format!("k{n}-{k}").into_boxed_str());
            let ip: &'static str = Box::leak(format!("203.0.113.{}", 100 + n).into_boxed_str());
            put(
                &case,
                &Ev {
                    table: "ual_events",
                    key,
                    source: "ual",
                    time: Some(at(1, 10, n * 4 + k)),
                    actor: Some("x@contoso.example"),
                    ip: Some(ip),
                    ..Ev::default()
                },
            );
        }
    }
    case
}

#[test]
fn pivot_limit_caps_rows_and_reports_the_total() {
    let case = many_ips();
    let who = account("x@contoso.example");
    let page = |limit| entity::pivot(case.conn(), &who, PivotOf::Ips, None, None, limit).unwrap();

    let top = page(Some(5));
    assert_eq!(top.total, 12);
    // Most events first, then by value (text order): .100 has 3; the 1-event IPs follow as .101, .102, .103, .104 ...
    assert_eq!(
        texts(&top.rows),
        [
            ("203.0.113.100".to_string(), 3, false),
            ("203.0.113.101".to_string(), 1, false),
            ("203.0.113.102".to_string(), 1, false),
            ("203.0.113.103".to_string(), 1, false),
            ("203.0.113.104".to_string(), 1, false),
        ]
    );
    // Below the cap and at it: nothing is cut, the total is the same.
    let all = page(None);
    assert_eq!((all.rows.len(), all.total), (12, 12));
    let exact = page(Some(12));
    assert_eq!((exact.rows.len(), exact.total), (12, 12));
    assert_eq!(page(Some(11)).rows.len(), 11);
    assert_eq!(page(Some(1)).total, 12);
    // A limit above the maximum is the maximum (only 12 rows exist, so check the constants separately).
    assert_eq!((PIVOT_DEFAULT_LIMIT, PIVOT_MAX_LIMIT), (500, 5000));
    assert_eq!(page(Some(PIVOT_MAX_LIMIT + 1)).rows.len(), 12);
    assert!(matches!(
        entity::pivot(case.conn(), &who, PivotOf::Ips, None, None, Some(0)),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn pivot_default_limit_is_500_and_max_is_5000() {
    let case = Case::in_memory().unwrap();
    case.conn()
        .execute_batch(
            "INSERT INTO events (source_table, record_key, source, event_time, category, actor_upn, ip) \
             SELECT 'ual_events', 'k' || i, 'ual', CAST('2026-09-01 10:00:00+00' AS TIMESTAMPTZ), 'other', \
                    'x@contoso.example', '2001:db8::' || printf('%x', i) \
             FROM range(5100) t(i)",
        )
        .unwrap();
    let who = account("x@contoso.example");
    let page = |limit| entity::pivot(case.conn(), &who, PivotOf::Ips, None, None, limit).unwrap();
    let d = page(None);
    assert_eq!((d.rows.len(), d.total), (500, 5100));
    let m = page(Some(6000));
    assert_eq!((m.rows.len(), m.total), (5000, 5100));
    let n = page(Some(5000));
    assert_eq!(n.rows.len(), 5000);
    // The sessions-style tables and device changes follow the same cap.
    assert_eq!(page(Some(4999)).rows.len(), 4999);
}

#[test]
fn device_changes_follow_the_limit() {
    let case = fixture();
    let d = Entity::Device("d1".into());
    let one = entity::pivot(case.conn(), &d, PivotOf::DeviceChanges, None, None, Some(1)).unwrap();
    assert_eq!(one.total, 2);
    assert_eq!(one.rows.len(), 1);
    assert_eq!(one.rows[0].extra["record_key"], "a1");
}

#[test]
fn events_without_a_time_count_but_have_no_first_seen() {
    let case = Case::in_memory().unwrap();
    let e = |key, time: Option<DateTime<Utc>>, ip| Ev {
        table: "ual_events",
        key,
        source: "ual",
        time,
        actor: Some("x@contoso.example"),
        ip: Some(ip),
        ..Ev::default()
    };
    put(&case, &e("k1", Some(at(1, 10, 0)), "203.0.113.1"));
    put(&case, &e("k2", None, "203.0.113.2"));
    let who = account("x@contoso.example");
    let s = entity::summary(case.conn(), &who, None, None).unwrap();
    assert_eq!(s.events, 2);
    assert_eq!(
        (s.first_seen, s.last_seen),
        (Some(at(1, 10, 0)), Some(at(1, 10, 0)))
    );
    assert_eq!(s.distinct["ips"], 2);
    // The IP whose only event has no time has no first or last seen to show.
    let ips = entity::pivot(case.conn(), &who, PivotOf::Ips, None, None, None)
        .unwrap()
        .rows;
    assert_eq!(texts(&ips), [("203.0.113.1".to_string(), 1, false)]);
}

/// Wall-clock measurement on a case kept by the synthetic perf harness; nothing to time without it:
/// SPARROW_PERF_KEEP=<dir> cargo test -p sparrow-core --release --test entity entity_timing -- --ignored --nocapture
#[test]
#[ignore = "heavy, wall-clock"]
fn entity_timing_on_kept_case() {
    let Some(keep) = std::env::var_os("SPARROW_PERF_KEEP") else {
        println!("SPARROW_PERF_KEEP is not set; nothing to time");
        return;
    };
    let case = Case::create_or_open(&std::path::Path::new(&keep).join("case.duckdb")).unwrap();
    let conn = case.conn();
    let busiest = |col: &str| -> String {
        conn.query_row(
            &format!("SELECT {col} FROM events WHERE {col} IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC LIMIT 1"),
            [],
            |r| r.get(0),
        )
        .unwrap()
    };
    let scopes = [
        ("busiest account", Entity::Account(busiest("actor_upn"))),
        ("busiest ip", Entity::Ip(busiest("ip"))),
        (
            "busiest session",
            Entity::Session(busiest("entra_session_id")),
        ),
        ("busiest device", Entity::Device(busiest("device_id"))),
    ];
    let time = |label: &str, f: &dyn Fn() -> String| {
        let t = std::time::Instant::now();
        let out = f();
        println!("{label}: {:.3}s  {out}", t.elapsed().as_secs_f64());
    };
    for (name, e) in &scopes {
        time(&format!("{name} summary"), &|| {
            let s = entity::summary(conn, e, None, None).unwrap();
            format!("{} events, {:?}", s.events, s.distinct)
        });
        for of in [
            PivotOf::Accounts,
            PivotOf::Ips,
            PivotOf::Devices,
            PivotOf::Sessions,
            PivotOf::DeviceChanges,
        ] {
            time(&format!("{name} pivot {of:?}"), &|| match entity::pivot(
                conn, e, of, None, None, None,
            ) {
                Ok(page) => format!("{} of {} rows", page.rows.len(), page.total),
                Err(err) => format!("{err}"),
            });
        }
        time(&format!("{name} findings"), &|| {
            format!(
                "{} findings",
                entity::findings(conn, e, None, None).unwrap().len()
            )
        });
    }
}
