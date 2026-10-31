//! `case::investigate`: one account, one window — its sessions, what each reached, the mail around it, its
//! configuration changes. Synthetic rows only: `events` rows inserted directly, evidence rows through the shared
//! inserter.

#[path = "common/detect.rs"]
mod detect;

use chrono::{DateTime, TimeZone, Utc};
use detect::insert_row;
use serde_json::json;
use sparrow_core::Case;
use sparrow_core::case::access::{Category, ScopeSource, report_with};
use sparrow_core::case::investigate::investigate;
use sparrow_core::case::marks::ValueKind;

const JDOE: &str = "jdoe@contoso.example";
const ATTACK_IP: &str = "203.0.113.45";
const OLD_IP: &str = "198.51.100.1";
const E1: &str = "e1e1e1e1-0000-4000-8000-000000000001";

fn at(day: u32, h: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, day, h, 0, 0).unwrap()
}

fn ts(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.6f+00").to_string()
}

struct Ev<'a> {
    table: &'a str,
    key: &'a str,
    t: DateTime<Utc>,
    category: &'a str,
    ip: Option<&'a str>,
    session: Option<&'a str>,
    operation: &'a str,
    result: Option<&'a str>,
    ua: Option<&'a str>,
}

fn ev<'a>(table: &'a str, key: &'a str, t: DateTime<Utc>) -> Ev<'a> {
    Ev {
        table,
        key,
        t,
        category: "other",
        ip: None,
        session: None,
        operation: "Op",
        result: None,
        ua: None,
    }
}

fn put(case: &Case, e: &Ev) {
    case.conn()
        .execute(
            "INSERT INTO events (source_table, record_key, source, event_time, category, tenant_key, operation, result, \
             actor_upn, ip, ip_country, asn, asn_org, ip_kind, entra_session_id, user_agent) \
             VALUES (?, ?, 'ual', CAST(? AS TIMESTAMPTZ), CAST(? AS event_category), 'contoso', ?, ?, ?, ?, 'NL', \
             64500, 'Example Hosting', 'hosting', ?, ?)",
            duckdb::params![
                e.table,
                e.key,
                ts(e.t),
                e.category,
                e.operation,
                e.result,
                JDOE,
                e.ip,
                e.session,
                e.ua
            ],
        )
        .unwrap();
}

fn ual_record(case: &Case, key: &str, session: &str, t: DateTime<Utc>) {
    insert_row(
        case,
        "ual_events",
        "contoso",
        json!({"record_id": key, "user_upn": JDOE, "session_id": session, "operation": "Op",
               "workload": "Exchange", "event_time": ts(t)}),
    );
}

fn trace(
    case: &Case,
    sender: &str,
    recipient: &str,
    subject: &str,
    t: DateTime<Utc>,
    direction: &str,
) {
    insert_row(
        case,
        "message_trace",
        "contoso",
        json!({"sender": sender, "recipient": recipient, "subject": subject, "received": ts(t),
               "direction": direction, "status": "Delivered", "internet_message_id": format!("<{subject}@x>")}),
    );
}

const U2: &str = "20000000-0000-4000-8000-000000000002";

/// History on 25 Aug from OLD_IP; on 2 Sep an AiTM sign-in (E1 from ATTACK_IP) and its mail read, an Exchange-only
/// session, a read from the old address, an inbox rule; the lure the evening before.
fn case() -> Case {
    let case = Case::in_memory().unwrap();
    put(
        &case,
        &Ev {
            ip: Some(OLD_IP),
            ..ev("signins", "h1", at(25, 9).with_month(8).unwrap())
        },
    );
    put(
        &case,
        &Ev {
            ip: Some(ATTACK_IP),
            session: Some(E1),
            category: "auth",
            operation: "UserLoggedIn",
            result: Some("0"),
            ua: Some("Mozilla/5.0 attacker"),
            ..ev("signins", "s1", at(2, 10))
        },
    );
    put(
        &case,
        &Ev {
            ip: Some(ATTACK_IP),
            session: Some(E1),
            ..ev("ual_events", "u1", at(2, 11))
        },
    );
    ual_record(&case, U2, "X1-Exchange", at(2, 12));
    put(
        &case,
        &Ev {
            ip: Some("192.0.2.5"),
            ..ev("ual_events", U2, at(2, 12))
        },
    );
    put(
        &case,
        &Ev {
            ip: Some(OLD_IP),
            ..ev("ual_events", "u3", at(2, 13))
        },
    );
    put(
        &case,
        &Ev {
            ip: Some(ATTACK_IP),
            session: Some(E1),
            category: "config_change",
            operation: "New-InboxRule",
            ..ev("ual_events", "u4", at(2, 14))
        },
    );
    trace(
        &case,
        "lure@vendor.example",
        JDOE,
        "Invoice due",
        at(1, 20),
        "Inbound",
    );
    trace(
        &case,
        "old@vendor.example",
        JDOE,
        "Old news",
        at(29, 8).with_month(8).unwrap(),
        "Inbound",
    );
    trace(
        &case,
        JDOE,
        "payroll@contoso.example",
        "Bank change",
        at(2, 15),
        "Outbound",
    );
    case.conn()
        .execute(
            "INSERT INTO findings (finding_id, fingerprint, tenant_key, severity, title, actor_upn, first_seen, last_seen, \
             created_by, created_at, updated_at) VALUES ('f1', 'fp', 'contoso', 'high', 'Inbox rule', ?, \
             CAST(? AS TIMESTAMPTZ), CAST(? AS TIMESTAMPTZ), 'rule', now(), now())",
            duckdb::params![JDOE, ts(at(2, 14)), ts(at(2, 14))],
        )
        .unwrap();
    case.conn()
        .execute(
            "INSERT INTO finding_evidence (finding_id, source_table, record_key, event_time, role, added_run_id) \
             VALUES ('f1', 'ual_events', 'u4', CAST(? AS TIMESTAMPTZ), 'trigger', 1)",
            [ts(at(2, 14))],
        )
        .unwrap();
    case
}

use chrono::Datelike;

#[test]
fn sessions_group_by_entra_session_then_exchange_then_ip() {
    let case = case();
    let inv = investigate(case.conn(), "JDoe@Contoso.example", at(2, 0), at(3, 0)).unwrap();
    assert_eq!(inv.account, JDOE);
    let keys: Vec<&str> = inv.sessions.iter().map(|s| s.key.as_str()).collect();
    assert_eq!(
        keys,
        vec![E1, "exchange:x1-exchange", &format!("ip:{OLD_IP}")]
    );
    let e1 = &inv.sessions[0];
    assert_eq!((e1.first, e1.last), (at(2, 10), at(2, 14)));
    assert_eq!(e1.events, 3);
    assert_eq!(e1.ips.len(), 1);
    assert_eq!(e1.ips[0].ip, ATTACK_IP);
    assert_eq!(e1.ips[0].asn, Some(64500));
    assert_eq!(e1.user_agents, vec!["Mozilla/5.0 attacker".to_string()]);
    assert_eq!(e1.signin_results.get("0"), Some(&1));
    assert_eq!(e1.findings, vec!["f1".to_string()]);
}

#[test]
fn a_new_ip_is_marked_new() {
    let case = case();
    let inv = investigate(case.conn(), JDOE, at(2, 0), at(3, 0)).unwrap();
    let ip = |key: &str| inv.sessions.iter().find(|s| s.key == key).unwrap().ips[0].new_for_account;
    assert!(ip(E1), "seen only in the window");
    assert!(!ip(&format!("ip:{OLD_IP}")), "seen a week before");
}

#[test]
fn reach_matches_access_for_the_session() {
    let case = case();
    let inv = investigate(case.conn(), JDOE, at(2, 0), at(3, 0)).unwrap();
    let e1 = &inv.sessions[0];
    let src = ScopeSource {
        adhoc: vec![(ValueKind::Session, E1.to_string())],
        ..ScopeSource::accepted()
    };
    let r = report_with(case.conn(), Some(JDOE), &src).unwrap();
    for c in Category::ALL {
        let want = r.accounts[0]
            .items
            .iter()
            .filter(|i| i.category == c)
            .count() as u64;
        let got = e1
            .reach
            .iter()
            .find(|x| x.category == c)
            .map_or(0, |x| x.items);
        assert_eq!(got, want, "{c:?}");
    }
    assert!(e1.reach.iter().any(|x| x.items > 0), "{:?}", e1.reach);
}

#[test]
fn mail_in_includes_the_day_before() {
    let case = case();
    let inv = investigate(case.conn(), JDOE, at(2, 0), at(3, 0)).unwrap();
    let subjects: Vec<&str> = inv
        .mail_in
        .iter()
        .filter_map(|m| m.subject.as_deref())
        .collect();
    assert_eq!(subjects, vec!["Invoice due"]);
    assert_eq!(
        inv.mail_in[0].sender.as_deref(),
        Some("lure@vendor.example")
    );
    let out: Vec<&str> = inv
        .mail_out
        .iter()
        .filter_map(|m| m.subject.as_deref())
        .collect();
    assert_eq!(out, vec!["Bank change"]);
    let ops: Vec<&str> = inv
        .config_changes
        .iter()
        .map(|c| c.operation.as_str())
        .collect();
    assert_eq!(ops, vec!["New-InboxRule"]);
    assert_eq!(inv.config_changes[0].row, "ual_events:u4");
}

#[test]
fn an_empty_window_lists_the_finding_times() {
    let case = case();
    let inv = investigate(case.conn(), JDOE, at(20, 0), at(21, 0)).unwrap();
    assert!(inv.sessions.is_empty() && inv.mail_in.is_empty() && inv.config_changes.is_empty());
    assert_eq!(inv.finding_times.len(), 1);
    assert_eq!(inv.finding_times[0].finding_id, "f1");
    assert_eq!(inv.finding_times[0].first_seen, Some(at(2, 14)));
}

#[test]
fn next_steps_name_each_session() {
    let case = case();
    let inv = investigate(case.conn(), JDOE, at(2, 0), at(3, 0)).unwrap();
    let cmds: Vec<String> = inv.next.iter().map(|n| n.args.join(" ")).collect();
    assert!(
        cmds.iter()
            .any(|c| c.contains(&format!("--value session={E1}"))),
        "{cmds:?}"
    );
    assert!(
        cmds.iter()
            .any(|c| c.starts_with("access") && c.contains(&format!("--session {E1}"))),
        "{cmds:?}"
    );
    assert!(
        cmds.iter()
            .any(|c| c.contains(&format!("--value ip={OLD_IP}"))),
        "{cmds:?}"
    );
}

const U5: &str = "20000000-0000-4000-8000-000000000005";
const U6: &str = "20000000-0000-4000-8000-000000000006";

#[test]
fn an_exchange_session_of_an_entra_session_joins_it() {
    // As the access report propagates: a UAL record with only the Exchange session of an Entra session's record (and
    // no IP of its own, or that record's IP) is that Entra session's.
    let case = case();
    ual_record(&case, U5, "X9-Shared", at(2, 16));
    put(
        &case,
        &Ev {
            ip: Some(ATTACK_IP),
            session: Some(E1),
            ..ev("ual_events", U5, at(2, 16))
        },
    );
    ual_record(&case, U6, "X9-Shared", at(2, 17));
    put(
        &case,
        &Ev {
            ..ev("ual_events", U6, at(2, 17))
        },
    );
    let inv = investigate(case.conn(), JDOE, at(2, 0), at(3, 0)).unwrap();
    let keys: Vec<&str> = inv.sessions.iter().map(|s| s.key.as_str()).collect();
    assert!(!keys.contains(&"exchange:x9-shared"), "{keys:?}");
    let e1 = inv.sessions.iter().find(|s| s.key == E1).unwrap();
    assert_eq!(e1.events, 5);
}

const M1: &str = "30000000-0000-4000-8000-000000000001";
const M2: &str = "30000000-0000-4000-8000-000000000002";

fn mia(case: &Case, record: &str, imid: &str, t: DateTime<Utc>) {
    insert_row(
        case,
        "ual_events",
        "contoso",
        json!({"record_id": record, "user_upn": JDOE, "mailbox_upn": JDOE, "operation": "MailItemsAccessed",
               "workload": "Exchange", "event_time": ts(t)}),
    );
    insert_row(
        case,
        "mail_items_accessed",
        "contoso",
        json!({"record_id": record, "item_ordinal": 0, "access_type": "bind", "folder_path": "\\\\Inbox",
               "internet_message_id": imid, "size_bytes": 10, "user_upn": JDOE, "event_time": ts(t)}),
    );
}

#[test]
fn a_message_both_sessions_read_counts_in_each() {
    // The user's own session read the message first, the attacker's later: each session's reach has it, as
    // `sparrow access --session` for each would.
    let case = case();
    mia(&case, M1, "<shared@x>", at(2, 10));
    put(
        &case,
        &Ev {
            ip: Some(OLD_IP),
            operation: "MailItemsAccessed",
            ..ev("ual_events", M1, at(2, 10))
        },
    );
    mia(&case, M2, "<shared@x>", at(2, 11));
    put(
        &case,
        &Ev {
            ip: Some(ATTACK_IP),
            session: Some(E1),
            operation: "MailItemsAccessed",
            ..ev("ual_events", M2, at(2, 11))
        },
    );
    let inv = investigate(case.conn(), JDOE, at(2, 0), at(3, 0)).unwrap();
    let read = |key: &str| {
        inv.sessions
            .iter()
            .find(|s| s.key == key)
            .unwrap()
            .reach
            .iter()
            .find(|r| r.category == Category::MailRead)
            .map_or(0, |r| r.items)
    };
    assert_eq!(read(E1), 1);
    assert_eq!(read(&format!("ip:{OLD_IP}")), 1);
}

#[test]
fn a_message_read_before_the_window_and_in_it_counts_in_the_window() {
    let case = case();
    mia(&case, M1, "<again@x>", at(1, 9));
    put(
        &case,
        &Ev {
            ip: Some(ATTACK_IP),
            session: Some(E1),
            operation: "MailItemsAccessed",
            ..ev("ual_events", M1, at(1, 9))
        },
    );
    mia(&case, M2, "<again@x>", at(2, 11));
    put(
        &case,
        &Ev {
            ip: Some(ATTACK_IP),
            session: Some(E1),
            operation: "MailItemsAccessed",
            ..ev("ual_events", M2, at(2, 11))
        },
    );
    let inv = investigate(case.conn(), JDOE, at(2, 0), at(3, 0)).unwrap();
    let e1 = inv.sessions.iter().find(|s| s.key == E1).unwrap();
    let read = e1
        .reach
        .iter()
        .find(|r| r.category == Category::MailRead)
        .map_or(0, |r| r.items);
    assert_eq!(read, 1, "{:?}", e1.reach);
}

#[test]
fn a_flag_scoped_elsewhere_does_not_touch_the_session() {
    let case = case();
    case.conn()
        .execute_batch(&format!(
            "INSERT INTO value_flags (flag_id, kind, value, level, scope_kind, scope_value, decided_by, decided_at, review_state) VALUES \
             ('vf1', 'ip', '{ATTACK_IP}', 'malicious', 'account', 'bob@contoso.example', 'analyst:c', now(), 'accepted'), \
             ('vf2', 'ip', '{OLD_IP}', 'suspicious', 'account', '{JDOE}', 'analyst:c', now(), 'accepted')"
        ))
        .unwrap();
    let inv = investigate(case.conn(), JDOE, at(2, 0), at(3, 0)).unwrap();
    let flags = |key: &str| {
        inv.sessions
            .iter()
            .find(|s| s.key == key)
            .unwrap()
            .flags
            .clone()
    };
    assert!(
        flags(E1).is_empty(),
        "Bob's flag is not this account's: {:?}",
        flags(E1)
    );
    assert_eq!(flags(&format!("ip:{OLD_IP}")).len(), 1);
}

#[test]
fn new_follows_the_entity_pivot_rule() {
    // First seen after the account's first day: new, also in a later window.
    let case = case();
    put(
        &case,
        &Ev {
            ip: Some(ATTACK_IP),
            session: Some(E1),
            ..ev("ual_events", "u9", at(3, 9))
        },
    );
    let inv = investigate(case.conn(), JDOE, at(3, 0), at(4, 0)).unwrap();
    assert!(inv.sessions[0].ips[0].new_for_account);
}
