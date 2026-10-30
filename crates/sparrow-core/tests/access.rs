//! The access report (`case::access`): what the records the analyst's accepted malicious flags tie to the attacker
//! reached. Cases are built from synthetic rows: `events` rows inserted directly (as in `tests/marks.rs`), evidence rows
//! through the shared inserter, flags written straight into `value_flags` / `event_flags` in each review state.

#[path = "common/detect.rs"]
mod detect;

use chrono::{DateTime, Duration, TimeZone, Utc};
use detect::insert_row;
use serde_json::json;
use sparrow_core::Case;
use sparrow_core::case::access::{self, Attribution};

const JDOE: &str = "jdoe@contoso.example";
const BOB: &str = "bob@contoso.example";
const IP: &str = "203.0.113.45";
const SESSION: &str = "2222aaaa-2222-4222-8222-22222222bbbb";
const DEVICE: &str = "d3d3d3d3-0000-4000-8000-00000000abcd";

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 1, 10, 0, 0).unwrap()
}

fn ts(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.6f+00").to_string()
}

/// One `events` row; unset columns are NULL.
#[derive(Default, Clone)]
struct Ev {
    table: &'static str,
    key: &'static str,
    actor: Option<&'static str>,
    owner: Option<&'static str>,
    ip: Option<&'static str>,
    prefix: Option<&'static str>,
    asn: Option<i32>,
    device: Option<&'static str>,
    session: Option<&'static str>,
    category: Option<&'static str>,
    workload: Option<&'static str>,
    operation: Option<&'static str>,
    at: i64,
}

fn ual(key: &'static str) -> Ev {
    Ev {
        table: "ual_events",
        key,
        actor: Some(JDOE),
        ..Ev::default()
    }
}

/// `at` is seconds after `t0()`.
fn put(case: &Case, e: &Ev) {
    case.conn()
        .execute(
            "INSERT INTO events (source_table, record_key, source, event_time, category, tenant_key, workload, operation, \
             actor_upn, owner_upn, ip, ip_prefix, asn, device_id, entra_session_id) \
             VALUES (?, ?, 'ual', CAST(? AS TIMESTAMPTZ), CAST(? AS event_category), 'contoso', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            duckdb::params![
                e.table,
                e.key,
                ts(t0() + Duration::seconds(e.at)),
                e.category.unwrap_or("other"),
                e.workload,
                e.operation,
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

/// A UAL record whose top-level SessionId (`ual_events.session_id`, an Exchange session) is `session`.
fn ual_record(case: &Case, key: &str, user: &str, session: &str) {
    insert_row(
        case,
        "ual_events",
        "contoso",
        json!({"record_id": key, "user_upn": user, "session_id": session, "operation": "MailItemsAccessed",
               "workload": "Exchange", "event_time": ts(t0())}),
    );
}

#[derive(Clone, Copy)]
enum State {
    Accepted,
    Pending,
    Discarded,
    Removed,
}

fn review(state: State) -> (&'static str, &'static str, bool) {
    match state {
        State::Accepted => ("analyst:carlos", "accepted", false),
        State::Pending => ("agent:triage", "pending_review", false),
        State::Discarded => ("agent:triage", "discarded", false),
        State::Removed => ("analyst:carlos", "accepted", true),
    }
}

static FLAG_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn vflag(case: &Case, kind: &str, value: &str, scope: Option<(&str, &str)>, state: State) {
    let (by, rs, removed) = review(state);
    let id = format!(
        "vf{}",
        FLAG_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    case.conn()
        .execute(
            "INSERT INTO value_flags (flag_id, kind, value, level, scope_kind, scope_value, decided_by, decided_at, \
             review_state, removed_at) VALUES (?, CAST(? AS flag_value_kind), ?, 'malicious', ?, ?, ?, CAST(? AS TIMESTAMPTZ), \
             CAST(? AS review_state), CASE WHEN ? THEN CAST(? AS TIMESTAMPTZ) END)",
            duckdb::params![
                id,
                kind,
                value,
                scope.map(|s| s.0),
                scope.map(|s| s.1),
                by,
                ts(t0()),
                rs,
                removed,
                ts(t0())
            ],
        )
        .unwrap();
}

fn rflag(case: &Case, table: &str, key: &str, state: State) {
    let (by, rs, _) = review(state);
    case.conn()
        .execute(
            "INSERT INTO event_flags (source_table, record_key, level, decided_by, decided_at, review_state, batch_id) \
             VALUES (?, ?, 'malicious', ?, CAST(? AS TIMESTAMPTZ), CAST(? AS review_state), 'b1')",
            duckdb::params![table, key, by, ts(t0()), rs],
        )
        .unwrap();
}

/// (record_key, attribution) of every attributed record, sorted.
fn keys(case: &Case) -> Vec<(String, Attribution)> {
    let mut out: Vec<_> = access::attributed(case.conn(), None)
        .unwrap()
        .into_iter()
        .map(|a| (a.record_key, a.attribution))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn attributes_by_session_ip_prefix_device_and_row() {
    let case = Case::in_memory().unwrap();
    put(
        &case,
        &Ev {
            session: Some(SESSION),
            ip: Some("198.51.100.1"),
            ..ual("k1")
        },
    );
    put(
        &case,
        &Ev {
            ip: Some(IP),
            at: 1,
            ..ual("k2")
        },
    );
    put(
        &case,
        &Ev {
            ip: Some("198.18.5.7"),
            prefix: Some("198.18.5.0/24"),
            at: 2,
            ..ual("k3")
        },
    );
    put(
        &case,
        &Ev {
            device: Some(DEVICE),
            at: 3,
            ..ual("k4")
        },
    );
    put(
        &case,
        &Ev {
            ip: Some("198.51.100.9"),
            at: 4,
            ..ual("k5")
        },
    );
    put(
        &case,
        &Ev {
            asn: Some(64500),
            ip: Some("192.0.2.8"),
            at: 5,
            ..ual("k6")
        },
    );
    put(
        &case,
        &Ev {
            ip: Some("198.51.100.2"),
            at: 6,
            ..ual("k7")
        },
    );
    vflag(&case, "session", SESSION, None, State::Accepted);
    vflag(&case, "ip", IP, None, State::Accepted);
    vflag(&case, "ip_prefix", "198.18.5.0/24", None, State::Accepted);
    vflag(&case, "device", DEVICE, None, State::Accepted);
    rflag(&case, "ual_events", "k5", State::Accepted);
    vflag(
        &case,
        "asn",
        "64500",
        Some(("account", JDOE)),
        State::Accepted,
    );
    use Attribution::*;
    let want: Vec<(String, Attribution)> = [
        ("k1", Session),
        ("k2", Ip),
        ("k3", Ip),
        ("k4", Device),
        ("k5", Row),
        ("k6", Ip),
    ]
    .into_iter()
    .map(|(k, a)| (k.to_string(), a))
    .collect();
    assert_eq!(keys(&case), want);
    let all = access::attributed(case.conn(), Some("JDOE@contoso.example")).unwrap();
    assert_eq!(all.len(), 6);
    assert!(all.iter().all(|a| a.account == JDOE));
}

#[test]
fn strongest_attribution_wins() {
    let case = Case::in_memory().unwrap();
    put(
        &case,
        &Ev {
            session: Some(SESSION),
            ip: Some(IP),
            ..ual("k1")
        },
    );
    vflag(&case, "session", SESSION, None, State::Accepted);
    vflag(&case, "ip", IP, None, State::Accepted);
    rflag(&case, "ual_events", "k1", State::Accepted);
    assert_eq!(keys(&case), vec![("k1".to_string(), Attribution::Session)]);
}

#[test]
fn asn_flag_without_account_scope_attributes_nothing() {
    let case = Case::in_memory().unwrap();
    put(
        &case,
        &Ev {
            asn: Some(64500),
            ip: Some("192.0.2.8"),
            ..ual("k1")
        },
    );
    vflag(&case, "asn", "64500", None, State::Accepted);
    assert!(keys(&case).is_empty());
}

#[test]
fn account_flag_attributes_nothing() {
    let case = Case::in_memory().unwrap();
    put(
        &case,
        &Ev {
            ip: Some("192.0.2.8"),
            ..ual("k1")
        },
    );
    vflag(&case, "account", JDOE, None, State::Accepted);
    assert!(keys(&case).is_empty());
}

#[test]
fn a_scoped_flag_attributes_only_inside_its_scope() {
    let case = Case::in_memory().unwrap();
    put(
        &case,
        &Ev {
            ip: Some(IP),
            ..ual("k1")
        },
    );
    put(
        &case,
        &Ev {
            ip: Some(IP),
            actor: Some(BOB),
            at: 1,
            ..ual("k2")
        },
    );
    vflag(&case, "ip", IP, Some(("account", BOB)), State::Accepted);
    assert_eq!(keys(&case), vec![("k2".to_string(), Attribution::Ip)]);
}

#[test]
fn an_account_scope_matches_the_actor_not_the_mailbox_owner() {
    // An IP flagged for jdoe: bob reading jdoe's mailbox from that IP is not jdoe's attacker activity.
    let case = Case::in_memory().unwrap();
    put(
        &case,
        &Ev {
            ip: Some(IP),
            actor: Some(BOB),
            owner: Some(JDOE),
            ..ual("k1")
        },
    );
    put(
        &case,
        &Ev {
            ip: Some(IP),
            at: 1,
            ..ual("k2")
        },
    );
    vflag(&case, "ip", IP, Some(("account", JDOE)), State::Accepted);
    assert_eq!(keys(&case), vec![("k2".to_string(), Attribution::Ip)]);
}

#[test]
fn exchange_session_inherits_from_an_attributed_record() {
    let case = Case::in_memory().unwrap();
    let (a, b, c) = (
        "00000000-0000-4000-8000-00000000000a",
        "00000000-0000-4000-8000-00000000000b",
        "00000000-0000-4000-8000-00000000000c",
    );
    ual_record(&case, a, JDOE, "X1");
    ual_record(&case, b, JDOE, "x1");
    ual_record(&case, c, BOB, "X1");
    put(
        &case,
        &Ev {
            ip: Some(IP),
            ..ual(a)
        },
    );
    put(
        &case,
        &Ev {
            ip: Some("198.51.100.1"),
            at: 1,
            ..ual(b)
        },
    );
    put(
        &case,
        &Ev {
            ip: Some("198.51.100.1"),
            actor: Some(BOB),
            at: 2,
            ..ual(c)
        },
    );
    vflag(&case, "ip", IP, Some(("account", JDOE)), State::Accepted);
    assert_eq!(
        keys(&case),
        vec![
            (a.to_string(), Attribution::Ip),
            (b.to_string(), Attribution::Session)
        ]
    );
}

#[test]
fn a_session_flag_matches_the_exchange_session_id_too() {
    let case = Case::in_memory().unwrap();
    let a = "00000000-0000-4000-8000-0000000000a1";
    ual_record(&case, a, JDOE, &SESSION.to_uppercase());
    put(
        &case,
        &Ev {
            ip: Some("198.51.100.1"),
            ..ual(a)
        },
    );
    vflag(&case, "session", SESSION, None, State::Accepted);
    assert_eq!(keys(&case), vec![(a.to_string(), Attribution::Session)]);
}

#[test]
fn ignores_removed_discarded_and_pending_flags() {
    let case = Case::in_memory().unwrap();
    put(
        &case,
        &Ev {
            ip: Some(IP),
            ..ual("k1")
        },
    );
    put(
        &case,
        &Ev {
            ip: Some("198.51.100.1"),
            at: 1,
            ..ual("k2")
        },
    );
    put(
        &case,
        &Ev {
            ip: Some("198.51.100.2"),
            at: 2,
            ..ual("k3")
        },
    );
    put(
        &case,
        &Ev {
            ip: Some("198.51.100.3"),
            at: 3,
            ..ual("k4")
        },
    );
    vflag(&case, "ip", IP, None, State::Pending);
    vflag(&case, "ip", "198.51.100.1", None, State::Removed);
    vflag(&case, "ip", "198.51.100.2", None, State::Discarded);
    rflag(&case, "ual_events", "k4", State::Discarded);
    assert!(keys(&case).is_empty());
    assert_eq!(access::pending_flags(case.conn()).unwrap(), 1);
    rflag(&case, "ual_events", "k3", State::Pending);
    assert_eq!(access::pending_flags(case.conn()).unwrap(), 2);
}
