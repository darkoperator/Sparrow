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
    // Within jdoe's Exchange session X1: a (flagged IP) is direct; d (no IP of its own) inherits the session; b, from an
    // unflagged IP, is the real user's client sharing a long-lived session and stays out; c is another account's.
    let case = Case::in_memory().unwrap();
    let (a, b, c, d) = (
        "00000000-0000-4000-8000-00000000000a",
        "00000000-0000-4000-8000-00000000000b",
        "00000000-0000-4000-8000-00000000000c",
        "00000000-0000-4000-8000-00000000000d",
    );
    ual_record(&case, a, JDOE, "X1");
    ual_record(&case, b, JDOE, "x1");
    ual_record(&case, c, BOB, "X1");
    ual_record(&case, d, JDOE, "X1");
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
    put(&case, &Ev { at: 3, ..ual(d) });
    vflag(&case, "ip", IP, Some(("account", JDOE)), State::Accepted);
    assert_eq!(
        keys(&case),
        vec![
            (a.to_string(), Attribution::Ip),
            (d.to_string(), Attribution::Session)
        ]
    );
}

#[test]
fn propagation_never_makes_windows() {
    // A propagated record a day later must not open a window that time-attributes the account's identityless records.
    let case = Case::in_memory().unwrap();
    let (a, d) = (
        "00000000-0000-4000-8000-0000000000aa",
        "00000000-0000-4000-8000-0000000000dd",
    );
    ual_record(&case, a, JDOE, "X1");
    ual_record(&case, d, JDOE, "X1");
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
            at: 86_400,
            ..ual(d)
        },
    );
    put(
        &case,
        &Ev {
            workload: Some("MicrosoftTeams"),
            operation: Some("ChatRetrieved"),
            at: 86_400 + 60,
            ..ual("t1")
        },
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let kinds: Vec<_> = access::scope(case.conn(), JDOE)
        .unwrap()
        .into_iter()
        .map(|s| s.kind)
        .collect();
    assert_eq!(kinds, vec!["ip"]);
    assert!(!keys(&case).iter().any(|(k, _)| k == "t1"));
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

// Task 2: windows and time attribution.

fn at(h: i64, m: i64) -> i64 {
    h * 3600 + m * 60
}

/// A Teams read with no IP and no session (as Graph-only reads are), `secs` after t0.
fn identityless(key: &'static str, secs: i64) -> Ev {
    Ev {
        workload: Some("MicrosoftTeams"),
        operation: Some("ChatRetrieved"),
        at: secs,
        ..ual(key)
    }
}

#[test]
fn windows_split_at_gaps_over_an_hour() {
    let case = Case::in_memory().unwrap();
    for (k, s) in [("k1", at(0, 0)), ("k2", at(0, 40)), ("k3", at(3, 0))] {
        put(
            &case,
            &Ev {
                ip: Some(IP),
                at: s,
                ..ual(k)
            },
        );
    }
    vflag(&case, "ip", IP, None, State::Accepted);
    let scope = access::scope(case.conn(), JDOE).unwrap();
    assert_eq!(scope.len(), 1);
    assert_eq!(
        (scope[0].kind.as_str(), scope[0].value.as_str()),
        ("ip", IP)
    );
    let w: Vec<_> = scope[0].windows.iter().map(|w| (w.start, w.end)).collect();
    assert_eq!(
        w,
        vec![
            (t0(), t0() + Duration::minutes(100)),
            (t0() + Duration::hours(3), t0() + Duration::hours(4))
        ]
    );
}

#[test]
fn day_1_and_day_20_give_two_windows() {
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
            at: 19 * 86_400,
            ..ual("k2")
        },
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    assert_eq!(
        access::scope(case.conn(), JDOE).unwrap()[0].windows.len(),
        2
    );
}

#[test]
fn time_attribution_takes_identityless_records_inside_a_window() {
    let case = Case::in_memory().unwrap();
    put(
        &case,
        &Ev {
            ip: Some(IP),
            ..ual("k1")
        },
    );
    put(&case, &identityless("t1", at(0, 20)));
    put(&case, &identityless("t2", at(2, 30)));
    vflag(&case, "ip", IP, None, State::Accepted);
    assert_eq!(
        keys(&case),
        vec![
            ("k1".to_string(), Attribution::Ip),
            ("t1".to_string(), Attribution::Time)
        ]
    );
}

#[test]
fn time_attribution_skips_records_with_their_own_identity() {
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
            ..identityless("t1", at(0, 20))
        },
    );
    put(
        &case,
        &Ev {
            session: Some(SESSION),
            ..identityless("t2", at(0, 21))
        },
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    assert_eq!(keys(&case), vec![("k1".to_string(), Attribution::Ip)]);
}

#[test]
fn time_never_adds_an_account() {
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
            actor: Some(BOB),
            ..identityless("t1", at(0, 20))
        },
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    assert_eq!(keys(&case), vec![("k1".to_string(), Attribution::Ip)]);
}

#[test]
fn time_attribution_follows_the_actor_not_the_owner() {
    // Mail delivered to jdoe (owner only) and bob reading jdoe's mailbox are not jdoe's attacker activity.
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
            actor: None,
            owner: Some(JDOE),
            ..identityless("t1", at(0, 10))
        },
    );
    put(
        &case,
        &Ev {
            actor: Some(BOB),
            owner: Some(JDOE),
            ..identityless("t2", at(0, 11))
        },
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    assert_eq!(keys(&case), vec![("k1".to_string(), Attribution::Ip)]);
}

// Task 3: mail read and mail sent.

use sparrow_core::case::access::{Category, Item};

/// A UAL record and its `events` row: `audit` becomes AuditData, `ip` the client IP of both.
#[allow(clippy::too_many_arguments)]
fn ual_ev(
    case: &Case,
    key: &'static str,
    op: &'static str,
    user: &'static str,
    mailbox: &str,
    ip: Option<&'static str>,
    secs: i64,
    audit: serde_json::Value,
) {
    let mut f = json!({"record_id": key, "user_upn": user, "mailbox_upn": mailbox, "operation": op,
                       "workload": "Exchange", "event_time": ts(t0() + Duration::seconds(secs)), "audit_data": audit.to_string()});
    if let Some(ip) = ip {
        f["client_ip"] = json!(ip);
    }
    insert_row(case, "ual_events", "contoso", f);
    put(
        case,
        &Ev {
            ip,
            actor: Some(user),
            owner: Some(Box::leak(mailbox.to_lowercase().into_boxed_str())),
            workload: Some("Exchange"),
            operation: Some(op),
            at: secs,
            ..ual(key)
        },
    );
}

fn mia_item(
    case: &Case,
    record: &str,
    ord: i32,
    access: &str,
    folder: &str,
    imid: Option<&str>,
    size: i64,
) {
    insert_row(
        case,
        "mail_items_accessed",
        "contoso",
        json!({"record_id": record, "item_ordinal": ord, "access_type": access, "folder_path": folder,
               "internet_message_id": imid, "size_bytes": size}),
    );
}

fn trace(case: &Case, imid: &str, sender: &str, recipient: &str, subject: &str, secs: i64) {
    insert_row(
        case,
        "message_trace",
        "contoso",
        json!({"record_key": format!("mt-{imid}-{recipient}"), "internet_message_id": imid, "sender": sender,
               "recipient": recipient, "subject": subject, "received": ts(t0() - Duration::seconds(secs))}),
    );
}

fn items_of(case: &Case, category: Category) -> Vec<Item> {
    access::items(case.conn(), None)
        .unwrap()
        .into_iter()
        .filter(|i| i.category == category)
        .collect()
}

const R1: &str = "10000000-0000-4000-8000-000000000001";
const R2: &str = "10000000-0000-4000-8000-000000000002";
const R3: &str = "10000000-0000-4000-8000-000000000003";

#[test]
fn mail_read_lists_one_item_per_message_with_trace_details() {
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R1,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some(IP),
        0,
        json!({}),
    );
    mia_item(&case, R1, 0, "bind", "\\Inbox", Some("<a@x>"), 1000);
    mia_item(&case, R1, 1, "bind", "\\Inbox", Some("<b@x>"), 2000);
    trace(
        &case,
        "<a@x>",
        "ap@vendor.example",
        "jdoe@contoso.example",
        "Q3 invoices",
        3600,
    );
    trace(
        &case,
        "<a@x>",
        "ap@vendor.example",
        "amy@contoso.example",
        "Q3 invoices",
        3600,
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let items = items_of(&case, Category::MailRead);
    assert_eq!(items.len(), 2);
    let a = items
        .iter()
        .find(|i| i.record_key == R1 && i.item.is_some())
        .unwrap();
    assert_eq!(a.account, JDOE);
    assert_eq!(a.action, "read");
    assert_eq!(a.attribution, Attribution::Ip);
    assert_eq!(a.item.as_deref(), Some("Q3 invoices"));
    assert_eq!(a.from.as_deref(), Some("ap@vendor.example"));
    assert_eq!(
        a.to.as_deref(),
        Some("amy@contoso.example; jdoe@contoso.example")
    );
    assert_eq!(a.item_time, Some(t0() - Duration::hours(1)));
    assert_eq!(a.location.as_deref(), Some("\\Inbox"));
    assert_eq!(a.size_bytes, Some(1000));
    assert_eq!(a.ip.as_deref(), Some(IP));
    assert_eq!(a.source, "ual_events:MailItemsAccessed");
    assert_eq!((a.owner.as_deref(), a.note.as_deref()), (None, None));
    let b = items.iter().find(|i| i.item.is_none()).unwrap();
    assert_eq!(
        (b.from.as_deref(), b.item_time, b.size_bytes),
        (None, None, Some(2000))
    );
}

#[test]
fn sync_is_a_folder_item() {
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R1,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some(IP),
        0,
        json!({}),
    );
    mia_item(&case, R1, 0, "sync", "\\Inbox", None, 0);
    vflag(&case, "ip", IP, None, State::Accepted);
    let items = items_of(&case, Category::MailRead);
    assert_eq!(items.len(), 1);
    assert_eq!(
        (
            items[0].action.as_str(),
            items[0].location.as_deref(),
            items[0].item.as_deref()
        ),
        ("synced", Some("\\Inbox"), None)
    );
}

#[test]
fn a_message_counts_once_and_direct_wins() {
    let case = Case::in_memory().unwrap();
    // Time-attributed first (no IP, inside the window), then direct, then a legacy mailbox-audit sighting.
    ual_ev(
        &case,
        R1,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some(IP),
        600,
        json!({}),
    );
    ual_ev(
        &case,
        R2,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        None,
        900,
        json!({}),
    );
    mia_item(&case, R1, 0, "bind", "\\Inbox", Some("<a@x>"), 10);
    mia_item(&case, R2, 0, "bind", "\\Inbox", Some("<a@x>"), 10);
    insert_row(
        &case,
        "mailbox_audit_legacy",
        "contoso",
        json!({"record_key": "mal-1", "operation": "MailItemsAccessed", "mailbox_upn": JDOE, "client_ip": IP,
               "folder_path": "\\Inbox", "internet_message_ids": ["<a@x>"], "event_time": ts(t0() + Duration::seconds(1200))}),
    );
    put(
        &case,
        &Ev {
            table: "mailbox_audit_legacy",
            key: "mal-1",
            actor: Some(JDOE),
            owner: Some(JDOE),
            ip: Some(IP),
            at: 1200,
            ..Ev::default()
        },
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let items = items_of(&case, Category::MailRead);
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(
        (items[0].attribution, items[0].record_key.as_str()),
        (Attribution::Ip, R1)
    );
}

#[test]
fn send_as_is_filed_under_the_account_with_a_note() {
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R1,
        "SendAs",
        JDOE,
        "ceo@contoso.example",
        Some(IP),
        0,
        json!({"SendAsUserSmtp": "CEO@contoso.example", "Item": {"Subject": "Wire today", "InternetMessageId": "<s@x>"}}),
    );
    trace(
        &case,
        "<s@x>",
        "ceo@contoso.example",
        "cfo@contoso.example",
        "Wire today",
        -5,
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let items = items_of(&case, Category::MailSent);
    assert_eq!(items.len(), 1);
    let s = &items[0];
    assert_eq!((s.account.as_str(), s.action.as_str()), (JDOE, "sent as"));
    assert_eq!(s.item.as_deref(), Some("Wire today"));
    assert_eq!(s.to.as_deref(), Some("cfo@contoso.example"));
    assert_eq!(s.owner.as_deref(), Some("ceo@contoso.example"));
    assert_eq!(s.note.as_deref(), Some("sent as ceo@contoso.example"));
}

#[test]
fn delegate_read_notes_the_mailbox() {
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R3,
        "MailItemsAccessed",
        JDOE,
        "AP@contoso.example",
        Some(IP),
        0,
        json!({}),
    );
    mia_item(&case, R3, 0, "bind", "\\Inbox", Some("<d@x>"), 10);
    vflag(&case, "ip", IP, None, State::Accepted);
    let items = items_of(&case, Category::MailRead);
    assert_eq!(items[0].owner.as_deref(), Some("ap@contoso.example"));
    assert_eq!(
        items[0].note.as_deref(),
        Some("in mailbox ap@contoso.example")
    );
}

fn legacy(case: &Case, key: &'static str, op: &str, ids: &[&str], subjects: &[&str]) {
    insert_row(
        case,
        "mailbox_audit_legacy",
        "contoso",
        json!({"record_key": key, "operation": op, "mailbox_upn": JDOE, "client_ip": IP, "folder_path": "\\Inbox",
               "internet_message_ids": ids, "subjects": subjects, "event_time": ts(t0())}),
    );
    put(
        case,
        &Ev {
            table: "mailbox_audit_legacy",
            key,
            actor: Some(JDOE),
            owner: Some(JDOE),
            ip: Some(IP),
            ..Ev::default()
        },
    );
}

#[test]
fn a_legacy_read_of_several_messages_lists_each() {
    let case = Case::in_memory().unwrap();
    legacy(
        &case,
        "mal-1",
        "MailItemsAccessed",
        &["<a@x>", "<b@x>", "<c@x>"],
        &[],
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    assert_eq!(items_of(&case, Category::MailRead).len(), 3);
}

#[test]
fn a_legacy_send_of_several_messages_lists_each_with_its_subject() {
    let case = Case::in_memory().unwrap();
    legacy(
        &case,
        "mal-2",
        "Send",
        &["<a@x>", "<b@x>"],
        &["First", "Second"],
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let mut got: Vec<_> = items_of(&case, Category::MailSent)
        .into_iter()
        .map(|i| i.item.unwrap())
        .collect();
    got.sort();
    assert_eq!(got, vec!["First", "Second"]);
}

#[test]
fn send_as_without_its_property_falls_back_to_the_mailbox() {
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R1,
        "SendAs",
        JDOE,
        "CEO@contoso.example",
        Some(IP),
        0,
        json!({"Item": {"Subject": "Hi"}}),
    );
    ual_ev(
        &case,
        R2,
        "SendOnBehalf",
        JDOE,
        "JDOE@contoso.example",
        Some(IP),
        1,
        json!({"Item": {"Subject": "Hi 2"}}),
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let items = items_of(&case, Category::MailSent);
    let a = items.iter().find(|i| i.record_key == R1).unwrap();
    assert_eq!(a.note.as_deref(), Some("sent as ceo@contoso.example"));
    let b = items.iter().find(|i| i.record_key == R2).unwrap();
    assert_eq!(
        (b.owner.as_deref(), b.note.as_deref()),
        (None, None),
        "a case-only difference is the same mailbox"
    );
}

// Task 4: attachments, files, Teams, Copilot, other apps.

/// A UAL record of `workload` and its `events` row, by jdoe; `ip` None leaves both without an IP.
#[allow(clippy::too_many_arguments)]
fn ual_w(
    case: &Case,
    key: &'static str,
    workload: &'static str,
    op: &'static str,
    ip: Option<&'static str>,
    secs: i64,
    category: &'static str,
    audit: serde_json::Value,
) {
    let mut f = json!({"record_id": key, "user_upn": JDOE, "operation": op, "workload": workload,
                       "event_time": ts(t0() + Duration::seconds(secs)), "audit_data": audit.to_string(),
                       "object_id": "obj-1", "app_id": "app-9"});
    if let Some(ip) = ip {
        f["client_ip"] = json!(ip);
    }
    insert_row(case, "ual_events", "contoso", f);
    put(
        case,
        &Ev {
            ip,
            workload: Some(workload),
            operation: Some(op),
            category: Some(category),
            at: secs,
            ..ual(key)
        },
    );
}

const R4: &str = "10000000-0000-4000-8000-000000000004";
const R5: &str = "10000000-0000-4000-8000-000000000005";
const R6: &str = "10000000-0000-4000-8000-000000000006";

#[test]
fn attachment_access_is_an_attachment_item() {
    let case = Case::in_memory().unwrap();
    ual_w(
        &case,
        R1,
        "Exchange",
        "AttachmentAccess",
        Some(IP),
        0,
        "other",
        json!({"AttachmentId": "att-1", "AttachmentSizeInBytes": 4096}),
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let a = items_of(&case, Category::Attachment);
    assert_eq!(a.len(), 1);
    assert_eq!(
        (a[0].item.as_deref(), a[0].size_bytes, a[0].action.as_str()),
        (Some("att-1"), Some(4096), "accessed")
    );
    assert!(items_of(&case, Category::Other).is_empty());
}

#[test]
fn file_events_become_file_items() {
    let case = Case::in_memory().unwrap();
    ual_w(
        &case,
        R1,
        "SharePoint",
        "FileDownloaded",
        Some(IP),
        0,
        "other",
        json!({}),
    );
    insert_row(
        &case,
        "file_events",
        "contoso",
        json!({"record_id": R1, "item_type": "file", "is_onenote": false,
        "file_name": "payroll.xlsx", "site_url": "https://contoso.sharepoint.com/sites/hr/", "relative_url": "Shared Documents/payroll.xlsx",
        "application_name": "Microsoft Office"}),
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let f = items_of(&case, Category::File);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].action, "FileDownloaded");
    assert_eq!(f[0].item.as_deref(), Some("payroll.xlsx"));
    assert_eq!(
        f[0].location.as_deref(),
        Some("https://contoso.sharepoint.com/sites/hr/Shared Documents/payroll.xlsx")
    );
    assert_eq!(f[0].app.as_deref(), Some("Microsoft Office"));
    assert!(items_of(&case, Category::Other).is_empty());
}

#[test]
fn sharing_notes_the_target() {
    let case = Case::in_memory().unwrap();
    ual_w(
        &case,
        R1,
        "OneDrive",
        "SharingSet",
        Some(IP),
        0,
        "other",
        json!({}),
    );
    insert_row(
        &case,
        "sharing_events",
        "contoso",
        json!({"record_id": R1, "link_type": "specific_people",
        "target_email": "x@evil.example", "is_external": true}),
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let f = items_of(&case, Category::File);
    assert_eq!(f.len(), 1);
    assert_eq!(
        (f[0].action.as_str(), f[0].note.as_deref()),
        ("SharingSet", Some("shared with x@evil.example (external)"))
    );
}

#[test]
fn file_tile_counts_files_in_one_folder_separately() {
    // SourceRelativeUrl is the item's folder, so the folder alone does not name a file: two files in one folder are
    // two files, and the same file downloaded twice is one.
    let case = Case::in_memory().unwrap();
    for (key, secs, name) in [(R1, 0, "a.pdf"), (R2, 60, "b.pdf"), (R3, 120, "a.pdf")] {
        ual_w(
            &case,
            key,
            "OneDrive",
            "FileDownloaded",
            Some(IP),
            secs,
            "other",
            json!({}),
        );
        insert_row(
            &case,
            "file_events",
            "contoso",
            json!({"record_id": key, "item_type": "file", "is_onenote": false, "file_name": name,
            "site_url": "https://contoso-my.sharepoint.com/personal/jdoe/", "relative_url": "Documents/Desktop",
            "application_name": "Microsoft Office"}),
        );
    }
    vflag(&case, "ip", IP, None, State::Accepted);
    let r = access::report(case.conn(), Some(JDOE)).unwrap();
    let t = tile(&r.accounts[0], Category::File);
    assert_eq!((t.direct, t.by_time), (2, 0));
    assert_eq!(t.qualifier.as_deref(), Some("2 downloaded"));
}

#[test]
fn file_tile_keeps_unnamed_items_and_folders_without_a_site_apart() {
    // Two unnamed items in one folder are two records; one name in two folders (no SiteUrl) is two files; a file
    // reached directly and by time counts once, as direct.
    let case = Case::in_memory().unwrap();
    let rows = [
        (
            R1,
            0,
            Some(IP),
            json!({"site_url": "https://c.sharepoint.com/", "relative_url": "Docs"}),
        ),
        (
            R2,
            60,
            Some(IP),
            json!({"site_url": "https://c.sharepoint.com/", "relative_url": "Docs"}),
        ),
        (
            R3,
            120,
            Some(IP),
            json!({"relative_url": "A", "file_name": "x.pdf"}),
        ),
        (
            R4,
            180,
            Some(IP),
            json!({"relative_url": "B", "file_name": "x.pdf"}),
        ),
        (
            R5,
            240,
            None,
            json!({"relative_url": "B", "file_name": "x.pdf"}),
        ),
    ];
    for (key, secs, ip, mut f) in rows {
        ual_w(
            &case,
            key,
            "SharePoint",
            "FileAccessed",
            ip,
            secs,
            "other",
            json!({}),
        );
        f["record_id"] = json!(key);
        f["item_type"] = json!("file");
        f["is_onenote"] = json!(false);
        insert_row(&case, "file_events", "contoso", f);
    }
    vflag(&case, "ip", IP, None, State::Accepted);
    let f = items_of(&case, Category::File);
    let locs: Vec<_> = f
        .iter()
        .filter(|i| i.item.is_some())
        .map(|i| i.location.as_deref())
        .collect();
    assert!(
        locs.contains(&Some("A")) && locs.contains(&Some("B")),
        "{locs:?}"
    );
    let r = access::report(case.conn(), Some(JDOE)).unwrap();
    let t = tile(&r.accounts[0], Category::File);
    let timed = f.iter().any(|i| i.attribution == Attribution::Time);
    assert!(timed, "R5 should be tied by time");
    assert_eq!((t.direct, t.by_time), (4, 0));
}

#[test]
fn teams_reads_by_time_are_marked_time() {
    let case = Case::in_memory().unwrap();
    ual_w(
        &case,
        R1,
        "Exchange",
        "MailItemsAccessed",
        Some(IP),
        0,
        "other",
        json!({}),
    );
    ual_w(
        &case,
        R2,
        "MicrosoftTeams",
        "ChatRetrieved",
        None,
        600,
        "other",
        json!({"ChatName": "Finance", "ChatThreadId": "19:abc"}),
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let t = items_of(&case, Category::Teams);
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].attribution, Attribution::Time);
    assert_eq!(
        (
            t[0].item.as_deref(),
            t[0].location.as_deref(),
            t[0].action.as_str()
        ),
        (Some("Finance"), Some("19:abc"), "ChatRetrieved")
    );
}

#[test]
fn copilot_lists_each_accessed_resource() {
    let case = Case::in_memory().unwrap();
    ual_w(
        &case,
        R1,
        "Copilot",
        "CopilotInteraction",
        Some(IP),
        0,
        "other",
        json!({"CopilotEventData": {"AppHost": "Outlook",
        "AccessedResources": [{"Name": "Q3.docx", "SiteUrl": "https://contoso.sharepoint.com/q3", "Action": "Read"},
                              {"Name": "Board deck", "Action": "Read"}]}}),
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let mut c: Vec<_> = items_of(&case, Category::Copilot)
        .into_iter()
        .map(|i| (i.item, i.location, i.action, i.note))
        .collect();
    c.sort();
    assert_eq!(
        c,
        vec![
            (
                Some("Board deck".to_string()),
                None,
                "Read".to_string(),
                Some("via Copilot in Outlook".to_string())
            ),
            (
                Some("Q3.docx".to_string()),
                Some("https://contoso.sharepoint.com/q3".to_string()),
                "Read".to_string(),
                Some("via Copilot in Outlook".to_string())
            ),
        ]
    );
}

#[test]
fn copilot_without_resources_is_one_prompt() {
    let case = Case::in_memory().unwrap();
    ual_w(
        &case,
        R1,
        "Copilot",
        "CopilotInteraction",
        Some(IP),
        0,
        "other",
        json!({"CopilotEventData": {"AppHost": "Teams", "AccessedResources": []}}),
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let c = items_of(&case, Category::Copilot);
    assert_eq!(c.len(), 1);
    assert_eq!(
        (
            c[0].item.as_deref(),
            c[0].action.as_str(),
            c[0].note.as_deref()
        ),
        (None, "prompt", Some("Copilot in Teams"))
    );
}

#[test]
fn other_catches_everything_else_but_sign_ins() {
    let case = Case::in_memory().unwrap();
    ual_w(
        &case,
        R4,
        "SharePoint",
        "SearchQueryPerformed",
        Some(IP),
        0,
        "other",
        json!({}),
    );
    insert_row(
        &case,
        "search_queries",
        "contoso",
        json!({"record_id": R4, "workload": "sharepoint", "query_text": "wire instructions"}),
    );
    ual_w(
        &case,
        R5,
        "PowerBI",
        "ViewReport",
        Some(IP),
        1,
        "other",
        json!({}),
    );
    ual_w(
        &case,
        R6,
        "AzureActiveDirectory",
        "UserLoggedIn",
        Some(IP),
        2,
        "auth",
        json!({}),
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let mut o: Vec<_> = items_of(&case, Category::Other)
        .into_iter()
        .map(|i| (i.record_key, i.action, i.item, i.location, i.app))
        .collect();
    o.sort();
    assert_eq!(
        o,
        vec![
            (
                R4.to_string(),
                "SearchQueryPerformed".to_string(),
                Some("wire instructions".to_string()),
                Some("SharePoint".to_string()),
                Some("app-9".to_string())
            ),
            (
                R5.to_string(),
                "ViewReport".to_string(),
                Some("obj-1".to_string()),
                Some("PowerBI".to_string()),
                Some("app-9".to_string())
            ),
        ]
    );
}

#[test]
fn other_items_name_their_application() {
    let case = Case::in_memory().unwrap();
    // A known application id: its name comes from the identities.
    ual_w(
        &case,
        R1,
        "Exchange",
        "Update",
        Some(IP),
        0,
        "other",
        json!({}),
    );
    case.conn()
        .execute_batch(
            "INSERT INTO identities (identity_id, tenant_key, kind, app_id, display_names, aliases) \
             VALUES ('app:app-9', 'contoso', 'app', 'APP-9', ['Outlook Web'], 1)",
        )
        .unwrap();
    // No AppId: Exchange's ClientAppId stands in for it.
    insert_row(
        &case,
        "ual_events",
        "contoso",
        json!({"record_id": R4, "user_upn": JDOE, "operation": "Move", "workload": "Exchange", "client_ip": IP,
               "event_time": ts(t0() + Duration::seconds(1)), "audit_data": "{}", "client_app_id": "client-7"}),
    );
    put(
        &case,
        &Ev {
            ip: Some(IP),
            workload: Some("Exchange"),
            operation: Some("Move"),
            category: Some("other"),
            at: 1,
            ..ual(R4)
        },
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let other = items_of(&case, Category::Other);
    let apps: Vec<_> = other
        .iter()
        .map(|i| (i.action.as_str(), i.app.as_deref(), i.app_name.as_deref()))
        .collect();
    assert!(
        apps.contains(&("Update", Some("app-9"), Some("Outlook Web"))),
        "{apps:?}"
    );
    assert!(apps.contains(&("Move", Some("client-7"), None)), "{apps:?}");
}

#[test]
fn no_record_lands_in_two_categories() {
    let case = Case::in_memory().unwrap();
    ual_w(
        &case,
        R1,
        "Exchange",
        "MailItemsAccessed",
        Some(IP),
        0,
        "other",
        json!({}),
    );
    mia_item(&case, R1, 0, "bind", "\\Inbox", Some("<a@x>"), 10);
    ual_w(
        &case,
        R2,
        "Exchange",
        "Send",
        Some(IP),
        1,
        "other",
        json!({"Item": {"Subject": "s"}}),
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let all = access::items(case.conn(), None).unwrap();
    assert_eq!(
        all.iter().filter(|i| i.category == Category::Other).count(),
        0,
        "{all:?}"
    );
}

#[test]
fn a_sharing_record_with_a_file_child_keeps_its_target() {
    let case = Case::in_memory().unwrap();
    ual_w(
        &case,
        R1,
        "SharePoint",
        "SharingSet",
        Some(IP),
        0,
        "other",
        json!({}),
    );
    insert_row(
        &case,
        "file_events",
        "contoso",
        json!({"record_id": R1, "item_type": "file", "is_onenote": false,
        "file_name": "plan.docx", "site_url": "https://contoso.sharepoint.com/", "relative_url": "plan.docx"}),
    );
    insert_row(
        &case,
        "sharing_events",
        "contoso",
        json!({"record_id": R1, "link_type": "anonymous",
        "target_email": "x@evil.example", "is_external": true}),
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let all = access::items(case.conn(), None).unwrap();
    assert_eq!(all.len(), 1, "{all:?}");
    assert_eq!(all[0].category, Category::File);
    assert_eq!(all[0].item.as_deref(), Some("plan.docx"));
    assert_eq!(
        all[0].note.as_deref(),
        Some("shared with x@evil.example (external)")
    );
}

#[test]
fn copilot_in_teams_is_copilot_only() {
    let case = Case::in_memory().unwrap();
    ual_w(
        &case,
        R1,
        "MicrosoftTeams",
        "CopilotInteraction",
        Some(IP),
        0,
        "other",
        json!({"CopilotEventData": {"AppHost": "Teams"}}),
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let cats: Vec<_> = access::items(case.conn(), None)
        .unwrap()
        .into_iter()
        .map(|i| i.category)
        .collect();
    assert_eq!(cats, vec![Category::Copilot]);
}

#[test]
fn a_non_ual_row_with_a_mail_operation_name_is_other() {
    let case = Case::in_memory().unwrap();
    put(
        &case,
        &Ev {
            table: "admin_audit_events",
            key: "aa-1",
            actor: Some(JDOE),
            ip: Some(IP),
            operation: Some("Send"),
            ..Ev::default()
        },
    );
    case.conn()
        .execute(
            "UPDATE events SET target = 'mailbox ceo' WHERE record_key = 'aa-1'",
            [],
        )
        .unwrap();
    vflag(&case, "ip", IP, None, State::Accepted);
    let all = access::items(case.conn(), None).unwrap();
    assert_eq!(all.len(), 1, "{all:?}");
    assert_eq!(
        (all[0].category, all[0].item.as_deref()),
        (Category::Other, Some("mailbox ceo"))
    );
}

// Task 5: coverage, tiles and the report.

use sparrow_core::case::access::NEVER_LOGGED;

fn availability(case: &Case, evidence: &str, status: &str) {
    insert_row(
        case,
        "evidence_availability",
        "contoso",
        json!({"tenant_key": "contoso", "evidence": evidence,
        "title": evidence, "status": status, "reason": format!("{evidence} {status}"), "rows": 1,
        "evaluated_at": ts(t0())}),
    );
}

fn tile(acc: &access::AccountAccess, c: Category) -> &access::Tile {
    acc.tiles.iter().find(|t| t.category == c).unwrap()
}

#[test]
fn report_lists_flagged_accounts_with_seven_tiles() {
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R1,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some(IP),
        0,
        json!({}),
    );
    mia_item(&case, R1, 0, "bind", "\\Inbox", Some("<a@x>"), 10);
    vflag(&case, "ip", IP, None, State::Accepted);
    vflag(&case, "account", BOB, None, State::Accepted);
    vflag(
        &case,
        "account",
        "eve@contoso.example",
        None,
        State::Pending,
    );
    let r = access::report(case.conn(), None).unwrap();
    let names: Vec<_> = r.accounts.iter().map(|a| a.account.as_str()).collect();
    assert_eq!(names, vec![BOB, JDOE]);
    assert_eq!(r.pending_flags, 1);
    for a in &r.accounts {
        assert_eq!(
            a.tiles.iter().map(|t| t.category).collect::<Vec<_>>(),
            Category::ALL.to_vec()
        );
    }
    let bob = &r.accounts[0];
    assert!(bob.items.is_empty() && bob.scope.is_empty());
    let jdoe = &r.accounts[1];
    assert_eq!(jdoe.items.len(), 1);
    assert_eq!(jdoe.tenant_key.as_deref(), Some("contoso"));
    assert_eq!(jdoe.scope[0].value, IP);
    assert_eq!(
        access::flagged_accounts(case.conn()).unwrap(),
        vec![BOB.to_string(), JDOE.to_string()]
    );
    let one = access::report(case.conn(), Some("JDOE@contoso.example")).unwrap();
    assert_eq!(one.accounts.len(), 1);
    assert_eq!(one.accounts[0].items.len(), 1);
}

#[test]
fn tile_counts_split_direct_and_time() {
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R1,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some(IP),
        0,
        json!({}),
    );
    mia_item(&case, R1, 0, "bind", "\\Inbox", Some("<a@x>"), 1_048_576);
    mia_item(&case, R1, 1, "bind", "\\Inbox", Some("<b@x>"), 1_048_576);
    mia_item(&case, R1, 2, "sync", "\\Sent Items", None, 0);
    ual_ev(
        &case,
        R2,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        None,
        60,
        json!({}),
    );
    mia_item(&case, R2, 0, "bind", "\\Archive", Some("<c@x>"), 1_048_576);
    mia_item(&case, R2, 1, "bind", "\\Inbox", Some("<a@x>"), 1_048_576);
    vflag(&case, "ip", IP, None, State::Accepted);
    let r = access::report(case.conn(), Some(JDOE)).unwrap();
    let t = tile(&r.accounts[0], Category::MailRead);
    assert_eq!((t.direct, t.by_time), (2, 1));
    assert_eq!(
        t.qualifier.as_deref(),
        Some("2 folders · 3.0 MB · 1 folder synced")
    );
}

#[test]
fn zero_is_never_none_seen_without_coverage() {
    let teams = |case: &Case| {
        let r = access::report(case.conn(), Some(JDOE)).unwrap();
        tile(&r.accounts[0], Category::Teams).clone()
    };
    let base = || {
        let case = Case::in_memory().unwrap();
        ual_ev(
            &case,
            R1,
            "MailItemsAccessed",
            JDOE,
            JDOE,
            Some(IP),
            0,
            json!({}),
        );
        vflag(&case, "ip", IP, None, State::Accepted);
        case
    };
    let none = base();
    let t = teams(&none);
    assert_eq!(
        (t.direct, t.none_seen, t.coverage.status.as_str()),
        (0, false, "none")
    );
    let collected = base();
    availability(&collected, "ual", "collected");
    let t = teams(&collected);
    assert!(t.none_seen);
    assert_eq!(t.coverage.status, "collected");
    let partial = base();
    availability(&partial, "ual", "partial");
    let t = teams(&partial);
    assert!(!t.none_seen);
    assert_eq!(
        t.coverage.reason,
        "UAL partial: Teams operations of this account may not have been collected"
    );
    // A partial UAL that does hold Teams operations for the tenant: none of them is the attacker's.
    ual_w(
        &partial,
        R5,
        "MicrosoftTeams",
        "MessageSent",
        Some("198.51.100.7"),
        5,
        "other",
        json!({}),
    );
    assert!(teams(&partial).none_seen);
}

#[test]
fn never_logged_is_listed_once_per_report() {
    let case = Case::in_memory().unwrap();
    vflag(&case, "account", JDOE, None, State::Accepted);
    vflag(&case, "account", BOB, None, State::Accepted);
    let r = access::report(case.conn(), None).unwrap();
    let want: Vec<String> = NEVER_LOGGED.iter().map(|(_, g)| g.to_string()).collect();
    assert_eq!(r.never_logged, want);
    assert_eq!(NEVER_LOGGED.len(), 4);
    // Each account keeps only its own coverage reasons.
    for a in &r.accounts {
        assert!(a.gaps.iter().all(|g| !want.contains(g)), "{:?}", a.gaps);
    }
}

#[test]
fn a_partial_source_needs_the_account_own_operations() {
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R1,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some(IP),
        0,
        json!({}),
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    availability(&case, "ual", "partial");
    // Teams operations exist in the tenant, but only for bob: they say nothing about jdoe's coverage.
    insert_row(
        &case,
        "ual_events",
        "contoso",
        json!({"record_id": R6, "user_upn": BOB, "operation": "MessageSent",
        "workload": "MicrosoftTeams", "event_time": ts(t0())}),
    );
    let r = access::report(case.conn(), Some(JDOE)).unwrap();
    assert!(!tile(&r.accounts[0], Category::Teams).none_seen);
}

#[test]
fn a_mail_source_status_is_not_overridden_by_the_ual() {
    let case = Case::in_memory().unwrap();
    ual_w(
        &case,
        R1,
        "SharePoint",
        "FileAccessed",
        Some(IP),
        0,
        "other",
        json!({}),
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    availability(&case, "ual", "collected");
    availability(&case, "mail_items_accessed", "not_enabled");
    availability(&case, "mail_send", "not_licensed");
    let r = access::report(case.conn(), Some(JDOE)).unwrap();
    let read = tile(&r.accounts[0], Category::MailRead);
    assert_eq!(
        (read.coverage.status.as_str(), read.none_seen),
        ("not_enabled", false)
    );
    let sent = tile(&r.accounts[0], Category::MailSent);
    assert_eq!(
        (sent.coverage.status.as_str(), sent.none_seen),
        ("not_licensed", false)
    );
    availability(&case, "mailbox_audit_legacy", "collected");
    let r = access::report(case.conn(), Some(JDOE)).unwrap();
    assert_eq!(
        tile(&r.accounts[0], Category::MailRead).coverage.status,
        "collected"
    );
}

#[test]
fn a_sync_only_read_is_not_none_seen() {
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R1,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some(IP),
        0,
        json!({}),
    );
    mia_item(&case, R1, 0, "sync", "\\Inbox", None, 0);
    vflag(&case, "ip", IP, None, State::Accepted);
    availability(&case, "mail_items_accessed", "collected");
    let r = access::report(case.conn(), Some(JDOE)).unwrap();
    let t = tile(&r.accounts[0], Category::MailRead);
    assert!(!t.none_seen);
    assert_eq!(t.qualifier.as_deref(), Some("1 folder synced"));
}

#[test]
fn the_tenant_comes_from_the_attributed_records() {
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R1,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some(IP),
        0,
        json!({}),
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    // More (unattributed) events of the same UPN in another tenant.
    for (i, k) in ["f1", "f2", "f3"].into_iter().enumerate() {
        put(
            &case,
            &Ev {
                ip: Some("198.51.100.4"),
                at: i as i64 + 1,
                ..ual(k)
            },
        );
        case.conn()
            .execute(
                "UPDATE events SET tenant_key = 'fabrikam' WHERE record_key = ?",
                [k],
            )
            .unwrap();
    }
    let r = access::report(case.conn(), Some(JDOE)).unwrap();
    assert_eq!(r.accounts[0].tenant_key.as_deref(), Some("contoso"));
}

// Task 6: exports.

use sparrow_core::export::access::{CSV_COLUMNS, write_csv, write_summary};

fn exported(case: &Case) -> (String, String) {
    let r = access::report(case.conn(), None).unwrap();
    let (mut c, mut m) = (Vec::new(), Vec::new());
    write_csv(&r, &mut c).unwrap();
    write_summary(&r, &mut m).unwrap();
    (String::from_utf8(c).unwrap(), String::from_utf8(m).unwrap())
}

#[test]
fn csv_has_the_columns_and_iso_times() {
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R1,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some(IP),
        0,
        json!({}),
    );
    mia_item(&case, R1, 0, "bind", "\\Inbox", Some("<a@x>"), 10);
    trace(&case, "<a@x>", "ap@vendor.example", JDOE, "Q3", 3600);
    vflag(&case, "ip", IP, None, State::Accepted);
    let (csv, _) = exported(&case);
    assert!(csv.starts_with('\u{feff}'));
    let mut lines = csv.trim_start_matches('\u{feff}').lines();
    assert_eq!(lines.next().unwrap(), CSV_COLUMNS.join(","));
    let row = lines.next().unwrap();
    assert!(row.starts_with("jdoe@contoso.example,mail_read,ip,2026-09-01T10:00:00Z,read,Q3,\\Inbox,ap@vendor.example,"), "{row}");
    assert!(row.contains(",2026-09-01T09:00:00Z,"), "{row}");
    assert_eq!(lines.next(), None);
}

#[test]
fn csv_neutralises_formulas() {
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R1,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some(IP),
        0,
        json!({}),
    );
    mia_item(&case, R1, 0, "bind", "\\Inbox", Some("<a@x>"), 10);
    trace(
        &case,
        "<a@x>",
        "ap@vendor.example",
        JDOE,
        "=HYPERLINK(\"http://evil\")",
        60,
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let (csv, _) = exported(&case);
    assert!(
        csv.contains("\"'=HYPERLINK(\"\"http://evil\"\")\""),
        "{csv}"
    );
}

#[test]
fn markdown_summary_counts_and_escapes_pipes() {
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R1,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some(IP),
        0,
        json!({}),
    );
    mia_item(&case, R1, 0, "bind", "\\Inbox", Some("<a@x>"), 10);
    ual_ev(
        &case,
        R2,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        None,
        60,
        json!({}),
    );
    mia_item(&case, R2, 0, "bind", "\\Inbox", Some("<b@x>"), 10);
    vflag(&case, "ip", IP, None, State::Accepted);
    vflag(
        &case,
        "account",
        "a|b@contoso.example",
        None,
        State::Accepted,
    );
    availability(&case, "mail_items_accessed", "collected");
    availability(&case, "mail_send", "collected");
    let (_, md) = exported(&case);
    assert!(md.contains("| Account | Emails read | Emails sent | Attachments | SharePoint / OneDrive | Teams | Copilot | Other apps |"), "{md}");
    assert!(
        md.contains("| jdoe@contoso.example | 1 (+1 by time) | 0 none seen |"),
        "{md}"
    );
    assert!(md.contains("a\\|b@contoso.example"), "{md}");
    assert!(md.contains("### Coverage gaps"), "{md}");
    assert!(
        md.contains("Teams chats read in the Teams app are not audited \\(only Graph reads are\\)"),
        "{md}"
    );
}

#[test]
fn csv_neutralises_every_text_column() {
    let case = Case::in_memory().unwrap();
    ual_w(
        &case,
        R1,
        "SharePoint",
        "FileDownloaded",
        Some(IP),
        0,
        "other",
        json!({}),
    );
    insert_row(
        &case,
        "file_events",
        "contoso",
        json!({"record_id": R1, "item_type": "file", "is_onenote": false,
        "file_name": "+cmd.xlsx", "site_url": "@site/", "relative_url": "x", "application_name": "-app"}),
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let (csv, _) = exported(&case);
    let mut r = csv::Reader::from_reader(csv.trim_start_matches('\u{feff}').as_bytes());
    let rec = r.records().next().unwrap().unwrap();
    let col = |name: &str| {
        rec.get(CSV_COLUMNS.iter().position(|c| *c == name).unwrap())
            .unwrap()
            .to_string()
    };
    assert_eq!(col("item"), "'+cmd.xlsx");
    assert_eq!(col("location"), "'@site/x");
    assert_eq!(col("app"), "'-app");
}

#[test]
fn a_sync_only_cell_shows_the_synced_folders() {
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R1,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some(IP),
        0,
        json!({}),
    );
    mia_item(&case, R1, 0, "sync", "\\Inbox", None, 0);
    vflag(&case, "ip", IP, None, State::Accepted);
    let (_, md) = exported(&case);
    assert!(
        md.contains("| jdoe@contoso.example | 0 (1 folder synced) |"),
        "{md}"
    );
}

// The staging of attributed UAL records (items read their AuditData from a connection temp table).

#[test]
fn items_work_on_a_read_only_case_file_twice() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("case.duckdb");
    {
        let case = Case::create_or_open(&path).unwrap();
        ual_ev(
            &case,
            R1,
            "SendAs",
            JDOE,
            "ceo@contoso.example",
            Some(IP),
            0,
            json!({"SendAsUserSmtp": "ceo@contoso.example", "Item": {"Subject": "Wire"}}),
        );
        ual_w(
            &case,
            R2,
            "MicrosoftTeams",
            "ChatRetrieved",
            None,
            60,
            "other",
            json!({"ChatName": "Finance"}),
        );
        vflag(&case, "ip", IP, None, State::Accepted);
        case.conn().execute_batch("CHECKPOINT").unwrap();
    }
    let ro = Case::open_read_only(&path).unwrap();
    for _ in 0..2 {
        let items = access::items(ro.conn(), None).unwrap();
        let got: Vec<_> = items
            .iter()
            .map(|i| (i.category, i.attribution, i.item.clone()))
            .collect();
        assert_eq!(
            got,
            vec![
                (
                    Category::MailSent,
                    Attribution::Ip,
                    Some("Wire".to_string())
                ),
                (
                    Category::Teams,
                    Attribution::Time,
                    Some("Finance".to_string())
                ),
            ]
        );
    }
}

#[test]
fn staging_spans_chunks_without_loss_or_repeats() {
    let case = Case::in_memory().unwrap();
    let n = 1_205;
    for k in 0..n {
        let key: &'static str =
            Box::leak(format!("20000000-0000-4000-8000-{k:012}").into_boxed_str());
        insert_row(
            &case,
            "ual_events",
            "contoso",
            json!({"record_id": key, "user_upn": JDOE, "operation": "Send",
            "workload": "Exchange", "client_ip": IP, "event_time": ts(t0() + Duration::seconds(k)),
            "audit_data": json!({"Item": {"Subject": format!("s{k}")}}).to_string()}),
        );
        put(
            &case,
            &Ev {
                ip: Some(IP),
                at: k,
                ..ual(key)
            },
        );
    }
    vflag(&case, "ip", IP, None, State::Accepted);
    let items = access::items(case.conn(), None).unwrap();
    assert_eq!(items.len(), n as usize);
    let subjects: std::collections::BTreeSet<_> =
        items.iter().map(|i| i.item.clone().unwrap()).collect();
    assert_eq!(subjects.len(), n as usize);
}

// Final review fixes.

#[test]
fn a_throttled_mail_read_is_partial() {
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R1,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some(IP),
        0,
        json!({}),
    );
    insert_row(
        &case,
        "mail_items_accessed",
        "contoso",
        json!({"record_id": R1, "item_ordinal": 0, "access_type": "bind",
        "folder_path": "\\Inbox", "internet_message_id": "<a@x>", "size_bytes": 10, "is_throttled": true}),
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    availability(&case, "mail_items_accessed", "collected");
    let r = access::report(case.conn(), Some(JDOE)).unwrap();
    let t = tile(&r.accounts[0], Category::MailRead);
    assert_eq!(t.coverage.status, "partial");
    assert!(
        t.coverage.reason.contains("throttled"),
        "{}",
        t.coverage.reason
    );
    assert!(r.accounts[0].gaps.iter().any(|g| g.contains("throttled")));
}

#[test]
fn a_mailbox_that_does_not_audit_the_action_is_partial() {
    let case = Case::in_memory().unwrap();
    ual_w(
        &case,
        R1,
        "SharePoint",
        "FileAccessed",
        Some(IP),
        0,
        "other",
        json!({}),
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    availability(&case, "mail_items_accessed", "collected");
    availability(&case, "mail_send", "collected");
    insert_row(
        &case,
        "mailboxes",
        "contoso",
        json!({"record_key": "mb1", "upn": "JDOE@contoso.example",
        "audit_owner": ["Send"], "audit_bypass_enabled": false}),
    );
    let r = access::report(case.conn(), Some(JDOE)).unwrap();
    let read = tile(&r.accounts[0], Category::MailRead);
    assert_eq!(
        (read.coverage.status.as_str(), read.none_seen),
        ("partial", false)
    );
    assert!(
        read.coverage
            .reason
            .contains("does not audit MailItemsAccessed"),
        "{}",
        read.coverage.reason
    );
    assert!(tile(&r.accounts[0], Category::MailSent).none_seen);
    case.conn()
        .execute("UPDATE mailboxes SET audit_bypass_enabled = TRUE", [])
        .unwrap();
    let r = access::report(case.conn(), Some(JDOE)).unwrap();
    let sent = tile(&r.accounts[0], Category::MailSent);
    assert_eq!(
        (sent.coverage.status.as_str(), sent.none_seen),
        ("partial", false)
    );
    assert!(
        sent.coverage.reason.contains("audit bypass"),
        "{}",
        sent.coverage.reason
    );
}

#[test]
fn reads_without_a_message_id_are_counted_apart() {
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R1,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some(IP),
        0,
        json!({}),
    );
    mia_item(&case, R1, 0, "bind", "\\Inbox", Some("<a@x>"), 10);
    mia_item(&case, R1, 1, "bind", "\\Inbox", None, 10);
    ual_ev(
        &case,
        R2,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some(IP),
        5,
        json!({}),
    );
    mia_item(&case, R2, 0, "bind", "\\Inbox", None, 10);
    legacy(&case, "mal-9", "MessageBind", &[], &[]);
    vflag(&case, "ip", IP, None, State::Accepted);
    let read = items_of(&case, Category::MailRead);
    assert_eq!(
        read.iter()
            .filter(|i| i.action == "read (no message id)")
            .count(),
        3,
        "{read:?}"
    );
    let r = access::report(case.conn(), Some(JDOE)).unwrap();
    let t = tile(&r.accounts[0], Category::MailRead);
    assert_eq!((t.direct, t.by_time), (1, 0));
    assert!(
        t.qualifier
            .as_deref()
            .unwrap()
            .ends_with(" · 3 reads without a message id"),
        "{:?}",
        t.qualifier
    );
}

#[test]
fn the_staging_table_is_dropped_after_the_items() {
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R1,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some(IP),
        0,
        json!({}),
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    access::report(case.conn(), None).unwrap();
    let n: i64 = case
        .conn()
        .query_row(
            "SELECT count(*) FROM duckdb_tables() WHERE temporary AND table_name = 'access_ual'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0);
}

#[test]
fn the_summary_lists_the_never_logged_gaps_once() {
    let case = Case::in_memory().unwrap();
    vflag(&case, "account", JDOE, None, State::Accepted);
    vflag(&case, "account", BOB, None, State::Accepted);
    let (_, md) = exported(&case);
    assert_eq!(
        md.matches("Teams chats read in the Teams app are not audited")
            .count(),
        1,
        "{md}"
    );
    assert!(md.contains("### Not logged by Microsoft"), "{md}");
}

// ---- Preview: pending and ad-hoc scope (`report_with`) ----

use sparrow_core::case::access::{Basis, ScopeSource, report_with};
use sparrow_core::case::marks::ValueKind;

/// jdoe read one message from `IP` (R1) and one from another address (R2).
fn preview_case() -> Case {
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R1,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some(IP),
        0,
        json!({}),
    );
    mia_item(&case, R1, 0, "bind", "\\Inbox", Some("<a@x>"), 10);
    ual_ev(
        &case,
        R2,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some("198.51.100.77"),
        60,
        json!({}),
    );
    mia_item(&case, R2, 0, "bind", "\\Inbox", Some("<b@x>"), 10);
    case
}

fn pending() -> ScopeSource {
    ScopeSource {
        include_pending: true,
        ..ScopeSource::accepted()
    }
}

fn adhoc(kind: ValueKind, value: &str) -> ScopeSource {
    ScopeSource {
        adhoc: vec![(kind, value.to_string())],
        ..ScopeSource::accepted()
    }
}

#[test]
fn pending_flags_count_with_include_pending() {
    let case = preview_case();
    vflag(&case, "ip", IP, None, State::Pending);
    let plain = report_with(case.conn(), Some(JDOE), &ScopeSource::accepted()).unwrap();
    assert!(
        plain.accounts[0].items.is_empty(),
        "pending counts for nothing by default"
    );
    assert!(!plain.preview);
    let r = report_with(case.conn(), Some(JDOE), &pending()).unwrap();
    let a = &r.accounts[0];
    assert_eq!(a.items.len(), 1);
    assert_eq!(a.items[0].record_key, R1);
    assert_eq!(a.items[0].basis, Basis::Pending);
    assert_eq!(a.scope.len(), 1);
    assert_eq!(a.scope[0].basis, Basis::Pending);
    assert!(r.preview);
    // Removed and discarded flags stay out even then.
    let case = preview_case();
    vflag(&case, "ip", IP, None, State::Discarded);
    vflag(&case, "ip", IP, None, State::Removed);
    let r = report_with(case.conn(), Some(JDOE), &pending()).unwrap();
    assert!(r.accounts[0].items.is_empty());
}

#[test]
fn pending_row_flags_count_with_include_pending() {
    let case = preview_case();
    rflag(&case, "ual_events", R2, State::Pending);
    let r = report_with(case.conn(), Some(JDOE), &pending()).unwrap();
    let keys: Vec<_> = r.accounts[0]
        .items
        .iter()
        .map(|i| (i.record_key.as_str(), i.basis))
        .collect();
    assert_eq!(keys, vec![(R2, Basis::Pending)]);
}

#[test]
fn adhoc_scope_reaches_like_a_flag() {
    let flagged = preview_case();
    vflag(&flagged, "ip", IP, None, State::Accepted);
    let accepted = access::report(flagged.conn(), Some(JDOE)).unwrap();
    let case = preview_case();
    let r = report_with(case.conn(), Some(JDOE), &adhoc(ValueKind::Ip, IP)).unwrap();
    let (a, b) = (&accepted.accounts[0], &r.accounts[0]);
    let strip = |items: &[Item]| -> Vec<(String, String)> {
        items
            .iter()
            .map(|i| (i.record_key.clone(), i.action.clone()))
            .collect()
    };
    assert_eq!(strip(&b.items), strip(&a.items));
    assert!(b.items.iter().all(|i| i.basis == Basis::Adhoc));
    assert_eq!(b.scope[0].basis, Basis::Adhoc);
    assert_eq!(b.scope[0].windows, a.scope[0].windows);
    assert!(r.preview);
    // Case-wide: without --account the ad-hoc value puts the account on the report.
    let all = report_with(case.conn(), None, &adhoc(ValueKind::Ip, IP)).unwrap();
    assert_eq!(
        all.accounts
            .iter()
            .map(|a| a.account.as_str())
            .collect::<Vec<_>>(),
        vec![JDOE]
    );
}

#[test]
fn accepted_wins_over_pending_and_adhoc() {
    let case = preview_case();
    vflag(&case, "ip", IP, None, State::Accepted);
    vflag(&case, "ip", IP, None, State::Pending);
    let src = ScopeSource {
        include_pending: true,
        adhoc: vec![(ValueKind::Ip, IP.to_string())],
        ..ScopeSource::accepted()
    };
    let r = report_with(case.conn(), Some(JDOE), &src).unwrap();
    let a = &r.accounts[0];
    assert_eq!(a.items.len(), 1);
    assert_eq!(a.items[0].basis, Basis::Accepted);
    assert_eq!(a.scope.len(), 1);
    assert_eq!(a.scope[0].basis, Basis::Accepted);
    assert!(
        !r.preview,
        "nothing but accepted scope is in play: not a preview"
    );
    // A pending flag on the other address puts one non-accepted record in play: a preview.
    vflag(&case, "ip", "198.51.100.77", None, State::Pending);
    let r = report_with(case.conn(), Some(JDOE), &src).unwrap();
    let bases: Vec<_> = r.accounts[0].items.iter().map(|i| i.basis).collect();
    assert_eq!(bases, vec![Basis::Accepted, Basis::Pending]);
    assert!(r.preview);
    // Pending beats ad-hoc.
    let case = preview_case();
    vflag(&case, "ip", IP, None, State::Pending);
    let r = report_with(case.conn(), Some(JDOE), &src).unwrap();
    assert_eq!(r.accounts[0].items[0].basis, Basis::Pending);
}

#[test]
fn adhoc_values_are_bound() {
    let case = preview_case();
    vflag(&case, "ip", IP, None, State::Accepted);
    for kind in [
        ValueKind::Ip,
        ValueKind::IpPrefix,
        ValueKind::Session,
        ValueKind::Device,
    ] {
        let src = adhoc(kind, "1.2.3.4' OR 1=1 --");
        let r = report_with(case.conn(), None, &src).unwrap();
        // Only the accepted flag's record: the text matched nothing.
        let keys: Vec<_> = r
            .accounts
            .iter()
            .flat_map(|a| a.items.iter().map(|i| i.record_key.as_str()))
            .collect();
        assert_eq!(keys, vec![R1], "{kind:?}");
    }
}

#[test]
fn adhoc_kinds_are_ip_prefix_session_and_device() {
    let case = preview_case();
    for kind in [ValueKind::Account, ValueKind::Asn] {
        let e = report_with(case.conn(), None, &adhoc(kind, "x")).unwrap_err();
        assert!(
            e.to_string().contains("ip, ip_prefix, session or device"),
            "{e}"
        );
    }
}

#[test]
fn report_is_unchanged_for_the_app() {
    let case = preview_case();
    vflag(&case, "ip", IP, None, State::Accepted);
    vflag(&case, "ip", "198.51.100.77", None, State::Pending);
    let a = access::report(case.conn(), None).unwrap();
    let b = report_with(case.conn(), None, &ScopeSource::accepted()).unwrap();
    assert_eq!(a, b);
    assert!(!a.preview);
    assert!(
        a.accounts[0]
            .items
            .iter()
            .all(|i| i.basis == Basis::Accepted)
    );
}

#[test]
fn csv_has_the_basis_column() {
    let case = preview_case();
    vflag(&case, "ip", IP, None, State::Accepted);
    let r = report_with(
        case.conn(),
        Some(JDOE),
        &adhoc(ValueKind::Ip, "198.51.100.77"),
    )
    .unwrap();
    assert_eq!(CSV_COLUMNS.len(), 19);
    assert_eq!(CSV_COLUMNS[18], "basis");
    assert_eq!(
        CSV_COLUMNS[17], "record_id",
        "the 18 earlier columns keep their places"
    );
    let mut out = Vec::new();
    write_csv(&r, &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    let mut rd = csv::Reader::from_reader(text.trim_start_matches('\u{feff}').as_bytes());
    let bases: Vec<String> = rd.records().map(|r| r.unwrap()[18].to_string()).collect();
    assert_eq!(bases, vec!["accepted", "adhoc"]);
}

#[test]
fn a_message_seen_several_times_takes_the_strongest_basis() {
    // The same message read twice: first from a pending IP, later from an accepted one. One item, accepted.
    let case = Case::in_memory().unwrap();
    ual_ev(
        &case,
        R1,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some(IP),
        0,
        json!({}),
    );
    mia_item(&case, R1, 0, "bind", "\\Inbox", Some("<same@x>"), 10);
    ual_ev(
        &case,
        R2,
        "MailItemsAccessed",
        JDOE,
        JDOE,
        Some("198.51.100.77"),
        60,
        json!({}),
    );
    mia_item(&case, R2, 0, "bind", "\\Inbox", Some("<same@x>"), 10);
    // And one message sent twice (two Send records with one InternetMessageId).
    let sent = json!({"Item": {"InternetMessageId": "<sent@x>", "Subject": "s"}});
    ual_ev(&case, R3, "Send", JDOE, JDOE, Some(IP), 120, sent.clone());
    ual_ev(
        &case,
        R4,
        "Send",
        JDOE,
        JDOE,
        Some("198.51.100.77"),
        180,
        sent,
    );
    vflag(&case, "ip", IP, None, State::Pending);
    vflag(&case, "ip", "198.51.100.77", None, State::Accepted);
    let mail = |src: &ScopeSource| -> Vec<(Category, String, Option<String>, Basis)> {
        report_with(case.conn(), Some(JDOE), src).unwrap().accounts[0]
            .items
            .iter()
            .filter(|i| matches!(i.category, Category::MailRead | Category::MailSent))
            .map(|i| (i.category, i.record_key.clone(), i.ip.clone(), i.basis))
            .collect()
    };
    // The item is the accepted sighting (the strongest basis first, then the earliest), not the earlier pending one:
    // a row, time and IP labelled accepted are the ones the reviewed report shows.
    let other = Some("198.51.100.77".to_string());
    assert_eq!(
        mail(&pending()),
        vec![
            (
                Category::MailRead,
                R2.to_string(),
                other.clone(),
                Basis::Accepted
            ),
            (Category::MailSent, R4.to_string(), other, Basis::Accepted)
        ]
    );
    assert_eq!(mail(&pending()), mail(&ScopeSource::accepted()));
}

#[test]
fn preview_tiles_and_summary_rows_say_what_is_not_accepted() {
    let case = preview_case();
    vflag(&case, "ip", IP, None, State::Accepted);
    let src = adhoc(ValueKind::Ip, "198.51.100.77");
    let r = report_with(case.conn(), Some(JDOE), &src).unwrap();
    let t = tile(&r.accounts[0], Category::MailRead);
    assert_eq!((t.direct, t.pending, t.adhoc), (2, 0, 1));
    let mut md = Vec::new();
    write_summary(&r, &mut md).unwrap();
    let md = String::from_utf8(md).unwrap();
    let row = md.lines().find(|l| l.contains(JDOE)).unwrap();
    assert!(row.starts_with("| PREVIEW "), "{row}");
    assert!(row.contains("2 (1 ad-hoc)"), "{row}");
    // The reviewed report: no marks at all.
    let r = access::report(case.conn(), Some(JDOE)).unwrap();
    let t = tile(&r.accounts[0], Category::MailRead);
    assert_eq!((t.direct, t.pending, t.adhoc), (1, 0, 0));
    let mut md = Vec::new();
    write_summary(&r, &mut md).unwrap();
    assert!(!String::from_utf8(md).unwrap().contains("PREVIEW"));
}

#[test]
fn the_reviewed_report_carries_no_preview_marks() {
    let case = preview_case();
    vflag(&case, "ip", IP, None, State::Accepted);
    vflag(&case, "ip", "198.51.100.77", None, State::Pending);
    let v = serde_json::to_value(access::report(case.conn(), None).unwrap()).unwrap();
    assert_eq!(v["preview"], false);
    for a in v["accounts"].as_array().unwrap() {
        assert!(
            a["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|i| i["basis"] == "accepted")
        );
        assert!(
            a["scope"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["basis"] == "accepted")
        );
        assert!(
            a["tiles"]
                .as_array()
                .unwrap()
                .iter()
                .all(|t| t["pending"] == 0 && t["adhoc"] == 0)
        );
    }
}

#[test]
fn items_carry_their_row_ref() {
    let case = preview_case();
    vflag(&case, "ip", IP, None, State::Accepted);
    let r = access::report(case.conn(), Some(JDOE)).unwrap();
    let i = &r.accounts[0].items[0];
    assert_eq!(i.row, format!("ual_events:{R1}"));
    // The exact argument `mark flag --row`, `note add` and `timeline-entry propose --evidence` take.
    let e = sparrow_core::case::timeline_entries::EvidenceRef::parse(&i.row).unwrap();
    assert_eq!(
        (e.source_table.as_str(), e.record_key.as_str()),
        ("ual_events", R1)
    );
}

#[test]
fn every_emitted_row_is_one_mark_flag_accepts() {
    let case = preview_case();
    // A legacy mailbox audit record, filed under `other`.
    put(
        &case,
        &Ev {
            table: "mailbox_audit_legacy",
            ip: Some(IP),
            operation: Some("UpdateInboxRules"),
            at: 30,
            ..ual("L1")
        },
    );
    vflag(&case, "ip", IP, None, State::Accepted);
    let r = access::report(case.conn(), Some(JDOE)).unwrap();
    let rows: Vec<sparrow_core::case::marks::RowRef> = r.accounts[0]
        .items
        .iter()
        .map(|i| {
            let e = sparrow_core::case::timeline_entries::EvidenceRef::parse(&i.row).unwrap();
            sparrow_core::case::marks::RowRef::new(&e.source_table, &e.record_key)
        })
        .collect();
    assert!(
        rows.iter()
            .any(|r| r.source_table == "mailbox_audit_legacy"),
        "{rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.source_table == "ual_events"),
        "{rows:?}"
    );
    let actor = sparrow_core::case::actor::Actor::agent("t", None).unwrap();
    sparrow_core::case::marks::flag_rows(
        case.conn(),
        &actor,
        &rows,
        Some(sparrow_core::case::marks::FlagLevel::Suspicious),
    )
    .expect("every emitted row is an event of the case");
}
