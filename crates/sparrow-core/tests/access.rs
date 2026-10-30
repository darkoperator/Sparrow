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
