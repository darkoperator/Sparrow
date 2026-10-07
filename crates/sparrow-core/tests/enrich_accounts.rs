//! The per-account roll-up (agent accuracy T2): `account_rollup`, rebuilt with the finding facts
//! after every detection run. Every case is built in the STORED shape of its tables.

#[path = "common/detect.rs"]
mod detect;

use chrono::{DateTime, TimeZone, Utc};
use detect::{insert_row, insert_ual};
use serde_json::json;
use sparrow_core::Case;
use sparrow_core::data::DataDirs;
use sparrow_core::detect::enrich::accounts::{AccountRow, MAX_ADDRESSES, read_accounts};
use sparrow_core::detect::load::{LoadedRule, RuleSet, load_rules, rule_sha256};
use sparrow_core::detect::rule::{Rule, Stage};
use sparrow_core::detect::run::{DetectOptions, run};
use std::collections::BTreeMap;

const T: &str = "t1";
const ALICE: &str = "alice@contoso.example";

fn at(day: u32, h: u32, m: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, day, h, m, 0).unwrap()
}

fn iso(t: DateTime<Utc>) -> String {
    t.to_rfc3339()
}

fn opts(day: u32) -> DetectOptions {
    DetectOptions {
        now: Some(at(day, 12, 0)),
        ..DetectOptions::default()
    }
}

fn new_case() -> Case {
    let case = Case::in_memory().unwrap();
    insert_row(&case, "tenant", T, json!({"tenant_key": T}));
    detect::collection_of(&case, T);
    insert_row(
        &case,
        "tenant_domains",
        T,
        json!({"tenant_key": T, "domain": "contoso.example", "source": "derived_upn", "rows_seen": 1}),
    );
    case
}

fn signin(case: &Case, upn: &str, ip: &str, t: DateTime<Utc>, error_code: i64) {
    insert_row(
        case,
        "signins",
        T,
        json!({"user_upn": upn, "ip": ip, "event_time": iso(t), "error_code": error_code,
               "event_type": "interactive", "is_interactive": true, "app_name": "Office 365"}),
    );
}

/// A parent-less MailItemsAccessed row (Microsoft-Extractor-Suite MessageIDs), as stored.
fn mia(case: &Case, upn: &str, ip: &str, t: DateTime<Utc>, key: &str) {
    insert_row(
        case,
        "mail_items_accessed",
        T,
        json!({"item_key": key, "event_time": iso(t), "user_upn": upn, "client_ip": ip,
               "access_type": "bind", "folder_path": "\\Inbox", "time_tz_assumed": false}),
    );
}

fn forwarding_mailbox(case: &Case, upn: &str) {
    insert_row(
        case,
        "mailboxes",
        T,
        json!({"upn": upn, "forwarding_smtp_address": "x@evil.example", "collected_at": iso(at(10, 0, 0))}),
    );
}

fn rule_from(id: &str, severity: &str, body: &str) -> LoadedRule {
    let text = format!(
        "id: {id}\ntitle: title of {id}\nversion: 1\nstatus: experimental\nseverity: {severity}\nanalyst_guidance: g\n{body}\ntests:\n  - name: p\n    records: []\n    expect_hits: 1\n  - name: n\n    records: []\n    expect_hits: 0\n"
    );
    let rule: Rule = serde_norway::from_str(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
    let sha256 = rule_sha256(&rule, &BTreeMap::new(), &BTreeMap::new());
    LoadedRule {
        path: format!("test:{id}"),
        sha256,
        rule,
    }
}

fn forwarding_rule() -> LoadedRule {
    rule_from(
        "SPW-T-001",
        "high",
        "stage: persistence\nsource: mailboxes\nmatch:\n  forwarding_smtp_address: {exists: true}\ngroup_by: [actor_upn]",
    )
}

fn set_of(rules: Vec<LoadedRule>) -> RuleSet {
    RuleSet {
        rules,
        lists: BTreeMap::new(),
        list_meta: BTreeMap::new(),
        warnings: vec![],
    }
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn account<'a>(rows: &'a [AccountRow], upn: &str) -> &'a AccountRow {
    rows.iter()
        .find(|a| a.upn == upn)
        .unwrap_or_else(|| panic!("no account {upn}: {rows:#?}"))
}

#[test]
fn an_address_seen_only_in_mail_items_accessed_is_listed_with_its_reason() {
    let mut case = new_case();
    forwarding_mailbox(&case, ALICE);
    // Alice signs in from A and reads mail from A; B and C act for her but never sign her in.
    let (a, b, c) = ("203.0.113.10", "198.51.100.20", "198.51.100.30");
    signin(&case, ALICE, a, at(1, 8, 0), 0);
    mia(&case, ALICE, a, at(3, 9, 0), "mia-a");
    mia(&case, ALICE, b, at(3, 10, 0), "mia-b1");
    mia(&case, ALICE, b, at(3, 11, 0), "mia-b2");
    insert_ual(
        &case,
        T,
        json!({"operation": "MailItemsAccessed", "workload": "Exchange", "record_type": 50,
               "record_type_name": "ExchangeItemAggregated", "result_status": "Succeeded",
               "user_upn": ALICE, "client_ip": c, "event_time": iso(at(4, 10, 0)),
               "data_completeness": "full"}),
    );
    // Another user's MailItemsAccessed from B is not Alice's.
    mia(&case, "bob@contoso.example", b, at(2, 10, 0), "mia-bob");
    let report = run(&mut case, &set_of(vec![forwarding_rule()]), &opts(20)).unwrap();
    assert_eq!(report.enrich.error, None);
    assert_eq!(report.enrich.accounts, 1);

    let rows = read_accounts(case.conn()).unwrap();
    assert_eq!(rows.len(), 1);
    let al = account(&rows, ALICE);
    let got: Vec<(&str, Vec<&str>, Vec<&str>, bool)> = al
        .addresses
        .iter()
        .map(|x| {
            (
                x.ip.as_str(),
                x.reasons.iter().map(String::as_str).collect(),
                x.tables.iter().map(String::as_str).collect(),
                x.in_user_signins,
            )
        })
        .collect();
    assert_eq!(
        got,
        vec![
            (
                b,
                vec!["acts_without_signin"],
                vec!["mail_items_accessed"],
                false
            ),
            (c, vec!["acts_without_signin"], vec!["ual_events"], false),
        ]
    );
    assert_eq!(al.addresses[0].first_seen, Some(at(3, 10, 0)));
    assert_eq!(al.addresses[0].last_seen, Some(at(3, 11, 0)));
    assert_eq!((al.addresses_total, al.addresses_truncated), (2, false));
}

/// A spray source that failed against five users and against X before X's success from it.
const SPRAY: &str = "203.0.113.66";

fn spray(case: &Case, x: &str) {
    insert_row(
        case,
        "spray_sources",
        T,
        json!({"tenant_key": T, "ip": SPRAY, "users_targeted": 6, "failures": 6,
               "first_failure": iso(at(2, 1, 0)), "last_failure": iso(at(2, 1, 10))}),
    );
    for i in 0..5 {
        signin(
            case,
            &format!("user{i}@contoso.example"),
            SPRAY,
            at(2, 1, i),
            50126,
        );
    }
    signin(case, x, "192.0.2.10", at(1, 9, 0), 0);
    signin(case, x, SPRAY, at(2, 1, 10), 50126);
    signin(case, x, SPRAY, at(2, 3, 0), 0);
}

#[test]
fn a_spray_takeover_ranks_the_account_first() {
    let mut case = new_case();
    let x = "xavier@contoso.example";
    let y = "yvonne@contoso.example";
    spray(&case, x);
    // Y sets an external forwarding rule the day before X's takeover.
    insert_ual(
        &case,
        T,
        json!({"operation": "New-InboxRule", "workload": "Exchange", "record_type": 1,
               "record_type_name": "ExchangeAdmin", "result_status": "True",
               "user_upn": y, "client_ip": "192.0.2.20", "event_time": iso(at(1, 10, 0)),
               "parameters": {"Name": "fw", "Mailbox": y, "ForwardTo": "z@evil.example"},
               "data_completeness": "full"}),
    );
    let report = run(
        &mut case,
        &load_rules(&DataDirs::default()).unwrap(),
        &opts(20),
    )
    .unwrap();
    assert_eq!(report.enrich.error, None);
    // SPW-ID-006 reports the spray with no actor.
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM findings WHERE rule_id = 'SPW-ID-006' AND actor_upn IS NULL"
        ),
        1
    );

    let rows = read_accounts(case.conn()).unwrap();
    let ids: Vec<&str> = rows.iter().map(|a| a.upn.as_str()).collect();
    assert_eq!(ids, vec![x, y], "{rows:#?}");
    let ax = &rows[0];
    let ay = &rows[1];
    assert_eq!(
        (ax.worst_severity.as_str(), ay.worst_severity.as_str()),
        ("high", "high")
    );
    assert_eq!(
        ax.stages,
        vec![Stage::SuspiciousSignIn, Stage::CredentialTakeover]
    );
    assert_eq!(ay.stages, vec![Stage::Persistence]);
    assert!(
        ay.first_suspicious < ax.first_suspicious,
        "the stage count wins over time"
    );
    assert_eq!(ax.first_suspicious, Some(at(2, 3, 0)));
    assert_eq!(ax.rules, vec!["SPW-ID-005".to_string()]);
    assert_eq!(
        ay.rules,
        vec!["SPW-HAWK-010".to_string(), "SPW-MAIL-004".to_string()]
    );
    assert_eq!(ay.by_severity, BTreeMap::from([("high".to_string(), 2)]));
    assert_eq!(ay.finding_count, 2);
    // X's spray address: on its finding's evidence and a spray source.
    let sp = &ax.addresses[0];
    assert_eq!(sp.ip, SPRAY);
    assert_eq!(
        sp.reasons,
        vec!["finding_evidence".to_string(), "spray_source".to_string()]
    );
    assert!(sp.spray_source && sp.in_user_signins);
    assert_eq!(sp.tables, vec!["signins".to_string()]);
    assert_eq!(
        ax.addresses.len(),
        1,
        "X's home address has no reason: {:?}",
        ax.addresses
    );
    // The stored stages are the names, in order.
    let stored: String = case
        .conn()
        .query_row(
            "SELECT CAST(stages AS VARCHAR) FROM account_rollup WHERE upn = ?",
            [x],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, r#"["suspicious_sign_in","credential_takeover"]"#);
}

#[test]
fn findings_without_an_actor_create_no_account() {
    let mut case = new_case();
    forwarding_mailbox(&case, ALICE);
    // Alice's own sign-in from .66 fails; a tenant-level rule cites it with no actor.
    let ip = "198.51.100.66";
    signin(&case, ALICE, ip, at(2, 9, 0), 50126);
    let tenant_level = rule_from(
        "SPW-T-002",
        "medium",
        "stage: persistence\nsql: |\n  SELECT s.record_key, 'signins' AS source_table, s.event_time,\n         CAST(NULL AS VARCHAR) AS actor_upn, s.ip AS ip, CAST(NULL AS JSON) AS context\n  FROM signins s WHERE s.error_code = 50126 AND $tenant IS NOT NULL\ngroup_by: [ip]",
    );
    let report = run(
        &mut case,
        &set_of(vec![forwarding_rule(), tenant_level]),
        &opts(20),
    )
    .unwrap();
    assert_eq!(report.findings_new, 2, "{report:?}");
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM findings f JOIN finding_evidence e USING (finding_id) \
             WHERE f.rule_id = 'SPW-T-002' AND f.actor_upn IS NULL"
        ),
        1
    );
    assert_eq!(report.enrich.accounts, 1);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM account_rollup WHERE upn IS NULL OR upn = ''"
        ),
        0
    );
    let rows = read_accounts(case.conn()).unwrap();
    assert_eq!(rows.len(), 1);
    let al = account(&rows, ALICE);
    assert_eq!(al.rules, vec!["SPW-T-001".to_string()]);
    assert!(
        al.addresses.iter().all(|a| a.ip != ip),
        "the actorless finding's address is nobody's evidence: {:?}",
        al.addresses
    );
}

#[test]
fn rebuilding_twice_leaves_one_row_per_account() {
    let mut case = new_case();
    forwarding_mailbox(&case, ALICE);
    forwarding_mailbox(&case, "bob@contoso.example");
    mia(&case, ALICE, "198.51.100.20", at(3, 10, 0), "mia-1");
    let set = set_of(vec![forwarding_rule()]);
    let first = run(&mut case, &set, &opts(20)).unwrap();
    assert_eq!(first.enrich.accounts, 2);
    let second = run(&mut case, &set, &opts(21)).unwrap();
    assert_eq!(second.run_id, 2);
    assert_eq!(second.enrich.accounts, 2);
    assert_eq!(count(&case, "SELECT count(*) FROM account_rollup"), 2);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM account_rollup WHERE computed_run_id = 2"
        ),
        2
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM finding_facts WHERE computed_run_id = 2"
        ),
        2
    );
    assert_eq!(read_accounts(case.conn()).unwrap().len(), 2);
}

#[test]
fn addresses_are_capped_at_twenty_with_truncation() {
    let mut case = new_case();
    forwarding_mailbox(&case, ALICE);
    // 25 addresses act for Alice without ever signing her in, one a minute, the last first.
    for i in 0..25u32 {
        mia(
            &case,
            ALICE,
            &format!("198.51.100.{}", 100 + i),
            at(3, 10, 24 - i),
            &format!("mia-{i}"),
        );
    }
    run(&mut case, &set_of(vec![forwarding_rule()]), &opts(20)).unwrap();
    let rows = read_accounts(case.conn()).unwrap();
    let al = account(&rows, ALICE);
    assert_eq!(al.addresses.len(), MAX_ADDRESSES);
    assert_eq!((al.addresses_total, al.addresses_truncated), (25, true));
    // The earliest 20 are kept, in first_seen order: .124 (10:00) first, .105 (10:19) last.
    let ips: Vec<String> = al.addresses.iter().map(|a| a.ip.clone()).collect();
    let want: Vec<String> = (0..20u32)
        .map(|k| format!("198.51.100.{}", 124 - k))
        .collect();
    assert_eq!(ips, want);
}
